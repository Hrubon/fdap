#include "cbor.h"
#include "cfg.h"
#include "debug.h"
#include "diag.h"
#include "filter.h"
#include "iobuf.h"
#include "list.h"
#include "log.h"
#include "objpool.h"
#include "socket.h"
#include "storage.h"
#include "timeout.h"
#include "tls.h"
#include <arpa/inet.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define RX_BUF_SIZE		1024
#define SOCKETS_PER_BLOCK	64
#define TX_BUF_SIZE		2048
#define TX_BATCH_SIZE		30
#define REQUEST_DECODE_MIN	2
#define CONFIG_FILE		"conf/fdapd.conf"

static int epoll_fd;
static sig_atomic_t flag_quit;
static sig_atomic_t flag_print_sockets;
static struct fdapd_cfg cfg;
static struct list sockets;
static struct objpool socket_pool;
static struct tls_srv tls;
static struct toset tos;
static struct storage *stor;

/*
 * Allocate new `socket` structure.
 */
static struct socket *new_socket(void)
{
	return objpool_alloc(&socket_pool);
}

/*
 * A simple helper around `epoll_ctl`. Call the `op` operation on the `epoll`
 * multiplexer, configuring `events` for `socket`.
 */
static void socket_epoll_ctl(struct socket *s, int op, uint32_t events)
{
	struct epoll_event ev = {
		.events = events,
		.data.ptr = s,
	};
	s->events = events;
	if (epoll_ctl(epoll_fd, op, s->fd, &ev) == -1) {
		LOGF(LOG_EMERG, "Could not register epoll event: %s", strerror(errno));
		err(EXIT_FAILURE, "epoll_ctl failed");
	}
}

/*
 * Subscribe `socket` to `events` of `epoll`. The socket has to be registered
 * by a previous `EPOLL_CTL_ADD` operation.
 */
static void socket_subscribe(struct socket *s, uint32_t events)
{
	socket_epoll_ctl(s, EPOLL_CTL_MOD, s->events | events);
}

/*
 * Unsubscribe `socket` from `events` of `epoll`. The socket has to be
 * registered by a previous `EPOLL_CTL_ADD` operation.
 */
static void socket_unsubscribe(struct socket *s, uint32_t events)
{
	socket_epoll_ctl(s, EPOLL_CTL_MOD, s->events & ~events);
}

/*
 * Register `s` with `epoll` and start receiving (and handling) events for it.
 */
static void start_socket(struct socket *s)
{
	list_insert(&sockets, &s->n);
	if (s->ops->setup)
		s->ops->setup(s);
	socket_epoll_ctl(s, EPOLL_CTL_ADD, EPOLLIN);
}

/*
 * Unregister `s` from `epoll`, invoke a socket-specific tear-down hook and
 * delete `s`.
 */
static void destroy_socket(struct socket *s)
{
	toset_cancel_all(&tos, s);
	socket_epoll_ctl(s, EPOLL_CTL_DEL, 0);
	s->ops->teardown(s);
	shutdown(s->fd, SHUT_RDWR);
	close(s->fd);
	list_remove(&sockets, &s->n);
	objpool_dealloc(&socket_pool, s);
}

/******************************** TCP/IP listening sockets ********************************/

/*
 * Accept incoming TCP connection on the socket `s` and register it.
 */
static void tcp_accept(struct socket *s)
{
	struct socket *client = new_socket();
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	client->fd = accept(s->fd, (struct sockaddr *)&addr, &len);
	if (client->fd == -1) {
		LOGF(LOG_ERR, "Could not accept TCP client: %s", strerror(errno));
		return;
	}
	if (s->use_tls) {
		if (tls_srv_establish(&tls, &client->fd, &client->tls) != 0) {
			close(client->fd);
			return;
		}
		client->rx = iobuf_tls_new(&client->tls, RX_BUF_SIZE);
		client->tx = iobuf_tls_new(&client->tls, RX_BUF_SIZE);
	} else {
		client->rx = iobuf_sock_new(client->fd, RX_BUF_SIZE);
		client->tx = iobuf_sock_new(client->fd, TX_BUF_SIZE);
	}
	client->use_tls = s->use_tls;
	client->ops = s->client_ops;
	client->transport = ST_TCP;
	client->auth = false;
	client->admin = false;
	client->own_id = 0;
	start_socket(client);
	LOGF(LOG_INFO, "Accepted new client: %s", print_socket(client));
}

static void tcp_hup(struct socket *s)
{
	(void) s;
	assert(0);
}

static void tcp_teardown(struct socket *s)
{
	(void) s;
}

/*
 * Operations of a TCP listening socket.
 */
struct socket_ops tcp_ops = {
	.pollhup = tcp_hup,
	.pollin = tcp_accept,
	.pollout = NULL,
	.setup = NULL,
	.teardown = tcp_teardown,
};

/*
 * Start listening on the socket `s`. Bind to this machine's `hostname`
 * and `port`. Returns a boolean indicating success.
 */
static bool tcp_listen(struct socket *s, const char *hostname, const char *port)
{
	struct addrinfo hints;
	memset(&hints, '\0', sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;
	int ret;
	struct addrinfo *head;
	if ((ret = getaddrinfo(hostname, port, &hints, &head)) == 1) {
		const char *err;
		if (ret == EAI_SYSTEM)
			err = strerror(errno);
		else
			err = gai_strerror(ret);
		LOGF(LOG_ERR, "Could not find suitable address to bind, error: %s", err);
		return false;
	}
	struct addrinfo *cur;
	for (cur = head; cur != NULL; cur = cur->ai_next) {
		s->fd = socket(cur->ai_family, SOCK_STREAM, 0);
		if (s->fd == -1) {
			LOGF(LOG_WARNING, "Could not create TCP socket: %s", strerror(errno));
			continue;
		}
		int optval = 1;
		if (setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
			close(s->fd);
			LOGF(LOG_WARNING, "Could not set socketopt: %s", strerror(errno));
			continue;
		}
		if (bind(s->fd, cur->ai_addr, cur->ai_addrlen) == -1) {
			close(s->fd);
			LOGF(LOG_WARNING, "Could not bind TCP socket: %s", strerror(errno));
			continue;
		}
		if (listen(s->fd, 0) == -1) {
			close(s->fd);
			LOGF(LOG_WARNING, "Could not start listening: %s", strerror(errno));
			continue;
		}
		break;
	}
	freeaddrinfo(head);
	return cur != NULL;
}

/*
 * Start listening for incoming TCP connections on this machine's `hostname` and
 * `port`. Creates a new TCP listening socket and registers it. Clients accepted
 * on the newly created socket will be configured with `client_ops`. The `use_tls`
 * flag indicates whether TLS will be started on top of the clients' TCP connections.
 */
static void tcp_listen_start(const char *hostname, const char *port, bool use_tls, struct socket_ops *client_ops)
{
	struct socket *s = new_socket();
	if (!tcp_listen(s, hostname, port)) {
		LOG(LOG_CRIT, "TCP socket start-up failed");
		errx(EXIT_FAILURE, "Cannot start TCP listening socket");
	}
	s->ops = &tcp_ops;
	s->use_tls = use_tls;
	s->client_ops = client_ops;
	s->transport = ST_TCP;
	s->mode = SM_LISTEN;
	start_socket(s);
}

/******************************** UNIX domain listening sockets ********************************/

/*
 * Accept incoming UNIX-domain socket connection and register it.
 */
static void unix_accept(struct socket *s)
{
	struct socket *client = new_socket();
	client->fd = accept(s->fd, NULL, 0);
	if (client->fd == -1) {
		LOGF(LOG_ERR, "Could not accept UNIX-domain socket client: %s", strerror(errno));
		return;
	}
	client->rx = iobuf_sock_new(client->fd, RX_BUF_SIZE);
	client->tx = iobuf_sock_new(client->fd, TX_BUF_SIZE);
	client->ops = s->client_ops;
	client->transport = ST_UNIX;
	start_socket(client);
	LOGF(LOG_INFO, "Accepted new client: %s", print_socket(client));
}

static void unix_hup(struct socket *s)
{
	(void) s;
	assert(0);
}

static void unix_teardown(struct socket *s)
{
	(void) s;
}

/*
 * Operations of a UNIX-domain listening socket.
 */
struct socket_ops unix_ops = {
	.pollhup = unix_hup,
	.pollin = unix_accept,
	.pollout = NULL,
	.setup = NULL,
	.teardown = unix_teardown,
};

/*
 * Start listening on the socket `s` for incoming UNIX-domain socket connections.
 * `path` is the name of the UNIX-domain socket.
 */
static bool unix_listen(struct socket *s, const char *path)
{
	unlink(path);
	s->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s->fd == -1) {
		LOGF(LOG_ERR, "Could not create a socket: %s", strerror(errno));
		return false;
	}
	struct sockaddr_un addr;
	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;
	size_t path_max = sizeof(addr.sun_path);
	if (strlen(path) + 1 > path_max) {
		LOG(LOG_CRIT, "Could not bind a UNIX-domain socket, target path is too long.");
		goto out;
	}
	strncpy(addr.sun_path, path, path_max);
	if (bind(s->fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		LOGF(LOG_CRIT, "Could not bind a UNIX-domain socket: %s", strerror(errno));
		goto out;
	}
	if (listen(s->fd, 0) == -1) {
		LOGF(LOG_CRIT, "Could not start listening: %s", strerror(errno));
		goto out;
	}
	return true;
out:
	close(s->fd);
	return false;
}

/*
 * Start listening for incoming TCP connections on a socket called `path`.
 * Creates a new UNIX-domain listening socket and registers it. Clients
 * accepted on the newly created socket will be configured with `client_ops`.
 */
static void unix_listen_start(const char *path, struct socket_ops *client_ops)
{
	struct socket *s = new_socket();
	if (!unix_listen(s, path))
		errx(EXIT_FAILURE, "Cannot start UNIX-domain listening socket");
	s->ops = &unix_ops;
	s->use_tls = false;
	s->client_ops = client_ops;
	s->transport = ST_UNIX;
	s->mode = SM_LISTEN;
	start_socket(s);
}

/******************************** FDAPc (client) sockets ********************************/

static void fdapc_quit(struct socket *s)
{
	LOG(LOG_NOTICE, "Client connection closed");
	LOGF(LOG_NOTICE, "%s", print_socket(s));
	destroy_socket(s);
}

static void fdapc_err_quit(struct socket *s, char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	VLOGF(LOG_NOTICE, msg, args);
	va_end(args);
	fdapc_quit(s);
}

/*
 * A helper to read a short (shorter than `SHORT_STRING_MAX`) string
 * into a static buffer. TODO Move this to `cbor.c`.
 */
#define SHORT_STRING_MAX	32
static char str[SHORT_STRING_MAX];
static char *read_string_helper(struct cbor *c)
{
	size_t len = cbor_read_text_start_len(c);
	assert(len < SHORT_STRING_MAX);
	size_t l = 0;
	while (!cbor_read_text_end(c))
		l += cbor_read_text(c, str + l, SHORT_STRING_MAX - 1 - l);
	assert(l == len);
	str[l] = '\0';
	return str;
}

static struct record *fdapc_decode_entry(struct socket *s)
{
	size_t nattrs = cbor_read_map_start_size(&s->rx_cbor);
	struct record *rec = record_new(stor, nattrs);
	while (!cbor_read_map_end(&s->rx_cbor)) {
		char *key = read_string_helper(&s->rx_cbor);
		key_id_t id = keystore_key_to_id(&stor->attrs_store, key);
		cbor_read_item(&s->rx_cbor, record_insert(rec, id));
	}
	return rec;
}

/*
 * Decode incoming request from client. When this function is called, the RX
 * buffer contains at least as many bytes as the request was declared to be
 * long, and a read limit was set on it. Hence no I/O operation will block, but
 * a CBOR decoding error (unexpected EOF) can be encountered due to the request
 * being longer than declared (which is a violation of the protocol, so be it.)
 *
 * TODO At the moment, this also handles the request. Move this away or rename this function, this is weird.
 */
static void fdapc_decode_request(struct socket *s)
{
	struct record *rec;
	record_id_t id = RECORD_ID_NONE;
	s->req.oper = cbor_read_u32(&s->rx_cbor);
	enum storage_result res;
	s->resp.results = iter_new_null();
	if (s->req.oper == FDAP_AUTH) {
		cbor_read_text_alloc(&s->rx_cbor, &s->req.auth.username);
		cbor_read_text_alloc(&s->rx_cbor, &s->req.auth.pwd);
		struct filter f;
		assert(filter_build(&f, "read-only.username = %s", s->req.auth.username));
		struct iter *iter = storage_search(stor, &f);
		rec = iter_next(iter);
		if (rec) {
			struct cbor_item *pwd_item = record_getby_name_keys(rec, "password", &stor->attrs_store);
			if (pwd_item == NULL || pwd_item->type != CBOR_TYPE_TEXT) {
				s->resp.result = FDAP_ERR_INVALID_ENTRY;
				iter_destroy(iter);
				return;
			}
			char *pwd = cbor_item_get_text(pwd_item);
			if (strcmp(pwd, s->req.auth.pwd) == 0) {
				s->auth = true;
				s->own_id = rec->id;
				struct cbor_item *admin_item = record_getby_name_keys(rec, "read-only.admin", &stor->attrs_store);
				if (admin_item->type == CBOR_TYPE_SVAL && admin_item->sval == CBOR_SVAL_TRUE)
					s->admin = true;
				s->resp.result = FDAP_OK;
				s->resp.results = iter_new_single(rec);
				iter_destroy(iter);
				return;
			} else {
				s->resp.result = FDAP_ERR_NOT_AUTH;
			}
		} else {
			s->resp.result = FDAP_NOT_FOUND;
		}
		iter_destroy(iter);
		return;
	}
	switch (s->req.oper) {
	case FDAP_SEARCH:
		filter_decode(&s->req.filter, &s->rx_cbor);
		if (!s->auth)
			goto notauth;
		s->resp.result = FDAP_OK;
		s->resp.results = storage_search(stor, &s->req.filter);
		break;
	case FDAP_GET:
		id = cbor_read_u32(&s->rx_cbor);
		if (!s->auth)
			goto notauth;
		rec = storage_get(stor, id);
		s->resp.result = rec ? FDAP_OK : FDAP_NOT_FOUND;
		s->resp.results = iter_new_single(rec);
		break;
	case FDAP_UPDATE:
		if (!s->auth)
			goto notauth;
		/* TODO If is owner, can execute, otherwise goto forbid; */
		id = cbor_read_u32(&s->rx_cbor);
		/* fall-through */
	case FDAP_CREATE:
		rec = fdapc_decode_entry(s);
		if (!s->auth) {
			record_destroy(stor, rec);
			goto notauth;
		}
		if (!s->admin) {
			record_destroy(stor, rec);
			goto forbid;
		}
		rec->id = id; /* RECORD_ID_NONE or ID from the UPDATE request */
		res = storage_update(stor, rec);
		record_destroy(stor, rec);
		switch (res) {
		case STOR_OK:
			s->resp.result = FDAP_OK;
			break;
		case STOR_NXREC:
			s->resp.result = FDAP_NOT_FOUND;
			break;
		case STOR_REFS:
			s->resp.result = FDAP_ERR_INVALID_REF;
			break;
		case STOR_COMMIT:
			s->resp.result = FDAP_ERR_INTERNAL;
			break;
		}
		if (res != STOR_OK) {
			break;
		}
		if (id == RECORD_ID_NONE)
			id = stor->last_id; /* TODO a bit of a hack */
		struct record *new = storage_get(stor, id);
		assert(new != NULL);
		s->resp.result = FDAP_OK;
		s->resp.results = iter_new_single(new);
		break;
	case FDAP_DELETE:
		id = cbor_read_u32(&s->rx_cbor);
		if (!s->auth)
			goto notauth;
		if (!s->admin)
			goto forbid;
		rec = storage_get(stor, id);
		if (!rec) {
			s->resp.result = FDAP_NOT_FOUND;
			break;
		}
		res = storage_remove(stor, id);
		switch (res) {
		case STOR_OK:
			s->resp.result = FDAP_OK;
			s->resp.results = iter_new_single(rec);
			break;
		case STOR_NXREC:
			s->resp.result = FDAP_NOT_FOUND;
			break;
		case STOR_REFS:
			s->resp.result = FDAP_ERR_INVALID_REF;
			break;
		case STOR_COMMIT:
			s->resp.result = FDAP_ERR_INTERNAL;
			break;
		}
		break;
	default:
		LOGF(LOG_ERR, "Unknown FDAP operation code %u", s->req.oper);
		assert(0);
	}
	return;
notauth:
	s->resp.result = FDAP_ERR_NOT_AUTH;
	s->resp.results = iter_new_null();
	return;
forbid:
	s->resp.result = FDAP_ERR_FORBIDDEN;
	s->resp.results = iter_new_null();
	goto forbid;
}

/*
 * Handles incoming data from an FDAP client and implements a simple finite-state
 * machine. The FSM is used to read client's request in a non-blocking manner.
 *
 * All CBOR decoder calls are wrapped in a `try`/`catch` construct which
 * emulates simple exceptions. (See `except.h`.) When exceptions are caught, 
 * the client is terminated. 
 *
 * TODO Ensure proper disposal of all resources when an exception's caught.
 */
static void fdapc_in(struct socket *s)
{
	LOGF(LOG_INFO, "Incoming data from client %s", print_socket(s));
	ssize_t nfill = iobuf_fill_bg(s->rx);
	if (nfill < 0) {
		fdapc_err_quit(s, "I/O error while reading request");
		return;
	}
	if (nfill == 0) {
		if (s->clistate == C_IDLE)
			fdapc_quit(s);
		else
			fdapc_err_quit(s, "Unexpected EOF while reading request");
		return;
	}
	size_t have = iobuf_avail(s->rx);
	switch (s->clistate) {
	case C_IDLE:
		s->clistate = C_BUF;
		iobuf_rlimit(s->rx, REQUEST_DECODE_MIN);
		/* fall-through */
	case C_BUF:
		toset_cancel(&tos, s, TO_IDLE);
		toset_reset(&tos, s, TO_RX);
		if (have < REQUEST_DECODE_MIN)
			break;
		try {
			s->req_len = cbor_read_u16(&s->rx_cbor);
		} catch {
			fdapc_err_quit(s, "Error while decoding request length: %s",
				cbor_strerror(&s->rx_cbor));
			return;
		}
		have = iobuf_avail(s->rx);
		s->clistate = C_BUF_BODY;
		iobuf_rlimit(s->rx, s->rx->rlimit + s->req_len); /* TODO don't touch ->rlimit */
		/* fall-through */
	case C_BUF_BODY:
		if (have < s->req_len)
			break;
		toset_cancel(&tos, s, TO_RX);
		socket_unsubscribe(s, EPOLLIN);
		try {
			fdapc_decode_request(s);
		} catch {
			fdapc_err_quit(s, "Error while decoding request body: %s",
				cbor_strerror(&s->rx_cbor));
			return;
		}
		try {
			cbor_write_u32(&s->tx_cbor, s->resp.result);
		} catch {
			fdapc_err_quit(s, "Error while writing operation result code: %s",
				cbor_strerror(&s->tx_cbor));
			return;
		}
		if (iobuf_flush(s->tx) != 0) {
			fdapc_err_quit(s, "Error while flushing TX buffer");
			return;
		}
		socket_subscribe(s, EPOLLOUT);
		toset_reset(&tos, s, TO_TX);
		s->clistate = C_TX;
		break;
	default:
		assert(0);
	}
}

static void fdapc_out(struct socket *s)
{
	struct record *next;
	switch (s->clistate) {
	case C_TX:
		next = iter_next(s->resp.results);
		if (next) {
			try {
				record_encode(next, stor, &s->tx_cbor, false);
			} catch {
				fdapc_err_quit(s, "Error while encoding record: %s",
					cbor_strerror(&s->tx_cbor));
				iter_destroy(s->resp.results);
				return;
			}
			if (iobuf_flush(s->tx) != 0) {
				fdapc_err_quit(s, "Error while flushing TX buffer");
				iter_destroy(s->resp.results);
				return;
			}
			break;
		}
		try {
			cbor_write_u32(&s->tx_cbor, 0);
		} catch {
			fdapc_err_quit(s, "Error while encoding end-of-response marker");
			return;
		}
		if (iobuf_flush(s->tx) != 0) {
			fdapc_err_quit(s, "Error while flushing TX buffer");
			return;
		}
		iter_destroy(s->resp.results);
		LOG(LOG_INFO, "Done sending response to client.");
		fdap_request_free(&s->req);
		toset_cancel(&tos, s, TO_TX);
		socket_unsubscribe(s, EPOLLOUT);
		socket_subscribe(s, EPOLLIN);
		toset_reset(&tos, s, TO_IDLE); /* TODO DRY, cf. fdapc_setup */
		s->clistate = C_IDLE;
		break;
	default:
		assert(0);
	}
}

static void fdapc_hup(struct socket *s)
{
	(void) s;
	// TODO Quit daemon on client hang-up? Really?
	//fdapc_err_quit(s, "Socket hang-up detected.");
}

/*
 * Additional configuration of an FDAP client socket. At this moment, this
 * merely sets some flags.
 */
static void fdapc_setup(struct socket *s)
{
	s->mode = SM_FDAPC;
	s->clistate = C_IDLE;
	toset_reset(&tos, s, TO_IDLE);
	cbor_init(&s->rx_cbor, s->rx, cbor_errh_throw);
	cbor_init(&s->tx_cbor, s->tx, cbor_errh_throw);
}

/*
 * Tear-down FDAP client connection.
 */
static void fdapc_teardown(struct socket *s)
{
	if (s->use_tls)
		tls_peer_free(&s->tls);
	cbor_free(&s->rx_cbor);
	cbor_free(&s->tx_cbor);
	iobuf_destroy(s->rx);
	iobuf_destroy(s->tx);
}

/*
 * Handle FDAP client time-out.
 */
static void fdapc_timeout(struct socket *s, enum to_type type)
{
	fdapc_err_quit(s, "Client time-out exceeded: %s", strto(type));
}

/*
 * Operations of an FDAP client socket.
 */
struct socket_ops fdapc_ops = {
	.pollhup = fdapc_hup,
	.pollin = fdapc_in,
	.pollout = fdapc_out,
	.setup = fdapc_setup,
	.teardown = fdapc_teardown,
	.timeout = fdapc_timeout,
};

/******************************** FDAPd (downstream) sockets ********************************/

struct socket_ops downstream_ops = {
	.pollhup = NULL,
	.pollin = NULL,
	.pollout = NULL,
	.setup = NULL,
	.teardown = NULL,
};

/******************************** epoll()-based main loop ********************************/

static void print_sockets(int transport, int mode)
{
	list_walk(sockets, n) {
		struct socket *s = container_of(n, struct socket, n);
		if ((transport < 0 || s->transport == transport) && (mode < 0 || s->mode == mode))
			LOGF(LOG_INFO, "%s", print_socket(s));
	}
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		flag_quit = 1;
		break;
	case SIGUSR1:
		flag_print_sockets = 1;
		break;
	}
}

static bool setup_signals(void)
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = signal_handler;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		return false;
	if (sigaction(SIGINT, &sa, NULL) == -1)
		return false;
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		return false;
	return true;
}

/*
 * Setup listening sockets according to `cfg`.
 */
static void setup_listening_sockets(void)
{
	for (size_t i = 0; i < cfg.nsocks; i++) {
		struct lsock_cfg sock = cfg.socks[i];
		struct socket_ops *ops;
		switch (sock.mode) {
		case SM_FDAPC:
			ops = &fdapc_ops;
			break;
		case SM_DSTREAM:
			ops = &downstream_ops;
			break;
		default:
			assert(0);
		}
		switch (sock.trans) {
		case ST_TCP:
			assert(!sock.use_tls || cfg.init_tls);
			tcp_listen_start(sock.host, sock.port, sock.use_tls, ops);
			break;
		case ST_UNIX:
			unix_listen_start(sock.path, ops);
			break;
		default:
			assert(0);
		}
	}
	LOG(LOG_INFO, "All listening sockets successfully initialized:");
	print_sockets(-1, -1);
}

/*
 * FDAP daemon entry point.
 */
int main(void)
{
	if (fdapd_cfg_parse_file(&cfg, CONFIG_FILE) != 0)
		errx(EXIT_FAILURE, "Configuration parse failed");

	if (!setup_signals()) {
		LOGF(LOG_EMERG, "Signals setup failed: %s", strerror(errno));
		errx(EXIT_FAILURE, "sigaction");
	}

	stor = storage_dummy_new(cfg.stor_path);

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1) {
		LOGF(LOG_EMERG, "Could not open epoll file descriptor: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (cfg.init_tls) {
		tls_srv_init(&tls);
		if (tls_srv_config(&tls, cfg.cacert_path, cfg.srvcert_path, cfg.pk_path, cfg.pk_pwd) != 0)
			errx(EXIT_FAILURE, "TLS configuration init failed");
	}
	list_init(&sockets);
	objpool_init(&socket_pool, sizeof(struct socket), SOCKETS_PER_BLOCK);
	toset_init(&tos);
	toset_set_expiry(&tos, TO_IDLE, 60000);
	toset_set_expiry(&tos, TO_RX, 2000);

	setup_listening_sockets();

	size_t max_events = 16; /* TODO */
	struct epoll_event events[max_events];

	int ret;
	for (;;) {
		ret = epoll_wait(epoll_fd, events, max_events, toset_nearest_expiry(&tos));
		if (ret == -1) {
			if (errno != EINTR)
				LOG(LOG_WARNING, "epoll_wait: %m");
			if (flag_quit)
				break;
			if (flag_print_sockets) {
				flag_print_sockets = 0;
				print_sockets(-1, -1);
			}
			continue;
		}
		size_t nevts = (size_t)ret;
		for (size_t i = 0; i < nevts; i++) {
			struct socket *s = events[i].data.ptr;
			if (events[i].events & EPOLLIN)
				s->ops->pollin(s);
			if (events[i].events & EPOLLOUT)
				s->ops->pollout(s);
			if (events[i].events & EPOLLHUP)
				s->ops->pollhup(s);

			/* TODO poll on a pipe to handle signals instead */
			if (flag_quit)
				break;
			if (flag_print_sockets) {
				flag_print_sockets = 0;
				print_sockets(-1, -1);
			}
				
		}
		toset_check_expired(&tos);
	}

	if (flag_quit) {
		ret = 0;
		list_walk(sockets, n) {
			struct socket *s = container_of(n, struct socket, n);
			destroy_socket(s);
		}
	}

	toset_free(&tos);
	tls_srv_free(&tls);
	objpool_free(&socket_pool);
	fdapd_cfg_free(&cfg);
	storage_destroy(stor);
	return ret;
}
