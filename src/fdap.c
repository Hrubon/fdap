#include "array.h"
#include "assert.h"
#include "cbor.h"
#include "cfg.h"
#include "diag.h"
#include "fdap.h"
#include "iter.h"
#include "log.h"
#include "memory.h"
#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define RX_BUF_SIZE		1024
#define TX_BUF_SIZE		2048

#define STRBUF_INIT_SIZE	64
#define STR_MAX_LEN		4096

#define CONF_DEFAULT_PATH	"/etc/fdap/fdapc.conf"

static bool tcp_connect(struct socket *s, const char *hostname, const char *port)
{
	int ret;
	struct addrinfo hints; 
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	struct addrinfo *head;
	if ((ret = getaddrinfo(hostname, port, &hints, &head)) != 0) {
		const char *err;
		if (ret == EAI_SYSTEM)
			err = strerror(errno);
		else
			err = gai_strerror(ret);
		LOGF(LOG_ERR, "Could not resolve server IP address to connect, error: %s", err);
		return false;
	}
	struct addrinfo *cur;
	for (cur = head; cur != NULL; cur = cur->ai_next) {
		s->fd = socket(cur->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (s->fd  == -1)
			continue;
		if (connect(s->fd, cur->ai_addr, cur->ai_addrlen) == -1) {
			close(s->fd);
			continue;
		}
		break;
	}
	freeaddrinfo(head);
	if (cur == NULL) {
		LOGF(LOG_ERR, "Could not connect to to the server via TCP, error %s", strerror(errno));
		return false;
	} else {
		LOGF(LOG_INFO, "TCP connection to server %s up", print_socket(s));
		return true;
	}
}

static bool unix_connect(struct socket *s, const char *path)
{
	struct sockaddr_un addr;
	memset(&addr, '\0', sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	if ((s->fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		LOGF(LOG_ERR, "Could not create a socket, error: %s", strerror(errno));
		return false;
	}
	if (connect(s->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(s->fd);
		LOGF(LOG_ERR, "Could not connect to the server via IPC, error: %s", strerror(errno));
		return false;
	}
	LOGF(LOG_INFO, "IPC connection to server %s up", print_socket(s));
	return true;
}

static bool start_tls(struct fdap_handle *h, struct csock_cfg *cfg)
{
	tls_cli_init(&h->tls);
	if (tls_cli_config(&h->tls, cfg->cacert_path) != 0)
		goto err;
	if (tls_cli_establish(&h->tls, &h->sock.fd, &h->sock.tls, 
		!cfg->tls_skip_vrf, !cfg->tls_skip_cn_vrf, cfg->host) != 0)
		goto err;
	LOGF(LOG_INFO, "TLS channel with server %s established", print_socket(&h->sock));
	return true;
err:
	tls_peer_free(&h->sock.tls);
	tls_cli_free(&h->tls);
	return false;

}

static bool start_socket(struct fdap_handle *h, struct csock_cfg *cfg)
{
	h->sock.transport = cfg->trans;
	h->sock.mode = cfg->mode;
	h->sock.clistate = C_IDLE;
	h->sock.use_tls = cfg->use_tls;
	switch (cfg->trans) {
	case ST_TCP:
		if (!tcp_connect(&h->sock, cfg->host, cfg->port))
			return false;
		break;
	case ST_UNIX:
		if (!unix_connect(&h->sock, cfg->path))
			return false;
		break;
	default:
		assert(0);
	}
	if (cfg->use_tls) {
		if (!start_tls(h, cfg))
			return false;
		h->sock.rx = iobuf_tls_new(&h->sock.tls, RX_BUF_SIZE);
		h->sock.tx = iobuf_tls_new(&h->sock.tls, TX_BUF_SIZE);
	} else {
		
		h->sock.rx = iobuf_sock_new(h->sock.fd, RX_BUF_SIZE);
		h->sock.tx = iobuf_sock_new(h->sock.fd, TX_BUF_SIZE);
	}
	cbor_init(&h->sock.rx_cbor, h->sock.rx, cbor_errh_default);
	cbor_init(&h->sock.tx_cbor, h->sock.tx, cbor_errh_default);
	return true;
}

static struct fdap_handle *new_handle(struct fdapc_cfg *cfg)
{
	assert(ARRAY_SIZE(cfg->socks) == 1);

	struct fdap_handle *h = fdap_malloc(sizeof(*h));
	int ret = start_socket(h, &cfg->socks[0]);
	if (ret != 0) {
		free(h);
		return NULL;
	}
	return h;
}

static void encode_entry(struct cbor *c, struct cbor_item *entry)
{
	if (entry->type != CBOR_TYPE_MAP) {
		fdap_err = FDAP_ERR_NOT_MAP;
		return;
	}
	cbor_write_item(c, entry);
}

static void encode_request(struct cbor *d, struct fdap_req *r)
{
	/* create a new temporary in-memory CBOR stream */
	struct iobuf *tmp = iobuf_str_new(701); // TODO
	struct cbor c;
	cbor_init(&c, tmp, d->errh);

	/* encode request into the temporary stream */
	cbor_write_u32(&c, r->oper);
	switch (r->oper) {
	case FDAP_AUTH:
		cbor_write_text(&c, r->auth.username);
		cbor_write_text(&c, r->auth.pwd);
		break;
	case FDAP_SEARCH:
		filter_encode(&r->filter, &c);
		break;
	case FDAP_GET:
		cbor_write_u32(&c, r->id);
		break;
	case FDAP_CREATE:
		encode_entry(&c, &r->entry);
		break;
	case FDAP_UPDATE:
		cbor_write_u32(&c, r->id);
		encode_entry(&c, &r->entry);
		break;
	case FDAP_DELETE:
		cbor_write_u32(&c, r->id);
		break;
	default:
		fdap_err = FDAP_ERR_NOT_IMPL;
		return;
	}

	iobuf_flush(tmp);
	iobuf_seek(tmp, 0);
	cbor_write_u64(d, iobuf_tell(tmp));
	if (iobuf_copy(d->buf, tmp) == -1)
		goto ioerr;
	cbor_free(&c);
	iobuf_destroy(tmp);
	if (iobuf_flush(d->buf) == -1)
		goto ioerr;
	return;
ioerr:
	fdap_err = FDAP_ERR_INTERNAL;
}

static struct fdap_resp *wait_response(struct socket *s, struct fdap_req *r)
{
	try {
		encode_request(&s->tx_cbor, r);
	} catch {
		fdap_err = FDAP_ERR_INTERNAL;
		fdap_request_free(r);
		return NULL;
	}
	struct fdap_resp *resp = fdap_malloc(sizeof(*resp));
	try {
		resp->result = cbor_read_u32(&s->rx_cbor);
	} catch {
		LOGF(LOG_ERR, "Error while decoding response code: %s",
			cbor_strerror(&s->rx_cbor));
		return NULL;
	}
	resp->results = iter_new_cbor(&s->rx_cbor);
	fdap_request_free(r);
	return resp;
}



/******************************** FDAP protocol public interface ********************************/

int fdap_err;

struct fdap_handle *fdap_open(struct fdapc_cfg *cfg)
{
	struct fdap_handle *h = fdap_malloc(sizeof(*h));
	for (size_t i = 0; i < ARRAY_SIZE(cfg->socks); i++) {
		if (start_socket(h, &cfg->socks[i]))
			return h;
		if (i != ARRAY_LAST_INDEX(cfg->socks))
			LOG(LOG_NOTICE, "Trying next upstream");
	}
	free(h);
	LOG(LOG_NOTICE, "Not connected to a server -- no reachable upstream");
	return NULL;
}

struct fdap_handle *fdap_open_file(const char *path)
{
	if (access(path, F_OK) == -1) {
		LOGF(LOG_ERR, "Cannot access configuration file '%s'", path);
		return NULL;
	}
	struct fdapc_cfg cfg;
	if (fdapc_cfg_parse_file(&cfg, path) != 0) {
		LOG(LOG_ERR, "Config file parsing failed");
		return NULL;
	}
	return fdap_open(&cfg);
}

struct fdap_handle *fdap_open_default(void)
{
	return fdap_open_file(CONF_DEFAULT_PATH);
}

struct fdap_handle *fdap_open_tls(char *host, char *port)
{
	struct fdapc_cfg cfg;
	cfg.socks = array_new(1, sizeof(*cfg.socks));
	cfg.socks[0].trans = ST_TCP;
	cfg.socks[0].host = host;
	cfg.socks[0].port = port;
	cfg.socks[0].cacert_path = autodetect_cacert_path();
	cfg.socks[0].tls_skip_vrf = false;
	cfg.socks[0].tls_skip_cn_vrf = false;
	
	return new_handle(&cfg);
}

struct fdap_handle *fdap_open_tcp(char *host, char *port)
{
	struct fdapc_cfg cfg;
	cfg.socks = array_new(1, sizeof(*cfg.socks));
	cfg.socks[0].trans = ST_TCP;
	cfg.socks[0].host = host;
	cfg.socks[0].port = port;
	
	return new_handle(&cfg);
}

struct fdap_handle *fdap_open_ipc(char *path)
{
	struct fdapc_cfg cfg;
	cfg.socks = array_new(1, sizeof(*cfg.socks));
	cfg.socks[0].trans = ST_UNIX;
	cfg.socks[0].path = path;

	return new_handle(&cfg);
}

static void print_filter(struct filter *f)
{
	struct strbuf buf;
	strbuf_init(&buf, STRBUF_INIT_SIZE);
	filter_dump(f, &buf);
	LOG(LOG_NOTICE, strbuf_get_string(&buf));
	strbuf_free(&buf);
}

static void print_diag(struct cbor_item *i)
{
	struct strbuf buf;
	strbuf_init(&buf, STRBUF_INIT_SIZE);
	cbor_item_dump(i, &buf);
	LOG(LOG_NOTICE, strbuf_get_string(&buf));
	strbuf_free(&buf);
}



struct fdap_resp *fdap_auth(fdap_t h, char *username, char *password)
{
	fdap_err = FDAP_OK;
	struct fdap_req req;
	req.oper = FDAP_AUTH;
	if (strlen(username) > STR_MAX_LEN || strlen(password) > STR_MAX_LEN) {
		fdap_err = FDAP_ERR_STR_TOO_LONG;
		return NULL;
	}
	req.auth.username = strdup(username);
	req.auth.pwd = strdup(password);
	return wait_response(&h->sock, &req);
}

struct fdap_resp *fdap_search(struct fdap_handle *h, char *filter, ...)
{
	fdap_err = FDAP_OK;
	struct fdap_req req;
	struct fdap_resp *resp;
	req.oper = FDAP_SEARCH;
	va_list va;
	va_start(va, filter);
	bool ret = filter_vbuild(&req.filter, filter, va);
	va_end(va);
	if (!ret) {
		fdap_err = FDAP_ERR_INVALID_FILTER;
		resp = NULL;
	} else {
		resp = wait_response(&h->sock, &req);
	}
	return resp;
}

struct fdap_resp *fdap_get(fdap_t h, fdap_id_t id)
{
	fdap_err = FDAP_OK;
	struct fdap_req req;
	req.oper = FDAP_GET;
	req.id = id;
	return wait_response(&h->sock, &req);
}

struct fdap_resp *fdap_create(fdap_t h, char *entry, ...)
{
	fdap_err = FDAP_OK;
	struct fdap_req req;
	req.oper = FDAP_CREATE;
	va_list va;
	va_start(va, entry);
	bool ret = diag_build(&req.entry, entry, va);
	va_end(va);
	if (!ret) {
		fdap_err = FDAP_ERR_INVALID_ENTRY;
		return NULL;
	}
	return wait_response(&h->sock, &req);
}

struct fdap_resp *fdap_update(fdap_t h, fdap_id_t id, char *entry, ...)
{
	fdap_err = FDAP_OK;
	struct fdap_req req;
	req.oper = FDAP_UPDATE;
	req.id = id;
	va_list va;
	va_start(va, entry);
	bool ret = diag_build(&req.entry, entry, va);
	va_end(va);
	if (!ret) {
		fdap_err = FDAP_ERR_INVALID_ENTRY;
		return NULL;
	}
	return wait_response(&h->sock, &req);
}

struct fdap_resp *fdap_delete(fdap_t h, fdap_id_t id)
{
	fdap_err = FDAP_OK;
	struct fdap_req req;
	req.oper = FDAP_DELETE;
	req.id = id;
	return wait_response(&h->sock, &req);
}

void fdap_close(struct fdap_handle *h)
{
	if (!h)
		return;
	cbor_free(&h->sock.tx_cbor);
	cbor_free(&h->sock.rx_cbor);
	iobuf_destroy(h->sock.rx);
	iobuf_destroy(h->sock.tx);
	if (h->sock.use_tls) {
		tls_peer_free(&h->sock.tls);
		tls_cli_free(&h->tls);
	}
	if (h->sock.transport == ST_TCP)
		shutdown(h->sock.fd, SHUT_RDWR);
	close(h->sock.fd);
	free(h);
}
