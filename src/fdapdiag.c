#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include "cfg.h"
#include "fdap.h"
#include "log.h"
#include "mempool.h"

#define STRBUF_INIT_SIZE	64
#define STRPOOL_INIT_SIZE	256
#define BANNER			"# FDAP diagnostics utility 0.0.1\n"

static char cur;
static bool instr;
static struct strbuf buf;
static struct mempool strpool;
static fdap_t fdap;

static void load_config(struct fdapc_cfg *cfg, int argc, char *argv[])
{
	if (argc < 3)
		LOG(LOG_ERR, "At least one option required");
	fdapc_cfg_init(cfg);
	struct csock_cfg *sock = fdapc_cfg_new_csock(cfg);
	sock->mode = SM_FDAPC;
	for (int i = 1; i < argc; i += 2) {
		if (argv[i][0] != '-' && argv[i][1] != '\0')
			LOG(LOG_ERR, "Option expected");
		if (i + 1 >= argc)
			LOG(LOG_ERR, "Option value missing");
		char *val = argv[i + 1];
		switch (argv[i][1]) {
		case 'c':
			fdapc_cfg_free(cfg);
			if (fdapc_cfg_parse_file(cfg, val) != 0) {
				LOG(LOG_ERR, "Config file parsing failed");
				exit(EXIT_FAILURE);
			}
			return;
		case 't':
			if (sock->trans != ST_INVALID)
				goto double_opt;
			if (strcmp(val, "tls") == 0) {
				sock->trans = ST_TCP;
				sock->use_tls = true;
			}
			else if (strcmp(val, "tcp") == 0)
				sock->trans = ST_TCP;
			else if (strcmp(val, "uds") == 0)
				sock->trans = ST_UNIX;
			else {
				LOGF(LOG_ERR, "Unknown transport type '%s'", val);
				exit(EXIT_FAILURE);
			}
			break;
		case 'h':
			if (sock->host)
				goto double_opt;
			sock->host = mempool_strdup(&cfg->strpool, val);
			break;
		case 'p':
			if (sock->port)
				goto double_opt;
			sock->port = mempool_strdup(&cfg->strpool, val);
			break;
		case 'P':
			if (sock->path)
				goto double_opt;
			sock->path = mempool_strdup(&cfg->strpool, val);
			break;
		case 'a':
			if (sock->cacert_path)
				goto double_opt;
			sock->cacert_path = mempool_strdup(&cfg->strpool, val);
			break;
		default:
			LOGF(LOG_ERR, "Unknown option '-%c'", argv[i][1]);
			exit(EXIT_FAILURE);
		}
	}
	if (!sock->cacert_path)
		sock->cacert_path = mempool_strdup(&cfg->strpool, autodetect_cacert_path());
	return;
double_opt:
	LOG(LOG_ERR, "Each option must be specified just once");
	exit(EXIT_FAILURE);
}

static bool eoc(char c)
{
	if (instr)
		return c == EOF;
	else
		return c == EOF || c == ';';
}

static void next(void)
{
	cur = getchar();
}

static void eat_ws(void)
{
	while (isspace(cur))
		next();
}

static bool tryc(char c)
{
	if (cur != c)
		return false;
	next();
	return true;
}

static bool require(char r)
{
	if (!tryc(r))
		errx(EXIT_FAILURE, "Expected '%c', got '%c'", r, cur);
	return true;
}

static void eat_rest(void)
{
	while (!tryc(';'))
		next();
}

static char *parse_str(void)
{
	eat_ws();
	strbuf_reset(&buf);
	bool quoted = tryc('\"');
	instr = true;
	bool have_delim = false;
	while (cur != EOF) {
		if ((quoted && tryc('\"')) || (!quoted && (isspace(cur) || cur == ';'))) {
			if (isspace(cur))
				next();
			have_delim = true;
			break;
		}
		tryc('\\');
		strbuf_putc(&buf, cur);
		next();
	}
	if (quoted && !have_delim) {
		LOG(LOG_ERR, "Unterminated string");
		return NULL;
	}
	instr = false;
	char *str = mempool_strdup(&strpool, strbuf_get_string(&buf));
	return str;
}

static char *parse_str_check(char *name)
{
	char *str = parse_str();
	if (str == NULL || strlen(str) == 0)
		errx(EXIT_FAILURE, "Parse error: %s is missing or empty", name);
	return str;
}

static long parse_ulong(void)
{
	char *str = parse_str();
	if (!str)
		return -1;
	char *e;
	long val = strtol(str, &e, 10);
	if (*e != '\0')
		return -1;
	return val;
}

static unsigned long parse_ulong_check(char *name)
{
	long u = parse_ulong();
	if (u < 0)
		errx(EXIT_FAILURE, "Parse error: %s is missing, empty or invalid", name);
	return u;
}

static void parse_cmd()
{
	char *cmd = parse_str();
	if (strcmp(cmd, "") == 0)
		return;
	enum fdap_oper op;
	char *username;
	char *password;
	char *entry;
	char *filter;
	long id;
	if (strcmp(cmd, "auth") == 0) {
		op = FDAP_AUTH;
		username = parse_str_check("username");
		password = parse_str_check("password");
	} else if (strcmp(cmd, "search") == 0) {
		op = FDAP_SEARCH;
		filter = parse_str_check("filter");
	} else if (strcmp(cmd, "get") == 0) {
		op = FDAP_GET;
		id = parse_ulong_check("id");
	} else if (strcmp(cmd, "create") == 0) {
		op = FDAP_CREATE;
		entry = parse_str_check("entry");
	} else if (strcmp(cmd, "update") == 0) {
		op = FDAP_UPDATE;
		id = parse_ulong_check("id");
		entry = parse_str_check("entry");
	} else if (strcmp(cmd, "delete") == 0) {
		op = FDAP_DELETE;
		id = parse_ulong_check("id");
	} else {
		LOGF(LOG_ERR, "Operation '%s' is not known, known operations: "
			"auth, create, delete, get, update, search", cmd);
		eat_rest();
		return;
	}

	eat_ws();
	if (cur != EOF && !tryc(';'))
		errx(EXIT_FAILURE, "Expected ; or EOF at the end of command");

	struct fdap_resp *resp;
	switch (op) {
	case FDAP_AUTH:
		resp = fdap_auth(fdap, username, password);
		break;
	case FDAP_SEARCH:
		resp = fdap_search(fdap, filter);
		break;
	case FDAP_GET:
		resp = fdap_get(fdap, id);
		break;
	case FDAP_CREATE:
		resp = fdap_create(fdap, entry);
		break;
	case FDAP_UPDATE:
		resp = fdap_update(fdap, id, entry);
		break;
	case FDAP_DELETE:
		resp = fdap_delete(fdap, id);
		break;
	default:
		assert(0);
	}
	if (!resp)
		return;

	printf("FDAP/%u %s\n", resp->result, fdap_strerr(resp->result));
	struct strbuf diag;
	strbuf_init(&diag, 512);
	for (struct record *r = iter_next(resp->results); r; r = iter_next(resp->results)) {
		struct cbor_item *item = record_to_item(r);
		strbuf_reset(&diag);
		cbor_item_dump(item, &diag);
		printf("%4u %4u\t%s\n", r->id, r->version, strbuf_get_string(&diag));
	}
	strbuf_free(&diag);
	fflush(stdout);
	printf("# No more results.\n\n");
	fdap_response_destroy(resp);
}

static void parse_cmds(void)
{
	strbuf_init(&buf, STRBUF_INIT_SIZE);
	fprintf(stderr, BANNER);
	instr = false;
	do {
		next();
		mempool_init(&strpool, STRPOOL_INIT_SIZE);
		parse_cmd();
		mempool_free(&strpool);
	} while (cur != EOF);
	strbuf_free(&buf);
}

int main(int argc, char *argv[])
{
	int ret;
	struct fdapc_cfg cfg;
	load_config(&cfg, argc, argv);
	fdap = fdap_open(&cfg);
	if (!fdap) {
		ret = EXIT_FAILURE;
		goto exit;
	}

	parse_cmds();
	ret = EXIT_SUCCESS;
exit:
	fdap_close(fdap);
	fdapc_cfg_free(&cfg);
	return ret;
}
