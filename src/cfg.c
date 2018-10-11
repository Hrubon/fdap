#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include "string.h"
#include "array.h"
#include "cfg.h"

#include "debug.h"

#define CFG_MPOOL_BLOCK_SIZE 128
#define CSOCKS_INIT_SIZE 4
#define LSOCKS_INIT_SIZE 4
#define LSOCK_DEFAULT_LIMIT 10

static char* cacert_sys_paths[] = {
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/ssl/certs/ca-bundle.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/pki/tls/certs/ca-bundle.trust.crt",
	"/var/lib/ca-certificates/ca-bundle.pem"
};

char *autodetect_cacert_path(void)
{
	size_t len = sizeof(cacert_sys_paths) / sizeof(cacert_sys_paths[0]);
	for (size_t i = 0; i < len; i++) {
		if (access(cacert_sys_paths[i], F_OK) != -1)
			return cacert_sys_paths[i];
	}
	return NULL;
}

void csock_cfg_init(struct csock_cfg *cfg)
{
	cfg->trans = ST_INVALID;
	cfg->mode = SM_FDAPC;
	cfg->use_tls = false;
	cfg->host = NULL;
	cfg->port = NULL;
	cfg->path = NULL;
	cfg->cacert_path = NULL; 
	cfg->tls_skip_vrf = false;
	cfg->tls_skip_cn_vrf = false;
}

void fdapc_cfg_init(struct fdapc_cfg *cfg)
{
	mempool_init(&cfg->strpool, CFG_MPOOL_BLOCK_SIZE);
	cfg->socks = array_new(CSOCKS_INIT_SIZE, sizeof(*cfg->socks));
}

struct csock_cfg *fdapc_cfg_new_csock(struct fdapc_cfg *cfg)
{
	struct csock_cfg *sock = ARRAY_RESERVE(cfg->socks);
	csock_cfg_init(sock);
	return sock;
}

void fdapc_cfg_free(struct fdapc_cfg *cfg)
{
	mempool_free(&cfg->strpool);
	array_destroy(cfg->socks);
}

void lsock_cfg_init(struct lsock_cfg *cfg)
{
	cfg->trans = ST_INVALID;
	cfg->mode = SM_INVALID;
	cfg->use_tls = false;
	cfg->host = NULL;
	cfg->port = NULL;
	cfg->path = NULL;
	cfg->limit = LSOCK_DEFAULT_LIMIT;
}

void fdapd_cfg_init(struct fdapd_cfg *cfg)
{
	mempool_init(&cfg->strpool, CFG_MPOOL_BLOCK_SIZE);
	cfg->cacert_path = NULL;
	cfg->srvcert_path = NULL;
	cfg->pk_path = NULL;
	cfg->pk_pwd = NULL;
	cfg->init_tls = false;
	cfg->nsocks = 0;
	cfg->socks = array_new(LSOCKS_INIT_SIZE, sizeof(*cfg->socks));
}

struct lsock_cfg *fdapd_cfg_new_lsock(struct fdapd_cfg *cfg)
{
	struct lsock_cfg *sock = ARRAY_RESERVE(cfg->socks);
	lsock_cfg_init(sock);
	cfg->nsocks++;
	return sock;
}

void fdapd_cfg_free(struct fdapd_cfg *cfg)
{
	mempool_free(&cfg->strpool);
	array_destroy(cfg->socks);
}
