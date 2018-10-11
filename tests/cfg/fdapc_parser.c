#include <assert.h>
#include <string.h>
#include "cfg.h"
#include "log.h"

int main(void)
{
	struct fdapc_cfg cfg;
	int ret;

	ret = fdapc_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapc1.conf");
	assert(ret == 0);
	assert(cfg.socks[0].trans == ST_TCP);
	assert(!strcmp(cfg.socks[0].host, "localhost"));
	assert(!strcmp(cfg.socks[0].port, "4433"));
	assert(cfg.socks[1].trans == ST_UNIX);
	assert(!strcmp(cfg.socks[1].path, "/var/run/fdap.sock"));
	assert(cfg.socks[2].trans == ST_TCP);
	assert(cfg.socks[2].use_tls);
	assert(!strcmp(cfg.socks[2].host, "10.28.10.1"));
	assert(!strcmp(cfg.socks[2].port, "443"));
	assert(!strcmp(cfg.socks[2].cacert_path, "/etc/xyz.pem"));
	assert(cfg.socks[2].tls_skip_cn_vrf);
	fdapc_cfg_free(&cfg);

	ret = fdapc_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapc2.conf");
	assert(ret == 0);
	assert(cfg.socks[0].trans == ST_TCP);
	assert(!strcmp(cfg.socks[0].host, "localhost"));
	assert(!strcmp(cfg.socks[0].port, "4433"));
	assert(cfg.socks[1].trans == ST_UNIX);
	assert(!strcmp(cfg.socks[1].path, "/var/run/fdap.sock"));
	assert(cfg.socks[2].trans == ST_TCP);
	assert(cfg.socks[2].use_tls);
	assert(!strcmp(cfg.socks[2].host, "fdap.gymlit.cz"));
	assert(!strcmp(cfg.socks[2].port, "443"));
	assert(cfg.socks[2].cacert_path != NULL);
	assert(!access(cfg.socks[2].cacert_path, F_OK));
	assert(!cfg.socks[2].tls_skip_cn_vrf);
	fdapc_cfg_free(&cfg);

	ret = fdapc_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapc3.conf");
	assert(ret != 0);
	fdapc_cfg_free(&cfg);

	ret = fdapc_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapc4.conf");
	assert(ret != 0);
	fdapc_cfg_free(&cfg);

	ret = fdapc_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapc5.conf");
	assert(ret != 0);
	fdapc_cfg_free(&cfg);

	ret = fdapc_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapc6.conf");
	assert(ret != 0);
	fdapc_cfg_free(&cfg);

	return EXIT_SUCCESS;
}
