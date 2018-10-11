#include <assert.h>
#include <string.h>
#include "cfg.h"
#include "log.h"

int main(void)
{
	struct fdapd_cfg cfg;
	int ret;

	ret = fdapd_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapd1.conf");
	assert(ret == 0);
	assert(!strcmp(cfg.cacert_path, "/etc/certs.ber"));
	assert(!strcmp(cfg.srvcert_path, "/etc/fdapd/srv.ber"));
	assert(!strcmp(cfg.pk_path, "/etc/fdapd/key"));
	assert(!strcmp(cfg.pk_pwd, "ffs349sq"));
	assert(cfg.init_tls);
	assert(cfg.socks[0].trans == ST_TCP);
	assert(cfg.socks[0].use_tls);
	assert(!strcmp(cfg.socks[0].host, "fdap.mff.cuni.cz"));
	assert(!strcmp(cfg.socks[0].port, "2243"));
	assert(cfg.socks[0].limit == 15);
	assert(cfg.socks[1].trans == ST_TCP);
	assert(!cfg.socks[1].use_tls);
	assert(!strcmp(cfg.socks[1].host, "10.0.0.7"));
	assert(!strcmp(cfg.socks[1].port, "2244"));
	assert(cfg.socks[1].limit == 10); // which is default value
	assert(cfg.socks[2].trans == ST_UNIX);
	assert(!strcmp(cfg.socks[2].path, "/var/run/fdapd/fdapd.sock"));
	assert(cfg.socks[2].limit == 20);
	fdapd_cfg_free(&cfg);

	ret = fdapd_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapd2.conf");
	assert(ret != 0);
	fdapd_cfg_free(&cfg);

	ret = fdapd_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapd3.conf");
	assert(ret != 0);
	fdapd_cfg_free(&cfg);
	
	ret = fdapd_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapd4.conf");
	assert(ret != 0);
	fdapd_cfg_free(&cfg);

	ret = fdapd_cfg_parse_file(&cfg, "./tests/cfg/conf/fdapd5.conf");
	assert(ret != 0);
	fdapd_cfg_free(&cfg);

	return EXIT_SUCCESS;
}
