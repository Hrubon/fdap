#ifndef FDAPD_CONFIG_H
#define FDAPD_CONFIG_H

#include <stdbool.h>
#include <unistd.h>
#include "mempool.h"
#include "socket.h"

char *autodetect_cacert_path(void);

/*
 * Client socket configuration
 */
struct csock_cfg
{
	enum socktrans trans;		/* socket underlaying transport protocol */
	enum sockmode mode;		/* which kind of traffic should the socket handle */
	bool use_tls;			/* whether to TLS layer above the transport */
	char *host;			/* IP address or hostname */
	char *port;			/* TCP port */
	char *path;			/* file-name for Unix-domain sockets */
	char *cacert_path;		/* path to the CA certificate chain file (system CA store) */
	bool tls_skip_vrf;		/* whether to skip server certificate verification at all */
	bool tls_skip_cn_vrf;        	/* whether to skip hostname verification against cert. CN */
};

/*
 * FDAP Client configuration
 */
struct fdapc_cfg
{
	struct mempool strpool;		/* mempool for strings contained in cfg */
	struct csock_cfg *socks;	/* configuration of client socket */
};


/*
 * Client config operations
 */
void csock_cfg_init(struct csock_cfg *cfg);
void fdapc_cfg_init(struct fdapc_cfg *cfg);
struct csock_cfg *fdapc_cfg_new_csock(struct fdapc_cfg *cfg);
void fdapc_cfg_free(struct fdapc_cfg *cfg);

int fdapc_cfg_parse_file(struct fdapc_cfg *cfg, const char *filename);



/*
 * Listening socket configuration 
 */
struct lsock_cfg
{
	enum socktrans trans;		/* socket underlaying transport protocol */
	enum sockmode mode;		/* which kind of traffic should the socket handle */
	bool use_tls;			/* whether to TLS layer above the transport */
	char *host;			/* IP address or hostname */
	char *port;			/* TCP port */
	char *path;			/* file-name for Unix-domain sockets */
	size_t limit;			/* maximum allowed number of simultaneously connected clients */
};

/*
 * FDAP Daemon configuration
 */
struct fdapd_cfg
{
	struct mempool strpool;		/* mempool for strings contained in cfg */
	char *cacert_path;		/* path to the CA certificate chain file (system CA store) */
	char *srvcert_path;		/* path to the server certificate chain file used for TLS */
	char *pk_path;			/* path to the server private key file that corresponds to the TLS certificate */
	char *pk_pwd;			/* password to decrpyt private key file */
	char *stor_path;		/* path to the directory file storage */
	bool init_tls;			/* whether to init TLS module or not */
	size_t nsocks;			/* number of sockets in configuration */
	struct lsock_cfg *socks;	/* configuration of listening sockets */
};

/*
 * Daemon config operations
 */
void lsock_cfg_init(struct lsock_cfg *cfg);
void fdapd_cfg_init(struct fdapd_cfg *cfg);
struct lsock_cfg *fdapd_cfg_new_lsock(struct fdapd_cfg *cfg);
void fdapd_cfg_free(struct fdapd_cfg *cfg);

int fdapd_cfg_parse_file(struct fdapd_cfg *cfg, const char *filename);


#endif
