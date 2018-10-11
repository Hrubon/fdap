#ifndef FDAP_H
#define FDAP_H

/*
 * FDAP client library public API. Include this header file
 * in order to use FDAP on the client side.
 */

#include "cfg.h"
#include "cbor.h"
#include "request.h"
#include "socket.h"
#include "tls.h"


/*
 * Error code describing error state on client side.
 */
extern int fdap_err;

/*
 * Handle to FDAP protocol interface.
 */
struct fdap_handle
{
	struct socket sock;
	struct tls_cli tls;
};

typedef struct fdap_handle *fdap_t;

/*
 * FDAP protocol interface
 */


struct fdapc_cfg;

fdap_t fdap_open(struct fdapc_cfg *cfg);
fdap_t fdap_open_file(const char *path);
fdap_t fdap_open_default(void);
fdap_t fdap_open_tls(char *host, char *port);
fdap_t fdap_open_tcp(char *host, char *port);
fdap_t fdap_open_ipc(char *sun_path);
struct fdap_resp *fdap_auth(fdap_t h, char *username, char *password);
struct fdap_resp *fdap_search(fdap_t h, char *filter, ...);
struct fdap_resp *fdap_get(fdap_t h, fdap_id_t id);
struct fdap_resp *fdap_create(fdap_t h, char *entry, ...);
struct fdap_resp *fdap_update(fdap_t h, fdap_id_t id, char *entry, ...);
struct fdap_resp *fdap_delete(fdap_t h, fdap_id_t id);
void fdap_close(fdap_t h);

#endif
