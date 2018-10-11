#ifndef TLS_H
#define TLS_H

/*
 * TLS module. Provides an abstract API to encapsulate implementation
 * details of a specific TLS library. We use `mbedtls` as a TLS library.
 *
 * TLS module consists of three parts: Server, Client and Peer.
 * `tls_srv` structure with corresponding set of functions are intended
 * for use on server, and `tls_cli` on client. Both hold TLS-related
 * configuration, certificates, including functions that handles initialization
 * and TLS tunnel establishment. Both server and client have non-trivial
 * functionality in common, so `tls_ctx` structure represents the common core
 * with corresponding set of functions inside the module. This is just an internal
 * implementation detail that does not affect public API of the module.
 *
 * `tls_peer` structure represents a remote TLS end-point that is fully
 * initialized for encrypted communication (one end of a TLS tunnel).
 * On the client, `tls_peer` represents a server, whereas on the server, `tls_peer`
 * represents a client -- for each accepted TLS client one peer.
 * `tls_peer` is a product of `tls_srv_establish` function; `tls_cli_establish`
 * function, respectively. 
 */

#include <mbedtls/config.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/timing.h>
#include <stdbool.h>

#define MBEDTLS_CONFIG_FILE "src/include/mbedtls_config.h"


/*
 * TLS context (common core used by both the server and the client implementation).
 */
struct tls_ctx
{
	mbedtls_entropy_context entropy;	/* Entropy source used by mbedtls */
	mbedtls_ctr_drbg_context ctr_drbg;	/* Random generator used by mbedtls */
	mbedtls_ssl_config conf;		/* TLS configuration used by mbedtls */
};

/*
 * TLS server context.
 */
struct tls_srv
{
	struct tls_ctx tls;		/* Common TLS context used by both client and server */
	mbedtls_x509_crt srvcert;	/* Loaded TLS cert. chain
					   (CA cert. <-> CA immediate cert. <-> server cert.) */
	mbedtls_pk_context pkey;	/* Loaded private key to the server TLS cert. */
};

/*
 * TLS client context.
 */
struct tls_cli
{
	struct tls_ctx tls;		/* Common TLS context used by both client and server */
	mbedtls_x509_crt cacert;	/* Loaded trusted CA certificates chain */
};


/*
 * TLS context per (accepted) client.
 */
struct tls_peer
{
	mbedtls_ssl_context ssl;	/* per client context -- product of a TLS handshake */
};



/*
 * A return value of several TLS functions.
 * 0 indicates success, failure otherwise.
 */
typedef int tls_err_t;



/*
 * Initialize server-side TLS context.
 */
void tls_srv_init(struct tls_srv *ctx);

/*
 * Configure server TLS context with `cacert_path`, `srvcert_path`
 * and `pk_path` to be ready to use.
 *
 * If the private key file is protected by password, `pk_pwd` can be supplied to decrypt the file.
 * Can be NULL if the decryption is not desirable.
 */
tls_err_t tls_srv_config(struct tls_srv *ctx, const char *cacert_path, const char *srvcert_path, const char *pk_path, const char *pk_pwd);

/*
 * Reseed server random generator used by TLS core.
 * It is recommended to call this function after each fork in parent
 * if the server TLS context is inherited by children.
 */
tls_err_t tls_srv_reseed(struct tls_srv *ctx);

/*
 * Perform TLS handshake with the remote peer identified by `peer_fd`
 * and establish a TLS tunnel.
 *
 * `peer_fd` file descriptor can be obtained for example by `accept` function.
 * If the handshake is successful, the remote peer, represented by supplied
 * `pctx` argument, is ready to use for encrypted communication.
 */
tls_err_t tls_srv_establish(struct tls_srv *ctx, int *peer_fd, struct tls_peer *pctx);

/*
 * Free resources associated with the TLS context structure.
 */
void tls_srv_free(struct tls_srv *ctx);



/*
 * Initialize client-side TLS context.
 */
void tls_cli_init(struct tls_cli *ctx);

/*
 * Configure client TLS context with CA cert. path to be ready to use.
 */
tls_err_t tls_cli_config(struct tls_cli *ctx, const char *cacert_path);

/*
 * Perform TLS handshake with the remote peer identified by `peer_fd`
 * and establish a TLS tunnel.
 *
 * `peer_fd` file descriptor can be obtained for example
 * by `connect` function. If the handshake is successful, the remote peer, represented by supplied
 * `pctx` argument, is ready to use for encrypted communication.
 *
 * If `verify_srvcert` is set to `true`, a server certificate, that is presented
 * by a server during the handshake, will be verified against trusted CA certificates,
 * configured by previous call to `tls_cli_config` function. The authority that signed
 * the certificate must have a certificate in a trusted CA root file in order to be TLS
 * handshake successful.
 *
 * If `verify_hostname` is set to `true`, a server common name (CN) field in a server
 * certificate will be verified against `hostname` supplied in the next argument.
 * It is the recommended option, to turn this on, and supply valid hostname of the server.
 * However, it can be sometimes useful to turn this off; for example when connecting to an
 * IP address of the server, instead of a hostname.
 */
tls_err_t tls_cli_establish(struct tls_cli *ctx, int *peer_fd, struct tls_peer *pctx, bool verify_srvcert, bool verify_hostname, char *hostname);

/*
 * Free resources associated with the TLS context structure.
 */
void tls_cli_free(struct tls_cli *ctx);



/*
 * Read at most `len` data bytes from TLS peer `ctx` and decrypt them to buffer `buf`.
 * The real number of read bytes is returned.
 */
int tls_peer_read(struct tls_peer *ctx, unsigned char *buf, size_t len);

/*
 * Try to write exactly `len` data bytes from buffer `buf` to TLS peer `ctx` and encrypt them.
 * The real number of written bytes is returned.
 */
int tls_peer_write(struct tls_peer *ctx, const unsigned char *buf, size_t len);

/*
 * Notify the remote peer that the TLS tunnel is going to be closed.
 * Note, that this does not close the underlying transport connection (e.g. TCP).
 */
void tls_peer_free(struct tls_peer *ctx);

#endif

