#include "iobuf.h"
#include "iobuf.h"
#include "log.h"
#include "tls.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CLI_INIT_SEED "7c658a8e-3b12-484b-91e2-29a63c46f420"
#define SRV_INIT_SEED "644baef0-56ac-427e-ba45-36ea0fe87755"
#define SRV_SEED "6236a726-2f7b-4b63-863a-84688ab03ca9"
#define PEER_SEED "76adccb0-a966-4560-9cf3-92178018696c"


/******************************** TLS common functions ********************************/

static void tls_init(struct tls_ctx *ctx)
{
	mbedtls_entropy_init(&ctx->entropy);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
	mbedtls_ssl_config_init(&ctx->conf);
}


static tls_err_t tls_seed(struct tls_ctx *ctx, const char *seed)
{
	LOG(LOG_DEBUG, "Initial seeding of the random generator");
	const unsigned char *seed2 = (const unsigned char*)seed;
	int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
		seed2, strlen(seed));
	if (ret != 0) {
		LOG(LOG_ERR, "Unable to set seed to random generator");
		LOGF(LOG_DEBUG, "mbedtls_ctr_drbg_seed returned %d (0x%04X)", ret, ret);
		return -1;
	}
	return 0;
}


static tls_err_t tls_reseed(struct tls_ctx *ctx, const char *seed)
{
	LOG(LOG_DEBUG, "Reseeding of the random generator");
	const unsigned char *seed2 = (const unsigned char*)seed;
	int ret = mbedtls_ctr_drbg_reseed(&ctx->ctr_drbg, seed2, strlen(seed));
	if (ret != 0) {
		LOG(LOG_ERR, "Unable to reseed random generator");
		LOGF(LOG_DEBUG, "mbedtls_ctr_drbg_reseed returned %d (0x%04X)", ret, ret);
		return -1;
	}
	return 0;
}

static void tls_log(void *ctx, int level, const char *file, int line, const char *str)
{
	(void) ctx;
	(void) file;
	(void) line;
	int slog_level;
	switch (level) {
	case MBEDTLS_DBG_LEVEL_ERROR:
		slog_level = LOG_ERR;
		break;
	case MBEDTLS_DBG_LEVEL_STATE_CHANGE:
		slog_level = LOG_INFO;
		break;
	default:
		slog_level = LOG_DEBUG;
		break;
	}
	LOG(slog_level, (char *)str);
}

static tls_err_t tls_config(struct tls_ctx *ctx, int endpoint_type)
{
	LOG(LOG_DEBUG, "Configuring TLS");
	int ret = mbedtls_ssl_config_defaults(&ctx->conf,
		endpoint_type,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		LOG(LOG_ERR, "Unable to configure TLS defaults");
		LOGF(LOG_DEBUG, "mbedtls_ssl_config_defaults returned %d (0x%04X)", ret, ret);
		return -1;
	}
	mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
	mbedtls_ssl_conf_dbg(&ctx->conf, tls_log, NULL);
	mbedtls_debug_set_threshold(MBEDTLS_DBG_TARGET_LEVEL);
	return 0;
}

static int fd_from_ctx(void *ctx)
{
	return *((int *)ctx);
}

static int net_send(void *ctx, const unsigned char *buf, size_t len)
{
	return write(fd_from_ctx(ctx), buf, len);
}

static int net_recv(void *ctx, unsigned char *buf, size_t len)
{
	return read(fd_from_ctx(ctx), buf, len);
}

static tls_err_t tls_establish(struct tls_ctx *ctx, int *peer_fd, struct tls_peer *pctx)
{
	int ret;
	/* Apply configuration on the TLS context */
	if ((ret = mbedtls_ssl_setup(&pctx->ssl, &ctx->conf)) != 0) {
		LOG(LOG_ERR, "Unable to apply TLS configuration");
		LOGF(LOG_DEBUG, "mbedtls_ssl_setup returned %d (0x%04X)", ret, ret);
		goto out;
	}
	/* Setup underlying TLS bi-directional IO callbacks */
	mbedtls_ssl_set_bio(&pctx->ssl, peer_fd, net_send, net_recv, NULL);
	/* Perform TLS handshake */
	LOG(LOG_INFO, "Performing the SSL/TLS handshake");
	while ((ret = mbedtls_ssl_handshake(&pctx->ssl)) != 0) {
		LOG(LOG_ERR, "SSL/TLS handshake failed");
		LOGF(LOG_DEBUG, "mbedtls_ssl_handshake returned %d (0x%04X)", ret, ret);
		goto out;
	}
	LOG(LOG_INFO, "TLS tunnel established");
	return 0;
out:
	mbedtls_ssl_free(&pctx->ssl);
	return -1;
}

static void tls_free(struct tls_ctx *ctx)
{
	mbedtls_entropy_free(&ctx->entropy);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_ssl_config_free(&ctx->conf);
}


/******************************** TLS client functions ********************************/

void tls_cli_init(struct tls_cli *ctx)
{
	tls_init(&ctx->tls);
	mbedtls_x509_crt_init(&ctx->cacert);
}


tls_err_t tls_cli_config(struct tls_cli *ctx, const char *cacert_path)
{
	int ret;
	if (tls_seed(&ctx->tls, CLI_INIT_SEED) < 0)
		return -1;
	if (tls_config(&ctx->tls, MBEDTLS_SSL_IS_CLIENT) < 0)
		return -1;
	/* Setup CA certificates */
	if (cacert_path == NULL) {
		LOG(LOG_NOTICE, "Using embedded testing CA cert");
		ret = mbedtls_x509_crt_parse(&ctx->cacert, (const unsigned char*)mbedtls_test_cas_pem,
			mbedtls_test_cas_pem_len);
		if (ret != 0) {
			LOG(LOG_ERR, "Unable to parse built-in (mbedtls) CA certificate");
			LOGF(LOG_DEBUG, "mbedtls_x509_crt_parse returned %d (0x%04X).", ret, ret);
			return ret;
		}
		/* Because of invalid certificate hash in mbedtls test certificate */
		mbedtls_ssl_conf_authmode(&ctx->tls.conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	}
	else {
		LOGF(LOG_DEBUG, "Loading the CA cert from file '%s'", cacert_path);
		ret = mbedtls_x509_crt_parse_file(&ctx->cacert, cacert_path);
		if (ret != 0) {
			LOG(LOG_ERR, "Unable to parse CA certificate file");
			LOGF(LOG_DEBUG, "mbedtls_x509_crt_parse_file returned %d (0x%04X).", ret, ret);
			return ret;
		}
		mbedtls_ssl_conf_authmode(&ctx->tls.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		LOGF(LOG_INFO, "CA certificates loaded from file '%s'", cacert_path);
	}
	mbedtls_ssl_conf_ca_chain(&ctx->tls.conf, &ctx->cacert, NULL); // TODO: Revocation list?
	LOG(LOG_DEBUG, "TLS module successfully configured.");
	return 0;
}


tls_err_t tls_cli_establish(struct tls_cli *ctx, int *peer_fd, struct tls_peer *pctx, bool verify_srvcert, bool verify_hostname, char *hostname)
{
	int ret;

	mbedtls_ssl_init(&pctx->ssl);
	if (!verify_srvcert) {
		mbedtls_ssl_conf_authmode(&ctx->tls.conf, MBEDTLS_SSL_VERIFY_NONE);
	} else if (verify_hostname) {
		ret = mbedtls_ssl_set_hostname(&pctx->ssl, hostname);
		if (ret != 0) {
			LOG(LOG_ERR, "Setting server hostname failed.");
			return -1;
		}
	}

	ret = tls_establish(&ctx->tls, peer_fd, pctx);
	if (ret < 0) {
		if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
			ret = mbedtls_ssl_get_verify_result(&pctx->ssl);
			if (ret != 0) {
				char vrfy_buf[512];
				mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", ret);
				LOGF(LOG_ERR, "Server certificate verification failed:\n%s", vrfy_buf);
			}
		}
		return -1;
	}

	return 0;
}


void tls_cli_free(struct tls_cli *ctx)
{
	tls_free(&ctx->tls);
	mbedtls_x509_crt_free(&ctx->cacert);
}


/******************************** TLS server functions ********************************/

void tls_srv_init(struct tls_srv *ctx)
{
	tls_init(&ctx->tls);
	mbedtls_x509_crt_init(&ctx->srvcert);
	mbedtls_pk_init(&ctx->pkey);
}


tls_err_t tls_srv_config(struct tls_srv *ctx, const char *cacert_path, const char *srvcert_path, const char *pk_path, const char *pk_pwd)
{
	int ret;
	if (tls_seed(&ctx->tls, SRV_INIT_SEED) < 0)
		return -1;
	if (tls_config(&ctx->tls, MBEDTLS_SSL_IS_SERVER) < 0)
		return -1;
	/* Setup CA certificates, server certificate and private key */
	if (cacert_path == NULL || srvcert_path == NULL || pk_path == NULL) {
		LOG(LOG_NOTICE, "Using embedded testing server certificate and key");
		ret = mbedtls_x509_crt_parse(&ctx->srvcert, (const unsigned char*)mbedtls_test_srv_crt, mbedtls_test_srv_crt_len);
		if (ret != 0) {
			LOG(LOG_ERR, "Unable to load mbedtls CA certificate");
			LOGF(LOG_DEBUG, "mbedtls_x509_crt_parse returned %d (0x%04X).", ret, ret);
			return -1;
		}
		ret = mbedtls_x509_crt_parse(&ctx->srvcert, (const unsigned char*)mbedtls_test_cas_pem,
			mbedtls_test_cas_pem_len);
		if (ret != 0) {
			LOG(LOG_ERR, "Unable to load mbedtls server certificate");
			LOGF(LOG_DEBUG, "mbedtls_x509_crt_parse returned %d (0x%04X).", ret, ret);
			return -1;
		}
		ret =  mbedtls_pk_parse_key(&ctx->pkey, (const unsigned char*)mbedtls_test_srv_key,
			mbedtls_test_srv_key_len, NULL, 0);
		if (ret != 0) {
			LOG(LOG_ERR, "Unable to load mbedtls server private key");
			LOGF(LOG_DEBUG, "mbedtls_pk_parse_key returned %d (0x%04X).", ret, ret);
			return -1;
		}
	}
	else {
		LOG(LOG_DEBUG, "Loading the server certificate and key");
		ret = mbedtls_x509_crt_parse_file(&ctx->srvcert, srvcert_path);
		if (ret != 0) {
			LOG(LOG_ERR, "Unable to parse CA certificates file");
			LOGF(LOG_DEBUG, "mbedtls_x509_crt_parse_file returned %d (0x%04X).", ret, ret);
			return -1;
		}
		ret = mbedtls_x509_crt_parse_file(&ctx->srvcert, cacert_path);
		if (ret != 0) {
			LOG(LOG_ERR, "Unable to parse server certificate file");
			LOGF(LOG_DEBUG, "mbedtls_x509_crt_parse_file returned %d (0x%04X).", ret, ret);
			return -1;
		}
		LOGF(LOG_INFO, "CA certificates loaded from file '%s'", cacert_path);
		ret = mbedtls_pk_parse_keyfile(&ctx->pkey, pk_path, pk_pwd);
		if (ret != 0) {
			LOG(LOG_ERR, "Unable to parse server private key file");
			LOGF(LOG_DEBUG, "mmbedtls_pk_parse_keyfile returned %d (0x%04X).", ret, ret);
			return -1;
		}
		LOGF(LOG_INFO, "Server certificate loaded from '%s'", srvcert_path);
		LOGF(LOG_INFO, "Server key loaded from '%s'", pk_path);
	}
	mbedtls_ssl_conf_ca_chain(&ctx->tls.conf, ctx->srvcert.next, NULL); // TODO: Revocation list?
	ret = mbedtls_ssl_conf_own_cert(&ctx->tls.conf, &ctx->srvcert, &ctx->pkey);
	if (ret != 0) {
		LOG(LOG_ERR, "Unable to apply server certificate on TLS configuration");
		LOGF(LOG_DEBUG, "mbedtls_ssl_conf_own_cert returned %d (0x%04X).", ret, ret);
		return -1;
	}
	return 0;
}


tls_err_t tls_srv_reseed(struct tls_srv *ctx)
{
	return tls_reseed(&ctx->tls, SRV_SEED);
}


tls_err_t tls_srv_establish(struct tls_srv *ctx, int *peer_fd, struct tls_peer *pctx)
{
	mbedtls_ssl_init(&pctx->ssl);
	if (tls_reseed(&ctx->tls, PEER_SEED) < 0)
		return -1;
	if (tls_establish(&ctx->tls, peer_fd, pctx) < 0)
		return -1;
	return 0;
}


void tls_srv_free(struct tls_srv *ctx)
{
	tls_free(&ctx->tls);
	mbedtls_x509_crt_free(&ctx->srvcert);
	mbedtls_pk_free(&ctx->pkey);
}


/******************************** TLS I/O wrapper functions ********************************/

int tls_peer_read(struct tls_peer *ctx, unsigned char *buf, size_t len)
{
	int ret = mbedtls_ssl_read(&ctx->ssl, buf, len);
	if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		return 0;
	return ret;
}

int tls_peer_write(struct tls_peer *ctx, const unsigned char *buf, size_t len)
{
	return mbedtls_ssl_write(&ctx->ssl, buf, len);
}

void tls_peer_free(struct tls_peer *ctx)
{
	mbedtls_ssl_close_notify(&ctx->ssl);
	mbedtls_ssl_free(&ctx->ssl);
}
