#include "debug.h"
#include "iobuf.h"
#include "log.h"
#include "memory.h"
#include "tls.h"
#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>

#define BUF_SIZE	137
#define DATA_LEN	10213
#define TLS_CA_PATH	"./tests/iobuf/tls/ca.cert.pem"
#define TLS_CERT_PATH	"./tests/iobuf/tls/srv.cert.pem"
#define TLS_KEY_PATH	"./tests/iobuf/tls/srv.key.pem"
#define TLS_PWD		"qwerty123"

static void *random_data(void) 
{
	srandom(time(NULL));
	byte_t *data = fdap_malloc(DATA_LEN);
	for (size_t i = 0; i < DATA_LEN; i++)
		data[i] = random() % 256;
	return data;
}


static void test_w(struct iobuf *wr, byte_t *data)
{
	assert(iobuf_write(wr, data, DATA_LEN) == 0);
	assert(iobuf_flush(wr) == 0);
}

static void test_r(struct iobuf *rd, byte_t *data)
{
	byte_t *echo = fdap_malloc(DATA_LEN);
	assert(iobuf_read(rd, echo, DATA_LEN) == DATA_LEN);
	for (size_t i = 0; i < DATA_LEN; i++)
		assert(data[i] == echo[i]);
	free(echo);
}

/*
 * Write random data to `rd` and attempt to read the same data from `wr`.
 * If `rd` and `wr` are the same, then `rd` must support seeking.
 */
static void test_rw(struct iobuf *rd, struct iobuf *wr)
{
	byte_t *data = random_data();
	test_w(wr, data);
	if (rd == wr)
		iobuf_seek(rd, 0);
	test_r(rd, data);
	free(data);
}

static void test_peek(struct iobuf *rd, struct iobuf *wr)
{
	for (char c = 'a'; c < 'z'; c++)
		iobuf_write(wr, (byte_t *)&c, 1);
	iobuf_flush(wr);
	if (rd == wr)
		iobuf_seek(rd, 0);
	for (char c = 'a'; c < 'z'; c++) {
		fprintf(stderr, "%c\n", c);
		assert(iobuf_peek(rd) == c);
		assert(iobuf_peek(rd) == c); /* peeking twice gives same result */
		assert(iobuf_getc(rd) == c);
		iobuf_ungetc(rd);
		assert(iobuf_getc(rd) == c); /* also moves us forward one byte */
	}
}

static void test_iobuf_str(void)
{
	struct iobuf *str_buf = iobuf_str_new(BUF_SIZE);
	test_rw(str_buf, str_buf);
	iobuf_seek(str_buf, 0);
	test_peek(str_buf, str_buf);
	iobuf_destroy(str_buf);
}

static void test_iobuf_sock(void)
{
	int fds[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	struct iobuf *rd = iobuf_sock_new(fds[0], BUF_SIZE);
	struct iobuf *wr = iobuf_sock_new(fds[1], 2 * BUF_SIZE);
	test_rw(rd, wr);
	iobuf_destroy(rd);
	iobuf_destroy(wr);
}

static void test_iobuf_tls(void)
{
	byte_t *data = random_data();
	int fds[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
	signal(SIGCHLD, SIG_IGN);
	int pid = fork();

	if (pid == 0) {
		close(fds[0]);
		struct tls_cli tls_cli;
		struct tls_peer tls_peer;
		tls_cli_init(&tls_cli);
		tls_cli_config(&tls_cli, TLS_CA_PATH);
		tls_cli_establish(&tls_cli, &fds[1], &tls_peer, false, false, NULL);
		struct iobuf *tls_buf = iobuf_tls_new(&tls_peer, BUF_SIZE);
		test_w(tls_buf, data);
		iobuf_destroy(tls_buf);
		tls_peer_free(&tls_peer);
		tls_cli_free(&tls_cli);
	} else {
		close(fds[1]);
		struct tls_srv tls_srv;
		struct tls_peer tls_peer;
		tls_srv_init(&tls_srv);
		tls_srv_config(&tls_srv, TLS_CA_PATH, TLS_CERT_PATH, TLS_KEY_PATH, TLS_PWD);
		tls_srv_establish(&tls_srv, &fds[0], &tls_peer);
		struct iobuf *tls_buf = iobuf_tls_new(&tls_peer, BUF_SIZE);
		test_r(tls_buf, data);
		iobuf_destroy(tls_buf);
		tls_peer_free(&tls_peer);
		tls_srv_free(&tls_srv);
	}
	free(data);
}

int main(void)
{
	test_iobuf_str();
	test_iobuf_sock();
	test_iobuf_tls();
	return 0;
}
