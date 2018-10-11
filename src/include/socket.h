#ifndef SOCKET_H
#define SOCKET_H

#include "cbor.h"
#include "filter.h"
#include "list.h"
#include "request.h"
#include "tls.h"
#include "timeout.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/un.h>

enum socktrans
{
	ST_INVALID,
	ST_TCP,
	ST_UNIX,
};

enum sockmode
{
	SM_INVALID,
	SM_FDAPC,
	SM_DSTREAM,
	SM_LISTEN,
};

enum clistate
{
	C_IDLE,		/* the client's idle */
	C_INVALID,	/* the client entered invalid state */
	C_BUF,		/* buffering data to read request length */
	C_BUF_BODY,	/* request length is known, buffering request body */
	C_TX,		/* response is being sent */
};

/*
 * La Sockette.
 */
struct socket
{
	struct lnode n;			/* node in the list of all sockets */
	struct socket_ops *ops;		/* socket operations */
	struct tls_peer tls;		/* socket's TLS context */
	int fd;				/* file descriptor of the socket */
	uint16_t req_len;		/* announced length of client request */
	struct fdap_req req;		/* current FDAP request */
	struct fdap_resp resp;		/* current FDAP response */
	uint32_t events;		/* subscribed events */
	struct socket_ops *client_ops;	/* operations to set on accepted clients */
	struct iobuf *rx;		/* RX stream */
	struct iobuf *tx;		/* TX stream */
	struct cbor rx_cbor;		/* RX CBOR stream */
	struct cbor tx_cbor;		/* TX CBOR stream */
	char transport;			/* socket transport, see `enum socktrans` */
	char mode;			/* socket mode, see `enum sockmode` */
	char clistate;			/* client state */
	bool use_tls;			/* is TLS to be used? */
	struct to *tos[TO_TYPE_MAX];	/* vector of time-outs */
	bool auth;			/* is the connection authenticated? */
	bool admin;			/* has the connection admin rights? */
	fdap_id_t own_id;		/* FDAP id of the owned entry */
};

char *print_socket(struct socket *s);

struct socket_ops
{
	void (*setup)(struct socket *s);
	void (*pollin)(struct socket *s);
	void (*pollhup)(struct socket *s);
	void (*pollout)(struct socket *s);
	void (*teardown)(struct socket *s);
	void (*timeout)(struct socket *s, enum to_type type);
};

#endif
