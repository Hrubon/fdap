#include "socket.h"
#include <assert.h>
#include <err.h>
#include <netdb.h>

#define SOCKID_MAX		64
#define SOCKNAME_MAX		16
#define SERVNAME_MAX		16
#define PRTBUF_LEN		256
#define UNKNOWN			"<unknown>"

static char sockid[SOCKID_MAX];
static char socket_print_buf[PRTBUF_LEN];

const char *stroper(enum fdap_oper oper)
{
	switch (oper) {
	case FDAP_AUTH:
		return "AUTH";
	case FDAP_SEARCH:
		return "SEARCH";
	case FDAP_CREATE:
		return "CREATE";
	case FDAP_UPDATE:
		return "UPDATE";
	case FDAP_DELETE:
		return "DELETE";
	default:
		assert(0);
	}
}

static const char *socket_id(struct socket *s)
{
	char sockname[SOCKNAME_MAX];
	char servname[SERVNAME_MAX];
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	if (s->mode == SM_LISTEN) {
		if (getsockname(s->fd, (struct sockaddr *)&addr, &len) == -1)
			return UNKNOWN;
	} else {
		if (getpeername(s->fd, (struct sockaddr *)&addr, &len) == -1)
			return UNKNOWN;
	}
	int ret;
	if (s->transport == ST_UNIX) {
		if (len == sizeof(sa_family_t))
			return UNKNOWN;
		strncpy(sockid, addr.sun_path, SOCKID_MAX);
	} else {
		if ((ret = getnameinfo((struct sockaddr *)&addr, len,
			sockname, SOCKNAME_MAX, servname, SERVNAME_MAX, NI_NUMERICHOST)) == -1)
			errx(1, "%s", gai_strerror(ret));
		strncpy(sockid, sockname, SOCKID_MAX);
		strncat(sockid, ":", SOCKID_MAX - 1);
		strncat(sockid, servname, SOCKID_MAX - 1);
	}
	return sockid;
}

static const char *strtrans(char trans)
{
	switch (trans) {
	case ST_TCP:
		return "TCP";
	case ST_UNIX:
		return "UNIX";
	default:
		return UNKNOWN;
	}
}

static const char *strmode(char mode)
{
	switch (mode) {
	case SM_LISTEN:
		return "LISTEN";
	case SM_FDAPC:
		return "CLIENT";
	case SM_DSTREAM:
		return "PEER";
	default:
		return UNKNOWN;
	}
}

char *print_socket(struct socket *s)
{
	snprintf(socket_print_buf, sizeof(socket_print_buf), "%s\t%s\t%s\t%s",
		strtrans(s->transport), strmode(s->mode),
		s->use_tls ? "TLS" : "", socket_id(s));
	return socket_print_buf;
}
