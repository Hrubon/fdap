#include "socket.h"
#include "timeout.h"
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>

#define TEST_SIZE	512
#define USLEEP_DELAY	3000

struct to_test
{
	struct socket socket;		/* a dummy socket */
	expiry_t tos[TO_TYPE_MAX];	/* time-outs configured */
	bool recvd[TO_TYPE_MAX];	/* time-outs received */
};

static struct to_test tests[TEST_SIZE];

static void timeout(struct socket *s, enum to_type type)
{
	struct to_test *t = (struct to_test *)s;
	t->recvd[type] = true;
}

int main(void)
{
	struct toset tos;
	toset_init(&tos);
	toset_set_expiry(&tos, TO_IDLE, 100);
	toset_set_expiry(&tos, TO_RX, 200);
	assert(toset_nearest_expiry(&tos) == EXPIRY_MAX);

	struct socket_ops dummy_ops = {
		.timeout = timeout,
	};

	/* reset all dummy sockets */
	for (size_t i = 0; i < TEST_SIZE; i++) {
		tests[i].socket.ops = &dummy_ops;
		for (size_t type = 0; type < TO_TYPE_MAX; type++)
			tests[i].socket.tos[type] = NULL;
	}

	/* configure all time-outs */
	for (size_t i = 0; i < TEST_SIZE; i++)
		for (size_t type = 0; type < TO_TYPE_MAX; type++)
			toset_reset(&tos, &tests[i].socket, type);

	/* wait long enough for only TO_IDLE to expire */
	usleep(1000 * toset_nearest_expiry(&tos) + USLEEP_DELAY);
	toset_check_expired(&tos);

	for (size_t i = 0; i < TEST_SIZE; i++) {
		assert(tests[i].recvd[TO_IDLE]);
		tests[i].recvd[TO_IDLE] = false;
		assert(!tests[i].recvd[TO_RX]);
		assert(!tests[i].recvd[TO_TX]);
	}

	/* wait long enough for TO_RX to expire, too */
	usleep(1000 * toset_nearest_expiry(&tos) + USLEEP_DELAY);
	toset_check_expired(&tos);
	for (size_t i = 0; i < TEST_SIZE; i++) {
		assert(!tests[i].recvd[TO_IDLE]);
		assert(tests[i].recvd[TO_RX]);
		assert(!tests[i].recvd[TO_TX]);
	}

	toset_free(&tos);
}
