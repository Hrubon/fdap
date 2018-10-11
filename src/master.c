#include <err.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t min_workers = 4;
static size_t max_workers = 8;
static size_t nworkers;
static int epoll_fd;
static sig_atomic_t flag_sigusr1;

/*
 * Worker contains information about a worker process.
 */
struct worker
{
	pid_t pid;	/* PID of the worker process */
	int fd;		/* one end of the UNIX socket pair */
};

enum
{
	MSG_TERM,	/* termination request */
	MSG_STATS,	/* message with worker statistics */
	MSG_ACCEPT,	/* accept new client */
	MSG_UPDATE,	/* update a document */
	MSG_CREATE,	/* create a document */
	MSG_DELETE,	/* delete a document */
	MSG_SEARCH,	/* start a search operation */
	MSG_RESITER,	/* iterate through search results */
};

struct ipchdr
{
	size_t len;
	char type;
};

struct ipcmsg
{
	struct ipchdr hdr;
};

struct stats
{
	pid_t pid;
};

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGUSR1:
		flag_sigusr1 = 1;
	}
}

static void setup_signals(void)
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = signal_handler;
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		err(EXIT_FAILURE, "sigaction");
}

static int worker_main(int fd)
{
	(void) fd;
	printf("Worker starting, PID=%i\n", getpid());
	sleep(5);
	struct ipchdr hdr;
	write(fd, &hdr, sizeof(hdr));
	sleep(5);
	printf("Worker terminating, PID=%i\n", getpid());
	return 0;
}

static void print_worker_stats(void)
{
	//for (size_t i = 0; i < nworkers; i++)
	//	printf("Worker, PID=%i, fd=%i\n", workers[i].pid, workers[i].fd);
}

/*
 * Spawn a new worker and configure the epoll device to receive events for it.
 */
static void spawn_worker(void)
{
	int fds[2];
	int nevents = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (nevents == -1)
		err(EXIT_FAILURE, "socketpair");
	pid_t pid = fork();
	if (pid == -1)
		err(EXIT_FAILURE, "fork");
	if (pid == 0) {
		close(fds[0]);
		exit(worker_main(fds[1]));
	}
	close(fds[1]);
	struct worker *worker = malloc(sizeof(worker));
	worker->pid = pid;
	worker->fd = fds[0];
	struct epoll_event ev = (struct epoll_event) {
		.events = EPOLLRDHUP | EPOLLIN | EPOLLET,
		.data.ptr = worker,
	};
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, worker->fd, &ev) == -1)
		err(EXIT_FAILURE, "epoll_ctl");
	nworkers++;
}

/*
 * Wait for the worker to exit and free it.
 */
static void collect_worker(struct worker *worker)
{
	if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, worker->fd, NULL) == -1)
		err(EXIT_FAILURE, "epoll_ctl");
	int status;
	if (waitpid(worker->pid, &status, WNOHANG) == -1)
		err(EXIT_FAILURE, "waitpid");
	printf("Worker down, PID=%i, status=%i\n", worker->pid, status);
	free(worker);
	assert(nworkers > 0);
	nworkers--;
}

static void recv_msg(struct worker *worker)
{
	struct ipchdr hdr;
	read(worker->fd, &hdr, sizeof(hdr));
	printf("Got message from worker, PID=%i\n", worker->pid);
}

int main(void)
{
	setup_signals();
	printf("Master process running, PID=%i\n", getpid());

	epoll_fd = epoll_create1(0);
	if (epoll_fd == -1)
		err(EXIT_FAILURE, "epoll_create");

	for (size_t i = 0; i < min_workers; i++)
		spawn_worker();
	print_worker_stats();

	size_t max_events = nworkers;
	struct epoll_event events[max_events];
	for (;;) {
		int nevents = epoll_wait(epoll_fd, events, max_events, 30000);
		if (nevents == -1) {
			if (errno != EINTR)
				err(EXIT_FAILURE, "epoll_wait");
			if (flag_sigusr1) {
				flag_sigusr1 = 0;
				spawn_worker();
			}
			continue;
		}
		for (size_t i = 0; i < nevents; i++) {
			struct worker *worker = events[i].data.ptr;
			if (events[i].events & EPOLLRDHUP)
				collect_worker(worker);
			else if (events[i].events & EPOLLIN)
				recv_msg(worker);
		}
	}

	close(epoll_fd);
	printf("Terminating master, PID=%i\n", getpid());
	return 0;
}
