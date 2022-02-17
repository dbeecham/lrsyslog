// _GNU_SOURCE for pipe2()
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "lrsyslog.h"
#include "lrsyslog_tcp_task.h"
#include "lrsyslog_nats_task.h"


#define EPOLL_NUM_EVENTS 8

int lrsyslog_init (
    struct lrsyslog_s * lrsyslog
)
{

    int ret = 0;

    // main thread needs an epoll
    lrsyslog->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (-1 == lrsyslog->epoll_fd) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_create1: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // tcp threads also needs an epoll
    lrsyslog->tcp_task_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (-1 == lrsyslog->tcp_task_epoll_fd) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_create1: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // And the nats task needs an epoll
    lrsyslog->nats_task_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (-1 == lrsyslog->nats_task_epoll_fd ) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_create1: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // nats task and tcp tasks communicate using a pipe
    // lrsyslog->pipe_fd[0] contains the read-end of the pipe, lrsyslog->pipe_fd[1] contains the write-end.
    ret = pipe2(lrsyslog->pipe_fd, O_CLOEXEC | O_NONBLOCK);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: pipe2: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    ret = fcntl(lrsyslog->pipe_fd[0], F_SETPIPE_SZ, 1048576);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: fcntl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // nats task needs the pipe on it's epoll
    ret = epoll_ctl(
        lrsyslog->nats_task_epoll_fd,
        EPOLL_CTL_ADD,
        lrsyslog->pipe_fd[0],
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
            .data = {
                .fd = lrsyslog->pipe_fd[0]
            }
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // Main thread needs a filled sigset on a signalfd to react to signals
    sigset_t sigset = {0};
    ret = sigfillset(&sigset);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: sigfillset: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }


    // Create the signalfd
    lrsyslog->signal_fd = signalfd(
        /* fd = */ -1,
        /* &sigset = */ &sigset,
        /* flags = */ SFD_NONBLOCK | SFD_CLOEXEC
    );
    if (-1 == lrsyslog->signal_fd) {
        syslog(LOG_ERR, "%s:%d:%s: signalfd: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }


    // Block the signals
    ret = sigprocmask(
            /* how = */ SIG_BLOCK,
            /* &sigset = */ &sigset,
            /* &oldset = */ NULL
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: sigprocmask: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }


    // Add the signalfd to epoll
    ret = epoll_ctl(
        lrsyslog->epoll_fd,
        EPOLL_CTL_ADD,
        lrsyslog->signal_fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
            .data = {
                .fd = lrsyslog->signal_fd
            }
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    return 0;
}


static int lrsyslog_epoll_event_signal_fd_sighup (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event,
    struct signalfd_siginfo * siginfo
)
{
    int ret = 0;
    syslog(LOG_INFO, "%s:%d:%s: caught SIGHUP", __FILE__, __LINE__, __func__);

    // Do something useful here maybe.

    // Re-arm the fd in epoll
    // Re-arm EPOLLONESHOT file descriptor in epoll
    ret = epoll_ctl(
        lrsyslog->epoll_fd,
        EPOLL_CTL_MOD,
        event->data.fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLET | EPOLLONESHOT,
            .data = {
                .fd = event->data.fd
            }
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d: epoll_ctl: %s", __func__, __LINE__, strerror(errno));
        return -1;
    }

    // We're done.
    return 0;
    (void)siginfo;
}


static int lrsyslog_epoll_event_signal_fd_sigint (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event,
    struct signalfd_siginfo * siginfo
)
{
    syslog(LOG_INFO, "%s:%d:%s: caught SIGINT - exiting!", __FILE__, __LINE__, __func__);
    exit(EXIT_SUCCESS);
    (void)lrsyslog;
    (void)event;
    (void)siginfo;
}


static int lrsyslog_epoll_event_signal_fd (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{

    int bytes_read;
    struct signalfd_siginfo siginfo;

    bytes_read = read(event->data.fd, &siginfo, sizeof(struct signalfd_siginfo));
    if (-1 == bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: read: %s", __FILE__, __LINE__, __func__, strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (0 == bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: signalfd fd was closed - which is unexpected!", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    // Dispatch on signal number
    if (SIGHUP == siginfo.ssi_signo)
        return lrsyslog_epoll_event_signal_fd_sighup(lrsyslog, event, &siginfo);

    if (SIGINT == siginfo.ssi_signo)
        return lrsyslog_epoll_event_signal_fd_sigint(lrsyslog, event, &siginfo);

    // window resize events - not interesting
    if (SIGWINCH == siginfo.ssi_signo)
        return 0;

    syslog(LOG_ERR, "%s:%d:%s: caught unknown signal %d - exiting", __FILE__, __LINE__, __func__, siginfo.ssi_signo);
    exit(EXIT_FAILURE);
}


static int lrsyslog_epoll_event_dispatch (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{
    if (event->data.fd == lrsyslog->signal_fd)
        return lrsyslog_epoll_event_signal_fd(lrsyslog, event);

    syslog(LOG_WARNING, "%s:%d:%s: No match on epoll event.", __FILE__, __LINE__, __func__);
    return -1;
}


static int lrsyslog_epoll_handle_events (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event epoll_events[EPOLL_NUM_EVENTS],
    int ep_events_len
)
{
    int ret = 0;
    for (int i = 0; i < ep_events_len; i++) {
        ret = lrsyslog_epoll_event_dispatch(lrsyslog, &epoll_events[i]);
        if (0 != ret) {
            return ret;
        }
    }
    return 0;
}


static int lrsyslog_tcp_server_start (
    struct lrsyslog_s * lrsyslog
)
{
    int ret = 0;

    struct addrinfo *servinfo, *p;
    ret = getaddrinfo(
        /* host = */ CONFIG_HOST,
        /* port = */ CONFIG_PORT, 
        /* hints = */ &(struct addrinfo) {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM
        },
        /* servinfo = */ &servinfo
    );
    if (0 != ret) {
        syslog(LOG_ERR, "%s:%d:%s: getaddrinfo:: %s", __FILE__, __LINE__, __func__, gai_strerror(ret));
        return -1;
    }

    // Loop over the results from getaddrinfo and try to bind them up.
    for (p = servinfo; p != NULL; p = p->ai_next) {

        // Create a socket
        lrsyslog->tcp_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (-1 == lrsyslog->tcp_fd) {
            syslog(LOG_WARNING, "%s:%d:%s: socket: %s", __FILE__, __LINE__, __func__, strerror(errno));
            // let's try the next entry...
            continue;
        }

        // Set the socket REUSEADDR - this makes sure that we can start the
        // application after a restart even if the socket is still registered
        // in the kernel by the old application due to stale connections from
        // clients.
        ret = setsockopt(lrsyslog->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
        if (-1 == ret) {
            syslog(LOG_WARNING, "%s:%d:%s: setsockopt: %s", __FILE__, __LINE__, __func__, strerror(errno));
            // We don't care if this doesn't work so much - we can run without REUSEADDR.
        }

        // Bind the socket to the port
        ret = bind(lrsyslog->tcp_fd, p->ai_addr, p->ai_addrlen);
        if (-1 == ret) {
            // Ok, we couldn't bind this socket - close this socket and try the
            // next hit from getaddrinfo.
            syslog(LOG_WARNING, "%s:%d:%s: bind: %s", __FILE__, __LINE__, __func__, strerror(errno));
            close(lrsyslog->tcp_fd);
            continue;
        }

        // If we get here, it means that we've successfully bound up a tcp
        // socket. We don't need to try any more results from getaddrinfo.
        // Break out of the loop.
        break;
    }
    // Remember to free up the servinfo data!
    freeaddrinfo(servinfo);

    // If p is NULL, it means that the above loop went through all of the
    // results from getaddrinfo and never broke out of the loop - so we have no
    // valid socket.
    if (NULL == p) {
        syslog(LOG_ERR, "%s:%d:%s: failed to bind to any address", __FILE__, __LINE__, __func__);
        return -1;
    }

    // At this point, we have successfully bound up a port. Now we just need to
    // listen for connection on the port.
    ret = listen(lrsyslog->tcp_fd, TCP_LISTEN_BACKLOG);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: listen: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // Add the tcp fd to tcp tasks epoll
    ret = epoll_ctl(
        lrsyslog->tcp_task_epoll_fd,
        EPOLL_CTL_ADD,
        lrsyslog->tcp_fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
            .data = {
                .fd = lrsyslog->tcp_fd
            }
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // We're done - we have a fd on the epoll that will trigger on incoming
    // connection.
    return 0;
}


int main (
    const int argc,
    const char *argv[]
)
{

    int ret = 0;

    openlog(CONFIG_SYSLOG_IDENT, LOG_CONS | LOG_PID, LOG_USER);

    struct lrsyslog_s lrsyslog = {
        .sentinel = 8090
    };
    ret = lrsyslog_init(&lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_init returned %d", __FILE__, __LINE__, __func__, ret);
        exit(EXIT_FAILURE);
    }


    // start listening for connections
    ret = lrsyslog_tcp_server_start(&lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_tcp_server_start returned %d", __FILE__, __LINE__, __func__, ret);
        exit(EXIT_FAILURE);
    }

    // Create tcp listener threads
    for (int i = 0; i < CONFIG_NUM_THREADS; i++) {
        ret = pthread_create(&lrsyslog.tcp_task_threads[i], NULL, lrsyslog_tcp_task, &lrsyslog);
        if (0 != ret) {
            syslog(LOG_ERR, "%s:%d: pthread_create: %s", __func__, __LINE__, strerror(errno));
            return -1;
        }
    }


    // And the nats thread
    ret = pthread_create(&lrsyslog.nats_thread, NULL, lrsyslog_nats_task, &lrsyslog);
    if (0 != ret) {
        syslog(LOG_ERR, "%s:%d: pthread_create: %s", __func__, __LINE__, strerror(errno));
        return -1;
    }


    // Time for the epoll_wait loop
    int ep_events_len = 0;
    struct epoll_event ep_events[EPOLL_NUM_EVENTS];
    for (ep_events_len = epoll_wait(lrsyslog.epoll_fd, ep_events, EPOLL_NUM_EVENTS, -1);
         ep_events_len > 0 || (-1 == ep_events_len && EINTR == errno);
         ep_events_len = epoll_wait(lrsyslog.epoll_fd, ep_events, EPOLL_NUM_EVENTS, -1))
    {
        ret = lrsyslog_epoll_handle_events(&lrsyslog, ep_events, ep_events_len);
        if (-1 == ret) {
            break;
        }
    }
    if (-1 == ep_events_len) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_wait: %s", __FILE__, __LINE__, __func__, strerror(errno));
        exit(EXIT_FAILURE);
    }


    exit(EXIT_SUCCESS);	
    (void)argc;
    (void)argv;
}
