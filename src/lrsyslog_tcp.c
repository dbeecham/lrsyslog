// Try to not define _GNU_SOURCE or _DEFAULT_SOURCE, since those enable
// glibc-specific features. Being able to compile to e.g. musl or uclibc
// makes porting to embedded linux systems much easier (and generally
// pressures the programmer into stricter and better programming practices).
#define _POSIX_C_SOURCE 201805L

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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/timerfd.h>
#include <stddef.h>

#include "lrsyslog.h"
#include "lrsyslog_tcp.h"
#include "lrsyslog_client.h"


int lrsyslog_tcp_accept (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_listen_s * listen
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;
    struct lrsyslog_uring_event_s * event;

    ret = lrsyslog_uring_event_new(lrsyslog, &event);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_new returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    event->type = LRSYSLOG_URING_EVENT_ACCEPT;
    event->listen = listen;

    // accept more connections
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (unlikely(NULL == sqe)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_accept(
        /* sqe = */ sqe, 
        /* fd = */ lrsyslog->listen.fd, 
        /* addrinfo = */ NULL,
        /* addrinfo_len = */ 0,
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, event);
    io_uring_submit(&lrsyslog->ring);

    return 0;
}


int lrsyslog_uring_event_listen_fd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
)
{
    int ret = 0;
    struct lrsyslog_client_s * client = NULL;

    if (unlikely(cqe->res < 0)) {
        syslog(LOG_ERR, "%s:%d:%s: accept: %s", __FILE__, __LINE__, __func__, strerror(-cqe->res));
        return -1;
    }

    // create a new client
    ret = lrsyslog_client_new(
        /* lrsyslog = */ lrsyslog,
        /* client = */ &client,
        /* fd = */ cqe->res,
        /* callbacks = */ (struct lrsyslog_client_parser_callbacks_s){
            .log_cb = lrsyslog_client_syslog_cb
        }
    );
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_new returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    // create a read request on the new client
    ret = lrsyslog_client_read(
        /* lrsyslog = */ lrsyslog,
        /* client = */ client
    );
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_read returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    ret = lrsyslog_tcp_accept(lrsyslog, event->listen);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_tcp_accept returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }
    
    ret = lrsyslog_uring_event_rc_sub(lrsyslog, event);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_rc_sub returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    io_uring_cqe_seen(&lrsyslog->ring, cqe);
    return 0;
}


int lrsyslog_tcp_server_start (
    struct lrsyslog_s * lrsyslog
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;
    struct lrsyslog_uring_event_s * event = NULL;

    char port[6];
    snprintf(port, 6, "%d", lrsyslog->opts.port);

    struct addrinfo *servinfo, *p;
    ret = getaddrinfo(
        /* host = */ CONFIG_HOST,
        /* port = */ port, 
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
        lrsyslog->listen.fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (-1 == lrsyslog->listen.fd) {
            syslog(LOG_WARNING, "%s:%d:%s: socket: %s", __FILE__, __LINE__, __func__, strerror(errno));
            // let's try the next entry...
            continue;
        }

        // Set the socket REUSEADDR - this makes sure that we can start the
        // application after a restart even if the socket is still registered
        // in the kernel by the old application due to stale connections from
        // clients.
        ret = setsockopt(lrsyslog->listen.fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
        if (-1 == ret) {
            syslog(LOG_WARNING, "%s:%d:%s: setsockopt: %s", __FILE__, __LINE__, __func__, strerror(errno));
            // We don't care if this doesn't work so much - we can run without REUSEADDR.
        }

        // Bind the socket to the port
        ret = bind(lrsyslog->listen.fd, p->ai_addr, p->ai_addrlen);
        if (-1 == ret) {
            // Ok, we couldn't bind this socket - close this socket and try the
            // next hit from getaddrinfo.
            syslog(LOG_WARNING, "%s:%d:%s: bind: %s", __FILE__, __LINE__, __func__, strerror(errno));
            close(lrsyslog->listen.fd);
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
    ret = listen(lrsyslog->listen.fd, CONFIG_TCP_LISTEN_BACKLOG);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: listen: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    ret = lrsyslog_uring_event_new(lrsyslog, &event);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_new returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    event->type = LRSYSLOG_URING_EVENT_ACCEPT;
    event->listen = &lrsyslog->listen;

    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_accept(
        /* sqe = */ sqe, 
        /* fd = */ lrsyslog->listen.fd, 
        /* addrinfo = */ NULL,
        /* addrinfo_len = */ 0,
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, event);
    io_uring_submit(&lrsyslog->ring);

    return 0;
}
