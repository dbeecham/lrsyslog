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
#include <netinet/in.h>
#include <netdb.h>

#include "lrsyslog.h"
#include "lrsyslog_nats.h"
#include "lrsyslog_nats_parser.h"


int lrsyslog_nats_ping_cb (
    struct lrsyslog_nats_parser_s * parser,
    void * context,
    void * arg
)
{
    struct io_uring_sqe * sqe;

    struct lrsyslog_s * lrsyslog = context;
    if (8090 != lrsyslog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    // write a PONG to NATS
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_write(
        /* sqe = */ sqe,
        /* fd = */ lrsyslog->nats.fd,
        /* buf = */ "PONG\r\n",
        /* buf_len = */ strlen("PONG\r\n"),
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, 0);
    io_uring_submit(&lrsyslog->ring);

    return 0;
    (void)parser;
    (void)arg;
}


int lrsyslog_uring_event_nats_fd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
)
{
    struct io_uring_sqe * sqe;
    int ret = 0;

    if (cqe->res < 0) {
        syslog(LOG_ERR, "%s:%d:%s: read: %s", __FILE__, __LINE__, __func__, strerror(-cqe->res));
        return -1;
    }
    if (0 == cqe->res) {
        syslog(LOG_ERR, "%s:%d:%s: nats connection closed", __FILE__, __LINE__, __func__);
        return -1;
    }

    // Parse the NATS data; one of the callbacks (named *_cb) will be called on
    // a successful parse.
    ret = lrsyslog_nats_parser_parse(&lrsyslog->nats.parser, lrsyslog->nats.buf, cqe->res);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_nats_parser_parse returned %d", __FILE__, __LINE__, __func__, ret);
        return -1;
    }

    // add a new read request on nats
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_read(sqe, lrsyslog->nats.fd, lrsyslog->nats.buf, 4096, 0);
    io_uring_sqe_set_data(sqe, &lrsyslog->nats.fd);

    // mark this event as seen
    io_uring_cqe_seen(&lrsyslog->ring, cqe);

    return 0;
}


int lrsyslog_nats_connect (
    struct lrsyslog_s * lrsyslog
)
{
    struct io_uring_sqe * sqe;
    int ret = 0;
    struct addrinfo *servinfo, *p;

    ret = getaddrinfo(
        /* host = */ CONFIG_NATS_HOST,
        /* port = */ CONFIG_NATS_PORT, 
        /* hints = */ &(struct addrinfo) {
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM
        },
        /* servinfo = */ &servinfo
    );
    if (0 != ret) {
        syslog(LOG_ERR, "%s:%d:%s: getaddrinfo: %s", __FILE__, __LINE__, __func__, gai_strerror(ret));
        return -1;
    }

    // Loop over the results from getaddrinfo and try to bind them up.
    for (p = servinfo; p != NULL; p = p->ai_next) {

        // Create a socket
        lrsyslog->nats.fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (-1 == lrsyslog->nats.fd) {
            syslog(LOG_WARNING, "%s:%d:%s: socket: %s", __FILE__, __LINE__, __func__, strerror(errno));
            // let's try the next entry...
            continue;
        }

        // Bind the socket to the port
        ret = connect(lrsyslog->nats.fd, p->ai_addr, p->ai_addrlen);
        if (-1 == ret) {
            // Ok, we couldn't connect to this address result - close this
            // socket and try the next hit from getaddrinfo.
            syslog(LOG_WARNING, "%s:%d:%s: connect: %s", __FILE__, __LINE__, __func__, strerror(errno));
            close(lrsyslog->nats.fd);
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
        syslog(LOG_ERR, "%s:%d:%s: failed to connect to any address", __FILE__, __LINE__, __func__);
        return -1;
    }

    // read some data from nats
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_read(sqe, lrsyslog->nats.fd, lrsyslog->nats.buf, 4096, 0);
    io_uring_sqe_set_data(sqe, &lrsyslog->nats.fd);

    return 0;
}
