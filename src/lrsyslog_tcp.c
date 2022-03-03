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
#include "lrsyslog_client_parser.h"

#define EPOLL_NUM_EVENTS 8


static const char * lrsyslog_tcp_task_facility_str (
    const uint8_t facility
)
{
    switch (facility) {

        case 0:
            return "kern";

        case 1:
            return "user";

        case 2:
            return "mail";

        case 3:
            return "daemon";

        case 4:
            return "auth";

        case 5:
            return "syslog";

        case 6:
            return "lpr";

        case 7:
            return "news";

        case 8:
            return "uucp";

        case 9:
            return "clock";

        case 10:
            return "authpriv";

        case 11:
            return "ftp";

        case 12:
            return "ntp";

        case 13:
            return "audit";

        case 14:
            return "alert";

        case 15:
            return "clock2";

        case 16:
            return "local0";

        case 17:
            return "local1";

        case 18:
            return "local2";

        case 19:
            return "local3";

        case 20:
            return "local4";

        case 21:
            return "local5";

        case 22:
            return "local6";

        case 23:
            return "local7";

        default:
            return "unknown";
    }
}


void lrsyslog_tcp_task_severity_str (
    const uint8_t severity,
    const char ** out,
    uint32_t * out_len
)
{
    switch (severity) {
        case LOG_DEBUG:
            *out = "debug";
            *out_len = 5;
            return;

        case LOG_INFO:
            *out = "info";
            *out_len = 4;
            return;

        case LOG_WARNING:
            *out = "warning";
            *out_len = 7;
            return;

        case LOG_ERR:
            *out = "err";
            *out_len = 3;
            return;

        case LOG_NOTICE:
            *out = "notice";
            *out_len = 6;
            return;

        case LOG_CRIT:
            *out = "crit";
            *out_len = 4;
            return;

        case LOG_EMERG:
            *out = "emerg";
            *out_len = 5;
            return;

        case LOG_ALERT:
            *out = "alert";
            *out_len = 5;
            return;

        default:
            *out = "unknown";
            *out_len = 7;
            return;
    }
}


int lrsyslog_tcp_syslog_cb (
    const char * host,
    const uint32_t host_len,
    const char * tag,
    const uint32_t tag_len,
    const uint32_t facility,
    const uint32_t severity,
    const uint32_t pid,
    const char * msg,
    const uint32_t msg_len,
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
    void * user_data
)
{
    struct io_uring_sqe * sqe;
    int ret = 0;
    struct lrsyslog_client_s * client = user_data;
    struct lrsyslog_s * lrsyslog = client->lrsyslog;

    const char * severity_str;
    uint32_t severity_str_len;
    lrsyslog_tcp_task_severity_str(severity, &severity_str, &severity_str_len);

    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_writev(
        /* sqe = */ sqe,
        /* fd = */ lrsyslog->nats.fd,
        /* iovec = */ (struct iovec[9]) {
            {
                .iov_base = "PUB lrsyslog.",
                .iov_len = 13
            },
            {
                .iov_base = tag,
                .iov_len = tag_len
            },
            {
                .iov_base = ".",
                .iov_len = 1
            },
            {
                .iov_base = severity_str,
                .iov_len = severity_str_len
            },
            {
                ".out ",
                .iov_len = 5
            },
            {
                .iov_base = msg_len_str,
                .iov_len = msg_len_str_len
            },
            {
                .iov_base = "\r\n",
                .iov_len = 2
            },
            {
                .iov_base = msg,
                .iov_len = msg_len
            },
            {
                .iov_base = "\r\n",
                .iov_len = 2
            }
        },
        /* ioved_len = */ 9,
        /* offset = */ 0
    );
    io_uring_sqe_set_data(sqe, client);
    io_uring_submit(&lrsyslog->ring);

    client->writing_to_nats = true;

    return 0;
    (void)ret;
}


int lrsyslog_uring_event_tcp_fd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;

    if (unlikely(cqe->res < 0)) {
        syslog(LOG_ERR, "%s:%d:%s: accept: %s", __FILE__, __LINE__, __func__, strerror(-cqe->res));
        return -1;
    }

    // malloc a data struct for the user
    struct lrsyslog_client_s * client = malloc(sizeof(struct lrsyslog_client_s));
    if (unlikely(NULL == client)) {
        syslog(LOG_ERR, "%s:%d:%s: malloc returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }

    client->sentinel = LRSYSLOG_CLIENT_SENTINEL;
    client->fd = cqe->res;
    client->closing = false;
    client->lrsyslog = lrsyslog;

    // Initialize the client parser
    ret = lrsyslog_client_parser_init(
        &client->parser,
        /* log_cb = */ lrsyslog_tcp_syslog_cb,
        /* user_data = */ client
    );
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_parser_init returned %d", __FILE__, __LINE__, __func__, ret);
        return -1;
    }

    // add a read request on the new client
    // register a read call on fd
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (unlikely(NULL == sqe)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_read(
        /* sqe = */ sqe,
        /* fd = */ cqe->res,
        /* buf = */ client->read_buf,
        /* buf_len = */ sizeof(client->read_buf),
        /* offset = */ 0
    );
    io_uring_sqe_set_data(sqe, client);
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);

    // link a timeout
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (unlikely(NULL == sqe)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_link_timeout(
        /* sqe = */ sqe,
        /* timeout = */ &(struct __kernel_timespec) {
            .tv_sec = 30,
            .tv_nsec = 0
        },
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
    io_uring_submit(&lrsyslog->ring);
    

    // accept more connections
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (unlikely(NULL == sqe)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_accept(
        /* sqe = */ sqe, 
        /* fd = */ lrsyslog->tcp_fd, 
        /* addrinfo = */ NULL,
        /* addrinfo_len = */ 0,
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, &lrsyslog->tcp_fd);
    io_uring_submit(&lrsyslog->ring);
    
    io_uring_cqe_seen(&lrsyslog->ring, cqe);
    return 0;
}


int lrsyslog_tcp_server_start (
    struct lrsyslog_s * lrsyslog
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;

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

    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_accept(
        /* sqe = */ sqe, 
        /* fd = */ lrsyslog->tcp_fd, 
        /* addrinfo = */ NULL,
        /* addrinfo_len = */ 0,
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, &lrsyslog->tcp_fd);
    io_uring_submit(&lrsyslog->ring);

    return 0;
}
