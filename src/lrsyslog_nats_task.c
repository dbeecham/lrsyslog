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
#include "lrsyslog_nats_task.h"
#include "nats_parser.h"


int lrsyslog_nats_task_ping_cb (
    struct nats_parser_s * parser,
    void * context,
    void * arg
)
{
    int bytes_written = 0;

    struct lrsyslog_s * lrsyslog = context;
    if (8090 != lrsyslog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    bytes_written = write(lrsyslog->nats_fd, "PONG\r\n", 6);
    if (-1 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: write: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (0 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: wrote 0 bytes! connection dead?", __FILE__, __LINE__, __func__);
        return -1;
    }
    if (6 != bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: partial write of %d bytes!", __FILE__, __LINE__, __func__, bytes_written);
        return -1;
    }

    return 0;
    (void)parser;
    (void)arg;
}


int lrsyslog_nats_task_epoll_event_nats_fd (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{

    int ret = 0;
    int bytes_read = 0;
    char buf[NATS_BUF_LEN];


    bytes_read = read(event->data.fd, buf, NATS_BUF_LEN);
    if (-1 == bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: read: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (0 == bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: nats closed connection!", __FILE__, __LINE__, __func__);
        return -1;
    }

    // Parse the NATS data; one of the callbacks (named *_cb) will be called on
    // a successful parse.
    ret = nats_parser_parse(&lrsyslog->nats_parser, buf, bytes_read);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: nats_parser_parse returned %d", __FILE__, __LINE__, __func__, ret);
        return -1;
    }

    ret = epoll_ctl(
        lrsyslog->nats_task_epoll_fd,
        EPOLL_CTL_MOD,
        event->data.fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
            .data = event->data
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    return 0;
}


int lrsyslog_nats_task_epoll_event_pipe_fd (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{

    int ret = 0;
    int bytes_read = 0;
    int bytes_written = 0;
    struct lrsyslog_pipe_msg_s pipe_msg = {0};
    char nats_msg[4096];
    int nats_msg_len = 0;


    bytes_read = read(event->data.fd, &pipe_msg, sizeof(struct lrsyslog_pipe_msg_s));
    if (-1 == bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: read: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (sizeof(struct lrsyslog_pipe_msg_s) != bytes_read) {
        syslog(LOG_ERR, "%s:%d:%s: nats closed connection!", __FILE__, __LINE__, __func__);
        return -1;
    }

    if (pipe_msg.topic_len <= 0) {
        syslog(LOG_ERR, "%s:%d:%s: non-positive topic length", __FILE__, __LINE__, __func__);
        return -1;
    }

    nats_msg_len = snprintf(nats_msg, 4096, "PUB %.*s %d\r\n%.*s\r\n",
            pipe_msg.topic_len, pipe_msg.topic,
            pipe_msg.msg_len,
            pipe_msg.msg_len, pipe_msg.msg
    );

    bytes_written = write(lrsyslog->nats_fd, nats_msg, nats_msg_len);
    if (-1 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: write: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (0 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: wrote 0 bytes!", __FILE__, __LINE__, __func__);
        return -1;
    }
    if (bytes_written != nats_msg_len) {
        syslog(LOG_ERR, "%s:%d:%s: partial write of %d bytes", __FILE__, __LINE__, __func__, bytes_written);
        return -1;
    }

    // re-arm pipe fd on epoll
    ret = epoll_ctl(
        lrsyslog->nats_task_epoll_fd,
        EPOLL_CTL_MOD,
        event->data.fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
            .data = event->data
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    return 0;
}


static int lrsyslog_nats_task_epoll_event_dispatch (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{
    if (event->data.fd == lrsyslog->nats_fd)
        return lrsyslog_nats_task_epoll_event_nats_fd(lrsyslog, event);

    if (event->data.fd == lrsyslog->pipe_fd[0])
        return lrsyslog_nats_task_epoll_event_pipe_fd(lrsyslog, event);

    syslog(LOG_WARNING, "%s:%d:%s: No match on epoll event.", __FILE__, __LINE__, __func__);
    return -1;
}


static int lrsyslog_nats_task_epoll_handle_events (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event epoll_events[EPOLL_NUM_EVENTS],
    int ep_events_len
)
{
    int ret = 0;
    for (int i = 0; i < ep_events_len; i++) {
        ret = lrsyslog_nats_task_epoll_event_dispatch(lrsyslog, &epoll_events[i]);
        if (0 != ret) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_nats_task_epoll_event_dispatch returned %d", __FILE__, __LINE__, __func__, ret);
            return ret;
        }
    }
    return 0;
}


int lrsyslog_epoll_loop (
    struct lrsyslog_s * lrsyslog
)
{

    int ret = 0;

    int ep_events_len = 0;
    struct epoll_event ep_events[EPOLL_NUM_EVENTS];
    for (ep_events_len = epoll_wait(lrsyslog->nats_task_epoll_fd, ep_events, EPOLL_NUM_EVENTS, -1);
         ep_events_len > 0;
         ep_events_len = epoll_wait(lrsyslog->nats_task_epoll_fd, ep_events, EPOLL_NUM_EVENTS, -1))
    {
        ret = lrsyslog_nats_task_epoll_handle_events(lrsyslog, ep_events, ep_events_len);
        if (-1 == ret) {
            return ret;
        }
    }
    if (-1 == ep_events_len) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_wait: %s", __FILE__, __LINE__, __func__, strerror(errno));
        exit(EXIT_FAILURE);
    }

    return 0;
}


int lrsyslog_nats_task_connect (
    struct lrsyslog_s * lrsyslog
)
{

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
        lrsyslog->nats_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (-1 == lrsyslog->nats_fd) {
            syslog(LOG_WARNING, "%s:%d:%s: socket: %s", __FILE__, __LINE__, __func__, strerror(errno));
            // let's try the next entry...
            continue;
        }

        // Bind the socket to the port
        ret = connect(lrsyslog->nats_fd, p->ai_addr, p->ai_addrlen);
        if (-1 == ret) {
            // Ok, we couldn't connect to this address result - close this
            // socket and try the next hit from getaddrinfo.
            syslog(LOG_WARNING, "%s:%d:%s: connect: %s", __FILE__, __LINE__, __func__, strerror(errno));
            close(lrsyslog->nats_fd);
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

    // Add the fd to epoll
    ret = epoll_ctl(
        lrsyslog->nats_task_epoll_fd,
        EPOLL_CTL_ADD,
        lrsyslog->nats_fd,
        &(struct epoll_event){
            .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
            .data = {
                .fd = lrsyslog->nats_fd
            }
        }
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    return 0;
}


static int lrsyslog_nats_task_init (
    struct lrsyslog_s * lrsyslog
)
{

    int ret = 0;

    ret = nats_parser_init(&lrsyslog->nats_parser, lrsyslog_nats_task_ping_cb, lrsyslog, NULL);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: nats_parser_init returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    return 0;
}


void * lrsyslog_nats_task (
    void * arg
)
{

    int ret = 0;

    struct lrsyslog_s * lrsyslog = arg;
    if (NULL == lrsyslog) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog pointer is NULL", __FILE__, __LINE__, __func__);
        return (void*)-1;
    }
    if (8090 != lrsyslog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: sentinel is wrong!", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    ret = lrsyslog_nats_task_init(lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_nats_task_init returned -1", __FILE__, __LINE__, __func__);
        return (void*)-1;
    }


    ret = lrsyslog_nats_task_connect(lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_nats_task_connect returned %d", __FILE__, __LINE__, __func__, ret);
        exit(EXIT_FAILURE);
    }

    ret = lrsyslog_epoll_loop(lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_epoll_loop returned %d", __FILE__, __LINE__, __func__, ret);
        exit(EXIT_FAILURE);
    }

    // TODO:
    //  * Connect to NATS
    //  * Set up a watchdog timer for NATS
    //  * When connected to NATS, subscribe to some topic
    //  * epoll_wait
    //  * if disconnected from NATS, just retry the connection.
    //  * on PING from nats, PONG back
    //  * on MSG from nats, send it to the socketpair
    //  * on msg from socketpair, send it to nats

    return 0;
}
