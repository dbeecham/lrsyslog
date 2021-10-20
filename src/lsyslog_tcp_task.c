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

#include "lsyslog.h"
#include "lsyslog_tcp_task.h"
#include "lsyslog_client_parser.h"
#include "gwy01_parser.h"

#define EPOLL_NUM_EVENTS 8

// TODO:
// * on message from socketpair, send it to clients
// * on message from clients, send it to socketpair


static int lsyslog_tcp_task_epoll_event_client_fd (
    struct lsyslog_s * lsyslog,
    struct epoll_event * event
)
{
    int ret = 0;
    int bytes_read = 0;
    char buf[TCP_READ_BUF_LEN];

    struct lsyslog_client_s * client = event->data.ptr;
    if (18091 != client->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: client sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    bytes_read = read(client->fd, buf, TCP_READ_BUF_LEN);
    if (-1 == bytes_read) {

        // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
        // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
        ret = epoll_ctl(
            lsyslog->tcp_task_epoll_fd,
            EPOLL_CTL_DEL,
            client->fd,
            NULL
        );
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }

        close(client->fd);


        // Close the client watchdog timer as well
        // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
        // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
        ret = epoll_ctl(
            lsyslog->tcp_task_epoll_fd,
            EPOLL_CTL_DEL,
            client->watchdog.timer_fd,
            NULL
        );
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }

        close(client->watchdog.timer_fd);

        // free the client slot
        *client = (struct lsyslog_client_s){0};
        return 0;
    }

    if (0 == bytes_read) {
        // Client disconnected, clear out the clients stuff.

        // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
        // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
        ret = epoll_ctl(
            lsyslog->tcp_task_epoll_fd,
            EPOLL_CTL_DEL,
            client->fd,
            NULL
        );
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }

        close(client->fd);
        
        // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
        // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
        ret = epoll_ctl(
            lsyslog->tcp_task_epoll_fd,
            EPOLL_CTL_DEL,
            client->watchdog.timer_fd,
            NULL
        );
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }
        close(client->watchdog.timer_fd);

        *client = (struct lsyslog_client_s){0};
        
        syslog(LOG_INFO, "%s:%d:%s: client disconnected", __FILE__, __LINE__, __func__);
        return 0;
    }

    // We read some data, so so let's kick the clients watchdog timer
    // arm timerfd
    ret = timerfd_settime(
        /* fd        = */ client->watchdog.timer_fd,
        /* opt       = */ 0,
        /* timerspec = */ &(struct itimerspec) {
            .it_interval = {0},
            .it_value = {
                .tv_sec  = CLIENT_PING_TIMEOUT_S,
                .tv_nsec = 0
            }
        },
        /* old_ts    = */ NULL
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d: timerfd_settime: %s", __func__, __LINE__, strerror(errno));
        return -1;
    }

    // Parse the data the user sent
    ret = lsyslog_client_parser_parse(&client->log, buf, bytes_read);
    if (-1 == ret) {
        syslog(LOG_WARNING, "%s:%d:%s: lsyslog_client_parser_parse returned %d", __FILE__, __LINE__, __func__, ret);
        return -1;
    }

    // Re-arm the fd on the epoll
    ret = epoll_ctl(
        lsyslog->tcp_task_epoll_fd,
        EPOLL_CTL_MOD,
        client->fd,
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


static int lsyslog_tcp_task_epoll_event_client_timer_fd (
    struct lsyslog_s * lsyslog,
    struct epoll_event * event
)
{
    // If this triggers, that means we've seen no data from the client for some
    // time, and it's time to kick the client out.
    //
    int ret = 0;

    struct lsyslog_client_watchdog_s * watchdog = event->data.ptr;
    if (18092 != watchdog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: watchdog sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    struct lsyslog_client_s * client = (struct lsyslog_client_s*)(((char*)watchdog) - offsetof(struct lsyslog_client_s, watchdog));
    if (18091 != client->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: client sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
    // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
    ret = epoll_ctl(
        lsyslog->tcp_task_epoll_fd,
        EPOLL_CTL_DEL,
        client->fd,
        NULL
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    close(client->fd);
    
    // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
    // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
    ret = epoll_ctl(
        lsyslog->tcp_task_epoll_fd,
        EPOLL_CTL_DEL,
        client->watchdog.timer_fd,
        NULL
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    close(client->watchdog.timer_fd);

    syslog(LOG_INFO, "%s:%d:%s: client '%.*s' has not sent any data in %d seconds, closing connection",
        __FILE__, __LINE__, __func__, client->log.host_i, client->log.host, CLIENT_PING_TIMEOUT_S);

    *client = (struct lsyslog_client_s){0};
    
    return 0;
}


int lsyslog_tcp_task_client_log_cb (
    struct lsyslog_syslog_s * log,
    void * context,
    void * arg
)
{
    int ret = 0;
    int bytes_written = 0;

    struct lsyslog_client_s * client = arg;
    if (18091 != client->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: client sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    struct lsyslog_s * lsyslog = context;
    if (8090 != lsyslog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: lsyslog sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    if (log->msg_i < 0) {
        syslog(LOG_ERR, "%s:%d:%s: negative msg_len", __FILE__, __LINE__, __func__);
        return -1;
    }

    struct lsyslog_pipe_msg_s pipe_msg = {0};
    pipe_msg.severity = log->severity;
    pipe_msg.facility = log->facility;

    pipe_msg.topic_len = snprintf(
        pipe_msg.topic,
        128,
        "lsyslog.%.*s.%.*s.%d.%d.out",
        log->host_i,
        log->host,
        log->tag_i,
        log->tag,
        log->facility,
        log->severity
    );
    if (-1 == pipe_msg.topic_len) {
        syslog(LOG_ERR, "%s:%d:%s: snprintf: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    int msg_len = 1024;
    if (log->msg_i < msg_len) {
        msg_len = log->msg_i;
    }
    memcpy(&pipe_msg.msg, log->msg, msg_len);
    pipe_msg.msg_len = msg_len;

    bytes_written = write(lsyslog->pipe_fd[1], &pipe_msg, sizeof(struct lsyslog_pipe_msg_s));
    if (-1 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: write: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (0 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: wrote 0 bytes to pipe!", __FILE__, __LINE__, __func__);
        return -1;
    }
    if (sizeof(struct lsyslog_pipe_msg_s) != bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: partial write of %d bytes to pipe!", __FILE__, __LINE__, __func__, bytes_written);
        return 0;
    }

    return 0;
    (void)ret;
    (void)log;
}


static int lsyslog_tcp_task_epoll_event_tcp_fd (
    struct lsyslog_s * lsyslog,
    struct epoll_event * event
)
{
    // Accept the client into the lsyslog religion/sect
    int ret;
    int client_fd = 0;
    struct sockaddr_storage their_addr = {0};
    socklen_t sin_size = sizeof(struct sockaddr_storage);
    
    client_fd = accept(lsyslog->tcp_fd, (struct sockaddr*)&their_addr, &sin_size);
    if (-1 == client_fd) {
        syslog(LOG_ERR, "%s:%d:%s: accept: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // First off, we need to find a free spot for the client.
    for (int i = 0; i < MAX_CLIENTS; i++) {

        if (0 == lsyslog->clients[i].sentinel) {

            // This spot is free! Assign it!
            lsyslog->clients[i].sentinel = 18091;
            lsyslog->clients[i].fd = client_fd;

            // Initialize the client parser
            ret = lsyslog_client_parser_init(
                &lsyslog->clients[i].log,
                /* log_cb = */ lsyslog_tcp_task_client_log_cb,
                /* context = */ lsyslog,
                /* arg = */ &lsyslog->clients[i]
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: lsyslog_client_parser_init returned %d", __FILE__, __LINE__, __func__, ret);
                
            }

            // Create a watchdog timerfd for this client
            lsyslog->clients[i].watchdog.sentinel = 18092;
            lsyslog->clients[i].watchdog.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
            if (-1 == lsyslog->clients[i].watchdog.timer_fd) {
                syslog(LOG_ERR, "%s:%d:%s: timerfd_create: %s", __FILE__, __LINE__, __func__, strerror(errno));
                return -1;
            }

            // Start the timer
            // arm timerfd
            ret = timerfd_settime(
                /* fd        = */ lsyslog->clients[i].watchdog.timer_fd,
                /* opt       = */ 0,
                /* timerspec = */ &(struct itimerspec) {
                    .it_interval = {0},
                    .it_value = {
                        .tv_sec  = CLIENT_PING_TIMEOUT_S,
                        .tv_nsec = 0
                    }
                },
                /* old_ts    = */ NULL
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: timerfd_settime: %s", __FILE__, __LINE__, __func__, strerror(errno));
                return -1;
            }


            // Add the clients watchdog timer
            ret = epoll_ctl(
                lsyslog->tcp_task_epoll_fd,
                EPOLL_CTL_ADD,
                lsyslog->clients[i].watchdog.timer_fd,
                &(struct epoll_event){
                    .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
                    .data = {
                        .ptr = &lsyslog->clients[i].watchdog
                    }
                }
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
                return -1;
            }


            // Add the client to epoll
            ret = epoll_ctl(
                lsyslog->tcp_task_epoll_fd,
                EPOLL_CTL_ADD,
                client_fd,
                &(struct epoll_event){
                    .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
                    .data = {
                        .ptr = &lsyslog->clients[i]
                    }
                }
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
                return -1;
            }


            // Before we go, let's re-arm the accept fd on epoll
            ret = epoll_ctl(
                lsyslog->tcp_task_epoll_fd,
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

            // All done, let's pop back to epoll_wait.
            return 0;
        }
    }


    // If we reach this point, then we found on free spots for the new client.
    syslog(LOG_WARNING, "%s:%d:%s: no free spots for client", __FILE__, __LINE__, __func__);
    close(client_fd);
    return 0;
}


static int lsyslog_tcp_task_epoll_event_dispatch (
    struct lsyslog_s * lsyslog,
    struct epoll_event * event
)
{
    if (event->data.fd == lsyslog->tcp_fd)
        return lsyslog_tcp_task_epoll_event_tcp_fd(lsyslog, event);

    // If it's not the connect socket, it's either a client fd or a timer fd
    // associated with a client. For that, we need to dispatch on the sentinel
    // value.
    int event_sentinel = *(int*)event->data.ptr;
    if (18091 == event_sentinel)
        return lsyslog_tcp_task_epoll_event_client_fd(lsyslog, event);

    if (18092 == event_sentinel)
        return lsyslog_tcp_task_epoll_event_client_timer_fd(lsyslog, event);

    // otherwise, we've got no match on the epoll, just quit.
    syslog(LOG_ERR, "%s:%d:%s: event dispatch defaulted!", __FILE__, __LINE__, __func__);
    return -1;
}


static int lsyslog_tcp_task_epoll_handle_events (
    struct lsyslog_s * lsyslog,
    struct epoll_event epoll_events[EPOLL_NUM_EVENTS],
    int ep_events_len
)
{
    int ret = 0;
    for (int i = 0; i < ep_events_len; i++) {
        ret = lsyslog_tcp_task_epoll_event_dispatch(lsyslog, &epoll_events[i]);
        if (0 != ret) {
            return ret;
        }
    }
    return 0;
}


void * lsyslog_tcp_task (
        void * arg
)
{
    int ret;
    struct lsyslog_s * lsyslog = arg;
    if (8090 != lsyslog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: lsyslog sentinel is wrong!", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    int ep_events_len = 0;
    struct epoll_event ep_events[EPOLL_NUM_EVENTS];
    for (ep_events_len = epoll_wait(lsyslog->tcp_task_epoll_fd, ep_events, EPOLL_NUM_EVENTS, -1);
         ep_events_len > 0 || (-1 == ep_events_len && EINTR == errno);
         ep_events_len = epoll_wait(lsyslog->tcp_task_epoll_fd, ep_events, EPOLL_NUM_EVENTS, -1))
    {
        ret = lsyslog_tcp_task_epoll_handle_events(lsyslog, ep_events, ep_events_len);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lsyslog_tcp_task_epoll_handle_events returned %d", __FILE__, __LINE__, __func__, ret);
            exit(EXIT_FAILURE);
        }
    }
    if (-1 == ep_events_len) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_wait: %s", __FILE__, __LINE__, __func__, strerror(errno));
        exit(EXIT_FAILURE);
    }

    return 0;
}
