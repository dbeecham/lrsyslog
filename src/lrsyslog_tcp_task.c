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
#include "lrsyslog_tcp_task.h"
#include "lrsyslog_client_parser.h"

#define EPOLL_NUM_EVENTS 8

// TODO:
// * on message from socketpair, send it to clients
// * on message from clients, send it to socketpair


static int lrsyslog_tcp_task_epoll_event_client_fd (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{
    int ret = 0;
    int bytes_read = 0;
    char buf[TCP_READ_BUF_LEN];

    struct lrsyslog_client_s * client = event->data.ptr;
    if (18091 != client->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: client sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    bytes_read = read(client->fd, buf, TCP_READ_BUF_LEN);
    if (-1 == bytes_read) {

        // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
        // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
        ret = epoll_ctl(
            lrsyslog->tcp_task_epoll_fd,
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
            lrsyslog->tcp_task_epoll_fd,
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
        *client = (struct lrsyslog_client_s){0};
        return 0;
    }

    if (0 == bytes_read) {
        // Client disconnected, clear out the clients stuff.

        // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
        // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
        ret = epoll_ctl(
            lrsyslog->tcp_task_epoll_fd,
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
            lrsyslog->tcp_task_epoll_fd,
            EPOLL_CTL_DEL,
            client->watchdog.timer_fd,
            NULL
        );
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
            return -1;
        }
        close(client->watchdog.timer_fd);

        *client = (struct lrsyslog_client_s){0};
        
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
    ret = lrsyslog_client_parser_parse(&client->log, buf, bytes_read);
    if (-1 == ret) {
        syslog(LOG_WARNING, "%s:%d:%s: lrsyslog_client_parser_parse returned %d", __FILE__, __LINE__, __func__, ret);
        return -1;
    }

    // Re-arm the fd on the epoll
    ret = epoll_ctl(
        lrsyslog->tcp_task_epoll_fd,
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


static int lrsyslog_tcp_task_epoll_event_client_timer_fd (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{
    // If this triggers, that means we've seen no data from the client for some
    // time, and it's time to kick the client out.
    //
    int ret = 0;

    struct lrsyslog_client_watchdog_s * watchdog = event->data.ptr;
    if (18092 != watchdog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: watchdog sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    struct lrsyslog_client_s * client = (struct lrsyslog_client_s*)(((char*)watchdog) - offsetof(struct lrsyslog_client_s, watchdog));
    if (18091 != client->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: client sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    // Remember to EPOLL_CTL_DEL *before* closing the file descriptor, see
    // https://idea.popcount.org/2017-03-20-epoll-is-fundamentally-broken-22/
    ret = epoll_ctl(
        lrsyslog->tcp_task_epoll_fd,
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
        lrsyslog->tcp_task_epoll_fd,
        EPOLL_CTL_DEL,
        client->watchdog.timer_fd,
        NULL
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    close(client->watchdog.timer_fd);

    syslog(LOG_INFO, "%s:%d:%s: client has not sent any data in %d seconds, closing connection",
        __FILE__, __LINE__, __func__, CLIENT_PING_TIMEOUT_S);

    *client = (struct lrsyslog_client_s){0};
    
    return 0;
}


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


static const char * lrsyslog_tcp_task_severity_str (
    const uint8_t severity
)
{
    switch (severity) {
        case LOG_CRIT:
            return "crit";

        case LOG_EMERG:
            return "emerg";

        case LOG_ALERT:
            return "alert";

        case LOG_ERR:
            return "err";

        case LOG_WARNING:
            return "warning";

        case LOG_NOTICE:
            return "notice";

        case LOG_INFO:
            return "info";

        case LOG_DEBUG:
            return "debug";

        default:
            return "unknown";
    }
}


int lrsyslog_tcp_task_client_log_cb (
    const char * host,
    const uint32_t host_len,
    const char * tag,
    const uint32_t tag_len,
    const uint32_t facility,
    const uint32_t severity,
    const uint32_t pid,
    const char * msg,
    const uint32_t msg_len,
    void * user_data
)
{
    int ret = 0;
    int bytes_written = 0;

    struct lrsyslog_client_s * client = user_data;
    if (18091 != client->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: client sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    struct lrsyslog_s * lrsyslog = client->lrsyslog;
    if (8090 != lrsyslog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    struct lrsyslog_pipe_msg_s pipe_msg = {0};
    pipe_msg.severity = severity;
    pipe_msg.facility = facility;

    pipe_msg.topic_len = snprintf(
        pipe_msg.topic,
        128,
        "lrsyslog.%.*s.%.*s.%s.out",
        host_len, host,
        tag_len, tag,
        lrsyslog_tcp_task_severity_str(severity)
    );
    if (-1 == pipe_msg.topic_len) {
        syslog(LOG_ERR, "%s:%d:%s: snprintf: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    uint32_t msg_len_clamped = 1024;
    if (msg_len < msg_len_clamped) {
        msg_len_clamped = msg_len;
    }
    memcpy(&pipe_msg.msg, msg, msg_len_clamped);
    pipe_msg.msg_len = msg_len_clamped;

    bytes_written = write(lrsyslog->pipe_fd[1], &pipe_msg, sizeof(struct lrsyslog_pipe_msg_s));
    if (-1 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: write: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    if (0 == bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: wrote 0 bytes to pipe!", __FILE__, __LINE__, __func__);
        return -1;
    }
    if (sizeof(struct lrsyslog_pipe_msg_s) != bytes_written) {
        syslog(LOG_ERR, "%s:%d:%s: partial write of %d bytes to pipe!", __FILE__, __LINE__, __func__, bytes_written);
        return 0;
    }

    return 0;
    (void)ret;
}


static int lrsyslog_tcp_task_epoll_event_tcp_fd (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{
    // Accept the client into the lrsyslog religion/sect
    int ret;
    int client_fd = 0;
    struct sockaddr_storage their_addr = {0};
    socklen_t sin_size = sizeof(struct sockaddr_storage);
    
    client_fd = accept(lrsyslog->tcp_fd, (struct sockaddr*)&their_addr, &sin_size);
    if (-1 == client_fd) {
        syslog(LOG_ERR, "%s:%d:%s: accept: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // First off, we need to find a free spot for the client.
    for (int i = 0; i < CONFIG_MAX_CLIENTS; i++) {

        if (0 == lrsyslog->clients[i].sentinel) {

            // This spot is free! Assign it!
            lrsyslog->clients[i].sentinel = 18091;
            lrsyslog->clients[i].fd = client_fd;
            lrsyslog->clients[i].lrsyslog = lrsyslog;

            // Initialize the client parser
            ret = lrsyslog_client_parser_init(
                &lrsyslog->clients[i].log,
                /* log_cb = */ lrsyslog_tcp_task_client_log_cb,
                /* user_data = */ &lrsyslog->clients[i]
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_parser_init returned %d", __FILE__, __LINE__, __func__, ret);
                
            }

            // Create a watchdog timerfd for this client
            lrsyslog->clients[i].watchdog.sentinel = 18092;
            lrsyslog->clients[i].watchdog.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
            if (-1 == lrsyslog->clients[i].watchdog.timer_fd) {
                syslog(LOG_ERR, "%s:%d:%s: timerfd_create: %s", __FILE__, __LINE__, __func__, strerror(errno));
                return -1;
            }

            // Start the timer
            // arm timerfd
            ret = timerfd_settime(
                /* fd        = */ lrsyslog->clients[i].watchdog.timer_fd,
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
                lrsyslog->tcp_task_epoll_fd,
                EPOLL_CTL_ADD,
                lrsyslog->clients[i].watchdog.timer_fd,
                &(struct epoll_event){
                    .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
                    .data = {
                        .ptr = &lrsyslog->clients[i].watchdog
                    }
                }
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
                return -1;
            }


            // Add the client to epoll
            ret = epoll_ctl(
                lrsyslog->tcp_task_epoll_fd,
                EPOLL_CTL_ADD,
                client_fd,
                &(struct epoll_event){
                    .events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLONESHOT,
                    .data = {
                        .ptr = &lrsyslog->clients[i]
                    }
                }
            );
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: epoll_ctl: %s", __FILE__, __LINE__, __func__, strerror(errno));
                return -1;
            }


            // Before we go, let's re-arm the accept fd on epoll
            ret = epoll_ctl(
                lrsyslog->tcp_task_epoll_fd,
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


static int lrsyslog_tcp_task_epoll_event_dispatch (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event * event
)
{
    if (event->data.fd == lrsyslog->tcp_fd)
        return lrsyslog_tcp_task_epoll_event_tcp_fd(lrsyslog, event);

    // If it's not the connect socket, it's either a client fd or a timer fd
    // associated with a client. For that, we need to dispatch on the sentinel
    // value.
    int event_sentinel = *(int*)event->data.ptr;
    if (18091 == event_sentinel)
        return lrsyslog_tcp_task_epoll_event_client_fd(lrsyslog, event);

    if (18092 == event_sentinel)
        return lrsyslog_tcp_task_epoll_event_client_timer_fd(lrsyslog, event);

    // otherwise, we've got no match on the epoll, just quit.
    syslog(LOG_ERR, "%s:%d:%s: event dispatch defaulted!", __FILE__, __LINE__, __func__);
    return -1;
}


static int lrsyslog_tcp_task_epoll_handle_events (
    struct lrsyslog_s * lrsyslog,
    struct epoll_event epoll_events[EPOLL_NUM_EVENTS],
    int ep_events_len
)
{
    int ret = 0;
    for (int i = 0; i < ep_events_len; i++) {
        ret = lrsyslog_tcp_task_epoll_event_dispatch(lrsyslog, &epoll_events[i]);
        if (0 != ret) {
            return ret;
        }
    }
    return 0;
}


void * lrsyslog_tcp_task (
        void * arg
)
{
    int ret;
    struct lrsyslog_s * lrsyslog = arg;
    if (8090 != lrsyslog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog sentinel is wrong!", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    int ep_events_len = 0;
    struct epoll_event ep_events[EPOLL_NUM_EVENTS];
    for (ep_events_len = epoll_wait(lrsyslog->tcp_task_epoll_fd, ep_events, EPOLL_NUM_EVENTS, -1);
         ep_events_len > 0 || (-1 == ep_events_len && EINTR == errno);
         ep_events_len = epoll_wait(lrsyslog->tcp_task_epoll_fd, ep_events, EPOLL_NUM_EVENTS, -1))
    {
        ret = lrsyslog_tcp_task_epoll_handle_events(lrsyslog, ep_events, ep_events_len);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_tcp_task_epoll_handle_events returned %d", __FILE__, __LINE__, __func__, ret);
            exit(EXIT_FAILURE);
        }
    }
    if (-1 == ep_events_len) {
        syslog(LOG_ERR, "%s:%d:%s: epoll_wait: %s", __FILE__, __LINE__, __func__, strerror(errno));
        exit(EXIT_FAILURE);
    }

    return 0;
}
