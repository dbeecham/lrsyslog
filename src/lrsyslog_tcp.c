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


static const char * lrsyslog_tcp_facility_str (
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


void lrsyslog_tcp_severity_str (
    const uint32_t severity,
    const char ** severity_str,
    uint32_t * severity_str_len
)
{
    switch (severity) {
        case LOG_CRIT:
            *severity_str = "crit";
            *severity_str_len = 4;
            return;

        case LOG_EMERG:
            *severity_str = "emerg";
            *severity_str_len = 5;
            return;

        case LOG_ALERT:
            *severity_str = "alert";
            *severity_str_len = 5;
            return;

        case LOG_ERR:
            *severity_str = "err";
            *severity_str_len = 3;
            return;

        case LOG_WARNING:
            *severity_str = "warning";
            *severity_str_len = 7;
            return;

        case LOG_NOTICE:
            *severity_str = "notice";
            *severity_str_len = 6;
            return;

        case LOG_INFO:
            *severity_str = "info";
            *severity_str_len = 4;
            return;

        case LOG_DEBUG:
            *severity_str = "debug";
            *severity_str_len = 5;
            return;

        default:
            *severity_str = "unknown";
            *severity_str_len = 7;
            return;
    }
}


int lrsyslog_client_log_cb (
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
    int ret = 0;
    struct io_uring_sqe * sqe;
    const char * severity_str = 0;
    uint32_t severity_str_len = 0;

    struct lrsyslog_client_s * client = user_data;
    if (LRSYSLOG_CLIENT_SENTINEL != client->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: client sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    struct lrsyslog_s * lrsyslog = client->lrsyslog;
    if (LRSYSLOG_SENTINEL != lrsyslog->sentinel) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog sentinel is wrong!", __FILE__, __LINE__, __func__);
        return -1;
    }

    lrsyslog_tcp_severity_str(severity, &severity_str, &severity_str_len);

    client->writing = true;

    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_writev(
        /* sqe = */ sqe,
        /* fd = */ lrsyslog->nats.fd,
        /* iovec = */ (const struct iovec[]) {
            {
                .iov_base = "PUB lrsyslog.",
                .iov_len = 13
            },
            {
                .iov_base = (char*)host,
                .iov_len = host_len,
            },
            {
                .iov_base = ".",
                .iov_len = 1
            },
            {
                .iov_base = (char*)tag,
                .iov_len = tag_len,
            },
            {
                .iov_base = ".",
                .iov_len = 1
            },
            {
                .iov_base = (char*)severity_str,
                .iov_len = severity_str_len
            },
            {
                .iov_base = ".out ",
                .iov_len = 5
            },
            {
                .iov_base = (char*)msg_len_str,
                .iov_len = msg_len_str_len,
            },
            {
                .iov_base = "\r\n",
                .iov_len = 2
            },
            {
                .iov_base = (char*)msg,
                .iov_len = msg_len
            },
            {
                .iov_base = "\r\n",
                .iov_len = 2
            }
        },
        /* ioved_len = */ 11,
        /* offset = */ 0
    );
    io_uring_sqe_set_data(sqe, client);
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);

    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_link_timeout(
        /* sqe = */ sqe, 
        /* timespec = */ &(struct __kernel_timespec) {
            .tv_sec = 3,
            .tv_nsec = 0
        },
        /* flags = */ 0
    );
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
    io_uring_sqe_set_data(sqe, 0);


    io_uring_submit(&lrsyslog->ring);

    return 0;
    (void)ret;
}
