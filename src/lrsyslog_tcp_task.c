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
    void * user_data
)
{
    struct io_uring_sqe * sqe;
    int ret = 0;
    int bytes_written = 0;
    char topic[128];
    int topic_len;
    char payload_len[32];
    int payload_len_len = 0;

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


    topic_len = snprintf(
        topic,
        128,
        "lrsyslog.%.*s.%.*s.%s.out ",
        host_len, host,
        tag_len, tag,
        lrsyslog_tcp_task_severity_str(severity)
    );
    if (-1 == topic_len) {
        syslog(LOG_ERR, "%s:%d:%s: snprintf: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    payload_len_len = snprintf(
        payload_len,
        sizeof(payload_len),
        "%d\r\n",
        msg_len
    );

    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_writev(
        /* sqe = */ sqe,
        /* fd = */ lrsyslog->nats.fd,
        /* iovec = */ (struct iovec[]) {
            {
                .iov_base = "PUB ",
                .iov_len = 4
            },
            {
                .iov_base = topic,
                .iov_len = topic_len
            },
            {
                .iov_base = payload_len,
                .iov_len = payload_len_len
            },
            {
                .iov_base = (void*)msg,
                .iov_len = msg_len
            },
            {
                .iov_base = "\r\n",
                .iov_len = 2
            }
        },
        /* ioved_len = */ 5,
        /* offset = */ 0
    );
    io_uring_sqe_set_data(sqe, 0);
    io_uring_submit(&lrsyslog->ring);

    return 0;
    (void)ret;
}
