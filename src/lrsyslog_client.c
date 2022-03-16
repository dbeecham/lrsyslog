#define _DEFAULT_SOURCE

#include <stdint.h>
#include <syslog.h>
#include <stdatomic.h>
#include <assert.h>

#include <liburing.h>

#include "lrsyslog.h"
#include "lrsyslog_client.h"
#include "lrsyslog_client_parser.h"

static const char * lrsyslog_client_facility_str (
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


void lrsyslog_client_severity_str (
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


// Decrements the refcount of a client. When a client is first created, it's
// refcount is set to 1, and every read operation which needs a pointer to the
// client structure in the uring user data increments the refcount; except the
// close syscall. When the close syscall has returned, and all other syscalls
// regarding the client has also returned, the client structure is freed.
int lrsyslog_client_rc_sub (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s ** client
)
{
    
    uint32_t rc = atomic_fetch_sub(&(*client)->refcount, 1);
    if (1 == rc) {
        free(*client);
        *client = NULL;
        return 0;
    }
    if (0 == rc) {
        syslog(LOG_INFO, "%s:%d:%s: tried to free client, but it's already freed", __FILE__, __LINE__, __func__);
        return -1;
    }

    return 0;
}


int lrsyslog_client_rc_inc (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s * client
)
{
    atomic_fetch_add(&client->refcount, 1);
    return 0;
}


int lrsyslog_client_syslog_cb (
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
    struct lrsyslog_uring_event_s * event = NULL;

    const char * severity_str;
    uint32_t severity_str_len;
    lrsyslog_client_severity_str(severity, &severity_str, &severity_str_len);


    // add a write request on the new client
    ret = lrsyslog_uring_event_new(lrsyslog, &event);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_new returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    event->type = LRSYSLOG_URING_EVENT_CLIENT_WRITE_NATS;
    event->client = client;

    // increment client refcount
    lrsyslog_client_rc_inc(lrsyslog, event->client);

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
                .iov_base = (char*)tag,
                .iov_len = tag_len
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
                ".out ",
                .iov_len = 5
            },
            {
                .iov_base = (char*)msg_len_str,
                .iov_len = msg_len_str_len
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
        /* ioved_len = */ 9,
        /* offset = */ 0
    );
    io_uring_sqe_set_data(sqe, event);
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
            .tv_sec = 5,
            .tv_nsec = 0
        },
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);



    io_uring_submit(&lrsyslog->ring);

    return 0;
    (void)ret;
}


int lrsyslog_client_read (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s * client
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;
    struct lrsyslog_uring_event_s * event = NULL;

    // add a read request on the new client
    ret = lrsyslog_uring_event_new(lrsyslog, &event);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_new returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    event->type = LRSYSLOG_URING_EVENT_CLIENT_READ;
    event->client = client;

    // increment refcount on the client
    lrsyslog_client_rc_inc(lrsyslog, client);


    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (unlikely(NULL == sqe)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_read(
        /* sqe = */ sqe,
        /* fd = */ client->fd,
        /* buf = */ client->read_buf,
        /* buf_len = */ CONFIG_CLIENT_READ_BUF_LEN,
        /* offset = */ 0
    );
    io_uring_sqe_set_data(sqe, event);
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
            .tv_sec = CONFIG_CLIENT_TIMEOUT_S,
            .tv_nsec = 0
        },
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, 0);
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);

    io_uring_submit(&lrsyslog->ring);

    return 0;
}


int lrsyslog_client_close (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s * client
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;
    struct lrsyslog_uring_event_s * event = NULL;

    // add a close request on the new client
    ret = lrsyslog_uring_event_new(lrsyslog, &event);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_new returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    event->type = LRSYSLOG_URING_EVENT_CLIENT_CLOSE;
    event->client = client;

    // increment refcount on the client
    lrsyslog_client_rc_inc(lrsyslog, client);

    // send close syscall
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (unlikely(NULL == sqe)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_close(
        /* sqe = */ sqe,
        /* fd = */ client->fd
    );
    io_uring_sqe_set_data(sqe, event);
    io_uring_submit(&lrsyslog->ring);

    return 0;
}


int lrsyslog_client_new (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s ** client,
    int fd,
    struct lrsyslog_client_parser_callbacks_s cbs
)
{

    int ret = 0;

    *client = malloc(sizeof(struct lrsyslog_client_s));
    if (unlikely(NULL == *client)) {
        syslog(LOG_ERR, "%s:%d:%s: malloc returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }

    (*client)->refcount = 1;
    (*client)->fd = fd;
    (*client)->lrsyslog = lrsyslog;

    // Initialize the client parser
    ret = lrsyslog_client_parser_init(
        &(*client)->parser,
        /* callbacks = */ cbs,
        /* user_data = */ *client
    );
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_parser_init returned %d", __FILE__, __LINE__, __func__, ret);
        return -1;
    }

    return 0;
}


int lrsyslog_uring_event_client_read (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
)
{
    int ret = 0;
    uint32_t bytes_parsed = 0;
    

    if (-ECANCELED == cqe->res) {
        ret = lrsyslog_client_close(lrsyslog, event->client);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_close returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        // mark this event as seen
        ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
        if (unlikely(-1 == ret)) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
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
    if (cqe->res < 0) {
        ret = lrsyslog_client_close(lrsyslog, event->client);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_close returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        // mark this event as seen
        ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
        if (unlikely(-1 == ret)) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
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
    if (0 == cqe->res) {
        ret = lrsyslog_client_close(lrsyslog, event->client);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_close returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
        if (unlikely(-1 == ret)) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        // mark this event as seen
        ret = lrsyslog_uring_event_rc_sub(lrsyslog, event);
        if (unlikely(-1 == ret)) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_rc_sub returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        io_uring_cqe_seen(&lrsyslog->ring, cqe);

        return 0;
    }

    // parse read data
    ret = lrsyslog_client_parser_parse(&event->client->parser, event->client->read_buf, cqe->res, &bytes_parsed);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_parser_parse returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }
    if (unlikely(cqe->res < ret)) {
        syslog(LOG_ERR, "%s:%d:%s: BUG!", __FILE__, __LINE__, __func__);
        return -1;
    }
    if (1 == ret) {
        // callback was called; don't re-arm the read syscall on uring.
        event->client->read_buf_len = cqe->res - bytes_parsed;
        event->client->read_buf_p = event->client->read_buf + bytes_parsed;

        assert(event->client->read_buf_len <= CONFIG_CLIENT_READ_BUF_LEN);

        // parsed a message successfully, don't re-arm the read request just yet.
        ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
        if (unlikely(-1 == ret)) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
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
    event->client->read_buf_len = 0;


    // read more data
    ret = lrsyslog_client_read(lrsyslog, event->client);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_read returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    // mark this event as seen
    ret = lrsyslog_uring_event_rc_sub(lrsyslog, event);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_rc_sub returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    io_uring_cqe_seen(&lrsyslog->ring, cqe);
    
    return 0;
}


int lrsyslog_uring_event_client_close (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
)
{
    int ret = 0;

    ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
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


int lrsyslog_uring_event_client_write_nats (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
)
{
    int ret = 0;
    uint32_t bytes_parsed = 0;

    if (cqe->res <= 0) {
        syslog(LOG_ERR, "%s:%d:%s: write: %s", __FILE__, __LINE__, __func__, strerror(cqe->res));
        return -1;
    }

    // do we have more data we need to parse?
    if (0 != event->client->read_buf_len) {
        ret = lrsyslog_client_parser_parse(&event->client->parser, event->client->read_buf_p, event->client->read_buf_len, &bytes_parsed);
        if (unlikely(-1 == ret)) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_parser_parse returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }
        if (1 == ret) {
            // callback was called; don't re-arm the read syscall on uring.
            event->client->read_buf_len -= bytes_parsed;
            event->client->read_buf_p += bytes_parsed;

            assert(event->client->read_buf_len <= CONFIG_CLIENT_READ_BUF_LEN);

            // parsed a message successfully, don't re-arm the read request just yet.
            ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
            if (unlikely(-1 == ret)) {
                syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
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
        event->client->read_buf_len = 0;
    }

    ret = lrsyslog_client_read(lrsyslog, event->client);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_read returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    ret = lrsyslog_client_rc_sub(lrsyslog, &event->client);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_rc_sub returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    // mark this event as seen
    ret = lrsyslog_uring_event_rc_sub(lrsyslog, event);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_rc_sub returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    io_uring_cqe_seen(&lrsyslog->ring, cqe);
    
    return 0;
}
