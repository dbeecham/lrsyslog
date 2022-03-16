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
#include <sys/signalfd.h>
#include <sys/resource.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <liburing.h>
#include <poll.h>
#include <stddef.h>
#include <stdatomic.h>

#include "lrsyslog.h"
#include "lrsyslog_tcp.h"
#include "lrsyslog_client.h"
#include "lrsyslog_nats.h"
#include "lrsyslog_args_parser.h"


int lrsyslog_uring_event_rc_sub (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_uring_event_s * event
)
{
    uint_fast8_t rc = atomic_fetch_sub(&event->refcount, 1);
    if (unlikely(0 == rc)) {
        syslog(LOG_ERR, "%s:%d:%s: tried to unlock %ld, but it's not locked!", __FILE__, __LINE__, __func__, event - lrsyslog->events);
        return -1;
    }

    // could free here if we malloc these instead
    return 0;
}


int lrsyslog_uring_event_new (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_uring_event_s ** event
)
{
    int ret = 0;
    uint_fast32_t i;
    uint_fast32_t rc;

    for (int j = 0; j < CONFIG_URING_HANDLES; j++) {

        i = atomic_fetch_add(&lrsyslog->events_i, 1); 

        rc = atomic_fetch_add(&lrsyslog->events[i % CONFIG_URING_HANDLES].refcount, 1);
        if (likely(0 == rc)) {
            *event = &lrsyslog->events[i % CONFIG_URING_HANDLES];
            return 0;
        }

        ret = lrsyslog_uring_event_rc_sub(lrsyslog, &lrsyslog->events[i % CONFIG_URING_HANDLES]);
        if (unlikely(-1 == ret)) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_event_rc_sub returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

    }

    syslog(LOG_ERR, "%s:%d:%s: unable to find a free uring event slot", __FILE__, __LINE__, __func__);
    return -1;
}


int lrsyslog_init_rlimit (
    struct lrsyslog_s * lrsyslog
)
{
    int ret = 0;
    struct rlimit rlim = {0};


    // set number of file descriptors to its hard limit
    ret = getrlimit(RLIMIT_NOFILE, &rlim);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: getrlimit: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    rlim.rlim_cur = rlim.rlim_max;

    ret = setrlimit(RLIMIT_NOFILE, &rlim);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: setrlimit: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    

    return 0;
}


int lrsyslog_init (
    struct lrsyslog_s * lrsyslog
)
{

    int ret = 0;

    ret = lrsyslog_init_rlimit(lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_init_rlimit returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }


    ret = io_uring_queue_init(CONFIG_URING_DEPTH, &lrsyslog->ring, 0);
    if (unlikely(0 != ret)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_queue_init: %s", __FILE__, __LINE__, __func__, strerror(-ret));
        return -1;
    }

    // Main thread needs a filled sigset on a signalfd to react to signals
    sigset_t sigset = {0};
    ret = sigfillset(&sigset);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: sigfillset: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // Create the signalfd
//    lrsyslog->signal_fd = signalfd(
//        /* fd = */ -1,
//        /* &sigset = */ &sigset,
//        /* flags = */ SFD_NONBLOCK | SFD_CLOEXEC
//    );
//    if (-1 == lrsyslog->signal_fd) {
//        syslog(LOG_ERR, "%s:%d:%s: signalfd: %s", __FILE__, __LINE__, __func__, strerror(errno));
//        return -1;
//    }


    // Block the signals
//    ret = sigprocmask(
//            /* how = */ SIG_BLOCK,
//            /* &sigset = */ &sigset,
//            /* &oldset = */ NULL
//    );
//    if (-1 == ret) {
//        syslog(LOG_ERR, "%s:%d:%s: sigprocmask: %s", __FILE__, __LINE__, __func__, strerror(errno));
//        return -1;
//    }


    // initialize the nats parser
    ret = lrsyslog_nats_parser_init(
        &lrsyslog->nats.parser,
        lrsyslog_nats_ping_cb,
        lrsyslog,
        NULL
    );
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_nats_parser_init returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    return 0;
}


int lrsyslog_uring_dispatch (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
)
{

    if (0 == cqe->user_data) {
        // if cqe->res == -ETIME, then this is a timer that expired (not
        // interested because the write/read will have errno set to -ETIMEOUT
        // as well)
        io_uring_cqe_seen(&lrsyslog->ring, cqe);
        return 0;
    }

    struct lrsyslog_uring_event_s * event = io_uring_cqe_get_data(cqe);

    if (LRSYSLOG_URING_EVENT_CLIENT_READ == event->type) {
        return lrsyslog_uring_event_client_read(lrsyslog, cqe, event);
    }

    if (LRSYSLOG_URING_EVENT_CLIENT_WRITE_NATS == event->type) {
        return lrsyslog_uring_event_client_write_nats(lrsyslog, cqe, event);
    }

    if (LRSYSLOG_URING_EVENT_CLIENT_CLOSE == event->type) {
        return lrsyslog_uring_event_client_close(lrsyslog, cqe, event);
    }

    if (LRSYSLOG_URING_EVENT_ACCEPT == event->type) {
        return lrsyslog_uring_event_listen_fd(lrsyslog, cqe, event);
    }

    if (LRSYSLOG_URING_EVENT_NATS_READ == event->type) {
        return lrsyslog_uring_event_nats_read(lrsyslog, cqe, event);
    }

    syslog(LOG_ERR, "%s:%d:%s: unhandled cqe! user_data=%d", __FILE__, __LINE__, __func__, *(int*)cqe->user_data);
    return -1;
}


int lrsyslog_loop (
    struct lrsyslog_s * lrsyslog
)
{
    int ret = 0;
    struct io_uring_cqe * cqe;

    while (1) {

        ret = io_uring_wait_cqe(&lrsyslog->ring, &cqe);
        if (unlikely(0 < ret)) {
            syslog(LOG_ERR, "%s:%d:%s: io_uring_wait_cqe: %s", __FILE__, __LINE__, __func__, strerror(-ret));
            return -1;
        }

        ret = lrsyslog_uring_dispatch(lrsyslog, cqe);
        if (unlikely(-1 == ret)) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_uring_dispatch returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

    }
}


int main (
    const int argc,
    const char *argv[]
)
{
    int ret = 0;

    openlog(CONFIG_SYSLOG_IDENT, LOG_NDELAY, LOG_USER);

    struct lrsyslog_s lrsyslog = {
        .opts = {
            .port = CONFIG_PORT
        }
    };
    
    ret = lrsyslog_init(&lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_init returned %d", __FILE__, __LINE__, __func__, ret);
        exit(EXIT_FAILURE);
    }

    // parse command line arguments
    ret = lrsyslog_args_parser_parse(
        /* argc = */ argc,
        /* argv = */ argv,
        /* opts = */ &lrsyslog.opts
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_args_parser_parse returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    // connect to nats
    ret = lrsyslog_nats_connect(&lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_nats_connect returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    // start listening for connections
    ret = lrsyslog_tcp_server_start(&lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_tcp_server_start returned %d", __FILE__, __LINE__, __func__, ret);
        exit(EXIT_FAILURE);
    }


    ret = lrsyslog_loop(&lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_loop returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    syslog(LOG_DEBUG, "%s:%d:%s: bye!", __FILE__, __LINE__, __func__);
    return 0;

    (void)argc;
    (void)argv;
}
