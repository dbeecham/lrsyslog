// _GNU_SOURCE for pipe2()
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
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <liburing.h>
#include <poll.h>
#include <stddef.h>

#include "lrsyslog.h"
#include "lrsyslog_tcp.h"
#include "lrsyslog_nats.h"
#include "lrsyslog_args_parser.h"


int lrsyslog_init (
    struct lrsyslog_s * lrsyslog
)
{

    int ret = 0;

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


int lrsyslog_uring_event_client_fd_read (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_client_s * client
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;

    if (-ECANCELED == cqe->res) {
        // read request timed out - close the client.

        // mark this client as closing
        client->closing = true;

        // send close syscall
        sqe = io_uring_get_sqe(&lrsyslog->ring);
        if (NULL == sqe) {
            syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
            return -1;
        }
        io_uring_prep_close(
            /* sqe = */ sqe,
            /* fd = */ client->fd
        );
        io_uring_sqe_set_data(sqe, client);
        io_uring_submit(&lrsyslog->ring);

        // mark this event as seen
        io_uring_cqe_seen(&lrsyslog->ring, cqe);

        return 0;
    }
    if (cqe->res < 0) {
        // some other generic error occured, close the client...

        // mark client as closing
        client->closing = true;

        sqe = io_uring_get_sqe(&lrsyslog->ring);
        if (NULL == sqe) {
            syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
            return -1;
        }
        io_uring_prep_close(
            /* sqe = */ sqe,
            /* fd = */ client->fd
        );
        io_uring_sqe_set_data(sqe, client);
        io_uring_submit(&lrsyslog->ring);

        // mark this event as seen
        io_uring_cqe_seen(&lrsyslog->ring, cqe);

        return 0;
    }
    if (0 == cqe->res) {
        // client closed connection, close it on our end as well...

        // mark client as closing
        client->closing = true;

        sqe = io_uring_get_sqe(&lrsyslog->ring);
        if (NULL == sqe) {
            syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
            return -1;
        }
        io_uring_prep_close(
            /* sqe = */ sqe,
            /* fd = */ client->fd
        );
        io_uring_sqe_set_data(sqe, client);
        io_uring_submit(&lrsyslog->ring);

        // mark this event as seen
        io_uring_cqe_seen(&lrsyslog->ring, cqe);

        return 0;
    }

    syslog(LOG_DEBUG, "%s:%d:%s: parsing", __FILE__, __LINE__, __func__);

    // parse read data
    ret = lrsyslog_client_parser_parse(&client->parser, client->read_buf, cqe->res);
    if (unlikely(-1 == ret)) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_parser_parse returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }
    if (ret < cqe->res) {
        syslog(LOG_DEBUG, "%s:%d:%s: more data to read", __FILE__, __LINE__, __func__);
        client->read_buf_len = cqe->res - ret;
        client->read_buf_p = client->read_buf + ret;
        // parsed a message successfully, don't re-arm the read request just yet.
        io_uring_cqe_seen(&lrsyslog->ring, cqe);
        return 0;
    }
    if (cqe->res < ret) {
        syslog(LOG_ERR, "%s:%d:%s: nooo", __FILE__, __LINE__, __func__);
        return -1;
    }

    // add a new read request on the client
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (unlikely(NULL == sqe)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_read(
        /* sqe = */ sqe,
        /* fd = */ client->fd,
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
    
    // mark this event as seen
    io_uring_cqe_seen(&lrsyslog->ring, cqe);
    
    return 0;
}


int lrsyslog_uring_event_client_fd_closing (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_client_s * client
)
{
    free(client);
    io_uring_cqe_seen(&lrsyslog->ring, cqe);
    return 0;
}


int lrsyslog_uring_event_client_fd_wrote_to_nats (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_client_s * client
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;

    if (cqe->res <= 0) {
        // mark client as closing
        client->closing = true;
        client->writing_to_nats = false;

        sqe = io_uring_get_sqe(&lrsyslog->ring);
        if (NULL == sqe) {
            syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
            return -1;
        }
        io_uring_prep_close(
            /* sqe = */ sqe,
            /* fd = */ client->fd
        );
        io_uring_sqe_set_data(sqe, client);
        io_uring_submit(&lrsyslog->ring);

        // mark this event as seen
        io_uring_cqe_seen(&lrsyslog->ring, cqe);

        return 0;
    }

    syslog(LOG_DEBUG, "%s:%d:%s: hi!", __FILE__, __LINE__, __func__);

    // do we have more data we need to parse?
    if (0 != client->read_buf_len) {
        syslog(LOG_DEBUG, "%s:%d:%s: we have more data to parse", __FILE__, __LINE__, __func__);
        ret = lrsyslog_client_parser_parse(&client->parser, client->read_buf_p, client->read_buf_len);
        if (ret < client->read_buf_len) {
            // we have even more data to parse
            client->read_buf_p = client->read_buf_p + ret;
            client->read_buf_len = client->read_buf_len - ret;

            // mark this event as seen
            io_uring_cqe_seen(&lrsyslog->ring, cqe);

            return 0;
        }
    }

    client->writing_to_nats = false;

    // add a new read request on the client
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (unlikely(NULL == sqe)) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_read(
        /* sqe = */ sqe,
        /* fd = */ client->fd,
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
    
    // mark this event as seen
    io_uring_cqe_seen(&lrsyslog->ring, cqe);
    
    return 0;
}


int lrsyslog_uring_event_client_fd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
)
{
    struct lrsyslog_client_s * client = (struct lrsyslog_client_s*)cqe->user_data;

    if (1 == client->writing_to_nats)
        return lrsyslog_uring_event_client_fd_wrote_to_nats(lrsyslog, cqe, client);

    if (0 == client->closing)
        return lrsyslog_uring_event_client_fd_read(lrsyslog, cqe, client);

    return lrsyslog_uring_event_client_fd_closing(lrsyslog, cqe, client);



}


int lrsyslog_uring_dispatch (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
)
{
    if (0 == cqe->user_data) {
        // if cqe->res == -ETIME, then this is a timer that expired (not interested)
        io_uring_cqe_seen(&lrsyslog->ring, cqe);
        return 0;
    }

    if (*(int*)cqe->user_data == lrsyslog->tcp_fd)
        return lrsyslog_uring_event_tcp_fd(lrsyslog, cqe);

    if (*(int*)cqe->user_data == lrsyslog->nats.fd)
        return lrsyslog_uring_event_nats_fd(lrsyslog, cqe);

    if (*(int*)cqe->user_data == LRSYSLOG_CLIENT_SENTINEL)
        return lrsyslog_uring_event_client_fd(lrsyslog, cqe);

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
        .sentinel = LRSYSLOG_SENTINEL,
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

    // Create tcp listener threads
//    for (int i = 0; i < CONFIG_NUM_THREADS; i++) {
//        ret = pthread_create(&lrsyslog.tcp_task_threads[i], NULL, lrsyslog_tcp_task, &lrsyslog);
//        if (0 != ret) {
//            syslog(LOG_ERR, "%s:%d: pthread_create: %s", __func__, __LINE__, strerror(errno));
//            return -1;
//        }
//    }


    // And the nats thread
//    ret = pthread_create(&lrsyslog.nats_thread, NULL, lrsyslog_nats_task, &lrsyslog);
//    if (0 != ret) {
//        syslog(LOG_ERR, "%s:%d: pthread_create: %s", __func__, __LINE__, strerror(errno));
//        return -1;
//    }

    exit(EXIT_SUCCESS);	
    (void)argc;
    (void)argv;
}
