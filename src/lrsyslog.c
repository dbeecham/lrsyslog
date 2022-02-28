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
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <liburing.h>

#include "lrsyslog.h"
#include "lrsyslog_tcp.h"
#include "lrsyslog_nats.h"
#include "lrsyslog_args_parser.h"
#include "lrsyslog_nats_parser.h"


#define EPOLL_NUM_EVENTS 8

int lrsyslog_init (
    struct lrsyslog_s * lrsyslog
)
{

    int ret = 0;

    ret = io_uring_queue_init(CONFIG_URING_DEPTH, &lrsyslog->ring, 0);
    if (0 != ret) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_queue_init: %s", __FILE__, __LINE__, __func__, strerror(-ret));
        return -1;
    }

    // Main thread needs a filled sigset on a signalfd to react to signals
    ret = sigemptyset(&lrsyslog->sigset);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: sigemptyset: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }
    
    ret = sigfillset(&lrsyslog->sigset);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: sigfillset: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }

    // Create the signalfd
    lrsyslog->signalfd = signalfd(
        /* fd = */ -1,
        /* &sigset = */ &lrsyslog->sigset,
        /* flags = */ SFD_NONBLOCK | SFD_CLOEXEC
    );
    if (-1 == lrsyslog->signalfd) {
        syslog(LOG_ERR, "%s:%d:%s: signalfd: %s", __FILE__, __LINE__, __func__, strerror(errno));
        return -1;
    }


    // Block the signals
//    ret = sigprocmask(
//            /* how = */ SIG_BLOCK,
//            /* &sigset = */ &lrsyslog->sigset,
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
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_nats_parser_init returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    return 0;
}


static int lrsyslog_tcp_server_start (
    struct lrsyslog_s * lrsyslog
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;

    syslog(LOG_DEBUG, "%s:%d:%s: hi!", __FILE__, __LINE__, __func__);

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
        lrsyslog->syslogfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (-1 == lrsyslog->syslogfd) {
            syslog(LOG_WARNING, "%s:%d:%s: socket: %s", __FILE__, __LINE__, __func__, strerror(errno));
            // let's try the next entry...
            continue;
        }

        // Set the socket REUSEADDR - this makes sure that we can start the
        // application after a restart even if the socket is still registered
        // in the kernel by the old application due to stale connections from
        // clients.
        ret = setsockopt(lrsyslog->syslogfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
        if (-1 == ret) {
            syslog(LOG_WARNING, "%s:%d:%s: setsockopt: %s", __FILE__, __LINE__, __func__, strerror(errno));
            // We don't care if this doesn't work so much - we can run without REUSEADDR.
        }

        // Bind the socket to the port
        ret = bind(lrsyslog->syslogfd, p->ai_addr, p->ai_addrlen);
        if (-1 == ret) {
            // Ok, we couldn't bind this socket - close this socket and try the
            // next hit from getaddrinfo.
            syslog(LOG_WARNING, "%s:%d:%s: bind: %s", __FILE__, __LINE__, __func__, strerror(errno));
            close(lrsyslog->syslogfd);
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
    ret = listen(lrsyslog->syslogfd, TCP_LISTEN_BACKLOG);
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
        /* fd = */ lrsyslog->syslogfd, 
        /* addrinfo = */ NULL,
        /* addrinfo_len = */ 0,
        /* flags = */ 0
    );
    io_uring_sqe_set_data(sqe, &lrsyslog->syslogfd);
    io_uring_submit(&lrsyslog->ring);

    // We're done - we have a fd on the epoll that will trigger on incoming
    // connection.
    return 0;
}


int lrsyslog_client_read (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s * client
)
{
    struct io_uring_sqe * sqe = NULL;

    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
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
            .tv_sec = CONFIG_CLIENT_READ_TIMEOUT_S,
            .tv_nsec = 0
        },
        /* flags = */ 0
    );
    io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
    io_uring_sqe_set_data(sqe, 0);

    io_uring_submit(&lrsyslog->ring);

    return 0;
}


int lrsyslog_uring_event_syslogfd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
)
{
    int ret = 0;
    struct io_uring_sqe * sqe;

    if (cqe->res < 0) {
        syslog(LOG_ERR, "%s:%d:%s: accept: %s", __FILE__, __LINE__, __func__, strerror(-cqe->res));
        return -1;
    }


    // malloc a data struct for the user
    struct lrsyslog_client_s * client = malloc(sizeof(struct lrsyslog_client_s));
    client->sentinel = LRSYSLOG_CLIENT_SENTINEL;
    client->fd = cqe->res;
    client->lrsyslog = lrsyslog;
    client->writing = false;
    client->closing = false;

    // Initialize the client parser
    ret = lrsyslog_client_parser_init(
        &client->parser,
        /* log_cb = */ lrsyslog_client_log_cb,
        /* user_data = */ client
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_parser_init returned %d", __FILE__, __LINE__, __func__, ret);
        return -1;
    }

    ret = lrsyslog_client_read(lrsyslog, client);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_read returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    // accept more connections
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_accept(sqe, lrsyslog->syslogfd, NULL, 0, 0);
    io_uring_sqe_set_data(sqe, &lrsyslog->syslogfd);
    io_uring_submit(&lrsyslog->ring);


    // mark this event as seen
    io_uring_cqe_seen(&lrsyslog->ring, cqe);


    return 0;
}


int lrsyslog_client_close (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s * client
)
{
    struct io_uring_sqe * sqe = NULL;

    // client error, clear it out
    client->closing = 1;
    sqe = io_uring_get_sqe(&lrsyslog->ring);
    if (NULL == sqe) {
        syslog(LOG_ERR, "%s:%d:%s: io_uring_get_sqe returned NULL", __FILE__, __LINE__, __func__);
        return -1;
    }
    io_uring_prep_close(sqe, client->fd);
    io_uring_sqe_set_data(sqe, client);
    io_uring_submit(&lrsyslog->ring);

    return 0;
}


int lrsyslog_uring_event_client_fd_read (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_client_s * client
)
{
    int ret = 0;

    if (cqe->res <= 0) {
        ret = lrsyslog_client_close(lrsyslog, client);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_close returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        // mark this event as seen
        io_uring_cqe_seen(&lrsyslog->ring, cqe);
        return 0;
        return 0;
    }

    ret = lrsyslog_client_parser_parse(&client->parser, client->read_buf, cqe->res);
    if (-1 == ret) {
        ret = lrsyslog_client_close(lrsyslog, client);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_close returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        // mark this event as seen
        io_uring_cqe_seen(&lrsyslog->ring, cqe);
        return 0;
    }
    if (true == client->writing) {
        // we haven't consumed all bytes yet; wait until the write returns, and
        // continue parsing then.
        client->read_buf_i = ret;
        client->read_buf_len = cqe->res;

        // mark this event as seen
        io_uring_cqe_seen(&lrsyslog->ring, cqe);
        return 0;
    }

    ret = lrsyslog_client_read(lrsyslog, client);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_read returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }
    
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


int lrsyslog_uring_event_client_fd_write (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_client_s * client
)
{
    int ret = 0;

    client->writing = false;

    // after we've written a message to nats, we need to check if there is more
    // data to parse and if so, call the parser.

    if (client->read_buf_i < client->read_buf_len) {

        uint32_t bytes_left = client->read_buf_len - client->read_buf_i;

        ret = lrsyslog_client_parser_parse(
            /* parser = */ &client->parser,
            /* buf = */ client->read_buf + client->read_buf_i,
            /* buf_len = */ bytes_left
        );
        if (-1 == ret) {
            ret = lrsyslog_client_close(lrsyslog, client);
            if (-1 == ret) {
                syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_close returned -1", __FILE__, __LINE__, __func__);
                return -1;
            }

            // mark this event as seen
            io_uring_cqe_seen(&lrsyslog->ring, cqe);
            return 0;
        }
        if (true == client->writing) {
            client->read_buf_i += ret;
            // mark this event as seen
            io_uring_cqe_seen(&lrsyslog->ring, cqe);
            return 0;
        }

        // all good, we've parsed all the data available, add a new read
        // request on the client.
        ret = lrsyslog_client_read(lrsyslog, client);
        if (-1 == ret) {
            syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_read returned -1", __FILE__, __LINE__, __func__);
            return -1;
        }

        // mark this event as seen
        io_uring_cqe_seen(&lrsyslog->ring, cqe);

        return 0;
    }

    // we don't have any more data to parse, just add a new read request on the
    // client.
    ret = lrsyslog_client_read(lrsyslog, client);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_client_read returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

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

    if (1 == client->closing)
        return lrsyslog_uring_event_client_fd_closing(lrsyslog, cqe, client);

    if (true == client->writing)
        return lrsyslog_uring_event_client_fd_write(lrsyslog, cqe, client);

    return lrsyslog_uring_event_client_fd_read(lrsyslog, cqe, client);
}


int lrsyslog_uring_dispatch (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
)
{
    if (0 == cqe->user_data) {
        io_uring_cqe_seen(&lrsyslog->ring, cqe);
        return 0;
    }
    if (1 == cqe->user_data) {
    }

    if (*(int*)cqe->user_data == lrsyslog->syslogfd)
        return lrsyslog_uring_event_syslogfd(lrsyslog, cqe);

    if (*(int*)cqe->user_data == lrsyslog->nats.fd)
        return lrsyslog_uring_event_nats_fd(lrsyslog, cqe);

    if (LRSYSLOG_CLIENT_SENTINEL == ((struct lrsyslog_client_s*)cqe->user_data)->sentinel)
        return lrsyslog_uring_event_client_fd(lrsyslog, cqe);

    syslog(LOG_ERR, "%s:%d:%s: unhandled cqe! user_data=%lld (%d)", __FILE__, __LINE__, __func__, cqe->user_data, *(int*)cqe->user_data);
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
        if (0 < ret) {
            syslog(LOG_ERR, "%s:%d:%s: io_uring_wait_cqe: %s", __FILE__, __LINE__, __func__, strerror(-ret));
            return -1;
        }

        ret = lrsyslog_uring_dispatch(lrsyslog, cqe);
        if (-1 == ret) {
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

#ifdef CONFIG_SYSLOG_PERROR
    openlog(CONFIG_SYSLOG_IDENT, LOG_PERROR, LOG_USER);
#else
    openlog(CONFIG_SYSLOG_IDENT, 0, LOG_USER);
#endif

    struct lrsyslog_s lrsyslog = {
        .sentinel = 8090,
        .opts = {
            .port = CONFIG_PORT
        }
    };
    ret = lrsyslog_init(&lrsyslog);
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_init returned %d", __FILE__, __LINE__, __func__, ret);
        exit(EXIT_FAILURE);
    }

    ret = lrsyslog_args_parser_parse(
        /* argc = */ argc,
        /* argv = */ argv,
        /* opts = */ &lrsyslog.opts
    );
    if (-1 == ret) {
        syslog(LOG_ERR, "%s:%d:%s: lrsyslog_args_parser_parse returned -1", __FILE__, __LINE__, __func__);
        return -1;
    }

    syslog(LOG_INFO, "%s:%d:%s: hi! port=%d", __FILE__, __LINE__, __func__, lrsyslog.opts.port);

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
