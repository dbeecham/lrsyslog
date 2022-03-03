#pragma once

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
#include <pthread.h>
#include <liburing.h>

#include "lrsyslog_client_parser.h"
#include "lrsyslog_nats_parser.h"


#ifndef likely
# define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)	__builtin_expect(!!(x), 0)
#endif


#ifndef CONFIG_URING_DEPTH
#define CONFIG_URING_DEPTH 256
#endif

#define EPOLL_NUM_EVENTS 8
#define NATS_BUF_LEN 2048

#ifndef CONFIG_NUM_THREADS
#define CONFIG_NUM_THREADS 4
#endif

#ifndef TCP_LISTEN_BACKLOG
#define TCP_LISTEN_BACKLOG 8
#endif

#ifndef CONFIG_NATS_HOST
#define CONFIG_NATS_HOST "127.0.0.1"
#endif

#ifndef CONFIG_NATS_PORT
#define CONFIG_NATS_PORT "4222"
#endif

#ifndef CONFIG_HOST
#define CONFIG_HOST "0.0.0.0"
#endif 

#ifndef CONFIG_PORT
#define CONFIG_PORT 514
#endif

#ifndef CONFIG_MAX_CLIENTS
#define CONFIG_MAX_CLIENTS 64
#endif

#ifndef TCP_READ_BUF_LEN
#define TCP_READ_BUF_LEN 512
#endif

#ifndef CLIENT_PING_TIMEOUT_S
#define CLIENT_PING_TIMEOUT_S 60
#endif

#ifndef CONFIG_SYSLOG_IDENT
#define CONFIG_SYSLOG_IDENT "lrsyslog-custom"
#endif

#define LRSYSLOG_SENTINEL 8090
#define LRSYSLOG_CLIENT_SENTINEL 8091
#define LRSYSLOG_CLIENT_WATCHDOG_SENTINEL 8092

struct lrsyslog_opts_s {
    int port;
};

struct lrsyslog_client_s {
    int sentinel;
    int fd;
    int closing;
    int writing_to_nats;
    struct lrsyslog_client_parser_s parser;
    struct lrsyslog_s * lrsyslog;
    char read_buf[4096];
    uint32_t read_buf_len;
    char * read_buf_p;
};

struct lrsyslog_s {
    int sentinel;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    struct io_uring ring;
    int tcp_fd;
    int tcp_task_epoll_fd;
    struct {
        int fd;
        char buf[4096];
        struct lrsyslog_nats_parser_s parser;
    } nats;
    struct lrsyslog_opts_s opts;
};
