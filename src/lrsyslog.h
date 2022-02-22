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
#include "nats_parser.h"

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

struct lrsyslog_client_watchdog_s {
    int sentinel;
    int timer_fd;
};

struct lrsyslog_opts_s {
    int port;
};

struct lrsyslog_client_s {
    int sentinel;
    int fd;
    int closing;
    struct lrsyslog_client_watchdog_s watchdog; 
    struct lrsyslog_syslog_s log;
    struct lrsyslog_s * lrsyslog;
    char read_buf[4096];
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
        struct nats_parser_s parser;
    } nats;
    struct lrsyslog_opts_s opts;
};

int lrsyslog_uring_event_nats_fd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
);

int lrsyslog_nats_connect (
    struct lrsyslog_s * lrsyslog
);

int lrsyslog_nats_ping_cb (
    struct nats_parser_s * parser,
    void * context,
    void * arg
);

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
);
