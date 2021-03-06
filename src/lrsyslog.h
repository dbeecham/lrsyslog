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

#ifndef CONFIG_CLIENT_READ_BUF_LEN
#define CONFIG_CLIENT_READ_BUF_LEN 4096
#endif

#ifndef CONFIG_NATS_READ_BUF_LEN
#define CONFIG_NATS_READ_BUF_LEN 4096
#endif

#ifndef CONFIG_CLIENT_READ_TIMEOUT_S
#define CONFIG_CLIENT_READ_TIMEOUT_S 30
#endif

#define LRSYSLOG_SENTINEL 8090
#define LRSYSLOG_CLIENT_SENTINEL 8091
#define LRSYSLOG_PUB_SENTINEL 8091


struct lrsyslog_opts_s {
    int port;
};

struct lrsyslog_nats_pub_s {
    char msg[4096];
    uint32_t msg_len;
};

struct lrsyslog_client_s {
    int sentinel;
    int fd;
    int closing;
    bool writing;
    struct lrsyslog_client_parser_s parser;
    struct lrsyslog_s * lrsyslog;
    char read_buf[CONFIG_CLIENT_READ_BUF_LEN];
    uint32_t read_buf_i;
    uint32_t read_buf_len;
};

struct lrsyslog_s {
    int sentinel;
    struct io_uring ring;
    int syslogfd;
    struct {
        int fd;
        char buf[CONFIG_NATS_READ_BUF_LEN];
        struct lrsyslog_nats_parser_s parser;
    } nats;
    struct lrsyslog_opts_s opts;
    sigset_t sigset;
    int signalfd;
};

int lrsyslog_uring_event_nats_fd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
);

int lrsyslog_nats_connect (
    struct lrsyslog_s * lrsyslog
);

int lrsyslog_nats_ping_cb (
    struct lrsyslog_nats_parser_s * parser,
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
    void * user_data
);
