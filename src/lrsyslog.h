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
#include <stdatomic.h>

#include <liburing.h>

#include "lrsyslog_client_parser.h"
#include "lrsyslog_nats_parser.h"


#ifndef likely
# define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)	__builtin_expect(!!(x), 0)
#endif


// this needs to be a power of 2
#ifndef CONFIG_URING_DEPTH
#define CONFIG_URING_DEPTH 256
#endif

// this needs to be a power of 2
#ifndef CONFIG_URING_HANDLES
#define CONFIG_URING_HANDLES 4096
#endif

#ifndef CONFIG_NUM_THREADS
#define CONFIG_NUM_THREADS 4
#endif

#ifndef CONFIG_TCP_LISTEN_BACKLOG
#define CONFIG_TCP_LISTEN_BACKLOG 32
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
#define CONFIG_MAX_CLIENTS 20480
#endif

#ifndef TCP_READ_BUF_LEN
#define TCP_READ_BUF_LEN 512
#endif

#ifndef CONFIG_CLIENT_TIMEOUT_S
#define CONFIG_CLIENT_TIMEOUT_S 120
#endif

#ifndef CONFIG_NATS_TIMEOUT_S
#define CONFIG_NATS_TIMEOUT_S 240
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

#define LRSYSLOG_SENTINEL 8090
#define LRSYSLOG_CLIENT_SENTINEL 8091
#define LRSYSLOG_CLIENT_WATCHDOG_SENTINEL 8092

#define LRSYSLOG_URING_EVENT_CLIENT_READ 11
#define LRSYSLOG_URING_EVENT_CLIENT_WRITE_NATS 12
#define LRSYSLOG_URING_EVENT_CLIENT_CLOSE 13
#define LRSYSLOG_URING_EVENT_NATS_READ 14
#define LRSYSLOG_URING_EVENT_ACCEPT 15

struct lrsyslog_s;

struct lrsyslog_client_s {
    int fd;
    struct lrsyslog_client_parser_s parser;
    uint8_t read_buf[CONFIG_CLIENT_READ_BUF_LEN];
    uint32_t read_buf_len;
    uint8_t * read_buf_p;
    atomic_uint_fast32_t refcount;
    struct lrsyslog_s * lrsyslog;
};

struct lrsyslog_nats_s {
    int fd;
    char buf[CONFIG_NATS_READ_BUF_LEN];
    struct lrsyslog_nats_parser_s parser;
};

struct lrsyslog_listen_s {
    int fd;
};

struct lrsyslog_uring_event_s {
    uint_fast8_t type;
    atomic_uint_fast8_t refcount;
    union {
        struct lrsyslog_client_s * client;
        struct lrsyslog_nats_s * nats;
        struct lrsyslog_listen_s * listen;
    };
};

struct lrsyslog_opts_s {
    int port;
};

struct lrsyslog_s {
    struct io_uring ring;
    struct lrsyslog_listen_s listen;
    struct lrsyslog_nats_s nats;
    struct lrsyslog_opts_s opts;
    struct lrsyslog_uring_event_s events[CONFIG_URING_HANDLES];
    atomic_uint_fast32_t events_i;
};


int lrsyslog_uring_event_new (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_uring_event_s ** event
);


int lrsyslog_uring_event_rc_sub (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_uring_event_s * event
);
