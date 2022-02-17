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

#include "lrsyslog_client_parser.h"
#include "nats_parser.h"

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
#define CONFIG_PORT "514"
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

struct lrsyslog_pipe_msg_s {
    int severity;
    int facility;
    int topic_len;
    int msg_len;
    char topic[128];
    char msg[1024];
};

struct lrsyslog_client_s {
    int sentinel;
    int fd;
    struct lrsyslog_client_watchdog_s watchdog; 
    struct lrsyslog_syslog_s log;
    struct lrsyslog_s * lrsyslog;
};

struct lrsyslog_s {
    int sentinel;
    int epoll_fd;
    int tcp_fd;
    int tcp_task_epoll_fd;
    int nats_fd;
    int nats_task_epoll_fd;
    struct nats_parser_s nats_parser;
    pthread_t tcp_task_threads[CONFIG_NUM_THREADS];
    pthread_t nats_thread;
    int signal_fd;
    int pipe_fd[2];
    struct lrsyslog_client_s clients[CONFIG_MAX_CLIENTS];
};
