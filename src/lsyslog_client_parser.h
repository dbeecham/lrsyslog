#pragma once

#include <stdint.h>

struct lsyslog_syslog_s {
    int cs;
    int fd;
    int prival;
    int severity;
    int facility;

    int (*log_cb)(
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
    void * user_data;

    char msg[1024];
    uint32_t msg_len;

    char host[128];
    uint32_t host_len;

    char tag[128];
    uint32_t tag_len;

    int pid;
};

int lsyslog_client_parser_init (
    struct lsyslog_syslog_s * log,
    int (*log_cb)(
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
    ),
    void * user_data
);

int lsyslog_client_parser_parse (
    struct lsyslog_syslog_s * log,
    const char * const buf,
    const int buf_len
);
