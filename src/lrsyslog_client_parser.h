#pragma once

#include <stdint.h>

struct lrsyslog_client_parser_s {
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
        const char * msg_len_str,
        const uint32_t msg_len_str_len,
        void * user_data
    );
    void * user_data;

    char msg[2048];
    uint32_t msg_len;

    char msg_len_str[8];
    uint32_t msg_len_str_len;

    char host[128];
    uint32_t host_len;

    char tag[128];
    uint32_t tag_len;

    int pid;
};

int lrsyslog_client_parser_init (
    struct lrsyslog_client_parser_s * parser,
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
        const char * msg_len_str,
        const uint32_t msg_len_str_len,
        void * user_data
    ),
    void * user_data
);

int lrsyslog_client_parser_parse (
    struct lrsyslog_client_parser_s * parser,
    const char * const buf,
    const int buf_len
);
