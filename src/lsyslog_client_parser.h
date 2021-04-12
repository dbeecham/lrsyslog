#pragma once

struct lsyslog_syslog_s {
    int cs;
    int fd;
    int prival;
    int severity;
    int facility;
    int (*log_cb)(struct lsyslog_syslog_s * log, void * context, void * arg);
    char msg[1024];
    int msg_i;
    char host[128];
    int host_i;
    char tag[128];
    int tag_i;
    int pid;
    void * context;
    void * arg;
};

int lsyslog_client_parser_init (
    struct lsyslog_syslog_s * log,
    int (*log_cb)(struct lsyslog_syslog_s * log, void * context, void * arg),
    void * context,
    void * arg
);

int lsyslog_client_parser_parse (
    struct lsyslog_syslog_s * log,
    const char * const buf,
    const int buf_len
);
