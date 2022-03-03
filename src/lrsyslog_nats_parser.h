#pragma once

struct lrsyslog_nats_parser_s {
    int cs;
    int (*ping_cb)(struct lrsyslog_nats_parser_s * parser, void * context, void * arg);
    void * context;
    void * arg;
};

int lrsyslog_nats_parser_init (
    struct lrsyslog_nats_parser_s * parser,
    int (*ping_cb)(struct lrsyslog_nats_parser_s * parser, void * context, void * arg),
    void * context,
    void * arg
);

int lrsyslog_nats_parser_parse (
    struct lrsyslog_nats_parser_s * parser,
    const char * const buf,
    const int buf_len
);
