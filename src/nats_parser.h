#pragma once

struct nats_parser_s {
    int cs;
    int (*ping_cb)(struct nats_parser_s * parser, void * context, void * arg);
    void * context;
    void * arg;
};

int nats_parser_init (
    struct nats_parser_s * parser,
    int (*ping_cb)(struct nats_parser_s * parser, void * context, void * arg),
    void * context,
    void * arg
);

int nats_parser_parse (
    struct nats_parser_s * parser,
    const char * const buf,
    const int buf_len
);
