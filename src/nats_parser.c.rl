#define _POSIX_C_SOURCE 201805L

#include <syslog.h>
#include <stdio.h>

#include "nats_parser.h"

%%{

    machine nats;

    access parser->;

    loop := (
        'PING\r\n' @{ parser->ping_cb(parser, parser->context, parser->arg); fgoto loop; } |
        '+OK\r\n' @{ fgoto loop; } |
        '-ERR' (any - '\n')* '\n' @{ syslog(LOG_INFO, "%s:%d:%s: got nats error, continuing anyway...", __FILE__, __LINE__, __func__); }
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse nats at %c\n", __FILE__, __LINE__, __func__, *p); fgoto loop; };

    info = (
        'INFO {' 
        (any - '\n' - '\r' - '}')+ 
        '}' 
        ' '? 
        '\r\n' @{fgoto loop;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse info at %c\n", __FILE__, __LINE__, __func__, *p); fgoto main; };

    main := info;

    write data;

}%%

int nats_parser_init (
    struct nats_parser_s * parser,
    int (*ping_cb)(struct nats_parser_s * parser, void * context, void * arg),
    void * context,
    void * arg
)
{
    %% write init;
    parser->context = context;
    parser->arg = arg;
    parser->ping_cb = ping_cb;
    return 0;
}

int nats_parser_parse (
    struct nats_parser_s * parser,
    const char * const buf,
    const int buf_len
)
{

    const char * p = buf;
    const char * pe = buf + buf_len;
    const char * eof = 0;

    %% write exec;

    return 0;
}
