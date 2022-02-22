#define _DEFAULT_SOURCE

#include <unistd.h>
#include <stdio.h>

#include "lrsyslog.h"

%%{

    machine args_parser;

    alphtype unsigned char;

    include _0_65535 "0_65535.rl";

    # Printable characters are all "normal" ascii characters, excluding
    # whitespace. It includes A-Z, a-z, 0-9, and all common special characters
    # such as !"'%(){}`.
    printable = (33 .. 126);

    # since all arguments are null-terminated, we need to check if we've
    # consumed all arguments
    action test_end {
        if (++i >= argc) {
            fbreak;
        }
    }

    action test_end_fail {
        if (++i >= argc) {
            return -1;
        }
    }

    action port_init {
        opts->port = 0;
    }
    action port_test_end {
        if (++i >= argc) {
            syslog(LOG_ERR, "%s:%d:%s: --port requires an argument", __FILE__, __LINE__, __func__);
            return -1;
        }
    }
    action port_copy {
        opts->port *= 10;
        opts->port += (*p - '0');
    }
    port := (
        (0 @port_test_end | '=') 
        _0_65535 >to(port_init) $port_copy
        0 @{ fhold; fret; }
    ) @err{ 
        syslog(LOG_ERR, "%s:%d:%s: parse error in port: *p=0x%02x, cs=%d, arg_i=%d, argv[arg_i]=%s", __FILE__, __LINE__, __func__, *p, fcurs, i, argv[i]); 
    };


    args = '--port' @{ fcall port; }
            0 @test_end;

    main := (
        args*
    ) @err{ 
        syslog(LOG_ERR, "%s:%d:%s: parse error in main: *p=0x%02x, cs=%d, arg_i=%d, argv[arg_i]=%s", __FILE__, __LINE__, __func__, *p, fcurs, i, argv[i]); 
    };

    write data;

}%%

int lrsyslog_args_parser_parse (
    const int argc,
    const char * const * const argv,
    struct lrsyslog_opts_s * opts
)
{
    if (argc == 0) {
        return -1;
    }
    if (argc == 1) {
        return 0;
    }

    int cs;
    int top;
    int stack[8];
    
    %% write init;

    int i = 1;
    const uint8_t * p = (uint8_t*)argv[i];
    const uint8_t * eof = 0;

    %% write exec noend;

    if (cs < %%{ write first_final; }%%) {
        syslog(LOG_DEBUG, "%s:%d:%s: hi!", __FILE__, __LINE__, __func__);
        return -1;
    } else {
        return 0;
    }

}
