#define _POSIX_C_SOURCE 201805L

#include "lsyslog.h"
#include "lsyslog_client_parser.h"

%%{

    machine client;

    access log->;

    action dosomething {
        syslog(LOG_INFO, "hi there");
    }

    gobble := (
        (any - '<')*
        '<' @{fhold; fgoto main;}
    );

    eol := (
        [\r\n] @{ log->log_cb(log, log->context, log->arg); fgoto main; }
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse eof marker at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };

    action message_init {
        log->msg_i = 0;
    }

    action message_copy {
        if (1023 <= log->msg_i) {
            fhold; fgoto eol;
        } else {
            log->msg[log->msg_i++] = *p;
        }
    }

    message := (
        space*
        (any - '\r' - '\n') >to(message_init) $(message_copy)
        (any - '\r' - '\n')* $(message_copy)
        [\r\n] @{ fhold; fgoto eol; }
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse message at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };

    structured_data := (
        '- ' @{fgoto message;} |
        ( '[timeQuality ' (
            ' ' |
            'tzKnown="' ('1' | '0') '"' |
            'isSynced="' ('1' | '0') '"' |
            'syncAccuracy="' digit+ '"'
        )* '] ' @{fgoto message;} ) |
        ' ' @{fgoto message;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse structured data at 0x%02x\n", __FILE__, __LINE__, __func__, fc, fc); fgoto gobble; };

    message_id := (
        '- ' @{fgoto structured_data;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse message id at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };

    process_id := (
        '- ' @{log->pid = -1; fgoto message_id;} |
        digit{1,5} >to{log->pid = 0;} ${log->pid *= 10; log->pid += (*p - '0');} ' ' @{fgoto message_id;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse process id at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };

    action tag_init {
        log->tag_i = 0;
    }

    action tag_copy {
        log->tag[log->tag_i++] = *p;
    }

    action tag_unknown {
        memcpy(log->tag, "unknown", strlen("unknown"));
        log->tag_i = strlen("unknown");
    }

    # rsyslog logs have an additional space between the hostname and the tag;
    # i'm not sure why.
    tag := (
        ' '?
        ('-' @tag_unknown | ([A-Za-z0-9.+] >to(tag_init) $(tag_copy) [A-Za-z0-9.+\-]{0,127} $(tag_copy)))
        ' ' @{fgoto process_id;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse tag at %c, buf=%.*s\n", __FILE__, __LINE__, __func__, *p, buf_len, buf); fgoto gobble; };

    action host_init {
        log->host_i = 0;
    }

    action host_copy {
        log->host[log->host_i++] = *p;
    }

    host := (
        [A-Za-z0-9_\-]{1,128} >to(host_init) $(host_copy)
        ' ' @{fgoto tag;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse host at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };

    date := (
        digit{4} '-' digit{2} '-' digit{2} 'T' [0-9:.+]+ ' ' @{fgoto host;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse date at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };

    version := (
        '1 ' @{fgoto date;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse version at %c, buf=%.*s\n", __FILE__, __LINE__, __func__, *p, buf_len, buf); fgoto gobble; };

    priority = (
        '<' (
            # No number can follow a starting 0
            '0>' @{ log->severity = 0; log->facility = 0; log->prival = 0; fgoto version; } |

            # These can be '1', '9', '10', '100', '191', but not '192', '200', '900'
            '1' @{ log->prival = 1; } (

                # 1 is ok
                '>' @{log->severity = 1; log->facility = 0; fgoto version; } |

                # 10-18, 10X, 11X, ..., 18X
                [0-8] @{log->prival = 10 + (*p - '0');} (
                        # 10-18 are OK
                        '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto version; } |

                        # 100-109, 110-119, ..., 180-189 are ok
                        [0-9] ${log->prival *= 10; log->prival += (*p - '0');} (
                            '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto version; }
                        ) 
                      ) |

                # 19, 19X
                '9' ${ log->prival *= 10; log->prival += (*p - '0'); } (

                    # 19 is valid
                    '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto version; } |

                    # 190, 191 are valid numbers
                    [0-1] ${ log->prival *= 10; log->prival += (*p - '0'); } (
                        '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto version; }
                    )

                    # 192-199 are not valid
                )
            ) |

            # 2-9, 20-29. 200 is too large.
            [2-9] @{ log->prival = (*p - '0'); } (
                '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto version; } |
                [0-9] ${ log->prival *= 10; log->prival += (*p - '0'); } (
                    '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto version; }
                )
            )
        )
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse priority at %c, buf=%s\n", __FILE__, __LINE__, __func__, *p, buf); fgoto gobble; };
        
    main := priority;

    write data;

}%%

int lsyslog_client_parser_init (
    struct lsyslog_syslog_s * log,
    int (*log_cb)(struct lsyslog_syslog_s * log, void * context, void * arg),
    void * context,
    void * arg
)
{
    %% write init;
    log->arg = arg;
    log->log_cb = log_cb;
    log->context = context;
    return 0;
}

int lsyslog_client_parser_parse (
    struct lsyslog_syslog_s * log,
    const char * const buf,
    const int buf_len
)
{

    div_t d = {0};

    const char * p = buf;
    const char * pe = buf + buf_len;
    const char * eof = 0;

    %% write exec;

    return 0;

}
