#define _POSIX_C_SOURCE 201805L

#include "lrsyslog.h"
#include "lrsyslog_client_parser.h"

%%{

    machine client;

    access log->;

    gobble := (
        (any - '<')*
        '<' @{fhold; fgoto main;}
    );

    rfc5424_eol := (
        [\r\n] @{ 
            if (NULL != log->log_cb) {
                ret = log->log_cb(
                    /* host = */ log->host,
                    /* host_len = */ log->host_len,
                    /* tag = */ log->tag,
                    /* tag_len = */ log->tag_len,
                    /* facility = */ log->facility,
                    /* severity = */ log->severity,
                    /* pid = */ log->pid,
                    /* msg = */ log->msg,
                    /* msg_len = */ log->msg_len,
                    /* user_data = */ log->user_data
                ); 
                if (-1 == ret) {
                    syslog(LOG_ERR, "%s:%d:%s: log->callbacks.default_cb returned -1", __FILE__, __LINE__, __func__);
                    return -1;
                }
            }
            fgoto main; 
        }
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse eof marker at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };


    action message_init {
        log->msg_len = 0;
    }
    action message_copy {
        if (1023 <= log->msg_len) {
            fhold; fgoto rfc5424_eol;
        } else {
            log->msg[log->msg_len++] = *p;
        }
    }
    message = 
        (any - '\r' - '\n') $message_init $message_copy 
        (any - '\r' - '\n')* $message_copy;

    # rfc5424 syslog message
    rfc5424_message := (
        space*
        message
        [\r\n] @{ fhold; fgoto rfc5424_eol; }
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse message at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };


    # rfc5424 structured data field
    structured_data := (
        '- ' @{fgoto rfc5424_message;} |
        ( '[timeQuality ' (
            ' ' |
            'tzKnown="' ('1' | '0') '"' |
            'isSynced="' ('1' | '0') '"' |
            'syncAccuracy="' digit+ '"'
        )* '] ' @{fgoto rfc5424_message;} ) |
        ' ' @{fgoto rfc5424_message;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse structured data at 0x%02x\n", __FILE__, __LINE__, __func__, fc); fgoto gobble; };


    # rfc5424 message id field
    message_id := (
        '- ' @{fgoto structured_data;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse message id at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };


    # rfc5424 pid field
    process_id := (
        '- ' @{log->pid = 0; fgoto message_id;} |
        digit{1,5} >to{log->pid = 0;} ${log->pid *= 10; log->pid += (*p - '0');} ' ' @{fgoto message_id;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse process id at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };


    # rfc5424 tag field (also contains the version in gwyos)
    action rfc5424_tag_unknown {
        memcpy(log->tag, "unknown", strlen("unknown"));
        log->tag_len = strlen("unknown");
    }
    action rfc5424_tag_copy {
        log->tag[log->tag_len++] = *p;
    }
    action rfc5424_safe_tag_copy {
        log->tag[log->tag_len++] = '-';
    }
    action rfc5424_tag_init {
        log->tag_len = 0;
    }
    rfc5424_tag := (
        # rsyslog logs have an additional space between the hostname and the tag;
        # i'm not sure why.
        ' '?
        ( 
            '-' @rfc5424_tag_unknown 
            | 
            (
                [A-Za-z0-9+\-] $rfc5424_tag_copy | '.' $rfc5424_safe_tag_copy
            ){1,127} >to(rfc5424_tag_init)
        )
        ' ' @{fgoto process_id;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse tag at %c, buf=%.*s\n", __FILE__, __LINE__, __func__, *p, buf_len, buf); fgoto gobble; };


    # rfc5424 host field
    action rfc5424_host_copy {
        log->host[log->host_len++] = *p;
    }
    action rfc5424_host_init {
        log->host_len = 0;
    }
    rfc5424_host := (
        [A-Za-z0-9_\-]{1,128} >to(rfc5424_host_init) $(rfc5424_host_copy)
        ' ' @{fgoto rfc5424_tag;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse host at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };


    # rfc5424 date field
    rfc5424_date := (
        digit{4} '-' digit{2} '-' digit{2} 'T' [0-9:.+]+ ' ' @{fgoto rfc5424_host;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse date at %c\n", __FILE__, __LINE__, __func__, *p); fgoto gobble; };


    # rfc5424 version field (should always be 1)
    rfc5424_version := (
        '1 ' @{fgoto rfc5424_date;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse version at %c, buf=%.*s\n", __FILE__, __LINE__, __func__, *p, buf_len, buf); fgoto gobble; };

    
    # rfc5424 priority field
    rfc5424_priority = (
        '<' (
            # No number can follow a starting 0
            '0>' @{ log->severity = 0; log->facility = 0; log->prival = 0; fgoto rfc5424_version; } |

            # These can be '1', '9', '10', '100', '191', but not '192', '200', '900'
            '1' @{ log->prival = 1; } (

                # 1 is ok
                '>' @{log->severity = 1; log->facility = 0; fgoto rfc5424_version; } |

                # 10-18, 10X, 11X, ..., 18X
                [0-8] @{log->prival = 10 + (*p - '0');} (
                        # 10-18 are OK
                        '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto rfc5424_version; } |

                        # 100-109, 110-119, ..., 180-189 are ok
                        [0-9] ${log->prival *= 10; log->prival += (*p - '0');} (
                            '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto rfc5424_version; }
                        ) 
                      ) |

                # 19, 19X
                '9' ${ log->prival *= 10; log->prival += (*p - '0'); } (

                    # 19 is valid
                    '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto rfc5424_version; } |

                    # 190, 191 are valid numbers
                    [0-1] ${ log->prival *= 10; log->prival += (*p - '0'); } (
                        '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto rfc5424_version; }
                    )

                    # 192-199 are not valid
                )
            ) |

            # 2-9, 20-29. 200 is too large.
            [2-9] @{ log->prival = (*p - '0'); } (
                '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto rfc5424_version; } |
                [0-9] ${ log->prival *= 10; log->prival += (*p - '0'); } (
                    '>' @{d = div(log->prival, 8); log->severity = d.rem; log->facility = d.quot; fgoto rfc5424_version; }
                )
            )
        )
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse priority at %c, buf=%s\n", __FILE__, __LINE__, __func__, *p, buf); fgoto gobble; };
        

    # rfc5424 message main entry; always starts with a priority
    main := rfc5424_priority;


    write data;

}%%

int lrsyslog_client_parser_init (
    struct lrsyslog_syslog_s * log,
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
)
{
    %% write init;
    log->user_data = user_data;
    log->log_cb = log_cb;

    return 0;
}

int lrsyslog_client_parser_parse (
    struct lrsyslog_syslog_s * log,
    const char * const buf,
    const int buf_len
)
{
    int ret = 0;
    div_t d = {0};

    const char * p = buf;
    const char * pe = buf + buf_len;
    const char * eof = 0;

    %% write exec;

    return 0;

}
