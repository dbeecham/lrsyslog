#define _POSIX_C_SOURCE 201805L

#include "lrsyslog.h"
#include "lrsyslog_client_parser.h"

%%{

    machine client;

    access parser->;

    gobble := (
        (any - '<')*
        '<' @{fhold; fgoto main;}
    );

    rfc5424_eol := (
        [\r\n] @{ 
            if (NULL != parser->log_cb) {
                // convert msg_len to str for callback consumption
                parser->msg_len_str_len = snprintf(
                    parser->msg_len_str,
                    sizeof(parser->msg_len_str),
                    "%d",
                    parser->msg_len
                );
                ret = parser->log_cb(
                    /* host = */ parser->host,
                    /* host_len = */ parser->host_len,
                    /* tag = */ parser->tag,
                    /* tag_len = */ parser->tag_len,
                    /* facility = */ parser->facility,
                    /* severity = */ parser->severity,
                    /* pid = */ parser->pid,
                    /* msg = */ parser->msg,
                    /* msg_len = */ parser->msg_len,
                    /* msg_str = */ parser->msg_len_str,
                    /* msg_str_len = */ parser->msg_len_str_len,
                    /* user_data = */ parser->user_data
                ); 
                if (-1 == ret) {
                    syslog(LOG_ERR, "%s:%d:%s: parser->callbacks.default_cb returned -1", __FILE__, __LINE__, __func__);
                    return -1;
                }
            }
            fnext main; 
            fbreak;
        }
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse eof marker at %c\n", __FILE__, __LINE__, __func__, *p); return -1;};


    action message_init {
        parser->msg_len = 0;
    }
    action message_copy {
        if (2047 <= parser->msg_len) {
            fhold; fgoto rfc5424_eol;
        } else {
            parser->msg[parser->msg_len++] = *p;
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
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse message at %c\n", __FILE__, __LINE__, __func__, *p); return -1; };


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
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse structured data at 0x%02x (index=%ld)\n", __FILE__, __LINE__, __func__, fc, p - buf); return -1; };


    # rfc5424 message id field
    message_id := (
        '- ' @{fgoto structured_data;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse message id at %c\n", __FILE__, __LINE__, __func__, *p); return -1; };


    # rfc5424 pid field
    process_id := (
        '- ' @{parser->pid = 0; fgoto message_id;} |
        digit{1,5} >to{parser->pid = 0;} ${parser->pid *= 10; parser->pid += (*p - '0');} ' ' @{fgoto message_id;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse process id at %c\n", __FILE__, __LINE__, __func__, *p); return -1; };


    # rfc5424 tag field (also contains the version in gwyos)
    action rfc5424_tag_unknown {
        memcpy(parser->tag, "unknown", strlen("unknown"));
        parser->tag_len = strlen("unknown");
    }
    action rfc5424_tag_copy {
        parser->tag[parser->tag_len++] = *p;
    }
    action rfc5424_safe_tag_copy {
        parser->tag[parser->tag_len++] = '-';
    }
    action rfc5424_tag_init {
        parser->tag_len = 0;
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
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse tag at %c, buf=%.*s\n", __FILE__, __LINE__, __func__, *p, buf_len, buf); return -1; };


    # rfc5424 host field
    action rfc5424_host_copy {
        parser->host[parser->host_len++] = *p;
    }
    action rfc5424_host_init {
        parser->host_len = 0;
    }
    rfc5424_host := (
        [A-Za-z0-9_\-]{1,128} >to(rfc5424_host_init) $(rfc5424_host_copy)
        ' ' @{fgoto rfc5424_tag;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse host at %c\n", __FILE__, __LINE__, __func__, *p); return -1; };


    # rfc5424 date field
    rfc5424_date := (
        digit{4} '-' digit{2} '-' digit{2} 'T' [0-9:.+]+ ' ' @{fgoto rfc5424_host;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse date at %c\n", __FILE__, __LINE__, __func__, *p); return -1; };


    # rfc5424 version field (should always be 1)
    rfc5424_version := (
        '1 ' @{fgoto rfc5424_date;}
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse version at %c, buf=%.*s\n", __FILE__, __LINE__, __func__, *p, buf_len, buf); return -1; };

    
    # rfc5424 priority field
    rfc5424_priority = (
        '<' (
            # No number can follow a starting 0
            '0>' @{ parser->severity = 0; parser->facility = 0; parser->prival = 0; fgoto rfc5424_version; } |

            # These can be '1', '9', '10', '100', '191', but not '192', '200', '900'
            '1' @{ parser->prival = 1; } (

                # 1 is ok
                '>' @{parser->severity = 1; parser->facility = 0; fgoto rfc5424_version; } |

                # 10-18, 10X, 11X, ..., 18X
                [0-8] @{parser->prival = 10 + (*p - '0');} (
                        # 10-18 are OK
                        '>' @{d = div(parser->prival, 8); parser->severity = d.rem; parser->facility = d.quot; fgoto rfc5424_version; } |

                        # 100-109, 110-119, ..., 180-189 are ok
                        [0-9] ${parser->prival *= 10; parser->prival += (*p - '0');} (
                            '>' @{d = div(parser->prival, 8); parser->severity = d.rem; parser->facility = d.quot; fgoto rfc5424_version; }
                        ) 
                      ) |

                # 19, 19X
                '9' ${ parser->prival *= 10; parser->prival += (*p - '0'); } (

                    # 19 is valid
                    '>' @{d = div(parser->prival, 8); parser->severity = d.rem; parser->facility = d.quot; fgoto rfc5424_version; } |

                    # 190, 191 are valid numbers
                    [0-1] ${ parser->prival *= 10; parser->prival += (*p - '0'); } (
                        '>' @{d = div(parser->prival, 8); parser->severity = d.rem; parser->facility = d.quot; fgoto rfc5424_version; }
                    )

                    # 192-199 are not valid
                )
            ) |

            # 2-9, 20-29. 200 is too large.
            [2-9] @{ parser->prival = (*p - '0'); } (
                '>' @{d = div(parser->prival, 8); parser->severity = d.rem; parser->facility = d.quot; fgoto rfc5424_version; } |
                [0-9] ${ parser->prival *= 10; parser->prival += (*p - '0'); } (
                    '>' @{d = div(parser->prival, 8); parser->severity = d.rem; parser->facility = d.quot; fgoto rfc5424_version; }
                )
            )
        )
    ) $err{ syslog(LOG_WARNING, "%s:%d:%s: failed to parse priority at %c, buf=%s\n", __FILE__, __LINE__, __func__, *p, buf); return -1; };
        

    # rfc5424 message main entry; always starts with a priority
    main := rfc5424_priority;


    write data;

}%%

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
)
{
    %% write init;
    parser->user_data = user_data;
    parser->log_cb = log_cb;

    return 0;
}

int lrsyslog_client_parser_parse (
    struct lrsyslog_client_parser_s * parser,
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

    return p - buf;
}
