#define _POSIX_C_SOURCE 201805L

#include <string.h>

#include "lsyslog.h"
#include "lsyslog_client_parser.h"

static int lsyslog_gwy01_parser_parse_spibtm (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine spibtm;
        main := 'a';
        write data;
    }%%

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int cs = 0;

    %% write init;
    %% write exec;

    return 0;
}

static int lsyslog_gwy01_parser_parse_gwyinit (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine gwyinit;
        main := (
            'a'
        ) $err{ printf("%s:%d:%s: unrecognized log entry: %.*s\n", __FILE__, __LINE__, __func__, log->msg_i, log->msg); return -1; };
        write data;
    }%%

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int cs = 0;

    %% write init;
    %% write exec;

    return 0;
}

static int lsyslog_gwy01_parser_parse_natsd_2_0_0 (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine natsd_2_0_0;
        action file_init {
            file_i = 0;
        }
        action file_copy {
            file[file_i++] = *p;
        }
        file = ('src/' [a-z_]{1,64} '.c') >to(file_init) $(file_copy);
        action line_init {
            line_i = 0;
        }
        action line_copy {
            line[line_i++] = *p;
        }
        line = digit{1,4} >to(line_init) $(line_copy);
        func = [a-z_]{1,64};
        msg = any*;
        main := (
            space* 
            ( ('src/' file ':' line ':' func ': ' msg)
            | (func ':' line ': ' msg)
            )
        ) $err{ printf("%s:%d:%s: unrecognized log entry: %.*s\n", __FILE__, __LINE__, __func__, log->msg_i, log->msg); return -1; };
        write data;
    }%%

    return -1;

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int bytes_written = 0;
    int cs = 0;
    char file[128];
    int file_i;
    char line[5];
    int line_i;
    char func[64];
    int func_i;

    bytes_written = snprintf(gwy01_log->topic, 128, "natsd");
    gwy01_log->topic_len = bytes_written;

    %% write init;
    %% write exec;

    return -1;
}

static int lsyslog_gwy01_parser_parse_gwysys (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine gwysys;
        action pub_long {
            bytes_written = snprintf(gwy01_log->msg, 1024, "{\"trace\":{\"file\":\"%.*s\",\"line\":\"%.*s\",\"func\":\"%.*s\"},\"msg\":\"%.*s\"}", file_i, file, line_i, line, func_i, func, msg_i, msg);
            gwy01_log->msg_len = bytes_written;
            return 0;
        }
        action pub_short {
            bytes_written = snprintf(gwy01_log->msg, 1024, "{\"trace\":{\"func\":\"%.*s\",\"line\":\"%.*s\"},\"msg\":\"%.*s\"}", func_i, func, line_i, line, msg_i, msg);
            gwy01_log->msg_len = bytes_written;
            return 0;
        }
        action file_init {
            file_i = 0;
        }
        action file_copy {
            file[file_i++] = *p;
        }
        file = ('src/' [a-z_]{1,64} '.c') >to(file_init) $(file_copy);
        action line_init {
            line_i = 0;
        }
        action line_copy {
            line[line_i++] = *p;
        }
        line = digit{1,4} >to(line_init) $(line_copy);
        action func_init {
            func_i = 0;

        }
        action func_copy {
            func[func_i++] = *p;
        }
        func = [a-z_]{1,64} >to(func_init) $(func_copy);
        action msg_init {
            msg_i = 0;
            printf("%i\n", msg_i);
        }
        action msg_copy {
            printf("hi\n");
            if(msg_i > 1024) {
                return -1;
            }
            msg[msg_i++] = *p;
        }
        msg = any* >to(msg_init) $(msg_copy);
        main := (
            space* 
            ( (file ':' line ':' func ': ' msg) @(pub_long)
            | (func ':' line ': ' msg) @(pub_short)
            )
        ) $err{ printf("%s:%d:%s: unrecognized log entry: %.*s\n", __FILE__, __LINE__, __func__, log->msg_i, log->msg); return -1; };
        write data;
    }%%

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int cs = 0;
    int bytes_written = 0;

    char file[128];
    int file_i = 0;
    char line[5];
    int line_i = 0;
    char func[64];
    int func_i = 0;
    char msg[1024];
    int msg_i = 0;

    bytes_written = snprintf(gwy01_log->topic, 128, "log.gwy01.%.*s.gwysys.info.out", log->host_i, log->host);
    gwy01_log->topic_len = bytes_written;

    %% write init;
    %% write exec;

    return -1;
}

static int lsyslog_gwy01_parser_parse_gwyws (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine gwyws;
        file = [a-z_]+ '.c' '.rl'?;
        line = digit{1,4};
        func = [a-z_]+;
        msg = any*;
        main := (
            space*
            ( ('src/' file ':' line ':' func ': ' msg)
            | (func ':' line ': ' msg)
            )
        ) $err{ printf("%s:%d:%s: unrecognized log entry: %.*s\n", __FILE__, __LINE__, __func__, log->msg_i, log->msg); return -1; };
        write data;
    }%%

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int cs = 0;
    int bytes_written = 0;

    %% write init;
    %% write exec;

    bytes_written = snprintf(gwy01_log->topic, 128, "log.gwy01.%.*s.gwyws.info.out", log->host_i, log->host);
    gwy01_log->topic_len = bytes_written;

    bytes_written = snprintf(gwy01_log->msg, 1024, "hello");
    gwy01_log->msg_len = bytes_written;

    return 0;
}

static int lsyslog_gwy01_parser_parse_gwywd (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine gwywd;
        file = [a-z_]+ '.c' '.rl'?;
        line = digit{1,4};
        func = [a-z_]+;
        msg = (any - digit) any*;
        main := (
            space*
            ( ('src/' file ':' line ':' func ': ' msg)
            | (func ':' line ': ' msg)
            | (func ':' msg)
            )
        ) $err{ printf("%s:%d:%s: unrecognized log entry: %.*s\n", __FILE__, __LINE__, __func__, log->msg_i, log->msg); return -1; };
        write data;
    }%%

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int cs = 0;
    int bytes_written = 0;

    %% write init;
    %% write exec;

    bytes_written = snprintf(gwy01_log->topic, 128, "gwywd");
    gwy01_log->topic_len = bytes_written;

    bytes_written = snprintf(gwy01_log->msg, 1024, "hello");
    gwy01_log->msg_len = bytes_written;

    return 0;
}

static int lsyslog_gwy01_parser_parse_swupdate (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine swupdate;
        msg = any*;
        main := msg;
        write data;
    }%%

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int cs = 0;
    int bytes_written = 0;

    %% write init;
    %% write exec;

    bytes_written = snprintf(gwy01_log->topic, 128, "log.gwy01.%.*s.swupdate.info", log->host_i, log->host);
    gwy01_log->topic_len = bytes_written;

    bytes_written = snprintf(gwy01_log->msg, 1024, "%.*s", log->msg_i, log->msg);
    gwy01_log->msg_len = bytes_written;

    return 0;
}

static int lsyslog_gwy01_parser_parse_gwybtn (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine gwybtn;
        file = [a-z_]+ '.c' '.rl'?;
        line = digit{1,4};
        func = [a-z_]+;
        msg = (any - digit) any*;
        main := (
            space*
            ( ('src/' file ':' line ':' func ': ' msg)
            | (func ':' line ': ' msg)
            | (func ':' msg)
            )
        ) $err{ printf("%s:%d:%s: unrecognized log entry: %.*s\n", __FILE__, __LINE__, __func__, log->msg_i, log->msg); return -1; };
        write data;
    }%%

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int cs = 0;
    int bytes_written = 0;

    %% write init;
    %% write exec;

    bytes_written = snprintf(gwy01_log->topic, 128, "gwybtn");
    gwy01_log->topic_len = bytes_written;

    bytes_written = snprintf(gwy01_log->msg, 1024, "hello");
    gwy01_log->msg_len = bytes_written;

    return 0;
}

static int lsyslog_gwy01_parser_parse_gwyleds (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    %%{
        machine gwyleds;
        file = [a-z_]+ '.c' '.rl'?;
        line = digit{1,4};
        func = [a-z_]+;
        msg = (any - digit) any*;
        main := (
            space*
            ( ('src/' file ':' line ':' func ': ' msg)
            | (func ':' line ': ' msg)
            | (func ':' msg)
            )
        ) $err{ printf("%s:%d:%s: unrecognized log entry: %.*s\n", __FILE__, __LINE__, __func__, log->msg_i, log->msg); return -1; };
        write data;
    }%%

    const char *p = log->msg;
    const char *pe = log->msg + log->msg_i;
    const char *eof = 0;
    int cs = 0;
    int bytes_written = 0;

    %% write init;
    %% write exec;

    bytes_written = snprintf(gwy01_log->topic, 128, "gwyleds");
    gwy01_log->topic_len = bytes_written;

    bytes_written = snprintf(gwy01_log->msg, 1024, "hello");
    gwy01_log->msg_len = bytes_written;

    return 0;
}

int lsyslog_gwy01_parser_parse (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
)
{
    int ret = 0;

    if (strcmp(log->tag, "spibtm") == 0)
        return lsyslog_gwy01_parser_parse_spibtm(log, gwy01_log);

    if (strcmp(log->tag, "gwyinit") == 0)
        return lsyslog_gwy01_parser_parse_gwyinit(log, gwy01_log);

    if (strncmp(log->tag, "natsd-2.0.0", strlen("natsd-2.0.0")) == 0)
        return lsyslog_gwy01_parser_parse_natsd_2_0_0(log, gwy01_log);

    if (strncmp(log->tag, "gwyws", strlen("gwyws")) == 0)
        return lsyslog_gwy01_parser_parse_gwyws(log, gwy01_log);

    if (strncmp(log->tag, "gwywd", strlen("gwywd")) == 0)
        return lsyslog_gwy01_parser_parse_gwywd(log, gwy01_log);

    if (strncmp(log->tag, "gwysys", strlen("gwysys")) == 0)
        return lsyslog_gwy01_parser_parse_gwysys(log, gwy01_log);

    if (strncmp(log->tag, "gwyleds", strlen("gwyleds")) == 0)
        return lsyslog_gwy01_parser_parse_gwyleds(log, gwy01_log);

    if (strncmp(log->tag, "gwybtn", strlen("gwybtn")) == 0)
        return lsyslog_gwy01_parser_parse_gwybtn(log, gwy01_log);

    if (strncmp(log->tag, "swupdate", strlen("swupdate")) == 0)
        return lsyslog_gwy01_parser_parse_swupdate(log, gwy01_log);

    fprintf(stderr, "no match on gwy01 tag %.*s\n", log->tag_i, log->tag);
    return -1;

}
