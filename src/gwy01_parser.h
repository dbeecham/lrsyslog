#pragma once

#include "lsyslog.h"
#include "lsyslog_client_parser.h"

int lsyslog_gwy01_parser_parse (
    struct lsyslog_syslog_s * log,
    struct lsyslog_pipe_msg_s * gwy01_log
);
