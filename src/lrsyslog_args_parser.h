#pragma once

#include "lrsyslog.h"

int lrsyslog_args_parser_parse (
    const int argc,
    const char * const * const argv,
    struct lrsyslog_opts_s * opts
);
