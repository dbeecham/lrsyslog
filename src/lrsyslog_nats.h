#pragma once

#include "lrsyslog.h"
#include "lrsyslog_nats_parser.h"

int lrsyslog_nats_ping_cb (
    struct lrsyslog_nats_parser_s * parser,
    void * context,
    void * arg
);

int lrsyslog_uring_event_nats_read (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
);

int lrsyslog_nats_connect (
    struct lrsyslog_s * lrsyslog
);
