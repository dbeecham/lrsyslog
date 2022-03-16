#pragma once

#include <stdint.h>

#include "lrsyslog.h"

int lrsyslog_uring_event_listen_fd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
);

int lrsyslog_tcp_server_start (
    struct lrsyslog_s * lrsyslog
);
