#pragma once

#include "lrsyslog.h"


int lrsyslog_client_new (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s ** client,
    int fd,
    struct lrsyslog_client_parser_callbacks_s cbs
);


int lrsyslog_client_read (
    struct lrsyslog_s * lrsyslog,
    struct lrsyslog_client_s * client
);


int lrsyslog_client_syslog_cb (
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
);


int lrsyslog_uring_event_client_read (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
);


int lrsyslog_uring_event_client_write_nats (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
);


int lrsyslog_uring_event_client_close (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe,
    struct lrsyslog_uring_event_s * event
);
