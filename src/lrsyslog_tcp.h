#pragma once

#include <stdint.h>

int lrsyslog_uring_event_tcp_fd (
    struct lrsyslog_s * lrsyslog,
    struct io_uring_cqe * cqe
);

int lrsyslog_tcp_syslog_cb (
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

int lrsyslog_tcp_server_start (
    struct lrsyslog_s * lrsyslog
);
