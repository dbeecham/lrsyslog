#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <assert.h>

#include "lsyslog_client_parser.h"

static int log_cb_called = 0;
static int log_cb_pid = 0;
static int log_cb_severity = 0;
static int log_cb_facility = 0;
static int log_cb_host_len = 0;

int log_cb (
    struct lsyslog_syslog_s * log,
    void * context,
    void * arg
)
{
    log_cb_called += 1;
    log_cb_pid = log->pid;
    log_cb_facility = log->facility;
    log_cb_severity = log->severity;
    log_cb_host_len = log->host_i;
    return 0;
    (void)context;
    (void)arg;
}


void test_lsyslog_client_parser_init() {
    int ret = 0;
    struct lsyslog_syslog_s lsyslog_syslog = {0};
    ret = lsyslog_client_parser_init(
        /* parser = */ &lsyslog_syslog,
        /* log_cb = */ log_cb,
        /* context = */ NULL,
        /* arg = */ NULL
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }
}


void test_lsyslog_client_parser_parses_basic_log() {
    int ret = 0;
    struct lsyslog_syslog_s lsyslog_syslog = {0};
    log_cb_called = 0;
    log_cb_pid = 0;

    ret = lsyslog_client_parser_init(
        /* parser = */ &lsyslog_syslog,
        /* log_cb = */ log_cb,
        /* context = */ NULL,
        /* arg = */ NULL
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    char buf[] = "<13>1 2020-10-26T12:12:48.414390+01:00 pp-ws-dbe hello - - [timeQuality tzKnown=\"1\" isSynced=\"0\"] hi\n";
    int buf_len = strlen(buf);

    ret = lsyslog_client_parser_parse(
        /* parser = */ &lsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_parse returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    if (1 != log_cb_called) {
        printf("%s:%d:%s: log_cb_called is %d, but expected it to be 1\n", __FILE__, __LINE__, __func__, log_cb_called);
        exit(EXIT_FAILURE);
    }
    if (-1 != log_cb_pid) {
        printf("%s:%d:%s: log_cb_pid is %d, but expected it to be -1\n", __FILE__, __LINE__, __func__, log_cb_pid);
        exit(EXIT_FAILURE);
    }

    char host[] = "pp-ws-dbe";
    if (strlen(host) != log_cb_host_len) {
        printf("%s:%d:%s: host_len is %d, expected %d\n", __FILE__, __LINE__, __func__, log_cb_host_len, strlen(host));
        exit(EXIT_FAILURE);
    }
}


void test_lsyslog_client_parser_parses_log_with_no_tag() {
    int ret = 0;
    struct lsyslog_syslog_s lsyslog_syslog = {0};
    log_cb_called = 0;
    log_cb_pid = 0;

    ret = lsyslog_client_parser_init(
        /* parser = */ &lsyslog_syslog,
        /* log_cb = */ log_cb,
        /* context = */ NULL,
        /* arg = */ NULL
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    char buf[] = "<44>1 2021-04-28T10:28:20.080548+00:00 091831543131364b  - - -  action 'action-2-builtin:omfwd' suspended (module 'builtin:omfwd'), retry 0. There should be messages before this one giving the reason for suspension. [v8.38.0 try http://www.rsyslog.com/e/2007 ]\n";
    int buf_len = strlen(buf);

    ret = lsyslog_client_parser_parse(
        /* parser = */ &lsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_parse returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    if (1 != log_cb_called) {
        printf("%s:%d:%s: log_cb_called is %d, but expected it to be 1\n", __FILE__, __LINE__, __func__, log_cb_called);
        exit(EXIT_FAILURE);
    }
    if (-1 != log_cb_pid) {
        printf("%s:%d:%s: log_cb_pid is %d, but expected it to be -1\n", __FILE__, __LINE__, __func__, log_cb_pid);
        exit(EXIT_FAILURE);
    }

    char host[] = "091831543131364b";
    if (strlen(host) != log_cb_host_len) {
        printf("%s:%d:%s: host_len is %d, expected %d\n", __FILE__, __LINE__, __func__, log_cb_host_len, strlen(host));
        exit(EXIT_FAILURE);
    }
}


void test_lsyslog_client_parser_parses_log_with_accuracy() {
    int ret = 0;
    struct lsyslog_syslog_s lsyslog_syslog = {0};
    log_cb_called = 0;
    log_cb_pid = 0;

    ret = lsyslog_client_parser_init(
        /* parser = */ &lsyslog_syslog,
        /* log_cb = */ log_cb,
        /* context = */ NULL,
        /* arg = */ NULL
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    char buf[] = "<13>1 2021-04-12T15:42:28.075395+02:00 pp-ws-dbe hellsadf - - [timeQuality tzKnown=\"1\" isSynced=\"1\" syncAccuracy=\"298500\"] hi\n";
    int buf_len = strlen(buf);

    ret = lsyslog_client_parser_parse(
        /* parser = */ &lsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_parse returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    if (1 != log_cb_called) {
        printf("%s:%d:%s: log_cb_called is %d, but expected it to be 1\n", __FILE__, __LINE__, __func__, log_cb_called);
        exit(EXIT_FAILURE);
    }
    if (-1 != log_cb_pid) {
        printf("%s:%d:%s: log_cb_pid is %d, but expected it to be -1\n", __FILE__, __LINE__, __func__, log_cb_pid);
        exit(EXIT_FAILURE);
    }
}


void test_lsyslog_client_parser_parses_log_from_gwy01_0() {
    int ret = 0;
    struct lsyslog_syslog_s lsyslog_syslog = {0};
    log_cb_called = 0;
    log_cb_pid = 0;

    ret = lsyslog_client_parser_init(
        /* parser = */ &lsyslog_syslog,
        /* log_cb = */ log_cb,
        /* context = */ NULL,
        /* arg = */ NULL
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    char buf[] = "<159>1 2021-02-01T09:26:23.685588+00:00 091831543131364b gwywd-dev-2.0.0 136 - -  src/subscriptions.c:353:nats_add_subscription_to_server: hi!\n";
    int buf_len = strlen(buf);

    ret = lsyslog_client_parser_parse(
        /* parser = */ &lsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);

    assert(1 == log_cb_called);
    assert(136 == log_cb_pid);

    if (19 != log_cb_facility) {
        printf("%s:%d:%s: log_cb_facility is %d, should be 19\n", __FILE__, __LINE__, __func__, log_cb_facility);
        exit(EXIT_FAILURE);
    }
    if (7 != log_cb_severity) {
        printf("%s:%d:%s: log_cb_severity is %d, should be 7\n", __FILE__, __LINE__, __func__, log_cb_severity);
        exit(EXIT_FAILURE);
    }
}


void test_lsyslog_client_parser_parses_log_from_gwy01_1() {
    int ret = 0;
    struct lsyslog_syslog_s lsyslog_syslog = {0};
    log_cb_called = 0;
    log_cb_pid = 0;

    ret = lsyslog_client_parser_init(
        /* parser = */ &lsyslog_syslog,
        /* log_cb = */ log_cb,
        /* context = */ NULL,
        /* arg = */ NULL
    );
    assert(0 == ret);

    char buf[] = "<15>1 2021-02-01T09:26:46.096736+00:00 091831543131364b gwynetwork-2.1.0 16818 - -  nats_publish_msg:92: Publishing on topic \"libnats.request.3rmyTidmJ448L1yJFhsTHrYAQEHyFp3\" with data [len=1] \"2\"\n";
    int buf_len = strlen(buf);

    ret = lsyslog_client_parser_parse(
        /* parser = */ &lsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);

    assert(1 == log_cb_called);
    assert(16818 == log_cb_pid);
    assert(7 == log_cb_severity);
    assert(1 == log_cb_facility);

}


void test_lsyslog_client_parser_facility_severity (
    int facility,
    int severity
)
{
    int ret = 0;
    struct lsyslog_syslog_s lsyslog_syslog = {0};
    log_cb_called = 0;
    log_cb_pid = 0;
    log_cb_facility = -1;
    log_cb_severity = -1;

    ret = lsyslog_client_parser_init(
        /* parser = */ &lsyslog_syslog,
        /* log_cb = */ log_cb,
        /* context = */ NULL,
        /* arg = */ NULL
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    char buf[512];
    snprintf(buf, 512, 
        "<%d>1 2021-02-01T09:26:23.685588+00:00 091831543131364b gwywd-dev-2.0.0 136 - -  src/subscriptions.c:353:nats_add_subscription_to_server: hi!\n",
        facility * 8 + severity
    );

    int buf_len = strlen(buf);

    ret = lsyslog_client_parser_parse(
        /* parser = */ &lsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(1 == log_cb_called);
    assert(136 == log_cb_pid);

    if (facility != log_cb_facility) {
        printf("%s:%d:%s: log_cb_facility is %d, should be 19 (severity = %d, multiplied=%d)\n", __FILE__, __LINE__, __func__, log_cb_facility, severity, facility * 8 + severity);
        exit(EXIT_FAILURE);
    }
    if (severity != log_cb_severity) {
        printf("%s:%d:%s: log_cb_severity is %d, should be 7\n", __FILE__, __LINE__, __func__, log_cb_severity);
        exit(EXIT_FAILURE);
    }
}


void test_lsyslog_client_parser_parses_facilities_and_severities() {
    for (int severity = 0; severity <= 7; severity += 1) {
        for (int facility = 0; facility <= 23; facility += 1) {
            test_lsyslog_client_parser_facility_severity(facility, severity);
        }
    }
}


void test_lsyslog_client_parser_does_not_parse_invalid_prival (
    int prival
) 
{
    int ret = 0;
    struct lsyslog_syslog_s lsyslog_syslog = {0};
    log_cb_called = 0;

    ret = lsyslog_client_parser_init(
        /* parser = */ &lsyslog_syslog,
        /* log_cb = */ log_cb,
        /* context = */ NULL,
        /* arg = */ NULL
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    char buf[512];
    snprintf(buf, 512, 
        "<%d>1 2021-02-01T09:26:23.685588+00:00 091831543131364b gwywd-dev-2.0.0 136 - -  src/subscriptions.c:353:nats_add_subscription_to_server: hi!\n",
        prival
    );
    int buf_len = strlen(buf);

    ret = lsyslog_client_parser_parse(
        /* parser = */ &lsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(0 == log_cb_called);
}

void test_lsyslog_client_parser_does_not_parse_invalid_privals() {
    test_lsyslog_client_parser_does_not_parse_invalid_prival(-1);
    test_lsyslog_client_parser_does_not_parse_invalid_prival(-2);
    for (int i = 192; i < 1024; i++) {
        test_lsyslog_client_parser_does_not_parse_invalid_prival(i);
    }
}


int main (
    int argc,
    char const* argv[]
)
{
    
//    test_lsyslog_client_parser_init();
//    test_lsyslog_client_parser_parses_basic_log();
//    test_lsyslog_client_parser_parses_log_with_accuracy();
//    test_lsyslog_client_parser_parses_log_from_gwy01_0();
//    test_lsyslog_client_parser_parses_log_from_gwy01_1();
//    test_lsyslog_client_parser_parses_facilities_and_severities();
//    test_lsyslog_client_parser_does_not_parse_invalid_privals();
    test_lsyslog_client_parser_parses_log_with_no_tag();

    return 0;
}
