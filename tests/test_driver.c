#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <assert.h>
#include <stdint.h>

#include "lrsyslog_client_parser.h"

static int log_cb_called = 0;
static int log_cb_pid = 0;
static int log_cb_severity = 0;
static int log_cb_facility = 0;

static char log_cb_msg[1024];
static int log_cb_msg_len = 0;
static char log_cb_host[1024];
static int log_cb_host_len = 0;
static char log_cb_tag[128];
static int log_cb_tag_len = 0;
static char log_cb_src_path[128];
static int log_cb_src_path_len = 0;
static char log_cb_src_func[128];
static int log_cb_src_func_len = 0;
static int log_cb_src_line = 0;
static char log_cb_raw_msg[1024];
static int log_cb_raw_msg_len = 0;


void test_lrsyslog_client_parser_init() {
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* log_cb = */ NULL,
        /* context = */ NULL
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lrsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }
    
    printf("%s: OK\n", __func__);
}


int test_lrsyslog_client_parser_parses_basic_log_cb (
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
)
{
    int * cb_called = user_data;
    *cb_called += 1;

    assert(0 == pid);
    assert(1 == facility);
    assert(5 == severity);
    assert(9 == host_len);
    assert(0 == memcmp(host, "pp-ws-dbe", 9));

    return 0;
}
void test_lrsyslog_client_parser_parses_basic_log() {
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* log_cb = */ test_lrsyslog_client_parser_parses_basic_log_cb,
        /* user_data = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<13>1 2020-10-26T12:12:48.414390+01:00 pp-ws-dbe hello - - [timeQuality tzKnown=\"1\" isSynced=\"0\"] hi\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lrsyslog_client_parser_parse returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    assert(1 == cb_called);

    printf("%s: OK\n", __func__);
}


int test_lrsyslog_client_parser_parses_log_with_no_tag_cb(
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
)
{
    int * cb_called = user_data;
    *cb_called += 1;

    assert(0 == pid);
    assert(strlen("091831543131364b") == host_len);
    assert(0 == memcmp(host, "091831543131364b", strlen("091831543131364b")));

    return 0;
}

void test_lrsyslog_client_parser_parses_log_with_no_tag() {
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_with_no_tag_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<44>1 2021-04-28T10:28:20.080548+00:00 091831543131364b  - - -  action 'action-2-builtin:omfwd' suspended (module 'builtin:omfwd'), retry 0. There should be messages before this one giving the reason for suspension. [v8.38.0 try http://www.rsyslog.com/e/2007 ]\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(1 == cb_called);

    printf("%s: OK\n", __func__);
}



int test_lrsyslog_client_parser_parses_log_with_accuracy_cb(
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
)
{
    int * cb_called = user_data;
    *cb_called += 1;

    assert(0 == pid);
    assert(strlen("pp-ws-dbe") == host_len);
    assert(0 == memcmp(host, "pp-ws-dbe", strlen("pp-ws-dbe")));
    assert(strlen("hi") == msg_len);
    assert(0 == memcmp(msg, "hi", strlen("hi")));

    return 0;
}

void test_lrsyslog_client_parser_parses_log_with_accuracy() {
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_with_accuracy_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<13>1 2021-04-12T15:42:28.075395+02:00 pp-ws-dbe hellsadf - - [timeQuality tzKnown=\"1\" isSynced=\"1\" syncAccuracy=\"298500\"] hi\n";
    int buf_len = strlen(buf);
    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(1 == cb_called);

    printf("%s: OK\n", __func__);
}


int test_lrsyslog_client_parser_parses_log_from_gwy01_0_cb(
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
)
{
    int * cb_called = user_data;
    *cb_called += 1;

    assert(19 == facility);
    assert(7 == severity);
    assert(136 == pid);
    assert(strlen("091831543131364b") == host_len);
    assert(0 == memcmp(host, "091831543131364b", strlen("091831543131364b")));
    assert(strlen("src/subscriptions.c:353:nats_add_subscription_to_server: hi!") == msg_len);
    assert(0 == memcmp(
                    msg, 
                    "src/subscriptions.c:353:nats_add_subscription_to_server: hi!", 
                    strlen("src/subscriptions.c:353:nats_add_subscription_to_server: hi!")
                )
    );

    return 0;
}

void test_lrsyslog_client_parser_parses_log_from_gwy01_0() {
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_from_gwy01_0_cb,
        /* context = */ &cb_called
    );
    if (-1 == ret) {
        printf("%s:%d:%s: lrsyslog_client_parser_init returned -1\n", __FILE__, __LINE__, __func__);
        exit(EXIT_FAILURE);
    }

    char buf[] = "<159>1 2021-02-01T09:26:23.685588+00:00 091831543131364b gwywd-dev-2.0.0 136 - -  src/subscriptions.c:353:nats_add_subscription_to_server: hi!\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(1 == cb_called);

    printf("%s: OK\n", __func__);
}


int test_lrsyslog_client_parser_parses_log_from_gwy01_1_cb(
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
)
{
    int * cb_called = user_data;
    *cb_called += 1;

    assert(16818 == pid);
    assert(7 == severity);
    assert(1 == facility);
    assert(strlen("091831543131364b") == host_len);
    assert(0 == memcmp(host, "091831543131364b", strlen("091831543131364b")));
    assert(strlen("nats_publish_msg:92: Publishing on topic \"libnats.request.3rmyTidmJ448L1yJFhsTHrYAQEHyFp3\" with data [len=1] \"2\"") == msg_len);
    assert(0 == memcmp(
                    msg, 
                    "nats_publish_msg:92: Publishing on topic \"libnats.request.3rmyTidmJ448L1yJFhsTHrYAQEHyFp3\" with data [len=1] \"2\"", 
                    strlen("nats_publish_msg:92: Publishing on topic \"libnats.request.3rmyTidmJ448L1yJFhsTHrYAQEHyFp3\" with data [len=1] \"2\"")
                )
    );

    return 0;
}

void test_lrsyslog_client_parser_parses_log_from_gwy01_1() {
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* callbacks = */ test_lrsyslog_client_parser_parses_log_from_gwy01_1_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<15>1 2021-02-01T09:26:46.096736+00:00 091831543131364b gwynetwork-2.1.0 16818 - -  nats_publish_msg:92: Publishing on topic \"libnats.request.3rmyTidmJ448L1yJFhsTHrYAQEHyFp3\" with data [len=1] \"2\"\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(1 == cb_called);

    printf("%s: OK\n", __func__);
}



int test_lrsyslog_client_parser_parses_log_from_gwy01_2_cb(
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
)
{
    int * cb_called = user_data;
    *cb_called += 1;

    assert(16818 == pid);
    assert(7 == severity);
    assert(1 == facility);
    assert(host_len == strlen("091831543131364b"));
    assert(0 == memcmp(host, "091831543131364b", strlen("091831543131364b")));

    assert(strlen("src/nrf/nrf_dispatch_settings.c:512:nrf_dispatch_settings_radio_timeout_cb: timeout!") == msg_len);
    assert(0 == memcmp(
                    msg, 
                    "src/nrf/nrf_dispatch_settings.c:512:nrf_dispatch_settings_radio_timeout_cb: timeout!", 
                    strlen("src/nrf/nrf_dispatch_settings.c:512:nrf_dispatch_settings_radio_timeout_cb: timeout!")
                )
    );


    return 0;
}

void test_lrsyslog_client_parser_parses_log_from_gwy01_2() {
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_from_gwy01_2_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<15>1 2021-02-01T09:26:46.096736+00:00 091831543131364b spibtm-e7b2e4a4855b5985753ddd26 16818 - - src/nrf/nrf_dispatch_settings.c:512:nrf_dispatch_settings_radio_timeout_cb: timeout!\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(1 == cb_called);


    printf("%s: OK\n", __func__);
}



int test_lrsyslog_client_parser_parses_log_with_no_src_cb (
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
)
{
    int * cb_called = user_data;
    *cb_called += 1;

    assert(16818 == pid);
    assert(7 == severity);
    assert(1 == facility);
    assert(host_len == strlen("091831543131364b"));
    assert(0 == memcmp(host, "091831543131364b", strlen("091831543131364b")));

    return 0;
}

void test_lrsyslog_client_parser_parses_log_with_no_src() {
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_with_no_src_cb,
        /* user_data = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<15>1 2021-02-01T09:26:46.096736+00:00 091831543131364b spibtm-e7b2e4a4855b5985753ddd26 16818 - - nrf_dispatch_settings_radio_timeout_cb: timeout!\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(1 == cb_called);

    printf("%s: OK\n", __func__);
}



struct test_lrsyslog_client_parser_facility_severity_s {
    int cb_called;
    int facility;
    int severity;
};

int test_lrsyslog_client_parser_facility_severity_cb (
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
)
{
    struct test_lrsyslog_client_parser_facility_severity_s * cb_info = user_data;

    assert(136 == pid);

    cb_info->cb_called += 1;
    cb_info->severity = severity;
    cb_info->facility = facility;

    return 0;
}

void test_lrsyslog_client_parser_facility_severity (
    int facility,
    int severity
)
{
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};
    struct test_lrsyslog_client_parser_facility_severity_s cb_info = {0};

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* log_cb = */ test_lrsyslog_client_parser_facility_severity_cb,
        /* context = */ &cb_info
    );
    assert(0 == ret);

    char buf[512];
    snprintf(buf, 512, 
        "<%d>1 2021-02-01T09:26:23.685588+00:00 091831543131364b gwywd-dev-2.0.0 136 - -  src/subscriptions.c:353:nats_add_subscription_to_server: hi!\n",
        facility * 8 + severity
    );

    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(1 == cb_info.cb_called);
    assert(facility == cb_info.facility);
    assert(severity == cb_info.severity);
}


void test_lrsyslog_client_parser_parses_facilities_and_severities() {
    for (int severity = 0; severity <= 7; severity += 1) {
        for (int facility = 0; facility <= 23; facility += 1) {
            test_lrsyslog_client_parser_facility_severity(facility, severity);
        }
    }

    printf("%s: OK\n", __func__);
}



int test_lrsyslog_client_parser_does_not_parse_invalid_prival_cb (
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
)
{
    assert(0);
}

void test_lrsyslog_client_parser_does_not_parse_invalid_prival (
    int prival
) 
{
    int ret = 0;
    struct lrsyslog_syslog_s lrsyslog_syslog = {0};

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_syslog,
        /* callbacks = */ test_lrsyslog_client_parser_does_not_parse_invalid_prival_cb,
        /* context = */ NULL
    );
    assert(0 == ret);

    char buf[512];
    snprintf(buf, 512, 
        "<%d>1 2021-02-01T09:26:23.685588+00:00 091831543131364b gwywd-dev-2.0.0 136 - -  src/subscriptions.c:353:nats_add_subscription_to_server: hi!\n",
        prival
    );
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_syslog,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(0 == ret);
    assert(0 == log_cb_called);

    return 0;
}


void test_lrsyslog_client_parser_does_not_parse_invalid_privals() {
    test_lrsyslog_client_parser_does_not_parse_invalid_prival(-1);
    test_lrsyslog_client_parser_does_not_parse_invalid_prival(-2);
    for (int i = 192; i < 1024; i++) {
        test_lrsyslog_client_parser_does_not_parse_invalid_prival(i);
    }

    printf("%s: OK\n", __func__);
}


int main (
    int argc,
    char const* argv[]
)
{
    
    test_lrsyslog_client_parser_init();
    test_lrsyslog_client_parser_parses_basic_log();
    test_lrsyslog_client_parser_parses_log_with_accuracy();
    test_lrsyslog_client_parser_parses_log_from_gwy01_0();
    test_lrsyslog_client_parser_parses_log_from_gwy01_1();
    test_lrsyslog_client_parser_parses_log_from_gwy01_2();
    test_lrsyslog_client_parser_parses_log_with_no_src();
    test_lrsyslog_client_parser_parses_facilities_and_severities();
    test_lrsyslog_client_parser_does_not_parse_invalid_privals();
    test_lrsyslog_client_parser_parses_log_with_no_tag();

    return 0;
}
