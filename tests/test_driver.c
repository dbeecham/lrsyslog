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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
        /* log_cb = */ test_lrsyslog_client_parser_parses_basic_log_cb,
        /* user_data = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<13>1 2020-10-26T12:12:48.414390+01:00 pp-ws-dbe hello - - [timeQuality tzKnown=\"1\" isSynced=\"0\"] hi\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_with_no_tag_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<44>1 2021-04-28T10:28:20.080548+00:00 091831543131364b  - - -  action 'action-2-builtin:omfwd' suspended (module 'builtin:omfwd'), retry 0. There should be messages before this one giving the reason for suspension. [v8.38.0 try http://www.rsyslog.com/e/2007 ]\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(buf_len == ret);
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_with_accuracy_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<13>1 2021-04-12T15:42:28.075395+02:00 pp-ws-dbe hellsadf - - [timeQuality tzKnown=\"1\" isSynced=\"1\" syncAccuracy=\"298500\"] hi\n";
    int buf_len = strlen(buf);
    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(buf_len == ret);
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
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
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(buf_len == ret);
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
        /* callbacks = */ test_lrsyslog_client_parser_parses_log_from_gwy01_1_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<15>1 2021-02-01T09:26:46.096736+00:00 091831543131364b gwynetwork-2.1.0 16818 - -  nats_publish_msg:92: Publishing on topic \"libnats.request.3rmyTidmJ448L1yJFhsTHrYAQEHyFp3\" with data [len=1] \"2\"\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(buf_len == ret);
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_from_gwy01_2_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<15>1 2021-02-01T09:26:46.096736+00:00 091831543131364b spibtm-e7b2e4a4855b5985753ddd26 16818 - - src/nrf/nrf_dispatch_settings.c:512:nrf_dispatch_settings_radio_timeout_cb: timeout!\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(buf_len == ret);
    assert(1 == cb_called);


    printf("%s: OK\n", __func__);
}


int test_lrsyslog_client_parser_parses_log_from_gwy01_3_cb(
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
)
{
    int * cb_called = user_data;
    *cb_called += 1;

    assert(host_len == strlen("0d182d364752354b"));
    assert(0 == memcmp(host, "0d182d364752354b", strlen("0d182d364752354b")));

    return 0;
}

void test_lrsyslog_client_parser_parses_log_from_gwy01_3() {
    int ret = 0;
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_from_gwy01_3_cb,
        /* context = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = 
        "<30>1 2022-03-14T09:39:50.816106+00:00 0d182d364752354b avahi-autoipd(eth0) 199 - -  Callout STOP, address 169.254.5.109 on interface eth0\n"
        "<158>1 2022-03-14T09:39:50.824885+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_sigwait: signal 17 cought...\n"
        "<158>1 2022-03-14T09:39:50.825778+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:900:gwyinit_sigwait_dispatch: child returned with exit code 0\n"
        "<132>1 2022-03-14T09:39:50.945242+00:00 0d182d364752354b spibtm-df00fb421be6cd06ccbdd099 - - -  src/spi_btm.c:243:index_settings_timeout_cb: timeout!\n"
        "<156>1 2022-03-14T09:39:50.949604+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 106 - -  src/gwyinit.c:118:gwyinit_supervisor: spibtm returned 256\n"
        "<158>1 2022-03-14T09:39:50.950278+00:00 0d182d364752354b natsd-ed8fdcb48dd59d81aa3d64a43 97 - -  src/natsd.c:449:natsd_uv_read_cb: EOF received from [0xbe8416c0], cleaning up...\n"
        "<158>1 2022-03-14T09:39:50.951334+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 106 - -  src/gwyinit.c:153:gwyinit_supervisor: sleeping for 2.377101 seconds (where 0.960754 is additional jitter)\n"
        "<30>1 2022-03-14T09:39:51.017616+00:00 0d182d364752354b avahi-autoipd(eth0) 200 - -  client: ip: RTNETLINK answers: No such process\n"
        "<158>1 2022-03-14T09:39:51.080843+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_sigwait: signal 17 cought...\n"
        "<158>1 2022-03-14T09:39:51.081416+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:900:gwyinit_sigwait_dispatch: child returned with exit code 0\n"
        "<158>1 2022-03-14T09:39:51.186568+00:00 0d182d364752354b gwyntp-a8291163586021855b77f3d9 267 - -  src/gwyntp.c:149:gwyntp_ntpservers_updated_cb: NTP servers list updated, restarting\n"
        "<158>1 2022-03-14T09:39:51.191671+00:00 0d182d364752354b natsd-ed8fdcb48dd59d81aa3d64a43 97 - -  src/natsd.c:449:natsd_uv_read_cb: EOF received from [0xbe7d1110], cleaning up...\n"
        "<158>1 2022-03-14T09:39:51.192635+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:933:gwyinit_sigwait: signal 17 cought...\n"
        "<156>1 2022-03-14T09:39:51.193274+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 129 - -  src/gwyinit.c:118:gwyinit_supervisor: gwyntp returned 256\n"
        "<158>1 2022-03-14T09:39:51.193620+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 129 - -  src/gwyinit.c:153:gwyinit_supervisor: sleeping for 2.456442 seconds (where 0.004115 is additional jitter)\n"
        "<158>1 2022-03-14T09:39:51.193891+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 1 - -  src/gwyinit.c:900:gwyinit_sigwait_dispatch: child returned with exit code 15\n"
        "<158>1 2022-03-14T09:39:51.205509+00:00 0d182d364752354b natsd-ed8fdcb48dd59d81aa3d64a43 97 - -  src/natsd.c:465:natsd_uv_read_cb: read -104 bytes from [0xbe8416c0], which is invalid - cleaning up...\n"
        "<14>1 2022-03-14T09:39:51.344315+00:00 0d182d364752354b gwyhk - - -  ok mdnsd is running now - pid 338\n"
        "<14>1 2022-03-14T09:39:51.355590+00:00 0d182d364752354b gwyhk - - -  src/gwyhk_mdnsd.c:55:gwyhk_mdnsd_task: Waiting for file: /tmp/mdns_services.conf\n"
        "<11>1 2022-03-14T09:39:51.592603+00:00 0d182d364752354b gwyupdate-2.2.0 298 - -  src/gwyupdate.c:754:gwyupdate_fetch_hawkbit_security_token: curl_easy_perform: 6: Couldn't resolve host name\n"
        "<11>1 2022-03-14T09:39:51.592729+00:00 0d182d364752354b gwyupdate-2.2.0 298 - -  src/gwyupdate.c:827:main: gwyupdate_fetch_hawkbit_security_token returned -1\n"
        "<156>1 2022-03-14T09:39:51.594804+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 130 - -  src/gwyinit.c:118:gwyinit_supervisor: gwyupdate returned 256\n"
        "<158>1 2022-03-14T09:39:51.595449+00:00 0d182d364752354b gwyinit-81253471b07a140b5de7da2 130 - -  src/gwyinit.c:153:gwyinit_supervisor: sleeping for 12.154268 seconds (where 0.285088 is additional jitter)\n";
        

    int buf_len = strlen(buf);


    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(139 == ret);
    assert(1 == cb_called);


    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf + 139,
        /* buf_len = */ buf_len - 139
    );
    assert(151 == ret);
    assert(2 == cb_called);


    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf + 139 + 151,
        /* buf_len = */ buf_len - 139 - 151
    );
    assert(172 == ret);
    assert(3 == cb_called);


    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf + 139 + 151 + 172,
        /* buf_len = */ buf_len - 139 - 151 - 172
    );
    assert(150 == ret);
    assert(4 == cb_called);


    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf + 139 + 151 + 172,
        /* buf_len = */ buf_len - 139 - 151 - 172
    );
    assert(150 == ret);
    assert(5 == cb_called);


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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    int cb_called = 0;

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
        /* log_cb = */ test_lrsyslog_client_parser_parses_log_with_no_src_cb,
        /* user_data = */ &cb_called
    );
    assert(0 == ret);

    char buf[] = "<15>1 2021-02-01T09:26:46.096736+00:00 091831543131364b spibtm-e7b2e4a4855b5985753ddd26 16818 - - nrf_dispatch_settings_radio_timeout_cb: timeout!\n";
    int buf_len = strlen(buf);

    ret = lrsyslog_client_parser_parse(
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(buf_len == ret);
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};
    struct test_lrsyslog_client_parser_facility_severity_s cb_info = {0};

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
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
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(buf_len == ret);
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
    const char * msg_len_str,
    const uint32_t msg_len_str_len,
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
    struct lrsyslog_client_parser_s lrsyslog_client_parser = {0};

    ret = lrsyslog_client_parser_init(
        /* parser = */ &lrsyslog_client_parser,
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
        /* parser = */ &lrsyslog_client_parser,
        /* buf = */ buf,
        /* buf_len = */ buf_len
    );
    assert(buf_len == ret);
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
    test_lrsyslog_client_parser_parses_log_from_gwy01_3();
    test_lrsyslog_client_parser_parses_log_with_no_src();
    test_lrsyslog_client_parser_parses_facilities_and_severities();
    test_lrsyslog_client_parser_does_not_parse_invalid_privals();
    test_lrsyslog_client_parser_parses_log_with_no_tag();

    return 0;
}
