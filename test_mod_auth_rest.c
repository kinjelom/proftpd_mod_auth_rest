/*
 * test_mod_auth_rest.c - Unit tests for mod_auth_rest
 */

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <microhttpd.h>
#include <stdio.h>

/* Test configuration */
#define TEST_UNIX_SOCKET "/tmp/test_auth_rest.sock"
#define TEST_HTTP_PORT 18080
#define TEST_API_KEY "test-api-key"
#define TEST_BEARER_TOKEN "test-bearer-token"

/* Mock server state */
typedef struct {
    int response_code;
    const char *uid;
    const char *gid;
    const char *dir;
    int check_api_key;
    int check_bearer;
} mock_server_state;

static mock_server_state server_state = {0};

/* Mock HTTP server callback */
static enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection, const char *url,
                                      const char *method, const char *version, const char *upload_data,
                                      size_t *upload_data_size, void **con_cls) {
#ifdef DEBUG
    fprintf(stderr, "[DEBUG] handle_request called:\n");
    fprintf(stderr, "  cls: %p\n", cls);
    fprintf(stderr, "  connection: %p\n", connection);
    fprintf(stderr, "  url: %s\n", url ? url : "(null)");
    fprintf(stderr, "  method: %s\n", method ? method : "(null)");
    fprintf(stderr, "  version: %s\n", version ? version : "(null)");
    fprintf(stderr, "  upload_data_size: %zu\n", upload_data_size ? *upload_data_size : 0);
    fprintf(stderr, "  con_cls: %p\n", con_cls ? *con_cls : NULL);

    if (upload_data && upload_data_size && *upload_data_size > 0) {
        size_t max_len = (*upload_data_size > 256) ? 256 : *upload_data_size;
        fprintf(stderr, "  upload_data (first %zu bytes): ", max_len);
        for (size_t i = 0; i < max_len; i++) {
            unsigned char c = (unsigned char)upload_data[i];
            fputc((c >= 32 && c < 127) ? c : '.', stderr);
        }
        fprintf(stderr, "\n");
    }
#endif

    struct MHD_Response *response;
    enum MHD_Result ret;

    /* Check authentication headers */
    if (server_state.check_api_key) {
        const char *api_key = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "x-api-key");
        if (!api_key || strcmp(api_key, TEST_API_KEY) != 0) {
            response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
            ret = MHD_queue_response(connection, 401, response);
            MHD_destroy_response(response);
            return ret;
        }
    }

    if (server_state.check_bearer) {
        const char *auth = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "authorization");
        char expected[256];
        snprintf(expected, sizeof(expected), "Bearer %s", TEST_BEARER_TOKEN);
        if (!auth || strcmp(auth, expected) != 0) {
            response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
            ret = MHD_queue_response(connection, 401, response);
            MHD_destroy_response(response);
            return ret;
        }
    }

    /* Create response with configured status */
    response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);

    /* Add custom headers for getpwnam endpoint */
    if (strstr(url, "/getpwnam/") && server_state.response_code == 204) {
        if (server_state.uid)
            MHD_add_response_header(response, "x-fs-uid", server_state.uid);
        if (server_state.gid)
            MHD_add_response_header(response, "x-fs-gid", server_state.gid);
        if (server_state.dir)
            MHD_add_response_header(response, "x-fs-dir", server_state.dir);
    }

    ret = MHD_queue_response(connection, server_state.response_code, response);
    MHD_destroy_response(response);

    return ret;
}

/* Setup/teardown */
static struct MHD_Daemon *test_daemon = NULL;

void setup_mock_server(void) {
    /* Reset state */
    memset(&server_state, 0, sizeof(server_state));
    server_state.response_code = 204;
    server_state.uid = "1000";
    server_state.gid = "1000";
    server_state.dir = "/home/testuser";
    server_state.check_api_key = 1;
    server_state.check_bearer = 1;

    /* Start HTTP server */
    test_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, TEST_HTTP_PORT, NULL, NULL,
                                   &handle_request, NULL, MHD_OPTION_END);
    ck_assert_ptr_nonnull(test_daemon);
}

void teardown_mock_server(void) {
    if (test_daemon) {
        MHD_stop_daemon(test_daemon);
        test_daemon = NULL;
    }
    unlink(TEST_UNIX_SOCKET);
}

/* ========== Test Cases ========== */

/* Connection mode decision tests */
#include "authrest_conn_mode.h"

START_TEST(test_conn_mode_unix) {
    ck_assert_int_eq(authrest_is_unix_conn_str("unix"), 1);
    ck_assert_int_eq(authrest_is_unix_conn_str("UNIX"), 1);
    ck_assert_int_eq(authrest_is_tcp_conn_str("unix"), 0);
}
END_TEST

START_TEST(test_conn_mode_tcp) {
    ck_assert_int_eq(authrest_is_tcp_conn_str("tcp"), 1);
    ck_assert_int_eq(authrest_is_tcp_conn_str("TCP"), 1);
    ck_assert_int_eq(authrest_is_unix_conn_str("tcp"), 0);
}
END_TEST

START_TEST(test_conn_mode_invalid) {
    ck_assert_int_eq(authrest_is_unix_conn_str(NULL), 0);
    ck_assert_int_eq(authrest_is_tcp_conn_str(NULL), 0);
    ck_assert_int_eq(authrest_is_unix_conn_str(""), 0);
    ck_assert_int_eq(authrest_is_tcp_conn_str(""), 0);
    ck_assert_int_eq(authrest_is_unix_conn_str("other"), 0);
    ck_assert_int_eq(authrest_is_tcp_conn_str("other"), 0);
}
END_TEST

START_TEST(test_effective_url_unix)
{
    int is_unix = -1;
    char *url = authrest_build_effective_url_static(
        "unix",
        "/var/run/fsaa.sock",
        "/api/authz/getpwnam/{username}",
        "alice",
        &is_unix);
    ck_assert_int_eq(is_unix, 1);
    /* Should use http://localhost base when unix socket */
    ck_assert_msg(strncmp(url, "http://localhost/", 17) == 0,
                  "Expected http://localhost/... base, got: %s", url);
    ck_assert_msg(strstr(url, "/api/authz/getpwnam/alice") != NULL,
                  "Expected path with username, got: %s", url);
    free(url);
}
END_TEST

START_TEST(test_effective_url_tcp_with_scheme)
{
    int is_unix = -1;
    char *url = authrest_build_effective_url_static(
        "tcp",
        "https://auth.example.com",
        "/api/authz/getpwnam/{username}",
        "bob",
        &is_unix);
    ck_assert_int_eq(is_unix, 0);
    ck_assert_msg(strncmp(url, "https://auth.example.com/", 25) == 0,
                  "Expected https://auth.example.com/..., got: %s", url);
    ck_assert_msg(strstr(url, "/api/authz/getpwnam/bob") != NULL,
                  "Expected path with username, got: %s", url);
    free(url);
}
END_TEST

START_TEST(test_effective_url_tcp_without_scheme)
{
    int is_unix = -1;
    char *url = authrest_build_effective_url_static(
        "tcp",
        "auth.local:8080",
        "api/authz/auth/{username}",
        "carol",
        &is_unix);
    ck_assert_int_eq(is_unix, 0);
    /* Expect http:// prefix added */
    ck_assert_msg(strncmp(url, "http://auth.local:8080/", 23) == 0,
                  "Expected http://auth.local:8080/..., got: %s", url);
    ck_assert_msg(strstr(url, "api/authz/auth/carol") != NULL,
                  "Expected path with username, got: %s", url);
    free(url);
}
END_TEST

/* Test successful user getpwnam */
START_TEST(test_getpwnam_success) {
    server_state.response_code = 204;
    server_state.uid = "1001";
    server_state.gid = "1001";
    server_state.dir = "/home/testuser";

    /* TODO: Call module's getpwnam function and verify results */
    /* This would require proper ProFTPD test harness setup */
}

END_TEST

/* Test getpwnam with missing headers */
START_TEST(test_getpwnam_missing_headers) {
    server_state.response_code = 204;
    server_state.uid = NULL; /* Missing uid header */
    server_state.gid = "1000";
    server_state.dir = "/home/test";

    /* Should decline when headers are missing */
}

END_TEST

/* Test getpwnam with invalid UID */
START_TEST(test_getpwnam_invalid_uid) {
    server_state.response_code = 204;
    server_state.uid = "not-a-number";
    server_state.gid = "1000";
    server_state.dir = "/home/test";

    /* Should decline with invalid UID */
}

END_TEST

/* Test getpwnam with 404 (user not found) */
START_TEST(test_getpwnam_user_not_found) {
    server_state.response_code = 404;

    /* Should decline gracefully */
}

END_TEST

/* Test getpwnam with 423 (user locked) */
START_TEST(test_getpwnam_user_locked) {
    server_state.response_code = 423;

    /* Should return PR_AUTH_BADPWD */
}

END_TEST

/* Test getpwnam with 401 (API auth failed) */
START_TEST(test_getpwnam_api_auth_failed) {
    server_state.response_code = 401;

    /* Should decline */
}

END_TEST

/* Test successful authentication */
START_TEST(test_auth_success) {
    server_state.response_code = 204;

    /* Should return PR_HANDLED */
}

END_TEST

/* Test authentication with wrong password (403) */
START_TEST(test_auth_wrong_password) {
    server_state.response_code = 403;

    /* Should return PR_AUTH_BADPWD */
}

END_TEST

/* Test authentication with user not found (404) */
START_TEST(test_auth_user_not_found) {
    server_state.response_code = 404;

    /* Should decline */
}

END_TEST

/* Test authentication with locked account (423) */
START_TEST(test_auth_user_locked) {
    server_state.response_code = 423;

    /* Should return PR_AUTH_BADPWD */
}

END_TEST

/* Test URL building with username substitution */
START_TEST(test_url_username_substitution) {
    /* Test {username} placeholder replacement */
    /* Test URL escaping */
    /* Test path joining */
}

END_TEST

/* Test header parsing (case-insensitive) */
START_TEST(test_header_parsing) {
    /* Test case-insensitive header matching */
    /* Test header value trimming */
}

END_TEST

/* Test JSON escaping for logging */
START_TEST(test_json_escape) {
    /* Test escaping of special characters */
    /* Test quotes, backslashes, control chars */
}

END_TEST

/* Test connection timeout */
START_TEST(test_connection_timeout) {
    /* Configure very short timeout */
    /* Connect to unresponsive server */
    /* Should timeout and decline */
}

END_TEST

/* Test username regex filtering */
START_TEST(test_username_regex_filter) {
    /* Test with matching username */
    /* Test with non-matching username */
}

END_TEST

/* ========== Test Suite ========== */

Suite *auth_rest_suite(void) {
    Suite *s = suite_create("mod_auth_rest");

    /* Getpwnam tests */
    TCase *tc_getpwnam = tcase_create("Getpwnam");
    tcase_add_checked_fixture(tc_getpwnam, setup_mock_server, teardown_mock_server);
    tcase_add_test(tc_getpwnam, test_getpwnam_success);
    tcase_add_test(tc_getpwnam, test_getpwnam_missing_headers);
    tcase_add_test(tc_getpwnam, test_getpwnam_invalid_uid);
    tcase_add_test(tc_getpwnam, test_getpwnam_user_not_found);
    tcase_add_test(tc_getpwnam, test_getpwnam_user_locked);
    tcase_add_test(tc_getpwnam, test_getpwnam_api_auth_failed);
    suite_add_tcase(s, tc_getpwnam);

    /* Authentication tests */
    TCase *tc_auth = tcase_create("Authentication");
    tcase_add_checked_fixture(tc_auth, setup_mock_server, teardown_mock_server);
    tcase_add_test(tc_auth, test_auth_success);
    tcase_add_test(tc_auth, test_auth_wrong_password);
    tcase_add_test(tc_auth, test_auth_user_not_found);
    tcase_add_test(tc_auth, test_auth_user_locked);
    suite_add_tcase(s, tc_auth);

        /* Connection mode tests */
    TCase *tc_connmode = tcase_create("ConnMode");
    tcase_add_test(tc_connmode, test_conn_mode_unix);
    tcase_add_test(tc_connmode, test_conn_mode_tcp);
    tcase_add_test(tc_connmode, test_conn_mode_invalid);
    suite_add_tcase(s, tc_connmode);

    /* Helper functions tests */
    TCase *tc_helpers = tcase_create("Helpers");
    tcase_add_test(tc_helpers, test_url_username_substitution);
    tcase_add_test(tc_helpers, test_effective_url_unix);
    tcase_add_test(tc_helpers, test_effective_url_tcp_with_scheme);
    tcase_add_test(tc_helpers, test_effective_url_tcp_without_scheme);
    tcase_add_test(tc_helpers, test_header_parsing);
    tcase_add_test(tc_helpers, test_json_escape);
    suite_add_tcase(s, tc_helpers);

    /* Configuration tests */
    TCase *tc_config = tcase_create("Configuration");
    tcase_add_test(tc_config, test_connection_timeout);
    tcase_add_test(tc_config, test_username_regex_filter);
    suite_add_tcase(s, tc_config);

    return s;
}

int main(void) {
    Suite *s = auth_rest_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
