/*
 * mod_auth_rest - REST-based authentication for ProFTPD (per OpenAPI 1.0)
 * Version string stays: 0.1.0
 */

#include <curl/curl.h>

#include "conf.h"
#include "modules.h"
#include "regexp.h"
#include "netaddr.h"
#include "privs.h"
#include "log.h"

#ifndef PR_LOG_SYSTEM_MODE
# define PR_LOG_SYSTEM_MODE 0660
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* Testable, header-only helpers for connection mode and URL building */
#include "authrest_conn_mode.h"

#define MOD_AUTH_REST_VERSION  "mod_auth_rest/0.1.0"

/* -------- Config -------- */
static char *connection_type = NULL; /* "unix" or "tcp" */
static char *base_address = NULL; /* "/var/run/server.sock" (unix) or "https://auth.example.com" (tcp) */
static char *getpwnam_path = NULL; /* e.g. "/api/authz/getpwnam/{username}" */
static char *auth_path = NULL; /* e.g. "/api/authz/auth/{username}" */
static char *api_key = NULL; /* X-Api-Key value */
static char *bearer_token = NULL; /* Authorization: Bearer <token> */
static pr_regex_t *user_regex = NULL; /* optional username regex */
static char *default_shell = NULL; /* default "/sbin/nologin" */

static long connect_timeout_ms = 300;
static long total_timeout_ms = 1000;

/* ---- logging state ---- */
static int authrest_log_fd = -1; /* -1 => disabled */
static int authrest_log_level = PR_LOG_INFO; /* default */
static int authrest_log_json = 0; /* 0=text, 1=json */

module auth_rest_module;


static const char *lvl_name(const int pri) {
    switch (pri) {
        case PR_LOG_EMERG: return "emerg";
        case PR_LOG_ALERT: return "alert";
        case PR_LOG_CRIT: return "crit";
        case PR_LOG_ERR: return "error";
        case PR_LOG_WARNING: return "warn";
        case PR_LOG_NOTICE: return "notice";
        case PR_LOG_INFO: return "info";
        case PR_LOG_DEBUG: return "debug";
        default: return "info";
    }
}

static const char *json_escape(pool *p, const char *s) {
    if (!s) return "";
    /* The worst case every char escapes => 2x */
    char *out = pcalloc(p, strlen(s)*2 + 1);
    char *w = out;
    for (const char *r = s; *r; r++) {
        switch (*r) {
            case '\\': *w++='\\'; *w++='\\'; break;
            case '\"': *w++='\\'; *w++='\"'; break;
            case '\b': *w++='\\'; *w++='b';  break;
            case '\f': *w++='\\'; *w++='f';  break;
            case '\n': *w++='\\'; *w++='n';  break;
            case '\r': *w++='\\'; *w++='r';  break;
            case '\t': *w++='\\'; *w++='t';  break;
            default: *w++ = *r; break;
        }
    }
    *w = '\0';
    return out;
}

/* -------- user attributes capture -------- */
typedef struct user_attrs {
    char *uid;
    char *gid;
    char *dir;
    char *shell;
    char *gecos;
} user_attrs;

/* One-line log write. */
static void log_event(const int pri, const char *event, const char *user, const long http_code, const int curl_code, const user_attrs *ua, const char *message) {
    if (authrest_log_fd < 0) return;
    if (pri > authrest_log_level) return;
    if (authrest_log_fd < 0) return;
    if (pri > authrest_log_level) return;

    char *uid = "";
    char *gid = "";
    char *dir = "";
    if (ua) {
        uid = ua->uid ? ua->uid : "";
        gid = ua->gid ? ua->gid : "";
        dir = ua->dir ? ua->dir : "";
    }

    if (authrest_log_json) {
        const char *u = json_escape(session.pool, user ? user : "");
        const char *msg = json_escape(session.pool, message ? message : "");
        pr_log_writefile(authrest_log_fd, MOD_AUTH_REST_VERSION,
          "{\"level\":\"%s\",\"event\":\"%s\",\"user\":\"%s\",\"http\":%ld,\"curl\":%d,\"uid\":\"%s\",\"gid\":\"%s\",\"dir\":\"%s\",\"msg\":\"%s\"}",
          lvl_name(pri), event ? event : "", u, http_code, curl_code, uid, gid, json_escape(session.pool, dir), msg);
    } else {
        pr_log_writefile(authrest_log_fd, MOD_AUTH_REST_VERSION,
                         "%s: %s user=%s http=%ld curl=%d uid=%s gid=%s dir=%s msg=%s" ,
                         lvl_name(pri), event ? event : "", user ? user : "", http_code, curl_code, uid, gid, dir, message ? message : "");
    }
}


/* ---------------- header/body sinks ---------------- */

static int hdr_is(const char *line, const char *key) {
    const size_t klen = strlen(key);
    return strncasecmp(line, key, klen) == 0 && line[klen] == ':';
}

static char *trim_r(pool *p, const char *s, size_t n) {
    while (n && (s[n-1] == ' ' || s[n-1] == '\t')) n--;
    return pstrndup(p, s, n);
}

static const char *hdr_value(const char *line) {
    const char *p = strchr(line, ':');
    if (!p) return "";
    p++;
    while (*p == ' ' || *p == '\t') p++;
    /* compute length up to end (we already stripped CRLF earlier) */
    const size_t n = strlen(p);
    return trim_r(session.pool, p, n);
}

static size_t on_header(const void *buffer, const size_t size, const size_t nmemb, void *userdata) {
    const char *line = buffer;
    const size_t len = size * nmemb;
    if (len < 2) return len;

    size_t copy_len = len;
    if (line[copy_len - 1] == '\n') copy_len--;
    if (line[copy_len - 1] == '\r') copy_len--;

    char *s = pstrndup(session.pool, line, copy_len);
    if (!s) return 0;

    user_attrs *attrs = userdata;

    if (hdr_is(s, "x-fs-uid")) attrs->uid = pstrdup(session.pool, hdr_value(s));
    else if (hdr_is(s, "x-fs-gid")) attrs->gid = pstrdup(session.pool, hdr_value(s));
    else if (hdr_is(s, "x-fs-dir")) attrs->dir = pstrdup(session.pool, hdr_value(s));
    else if (hdr_is(s, "x-fs-shell")) attrs->shell = pstrdup(session.pool, hdr_value(s));
    else if (hdr_is(s, "x-fs-gecos")) attrs->gecos = pstrdup(session.pool, hdr_value(s));

    return len;
}

/* sink for anybody; we ignore content */
static size_t on_body(const void *buffer, const size_t size, const size_t nmemb, const void *userdata) {
    (void) buffer;
    (void) userdata;
    return size * nmemb;
}

/* ---------------- helpers ---------------- */

static int is_unix_conn(void) {
    return connection_type && strcasecmp(connection_type, "unix") == 0;
}

static int is_tcp_conn(void) {
    return connection_type && strcasecmp(connection_type, "tcp") == 0;
}

/* join base and path with exactly one slash */
static char *join_base_and_path(pool *p, const char *base, const char *path) {
    if (!base || !*base) return pstrdup(p, path ? path : "");
    if (!path || !*path) return pstrdup(p, base);

    const int base_ends = base[strlen(base) - 1] == '/';
    const int path_starts = path[0] == '/';

    if (base_ends && path_starts) {
        /* drop one slash */
        return pstrcat(p, pstrndup(p, base, strlen(base) - 1), path, NULL);
    }
    if (!base_ends && !path_starts) {
        return pstrcat(p, base, "/", path, NULL);
    }
    return pstrcat(p, base, path, NULL);
}

/* Replace the first "{username}" in template with enc(username); if not present, append "/enc(username)" */
static char *subst_username(pool *p, CURL *curl, const char *tpl, const char *username) {
    if (!tpl) return pstrdup(p, "/");
    char *cee = curl_easy_escape(curl, username, 0);
    const char *u = cee ? cee : username;

    const char *needle = "{username}";
    const char *m = strstr(tpl, needle);
    char *out = NULL;

    if (m) {
        char *prefix = pstrndup(p, tpl, (size_t) (m - tpl));
        const char *suffix = m + strlen(needle);
        out = pstrcat(p, prefix, u, suffix, NULL);
    } else {
        /* ensure single slash before appending username */
        const int ends = tpl[0] && tpl[strlen(tpl) - 1] == '/';
        out = ends
                  ? pstrcat(p, tpl, u, NULL)
                  : pstrcat(p, tpl, "/", u, NULL);
    }

    if (cee) curl_free(cee);
    return out;
}

/* Build the final URL for curl and configure UNIX socket if needed */
static char *build_effective_url(pool *p, CURL *curl, const char *path_tpl, const char *username) {
    const char *path = subst_username(p, curl, path_tpl, username);
#ifdef TESTING
    /* remember which branch we take for unit tests */
    extern void authrest__test_set_last_used_unix(int v);
#endif
    if (is_unix_conn()) {
        CURLcode rc1 = curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, base_address);

#if LIBCURL_VERSION_NUM >= 0x075500  /* 7.85.0 */
        (void) curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http");
#else
        (void) curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
#endif
        if (rc1 != CURLE_OK && authrest_log_fd >= 0) {
            pr_log_writefile(authrest_log_fd, MOD_AUTH_REST_VERSION,
                "error: curl unix socket setopt failed rc=%d base=%s",
                rc1, base_address ? base_address : "(null)");
        }
        if (authrest_log_fd >= 0) {
            pr_log_writefile(authrest_log_fd, MOD_AUTH_REST_VERSION,
                "debug: using UNIX socket: %s", base_address);
        }
        return join_base_and_path(p, "http://localhost", path);
    }
    /* TCP: base_address should be a full origin like https://host[:port] */
    const char *base = base_address ? base_address : "http://localhost";
    /* best-effort: if no scheme is given, assume http:// */
    if (!strstr(base, "://")) {
        base = pstrcat(p, "http://", base_address ? base_address : "localhost", NULL);
    }
    if (authrest_log_fd >= 0) {
        pr_log_writefile(authrest_log_fd, MOD_AUTH_REST_VERSION, "debug: using TCP connection to: %s", base);
    }
#ifdef TESTING
    authrest__test_set_last_used_unix(0);
#endif
    return join_base_and_path(p, base, path);
}

/* -------- libcurl helpers -------- */

static void cleanup_curl_resources(CURL *curl, struct curl_slist *hdrs) {
    if (hdrs) curl_slist_free_all(hdrs);
    if (curl) curl_easy_cleanup(curl);
}

static CURL *curl_new(void) {
    CURL *h = curl_easy_init();
    if (!h) return NULL;

    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout_ms);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, total_timeout_ms);
    curl_easy_setopt(h, CURLOPT_USERAGENT, MOD_AUTH_REST_VERSION);

    /* Only enable HTTP/2 for TCP connections - will be overridden for UNIX sockets */
    if (is_tcp_conn()) {
        curl_easy_setopt(h, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    } else {
        curl_easy_setopt(h, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    }

    /* Enable verbose output when log level is debug */
    if (authrest_log_level >= PR_LOG_DEBUG) {
        curl_easy_setopt(h, CURLOPT_VERBOSE, 1L);
        if (authrest_log_fd >= 0) {
            /* Redirect curl verbose output to our log file if possible */
            curl_easy_setopt(h, CURLOPT_STDERR, stderr);
        }
    }

    return h;
}

static struct curl_slist *apply_headers(struct curl_slist *headers, pool *p) {
    headers = curl_slist_append(headers, "Accept: */*");
    if (api_key && *api_key) {
        headers = curl_slist_append(headers, pstrcat(p, "x-api-key: ", api_key, NULL));
    }
    if (bearer_token && *bearer_token) {
        headers = curl_slist_append(headers, pstrcat(p, "authorization: Bearer ", bearer_token, NULL));
    }
    return headers;
}

/* x-www-form-urlencoded pair: k=v (both URL-escaped) */
static char *form_pair(pool *p, CURL *curl, const char *k, const char *v) {
    char *ek = curl_easy_escape(curl, k, 0);
    char *ev = curl_easy_escape(curl, v ? v : "", 0);
    char *out = pstrcat(p, ek, "=", ev, NULL);
    if (ek) curl_free(ek);
    if (ev) curl_free(ev);
    return out;
}

static char *join_pairs(pool *p, char **pairs, int n) {
    if (n <= 0) return pstrdup(p, "");
    char *out = pstrdup(p, pairs[0]);
    for (int i = 1; i < n; i++) {
        out = pstrcat(p, out, "&", pairs[i], NULL);
    }
    return out;
}

/* -------- getpwnam handler --------
 * OpenAPI: GET {AuthRestBaseAddress}/{AuthRestGetpwnamPath} -> 204 + headers
 */
MODRET handle_rest_getpwnam(cmd_rec *cmd) {
    const char *username = cmd->argv[0];

    if (!getpwnam_path || !connection_type || !base_address || !api_key || !bearer_token) {
        log_event(PR_LOG_ERR, "getpwnam-declined", username, 0, 0, NULL, "wrong parameters");
        return PR_DECLINED(cmd);
    }

    if (!is_unix_conn() && !is_tcp_conn()) {
        log_event(PR_LOG_ERR, "getpwnam-declined", username, 0, 0, NULL, "there is no connection");
        return PR_DECLINED(cmd);
    }

    CURL *curl = curl_new();
    if (!curl) {
        log_event(PR_LOG_ERR, "getpwnam-declined", username, 0, 0, NULL, "cannot create curl handle");
        return PR_DECLINED(cmd);
    }

    if (user_regex && pr_regexp_exec(user_regex, username, 0, NULL, 0, 0, 0) != 0) {
        log_event(PR_LOG_INFO, "getpwnam-declined", username, 0, 0, NULL, "regex filtered username");
        return PR_DECLINED(cmd);
    }

    char *url = build_effective_url(cmd->tmp_pool, curl, getpwnam_path, username);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    user_attrs attrs = (user_attrs){0};
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &attrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);

    struct curl_slist *hdrs = NULL;
    hdrs = apply_headers(hdrs, cmd->tmp_pool);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    const CURLcode rc = curl_easy_perform(curl);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);

    if (rc != CURLE_OK) {
        log_event(PR_LOG_ERR, "getpwnam-declined", username, http, rc, &attrs, pstrcat(cmd->tmp_pool, "url: ", url, ", error: ", curl_easy_strerror(rc), NULL));
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }

    if (http == 401) {
        log_event(PR_LOG_ERR, "getpwnam-declined", username, http, rc, &attrs, "API client not authenticated  — check APIKey/Token");
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }
    if (http == 404) {
        log_event(PR_LOG_INFO, "getpwnam-declined", username, http, rc, &attrs, "user not found / not applicable");
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }
    if (http == 423) {
        log_event(PR_LOG_INFO, "getpwnam-failed", username, http, rc, &attrs, "user disabled/locked");
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    if (http != 204) {
        log_event(PR_LOG_ERR, "getpwnam-declined", username, http, rc, &attrs, "wrong http status code (!=204)");
        return PR_DECLINED(cmd);
    }

    if (!attrs.uid || !attrs.gid || !attrs.dir) {
        log_event(PR_LOG_INFO, "getpwnam-declined", username, http, rc, &attrs, "wrong user attributes");
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }

    struct passwd *pw = pcalloc(session.pool, sizeof(struct passwd));
    if (!pw) {
        log_event(PR_LOG_INFO, "getpwnam-declined", username, http, rc, &attrs, "cannot allocate memory");
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }

    pw->pw_name = pstrdup(session.pool, username);
    pw->pw_passwd = pstrdup(session.pool, "*"); // can't be used to authenticate a user

    char *end = NULL;
    const long uid = strtol(attrs.uid, &end, 10);
    if (!end || *end != '\0' || uid < 0) {
        log_event(PR_LOG_INFO, "getpwnam-declined", username, http, rc, &attrs, "bad uid");
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }
    const long gid = strtol(attrs.gid, &end, 10);
    if (!end || *end != '\0' || gid < 0) {
        log_event(PR_LOG_INFO, "getpwnam-declined", username, http, rc, &attrs, "bad gis");
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }

    pw->pw_uid = (uid_t) uid;
    pw->pw_gid = (gid_t) gid;

    pw->pw_dir = pstrdup(session.pool, attrs.dir);
    pw->pw_shell = pstrdup(session.pool, attrs.shell ? attrs.shell : default_shell);
#ifdef HAVE_PW_GECOS
    pw->pw_gecos = pstrdup(session.pool, attrs.gecos ? attrs.gecos : default_gecos);
#endif

    log_event(PR_LOG_INFO, "getpwnam-accepted", username, http, rc, &attrs, "");
    cleanup_curl_resources(curl, hdrs);
    return mod_create_data(cmd, pw);
}

/* -------- auth handler (USER/PASS) --------
 * OpenAPI: POST {AuthRestBaseAddress}/{AuthRestGetpwnamPath} with body: password (required),
 * optional client_ip, server_ip, protocol. Expects 204 on success.
 */
MODRET handle_rest_auth(cmd_rec *cmd) {
    const char *username = cmd->argv[0];
    const char *password = cmd->argv[1];

    if (!auth_path || !connection_type || !base_address || !api_key || !bearer_token) {
        log_event(PR_LOG_ERR, "auth-declined", username, 0, 0, NULL, "wrong parameters");
        return PR_DECLINED(cmd);
    }

    if (!is_unix_conn() && !is_tcp_conn()) {
        log_event(PR_LOG_ERR, "auth-declined", username, 0, 0, NULL, "there is no connection");
        return PR_DECLINED(cmd);
    }

    CURL *curl = curl_new();
    if (!curl) {
        log_event(PR_LOG_ERR, "auth-declined", username, 0, 0, NULL, "cannot create curl handle");
        return PR_DECLINED(cmd);
    }

    if (user_regex && pr_regexp_exec(user_regex, username, 0, NULL, 0, 0, 0) != 0) {
        log_event(PR_LOG_INFO, "auth-declined", username, 0, 0, NULL, "regex filtered username");
        return PR_DECLINED(cmd);
    }

    char *url = build_effective_url(cmd->tmp_pool, curl, auth_path, username);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* Body: application/x-www-form-urlencoded */
    char *pairs[5];
    int n = 0;
    pairs[n++] = form_pair(cmd->tmp_pool, curl, "password", password);

    /* Optional context */
    const char *cip = NULL, *sip = NULL;
    if (session.c && session.c->remote_addr) cip = pr_netaddr_get_ipstr(session.c->remote_addr);
    if (session.c && session.c->local_addr) sip = pr_netaddr_get_ipstr(session.c->local_addr);
    if (cip && *cip) pairs[n++] = form_pair(cmd->tmp_pool, curl, "client_ip", cip);
    if (sip && *sip) pairs[n++] = form_pair(cmd->tmp_pool, curl, "server_ip", sip);
    pairs[n++] = form_pair(cmd->tmp_pool, curl, "protocol", "ftp");

    char *post = join_pairs(cmd->tmp_pool, pairs, n);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);

    struct curl_slist *hdrs = NULL;
    hdrs = apply_headers(hdrs, cmd->tmp_pool);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    const CURLcode rc = curl_easy_perform(curl);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        log_event(PR_LOG_ERR, "auth-declined", username, http, rc, NULL, pstrcat(cmd->tmp_pool, "url: ", url, ", error: ", curl_easy_strerror(rc), NULL));
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }
    if (http == 401) {
        log_event(PR_LOG_ERR, "auth-declined", username, http, rc, NULL, "API client not authenticated  — check APIKey/Token");
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }
    if (http == 403) {
        log_event(PR_LOG_INFO, "auth-failed", username, http, rc, NULL, "user authentication failed");
        cleanup_curl_resources(curl, hdrs);
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    if (http == 404) {
        log_event(PR_LOG_INFO, "auth-declined", username, http, rc, NULL, "user not found / not applicable");
        cleanup_curl_resources(curl, hdrs);
        return PR_DECLINED(cmd);
    }
    if (http == 423) {
        log_event(PR_LOG_INFO, "auth-failed", username, http, rc, NULL, "user disabled/locked");
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    if (http != 204) {
        log_event(PR_LOG_ERR, "auth-declined", username, http, rc, NULL, "wrong http status code (!=204)");
        return PR_DECLINED(cmd);
    }

    session.auth_mech = "mod_auth_rest.c";
    return PR_HANDLED(cmd);
}

/* -------- Config directives -------- */

MODRET set_connection_type(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    const char *v = cmd->argv[1];
    if (strcasecmp(v, "unix") != 0 && strcasecmp(v, "tcp") != 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, cmd->argv[0], ": expected 'unix' or 'tcp', got '", v, "'", NULL));
    }
    add_config_param_str(cmd->argv[0], 1, v);
    return PR_HANDLED(cmd);
}

MODRET set_base_address(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_getpwnam_path(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_auth_path(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_api_key(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_bearer_token(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_user_regex(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    pr_regex_t *re = pr_regexp_alloc(&auth_rest_module);
    if (pr_regexp_compile_posix(re, cmd->argv[1], REG_ICASE | REG_EXTENDED | REG_NOSUB) != 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, cmd->argv[0], ": bad regex '", cmd->argv[1], "'", NULL));
    }
    add_config_param(cmd->argv[0], 1, (void *) re);
    return PR_HANDLED(cmd);
}

MODRET set_default_shell(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_connect_timeout_ms(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_total_timeout_ms(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

/* AuthRestLogFile <path>|none */
MODRET set_log_file(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

/* AuthRestLogLevel <emerg|alert|crit|error|warn|notice|info|debug|NUMBER> */
MODRET set_log_level(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

/* AuthRestLogFormat text|json */
MODRET set_log_format(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    const char *v = cmd->argv[1];
    if (strcasecmp(v, "text") != 0 && strcasecmp(v, "json") != 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, cmd->argv[0], ": expected 'text' or 'json', got '", v, "'", NULL));
    }
    add_config_param_str(cmd->argv[0], 1, v);
    return PR_HANDLED(cmd);
}

/* Gather config pointers/values */
static int auth_rest_sess_init(void) {
    const char *ct = NULL, *tt = NULL;

    connection_type = (char *) get_param_ptr(main_server->conf, "AuthRestConnectionType", FALSE);
    base_address = (char *) get_param_ptr(main_server->conf, "AuthRestBaseAddress", FALSE);
    getpwnam_path = (char *) get_param_ptr(main_server->conf, "AuthRestGetpwnamPath", FALSE);
    auth_path = (char *) get_param_ptr(main_server->conf, "AuthRestAuthPath", FALSE);

    api_key = (char *) get_param_ptr(main_server->conf, "AuthRestAPIKey", FALSE);
    bearer_token = (char *) get_param_ptr(main_server->conf, "AuthRestBearerToken", FALSE);
    user_regex = (pr_regex_t *) get_param_ptr(main_server->conf, "AuthRestUsernameRegex", FALSE);

    default_shell = (char *) get_param_ptr(main_server->conf, "AuthRestDefaultShell", FALSE);
    if (!default_shell) default_shell = "/sbin/nologin";

    ct = (char *) get_param_ptr(main_server->conf, "AuthRestConnectTimeoutMs", FALSE);
    tt = (char *) get_param_ptr(main_server->conf, "AuthRestTotalTimeoutMs", FALSE);
    if (ct) connect_timeout_ms = strtol(ct, NULL, 10);
    if (tt) total_timeout_ms = strtol(tt, NULL, 10);

    /* ---- logging config (no init log) ---- */
    char *path = get_param_ptr(main_server->conf, "AuthRestLogFile", FALSE);
    const char *lvl = get_param_ptr(main_server->conf, "AuthRestLogLevel", FALSE);
    const char *fmt = get_param_ptr(main_server->conf, "AuthRestLogFormat", FALSE);

    authrest_log_json = (fmt && strcasecmp(fmt, "json") == 0) ? 1 : 0;

    if (lvl) {
        const int parsed = pr_log_str2sysloglevel(lvl);
        if (parsed >= 0) {
            authrest_log_level = parsed;
        } else {
            char *end_p = NULL;
            const long v = strtol(lvl, &end_p, 10);
            if (end_p && *end_p == '\0' && v >= 0 && v <= PR_LOG_DEBUG)
                authrest_log_level = (int) v;
        }
    }

    if (path && strcasecmp(path, "none") != 0 && authrest_log_fd < 0) {
        PRIVS_ROOT
        const int res = pr_log_openfile(path, &authrest_log_fd, PR_LOG_SYSTEM_MODE);
        PRIVS_RELINQUISH
        if (res != 0) {
            pr_log_pri(PR_LOG_ERR, MOD_AUTH_REST_VERSION ": cannot open AuthRestLogFile '%s': %s",
                         path, strerror(errno));
            authrest_log_fd = -1; /* disable logging if open fails */
        }
    }
    log_event(PR_LOG_INFO, "session-initialized", "", 0, 0, NULL,pstrcat(session.pool,
        "connection_type: ", connection_type, ", base_address: ", base_address, NULL));

    return 0;
}

static conftable auth_rest_conftab[] = {
    {"AuthRestConnectionType", set_connection_type, NULL}, /* "unix" | "tcp" */
    {"AuthRestBaseAddress", set_base_address, NULL}, /* socket path OR https://host */
    {"AuthRestGetpwnamPath", set_getpwnam_path, NULL}, /* path with {username} */
    {"AuthRestAuthPath", set_auth_path, NULL}, /* path with {username} */
    {"AuthRestAPIKey", set_api_key, NULL},
    {"AuthRestBearerToken", set_bearer_token, NULL},
    {"AuthRestUsernameRegex", set_user_regex, NULL},
    {"AuthRestDefaultShell", set_default_shell, NULL},
    {"AuthRestConnectTimeoutMs", set_connect_timeout_ms, NULL},
    {"AuthRestTotalTimeoutMs", set_total_timeout_ms, NULL},
    {"AuthRestLogFile", set_log_file, NULL},
    {"AuthRestLogLevel", set_log_level, NULL},
    {"AuthRestLogFormat", set_log_format, NULL},
    {NULL, NULL, NULL}
};

static authtable auth_rest_auth_tab[] = {
    {0, "getpwnam", handle_rest_getpwnam},
    {0, "auth", handle_rest_auth},
    {0, NULL}
};

module auth_rest_module = {
    NULL, NULL,
    0x20, /* Module API v2.0 */
    "auth_rest", /* Module name */
    auth_rest_conftab, /* Configuration handlers */
    NULL, /* Command handlers */
    auth_rest_auth_tab, /* Authentication handlers */
    NULL, /* Module init */
    auth_rest_sess_init, /* Session init */
    MOD_AUTH_REST_VERSION /* Module version string */
};
