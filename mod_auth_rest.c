/*
 * mod_auth_rest - REST-based authentication for ProFTPD (per OpenAPI 1.0)
 * Version string stays: 0.1.0
 */

#include <curl/curl.h>

#include "conf.h"
#include "modules.h"
#include "regexp.h"
#include "netaddr.h"  /* pr_netaddr_get_ipstr */

#include <string.h>   /* strlen, strncasecmp, strchr */
#include <stdlib.h>   /* strtol */

#define MOD_AUTH_REST_VERSION  "mod_auth_rest/0.1.0"

/* -------- Config -------- */
static char *auth_url = NULL; /* base, e.g. /api/authz */
static char *lookup_url = NULL; /* base, e.g. /api/authz/users */
static char *api_key = NULL; /* X-Api-Key value */
static char *bearer_token = NULL; /* Authorization: Bearer <token> */
static pr_regex_t *user_creg = NULL; /* optional username regex */

static long connect_timeout_ms = 300;
static long total_timeout_ms = 1000;

module auth_rest_module;

/* -------- Attr capture -------- */
typedef struct rest_attrs {
    char *uid;
    char *gid;
    char *home;
} rest_attrs;

static int hdr_is(const char *line, const char *key) {
    size_t klen = strlen(key);
    return strncasecmp(line, key, klen) == 0 && line[klen] == ':';
}

static const char *hdr_value(const char *line) {
    const char *p = strchr(line, ':');
    if (!p) return "";
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static size_t on_header(const void *buffer, size_t size, size_t nmemb, void *userdata) {
    const char *line = buffer;
    size_t len = size * nmemb;
    if (len < 2) return len;

    size_t copy_len = len;
    if (line[copy_len - 1] == '\n') copy_len--;
    if (line[copy_len - 1] == '\r') copy_len--;

    char *s = pstrndup(session.pool, line, copy_len);
    if (!s) return 0;

    rest_attrs *attrs = (rest_attrs *) userdata;

    if (hdr_is(s, "x-fs-uid")) attrs->uid = pstrdup(session.pool, hdr_value(s));
    else if (hdr_is(s, "x-fs-gid")) attrs->gid = pstrdup(session.pool, hdr_value(s));
    else if (hdr_is(s, "x-fs-home")) attrs->home = pstrdup(session.pool, hdr_value(s));

    return len;
}

/* sink for anybody; we ignore content */
static size_t on_body(const void *buffer, size_t size, size_t nmemb, const void *userdata) {
    (void) buffer;
    (void) userdata;
    return size * nmemb;
}

/* --- URL helpers for http+unix:// and https+unix:// --------------------- */

static int has_prefix_ci(const char *s, const char *pfx) {
    return strncasecmp(s, pfx, strlen(pfx)) == 0;
}

/* Parse:
 *  http+unix://%2Fpath%2Fto.sock:/api/authz
 *  https+unix://%2Fpath%2Fto.sock:/api/authz
 *  unix://%2Fpath%2Fto.sock:/api/authz (alias of http+unix)
 *
 * On success:
 *  - sets CURLOPT_UNIX_SOCKET_PATH to decoded(sock_enc)
 *  - returns a newly allocated URL like "http://localhost/api/authz" or "https://localhost/api/authz"
 * On non-unix schemes, returns a strdup(raw) and does not touch the unix-socket option.
 */
static char *prepare_url_for_curl(pool *p, CURL *curl, const char *raw) {
    const char *scheme_httpu = "http+unix://";
    const char *scheme_httpsu = "https+unix://";
    const char *scheme_unix = "unix://";

    int is_https = 0;
    const char *rest = NULL;

    if (has_prefix_ci(raw, scheme_httpu)) {
        is_https = 0;
        rest = raw + strlen(scheme_httpu);
    } else if (has_prefix_ci(raw, scheme_httpsu)) {
        is_https = 1;
        rest = raw + strlen(scheme_httpsu);
    } else if (has_prefix_ci(raw, scheme_unix)) {
        is_https = 0;
        rest = raw + strlen(scheme_unix);
    } else {
        /* normal http(s) URL, pass through */
        return pstrdup(p, raw);
    }

    const char *colon = strchr(rest, ':');
    if (!colon) {
        /* malformed; fall back to pass through */
        return pstrdup(p, raw);
    }

    int outlen = 0;
    char *sock_dec = curl_easy_unescape(curl, rest, (int) (colon - rest), &outlen);
    if (sock_dec && *sock_dec) {
#ifdef CURLOPT_UNIX_SOCKET_PATH
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, sock_dec);
#endif
    }
    if (sock_dec) curl_free(sock_dec);

    const char *http_path = colon + 1; /* includes leading '/' */
    const char *host = is_https ? "https://localhost" : "http://localhost";
    return pstrcat(p, host, http_path, NULL);
}

/* Build URL by appending "/<username>" (URL-escaped) to a base that may be http(s) or *+unix */
static char *build_url_with_username(pool *p, CURL *curl, const char *base, const char *user) {
    char *resolved = prepare_url_for_curl(p, curl, base);
    char *encu = curl_easy_escape(curl, user, 0);
    int need_slash = resolved[strlen(resolved) - 1] != '/';
    char *full = pstrcat(p, resolved, need_slash ? "/" : "", encu ? encu : user, NULL);
    if (encu) curl_free(encu);
    return full;
}

/* Resolve a base URL (no username suffix) with unix-aware logic */
static char *resolve_base_url(pool *p, CURL *curl, const char *base) {
    return prepare_url_for_curl(p, curl, base);
}

/* -------- libcurl helpers -------- */

static CURL *curl_new(void) {
    CURL *h = curl_easy_init();
    if (!h) return NULL;

    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, connect_timeout_ms);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, total_timeout_ms);
    curl_easy_setopt(h, CURLOPT_USERAGENT, MOD_AUTH_REST_VERSION);
    curl_easy_setopt(h, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS); /* fallback ok */

    return h;
}

static struct curl_slist *apply_common_headers(struct curl_slist *headers, pool *p) {
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
 * OpenAPI: GET /api/authz/users/{username} -> 204 + headers
 */
MODRET handle_auth_rest_getpwnam(cmd_rec *cmd) {
    const char *username = cmd->argv[0];

    if (!lookup_url || !api_key || !bearer_token) return PR_DECLINED(cmd);
    if (user_creg && pr_regexp_exec(user_creg, username, 0, NULL, 0, 0, 0) != 0)
        return PR_DECLINED(cmd);

    CURL *curl = curl_new();
    if (!curl) return PR_DECLINED(cmd);

    char *url = build_url_with_username(cmd->tmp_pool, curl, lookup_url, username); /* /api/authz/users/{username} */
    curl_easy_setopt(curl, CURLOPT_URL, url);

    rest_attrs attrs = (rest_attrs){0};
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &attrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);

    struct curl_slist *hdrs = NULL;
    hdrs = apply_common_headers(hdrs, cmd->tmp_pool);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(curl);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_REST_VERSION ": CURL error: %s", curl_easy_strerror(rc));
        return PR_DECLINED(cmd);
    }

    if (http == 404) {
        /* Not found or disabled → let other backends try */
        return PR_DECLINED(cmd);
    }
    if (http == 401) {
        /* API client not authenticated → decline, do not leak */
        return PR_DECLINED(cmd);
    }
    if (http != 204) {
        /* Per spec, success is 204 only */
        return PR_DECLINED(cmd);
    }

    if (!attrs.uid || !attrs.gid || !attrs.home) {
        return PR_DECLINED(cmd);
    }

    struct passwd *pw = pcalloc(session.pool, sizeof(struct passwd));
    if (!pw) return PR_DECLINED(cmd);

    pw->pw_name = pstrdup(session.pool, username);
    pw->pw_passwd = pstrdup(session.pool, "x");

    char *end = NULL;
    long uid = strtol(attrs.uid, &end, 10);
    long gid = strtol(attrs.gid, NULL, 10);
    pw->pw_uid = (uid_t) uid;
    pw->pw_gid = (gid_t) gid;

    pw->pw_dir = pstrdup(session.pool, attrs.home);
    pw->pw_shell = pstrdup(session.pool, "/sbin/nologin");
#ifdef HAVE_PW_GECOS
    pw->pw_gecos = pstrdup(session.pool, "");
#endif

    return mod_create_data(cmd, pw);
}

/* -------- auth handler (USER/PASS) --------
 * OpenAPI: POST /api/authz/{username} with body: password (required),
 * optional client_ip, server_ip, protocol. Expects 204 on success.
 */
MODRET handle_auth_rest_auth(cmd_rec *cmd) {
    const char *username = cmd->argv[0];
    const char *password = cmd->argv[1];

    if (!auth_url || !api_key || !bearer_token) return PR_DECLINED(cmd);
    if (user_creg && pr_regexp_exec(user_creg, username, 0, NULL, 0, 0, 0) != 0)
        return PR_DECLINED(cmd);

    CURL *curl = curl_new();
    if (!curl) return PR_DECLINED(cmd);

    /* Build /api/authz/{username} */
    char *url = build_url_with_username(cmd->tmp_pool, curl, auth_url, username);
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
    /* Protocol is optional; you can set to "ftp" or detect TLS to send "ftps" if desired */
    /* pairs[n++] = form_pair(cmd->tmp_pool, curl, "protocol", "ftp"); */

    char *post = join_pairs(cmd->tmp_pool, pairs, n);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);

    rest_attrs attrs = (rest_attrs){0};
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, on_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &attrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, on_body);

    struct curl_slist *hdrs = NULL;
    hdrs = apply_common_headers(hdrs, cmd->tmp_pool);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    CURLcode rc = curl_easy_perform(curl);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        pr_log_pri(PR_LOG_ERR, MOD_AUTH_REST_VERSION ": CURL error: %s", curl_easy_strerror(rc));
        return PR_DECLINED(cmd);
    }

    /* Spec mapping */
    if (http == 401) {
        pr_log_pri(
            PR_LOG_ERR,
            MOD_AUTH_REST_VERSION
            ": backend returned 401 (API client unauthorized) — check AuthRestAPIKey/AuthRestBearerToken");
        return PR_DECLINED(cmd);
    }
    if (http == 403) {
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    if (http == 423) {
        pr_log_pri(PR_LOG_NOTICE, MOD_AUTH_REST_VERSION ": user '%s' disabled/locked (423)", username);
        return PR_ERROR_INT(cmd, PR_AUTH_BADPWD);
    }
    if (http != 204) {
        /* Per spec, success is 204 only; any other code → let other backends try */
        return PR_DECLINED(cmd);
    }

    session.auth_mech = "mod_auth_rest.c";
    return PR_HANDLED(cmd);
}

/* -------- Config directives -------- */

MODRET set_auth_url(cmd_rec *cmd) {
    CHECK_ARGS(cmd, 1);
    CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);
    add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
    return PR_HANDLED(cmd);
}

MODRET set_lookup_url(cmd_rec *cmd) {
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

static int auth_rest_getconf(void) {
    char *ct = NULL, *tt = NULL;

    auth_url = (char *) get_param_ptr(main_server->conf, "AuthRestAuthURL", FALSE); /* e.g. "/api/authz" */
    lookup_url = (char *) get_param_ptr(main_server->conf, "AuthRestLookupURL", FALSE); /* e.g. "/api/authz/users" */
    api_key = (char *) get_param_ptr(main_server->conf, "AuthRestAPIKey", FALSE);
    bearer_token = (char *) get_param_ptr(main_server->conf, "AuthRestBearerToken", FALSE);
    user_creg = (pr_regex_t *) get_param_ptr(main_server->conf, "AuthRestUserRegex", FALSE);

    ct = (char *) get_param_ptr(main_server->conf, "AuthRestConnectTimeoutMs", FALSE);
    tt = (char *) get_param_ptr(main_server->conf, "AuthRestTotalTimeoutMs", FALSE);
    if (ct) connect_timeout_ms = strtol(ct, NULL, 10);
    if (tt) total_timeout_ms = strtol(tt, NULL, 10);

    return 0;
}

static conftable auth_rest_conftab[] = {
    {"AuthRestAuthURL", set_auth_url, NULL}, /* base: /api/authz */
    {"AuthRestLookupURL", set_lookup_url, NULL}, /* base: /api/authz/users */
    {"AuthRestAPIKey", set_api_key, NULL},
    {"AuthRestBearerToken", set_bearer_token, NULL},
    {"AuthRestUserRegex", set_user_regex, NULL},
    {"AuthRestConnectTimeoutMs", set_connect_timeout_ms, NULL},
    {"AuthRestTotalTimeoutMs", set_total_timeout_ms, NULL},
    {NULL, NULL, NULL}
};

static authtable auth_rest_authtab[] = {
    {0, "getpwnam", handle_auth_rest_getpwnam},
    {0, "auth", handle_auth_rest_auth},
    {0, NULL}
};

module auth_rest_module = {
    NULL, NULL,
    0x20, /* Module API v2.0 */
    "auth_rest", /* Module name */
    auth_rest_conftab, /* Configuration handlers */
    NULL, /* Command handlers */
    auth_rest_authtab, /* Authentication handlers */
    NULL, /* Module init */
    auth_rest_getconf, /* Session init */
    MOD_AUTH_REST_VERSION /* Module version string */
};
