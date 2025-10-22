#ifndef AUTHREST_CONN_MODE_H
#define AUTHREST_CONN_MODE_H

#include <strings.h> /* strcasecmp */
#include <string.h>
#include <stdlib.h>

/* Pure helpers to determine connection mode from a configuration string. */
static int authrest_is_unix_conn_str(const char *connection_type) {
  return connection_type && strcasecmp(connection_type, "unix") == 0;
}

static int authrest_is_tcp_conn_str(const char *connection_type) {
  return connection_type && strcasecmp(connection_type, "tcp") == 0;
}

/* Join base and path with exactly one slash between */
static char *authrest_join_base_and_path(const char *base, const char *path) {
  if (!base || !*base) return strdup(path ? path : "");
  if (!path || !*path) return strdup(base);
  const size_t bl = strlen(base);
  const size_t pl = strlen(path);
  const int base_ends = base[bl - 1] == '/';
  const int path_starts = path[0] == '/';
  char *out;
  if (base_ends && path_starts) {
    out = (char *) malloc(bl + pl); /* drop one slash */
    memcpy(out, base, bl - 1);
    memcpy(out + bl - 1, path, pl + 1);
    return out;
  }
  if (!base_ends && !path_starts) {
    out = (char *) malloc(bl + 1 + pl + 1);
    memcpy(out, base, bl);
    out[bl] = '/';
    memcpy(out + bl + 1, path, pl + 1);
    return out;
  }
  out = (char *) malloc(bl + pl + 1);
  memcpy(out, base, bl);
  memcpy(out + bl, path, pl + 1);
  return out;
}

/* Replace the first occurrence of {username} with username; if not present, append "/username" */
static char *authrest_subst_username(const char *tpl, const char *username) {
  if (!tpl) return strdup("/");
  const char *needle = "{username}";
  const char *m = strstr(tpl, needle);
  if (m) {
    const size_t pre = (size_t) (m - tpl);
    const size_t suf = strlen(needle);
    const size_t post = strlen(tpl) - pre - suf;
    const size_t ul = strlen(username);
    char *out = malloc(pre + ul + post + 1);
    memcpy(out, tpl, pre);
    memcpy(out + pre, username, ul);
    memcpy(out + pre + ul, m + suf, post + 1);
    return out;
  }
  /* ensure single slash before appending username */
  const size_t tl = strlen(tpl);
  const int ends = tl > 0 && tpl[tl - 1] == '/';
  char *out = malloc(tl + (ends ? 0 : 1) + strlen(username) + 1);
  memcpy(out, tpl, tl);
  size_t pos = tl;
  if (!ends) out[pos++] = '/';
  strcpy(out + pos, username);
  return out;
}

/* Build effective URL and return whether a UNIX socket is used via out_is_unix (0/1).
   This is a pure/test helper mirroring the module logic without curl/proftpd deps. */
static char *authrest_build_effective_url_static(
    const char *connection_type,
    const char *base_address,
    const char *path_tpl,
    const char *username,
    int *out_is_unix) {
  char *path = authrest_subst_username(path_tpl, username ? username : "");
  if (authrest_is_unix_conn_str(connection_type)) {
    if (out_is_unix) *out_is_unix = 1;
    char *url = authrest_join_base_and_path("http://localhost", path);
    free(path);
    return url;
  }
  if (out_is_unix) *out_is_unix = 0;
  const char *base = base_address && *base_address ? base_address : "http://localhost";
  const int has_scheme = strstr(base, "://") != NULL;
  char *origin;
  if (!has_scheme) {
    const char *host = base_address && *base_address ? base_address : "localhost";
    origin = (char *) malloc(strlen("http://") + strlen(host) + 1);
    strcpy(origin, "http://");
    strcat(origin, host);
  } else {
    origin = strdup(base);
  }
  char *url = authrest_join_base_and_path(origin, path);
  free(origin);
  free(path);
  return url;
}

#endif /* AUTHREST_CONN_MODE_H */
