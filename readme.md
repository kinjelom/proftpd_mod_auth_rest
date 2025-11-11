# mod_auth_rest

REST-based authentication module for [ProFTPD](https://www.proftpd.org/).

This module authenticates FTP users against a remote **REST API** and fetches POSIX attributes (UID/GID/home). It’s
designed to be fast and simple: **no JSON parsing**—only HTTP status codes and a few headers.

## Features

* Authenticate users: `POST /api/authz/auth/{username}`
* Retrieve POSIX attributes: `GET /api/authz/lookup/{username}`
* **Header-only success path**: uses `x-fs-uid`, `x-fs-gid`, `x-fs-dir`, `x-fs-shell`, `x-fs-gecos`;
  ignores bodies
* **Low latency**: 1-RTT, no JSON decoding
* **UNIX domain sockets** or TCP:
    * `AuthRestConnectionType unix|tcp`
    * For `unix`, talks HTTP over a UNIX socket (`CURLOPT_UNIX_SOCKET_PATH`)
* Sends both `x-api-key` and `authorization: Bearer …`
* Optional username regex to scope which users this module handles
* Case-insensitive header handling

## Configuration

| Directive                    | Type         | Description                                                                                                                                                  | Default                        |
|------------------------------|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| **AuthRestConnectionType**   | string       | Connection mode: `unix` for UNIX domain socket, or `tcp` for HTTP/HTTPS network calls.                                                                       | *(required)*                   |
| **AuthRestBaseAddress**      | string       | Base address of the REST API.<br>For `unix`: path to socket file (e.g. `/var/run/fsaa.sock`).<br>For `tcp`: full base URL (e.g. `https://auth.example.com`). | *(required)*                   |
| **AuthRestGetpwnamPath**     | string       | Path for user lookup requests. Supports `{username}` placeholder. Combined with `AuthRestBaseAddress` to form the full lookup URL.                           | `/api/authz/lookup/{username}` |
| **AuthRestAuthPath**         | string       | Path for authentication requests. Supports `{username}` placeholder. Combined with `AuthRestBaseAddress` to form the full authentication URL.                | `/api/authz/auth/{username}`   |
| **AuthRestAPIKey**           | string       | Value sent in `X-Api-Key` header for API authentication.                                                                                                     | *(required)*                   |
| **AuthRestBearerToken**      | string       | Value sent in `Authorization: Bearer <token>` header for API authentication.                                                                                 | *(required)*                   |
| **AuthRestUsernameRegex**    | regex        | Regular expression limiting which usernames are handled by this module. Users not matching are ignored (other backends can try).                             | `.*` (all usernames)           |
| **AuthRestDefaultShell**     | string       | Default shell path used when the API response does not include the `x-fs-shell` header.                                                                      | `/sbin/nologin`                |
| **AuthRestConnectTimeoutMs** | integer (ms) | Timeout for establishing the connection to the REST API.                                                                                                     | `300`                          |
| **AuthRestTotalTimeoutMs**   | integer (ms) | Maximum total request duration (connect + transfer + response).                                                                                              | `1000`                         |
| **AuthRestLogFile**          | path\|none   | Path to the audit log file. Set to `none` to disable logging.                                                                                                | `none` (disabled)              |
| **AuthRestLogLevel**         | level        | Minimum log level: `emerg`, `alert`, `crit`, `error`, `warn`, `notice`, `info`, `debug`, or a numeric value (0-7).                                           | `info`                         |
| **AuthRestLogFormat**        | text\|json   | Log output format: `text` for human-readable logs, or `json` for structured JSON Lines logs (NDJSON each line represents a valid JSON object).               | `json`                         |

**Notes**

* **UNIX sockets**: when `AuthRestConnectionType unix`, the module sets `CURLOPT_UNIX_SOCKET_PATH` to `AuthRestBaseAddress` and calls `http://localhost` over that socket.
* **Case-insensitive headers**: HTTP headers are matched case-insensitively; lowercase in docs is for readability.
* **Security**: treat `AuthRestAPIKey` and `AuthRestBearerToken` as secrets; prefer config management/templating instead of hard-coding.
* **Logging**: Logs authentication events (getpwnam, auth) with HTTP status codes and CURL error codes. No sensitive
  data (passwords, tokens) is logged.

### Example

```shell
<IfModule mod_auth_rest.c>
  AuthOrder                  mod_auth_rest.c

  AuthRestLogFile            /var/log/proftpd/auth_rest.log # if not set there is no logging 
  AuthRestLogFormat          text # default text, or json

  # Connection
  AuthRestConnectionType     unix # or: tcp
  AuthRestBaseAddress        /var/run/fsaa.sock # for unix, for tcp: https://auth.example.com  

  # API paths (supports {username}; if omitted, username is appended)
  AuthRestGetpwnamPath       "/api/authz/lookup/{username}"
  AuthRestAuthPath           "/api/authz/auth/{username}"

  # Auth headers sent to the backend
  AuthRestAPIKey             "default"
  AuthRestBearerToken        "opaque-token"

  # Optional
  AuthRestUsernameRegex      "^[a-z0-9._-]{1,64}$"   # default: accept all
  AuthRestDefaultShell      "/sbin/nologin"
  AuthRestConnectTimeoutMs   1000   # default: 300
  AuthRestTotalTimeoutMs     3000   # default: 1000
  
  # Logging
  AuthRestLogFile            /var/log/proftpd/mod_auth_rest.jsonl
  AuthRestLogLevel           info
  AuthRestLogFormat          json
</IfModule>
```

## OpenAPI — “header-only, 1-RTT” design

Full contract: [`openapi.yaml`](openapi.yaml)

**Why headers?** Parsing JSON in a C module adds deps and CPU overhead. Returning small bits of data in headers keeps
the module lean.

### Quick reference

**Getpwnam POSIX attributes**

```
GET /api/authz/lookup/{username}
Request:
  Headers:
    x-api-key
    authorization: Bearer <token>

Response:
  204 No Content
  Headers:
    x-fs-uid: <uint>
    x-fs-gid: <uint>
    x-fs-dir: <path>
    x-fs-shell: <string> # default AuthRestDefaultShell
    x-fs-gecos: <string> # default ""
```

**Authenticate user**

```
POST /api/authz/auth/{username}
Request:
  Headers:
    x-api-key
    authorization: Bearer <token>
  Body (application/x-www-form-urlencoded):
    password   (required)
    client_ip  (optional)
    server_ip  (optional)
    protocol   (optional; e.g. "ftp")

Response:
  204 No Content
```

**Status mapping**

| HTTP Status | Meaning                         | FTP Result                        |
|-------------|---------------------------------|-----------------------------------|
| 204         | Authenticated and enabled       | Success                           |
| 400         | Bad request                     | Declined (other backends may try) |
| 401         | API client not authenticated    | Declined (other backends may try) |
| 403         | User authentication failed      | Authentication failure            |
| 404         | User not found / not applicable | Declined (other backends may try) |
| 423         | Account disabled/locked         | Authentication failure            |
| 5xx         | Backend/server error            | Declined (other backends may try) |

## Tests

```bash
make test
```

## Build & Install

`mod_auth_rest` is a **shared ProFTPD module**. You can build it either inside the ProFTPD source tree (
`--with-shared=mod_auth_rest`) or via the ProFTPD helper `prxs`.

### Prerequisites

* ProFTPD source (or headers) matching the target ProFTPD version
* Development tools and libraries:

    * C toolchain (`gcc`, `make`)
    * `libcurl` (with UNIX socket support), e.g. `libcurl4-openssl-dev`
    * OpenSSL dev headers (for TLS in ProFTPD), e.g. `libssl-dev`

> Debian/Ubuntu example:
> `sudo apt-get install build-essential libssl-dev libcurl4-openssl-dev`

### Option A — Build inside the ProFTPD source tree (recommended)

1. Get ProFTPD sources and enter the tree:

    ```bash
    tar xf proftpd-<VERSION>.tar.gz
    cd proftpd-<VERSION>
    ```

2. Place the module under `contrib/mod_auth_rest`:

    ```bash
    mkdir -p contrib/mod_auth_rest
    cp /path/to/mod_auth_rest.c contrib/mod_auth_rest/
    ```

3. Configure ProFTPD with DSO and mark this module as shared:

    ```bash
    ./configure \
      --enable-dso \
      --enable-openssl \
      --with-shared=mod_auth_rest
    ```

4. Build and install:

    ```bash
    make -j"$(nproc)"
    sudo make install
    ```

After installation, the module is typically at (path may vary by prefix/distro):

```
/usr/local/libexec/proftpd/mod_auth_rest.so
```

Enable it in `proftpd.conf`:

```apache
LoadModule mod_auth_rest.c
```

Restart ProFTPD.

---

### Option B — Build via `prxs` (fast for development)

If `prxs` is installed (ships with ProFTPD build tools):

```bash
prxs -c -i mod_auth_rest.c
```

This compiles and installs `mod_auth_rest.so` into your ProFTPD modules directory.
Then enable it:

```apache
LoadModule mod_auth_rest.c
```

Restart ProFTPD.

### Notes

* If your ProFTPD was installed from distro packages, ensure you have matching **-dev** headers or build against the
  same versioned sources.
* For UNIX domain socket support, your `libcurl` must be built with UDS enabled (most modern distros are fine).
