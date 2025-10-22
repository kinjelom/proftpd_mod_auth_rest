# mod_auth_rest

REST-based authentication module for [ProFTPD](https://www.proftpd.org/).

This module authenticates FTP users via a remote **REST API**,
allowing centralized user management for FTP and other POSIX-style services.

## Features

- Authenticates users by calling a REST API (`POST /api/authz/auth/{username}`)
- Retrieves POSIX attributes (`GET /api/authz/lookup/{username}`)
- Supports **UNIX domain sockets** via URL schemes (`http+unix://%2Fpath%2Fto.sock:/api/authz`)
- Sends both `x-api-key` and `authorization: Bearer` headers
- Works over HTTP/HTTPS or sockets
- A minimal and fast — ignores response bodies, uses only headers
- Optional regex to limit handled usernames

## Example Configuration

```shell
<IfModule mod_auth_rest.c>
  AuthOrder                  mod_auth_rest.c

  # UNIX socket example
  AuthRestLookupURL          "http+unix://%2Ftmp%2Ffs-auth.sock:/api/authz/lookup"
  AuthRestAuthURL            "http+unix://%2Ftmp%2Ffs-auth.sock:/api/authz/auth"

  # TCP example
  # AuthRestLookupURL        "https://auth.example.com/api/authz/lookup"
  # AuthRestAuthURL          "https://auth.example.com/api/authz/auth"

  AuthRestAPIKey             "default"
  AuthRestBearerToken        "opaque-token"

  # Optional
  # AuthRestUserRegex        "^[a-z0-9._-]{1,64}$"
  # AuthRestConnectTimeoutMs 300
  # AuthRestTotalTimeoutMs   1000
</IfModule>
```



## OpenAPI - "header-only, 1-RTT" design

The full API contract: [openapi.yaml](openapi.yaml)

Parsing JSON inside a C module adds dependencies and CPU overhead.  
Instead, this design returns user metadata in **HTTP headers**, allowing the module to skip JSON parsing, read a few headers, and proceed immediately.  
Failure cases are indicated purely by **HTTP status codes**.

This API is optimized for **low latency**:
- Single round-trip (1-RTT)
- No body parsing on the success path
- Simple integration from any language or platform


### OpenAPI Quick Reference

**Lookup user POSIX attributes**
```yaml
GET /api/authz/lookup/{username}:
  Request:
    Headers: x-api-key, authorization
  Response:
    204 with headers:
      x-fs-uid
      x-fs-gid
      x-fs-home
````

**Authenticate user** 
```yaml
POST /api/authz/auth/{username}:
  Request:
    Headers: x-api-key, authorization
    Body: application/x-www-form-urlencoded with password, client_ip, server_ip and protocol
  Response:
    204 with headers:
      x-fs-uid
      x-fs-gid
      x-fs-home
```


**Expected codes**

| HTTP Status | Meaning                      | FTP Result                       |
|-------------|------------------------------|----------------------------------|
| 204         | Authenticated and enabled    | Success                          |
| 400         | API client bad request       | Declined - allows other backends |
| 401         | API client not authenticated | Declined - allows other backends |
| 403         | User authentication failed   | Authentication failure           |
| 423         | User account disabled/locked | Authentication failure           |
| 500         | Internal server error        | Declined - allows other backends |


## Build & Install

```bash
apxs -c mod_auth_rest.c -o mod_auth_rest.so
cp .libs/mod_auth_rest.so /usr/lib/proftpd/
```

Then load it in `proftpd.conf`:

```apache
LoadModule mod_auth_rest.c
```

Restart ProFTPD.
