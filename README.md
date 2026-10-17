# Dufs

[![CI](https://github.com/sigoden/dufs/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigoden/dufs/actions/workflows/ci.yaml)
[![Crates](https://img.shields.io/crates/v/dufs.svg)](https://crates.io/crates/dufs)
[![Docker Pulls](https://img.shields.io/docker/pulls/sigoden/dufs)](https://hub.docker.com/r/sigoden/dufs)

Dufs is a distinctive utility file server that supports static serving, uploading, searching, accessing control, webdav...

![demo](https://user-images.githubusercontent.com/4012553/220513063-ff0f186b-ac54-4682-9af4-47a9781dee0d.png)

## Features

- Serve static files
- Download folder as zip file
- Upload files and folders (Drag & Drop)
- Create/Edit/Search files
- Resumable/partial uploads/downloads
- Access control
- Support https
- Support webdav
- Easy to use with curl

## Install

### With cargo

```
cargo install dufs
```

### With docker

```
docker run -v `pwd`:/data -p 5000:5000 --rm sigoden/dufs /data -A
```

### With [Homebrew](https://brew.sh)

```
brew install dufs
```

### Binaries on macOS, Linux, Windows

Download from [Github Releases](https://github.com/sigoden/dufs/releases), unzip and add dufs to your $PATH.

## CLI

```
Dufs is a distinctive utility file server - https://github.com/sigoden/dufs

Usage: dufs [OPTIONS] [serve-path]

Arguments:
  [serve-path]  Specific path to serve [default: .]

Options:
  -c, --config <file>        Specify configuration file
  -b, --bind <addrs>         Specify bind address or unix socket
  -p, --port <port>          Specify port to listen on [default: 5000]
      --path-prefix <path>   Specify a path prefix
      --hidden <value>       Hide paths from directory listings, e.g. tmp,*.log,*.lock
  -a, --auth <rules>         Add auth roles, e.g. user:pass@/dir1:rw,/dir2
      --auth-type <type>     Select the authentication adapter [default: builtin] [possible values: builtin, oidc]
      --ip-whitelist <rules> Set ip whitelist for paths, e.g. 127.0.0.1,10.0.0.0/8@/dir1
      --trusted-proxy <addrs> Trust forwarded headers from these proxy addresses (comma or space separated ip/cidr list), e.g. 127.0.0.1,10.0.0.0/8
  -A, --allow-all            Allow all operations
      --allow-upload         Allow upload files/folders
      --allow-delete         Allow delete files/folders
      --allow-search         Allow search files/folders
      --allow-symlink        Allow symlink to files/folders outside root directory
      --allow-archive        Allow download folders as archive file
      --allow-hash           Allow ?hash query to get file sha256 hash
      --allow-ip-whitelist   Allow managing the per-path acl from the WebUI; requires the x permission
      --enable-cors          Enable CORS, sets `Access-Control-Allow-Origin: *`
      --render-index         Serve index.html when requesting a directory, returns 404 if not found index.html
      --render-try-index     Serve index.html when requesting a directory, returns directory listing if not found index.html
      --render-spa           Serve SPA(Single Page Application)
      --assets <path>        Set the path to the assets directory for overriding the built-in assets
      --log-format <format>  Customize http log format
      --log-file <file>      Specify the file to save logs to, other than stdout/stderr
      --compress <level>     Set zip compress level [default: low] [possible values: none, low, medium, high]
      --completions <shell>  Print shell completion script for <shell> [possible values: bash, elvish, fish, powershell, zsh]
      --tls-cert <path>      Path to an SSL/TLS certificate to serve with HTTPS
      --tls-key <path>       Path to the SSL/TLS certificate's private key
  -h, --help                 Print help
  -V, --version              Print version
```

## Examples

Serve current working directory in read-only mode

```
dufs
```

Allow all operations like upload/delete/search/create/edit...

```
dufs -A
```

Only allow upload operation

```
dufs --allow-upload
```

Serve a specific directory

```
dufs Downloads
```

Serve a single file

```
dufs linux-distro.iso
```

Serve a single-page application like react/vue

```
dufs --render-spa
```

Serve a static website with index.html

```
dufs --render-index
```

Require username/password

```
dufs -a admin:123@/:rw
```

Listen on specific host:ip 

```
dufs -b 127.0.0.1 -p 80
```

Listen on unix socket
```
dufs -b /tmp/dufs.socket
```

Use https

```
dufs --tls-cert my.crt --tls-key my.key
```

## API

Upload a file

```sh
curl -T path-to-file http://127.0.0.1:5000/new-path/path-to-file
```

Download a file
```sh
curl http://127.0.0.1:5000/path-to-file           # download the file
curl http://127.0.0.1:5000/path-to-file?hash      # retrieve the sha256 hash of the file
```

Download a folder as zip file

```sh
curl -o path-to-folder.zip http://127.0.0.1:5000/path-to-folder?zip
```

Delete a file/folder

```sh
curl -X DELETE http://127.0.0.1:5000/path-to-file-or-folder
```

Create a directory

```sh
curl -X MKCOL http://127.0.0.1:5000/path-to-folder
```

Move the file/folder to the new path

```sh
curl -X MOVE http://127.0.0.1:5000/path -H "Destination: http://127.0.0.1:5000/new-path"
```

List/search directory contents

```sh
curl http://127.0.0.1:5000?q=Dockerfile           # search for files, similar to `find -name Dockerfile`
curl http://127.0.0.1:5000?simple                 # output names only, similar to `ls -1`
curl http://127.0.0.1:5000?json                   # output paths in json format
```

With authorization (Both basic or digest auth works)

```sh
curl http://127.0.0.1:5000/file --user user:pass                 # basic auth
curl http://127.0.0.1:5000/file --user user:pass --digest        # digest auth
```

Resumable downloads

```sh
curl -C- -o file http://127.0.0.1:5000/file
```

Resumable uploads

```sh
upload_offset=$(curl -I -s http://127.0.0.1:5000/file | tr -d '\r' | sed -n 's/content-length: //p')
dd skip=$upload_offset if=file status=none ibs=1 | \
  curl -X PATCH -H "X-Update-Range: append" --data-binary @- http://127.0.0.1:5000/file
```

Health checks

```sh
curl http://127.0.0.1:5000/__dufs__/health
```

<details>
<summary><h2>Advanced Topics</h2></summary>

### Access Control

Dufs supports account based access control. You can control who can do what on which path with `--auth`/`-a`.

```
dufs -a admin:admin@/:rw -a guest:guest@/
dufs -a user:pass@/:rw,/dir1 -a @/
```

1. Use `@` to separate the account and paths. No account means anonymous user.
2. Use `:` to separate the username and password of the account.
3. Use `,` to separate paths.
4. Use path suffix `:rw`/`:ro` set permissions: `read-write`/`read-only`. `:ro` can be omitted.
5. Add `x` to the suffix (`:rwx`, `:rx`, `:x`) to let the user edit the acl of that path.

- `-a admin:admin@/:rw`: `admin` has complete permissions for all paths.
- `-a admin:admin@/:rwx`: `admin` can also edit the acl for every path.
- `-a guest:guest@/`: `guest` has read-only permissions for all paths.
- `-a user:pass@/:rw,/dir1`: `user` has read-write permissions for `/*`, has read-only permissions for `/dir1/*`.
- `-a @/`: All paths is publicly accessible, everyone can view/download it.

A request without credentials is treated as the `guest` identity: if `--auth` defines a `guest` account its permissions apply, otherwise the anonymous `@/` rule is used. The **Login** button in the top-right navigates to `?login`, which starts the configured authentication — the browser's Basic/Digest prompt for `builtin`, or a redirect to the provider for `oidc`.

**Auth permissions are restricted by dufs global permissions.** If dufs does not enable upload permissions via `--allow-upload`, then the account will not have upload permissions even if it is granted `read-write`(`:rw`) permissions.

#### Hashed Password

DUFS supports the use of sha-512 hashed password.

Create hashed password:

```sh
$ openssl passwd -6 123456 # or `mkpasswd -m sha-512 123456`
$6$tWMB51u6Kb2ui3wd$5gVHP92V9kZcMwQeKTjyTRgySsYJu471Jb1I6iHQ8iZ6s07GgCIO69KcPBRuwPE5tDq05xMAzye0NxVKuJdYs/
```

Use hashed password:

```sh
dufs -a 'admin:$6$tWMB51u6Kb2ui3wd$5gVHP92V9kZcMwQeKTjyTRgySsYJu471Jb1I6iHQ8iZ6s07GgCIO69KcPBRuwPE5tDq05xMAzye0NxVKuJdYs/@/:rw'
```
> The hashed password contains `$6`, which can expand to a variable in some shells, so you have to use **single quotes** to wrap it.

Two important things for hashed passwords:

1. Dufs only supports sha-512 hashed passwords, so ensure that the password string always starts with `$6$`.
2. Digest authentication does not function properly with hashed passwords.


### OIDC Authentication

Dufs can delegate authentication to an OpenID Connect provider. Select the adapter with `--auth-type oidc` (or `DUFS_AUTH_TYPE=oidc`); `builtin` keeps the default username/password behaviour. The OIDC client is configured through environment variables:

| variable | required | description |
| --- | --- | --- |
| `DUFS_OIDC_ISSUER` | yes | Issuer URL, used for OpenID Connect discovery |
| `DUFS_OIDC_CLIENT_ID` | yes | Client id registered with the provider |
| `DUFS_OIDC_CLIENT_SECRET` | no | Client secret; omit for a public client using PKCE |
| `DUFS_OIDC_REDIRECT_URI` | yes | Public callback URL, e.g. `https://files.example.com/__dufs__/oidc/callback` (include any path prefix) |
| `DUFS_OIDC_POST_LOGOUT_REDIRECT_URI` | no | Post-logout URL; defaults to `DUFS_OIDC_REDIRECT_URI` minus `__dufs__/oidc/callback` |
| `DUFS_OIDC_SCOPES` | no | Space separated scopes [default: `openid profile email`] |
| `DUFS_OIDC_USERNAME_CLAIM` | no | Claim used as the username [default: `preferred_username`] |
| `DUFS_OIDC_SESSION_HOURS` | no | Session lifetime in hours [default: 168] |

`DUFS_AUTH` still defines the permissions, keyed by the username returned by the provider. The password part of each rule is not used, so it can be any placeholder:

```sh
export DUFS_AUTH_TYPE=oidc
export DUFS_AUTH='guest:unused@/:ro|alice:unused@/:rw|bob:unused@/public'
export DUFS_OIDC_ISSUER=https://sso.example.com
export DUFS_OIDC_CLIENT_ID=dufs
export DUFS_OIDC_CLIENT_SECRET=change-me
export DUFS_OIDC_REDIRECT_URI=https://files.example.com/__dufs__/oidc/callback
dufs
```

The identity is the `preferred_username` claim by default — not `name` or `nickname`. Set `DUFS_OIDC_USERNAME_CLAIM` if your provider exposes the login name under another claim (for example `username` or `email`). A user who authenticates successfully but is absent from `DUFS_AUTH` gets no access. Anonymous access (`@/`) still applies if configured.

Without a session the visitor is the `guest` identity. If `guest` (or an anonymous `@/` rule) is configured the page loads and the top-right **Login** button redirects to the provider; otherwise requests are redirected automatically. Configure a guest if you want the page to be visible without starting authentication. After the callback a session cookie is set and the original path is restored. Sessions live in memory, so restarting dufs signs everyone out. The callback endpoint is `__dufs__/oidc/callback` under the configured path prefix. Logging out clears the local session and redirects to the provider's `end_session_endpoint` with the `id_token_hint`, so the provider SSO session ends too; register the dufs root as a **Valid post logout redirect URI** in the provider. The post-logout URL defaults to `DUFS_OIDC_REDIRECT_URI` minus `__dufs__/oidc/callback` and can be overridden with `DUFS_OIDC_POST_LOGOUT_REDIRECT_URI`.

### Path ACL

Dufs can restrict a file or a directory to a list of client addresses with `--ip-whitelist`.

```sh
dufs --ip-whitelist '127.0.0.1,192.168.0.0/16@/public'
dufs --ip-whitelist '127.0.0.1@/dir1' --ip-whitelist '10.0.0.0/8@/dir1/file.txt'
dufs --ip-whitelist '127.0.0.1@/dir1|10.0.0.0/8@/dir2'
```

1. Use `@` to separate the address list and the path, e.g. `ips@/path`.
2. Use `,` to separate addresses. Each entry is an IP or a CIDR range.
3. Use `|` to separate rules, or repeat `--ip-whitelist`.
4. An empty address list (`@/dir1`) denies the path to everyone.
5. A missing `@` applies the address list to the served root.
6. A path with no rule of its own inherits the closest configured ancestor, and a rule set on a file overrides the rule set on its directory.
7. Paths with no configured ancestor are unrestricted.

```sh
# localhost only; nobody may read .git
dufs --ip-whitelist '127.0.0.1@/' --ip-whitelist '@/.git'
```

The whitelist also applies to directory listings, search results, WebDAV `PROPFIND` and folder archives, so a denied entry is not leaked through them. When the client address is unknown, e.g. over a unix socket, a configured address list denies access.

In the configuration file the same value can also be written as a mapping from path to an address list.

```yaml
ip-whitelist:
  /dir1: 127.0.0.1
  /dir2:
    - 10.0.0.0/8
    - 192.168.0.0/16
```

#### User read/write rules

Besides client addresses, a path can carry per-user read/write rules. They are edited from the same shield dialog and stored next to the ip whitelist.

- **Allow read**: the entry appears in the user's listings and can be read. The ip whitelist still applies.
- **Allow write**: the user can write the file/directory (for a directory: upload into it). Write implies read, and new files inherit the directory's rule.
- **Deny read**: the user cannot read or write the path, even when an ancestor allows it.

The acl is evaluated per user: the nearest ancestor rule that mentions the user wins, so a child rule only needs to list the users it changes. A path inside a managed subtree that never mentions the user defaults to deny; a path with no rule at all falls back to `--auth`. When the lists conflict, deny beats write and write beats read. A user listed in `allow_read`/`allow_write` gets access even when `--auth` does not grant it, and `deny_read` wins over an `--auth` grant. The `guest` identity may be listed as a normal username to control unauthenticated visitors.

The ancestors of a granted path stay reachable: when a rule below a directory grants the user access but no rule grants the directory itself, the directory becomes *traversable*. It is listed on the way down and can be opened, but it only lists its granted entries, it is read-only (no upload, rename or delete), and it is never granted on a file. An explicit `deny_read` on an ancestor does not hide a grant below it, since the grant could not be reached otherwise. With `--render-index` / `--render-try-index`, a traversable directory whose `index.html` is not readable shows that filtered listing instead of returning `403`.

The rules follow a rename: a `MOVE` carries the rules of the moved path and of every path below it to the new location, for both the acl and the ip whitelist. Without that, a rename would drop a `deny_read` inside the moved directory and the content would silently inherit the destination's rule instead (exposing a path the user was denied). Moving onto a path that already carries rules of its own is refused with `409 Conflict` rather than merging two rule sets. Deleting a path drops the rules that describe it and its descendants, so an entry created at the same path later starts from the inherited rule instead of a stale one. `COPY` creates a new entry and therefore only inherits the destination's rules.

Editing the acl requires the `x` permission for the target path (and `--allow-ip-whitelist`):

```sh
dufs -a admin:pass@/:rwx -a alice:pass@/:ro --allow-ip-whitelist
```

`x` users always win over the acl (they cannot be denied), but they are still limited by the ip whitelist. The backend rejects a save where the same user is both allowed and denied, where an `x` user is denied, or where the version is stale; `allow_write` users are added to `allow_read` automatically.

#### Managing from the WebUI

Start dufs with `--allow-ip-whitelist` (or `-A`) and grant a user the `x` permission; a shield button appears in the WebUI toolbar and on every row. It opens an editor with three tabs (`Read` / `Write` / `Deny Read`) plus the ip list; each tab is a tag editor: own entries are removable tags, inherited entries are dark locked tags without a remove button and are always shown first, and typing a username and pressing Tab adds a tag. Only entries configured on the target path are stored: entries inherited from the nearest ancestor are computed live and are never written into the file. Adding the same user to another list (for example deny) overrides the inherited entry for that user only. Saving shows a diff of the effective before/after permission of the changed users. Only a user with `x` for the target path may save it.

The list gets a `Whitelist` column: an empty list renders as `blocked` (nobody may access the path), a list containing `0.0.0.0/0` (or `::/0`) renders as blank (everyone may access it), and any other list shows its members. The editor pre-fills the whitelist that currently applies, so a path with no rule of its own shows `0.0.0.0/0` (everyone) and an empty input always means `blocked`. `Remove rule` drops the path's own rule so it inherits its closest configured parent again. Saving shows a diff of the affected users (before/after, the change types, and the acl rule chain) and asks for confirmation; a stale acl version is rejected with a conflict. The list also shows `Read` / `Write` columns: `alice` is a full grant, `(peter)` means a descendant denies the user, `[tom]` is an allow that only exists on a descendant, and `alice*` marks an `x` user; `guest` is shown as-is and full-write users (including `x` users) are omitted from the read column. The `Read` / `Write` columns are only shown to users with `x`, and a column without any entries is dropped. Long cells are truncated with `...` and open a full-list dialog; the dialog has a filter box, pressing Enter filters by the keyword (shown in the title), and pressing Enter on an empty box clears the filter. The summary is computed on demand from the in-memory rules (no separate index file); clicking a username does not open a per-user diff editor yet. The top-right Login button forces a fresh challenge even when the browser still holds guest credentials; after a successful login the `?login` marker is dropped and the page reloads without it. Only this button challenges: ordinary page and asset requests (including the plain `/favicon.ico`) never trigger a browser auth prompt. The management API accepts both Basic and Digest auth for reads and writes. The ip whitelist is the highest layer: a path the client address may not access is hidden even from an `x` user, while the management API itself stays available for fixing other paths. An `x` user still sees acl-denied entries in listings, search results and archives so they can manage them; for other callers, search results and archives only contain entries they may read, and the metadata dir is always excluded.

Rules are stored in `<serve-path>/.dufs/ip-whitelist.json` and `<serve-path>/.dufs/user-acl.json`. The `.dufs` directory holds dufs metadata: it is never listed, downloaded, searched, archived or served, and it cannot be written to over HTTP.

```sh
dufs --allow-ip-whitelist
```

The stored file is authoritative. When management is enabled and no store exists yet, the `--ip-whitelist` rules seed it; a CLI-only run keeps those rules in memory instead. Delete `.dufs/ip-whitelist.json` to start over.

#### Behind a reverse proxy

By default the client address is the TCP peer. Behind a reverse proxy that peer is the proxy itself, so a whitelist of real client addresses would deny everyone. List the proxy addresses with `--trusted-proxy` and dufs then takes the client address from `X-Forwarded-For`, falling back to `X-Real-IP`, **only when the connection comes from one of them**.

Each entry is either a plain address or a CIDR range, and entries can be separated by commas, by spaces, or by repeating the flag:

```sh
dufs --ip-whitelist '203.0.113.9@/private' --trusted-proxy 127.0.0.1,10.0.0.0/8
dufs --ip-whitelist '203.0.113.9@/private' --trusted-proxy '192.168.16.10 10.194.0.0/24'
dufs --ip-whitelist '203.0.113.9@/private' --trusted-proxy 192.168.16.10 --trusted-proxy 10.194.0.0/24
```

The forwarded list is read from right to left and the first address that is not itself a trusted proxy is used, so a well-behaved chain resolves to the real client while a spoofed prefix is ignored. The resolved address is also what `$remote_addr` logs, and it is returned to the client in the `X-Client-IP` response header, which makes a missing or wrong `--trusted-proxy` easy to spot.

> Never list `0.0.0.0/0`, and make sure dufs is not directly reachable from untrusted clients: a trusted peer that is not really a proxy lets a client forge its address and bypass the whitelist.

### Hide Paths

Dufs supports hiding paths from directory listings via option `--hidden <glob>,...`.

```
dufs --hidden .git,.DS_Store,tmp
```

> The glob used in --hidden only matches file and directory names, not paths. So `--hidden dir1/file` is invalid.

```sh
dufs --hidden '.*'                          # hidden dotfiles
dufs --hidden '*/'                          # hidden all folders
dufs --hidden '*.log,*.lock'                # hidden by exts
dufs --hidden '*.log' --hidden '*.lock'
```

### Log Format

Dufs supports customize http log format with option `--log-format`.

The log format can use following variables.

| variable     | description                                                               |
| ------------ | ------------------------------------------------------------------------- |
| $remote_addr | client address                                                            |
| $remote_user | user name supplied with authentication                                    |
| $request     | full original request line                                                |
| $status      | response status                                                           |
| $http_       | arbitrary request header field. examples: $http_user_agent, $http_referer |


The default log format is `'$time_iso8601 $log_level - $remote_addr "$request" $status`.
```
2022-08-06T06:59:31+08:00 INFO - 127.0.0.1 "GET /" 200
```

A json log format is also supported.
```
dufs --log-format '{"time":"$time_local","addr":"$remote_addr","uri":"$request_uri", "method":"$request_method","status":$status}'

{"time":"2022-08-06T06:59:31+08:00","addr":"127.0.0.1","uri":"/", "method":"GET","status":200}
```

Disable http log
```
dufs --log-format=''
```

Log user-agent
```
dufs --log-format '$remote_addr "$request" $status $http_user_agent'
```
```
2022-08-06T06:53:55+08:00 INFO - 127.0.0.1 "GET /" 200 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36
```

Log remote-user
```
dufs --log-format '$remote_addr $remote_user "$request" $status' -a /@admin:admin -a /folder1@user1:pass1
```
```
2022-08-06T07:04:37+08:00 INFO - 127.0.0.1 admin "GET /" 200
```

## Environment variables

All options can be set using environment variables prefixed with `DUFS_`.

```
[serve-path]                DUFS_SERVE_PATH="."
    --config <file>         DUFS_CONFIG=config.yaml
-b, --bind <addrs>          DUFS_BIND=0.0.0.0
-p, --port <port>           DUFS_PORT=5000
    --path-prefix <path>    DUFS_PATH_PREFIX=/dufs
    --hidden <value>        DUFS_HIDDEN=tmp,*.log,*.lock
-a, --auth <rules>          DUFS_AUTH="admin:admin@/:rw|@/" 
    --auth-type <type>      DUFS_AUTH_TYPE=oidc
    --ip-whitelist <rules>  DUFS_IP_WHITELIST="127.0.0.1@/dir1"
    --trusted-proxy <addrs> DUFS_TRUSTED_PROXY="127.0.0.1,10.0.0.0/8"
-A, --allow-all             DUFS_ALLOW_ALL=true
    --allow-upload          DUFS_ALLOW_UPLOAD=true
    --allow-delete          DUFS_ALLOW_DELETE=true
    --allow-search          DUFS_ALLOW_SEARCH=true
    --allow-symlink         DUFS_ALLOW_SYMLINK=true
    --allow-archive         DUFS_ALLOW_ARCHIVE=true
    --allow-hash            DUFS_ALLOW_HASH=true
    --allow-ip-whitelist    DUFS_ALLOW_IP_WHITELIST=true
    --enable-cors           DUFS_ENABLE_CORS=true
    --render-index          DUFS_RENDER_INDEX=true
    --render-try-index      DUFS_RENDER_TRY_INDEX=true
    --render-spa            DUFS_RENDER_SPA=true
    --assets <path>         DUFS_ASSETS=./assets
    --log-format <format>   DUFS_LOG_FORMAT=""
    --log-file <file>       DUFS_LOG_FILE=./dufs.log
    --compress <compress>   DUFS_COMPRESS=low
    --tls-cert <path>       DUFS_TLS_CERT=cert.pem
    --tls-key <path>        DUFS_TLS_KEY=key.pem
```

## Configuration File

You can specify and use the configuration file by selecting the option `--config <path-to-config.yaml>`.

The following are the configuration items:

```yaml
serve-path: '.'
bind: 0.0.0.0
port: 5000
path-prefix: /dufs
hidden:
  - tmp
  - '*.log'
  - '*.lock'
auth:
  - admin:admin@/:rw
  - user:pass@/src:rw,/share
  - '@/'  # According to the YAML spec, quoting is required.
auth-type: builtin
ip-whitelist:
  - '127.0.0.1,192.168.0.0/16@/'
  - '@/.git'  # According to the YAML spec, quoting is required.
trusted-proxy:
  - 127.0.0.1
  - 10.0.0.0/8
allow-all: false
allow-upload: true
allow-delete: true
allow-search: true
allow-symlink: true
allow-archive: true
allow-hash: true
allow-ip-whitelist: true
enable-cors: true
render-index: true
render-try-index: true
render-spa: true
assets: ./assets/
log-format: '$remote_addr "$request" $status $http_user_agent'
log-file: ./dufs.log
compress: low
tls-cert: tests/data/cert.pem
tls-key: tests/data/key_pkcs1.pem
```

### Customize UI

Dufs allows users to customize the UI with your own assets.

```
dufs --assets my-assets-dir/
```

> If you only need to make slight adjustments to the current UI, you copy dufs's [assets](https://github.com/sigoden/dufs/tree/main/assets) directory and modify it accordingly. The current UI doesn't use any frameworks, just plain HTML/JS/CSS. As long as you have some basic knowledge of web development, it shouldn't be difficult to modify.

Your assets folder must contains a `index.html` file.

`index.html` can use the following placeholder variables to retrieve internal data.

- `__INDEX_DATA__`: directory listing data
- `__ASSETS_PREFIX__`: assets url prefix
- `__PATH_PREFIX__`: path prefix

> A customized 404.html page is also supported.

Here are some Third-party customize UI project:

- https://github.com/TransparentLC/dufs-material-assets
- https://github.com/cercky/dufs_web
- https://github.com/52funny/dufs-tabler-web
- https://github.com/mikigo/dufs-shadcn-assets

</details>

## License

Copyright (c) 2022-2024 dufs-developers.

dufs is made available under the terms of either the MIT License or the Apache License 2.0, at your option.

See the LICENSE-APACHE and LICENSE-MIT files for license details.
