#ifndef ALMAP_HTTP_H
#define ALMAP_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * http.h - Step 28: native HTTP server for the ALmap Web UI.
 *
 * Dependency-free POSIX sockets. No mongoose/libmicrohttpd.
 * The C layer owns sockets, blocking accept/read/send, and child
 * process execution. Goose (modules/webui.goose) owns routing, HTML,
 * JSON parsing, validation, and response framing.
 *
 * almap_http_listen(port):
 *   Creates an AF_INET/SOCK_STREAM socket, sets SO_REUSEADDR, binds
 *   INADDR_ANY (0.0.0.0) on port (1..65535), and listens with backlog
 *   64. Returns the listening fd (>= 0) or -1 on failure.
 *
 * almap_http_accept(listen_fd):
 *   Blocks until a client connects. Retries on EINTR. Returns the
 *   client fd (>= 0) or -1 on failure.
 *
 * almap_http_next(listen_fd, buf, cap, client_fd, kind):
 *   poll() loop over the listener and up to ALMAP_WEB_MAX_CLIENTS
 *   pending non-blocking, close-on-exec clients (one ALMAP_WEB_REQ_CAP
 *   buffer per slot, kept in C). Blocks until an event, then sets
 *   *kind and returns:
 *     ALMAP_EV_REQUEST    a complete request (head + Content-Length
 *                         body) was copied into buf, NUL-terminated;
 *                         returns its length. *client_fd is the
 *                         client; the caller owns it (replies, closes).
 *     ALMAP_EV_TOO_LARGE / ALMAP_EV_BAD_LENGTH
 *                         the request is oversize / has a malformed
 *                         Content-Length; *client_fd is handed out the
 *                         same way (caller answers 413 / 400); returns 0.
 *     ALMAP_EV_SCAN_DONE  reserved for the scan worker; returns 0.
 *   A client that has not completed its request within
 *   ALMAP_WEB_REQ_DEADLINE_MS of being accepted (total, not per read),
 *   or that closes first, is closed silently: a request with fewer
 *   body bytes than its Content-Length is never handed out. Beyond
 *   ALMAP_WEB_MAX_CLIENTS pending clients a new connection is accepted
 *   and closed at once. Handed-out fds are switched back to blocking
 *   mode. Returns -1 (kind 0) on a fatal error. buf must hold cap
 *   bytes, cap >= 2.
 *
 * almap_http_send(client_fd, buf, len):
 *   Writes all len bytes (send loop with MSG_NOSIGNAL) so a closed
 *   client cannot kill the server with SIGPIPE. Returns 0 on success,
 *   -1 on failure. len may be 0 (no-op).
 *
 * almap_http_close(fd):
 *   Closes fd. Returns 0 on success, -1 on failure.
 *
 * almap_http_self_exe(buf, cap):
 *   Copies the current executable path (readlink /proc/self/exe) into
 *   buf NUL-terminated. Returns the path byte count (> 0) or -1 when
 *   unavailable. buf must hold cap bytes, cap >= 2.
 *
 * almap_http_run_scan(targets, ports, scan_type, fast, os_flag,
 *                     service_flag, evasion_flag, discover_flag,
 *                     timeout_ms, retries, script, out, cap, exit_code):
 *   Spawns the ALmap binary (self exe) as a child with --json and
 *   captures combined stdout+stderr into out NUL-terminated. Returns
 *   the output byte count (>= 0) or -1 on fork/exec/pipe failure.
 *   When exit_code is non-NULL it stores the child exit status
 *   (WEXITSTATUS when WIFEXITED, else -1). out must hold cap bytes,
 *   cap >= 2. Arguments are NUL-terminated C strings:
 *     targets    comma list (required, unless empty with discover)
 *     ports      ports string (required unless discover_flag)
 *     scan_type  "connect" | "syn" | "udp" (empty means "connect";
 *                ignored when discover_flag is set)
 *     fast, os_flag, service_flag, evasion_flag, discover_flag
 *                nonzero means add the corresponding flag
 *                (--fast, --os, --service, -f, --discover)
 *     timeout_ms  when > 0, passes --timeout <ms>
 *     retries    when >= 0, passes --retries <n> (fast engine timeout
 *                retries, CLI range 0..10)
 *     script     AlScript .so path; empty/NULL means no --script
 *
 * All functions are thread-unsafe only in that the server is
 * single-threaded by design (sequential request handling).
 *
 * Use only on networks you own or have permission to scan. The Web UI
 * spawns full ALmap scans with the server process privileges.
 */

/* Largest request (head + body) the Web UI accepts, and the largest
 * Content-Length it will honour. */
#define ALMAP_WEB_REQ_CAP 8192
#define ALMAP_WEB_CL_MAX ALMAP_WEB_REQ_CAP

/* Negated HTTP status codes for oversize / malformed Content-Length. */
#define ALMAP_HTTP_ERR_TOO_LARGE (-413)
#define ALMAP_HTTP_ERR_BAD_LENGTH (-400)

/* Pending-client limits. Each may be overridden by an environment
 * variable of the same name (read once, ignored when invalid). */
#define ALMAP_WEB_MAX_CLIENTS 32
#define ALMAP_WEB_REQ_DEADLINE_MS 2000

/* almap_http_next event kinds. */
#define ALMAP_EV_REQUEST 1
#define ALMAP_EV_TOO_LARGE 2
#define ALMAP_EV_BAD_LENGTH 3
#define ALMAP_EV_SCAN_DONE 4

/*
 * almap_http_parse_content_length(hdr, hdr_len, out): pure parser for
 * the Content-Length header in a request head. Returns 0 if absent,
 * 1 if valid (*out in 0..ALMAP_WEB_CL_MAX), -1 if malformed,
 * overflowing, conflicting or too large.
 *
 * almap_http_next reports ALMAP_EV_BAD_LENGTH for a malformed length
 * and ALMAP_EV_TOO_LARGE when head + declared body do not fit in
 * cap-1 bytes (or the head alone fills the buffer).
 */
int almap_http_parse_content_length(const unsigned char *hdr, int hdr_len,
                                    long *out);

int almap_http_listen(const char *bind_addr, int port);
int almap_http_accept(int listen_fd);
int almap_http_next(int listen_fd, unsigned char *buf, int cap,
                    int *client_fd, int *kind);
int almap_http_send(int client_fd, const unsigned char *buf, int len);
int almap_http_close(int fd);
int almap_http_self_exe(unsigned char *buf, int cap);
int almap_http_random_token(unsigned char *buf, int cap);
int almap_http_resolve_plugin(const char *name, unsigned char *out, int cap);
int almap_http_run_scan(const char *targets, const char *ports,
                        const char *scan_type, int fast, int os_flag,
                        int service_flag, int evasion_flag,
                        int discover_flag, int timeout_ms, int retries,
                        const char *script,
                        unsigned char *out, int cap, int *exit_code);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_HTTP_H */
