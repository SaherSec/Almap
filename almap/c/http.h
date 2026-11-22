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
 *     ALMAP_EV_SCAN_DONE  the scan child finished (see almap_http_scan_*);
 *                         *client_fd is the requester or -1; returns 0.
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
 *   Writes all len bytes (poll(POLLOUT) + non-blocking send with
 *   MSG_NOSIGNAL) so a closed client cannot kill the server with
 *   SIGPIPE. The whole call is bounded by ALMAP_WEB_SEND_BASE_MS +
 *   ALMAP_WEB_SEND_PER_MIB_MS per MiB of len (total wall clock, not per
 *   send): a client that reads too slowly is given up on. Returns 0 on
 *   success, -1 on failure or budget exhaustion (the caller closes the
 *   fd). len may be 0 (no-op).
 *
 * almap_http_close(fd):
 *   Closes fd. Returns 0 on success, -1 on failure.
 *
 * almap_http_close_linger(fd):
 *   Non-blocking. Hands fd to a C-owned draining list (max 32; when
 *   full the fd is closed at once): C sends FIN, discards what the
 *   client still sends and closes at EOF or after 200 ms, driven by
 *   almap_http_next. The caller must not close fd afterwards. Used for
 *   early 413/400 replies so the close cannot RST the reply away.
 *
 * almap_http_self_exe(buf, cap):
 *   Copies the current executable path (readlink /proc/self/exe) into
 *   buf NUL-terminated. Returns the path byte count (> 0) or -1 when
 *   unavailable. buf must hold cap bytes, cap >= 2.
 *
 * Scan child (one at a time; the child is this binary with --json, its
 * stdin /dev/null, stdout+stderr combined into one pipe, in its own
 * process group):
 *
 * almap_http_scan_start(client_fd, targets, ports, scan_type, fast,
 *                       os_flag, service_flag, evasion_flag,
 *                       discover_flag, timeout_ms, retries, script):
 *   Spawns the scan. Returns 0 started (C now OWNS client_fd until
 *   almap_http_next hands it back with ALMAP_EV_SCAN_DONE; the caller
 *   must not close it), -1 a scan is already running (caller keeps
 *   client_fd and answers 409), -2 on spawn/argument error (caller
 *   keeps client_fd, answers 500). Arguments are NUL-terminated:
 *     targets    comma list (required)
 *     ports      ports string (required unless discover_flag)
 *     scan_type  "connect" | "syn" | "udp" (empty means "connect";
 *                ignored when discover_flag is set)
 *     fast, os_flag, service_flag, evasion_flag, discover_flag
 *                nonzero adds --fast, --os, --service, -f, --discover
 *     timeout_ms when > 0, passes --timeout <ms>
 *     retries    when >= 0, passes --retries <n>
 *     script     AlScript .so path; empty/NULL means no --script
 *   While the scan runs, almap_http_next keeps serving other requests,
 *   collects the output (up to ALMAP_WEB_OUT_CAP bytes) and watches
 *   the requester. The child's whole process group is SIGKILLed and the
 *   child reaped at ALMAP_WEB_SCAN_LIMIT_S seconds, when the output
 *   exceeds the cap by one byte, or when the requester hangs up.
 *   When the scan ends, almap_http_next returns ALMAP_EV_SCAN_DONE with
 *   *client_fd the requester (-1 if it hung up; C closed it).
 *
 * almap_http_scan_result(head, head_cap, exit_code, state):
 *   Reports the finished scan: *state is an ALMAP_SCAN_* value,
 *   *exit_code the child status (WEXITSTATUS, else -1). For
 *   ALMAP_SCAN_FAILED up to head_cap bytes of its output are copied to
 *   head and their count returned (else 0). Returns -1 when there is no
 *   finished scan. Non-OK results release the output buffer.
 *
 * almap_http_scan_send_body(client_fd):
 *   For ALMAP_SCAN_OK: sends 200 + the whole output (or "[]" when it is
 *   empty) and releases the buffer. Returns 0 / -1.
 *
 * almap_http_scan_running(): 1 while a scan child is running, else 0.
 * almap_http_out_cap() / almap_http_scan_limit_s(): the effective
 *   output cap in bytes and wall-clock limit in seconds.
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

/* Total send budget per response part: BASE + PER_MIB per MiB sent, on
 * the monotonic clock (a slow reader cannot stall the server longer).
 * ALMAP_WEB_SEND_BASE_MS may be overridden by an environment variable of
 * the same name (1..600000 ms; ignored when invalid). */
#define ALMAP_WEB_SEND_BASE_MS 5000
#define ALMAP_WEB_SEND_PER_MIB_MS 1000

/* almap_http_next event kinds. */
#define ALMAP_EV_REQUEST 1
#define ALMAP_EV_TOO_LARGE 2
#define ALMAP_EV_BAD_LENGTH 3
#define ALMAP_EV_SCAN_DONE 4

/* Scan limits. Each may be overridden by an environment variable of the
 * same name (bytes 1..64 MiB / seconds 1..3600; ignored when invalid). */
#define ALMAP_WEB_OUT_CAP (16 * 1024 * 1024)
#define ALMAP_WEB_SCAN_LIMIT_S 300

/* almap_http_scan_result states. */
#define ALMAP_SCAN_OK 0
#define ALMAP_SCAN_FAILED 1
#define ALMAP_SCAN_OVER_CAP 2
#define ALMAP_SCAN_TIMED_OUT 3
#define ALMAP_SCAN_ABANDONED 4

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
int almap_http_close_linger(int fd);
int almap_http_self_exe(unsigned char *buf, int cap);
int almap_http_random_token(unsigned char *buf, int cap);
int almap_http_resolve_plugin(const char *name, unsigned char *out, int cap);
int almap_http_scan_start(int client_fd, const char *targets,
                          const char *ports, const char *scan_type,
                          int fast, int os_flag, int service_flag,
                          int evasion_flag, int discover_flag,
                          int timeout_ms, int retries, const char *script);
int almap_http_scan_result(unsigned char *head, int head_cap, int *exit_code,
                           int *state);
int almap_http_scan_send_body(int client_fd);
int almap_http_scan_running(void);
int almap_http_out_cap(void);
int almap_http_scan_limit_s(void);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_HTTP_H */
