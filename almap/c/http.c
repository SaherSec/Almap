#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700 /* realpath */
#endif

#include "http.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/time.h>
#endif

/*
 * http.c - Step 28: native HTTP server for the ALmap Web UI.
 *
 * Minimal HTTP/1.1 over POSIX sockets. Single-threaded, sequential.
 * No dependencies beyond libc/POSIX. Use only on networks you own or
 * have permission to scan.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static int find_header_end(const unsigned char *buf, int len) {
    int i;

    if (len < 4) {
        return -1;
    }
    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i + 4;
        }
    }
    return -1;
}

static int ci_prefix(const unsigned char *p, int avail, const char *lit) {
    int i;

    for (i = 0; lit[i] != '\0'; i++) {
        unsigned char c;

        if (i >= avail) {
            return 0;
        }
        c = p[i];
        if (c >= 'A' && c <= 'Z') {
            c = (unsigned char)(c - 'A' + 'a');
        }
        if (c != (unsigned char)lit[i]) {
            return 0;
        }
    }
    return 1;
}

/*
 * Pure parser (parse_cl) for the Content-Length header of a request head (request
 * line + headers, optionally with the blank line). Returns 0 when the
 * header is absent, 1 with *out set (0..ALMAP_WEB_CL_MAX) when valid,
 * -1 when malformed (non-digits, empty, negative), repeated with a
 * different value, or larger than ALMAP_WEB_CL_MAX. Accumulation stops
 * as soon as the cap is exceeded, so it cannot overflow.
 */
static int parse_cl(const unsigned char *hdr, int hdr_len, long *out,
                    int *too_large) {
    const int nlen = 14; /* strlen("content-length") */
    int found = 0;
    long result = 0;
    int pos = 0;

    if (out != NULL) {
        *out = 0;
    }
    if (too_large != NULL) {
        *too_large = 0;
    }
    if (hdr == NULL || hdr_len < 0) {
        return -1;
    }
    /* Skip the request line, then examine each header line. */
    while (pos < hdr_len && hdr[pos] != '\n') {
        pos++;
    }
    if (pos < hdr_len) {
        pos++;
    }
    while (pos < hdr_len) {
        int eol = pos;
        long val = 0;
        int k;
        int digits = 0;

        while (eol < hdr_len && hdr[eol] != '\n') {
            eol++;
        }
        if (hdr[pos] == '\r' || hdr[pos] == '\n') {
            break; /* blank line: end of headers */
        }
        if (ci_prefix(hdr + pos, eol - pos, "content-length")) {
            k = pos + nlen;
            while (k < eol && (hdr[k] == ' ' || hdr[k] == '\t')) {
                k++;
            }
            if (k < eol && hdr[k] == ':') {
                k++;
                while (k < eol && (hdr[k] == ' ' || hdr[k] == '\t')) {
                    k++;
                }
                while (k < eol && hdr[k] >= '0' && hdr[k] <= '9') {
                    /* Saturate at CL_MAX + 1: no overflow possible. */
                    if (val <= ALMAP_WEB_CL_MAX) {
                        val = val * 10 + (hdr[k] - '0');
                    }
                    if (val > ALMAP_WEB_CL_MAX) {
                        val = ALMAP_WEB_CL_MAX + 1;
                    }
                    digits++;
                    k++;
                }
                while (k < eol && (hdr[k] == ' ' || hdr[k] == '\t' ||
                                   hdr[k] == '\r')) {
                    k++;
                }
                /* More than 18 digits: treated as overflow (bad), not
                 * as a plausible-but-too-large length (413). */
                if (digits == 0 || digits > 18 || k != eol) {
                    return -1;
                }
                if (found && val != result) {
                    return -1;
                }
                found = 1;
                result = val;
            }
        }
        pos = eol + 1;
    }
    if (!found) {
        return 0;
    }
    if (result > ALMAP_WEB_CL_MAX) {
        if (too_large != NULL) {
            *too_large = 1;
        }
        return -1;
    }
    if (out != NULL) {
        *out = result;
    }
    return 1;
}

int almap_http_parse_content_length(const unsigned char *hdr, int hdr_len,
                                    long *out) {
    return parse_cl(hdr, hdr_len, out, NULL);
}

static void set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);

    if (flags >= 0) {
        (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

/* bind_addr is a dotted IPv4 address; NULL or "" means 127.0.0.1. */
int almap_http_listen(const char *bind_addr, int port) {
    int fd;
    int opt = 1;
    struct sockaddr_in addr;
    struct in_addr ip;

    if (port < 1 || port > 65535) {
        return -1;
    }
    if (bind_addr == NULL || bind_addr[0] == '\0') {
        bind_addr = "127.0.0.1";
    }
    if (inet_pton(AF_INET, bind_addr, &ip) != 1) {
        return -1;
    }
    /* A closed client must not kill the server. send() also uses
     * MSG_NOSIGNAL, but this covers any other write path. */
    signal(SIGPIPE, SIG_IGN);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    set_cloexec(fd);
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = ip;
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int almap_http_accept(int listen_fd) {
    int client;

    if (listen_fd < 0) {
        return -1;
    }
    for (;;) {
        client = accept(listen_fd, NULL, NULL);
        if (client >= 0) {
            /* The scan child must not inherit the listener or clients. */
            set_cloexec(client);
            return client;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
}

int almap_http_read(int client_fd, unsigned char *buf, int cap) {
    int total = 0;
#ifdef __linux__
    struct timeval tv;
#endif

    if (client_fd < 0 || buf == NULL || cap < 2) {
        return -1;
    }
    buf[0] = '\0';
#ifdef __linux__
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    while (total < cap - 1) {
        ssize_t n;
        int header_end;
        long clen = 0;
        int have_cl;
        int too_large = 0;

        n = recv(client_fd, buf + total, (size_t)(cap - 1 - total), 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return total > 0 ? total : -1;
        }
        if (n == 0) {
            break;
        }
        total += (int)n;
        buf[total] = '\0';

        header_end = find_header_end(buf, total);
        if (header_end < 0) {
            continue;
        }
        have_cl = parse_cl(buf, header_end, &clen, &too_large);
        if (have_cl < 0) {
            return too_large ? ALMAP_HTTP_ERR_TOO_LARGE
                             : ALMAP_HTTP_ERR_BAD_LENGTH;
        }
        if (have_cl == 0) {
            /* GET and other header-only requests are complete. */
            break;
        }
        if ((long)header_end + clen > (long)(cap - 1)) {
            return ALMAP_HTTP_ERR_TOO_LARGE;
        }
        if ((long)header_end + clen <= (long)total) {
            break;
        }
        /* Body incomplete: keep reading until CL bytes arrive. */
    }
    if (total == 0) {
        return -1;
    }
    if (total >= cap - 1 && find_header_end(buf, total) < 0) {
        /* Head alone fills the buffer: oversize, not truncated. */
        return ALMAP_HTTP_ERR_TOO_LARGE;
    }
    buf[total] = '\0';
    return total;
}

int almap_http_send(int client_fd, const unsigned char *buf, int len) {
    int sent = 0;

    if (client_fd < 0 || len < 0 || (len > 0 && buf == NULL)) {
        return -1;
    }
    while (sent < len) {
        ssize_t n = send(client_fd, buf + sent, (size_t)(len - sent),
                         MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (int)n;
    }
    return 0;
}

int almap_http_close(int fd) {
    if (fd < 0) {
        return -1;
    }
    return close(fd);
}

int almap_http_self_exe(unsigned char *buf, int cap) {
    ssize_t n;

    if (buf == NULL || cap < 2) {
        return -1;
    }
    n = readlink("/proc/self/exe", (char *)buf, (size_t)(cap - 1));
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    return (int)n;
}

/* 16 random bytes from /dev/urandom as 32 lowercase hex chars + NUL. */
int almap_http_random_token(unsigned char *buf, int cap) {
    static const char hex[] = "0123456789abcdef";
    unsigned char raw[16];
    size_t got = 0;
    int fd;
    int i;

    if (buf == NULL || cap < 33) {
        return -1;
    }
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    while (got < sizeof(raw)) {
        ssize_t n = read(fd, raw + got, sizeof(raw) - got);

        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            close(fd);
            return -1;
        }
        got += (size_t)n;
    }
    close(fd);
    for (i = 0; i < 16; i++) {
        buf[2 * i] = (unsigned char)hex[raw[i] >> 4];
        buf[2 * i + 1] = (unsigned char)hex[raw[i] & 15u];
    }
    buf[32] = '\0';
    return 32;
}

/* A plugin name is 1..128 chars of [A-Za-z0-9_.-], starts with an
 * alphanumeric, has no "..", and may end in ".so". */
static int plugin_name_ok(const char *name) {
    size_t i;
    size_t len;

    if (name == NULL) {
        return 0;
    }
    len = strlen(name);
    if (len == 0 || len > 128) {
        return 0;
    }
    if (!((name[0] >= 'a' && name[0] <= 'z') ||
          (name[0] >= 'A' && name[0] <= 'Z') ||
          (name[0] >= '0' && name[0] <= '9'))) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        char c = name[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
            return 0;
        }
    }
    return strstr(name, "..") == NULL;
}

/*
 * Resolve a plugin name to <dir of this executable>/plugins/<name>.so.
 * The resolved real path must be a regular file directly inside the
 * real plugins directory (symlinks pointing elsewhere are refused).
 * Returns the path length, -1 for an invalid name, -2 if the plugin
 * does not exist or resolves outside plugins/.
 */
int almap_http_resolve_plugin(const char *name, unsigned char *out, int cap) {
    char exe[PATH_MAX];
    char dir[PATH_MAX];
    char real_dir[PATH_MAX];
    char cand[PATH_MAX];
    char real_cand[PATH_MAX];
    char *slash;
    size_t nlen;
    size_t dlen;
    struct stat st;
    int n;

    if (out == NULL || cap < 2) {
        return -1;
    }
    out[0] = '\0';
    if (!plugin_name_ok(name)) {
        return -1;
    }
    nlen = strlen(name);
    if (nlen > 3 && strcmp(name + nlen - 3, ".so") == 0) {
        nlen -= 3;
    }
    if (realpath("/proc/self/exe", exe) == NULL) {
        return -2;
    }
    slash = strrchr(exe, '/');
    if (slash == NULL) {
        return -2;
    }
    *slash = '\0';
    n = snprintf(dir, sizeof(dir), "%s/plugins", exe);
    if (n < 0 || (size_t)n >= sizeof(dir) || realpath(dir, real_dir) == NULL) {
        return -2;
    }
    n = snprintf(cand, sizeof(cand), "%s/%.*s.so", real_dir, (int)nlen, name);
    if (n < 0 || (size_t)n >= sizeof(cand) || realpath(cand, real_cand) == NULL) {
        return -2;
    }
    dlen = strlen(real_dir);
    if (strncmp(real_cand, real_dir, dlen) != 0 || real_cand[dlen] != '/' ||
        strchr(real_cand + dlen + 1, '/') != NULL) {
        return -2;
    }
    if (stat(real_cand, &st) != 0 || !S_ISREG(st.st_mode)) {
        return -2;
    }
    n = (int)strlen(real_cand);
    if (n >= cap) {
        return -2;
    }
    memcpy(out, real_cand, (size_t)n + 1);
    return n;
}

int almap_http_run_scan(const char *targets, const char *ports,
                        const char *scan_type, int fast, int os_flag,
                        int service_flag, int evasion_flag,
                        int discover_flag, int timeout_ms, int retries,
                        const char *script,
                        unsigned char *out, int cap, int *exit_code) {
    char exe_path[512];
    char timeout_buf[16];
    char retries_buf[16];
    const char *argv[26];
    int argc = 0;
    int pipefd[2];
    pid_t pid;
    int total = 0;
    int status = 0;

    if (exit_code != NULL) {
        *exit_code = -1;
    }
    if (out == NULL || cap < 2) {
        return -1;
    }
    out[0] = '\0';
    if (targets == NULL || targets[0] == '\0') {
        return -1;
    }
    if (!discover_flag && (ports == NULL || ports[0] == '\0')) {
        return -1;
    }
    if (almap_http_self_exe((unsigned char *)exe_path,
                            (int)sizeof(exe_path)) < 0) {
        return -1;
    }

    timeout_buf[0] = '\0';
    if (timeout_ms > 0) {
        snprintf(timeout_buf, sizeof(timeout_buf), "%d", timeout_ms);
    }
    retries_buf[0] = '\0';
    if (retries >= 0) {
        snprintf(retries_buf, sizeof(retries_buf), "%d", retries);
    }

    argv[argc++] = exe_path;
    argv[argc++] = "-t";
    argv[argc++] = targets;
    if (discover_flag) {
        argv[argc++] = "--discover";
    } else {
        argv[argc++] = "-p";
        argv[argc++] = ports;
        argv[argc++] = "--scan";
        if (scan_type != NULL && scan_type[0] != '\0') {
            argv[argc++] = scan_type;
        } else {
            argv[argc++] = "connect";
        }
        if (timeout_ms > 0) {
            argv[argc++] = "--timeout";
            argv[argc++] = timeout_buf;
        }
        if (retries >= 0) {
            argv[argc++] = "--retries";
            argv[argc++] = retries_buf;
        }
        if (fast) {
            argv[argc++] = "--fast";
        }
        if (os_flag) {
            argv[argc++] = "--os";
        }
        if (service_flag) {
            argv[argc++] = "--service";
        }
        if (evasion_flag) {
            argv[argc++] = "-f";
        }
        if (script != NULL && script[0] != '\0') {
            argv[argc++] = "--script";
            argv[argc++] = script;
        }
    }
    argv[argc++] = "--json";
    argv[argc] = NULL;

    if (pipe(pipefd) != 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        /* Child: stdout+stderr -> pipe. */
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        if (dup2(pipefd[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        close(pipefd[1]);
        execv(exe_path, (char *const *)argv);
        _exit(127);
    }
    /* Parent: capture until EOF, truncating at cap-1. */
    close(pipefd[1]);
    while (total < cap - 1) {
        ssize_t n = read(pipefd[0], out + total, (size_t)(cap - 1 - total));

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        total += (int)n;
    }
    {
        unsigned char drain[4096];
        ssize_t n;

        do {
            n = read(pipefd[0], drain, sizeof(drain));
        } while (n > 0);
    }
    close(pipefd[0]);

    for (;;) {
        pid_t w = waitpid(pid, &status, 0);

        if (w == pid) {
            break;
        }
        if (w < 0 && errno != EINTR) {
            break;
        }
    }
    if (exit_code != NULL) {
        if (WIFEXITED(status)) {
            *exit_code = WEXITSTATUS(status);
        } else {
            *exit_code = -1;
        }
    }
    out[total] = '\0';
    return total;
}
