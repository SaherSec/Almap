/* Unit tests for the pure HTTP helpers in c/http.c.
 * Build: gcc -std=c99 -Wall -Wextra -I c tests/test_http.c c/http.c -o /tmp/test_http */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "http.h"

static int failures = 0;

static void check_cl(const char *name, const char *hdr, int want_rc,
                     long want_val) {
    long v = -7;
    int rc = almap_http_parse_content_length((const unsigned char *)hdr,
                                             (int)strlen(hdr), &v);

    if (rc != want_rc || (want_rc == 1 && v != want_val)) {
        printf("FAIL %s: rc=%d (want %d) val=%ld (want %ld)\n", name, rc,
               want_rc, v, want_val);
        failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

#define H(extra) "POST /api/scan HTTP/1.1\r\nHost: x\r\n" extra "\r\n"

static int new_listener(int *port) {
    struct sockaddr_in a;
    socklen_t l = sizeof(a);
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(fd, 16) != 0 || getsockname(fd, (struct sockaddr *)&a, &l) != 0) {
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

static int dial(int port) {
    struct sockaddr_in a;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short)port);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        return -1;
    }
    return fd;
}

static void expect(const char *name, int cond) {
    printf("%s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond) {
        failures++;
    }
}

/* Child: connect after delay_us, send the parts with gaps, then wait. */
static pid_t spawn_writer(int port, int delay_us, const char *a,
                          const char *b, const char *c) {
    pid_t pid = fork();

    if (pid == 0) {
        int fd;

        usleep((useconds_t)delay_us);
        fd = dial(port);
        if (fd < 0) {
            _exit(1);
        }
        if (a) { (void)write(fd, a, strlen(a)); usleep(60000); }
        if (b) { (void)write(fd, b, strlen(b)); usleep(60000); }
        if (c) { (void)write(fd, c, strlen(c)); }
        usleep(900000);
        _exit(0);
    }
    return pid;
}

static void test_next(void) {
    int port = 0;
    int lfd = new_listener(&port);
    unsigned char buf[ALMAP_WEB_REQ_CAP];
    int cfd = -1;
    int kind = 0;
    int n;
    pid_t w;
    int a;
    char tmp[8];

    expect("listener", lfd >= 0);
    if (lfd < 0) {
        return;
    }
    /* Request split across 3 writes. */
    w = spawn_writer(port, 0, "POST /api/scan HTTP/1.1\r\nHost: x\r\nContent-Le",
                     "ngth: 5\r\n\r\nab", "cde");
    n = almap_http_next(lfd, buf, (int)sizeof(buf), &cfd, &kind);
    expect("split request -> EV_REQUEST", kind == ALMAP_EV_REQUEST && n > 0 &&
           cfd >= 0 && strstr((char *)buf, "\r\n\r\nabcde") != NULL &&
           buf[n] == '\0');
    if (cfd >= 0) {
        close(cfd);
    }
    waitpid(w, NULL, 0);

    /* Incomplete body (CL 100, 10 bytes) is dropped at the deadline and
     * never handed out; a later complete request is. */
    a = dial(port);
    (void)write(a, "POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\n0123456789", 51);
    w = spawn_writer(port, 700000, "GET /api/status HTTP/1.1\r\nHost: x\r\n\r\n",
                     NULL, NULL);
    cfd = -1;
    n = almap_http_next(lfd, buf, (int)sizeof(buf), &cfd, &kind);
    expect("incomplete body never delivered; next request is",
           kind == ALMAP_EV_REQUEST && strncmp((char *)buf, "GET /api/status", 15) == 0);
    expect("stalled client closed by server", read(a, tmp, sizeof(tmp)) == 0);
    close(a);
    if (cfd >= 0) {
        close(cfd);
    }
    waitpid(w, NULL, 0);

    /* EOF with a short body is dropped too. */
    a = dial(port);
    (void)write(a, "POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\n01", 43);
    shutdown(a, SHUT_WR);
    w = spawn_writer(port, 300000, "GET /b HTTP/1.1\r\n\r\n", NULL, NULL);
    cfd = -1;
    n = almap_http_next(lfd, buf, (int)sizeof(buf), &cfd, &kind);
    expect("EOF short body dropped", kind == ALMAP_EV_REQUEST &&
           strncmp((char *)buf, "GET /b", 6) == 0);
    close(a);
    if (cfd >= 0) {
        close(cfd);
    }
    waitpid(w, NULL, 0);

    /* Oversize and malformed lengths. */
    w = spawn_writer(port, 0, "POST /x HTTP/1.1\r\nContent-Length: 9000\r\n\r\n", NULL, NULL);
    cfd = -1;
    n = almap_http_next(lfd, buf, (int)sizeof(buf), &cfd, &kind);
    expect("oversize -> EV_TOO_LARGE", kind == ALMAP_EV_TOO_LARGE && cfd >= 0);
    if (cfd >= 0) {
        close(cfd);
    }
    waitpid(w, NULL, 0);
    w = spawn_writer(port, 0, "POST /x HTTP/1.1\r\nContent-Length: abc\r\n\r\n", NULL, NULL);
    cfd = -1;
    n = almap_http_next(lfd, buf, (int)sizeof(buf), &cfd, &kind);
    expect("malformed -> EV_BAD_LENGTH", kind == ALMAP_EV_BAD_LENGTH && cfd >= 0);
    if (cfd >= 0) {
        close(cfd);
    }
    waitpid(w, NULL, 0);
    (void)n;
    close(lfd);
}

int main(void) {
    setenv("ALMAP_WEB_REQ_DEADLINE_MS", "300", 1);
    test_next();
    check_cl("absent", H(""), 0, 0);
    check_cl("12", H("Content-Length: 12\r\n"), 1, 12);
    check_cl("zero", H("Content-Length: 0\r\n"), 1, 0);
    check_cl("max 8192", H("Content-Length: 8192\r\n"), 1, 8192);
    check_cl("8193 too large", H("Content-Length: 8193\r\n"), -1, 0);
    check_cl("23 digits", H("Content-Length: 99999999999999999999999\r\n"), -1, 0);
    check_cl("negative", H("Content-Length: -1\r\n"), -1, 0);
    check_cl("trailing junk", H("Content-Length: 1x\r\n"), -1, 0);
    check_cl("empty value", H("Content-Length:\r\n"), -1, 0);
    check_cl("lower-case name", H("content-length: 5\r\n"), 1, 5);
    check_cl("conflicting duplicates",
             H("Content-Length: 5\r\nContent-Length: 6\r\n"), -1, 0);
    check_cl("not a content-length header",
             H("X-Content-Length: 5\r\n"), 0, 0);
    if (ALMAP_HTTP_ERR_TOO_LARGE != -413 || ALMAP_HTTP_ERR_BAD_LENGTH != -400) {
        printf("FAIL error constants\n");
        failures++;
    }
    return failures ? 1 : 0;
}
