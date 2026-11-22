/* Unit tests for the pure HTTP helpers in c/http.c.
 * Build: gcc -std=c99 -Wall -Wextra -I c tests/test_http.c c/http.c -o /tmp/test_http */
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
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


/* ---- scan lifecycle -------------------------------------------------
 * almap_http_scan_start execs this very test binary with the scanner's
 * argv ("-t <name> -p ..."); main() below turns that into a fake scanner
 * whose behaviour is picked by <name>. */
static int fake_scanner(const char *mode) {
    const char *nb = getenv("FAKE_BYTES");
    long n = nb ? atol(nb) : 0;
    char blk[4096];

    memset(blk, 'x', sizeof(blk));
    if (strcmp(mode, "echo") == 0) {
        printf("[1]");
        return 0;
    }
    if (strcmp(mode, "bytes") == 0) {
        while (n > 0) {
            size_t k = n > (long)sizeof(blk) ? sizeof(blk) : (size_t)n;

            if (write(1, blk, k) != (ssize_t)k) {
                return 9;
            }
            n -= (long)k;
        }
        return 0;
    }
    if (strcmp(mode, "fail") == 0) {
        printf("boom");
        fflush(stdout);
        fprintf(stderr, "-err");
        return 3;
    }
    if (strcmp(mode, "late") == 0) { /* slow, then prints */
        usleep(1200000);
        printf("[late]");
        return 0;
    }
    if (strcmp(mode, "sleep") == 0) {
        sleep(60);
        return 0;
    }
    if (strcmp(mode, "grand") == 0) { /* grandchild keeps the pipe open */
        pid_t g = fork();

        if (g == 0) {
            const char *f = getenv("FAKE_PIDFILE");
            FILE *fp = f ? fopen(f, "w") : NULL;

            if (fp) {
                fprintf(fp, "%d", (int)getpid());
                fclose(fp);
            }
            sleep(60);
            _exit(0);
        }
        sleep(60);
        return 0;
    }
    if (strcmp(mode, "stdin") == 0) {
        char c;
        ssize_t r = read(0, &c, 1);

        printf(r == 0 ? "eof" : "data");
        return 0;
    }
    return 1;
}

static long long now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* A connected pair: *srv is the server side (passed to scan_start),
 * *cli the requester's end. */
static void mk_pair(int lfd, int port, int *srv, int *cli) {
    *cli = dial(port);
    *srv = accept(lfd, NULL, NULL);
    /* The scan child must not keep the requester's socket alive. */
    (void)fcntl(*cli, F_SETFD, FD_CLOEXEC);
    (void)fcntl(*srv, F_SETFD, FD_CLOEXEC);
}

/* Run next() until the scan is done. Returns the kind seen (0 on
 * timeout of this helper) and the handed-back requester. */
static int wait_done(int lfd, int *client) {
    unsigned char buf[ALMAP_WEB_REQ_CAP];
    int kind = 0;
    int n;

    *client = -2;
    n = almap_http_next(lfd, buf, (int)sizeof(buf), client, &kind);
    (void)n;
    return kind;
}

static int no_children(void) {
    int st;

    return waitpid(-1, &st, WNOHANG) == -1 && errno == ECHILD;
}

static int read_all(int fd, char *out, int cap) {
    int total = 0;
    ssize_t n;

    while (total < cap - 1 && (n = read(fd, out + total, (size_t)(cap - 1 - total))) > 0) {
        total += (int)n;
    }
    out[total] = '\0';
    return total;
}

static int start(int srv, const char *mode) {
    return almap_http_scan_start(srv, mode, "1", "connect", 0, 0, 0, 0, 0,
                                 1000, 0, "");
}

static void test_scan(void) {
    int port = 0;
    int lfd = new_listener(&port);
    int srv, cli, got, state, ec, rc;
    unsigned char head[64];
    static char resp[300000];
    long long t0;

    if (lfd < 0) {
        expect("scan listener", 0);
        return;
    }
    unsetenv("ALMAP_WEB_OUT_CAP");
    unsetenv("ALMAP_WEB_SCAN_LIMIT_S");
    setenv("ALMAP_WEB_REQ_DEADLINE_MS", "30000", 1);

    /* OK: body "[1]" sent whole, requester handed back, stdin is EOF. */
    mk_pair(lfd, port, &srv, &cli);
    expect("scan start ok", start(srv, "echo") == 0);
    expect("scan_running while active", almap_http_scan_running() == 1);
    expect("second start -> -1", start(srv, "echo") == -1);
    expect("scan_next -> SCAN_DONE", wait_done(lfd, &got) == ALMAP_EV_SCAN_DONE && got == srv);
    expect("scan_running after", almap_http_scan_running() == 0);
    rc = almap_http_scan_result(head, sizeof(head), &ec, &state);
    expect("state OK / exit 0", rc == 0 && state == ALMAP_SCAN_OK && ec == 0);
    expect("send_body ok", almap_http_scan_send_body(got) == 0);
    close(got);
    read_all(cli, resp, sizeof(resp));
    close(cli);
    expect("200 + whole body", strncmp(resp, "HTTP/1.1 200", 12) == 0 &&
           strstr(resp, "Content-Length: 3\r\n") && strstr(resp, "\r\n\r\n[1]"));
    expect("result consumed once", almap_http_scan_result(head, sizeof(head), &ec, &state) == -1);
    expect("no children left", no_children());

    /* Child stdin is /dev/null. */
    mk_pair(lfd, port, &srv, &cli);
    start(srv, "stdin");
    wait_done(lfd, &got);
    almap_http_scan_result(head, sizeof(head), &ec, &state);
    almap_http_scan_send_body(got);
    close(got);
    read_all(cli, resp, sizeof(resp));
    close(cli);
    expect("child stdin at EOF", strstr(resp, "\r\n\r\neof") != NULL);

    /* Empty output -> "[]". */
    mk_pair(lfd, port, &srv, &cli);
    setenv("FAKE_BYTES", "0", 1);
    start(srv, "bytes");
    wait_done(lfd, &got);
    almap_http_scan_result(head, sizeof(head), &ec, &state);
    almap_http_scan_send_body(got);
    close(got);
    read_all(cli, resp, sizeof(resp));
    close(cli);
    expect("empty output -> []", strstr(resp, "\r\n\r\n[]") != NULL);

    /* Large output (> pipe buffer) drained after the child exits. */
    mk_pair(lfd, port, &srv, &cli);
    setenv("FAKE_BYTES", "200000", 1);
    start(srv, "bytes");
    wait_done(lfd, &got);
    rc = almap_http_scan_result(head, sizeof(head), &ec, &state);
    expect("200000 bytes OK", state == ALMAP_SCAN_OK);
    almap_http_scan_send_body(got);
    close(got);
    got = read_all(cli, resp, sizeof(resp));
    close(cli);
    expect("full 200000-byte body", strstr(resp, "Content-Length: 200000\r\n") &&
           got > 200000);

    /* Cap boundary. */
    setenv("ALMAP_WEB_OUT_CAP", "5000", 1);
    setenv("FAKE_BYTES", "5000", 1);
    mk_pair(lfd, port, &srv, &cli);
    start(srv, "bytes");
    wait_done(lfd, &got);
    almap_http_scan_result(head, sizeof(head), &ec, &state);
    expect("output == cap is OK", state == ALMAP_SCAN_OK);
    almap_http_scan_send_body(got);
    close(got);
    got = read_all(cli, resp, sizeof(resp));
    close(cli);
    expect("at-cap body whole", strstr(resp, "Content-Length: 5000\r\n") != NULL);
    setenv("FAKE_BYTES", "5001", 1);
    mk_pair(lfd, port, &srv, &cli);
    start(srv, "bytes");
    wait_done(lfd, &got);
    almap_http_scan_result(head, sizeof(head), &ec, &state);
    expect("cap+1 is OVER_CAP", state == ALMAP_SCAN_OVER_CAP && got == srv);
    expect("over-cap: send_body refused", almap_http_scan_send_body(got) == -1);
    close(got);
    close(cli);
    expect("over-cap: no children", no_children());
    expect("out_cap reports env", almap_http_out_cap() == 5000);
    setenv("ALMAP_WEB_OUT_CAP", "0", 1); /* invalid -> default */
    expect("invalid cap env ignored", almap_http_out_cap() == ALMAP_WEB_OUT_CAP);
    unsetenv("ALMAP_WEB_OUT_CAP");

    /* Failure: exit code and head of the output (stdout+stderr). */
    mk_pair(lfd, port, &srv, &cli);
    start(srv, "fail");
    wait_done(lfd, &got);
    rc = almap_http_scan_result(head, sizeof(head), &ec, &state);
    expect("FAILED, exit 3, head boom-err", state == ALMAP_SCAN_FAILED && ec == 3 &&
           rc == 8 && memcmp(head, "boom-err", 8) == 0);
    close(got);
    close(cli);

    /* Wall-clock limit: group kill, reaped, grandchild gone. */
    {
        char pidf[] = "/tmp/test_http_gc_XXXXXX";
        int pfd = mkstemp(pidf);
        FILE *f;
        int gpid = 0;
        char path[64];

        close(pfd);
        setenv("FAKE_PIDFILE", pidf, 1);
        setenv("ALMAP_WEB_SCAN_LIMIT_S", "1", 1);
        mk_pair(lfd, port, &srv, &cli);
        t0 = now_ms();
        start(srv, "grand");
        wait_done(lfd, &got);
        t0 = now_ms() - t0;
        almap_http_scan_result(head, sizeof(head), &ec, &state);
        expect("TIMED_OUT after ~1 s", state == ALMAP_SCAN_TIMED_OUT &&
               t0 >= 900 && t0 < 2500 && got == srv);
        expect("limit reports env", almap_http_scan_limit_s() == 1);
        close(got);
        close(cli);
        expect("timeout: no children", no_children());
        f = fopen(pidf, "r");
        if (f) {
            if (fscanf(f, "%d", &gpid) != 1) {
                gpid = 0;
            }
            fclose(f);
        }
        unlink(pidf);
        usleep(100000);
        {
            int alive = 0;
            FILE *sf;

            snprintf(path, sizeof(path), "/proc/%d/stat", gpid);
            sf = gpid > 0 ? fopen(path, "r") : NULL;
            if (sf) {
                char line[256];
                char *rp;

                if (fgets(line, sizeof(line), sf) &&
                    (rp = strrchr(line, ')')) != NULL && rp[2] != 'Z') {
                    alive = 1;
                }
                fclose(sf);
            }
            expect("grandchild killed with the group", gpid > 0 && !alive);
        }
        unsetenv("FAKE_PIDFILE");
    }
    expect("invalid client fd -> -2", start(-1, "echo") == -2);
    mk_pair(lfd, port, &srv, &cli);
    expect("restart after timeout", start(srv, "echo") == 0);
    wait_done(lfd, &got);
    almap_http_scan_result(head, sizeof(head), &ec, &state);
    close(got);
    close(cli);

    /* Requester hang-up: killed within a second, nothing handed back. */
    unsetenv("ALMAP_WEB_SCAN_LIMIT_S");
    mk_pair(lfd, port, &srv, &cli);
    start(srv, "sleep");
    close(cli);
    t0 = now_ms();
    expect("hang-up -> SCAN_DONE", wait_done(lfd, &got) == ALMAP_EV_SCAN_DONE);
    t0 = now_ms() - t0;
    almap_http_scan_result(head, sizeof(head), &ec, &state);
    expect("ABANDONED, client -1, < 1 s", state == ALMAP_SCAN_ABANDONED &&
           got == -1 && t0 < 1000);
    expect("abandoned: no children", no_children());
    expect("abandoned: server fd closed by C", fcntl(srv, F_GETFD) == -1);

    /* Extra bytes from the requester are not a hang-up. */
    mk_pair(lfd, port, &srv, &cli);
    start(srv, "late");
    (void)!write(cli, "JUNKJUNK", 8);
    expect("junk bytes: still SCAN_DONE OK", wait_done(lfd, &got) == ALMAP_EV_SCAN_DONE &&
           got == srv);
    almap_http_scan_result(head, sizeof(head), &ec, &state);
    expect("junk bytes: state OK", state == ALMAP_SCAN_OK);
    almap_http_scan_send_body(got);
    close(got);
    read_all(cli, resp, sizeof(resp));
    close(cli);
    expect("junk bytes: body delivered", strstr(resp, "[late]") != NULL);
    expect("start argument error -> -2", almap_http_scan_start(0, "", "1", "", 0, 0, 0, 0, 0, 0, 0, "") == -2);
    close(lfd);
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "-t") == 0) {
        return fake_scanner(argv[2]);
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    setenv("ALMAP_WEB_REQ_DEADLINE_MS", "300", 1);
    test_next();
    test_scan();
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
