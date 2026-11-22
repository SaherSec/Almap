/* Deterministic unit test for the 413 drainer (static drain_service in
 * c/http.c): it is called directly on a socketpair whose receive side
 * is pre-filled far beyond the per-call budget.
 * Build: gcc -std=c99 -Wall -Wextra -pthread -I c tests/test_drain.c -o /tmp/test_drain
 * (#includes c/http.c so the static functions are visible; override the
 * path with -DHTTP_C='"/path/http.c"' to test another copy.) */
#define _DEFAULT_SOURCE
#ifndef HTTP_C
#define HTTP_C "../c/http.c"
#endif
#include HTTP_C

#include <sys/ioctl.h>

static int failures;

static void expect(const char *name, int cond) {
    printf("%s %s\n", cond ? "ok  " : "FAIL", name);
    if (!cond) {
        failures++;
    }
}

static int unread(int fd) {
    int n = 0;

    if (ioctl(fd, FIONREAD, &n) != 0) {
        return -1;
    }
    return n;
}

int main(void) {
    enum { FILL = 256 * 1024, BUDGET = 16 * 1024, SLACK = 1024 };
    int sv[2];
    int big = 1 << 20;
    static unsigned char blob[FILL];
    struct pollfd pf;
    int which[1] = {0};
    int queued = 0;
    int left;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("FAIL socketpair\n");
        return 1;
    }
    (void)setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
    (void)setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
    memset(blob, 'A', sizeof(blob));
    (void)fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    while (queued < FILL) {
        ssize_t n = send(sv[0], blob, (size_t)(FILL - queued), MSG_NOSIGNAL);

        if (n <= 0) {
            break;
        }
        queued += (int)n;
    }
    printf("     queued %d bytes (%d unread on the drain side)\n", queued,
           unread(sv[1]));
    expect("setup: well over the budget is queued", queued >= 4 * BUDGET &&
           unread(sv[1]) >= 4 * BUDGET);

    drain_init();
    g_drain_fd[0] = sv[1];
    g_drain_end[0] = mono_ms() + 10000; /* deadline far in the future */
    pf.fd = sv[1];
    pf.events = POLLIN;
    pf.revents = POLLIN;
    drain_service(&pf, which, 1, mono_ms());
    left = unread(sv[1]);
    printf("     first call consumed %d bytes, %d left\n", queued - left, left);
    expect("(1) first call consumed at most budget + one recv",
           queued - left <= BUDGET + SLACK);
    expect("(1) fd still open and still holds unread data",
           g_drain_fd[0] == sv[1] && fcntl(sv[1], F_GETFD) != -1 && left > 0);

    /* The deadline passes while data is still unread: closed anyway. */
    g_drain_end[0] = mono_ms() - 1;
    pf.revents = POLLIN;
    drain_service(&pf, which, 1, mono_ms());
    expect("(2) closed at the deadline with data unread", g_drain_fd[0] < 0 &&
           fcntl(sv[1], F_GETFD) == -1);

    close(sv[0]);
    return failures ? 1 : 0;
}
