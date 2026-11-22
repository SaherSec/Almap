/* tests/test_ssh.c - unit tests for plugins/arsenal_ssh.h: the OpenSSH banner
 * parser (vendor and patch-level handling), SHA-256 and base64 (host key
 * fingerprints) against published test vectors, the RSA key size reader, and
 * the identification exchange against a local server that sends lines before
 * its SSH- line.
 * Build: gcc -std=c99 -Wall -Wextra -Werror -Wno-unused-function -I c -I plugins tests/test_ssh.c
 */
#define _GNU_SOURCE
#include "../plugins/arsenal_ssh.h"

#include <signal.h>
#include <sys/wait.h>

static int failures;
#define CHECK(c, what) do { if (!(c)) { printf("FAIL %s\n", what); failures++; } } while (0)

static void parse_case(const char *banner, int ok, int major, int minor, int portable, int vendor) {
    ArOpenSshVer v;
    char what[200];
    ar_ssh_parse_openssh(banner, &v);
    snprintf(what, sizeof(what), "parse '%s'", banner);
    CHECK(v.ok == ok, what);
    if (ok) {
        CHECK(v.major == major && v.minor == minor && v.portable == portable && v.vendor == vendor, what);
    }
}

static void hex(const unsigned char *d, int n, char *out) {
    int i;
    for (i = 0; i < n; i++) snprintf(out + 2 * i, 3, "%02x", d[i]);
}

int main(void) {
    unsigned char dg[32];
    char h[80];
    char b[64];

    parse_case("SSH-2.0-OpenSSH_9.7", 1, 9, 7, -1, 0);
    parse_case("SSH-2.0-OpenSSH_9.7p1", 1, 9, 7, 1, 0);
    parse_case("SSH-2.0-OpenSSH_9.3p2", 1, 9, 3, 2, 0);
    parse_case("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", 1, 9, 6, 1, 1);
    parse_case("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", 1, 9, 2, 1, 1);
    parse_case("SSH-1.99-OpenSSH_3.9.1p1", 1, 3, 9, 1, 0);
    parse_case("SSH-2.0-OpenSSH_10.3", 1, 10, 3, -1, 0);
    parse_case("SSH-2.0-OpenSSH_for_Windows_9.5", 0, 0, 0, 0, 0);
    parse_case("SSH-2.0-dropbear_2022.83", 0, 0, 0, 0, 0);
    parse_case("SSH-2.0-OpenSSH_", 0, 0, 0, 0, 0);
    parse_case("SSH-2.0-OpenSSH_9", 0, 0, 0, 0, 0);
    parse_case("SSH-2.0-OpenSSH_9.xp1", 0, 0, 0, 0, 0);
    parse_case("HTTP/1.1 200 OK", 0, 0, 0, 0, 0);
    parse_case("", 0, 0, 0, 0, 0);

    /* values the review found wrapping into a wrong version or patch level */
    parse_case("SSH-2.0-OpenSSH_0.805", 0, 0, 0, 0, 0);
    parse_case("SSH-2.0-OpenSSH_8.105", 0, 0, 0, 0, 0);
    parse_case("SSH-2.0-OpenSSH_9.3p99999999999999999999", 0, 0, 0, 0, 0);
    parse_case("SSH-2.0-OpenSSH_9.3p4294967298", 0, 0, 0, 0, 0);
    parse_case("SSH-2.0-OpenSSH_9.8", 1, 9, 8, -1, 0);

    /* every version boundary of the three decisions (1 in range, 2 outside, 0 undecided) */
    {
        static const struct { const char *b; int c6387, c38408, c25136; } t[] = {
            { "SSH-2.0-OpenSSH_3.9p1",   0, 1, 2 },
            { "SSH-2.0-OpenSSH_4.3p2",   0, 1, 2 },
            { "SSH-2.0-OpenSSH_4.4p1",   2, 1, 2 },
            { "SSH-2.0-OpenSSH_8.4p1",   2, 1, 2 },
            { "SSH-2.0-OpenSSH_8.5p1",   1, 1, 2 },
            { "SSH-2.0-OpenSSH_9.0p1",   1, 1, 2 },
            { "SSH-2.0-OpenSSH_9.1p1",   1, 1, 1 },
            { "SSH-2.0-OpenSSH_9.2p1",   1, 1, 2 },
            { "SSH-2.0-OpenSSH_9.3p1",   1, 1, 2 },
            { "SSH-2.0-OpenSSH_9.3",     1, 0, 2 },
            { "SSH-2.0-OpenSSH_9.3p2",   1, 2, 2 },
            { "SSH-2.0-OpenSSH_9.4p1",   1, 2, 2 },
            { "SSH-2.0-OpenSSH_9.7p1",   1, 2, 2 },
            { "SSH-2.0-OpenSSH_9.8p1",   2, 2, 2 },
            { "SSH-2.0-OpenSSH_9.9p1",   2, 2, 2 },
            { "SSH-2.0-OpenSSH_10.0p2",  2, 2, 2 },
        };
        size_t i;
        for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
            ArOpenSshVer v;
            char what[120];
            ar_ssh_parse_openssh(t[i].b, &v);
            snprintf(what, sizeof(what), "verdicts for %s", t[i].b);
            CHECK(v.ok && ar_ssh_cve_2024_6387(&v) == t[i].c6387 &&
                  ar_ssh_cve_2023_38408(&v) == t[i].c38408 &&
                  ar_ssh_cve_2023_25136(&v) == t[i].c25136, what);
        }
    }

    /* FIPS 180-4 / NIST vectors: empty, "abc", the 56-byte message (two padding
     * blocks), and 1,000,000 x 'a' */
    ar_sha256((const unsigned char *)"", 0, dg); hex(dg, 32, h);
    CHECK(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0, "sha256 empty");
    ar_sha256((const unsigned char *)"abc", 3, dg); hex(dg, 32, h);
    CHECK(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0, "sha256 abc");
    ar_sha256((const unsigned char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, dg); hex(dg, 32, h);
    CHECK(strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0, "sha256 56 bytes");
    {
        static unsigned char big[1000000];
        memset(big, 'a', sizeof(big));
        ar_sha256(big, sizeof(big), dg); hex(dg, 32, h);
        CHECK(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0, "sha256 million a");
    }
    ar_b64_nopad((const unsigned char *)"f", 1, b, sizeof(b)); CHECK(strcmp(b, "Zg") == 0, "b64 f");
    ar_b64_nopad((const unsigned char *)"fo", 2, b, sizeof(b)); CHECK(strcmp(b, "Zm8") == 0, "b64 fo");
    ar_b64_nopad((const unsigned char *)"foo", 3, b, sizeof(b)); CHECK(strcmp(b, "Zm9v") == 0, "b64 foo");
    ar_b64_nopad((const unsigned char *)"foobar", 6, b, sizeof(b)); CHECK(strcmp(b, "Zm9vYmFy") == 0, "b64 foobar");

    /* RSA blob: e = 65537, n = 3 bytes with a leading zero then 0x80 0x00 0x01 (24 bits) */
    {
        unsigned char blob[64];
        char out[200];
        size_t o = 0;
        ar_ssh_put_u32(blob, 7); memcpy(blob + 4, "ssh-rsa", 7); o = 11;
        ar_ssh_put_u32(blob + o, 3); blob[o + 4] = 1; blob[o + 5] = 0; blob[o + 6] = 1; o += 7;
        ar_ssh_put_u32(blob + o, 4); blob[o + 4] = 0; blob[o + 5] = 0x80; blob[o + 6] = 0; blob[o + 7] = 1; o += 8;
        CHECK(ar_ssh_describe_key(blob, (int)o, out, sizeof(out)) == 0 && strstr(out, "ssh-rsa 24 SHA256:") == out, "rsa key size");
        CHECK(ar_ssh_describe_key(blob, 5, out, sizeof(out)) != 0, "truncated blob refused");
    }
    CHECK(ar_ssh_describe_key((const unsigned char *)"\0\0\0\xff" "abcdefgh", 12, h, sizeof(h)) != 0, "bad type length refused");

    /* identification exchange: lines before the SSH- line are skipped, our
     * line is sent after it, and a peer with no SSH- line is refused */
    {
        int srv = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        socklen_t al = sizeof(a);
        int pass;
        for (pass = 0; pass < 2; pass++) {
            pid_t pid;
            int status = 0;
            AlScriptContext ctx;
            char banner[256];
            int fd;
            memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            srv = socket(AF_INET, SOCK_STREAM, 0);
            if (bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(srv, 1) != 0 ||
                getsockname(srv, (struct sockaddr *)&a, &al) != 0) {
                printf("FAIL cannot listen\n");
                return 1;
            }
            pid = fork();
            if (pid == 0) {
                char got[64];
                int c = accept(srv, NULL, NULL);
                const char *msg = pass == 0 ? "welcome\r\nSSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
                                            : "HTTP/1.1 200 OK\r\nServer: x\r\n\r\n";
                ssize_t n;
                (void)!write(c, msg, strlen(msg));
                n = pass == 0 ? read(c, got, sizeof(got) - 1) : 0;
                if (pass == 0 && n > 0) {
                    got[n] = '\0';
                    _exit(strcmp(got, "SSH-2.0-Almap\r\n") == 0 ? 0 : 3);
                }
                _exit(0);
            }
            memset(&ctx, 0, sizeof(ctx));
            ctx.target_ip = INADDR_LOOPBACK;
            ctx.port = ntohs(a.sin_port);
            ctx.timeout_ms = 1000;
            fd = ar_ssh_open(&ctx, banner, sizeof(banner));
            if (pass == 0) {
                CHECK(fd >= 0 && strcmp(banner, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5") == 0, "pre-banner line skipped");
            } else {
                CHECK(fd < 0 && banner[0] == '\0', "non-SSH peer refused");
            }
            if (fd >= 0) close(fd);
            waitpid(pid, &status, 0);
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "client identification line is exactly SSH-2.0-Almap");
            close(srv);
        }
    }

    /* a peer that drips its banner (no LF) or goes silent must not hold the
     * plugin longer than the connection budget (2 x timeout) */
    {
        int mode;
        for (mode = 0; mode < 2; mode++) {
            int srv = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in a;
            socklen_t al = sizeof(a);
            pid_t pid;
            AlScriptContext ctx;
            char banner[256];
            long long t0, took;
            int fd;
            memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(srv, 1) != 0 ||
                getsockname(srv, (struct sockaddr *)&a, &al) != 0) {
                printf("FAIL cannot listen\n");
                return 1;
            }
            pid = fork();
            if (pid == 0) {
                int c = accept(srv, NULL, NULL);
                int k;
                if (mode == 0) {
                    for (k = 0; k < 60; k++) { (void)!write(c, "x", 1); usleep(50000); }
                } else {
                    (void)!write(c, "SSH-2.0-OpenSSH_9.7\r\n", 21);
                    sleep(4);
                }
                _exit(0);
            }
            memset(&ctx, 0, sizeof(ctx));
            ctx.target_ip = INADDR_LOOPBACK;
            ctx.port = ntohs(a.sin_port);
            ctx.timeout_ms = 300;
            t0 = ar_ssh_now_ms();
            fd = ar_ssh_open(&ctx, banner, sizeof(banner));
            if (mode == 1) {
                unsigned char pk[64];
                CHECK(fd >= 0, "banner then silence: open succeeds");
                CHECK(ar_ssh_recv_packet(fd, pk, sizeof(pk), ctx.timeout_ms) < 0, "silent peer: no packet");
            } else {
                CHECK(fd < 0, "dripping peer refused");
            }
            took = ar_ssh_now_ms() - t0;
            CHECK(took < 900, "total time stays inside the connection budget");
            if (fd >= 0) close(fd);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            close(srv);
        }
    }

    if (failures == 0) {
        printf("test_ssh: ok\n");
        return 0;
    }
    printf("test_ssh: %d FAIL\n", failures);
    return 1;
}
