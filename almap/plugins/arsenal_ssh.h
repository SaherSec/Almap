/*
 * plugins/arsenal_ssh.h - SSH helpers for the SSH checks.
 *
 * What a plugin can do without a crypto library: read the identification
 * line, exchange KEXINIT (cleartext), and run the first step of a
 * curve25519 key exchange, whose reply carries the server host key in
 * cleartext. Everything after NEWKEYS is encrypted and is out of scope
 * (no authentication is ever attempted).
 *
 * Verdict words are not allowed in headers; the plugins decide.
 */
#ifndef ARSENAL_SSH_H
#define ARSENAL_SSH_H

#include "arsenal_util.h"

#include <poll.h>

#define AR_SSH_MSG_DISCONNECT 1
#define AR_SSH_MSG_KEXINIT 20
#define AR_SSH_MSG_ECDH_INIT 30
#define AR_SSH_MSG_ECDH_REPLY 31
#define AR_SSH_PACKET_MAX 8192

static inline void ar_ssh_put_u32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static inline unsigned int ar_ssh_get_u32(const unsigned char *p) {
    return ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
           ((unsigned int)p[2] << 8) | (unsigned int)p[3];
}

/* One time budget per connection: identification line plus KEXINIT and the
 * reply must finish within it, however slowly the peer drips bytes. Set by
 * ar_ssh_open (2 x the plugin timeout); plugins run one at a time. */
static long long ar_ssh_deadline_ms;

static inline long long ar_ssh_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* wait for input until the connection deadline; 1 = readable, 0 = out of time/error */
static inline int ar_ssh_wait(int fd) {
    struct pollfd pfd;
    long long left = ar_ssh_deadline_ms - ar_ssh_now_ms();
    int pr;
    if (left <= 0) {
        return 0;
    }
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    pr = poll(&pfd, 1, left > 2000000 ? 2000000 : (int)left);
    return pr > 0 && (pfd.revents & (POLLIN | POLLHUP)) != 0;
}

/* read exactly n bytes before the deadline; 0 on success */
static inline int ar_ssh_read_exact(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r;
        if (!ar_ssh_wait(fd)) {
            return -1;
        }
        r = recv(fd, buf + got, n - got, 0);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

/* read one line (up to LF) before the deadline; returns its length, 0 on failure */
static inline int ar_ssh_read_line(int fd, char *buf, size_t cap) {
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t r;
        if (!ar_ssh_wait(fd)) {
            break;
        }
        r = recv(fd, buf + total, 1, 0);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        total++;
        if (buf[total - 1] == '\n') {
            break;
        }
    }
    buf[total] = '\0';
    return (int)total;
}

/* Connect and exchange identification strings (RFC 4253 4.2): the server may
 * send other lines first, and OpenSSH waits for ours before its KEXINIT.
 * Returns the fd (banner holds the server's line, trimmed) or -1. */

static inline int ar_ssh_open(AlScriptContext *ctx, char *banner, size_t cap) {
    static const char hello[] = "SSH-2.0-Almap\r\n";
    int fd;
    int i;

    if (banner == NULL || cap < 2) {
        return -1;
    }
    banner[0] = '\0';
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    ar_ssh_deadline_ms = ar_ssh_now_ms() + 2LL * ctx->timeout_ms;
    for (i = 0; i < 16; i++) {
        int n = ar_ssh_read_line(fd, banner, cap);
        if (n <= 0) {
            break;
        }
        if (strncmp(banner, "SSH-", 4) == 0) {
            ar_clean(banner);
            if (as_send_all(fd, hello, sizeof(hello) - 1, ctx->timeout_ms) != 0) {
                break;
            }
            return fd;
        }
    }
    banner[0] = '\0';
    close(fd);
    return -1;
}

static inline int ar_ssh_send_packet(int fd, const unsigned char *payload,
                              size_t plen, int timeout_ms) {
    unsigned char buf[2048];
    size_t pad;
    size_t total;

    if (payload == NULL || plen + 5 + 16 > sizeof(buf)) {
        return -1;
    }
    pad = 8 - ((plen + 5) % 8);
    if (pad < 4) {
        pad += 8;
    }
    total = 4 + 1 + plen + pad;
    ar_ssh_put_u32(buf, (unsigned int)(plen + 1 + pad));
    buf[4] = (unsigned char)pad;
    memcpy(buf + 5, payload, plen);
    memset(buf + 5 + plen, 0, pad);
    return as_send_all(fd, buf, total, timeout_ms);
}

/* Read one (unencrypted) packet; returns the payload length or -1. The
 * payload is NUL-terminated; a payload larger than cap is an error, never
 * silently cut. */
static inline int ar_ssh_recv_packet(int fd, unsigned char *payload, size_t cap,
                              int timeout_ms) {
    unsigned char hdr[4];
    static unsigned char buf[AR_SSH_PACKET_MAX + 64];
    unsigned int plen;
    unsigned int pad;
    unsigned int body;

    if (payload == NULL || cap < 2) {
        return -1;
    }
    (void)timeout_ms;
    if (ar_ssh_read_exact(fd, hdr, 4) != 0) {
        return -1;
    }
    plen = ar_ssh_get_u32(hdr);
    if (plen < 6 || plen > sizeof(buf)) {
        return -1;
    }
    if (ar_ssh_read_exact(fd, buf, plen) != 0) {
        return -1;
    }
    pad = buf[0];
    if (pad + 2 > plen) {
        return -1;
    }
    body = plen - 1 - pad;
    if (body > cap - 1) {
        return -1;
    }
    memcpy(payload, buf + 1, body);
    payload[body] = '\0';
    return (int)body;
}

/* Our KEXINIT. kex and hostkeys are the algorithm lists to offer (NULL: a
 * broad default); the cipher, MAC and compression lists are fixed. */
static inline int ar_ssh_build_kexinit(unsigned char *out, size_t cap, const char *kex,
                                const char *hostkeys) {
    const char *lists[10];
    size_t o = 0;
    int i;

    lists[0] = kex != NULL ? kex :
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
        "diffie-hellman-group14-sha256";
    lists[1] = hostkeys != NULL ? hostkeys :
        "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    lists[2] = lists[3] = "aes128-ctr,aes256-ctr";
    lists[4] = lists[5] = "hmac-sha2-256,hmac-sha2-512";
    lists[6] = lists[7] = "none";
    lists[8] = lists[9] = "";
    if (out == NULL || cap < 64) {
        return -1;
    }
    out[o++] = AR_SSH_MSG_KEXINIT;
    for (i = 0; i < 16; i++) {
        out[o++] = (unsigned char)(0x20 + i);
    }
    for (i = 0; i < 10; i++) {
        size_t len = strlen(lists[i]);
        if (o + 4 + len + 5 > cap) {
            return -1;
        }
        ar_ssh_put_u32(out + o, (unsigned int)len);
        o += 4;
        memcpy(out + o, lists[i], len);
        o += len;
    }
    out[o++] = 0;
    ar_ssh_put_u32(out + o, 0);
    o += 4;
    return (int)o;
}

/* Copy name-list 0..9 of a KEXINIT payload into out; 0 on success. */
static inline int ar_ssh_kex_field(const unsigned char *payload, int len, int field,
                            char *out, size_t cap) {
    int off = 17;
    int i;

    if (payload == NULL || len < 17 || field < 0 || field > 9 ||
        out == NULL || cap < 2) {
        return -1;
    }
    out[0] = '\0';
    for (i = 0; i <= field; i++) {
        unsigned int n;
        if (off + 4 > len) {
            return -1;
        }
        n = ar_ssh_get_u32(payload + off);
        off += 4;
        if (n > (unsigned int)(len - off)) {
            return -1;
        }
        if (i == field) {
            if (n >= cap) {
                return -1;                 /* never hand back a cut list */
            }
            memcpy(out, payload + off, n);
            out[n] = '\0';
            return 0;
        }
        off += (int)n;
    }
    return -1;
}

/* Send our KEXINIT and return the server's KEXINIT payload length, or -1.
 * Reading stops at a DISCONNECT. */
static inline int ar_ssh_get_kexinit(int fd, unsigned char *payload, size_t cap,
                              int timeout_ms, const char *kex,
                              const char *hostkeys) {
    unsigned char mine[1024];
    int klen;
    int i;

    klen = ar_ssh_build_kexinit(mine, sizeof(mine), kex, hostkeys);
    if (klen < 0 ||
        ar_ssh_send_packet(fd, mine, (size_t)klen, timeout_ms) != 0) {
        return -1;
    }
    for (i = 0; i < 4; i++) {
        int n = ar_ssh_recv_packet(fd, payload, cap, timeout_ms);
        if (n <= 0 || payload[0] == AR_SSH_MSG_DISCONNECT) {
            return -1;
        }
        if (payload[0] == AR_SSH_MSG_KEXINIT) {
            return n;
        }
    }
    return -1;
}

/* ---- SHA-256 and base64 (for host key fingerprints) ---- */

typedef struct {
    unsigned int h[8];
} ArSha256;

static inline unsigned int ar_rotr(unsigned int x, int n) {
    return (x >> n) | (x << (32 - n));
}

static inline void ar_sha256_block(ArSha256 *c, const unsigned char *p) {
    static const unsigned int k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    unsigned int w[64];
    unsigned int a, b, cc, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ar_ssh_get_u32(p + 4 * i);
    }
    for (i = 16; i < 64; i++) {
        unsigned int s0 = ar_rotr(w[i - 15], 7) ^ ar_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = ar_rotr(w[i - 2], 17) ^ ar_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        unsigned int s1 = ar_rotr(e, 6) ^ ar_rotr(e, 11) ^ ar_rotr(e, 25);
        unsigned int ch = (e & f) ^ (~e & g);
        unsigned int t1 = h + s1 + ch + k[i] + w[i];
        unsigned int s0 = ar_rotr(a, 2) ^ ar_rotr(a, 13) ^ ar_rotr(a, 22);
        unsigned int mj = (a & b) ^ (a & cc) ^ (b & cc);
        unsigned int t2 = s0 + mj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static inline void ar_sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    ArSha256 c;
    unsigned char tail[128];
    size_t full = len - (len % 64);
    size_t rem = len % 64;
    size_t tl = (rem < 56) ? 64 : 128;
    unsigned long long bits = (unsigned long long)len * 8;
    size_t i;

    c.h[0] = 0x6a09e667; c.h[1] = 0xbb67ae85; c.h[2] = 0x3c6ef372; c.h[3] = 0xa54ff53a;
    c.h[4] = 0x510e527f; c.h[5] = 0x9b05688c; c.h[6] = 0x1f83d9ab; c.h[7] = 0x5be0cd19;
    for (i = 0; i < full; i += 64) {
        ar_sha256_block(&c, data + i);
    }
    memset(tail, 0, sizeof(tail));
    memcpy(tail, data + full, rem);
    tail[rem] = 0x80;
    for (i = 0; i < 8; i++) {
        tail[tl - 8 + i] = (unsigned char)(bits >> (56 - 8 * i));
    }
    ar_sha256_block(&c, tail);
    if (tl == 128) {
        ar_sha256_block(&c, tail + 64);
    }
    for (i = 0; i < 8; i++) {
        ar_ssh_put_u32(out + 4 * i, c.h[i]);
    }
}

/* base64 without padding, as ssh-keygen prints SHA256 fingerprints */
static inline void ar_b64_nopad(const unsigned char *in, size_t len, char *out, size_t cap) {
    static const char t[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i;
    size_t o = 0;

    for (i = 0; i < len && o + 5 < cap; i += 3) {
        unsigned int v = (unsigned int)in[i] << 16;
        if (i + 1 < len) v |= (unsigned int)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        if (i + 1 < len) out[o++] = t[(v >> 6) & 63];
        if (i + 2 < len) out[o++] = t[v & 63];
    }
    out[o] = '\0';
}

/* ---- host key through the cleartext half of curve25519-sha256 ---- */

/* Offer exactly one host key algorithm and curve25519-sha256, send
 * KEX_ECDH_INIT, and copy the host key blob (K_S) of KEX_ECDH_REPLY into
 * blob. Returns the blob length, or -1 (the server has no such key, refused,
 * or the exchange failed). Nothing after the reply is read or sent. */
static inline int ar_ssh_get_hostkey_blob(AlScriptContext *ctx, const char *hostkey_alg,
                                   unsigned char *blob, size_t cap) {
    char banner[256];
    static unsigned char pkt[AR_SSH_PACKET_MAX];
    unsigned char init[40];
    int fd;
    int n;
    int i;

    fd = ar_ssh_open(ctx, banner, sizeof(banner));
    if (fd < 0) {
        return -1;
    }
    if (ar_ssh_get_kexinit(fd, pkt, sizeof(pkt), ctx->timeout_ms,
                           "curve25519-sha256", hostkey_alg) < 0) {
        close(fd);
        return -1;
    }
    init[0] = AR_SSH_MSG_ECDH_INIT;
    ar_ssh_put_u32(init + 1, 32);
    for (i = 0; i < 32; i++) {
        init[5 + i] = (unsigned char)(0x41 + i);
    }
    if (ar_ssh_send_packet(fd, init, 37, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    for (i = 0; i < 4; i++) {
        n = ar_ssh_recv_packet(fd, pkt, sizeof(pkt), ctx->timeout_ms);
        if (n <= 0 || pkt[0] == AR_SSH_MSG_DISCONNECT) {
            break;
        }
        if (pkt[0] == AR_SSH_MSG_ECDH_REPLY && n >= 5) {
            unsigned int klen = ar_ssh_get_u32(pkt + 1);
            close(fd);
            if (klen == 0 || klen > (unsigned int)(n - 5) || klen > cap) {
                return -1;
            }
            memcpy(blob, pkt + 5, klen);
            return (int)klen;
        }
    }
    close(fd);
    return -1;
}

/* Describe a host key blob: type, bits, SHA256 fingerprint. 0 on success. */
static inline int ar_ssh_describe_key(const unsigned char *blob, int len, char *out, size_t cap) {
    char type[64];
    char fp[64];
    unsigned char digest[32];
    unsigned int tl;
    int bits = 0;
    int off;

    if (len < 8) {
        return -1;
    }
    tl = ar_ssh_get_u32(blob);
    if (tl == 0 || tl >= sizeof(type) || tl > (unsigned int)(len - 4)) {
        return -1;
    }
    memcpy(type, blob + 4, tl);
    type[tl] = '\0';
    off = 4 + (int)tl;
    if (strcmp(type, "ssh-ed25519") == 0) {
        bits = 256;
    } else if (strcmp(type, "ssh-rsa") == 0) {
        /* string e, string n (mpint): bits = length of n without leading zeros */
        unsigned int el, nl;
        if (off + 4 > len) return -1;
        el = ar_ssh_get_u32(blob + off);
        off += 4;
        if (el > (unsigned int)(len - off) || off + (int)el + 4 > len) return -1;
        off += (int)el;
        nl = ar_ssh_get_u32(blob + off);
        off += 4;
        if (nl == 0 || nl > (unsigned int)(len - off)) return -1;
        {
            unsigned int skip = 0;
            unsigned char top;
            int b = 8;
            while (skip < nl && blob[off + skip] == 0) skip++;
            if (skip == nl) return -1;
            top = blob[off + skip];
            while (b > 0 && (top & (1 << (b - 1))) == 0) b--;
            bits = (int)((nl - skip - 1) * 8) + b;
        }
    } else if (strcmp(type, "ecdsa-sha2-nistp256") == 0) {
        bits = 256;
    } else if (strcmp(type, "ecdsa-sha2-nistp384") == 0) {
        bits = 384;
    } else if (strcmp(type, "ecdsa-sha2-nistp521") == 0) {
        bits = 521;
    }
    ar_sha256(blob, (size_t)len, digest);
    ar_b64_nopad(digest, 32, fp, sizeof(fp));
    if (bits > 0) {
        snprintf(out, cap, "%s %d SHA256:%s", type, bits, fp);
    } else {
        snprintf(out, cap, "%s (size not read) SHA256:%s", type, fp);
    }
    return 0;
}

/* ---- OpenSSH banner versions ---- */

typedef struct {
    int ok;        /* 1: banner is "SSH-x-OpenSSH_<major>.<minor>[pN][ comment]" */
    int major;
    int minor;
    int portable;  /* N of "pN", or -1 when the banner has no pN */
    int vendor;    /* 1: a comment follows the version (Debian-..., Ubuntu-...) */
} ArOpenSshVer;

static inline void ar_ssh_parse_openssh(const char *banner, ArOpenSshVer *v) {
    const char *p;
    char *end;
    long n;

    v->ok = 0; v->major = 0; v->minor = 0; v->portable = -1; v->vendor = 0;
    if (banner == NULL || strncmp(banner, "SSH-", 4) != 0) {
        return;
    }
    p = strchr(banner + 4, '-');
    if (p == NULL || strncmp(p + 1, "OpenSSH_", 8) != 0) {
        return;
    }
    p += 9;
    if (*p < '0' || *p > '9') {
        return;
    }
    n = strtol(p, &end, 10);
    if (end == p || *end != '.' || n > 99) {
        return;
    }
    v->major = (int)n;
    p = end + 1;
    if (*p < '0' || *p > '9') {
        return;
    }
    n = strtol(p, &end, 10);
    if (n > 99) {
        return;
    }
    v->minor = (int)n;
    p = end;
    if (*p == '.') {                      /* 3.9.1p1: a third component */
        p++;
        while (*p >= '0' && *p <= '9') p++;
    }
    if (*p == 'p' && p[1] >= '0' && p[1] <= '9') {
        n = strtol(p + 1, &end, 10);
        if (n > 99) {
            return;                           /* out of range: never wrapped into a level */
        }
        v->portable = (int)n;
        p = end;
    }
    if (*p == ' ' && p[1] != '\0') {
        v->vendor = 1;
    } else if (*p != '\0' && *p != ' ') {
        return;                           /* something we do not understand */
    }
    v->ok = 1;
}

/* ---- the version decisions, kept here so a unit test can check every boundary.
 * Return 1 = in the affected range, 2 = outside it, 0 = not decided by the banner. */

/* CVE-2024-6387: 8.5p1 up to (not including) 9.8p1; below 4.4 depends on old patches */
static inline int ar_ssh_cve_2024_6387(const ArOpenSshVer *v) {
    int ver = v->major * 100 + v->minor;
    if (ver < 404) return 0;
    return (ver >= 805 && ver < 908) ? 1 : 2;
}

/* CVE-2023-38408: before 9.3p2; "9.3" with no pN cannot be placed */
static inline int ar_ssh_cve_2023_38408(const ArOpenSshVer *v) {
    int ver = v->major * 100 + v->minor;
    if (ver == 903 && v->portable < 0) return 0;
    return (ver < 903 || (ver == 903 && v->portable < 2)) ? 1 : 2;
}

/* CVE-2023-25136: only 9.1 */
static inline int ar_ssh_cve_2023_25136(const ArOpenSshVer *v) {
    return (v->major == 9 && v->minor == 1) ? 1 : 2;
}

#endif
