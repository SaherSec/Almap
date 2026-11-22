/*
 * plugins/arsenal_smbx.h - SMB helpers of the verified SMB checks.
 *
 * One time budget per connection, SMB1/SMB2 requests built byte by byte,
 * every reply length-checked. No authentication is ever attempted: the
 * NTLMSSP exchange stops after the server's CHALLENGE, which carries the
 * computer and domain names in cleartext.
 *
 * Verdict words are not allowed in headers; the plugins decide.
 */
#ifndef ARSENAL_SMBX_H
#define ARSENAL_SMBX_H

#include "arsenal_util.h"

#include <poll.h>

#define ARX_SMB_MAX 16384
static long long arx_deadline_ms;

static inline long long arx_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static inline int arx_wait(int fd) {
    struct pollfd pfd;
    long long left = arx_deadline_ms - arx_now_ms();
    int pr;
    if (left <= 0) {
        return 0;
    }
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    pr = poll(&pfd, 1, left > 2000000 ? 2000000 : (int)left);
    if (pr < 0 && errno == EINTR) {
        return arx_wait(fd);        /* a signal is not a timeout: wait out the rest */
    }
    return pr > 0 && (pfd.revents & (POLLIN | POLLHUP)) != 0;
}

static inline int arx_read_exact(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r;
        if (!arx_wait(fd)) {
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

/* connect and start the connection's time budget (2 x the plugin timeout) */
static inline int arx_open(AlScriptContext *ctx) {
    int fd = as_connect(ctx);
    if (fd >= 0) {
        arx_deadline_ms = arx_now_ms() + 2LL * ctx->timeout_ms;
    }
    return fd;
}

/* send one NetBIOS-framed message (msg = the SMB message without the 4-byte
 * frame header) and read one reply; returns the reply length (frame header
 * stripped) or -1. Session keep-alives (0x85) are skipped. */
static inline int arx_txrx(int fd, const unsigned char *msg, size_t len,
                           unsigned char *resp, size_t cap, int timeout_ms) {
    unsigned char hdr[4];
    unsigned char frame[1024];
    unsigned int n;
    int tries;

    if (len + 4 > sizeof(frame) || resp == NULL || cap < 64) {
        return -1;
    }
    frame[0] = 0;
    frame[1] = (unsigned char)((len >> 16) & 255u);
    frame[2] = (unsigned char)((len >> 8) & 255u);
    frame[3] = (unsigned char)(len & 255u);
    memcpy(frame + 4, msg, len);
    if (as_send_all(fd, frame, len + 4, timeout_ms) != 0) {
        return -1;
    }
    for (tries = 0; tries < 4; tries++) {
        if (arx_read_exact(fd, hdr, 4) != 0) {
            return -1;
        }
        n = ((unsigned int)hdr[1] << 16) | ((unsigned int)hdr[2] << 8) | hdr[3];
        if (hdr[0] == 0x85 && n == 0) {
            continue;
        }
        if (hdr[0] != 0 || n < 4 || n > cap) {
            return -1;
        }
        if (arx_read_exact(fd, resp, n) != 0) {
            return -1;
        }
        return (int)n;
    }
    return -1;
}

static inline unsigned int arx_le16(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8);
}
static inline unsigned int arx_le32(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}
static inline void arx_put16(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 255u);
    p[1] = (unsigned char)((v >> 8) & 255u);
}
static inline void arx_put32(unsigned char *p, unsigned int v) {
    arx_put16(p, v & 0xFFFFu);
    arx_put16(p + 2, v >> 16);
}

/* ---- SMB2 NEGOTIATE ---- */

#define ARX_D_202 0x0202
#define ARX_D_210 0x0210
#define ARX_D_300 0x0300
#define ARX_D_302 0x0302
#define ARX_D_311 0x0311

static inline const char *arx_smb2_name(unsigned int d) {
    switch (d) {
    case ARX_D_202: return "SMB 2.0.2";
    case ARX_D_210: return "SMB 2.1";
    case ARX_D_300: return "SMB 3.0";
    case ARX_D_302: return "SMB 3.0.2";
    case ARX_D_311: return "SMB 3.1.1";
    default: return NULL;
    }
}

/* Build an SMB2 NEGOTIATE offering the n dialects in d[]. When 0x0311 is
 * among them the request carries the pre-authentication integrity context
 * that SMB 3.1.1 requires. Returns the message length or 0. */
static inline size_t arx_smb2_neg_req(unsigned char *out, size_t cap,
                                      const unsigned int *d, int n) {
    size_t pos, ctx_off = 0;
    int i, has311 = 0;

    if (n < 1 || n > 5 || cap < 256) {
        return 0;
    }
    memset(out, 0, cap);
    out[0] = 0xFE; out[1] = 'S'; out[2] = 'M'; out[3] = 'B';
    arx_put16(out + 4, 64);          /* StructureSize */
    arx_put16(out + 14, 1);          /* CreditRequest */
    arx_put16(out + 64, 36);         /* body StructureSize */
    arx_put16(out + 66, (unsigned int)n);
    arx_put16(out + 68, 1);          /* SecurityMode: signing enabled */
    memcpy(out + 76, "AlmapScanGuid-01", 16);   /* ClientGuid; Capabilities (72) stays 0 */
    pos = 100;
    for (i = 0; i < n; i++) {
        arx_put16(out + pos, d[i]);
        pos += 2;
        if (d[i] == ARX_D_311) {
            has311 = 1;
        }
    }
    if (has311) {
        ctx_off = (pos + 7) & ~(size_t)7;
        arx_put32(out + 92, (unsigned int)ctx_off);   /* NegotiateContextOffset */
        arx_put16(out + 96, 1);                       /* NegotiateContextCount */
        arx_put16(out + ctx_off, 1);                  /* SMB2_PREAUTH_INTEGRITY_CAPABILITIES */
        arx_put16(out + ctx_off + 2, 38);             /* DataLength */
        arx_put16(out + ctx_off + 8, 1);              /* HashAlgorithmCount */
        arx_put16(out + ctx_off + 10, 32);            /* SaltLength */
        arx_put16(out + ctx_off + 12, 1);             /* SHA-512 */
        memcpy(out + ctx_off + 14, "AlmapPreauthSalt-0123456789abcd", 31);
        pos = ctx_off + 8 + 38;
    }
    return pos;
}

typedef struct {
    int ok;                 /* a well-formed successful NEGOTIATE response */
    unsigned int status;    /* NT status of the reply (0 = success) */
    unsigned int dialect;
    unsigned int security_mode;   /* bit 0 signing enabled, bit 1 signing required */
    unsigned int capabilities;
    int compression_ctx;    /* a compression capabilities context is present */
} ArxSmb2Neg;

/* Parse an SMB2 NEGOTIATE response (frame header already stripped). ok = 0
 * for anything that is not a complete, successful reply. */
static inline void arx_smb2_neg_parse(const unsigned char *r, int len, ArxSmb2Neg *o) {
    memset(o, 0, sizeof(*o));
    o->status = 0xFFFFFFFFu;
    if (r == NULL || len < 72 || r[0] != 0xFE || r[1] != 'S' || r[2] != 'M' || r[3] != 'B') {
        return;
    }
    o->status = arx_le32(r + 8);
    if (arx_le16(r + 12) != 0 || o->status != 0 || len < 128 || arx_le16(r + 64) != 65) {
        return;
    }
    o->dialect = arx_le16(r + 68);
    if (arx_smb2_name(o->dialect) == NULL) {      /* e.g. the 0x02FF wildcard: not a dialect we offered */
        return;
    }
    o->security_mode = arx_le16(r + 66);
    o->capabilities = arx_le32(r + 88);
    if (o->dialect == ARX_D_311) {
        unsigned int cnt = arx_le16(r + 70);
        size_t off = arx_le32(r + 124);
        size_t ulen = (size_t)len;
        unsigned int i;
        for (i = 0; i < cnt; i++) {
            size_t dl;
            if (off > ulen || ulen - off < 8) {
                break;
            }
            dl = arx_le16(r + off + 2);
            if (dl > ulen - off - 8) {
                break;
            }
            if (arx_le16(r + off) == 3) {
                o->compression_ctx = 1;
            }
            off = (off + 8 + dl + 7) & ~(size_t)7;
        }
    }
    o->ok = 1;
}

/* One SMB2 NEGOTIATE on a fresh connection. Returns 1 (reply parsed into o),
 * 0 (the peer answered with something else), -1 (no connection / no reply).
 * With fd_keep the connection stays open on success. */
static inline int arx_smb2_negotiate(AlScriptContext *ctx, const unsigned int *d, int n,
                                     ArxSmb2Neg *o, int *fd_keep) {
    unsigned char req[512];
    unsigned char resp[ARX_SMB_MAX];
    size_t len = arx_smb2_neg_req(req, sizeof(req), d, n);
    int fd, r;

    memset(o, 0, sizeof(*o));
    if (len == 0) {
        return -1;
    }
    fd = arx_open(ctx);
    if (fd < 0) {
        return -1;
    }
    r = arx_txrx(fd, req, len, resp, sizeof(resp), ctx->timeout_ms);
    if (r < 0) {
        close(fd);
        return -1;
    }
    arx_smb2_neg_parse(resp, r, o);
    if (fd_keep != NULL && o->ok) {
        *fd_keep = fd;
    } else {
        close(fd);
    }
    return o->ok ? 1 : 0;
}

/* ---- SMB1 NEGOTIATE (NT LM 0.12 only) ---- */

typedef struct {
    int ok;                 /* reply selected NT LM 0.12 */
    unsigned int security_mode;   /* 0x01 user level, 0x02 challenge/response,
                                     0x04 signing enabled, 0x08 signing required */
    unsigned int capabilities;
} ArxSmb1Neg;

static inline size_t arx_smb1_hdr(unsigned char *s, unsigned int cmd, unsigned int flags2) {
    memset(s, 0, 32);
    s[0] = 0xFF; s[1] = 'S'; s[2] = 'M'; s[3] = 'B';
    s[4] = (unsigned char)cmd;
    s[9] = 0x18;
    arx_put16(s + 10, flags2);
    arx_put16(s + 26, 0xFFFE);       /* PID */
    return 32;
}

static inline void arx_smb1_neg_parse(const unsigned char *r, int len, ArxSmb1Neg *o) {
    memset(o, 0, sizeof(*o));
    if (r == NULL || len < 57 || r[0] != 0xFF || r[1] != 'S' || r[2] != 'M' || r[3] != 'B' ||
        r[4] != 0x72 || arx_le32(r + 5) != 0 || r[32] != 17) {
        return;
    }
    if (arx_le16(r + 33) != 0) {      /* dialect index: 0 = NT LM 0.12, 0xFFFF = none */
        return;
    }
    o->security_mode = r[35];
    o->capabilities = arx_le32(r + 52);
    o->ok = 1;
}

static inline int arx_smb1_negotiate(AlScriptContext *ctx, ArxSmb1Neg *o, int *fd_keep) {
    static const char dialect[] = "\x02NT LM 0.12";
    unsigned char req[128];
    unsigned char resp[ARX_SMB_MAX];
    size_t n = arx_smb1_hdr(req, 0x72, 0xC843);
    int fd, r;

    memset(o, 0, sizeof(*o));
    req[n++] = 0;                                  /* WordCount */
    arx_put16(req + n, (unsigned int)sizeof(dialect));   /* includes the NUL */
    n += 2;
    memcpy(req + n, dialect, sizeof(dialect));
    n += sizeof(dialect);
    fd = arx_open(ctx);
    if (fd < 0) {
        return -1;
    }
    r = arx_txrx(fd, req, n, resp, sizeof(resp), ctx->timeout_ms);
    if (r < 0) {
        close(fd);
        return -1;
    }
    arx_smb1_neg_parse(resp, r, o);
    if (fd_keep != NULL && o->ok) {
        *fd_keep = fd;
    } else {
        close(fd);
    }
    return o->ok ? 1 : 0;
}

/* ---- NTLMSSP: the NEGOTIATE message and the CHALLENGE parser ---- */

static inline size_t arx_ntlm_negotiate(unsigned char *out, size_t cap) {
    static const unsigned char ver[8] = {6, 1, 0xB1, 0x1D, 0, 0, 0, 15};
    if (cap < 40) {
        return 0;
    }
    memset(out, 0, 40);
    memcpy(out, "NTLMSSP\0", 8);
    arx_put32(out + 8, 1);
    arx_put32(out + 12, 0xE2088297u);
    memcpy(out + 32, ver, 8);
    return 40;
}

/* UTF-16LE to printable ASCII ('?' for anything else), NUL terminated */
static inline void arx_u16(const unsigned char *src, size_t nbytes, char *dst, size_t cap) {
    size_t i, o = 0;
    if (cap == 0) {
        return;
    }
    for (i = 0; i + 1 < nbytes && o + 1 < cap; i += 2) {
        unsigned int c = arx_le16(src + i);
        if (c == 0) {
            break;
        }
        dst[o++] = (c >= 32 && c < 127) ? (char)c : '?';
    }
    dst[o] = '\0';
}

typedef struct {
    int ok;
    char nb_computer[48];
    char nb_domain[48];
    char dns_computer[96];
    char dns_domain[96];
    int has_version;
    unsigned int os_major, os_minor, os_build;
} ArxNtlm;

/* find an NTLMSSP CHALLENGE (type 2) in a security blob (raw or SPNEGO-wrapped) */
static inline void arx_ntlm_parse(const unsigned char *blob, int len, ArxNtlm *o) {
    int i;
    memset(o, 0, sizeof(*o));
    for (i = 0; blob != NULL && i + 48 <= len; i++) {
        const unsigned char *m = blob + i;
        unsigned int flags, tlen, toff, p;
        if (memcmp(m, "NTLMSSP\0", 8) != 0 || arx_le32(m + 8) != 2) {
            continue;
        }
        flags = arx_le32(m + 20);
        tlen = arx_le16(m + 40);
        toff = arx_le32(m + 44);
        if (toff > (unsigned int)(len - i) || tlen > (unsigned int)(len - i) - toff) {
            return;
        }
        if ((flags & 0x02000000u) != 0 && i + 56 <= len) {
            o->has_version = 1;
            o->os_major = m[48];
            o->os_minor = m[49];
            o->os_build = arx_le16(m + 50);
        }
        for (p = 0; p + 4 <= tlen;) {
            unsigned int id = arx_le16(m + toff + p);
            unsigned int al = arx_le16(m + toff + p + 2);
            const unsigned char *v = m + toff + p + 4;
            if (id == 0 || p + 4 + al > tlen) {
                break;
            }
            if (id == 1) arx_u16(v, al, o->nb_computer, sizeof(o->nb_computer));
            else if (id == 2) arx_u16(v, al, o->nb_domain, sizeof(o->nb_domain));
            else if (id == 3) arx_u16(v, al, o->dns_computer, sizeof(o->dns_computer));
            else if (id == 4) arx_u16(v, al, o->dns_domain, sizeof(o->dns_domain));
            p += 4 + al;
        }
        o->ok = 1;
        return;
    }
}

/* ---- SMB1 extended-security SESSION_SETUP (NTLMSSP NEGOTIATE only) ---- */

typedef struct {
    int ok;
    ArxNtlm ntlm;
    char native_os[64];
    char native_lanman[64];
    char primary_domain[48];
} ArxSmb1Sess;

/* Parse the reply to the SESSION_SETUP: status 0xC0000016 (more processing
 * required) carries the CHALLENGE blob and the native OS / LAN Manager /
 * domain strings (UTF-16, after an alignment byte). */
static inline void arx_smb1_sess_parse(const unsigned char *r, int len, ArxSmb1Sess *o) {
    unsigned int blen, bc, off, dpos;
    int i;
    memset(o, 0, sizeof(*o));
    if (r == NULL || len < 43 || r[0] != 0xFF || r[1] != 'S' || r[2] != 'M' || r[3] != 'B' ||
        r[4] != 0x73 || arx_le32(r + 5) != 0xC0000016u || r[32] != 4) {
        return;
    }
    blen = arx_le16(r + 39);
    bc = arx_le16(r + 41);
    off = 43;                                   /* start of the data bytes */
    if (off + bc > (unsigned int)len || blen > bc) {
        return;
    }
    arx_ntlm_parse(r + off, (int)blen, &o->ntlm);
    dpos = off + blen;
    if ((dpos & 1u) != 0) {
        dpos++;                                 /* strings start on an even offset */
    }
    for (i = 0; i < 3 && dpos + 2 <= off + bc; i++) {
        unsigned int e = dpos;
        char *dst = (i == 0) ? o->native_os : (i == 1) ? o->native_lanman : o->primary_domain;
        size_t cap = (i == 0) ? sizeof(o->native_os) : (i == 1) ? sizeof(o->native_lanman) : sizeof(o->primary_domain);
        while (e + 2 <= off + bc && (r[e] != 0 || r[e + 1] != 0)) {
            e += 2;
        }
        arx_u16(r + dpos, e - dpos, dst, cap);
        dpos = e + 2;
    }
    o->ok = 1;
}

/* On an SMB1 connection that negotiated NT LM 0.12: send SESSION_SETUP with
 * a NTLMSSP NEGOTIATE and parse the reply. 1 = parsed, 0 = other reply, -1 = none. */
static inline int arx_smb1_session(int fd, int timeout_ms, ArxSmb1Sess *o) {
    unsigned char req[256];
    unsigned char resp[ARX_SMB_MAX];
    unsigned char ntlm[48];
    size_t nl = arx_ntlm_negotiate(ntlm, sizeof(ntlm));
    size_t n = arx_smb1_hdr(req, 0x73, 0xC843);
    size_t datastart, i, bytes;
    static const char nat[] = "almap";
    int r;

    memset(o, 0, sizeof(*o));
    req[n++] = 12;                                  /* WordCount */
    req[n++] = 0xFF; req[n++] = 0;                  /* AndX: none */
    arx_put16(req + n, 0); n += 2;
    arx_put16(req + n, 4356); n += 2;               /* MaxBufferSize */
    arx_put16(req + n, 16); n += 2;                 /* MaxMpxCount */
    arx_put16(req + n, 0); n += 2;                  /* VcNumber */
    arx_put32(req + n, 0); n += 4;                  /* SessionKey */
    arx_put16(req + n, (unsigned int)nl); n += 2;   /* SecurityBlobLength */
    arx_put32(req + n, 0); n += 4;
    arx_put32(req + n, 0x8000D05Cu); n += 4;        /* capabilities: extended security */
    datastart = n + 2;
    bytes = nl + (((datastart + nl) & 1u) != 0 ? 1 : 0) + 2 * (sizeof(nat) * 2);
    arx_put16(req + n, (unsigned int)bytes);
    n += 2;
    memcpy(req + n, ntlm, nl);
    n += nl;
    if (((datastart + nl) & 1u) != 0) {
        req[n++] = 0;
    }
    for (i = 0; i < 2; i++) {
        size_t k;
        for (k = 0; k < sizeof(nat); k++) {
            req[n++] = (unsigned char)nat[k];
            req[n++] = 0;
        }
    }
    r = arx_txrx(fd, req, n, resp, sizeof(resp), timeout_ms);
    if (r < 0) {
        return -1;
    }
    arx_smb1_sess_parse(resp, r, o);
    return o->ok ? 1 : 0;
}

/* anonymous SMB1 negotiate + session setup on one connection.
 * 1 = session reply parsed, 2 = SMB1 negotiated but the session reply was not
 * usable (no reply, or not the expected status), 0 = SMB1 not accepted,
 * -1 = no SMB response */
static inline int arx_smb1_probe(AlScriptContext *ctx, ArxSmb1Neg *neg, ArxSmb1Sess *sess) {
    int fd = -1;
    int r = arx_smb1_negotiate(ctx, neg, &fd);
    memset(sess, 0, sizeof(*sess));
    if (r != 1) {
        return r;
    }
    r = arx_smb1_session(fd, ctx->timeout_ms, sess);
    close(fd);
    return r == 1 ? 1 : 2;
}

/* ---- SMB2 SESSION_SETUP (NTLMSSP NEGOTIATE only) ---- */

typedef struct {
    int ok;
    ArxNtlm ntlm;
} ArxSmb2Sess;

static inline void arx_smb2_sess_parse(const unsigned char *r, int len, ArxSmb2Sess *o) {
    unsigned int off, bl;
    memset(o, 0, sizeof(*o));
    if (r == NULL || len < 72 || r[0] != 0xFE || r[1] != 'S' || r[2] != 'M' || r[3] != 'B' ||
        arx_le32(r + 8) != 0xC0000016u || arx_le16(r + 12) != 1 || arx_le16(r + 64) != 9) {
        return;
    }
    off = arx_le16(r + 68);
    bl = arx_le16(r + 70);
    if (off < 72 || off > (unsigned int)len || bl > (unsigned int)len - off) {
        return;
    }
    arx_ntlm_parse(r + off, (int)bl, &o->ntlm);
    o->ok = 1;
}

static inline int arx_smb2_session(int fd, int timeout_ms, ArxSmb2Sess *o) {
    unsigned char req[256];
    unsigned char resp[ARX_SMB_MAX];
    size_t nl;
    int r;

    memset(o, 0, sizeof(*o));
    memset(req, 0, sizeof(req));
    req[0] = 0xFE; req[1] = 'S'; req[2] = 'M'; req[3] = 'B';
    arx_put16(req + 4, 64);
    arx_put16(req + 12, 1);                         /* Command: SESSION_SETUP */
    arx_put16(req + 14, 1);                         /* CreditRequest */
    req[24] = 1;                                    /* MessageId 1 */
    arx_put16(req + 64, 25);                        /* StructureSize */
    req[67] = 1;                                    /* SecurityMode */
    arx_put16(req + 76, 88);                        /* SecurityBufferOffset */
    nl = arx_ntlm_negotiate(req + 88, sizeof(req) - 88);
    if (nl == 0) {
        return -1;
    }
    arx_put16(req + 78, (unsigned int)nl);
    r = arx_txrx(fd, req, 88 + nl, resp, sizeof(resp), timeout_ms);
    if (r < 0) {
        return -1;
    }
    arx_smb2_sess_parse(resp, r, o);
    return o->ok ? 1 : 0;
}

/* ---- Samba version from the SMB1 "Native LAN Manager" string ---- */

typedef struct {
    int ok;
    int major, minor, patch;
    int vendor;             /* text after the patch level (-Debian, -SerNet-..., rc1) */
} ArxSambaVer;

static inline void arx_samba_parse(const char *s, ArxSambaVer *v) {
    const char *p = s;
    long a[3];
    int i;
    memset(v, 0, sizeof(*v));
    if (s == NULL || strncmp(s, "Samba ", 6) != 0) {
        return;
    }
    p += 6;
    for (i = 0; i < 3; i++) {
        char *end;
        if (!isdigit((unsigned char)*p)) {
            return;
        }
        a[i] = strtol(p, &end, 10);
        if (end - p > 4 || a[i] < 0 || a[i] > (i == 0 ? 99 : 999)) {
            return;
        }
        p = end;
        if (i < 2) {
            if (*p != '.') {
                return;
            }
            p++;
        }
    }
    v->ok = 1;
    v->major = (int)a[0];
    v->minor = (int)a[1];
    v->patch = (int)a[2];
    v->vendor = (*p != '\0');
}

static inline int arx_samba_cmp(const ArxSambaVer *v, int ma, int mi, int pa) {
    if (v->major != ma) return v->major < ma ? -1 : 1;
    if (v->minor != mi) return v->minor < mi ? -1 : 1;
    if (v->patch != pa) return v->patch < pa ? -1 : 1;
    return 0;
}

/* CVE-2017-7494: 3.5.0 and later, fixed in 4.4.14, 4.5.10 and 4.6.4.
 * 1 = inside the affected range, 2 = outside, 0 = not decided. */
static inline int arx_samba_cve_2017_7494(const ArxSambaVer *v) {
    if (!v->ok) return 0;
    if (arx_samba_cmp(v, 3, 5, 0) < 0) return 2;
    if (arx_samba_cmp(v, 4, 4, 14) < 0) return 1;
    if (v->major == 4 && v->minor == 4) return 2;
    if (v->major == 4 && v->minor == 5) return arx_samba_cmp(v, 4, 5, 10) < 0 ? 1 : 2;
    if (v->major == 4 && v->minor == 6) return arx_samba_cmp(v, 4, 6, 4) < 0 ? 1 : 2;
    return 2;
}

/* CVE-2021-44142 (vfs_fruit): 4.1 up to 4.13.16, 4.14.0-4.14.11 and
 * 4.15.0-4.15.4. Below 4.1 is not decided. */
static inline int arx_samba_cve_2021_44142(const ArxSambaVer *v) {
    if (!v->ok) return 0;
    if (arx_samba_cmp(v, 4, 1, 0) < 0) return 0;
    if (arx_samba_cmp(v, 4, 13, 17) < 0) return 1;
    if (v->major == 4 && v->minor == 13) return 2;
    if (v->major == 4 && v->minor == 14) return arx_samba_cmp(v, 4, 14, 12) < 0 ? 1 : 2;
    if (v->major == 4 && v->minor == 15) return arx_samba_cmp(v, 4, 15, 5) < 0 ? 1 : 2;
    return 2;
}

#endif /* ARSENAL_SMBX_H */
