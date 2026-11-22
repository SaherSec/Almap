/*
 * plugins/arsenal_tls.h - minimal TLS record/handshake helpers for the
 * ssl-* plugins. Raw TCP, fixed buffers, no OpenSSL.
 *
 *  - one IANA suite table (ar_tls_suites): names, CBC detection and the
 *    list the enumeration plugin probes all come from it;
 *  - ar_tls_recv_record reads one record WITH its content type;
 *  - ar_tls_read_flight parses the server's handshake flight as a stream,
 *    so handshake messages may be split across records or packed several
 *    to a record;
 *  - ar_tls_connect_hello connects, sends a ClientHello and reads the
 *    flight.
 *
 * The helpers only read: no application data is decrypted and no key
 * material is used. Use only on networks you own or have permission to scan.
 */
#ifndef ARSENAL_TLS_H
#define ARSENAL_TLS_H

#include "arsenal_util.h"

#define AR_TLS_CCS 20
#define AR_TLS_ALERT 21
#define AR_TLS_HANDSHAKE 22
#define AR_TLS_APPDATA 23
#define AR_TLS_HEARTBEAT 24

/* Largest record payload a peer may send (16384 + expansion). */
#define AR_TLS_MAX_RECORD 18432

typedef struct {
    unsigned short id;
    const char *name;
} ar_tls_suite;

/* IANA TLS cipher suites that the plugins know about, sorted by id. */
static const ar_tls_suite ar_tls_suites[] = {
    {0x0001, "TLS_RSA_WITH_NULL_MD5"},
    {0x0002, "TLS_RSA_WITH_NULL_SHA"},
    {0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"},
    {0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
    {0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
    {0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"},
    {0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0009, "TLS_RSA_WITH_DES_CBC_SHA"},
    {0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"},
    {0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"},
    {0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA"},
    {0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"},
    {0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"},
    {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
    {0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"},
    {0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"},
    {0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256"},
    {0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256"},
    {0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"},
    {0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"},
    {0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"},
    {0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"},
    {0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
    {0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"},
    {0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"},
    {0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"},
    {0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"},
    {0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"},
    {0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"},
    {0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
    {0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"},
    {0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
    {0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"},
    {0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"},
    {0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
    {0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
    {0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
    {0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    {0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
    {0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
};
#define AR_TLS_NSUITES ((int)(sizeof(ar_tls_suites) / sizeof(ar_tls_suites[0])))

/* The IANA name of suite `c`, or NULL if it is not in the table. */
static inline const char *ar_tls_cipher_name(unsigned int c) {
    int i;

    for (i = 0; i < AR_TLS_NSUITES; i++) {
        if (ar_tls_suites[i].id == c) {
            return ar_tls_suites[i].name;
        }
    }
    return NULL;
}

/* A suite name for printing: the IANA name or "0xNNNN" (into buf). */
static inline const char *ar_tls_cipher_label(unsigned int c, char *buf,
                                              size_t cap) {
    const char *n = ar_tls_cipher_name(c);

    if (n != NULL) {
        return n;
    }
    snprintf(buf, cap, "0x%04X", c);
    return buf;
}

/* 1 if suite `c` is a CBC suite (the POODLE-relevant kind). */
static inline int ar_tls_is_cbc(unsigned int c) {
    const char *n = ar_tls_cipher_name(c);

    return n != NULL && strstr(n, "_CBC_") != NULL;
}

/* Fill ids[] with the id of every suite in the table (CBC only if cbc_only);
 * returns the count. */
static inline int ar_tls_suite_ids(unsigned short *ids, int cap, int cbc_only) {
    int i;
    int n = 0;

    for (i = 0; i < AR_TLS_NSUITES && n < cap; i++) {
        if (!cbc_only || ar_tls_is_cbc(ar_tls_suites[i].id)) {
            ids[n++] = ar_tls_suites[i].id;
        }
    }
    return n;
}

static inline const char *ar_tls_version_name(unsigned int v) {
    switch (v) {
        case 0x0300: return "SSLv3";
        case 0x0301: return "TLSv1.0";
        case 0x0302: return "TLSv1.1";
        case 0x0303: return "TLSv1.2";
        case 0x0304: return "TLSv1.3";
        default: return "unknown";
    }
}

/*
 * ar_tls_client_hello: build a ClientHello record into out. `ciphers` is
 * the offered suite list. Extensions are added for TLS 1.0 and later
 * (groups, point formats, signature algorithms, renegotiation_info, and
 * the heartbeat extension if `heartbeat`). Returns the record length or -1.
 */
static inline int ar_tls_client_hello(unsigned char *out, size_t cap,
                                      unsigned int version,
                                      const unsigned short *ciphers, int nc,
                                      int heartbeat) {
    unsigned char body[1024];
    size_t b = 0;
    size_t ext_len_pos;
    size_t ext_start;
    int i;

    if (out == NULL || cap < 128 || ciphers == NULL || nc < 1 || nc > 200) {
        return -1;
    }
    memset(body, 0, sizeof(body));
    body[b++] = (unsigned char)(version >> 8);
    body[b++] = (unsigned char)(version & 255u);
    for (i = 0; i < 32; i++) {
        body[b++] = (unsigned char)(0x30 + i);
    }
    body[b++] = 0; /* session id length */
    body[b++] = (unsigned char)((nc * 2) >> 8);
    body[b++] = (unsigned char)((nc * 2) & 255u);
    for (i = 0; i < nc; i++) {
        body[b++] = (unsigned char)(ciphers[i] >> 8);
        body[b++] = (unsigned char)(ciphers[i] & 255u);
    }
    body[b++] = 1; /* one compression method: null */
    body[b++] = 0;
    if (version >= 0x0301) {
        ext_len_pos = b;
        b += 2;
        ext_start = b;
        /* supported_groups: x25519, secp256r1, secp384r1 */
        body[b++] = 0x00; body[b++] = 0x0A;
        body[b++] = 0x00; body[b++] = 0x08;
        body[b++] = 0x00; body[b++] = 0x06;
        body[b++] = 0x00; body[b++] = 0x1D;
        body[b++] = 0x00; body[b++] = 0x17;
        body[b++] = 0x00; body[b++] = 0x18;
        /* ec_point_formats: uncompressed */
        body[b++] = 0x00; body[b++] = 0x0B;
        body[b++] = 0x00; body[b++] = 0x02;
        body[b++] = 0x01; body[b++] = 0x00;
        /* signature_algorithms */
        body[b++] = 0x00; body[b++] = 0x0D;
        body[b++] = 0x00; body[b++] = 0x0A;
        body[b++] = 0x00; body[b++] = 0x08;
        body[b++] = 0x04; body[b++] = 0x03;
        body[b++] = 0x08; body[b++] = 0x04;
        body[b++] = 0x04; body[b++] = 0x01;
        body[b++] = 0x05; body[b++] = 0x01;
        /* renegotiation_info */
        body[b++] = 0xFF; body[b++] = 0x01;
        body[b++] = 0x00; body[b++] = 0x01;
        body[b++] = 0x00;
        if (heartbeat) {
            body[b++] = 0x00; body[b++] = 0x0F;
            body[b++] = 0x00; body[b++] = 0x01;
            body[b++] = 0x01; /* peer_allowed_to_send */
        }
        body[ext_len_pos] = (unsigned char)((b - ext_start) >> 8);
        body[ext_len_pos + 1] = (unsigned char)((b - ext_start) & 255u);
    }
    if (b + 64 > sizeof(body) || 9 + b > cap) {
        return -1;
    }
    out[0] = AR_TLS_HANDSHAKE;
    out[1] = 0x03; /* record version: the lowest the server must accept */
    out[2] = (unsigned char)(version >= 0x0301 ? 0x01 : 0x00);
    out[3] = (unsigned char)((b + 4) >> 8);
    out[4] = (unsigned char)((b + 4) & 255u);
    out[5] = 1; /* ClientHello */
    out[6] = (unsigned char)(b >> 16);
    out[7] = (unsigned char)(b >> 8);
    out[8] = (unsigned char)(b & 255u);
    memcpy(out + 9, body, b);
    return (int)(9 + b);
}

/*
 * ar_tls_recv_record: read one TLS record. Stores the content type in
 * *type and the payload (NUL-terminated) in out. Returns the payload
 * length (>= 0), -1 on timeout/EOF/too large, -2 if the bytes are not a
 * TLS record header (the peer is not speaking TLS).
 */
static inline int ar_tls_recv_record(int fd, int *type, unsigned char *out,
                                     size_t cap, int timeout_ms) {
    unsigned char hdr[5];
    unsigned int len;

    if (out == NULL || cap < 2 || type == NULL) {
        return -1;
    }
    if (as_recv_exact(fd, hdr, 5, timeout_ms) != 0) {
        return -1;
    }
    if (hdr[0] < AR_TLS_CCS || hdr[0] > AR_TLS_HEARTBEAT || hdr[1] != 0x03) {
        return -2;
    }
    len = ((unsigned int)hdr[3] << 8) | hdr[4];
    if (len + 1 > cap) {
        return -1;
    }
    if (len > 0 && as_recv_exact(fd, out, len, timeout_ms) != 0) {
        return -1;
    }
    out[len] = '\0';
    *type = hdr[0];
    return (int)len;
}

/* Result of reading the server's flight. */
#define AR_TLS_F_ERR (-1)   /* timeout, EOF or a peer that is not TLS */
#define AR_TLS_F_ALERT 0    /* the server answered with an alert */
#define AR_TLS_F_DONE 1     /* ServerHelloDone seen */
#define AR_TLS_F_HELLO 2    /* ServerHello seen (stopped there, as asked) */

typedef struct {
    int state;               /* AR_TLS_F_* */
    int not_tls;             /* the peer did not speak TLS */
    int alert_level;         /* when state is AR_TLS_F_ALERT */
    int alert_desc;
    int hello;               /* a ServerHello was parsed */
    unsigned int version;    /* selected protocol version */
    unsigned int cipher;     /* selected suite */
    unsigned char ske[8];    /* first bytes of ServerKeyExchange, if any */
    int ske_len;
} ar_tls_flight;

/*
 * ar_tls_read_flight: read records from fd until ServerHelloDone (or,
 * when until_done is 0, until the ServerHello), an alert, or an error.
 * Handshake messages are parsed as a byte stream, so a message may span
 * records and a record may hold several messages. Returns f->state.
 */
static inline int ar_tls_read_flight(int fd, int timeout_ms, int until_done,
                                     ar_tls_flight *f) {
    unsigned char rec[AR_TLS_MAX_RECORD];
    unsigned char hh[4];
    unsigned char first[96];
    int hh_got = 0;
    int first_n = 0;
    int msg_type = 0;
    unsigned long msg_len = 0;
    unsigned long msg_got = 0;
    int guard;

    memset(f, 0, sizeof(*f));
    f->state = AR_TLS_F_ERR;
    for (guard = 0; guard < 64; guard++) {
        int type = 0;
        int n = ar_tls_recv_record(fd, &type, rec, sizeof(rec), timeout_ms);
        int i;

        if (n == -2) {
            f->not_tls = 1;
            return f->state;
        }
        if (n < 0) {
            return f->state;
        }
        if (type == AR_TLS_ALERT) {
            f->alert_level = n > 0 ? rec[0] : 0;
            f->alert_desc = n > 1 ? rec[1] : 0;
            f->state = AR_TLS_F_ALERT;
            return f->state;
        }
        if (type != AR_TLS_HANDSHAKE) {
            continue;
        }
        for (i = 0; i < n; i++) {
            int msg_done = 0;

            if (hh_got < 4) {
                hh[hh_got++] = rec[i];
                if (hh_got == 4) {
                    msg_type = hh[0];
                    msg_len = ((unsigned long)hh[1] << 16) |
                              ((unsigned long)hh[2] << 8) | hh[3];
                    msg_got = 0;
                    first_n = 0;
                    msg_done = (msg_len == 0);
                }
            } else {
                if (first_n < (int)sizeof(first)) {
                    first[first_n++] = rec[i];
                }
                msg_got++;
                msg_done = (msg_got == msg_len);
            }
            if (!msg_done) {
                continue;
            }
            hh_got = 0;
            if (msg_type == 2 && first_n >= 35) { /* ServerHello */
                int sid = first[34];

                if (first_n >= 35 + sid + 2) {
                    f->version = ((unsigned int)first[0] << 8) | first[1];
                    f->cipher = ((unsigned int)first[35 + sid] << 8) |
                                first[36 + sid];
                    f->hello = 1;
                    if (!until_done) {
                        f->state = AR_TLS_F_HELLO;
                        return f->state;
                    }
                }
            } else if (msg_type == 12) { /* ServerKeyExchange */
                f->ske_len = first_n < (int)sizeof(f->ske) ? first_n
                                                          : (int)sizeof(f->ske);
                memcpy(f->ske, first, (size_t)f->ske_len);
            } else if (msg_type == 14) { /* ServerHelloDone */
                f->state = AR_TLS_F_DONE;
                return f->state;
            }
        }
    }
    return f->state;
}

/*
 * ar_tls_connect_hello: connect, send a ClientHello for `version` offering
 * `ciphers`, and read the server's flight. On return *fd is the open
 * socket (the caller closes it) or -1 if the connection failed.
 * Returns the flight state (AR_TLS_F_*), or AR_TLS_F_ERR if no connection.
 */
static inline int ar_tls_connect_hello(AlScriptContext *ctx,
                                       unsigned int version,
                                       const unsigned short *ciphers, int nc,
                                       int heartbeat, int until_done,
                                       ar_tls_flight *f, int *fd) {
    unsigned char hello[1400];
    int hlen;

    memset(f, 0, sizeof(*f));
    f->state = AR_TLS_F_ERR;
    *fd = -1;
    hlen = ar_tls_client_hello(hello, sizeof(hello), version, ciphers, nc,
                               heartbeat);
    if (hlen < 0) {
        return f->state;
    }
    *fd = as_connect(ctx);
    if (*fd < 0) {
        return f->state;
    }
    if (as_send_all(*fd, hello, (size_t)hlen, ctx->timeout_ms) != 0) {
        return f->state;
    }
    return ar_tls_read_flight(*fd, ctx->timeout_ms, until_done, f);
}

#endif /* ARSENAL_TLS_H */
