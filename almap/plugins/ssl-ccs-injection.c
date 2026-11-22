/* ssl-ccs-injection - OpenSSL ChangeCipherSpec injection (CVE-2014-0224).
 *
 * Completes a TLS 1.2 (or 1.1/1.0) handshake up to ServerHelloDone, then
 * sends a ChangeCipherSpec far too early. A patched server answers with
 * the alert unexpected_message (10) at once. A vulnerable OpenSSL accepts
 * it silently and then answers a second early CCS with bad_record_mac (20)
 * or decryption_failed (21). Silence after both is not conclusive.
 * Read only: no keys are used and nothing is decrypted.
 *
 * Replaces ssl-ccs-injection and ssl-ccs-injection-2.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_tls.h"

/* 0 = silence or closed, 1 = alert (desc set), 2 = some other record */
static int ccs_reply(int fd, int timeout_ms, int *desc) {
    unsigned char rec[AR_TLS_MAX_RECORD];
    int type = 0;
    int n = ar_tls_recv_record(fd, &type, rec, sizeof(rec), timeout_ms);

    *desc = -1;
    if (n < 0) {
        return 0;
    }
    if (type == AR_TLS_ALERT) {
        *desc = n > 1 ? rec[1] : 0;
        return 1;
    }
    return 2;
}

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int versions[] = { 0x0303, 0x0302, 0x0301 };
    unsigned short ids[64];
    unsigned char ccs[6] = { AR_TLS_CCS, 0x03, 0x03, 0x00, 0x01, 0x01 };
    ar_tls_flight f;
    int nc;
    int vi;
    int fd = -1;
    int st = AR_TLS_F_ERR;
    int desc = -1;
    int r;
    int wait_ms;

    if (!ar_valid(ctx)) {
        return 1;
    }
    nc = ar_tls_suite_ids(ids, 64, 0);
    for (vi = 0; vi < 3; vi++) {
        st = ar_tls_connect_hello(ctx, versions[vi], ids, nc, 0, 1, &f, &fd);
        if (st == AR_TLS_F_DONE) {
            break;
        }
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        if (st == AR_TLS_F_ERR) {
            break;
        }
    }
    if (st != AR_TLS_F_DONE) {
        if (f.not_tls) {
            ar_out(ctx, "ssl-ccs-injection: INFO not tested: the service did not answer with a TLS record");
        } else {
            ar_out(ctx, "ssl-ccs-injection: INFO not tested: no TLS handshake completed");
        }
        return 0;
    }
    ccs[2] = (unsigned char)(versions[vi] & 255u);
    wait_ms = ctx->timeout_ms < 1500 ? 1500 : ctx->timeout_ms;

    if (as_send_all(fd, ccs, sizeof(ccs), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "ssl-ccs-injection: INFO not tested: could not send the ChangeCipherSpec");
        return 0;
    }
    r = ccs_reply(fd, wait_ms, &desc);
    if (r == 1 && desc == 10) {
        ar_out(ctx, "ssl-ccs-injection: NOT VULNERABLE (%s: an early ChangeCipherSpec was rejected with unexpected_message)",
               ar_tls_version_name(f.version));
    } else if (r == 1 && (desc == 20 || desc == 21)) {
        ar_out(ctx, "ssl-ccs-injection: VULNERABLE (CVE-2014-0224): an early ChangeCipherSpec was accepted (%s, alert %d)",
               ar_tls_version_name(f.version), desc);
    } else if (r == 1) {
        ar_out(ctx, "ssl-ccs-injection: INFO alert %d after an early ChangeCipherSpec; not conclusive", desc);
    } else if (r == 2) {
        ar_out(ctx, "ssl-ccs-injection: INFO unexpected record after an early ChangeCipherSpec; not conclusive");
    } else if (as_send_all(fd, ccs, sizeof(ccs), ctx->timeout_ms) != 0) {
        ar_out(ctx, "ssl-ccs-injection: INFO the connection closed after an early ChangeCipherSpec; not conclusive");
    } else {
        r = ccs_reply(fd, wait_ms, &desc);
        if (r == 1 && (desc == 20 || desc == 21)) {
            ar_out(ctx, "ssl-ccs-injection: VULNERABLE (CVE-2014-0224): an early ChangeCipherSpec was accepted silently and the second one was answered with alert %d (%s)",
                   desc, ar_tls_version_name(f.version));
        } else if (r == 1 && desc == 10) {
            ar_out(ctx, "ssl-ccs-injection: NOT VULNERABLE (%s: the second early ChangeCipherSpec was rejected with unexpected_message)",
                   ar_tls_version_name(f.version));
        } else {
            ar_out(ctx, "ssl-ccs-injection: INFO no conclusive answer to two early ChangeCipherSpec messages");
        }
    }
    close(fd);
    return 0;
}
