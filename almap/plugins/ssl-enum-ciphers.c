/* ssl-enum-ciphers - protocol versions and cipher suites a TLS server accepts.
 *
 * For SSLv3 and TLS 1.0-1.2 it offers about 50 common IANA suites, records
 * the one the server selects, removes it from the offer and asks again,
 * until the server refuses. The result is the set of probed suites the
 * server accepts, per version, sorted by suite id. TLS 1.3 is not probed
 * and suites outside the probe list are not seen. Read only.
 *
 * Replaces ssl-enum-ciphers and ssl-enum-ciphers-2.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_tls.h"

#define MAXS 64

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int versions[] = { 0x0300, 0x0301, 0x0302, 0x0303 };
    unsigned short remaining[MAXS];
    unsigned short found[MAXS];
    ar_tls_flight f;
    char lab[16];
    int vi;
    int any = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (vi = 0; vi < 4; vi++) {
        int nr = ar_tls_suite_ids(remaining, MAXS, 0);
        int nf = 0;
        int round;

        for (round = 0; round < MAXS && nr > 0; round++) {
            int fd = -1;
            int st = ar_tls_connect_hello(ctx, versions[vi], remaining, nr, 0, 0, &f, &fd);
            int k;
            int at = -1;

            if (fd >= 0) {
                close(fd);
            }
            if (st != AR_TLS_F_HELLO || f.version != versions[vi]) {
                break;
            }
            for (k = 0; k < nr; k++) {
                if (remaining[k] == f.cipher) {
                    at = k;
                }
            }
            if (at < 0) {
                break; /* the server picked a suite we did not offer */
            }
            found[nf++] = (unsigned short)f.cipher;
            memmove(&remaining[at], &remaining[at + 1], (size_t)(nr - at - 1) * sizeof(remaining[0]));
            nr--;
        }
        if (nf > 0) {
            int a;
            int b;

            for (a = 1; a < nf; a++) { /* insertion sort by suite id */
                unsigned short key = found[a];

                for (b = a - 1; b >= 0 && found[b] > key; b--) {
                    found[b + 1] = found[b];
                }
                found[b + 1] = key;
            }
            if (!any) {
                ar_out(ctx, "ssl-enum-ciphers: %s: ", ar_tls_version_name(versions[vi]));
            } else {
                ar_append(ctx, "; %s: ", ar_tls_version_name(versions[vi]));
            }
            any = 1;
            for (a = 0; a < nf; a++) {
                ar_append(ctx, "%s%s", a ? ", " : "", ar_tls_cipher_label(found[a], lab, sizeof(lab)));
            }
        }
    }
    if (!any) {
        ar_out(ctx, "ssl-enum-ciphers: no probed suite negotiated (not a TLS server, TLS 1.3 only, or only suites outside the %d probed)", AR_TLS_NSUITES);
    } else {
        ar_append(ctx, " (probed %d suites; TLS 1.3 not probed)", AR_TLS_NSUITES);
    }
    return 0;
}
