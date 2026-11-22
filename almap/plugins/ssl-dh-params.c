/* ssl-dh-params - size of the Diffie-Hellman group a TLS server uses.
 *
 * Offers only DHE suites in a TLS 1.2 ClientHello and reads the group size
 * (the length of the prime p) from the ServerKeyExchange message. Read
 * only; nothing is decrypted.
 *
 * Replaces ssl-dh-params and ssl-dh-params-2.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned short dhe[AR_TLS_MAXIDS];
    unsigned short ids[AR_TLS_MAXIDS];
    ar_tls_flight f;
    char lab[16];
    int n = ar_tls_suite_ids(ids, AR_TLS_MAXIDS, 0);
    int nd = 0;
    int i;
    int fd = -1;
    int st;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        const char *name = ar_tls_cipher_name(ids[i]);

        if (name != NULL && strstr(name, "_DHE_") != NULL) {
            dhe[nd++] = ids[i];
        }
    }
    st = ar_tls_connect_hello(ctx, 0x0303, dhe, nd, 0, 1, &f, &fd);
    if (fd >= 0) {
        close(fd);
    }
    if (st == AR_TLS_F_DONE && f.hello && f.ske_len >= 3 &&
        ar_tls_cipher_name(f.cipher) != NULL &&
        strstr(ar_tls_cipher_name(f.cipher), "_DHE_") != NULL &&
        (((unsigned int)f.ske[0] << 8) | f.ske[1]) >= 64) {
        unsigned int plen = ((unsigned int)f.ske[0] << 8) | f.ske[1];
        unsigned int first = f.ske[2];
        int bits;
        int lead = 0;

        while (lead < 8 && !(first & (0x80u >> lead))) {
            lead++;
        }
        bits = (int)(plen * 8u) - lead;
        ar_out(ctx, "ssl-dh-params: DHE group %d bits (%s, %s)", bits,
               ar_tls_version_name(f.version),
               ar_tls_cipher_label(f.cipher, lab, sizeof(lab)));
    } else if (st == AR_TLS_F_DONE && f.hello) {
        ar_out(ctx, "ssl-dh-params: no finite-field DH group in the key exchange (%s selected)",
               ar_tls_cipher_label(f.cipher, lab, sizeof(lab)));
    } else if (st == AR_TLS_F_ALERT) {
        ar_out(ctx, "ssl-dh-params: no DHE suite negotiated in a TLS 1.2 hello (server alert %d)", f.alert_desc);
    } else if (f.not_tls) {
        ar_out(ctx, "ssl-dh-params: not tested: the service did not answer with a TLS record");
    } else {
        ar_out(ctx, "ssl-dh-params: not tested: no TLS answer");
    }
    return 0;
}
