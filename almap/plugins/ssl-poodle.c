/* ssl-poodle - SSLv3 with CBC suites (POODLE, CVE-2014-3566).
 *
 * Offers only CBC suites in an SSLv3 ClientHello. A server that selects
 * SSLv3 with a CBC suite is vulnerable. A server that answers with an
 * alert, or closes the connection while a TLS 1.2 hello still works, has
 * SSLv3 disabled. Read only; nothing is decrypted.
 *
 * Replaces ssl-poodle and ssl-poodle-2.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned short cbc[64];
    unsigned short all[64];
    ar_tls_flight f;
    char lab[16];
    int ncbc;
    int nall;
    int fd = -1;
    int st;

    if (!ar_valid(ctx)) {
        return 1;
    }
    ncbc = ar_tls_suite_ids(cbc, 64, 1);
    st = ar_tls_connect_hello(ctx, 0x0300, cbc, ncbc, 0, 0, &f, &fd);
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
    if (st == AR_TLS_F_HELLO) {
        if (f.version == 0x0300 && ar_tls_is_cbc(f.cipher)) {
            ar_out(ctx, "ssl-poodle: VULNERABLE (CVE-2014-3566): SSLv3 negotiated with the CBC suite %s",
                   ar_tls_cipher_label(f.cipher, lab, sizeof(lab)));
        } else {
            ar_out(ctx, "ssl-poodle: NOT VULNERABLE (the server selected %s with %s, not SSLv3 with a CBC suite)",
                   ar_tls_version_name(f.version),
                   ar_tls_cipher_label(f.cipher, lab, sizeof(lab)));
        }
        return 0;
    }
    if (st == AR_TLS_F_ALERT) {
        ar_out(ctx, "ssl-poodle: NOT VULNERABLE (the server refused SSLv3 with alert %d)", f.alert_desc);
        return 0;
    }
    if (f.not_tls) {
        ar_out(ctx, "ssl-poodle: INFO not tested: the service did not answer with a TLS record");
        return 0;
    }
    /* No answer to the SSLv3 hello: if TLS 1.2 works, SSLv3 is simply refused. */
    nall = ar_tls_suite_ids(all, 64, 0);
    st = ar_tls_connect_hello(ctx, 0x0303, all, nall, 0, 0, &f, &fd);
    if (fd >= 0) {
        close(fd);
    }
    if (st == AR_TLS_F_HELLO) {
        ar_out(ctx, "ssl-poodle: NOT VULNERABLE (the server ignored the SSLv3 hello but completes a %s hello)",
               ar_tls_version_name(f.version));
    } else {
        ar_out(ctx, "ssl-poodle: INFO not tested: no TLS handshake completed");
    }
    return 0;
}
