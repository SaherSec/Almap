/* ssl-poodle - SSLv3 with CBC suites (POODLE, CVE-2014-3566).
 *
 * Offers every CBC suite the plugin knows in an SSLv3 ClientHello. A server
 * that selects SSLv3 with a CBC suite is vulnerable (VULNERABLE). An alert
 * 70 (protocol_version) or 40 (handshake_failure) means it offers no SSLv3
 * CBC suite among those (NOT VULNERABLE). Silence or any other alert is
 * INFO: a filter may be dropping the hello in front of a server that still
 * speaks SSLv3. Read only; nothing is decrypted.
 *
 * Replaces ssl-poodle and ssl-poodle-2.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned short cbc[AR_TLS_MAXIDS];
    ar_tls_flight f;
    char lab[16];
    int ncbc;
    int fd = -1;
    int st;

    if (!ar_valid(ctx)) {
        return 1;
    }
    ncbc = ar_tls_suite_ids(cbc, AR_TLS_MAXIDS, 1);
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
    if (st == AR_TLS_F_ALERT && (f.alert_desc == 40 || f.alert_desc == 70)) {
        /* protocol_version or handshake_failure to an SSLv3 hello that offered
         * every CBC suite the plugin knows (%d): no SSLv3 + CBC to be had. */
        ar_out(ctx, "ssl-poodle: NOT VULNERABLE (the server refused an SSLv3 hello offering %d CBC suites with alert %d)",
               ncbc, f.alert_desc);
    } else if (st == AR_TLS_F_ALERT) {
        ar_out(ctx, "ssl-poodle: INFO alert %d to an SSLv3 hello; not conclusive", f.alert_desc);
    } else if (f.not_tls) {
        ar_out(ctx, "ssl-poodle: INFO not tested: the service did not answer with a TLS record");
    } else {
        /* No answer: SSLv3 may be disabled, or a filter may be dropping the
         * hello in front of a server that still speaks it. Not evidence. */
        ar_out(ctx, "ssl-poodle: INFO not conclusive: no answer to the SSLv3 hello");
    }
    return 0;
}
