/* ssl-poodle-2 - SSLv3 CBC POODLE probe. */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[4096];
    unsigned int ver = 0;
    unsigned int cipher = 0;
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_tls_probe(ctx, 0x0300, ar_tls_cbc_ciphers,
                      (int)(sizeof(ar_tls_cbc_ciphers) /
                            sizeof(ar_tls_cbc_ciphers[0])),
                      &ver, &cipher, 0, resp, sizeof(resp));
    if (rc == 1) {
        ar_out(ctx, "ssl-poodle-2: INFO matches probe for: SSLv3 CBC POODLE (%s)",
               ar_tls_cipher_name(cipher));
    } else if (rc == 0) {
        ar_out(ctx, "ssl-poodle-2: INFO probe did not match: SSLv3 CBC POODLE");
    } else {
        ar_out(ctx, "ssl-poodle-2: INFO POODLE: no TLS handshake");
    }
    return 0;
}
