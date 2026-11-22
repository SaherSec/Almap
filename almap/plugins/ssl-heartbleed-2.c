/* ssl-heartbleed-2 - OpenSSL Heartbleed probe. */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[4096];
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_tls_heartbleed(ctx, resp, sizeof(resp));
    if (rc == 1) {
        ar_out(ctx, "ssl-heartbleed-2: INFO matches probe for: OpenSSL Heartbleed (CVE-2014-0160)");
    } else if (rc == 0) {
        ar_out(ctx, "ssl-heartbleed-2: INFO probe did not match: OpenSSL Heartbleed");
    } else {
        ar_out(ctx, "ssl-heartbleed-2: INFO Heartbleed: no TLS handshake");
    }
    return 0;
}
