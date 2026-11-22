/* http-vuln-cve2023-27997-4 - Fortinet FortiGate XSSL probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/remote/login", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-27997-4: INFO no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Fortinet")) {
        ar_out(ctx, "http-vuln-cve2023-27997-4: INFO matches probe for: /remote/login [%d] (CVE-2023-27997)", ar_http_status(resp));
    } else {
        ar_out(ctx, "http-vuln-cve2023-27997-4: INFO probe did not match: CVE-2023-27997 (/remote/login [%d])", ar_http_status(resp));
    }
    return 0;
}
