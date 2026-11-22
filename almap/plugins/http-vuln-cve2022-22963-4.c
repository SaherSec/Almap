/* http-vuln-cve2022-22963-4 - Spring Cloud Function SpEL probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/functionRouter", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-22963-4: INFO no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Spring")) {
        ar_out(ctx, "http-vuln-cve2022-22963-4: INFO matches probe for: /functionRouter [%d] (CVE-2022-22963)", ar_http_status(resp));
    } else {
        ar_out(ctx, "http-vuln-cve2022-22963-4: INFO probe did not match: CVE-2022-22963 (/functionRouter [%d])", ar_http_status(resp));
    }
    return 0;
}
