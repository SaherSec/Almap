/* http-vuln-cve2023-34362-4 - MOVEit Transfer SQL injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/human.aspx", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-34362-4: INFO no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "MOVEit")) {
        ar_out(ctx, "http-vuln-cve2023-34362-4: INFO matches probe for: /human.aspx [%d] (CVE-2023-34362)", ar_http_status(resp));
    } else {
        ar_out(ctx, "http-vuln-cve2023-34362-4: INFO probe did not match: CVE-2023-34362 (/human.aspx [%d])", ar_http_status(resp));
    }
    return 0;
}
