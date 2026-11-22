/* http-internal-ip-disclosure-2 - look for private IPs in the response. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-internal-ip-disclosure-2: INFO internal IP disclosure: no response");
        return 0;
    }
    body = ar_http_body(resp);
    if (ar_contains_ci(body, "10.") ||
        ar_contains_ci(body, "192.168.") ||
        ar_contains_ci(body, "172.16.")) {
        ar_out(ctx, "http-internal-ip-disclosure-2: INFO potentially matches probe for: private IP address disclosed");
    } else {
        ar_out(ctx, "http-internal-ip-disclosure-2: INFO probe did not match: no private IP disclosed");
    }
    return 0;
}
