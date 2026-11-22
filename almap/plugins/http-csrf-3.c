/* http-csrf-3 - look for forms without a CSRF token. */
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
        ar_out(ctx, "http-csrf-3: INFO HTTP CSRF: no response");
        return 0;
    }
    body = ar_http_body(resp);
    if (ar_contains_ci(body, "<form") &&
        !ar_contains_ci(body, "csrf") &&
        !ar_contains_ci(body, "token")) {
        ar_out(ctx, "http-csrf-3: INFO potentially matches probe for: form without CSRF token");
    } else {
        ar_out(ctx, "http-csrf-3: INFO probe did not match: no unprotected form found");
    }
    return 0;
}
