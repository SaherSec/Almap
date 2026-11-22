/* ssh2-enum-algos - the algorithm name-lists in the server's KEXINIT. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *names[10] = {
        "kex", "hostkey", "enc-c2s", "enc-s2c", "mac-c2s",
        "mac-s2c", "comp-c2s", "comp-s2c", "lang-c2s", "lang-s2c"
    };
    static const char *pairs[4] = { "enc", "mac", "comp", "lang" };
    char omitted[96] = "";
    char banner[256];
    char val[4096];
    static unsigned char kex[AR_SSH_PACKET_MAX];
    int fd;
    int n;
    int i;
    int lines = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = ar_ssh_open(ctx, banner, sizeof(banner));
    if (fd < 0) {
        ar_out(ctx, "ssh2-enum-algos: no SSH identification line");
        return 0;
    }
    n = ar_ssh_get_kexinit(fd, kex, sizeof(kex), ctx->timeout_ms, NULL, NULL);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "ssh2-enum-algos: no KEXINIT from the server (%s)", banner);
        return 0;
    }
    /* One line per list; a c2s/s2c pair that is identical prints once. A list
     * that does not fit whole in the output buffer is never cut: it is named
     * at the end as omitted. */
    for (i = 0; i < 10; i++) {
        char other[4096];
        const char *label = names[i];
        int pair = (i >= 2 && (i % 2) == 0);   /* 2,4,6,8 start a pair */
        if (ar_ssh_kex_field(kex, n, i, val, sizeof(val)) != 0 || val[0] == '\0') {
            continue;
        }
        if (pair && ar_ssh_kex_field(kex, n, i + 1, other, sizeof(other)) == 0 &&
            strcmp(val, other) == 0) {
            label = pairs[(i - 2) / 2];
            i++;                                 /* the s2c twin is the same */
        }
        if (strlen(ctx->output_buf) + 2 + strlen(label) + 2 + strlen(val) + 160 <
            (size_t)ctx->output_max) {
            ar_append(ctx, "%s%s: %s", lines > 0 ? "; " : "", label, val);
            lines++;
        } else {
            size_t used = strlen(omitted);
            if (used + strlen(label) + 3 < sizeof(omitted)) {
                snprintf(omitted + used, sizeof(omitted) - used, "%s%s", used > 0 ? ", " : "", label);
            }
        }
    }
    if (omitted[0] != '\0') {
        ar_append(ctx, "%s(omitted, output limit: %s)", lines > 0 ? "; " : "", omitted);
        lines++;
    }
    if (lines == 0) {
        ar_out(ctx, "ssh2-enum-algos: the KEXINIT lists no algorithms");
    }
    return 0;
}
