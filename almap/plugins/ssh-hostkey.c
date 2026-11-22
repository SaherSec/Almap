/* ssh-hostkey - the server's host keys (type, size, SHA256 fingerprint).
 * Reads the key from the cleartext KEX_ECDH_REPLY; no authentication. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *algs[3] = { "ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512" };
    unsigned char blob[4096];
    char desc[256];
    char missing[96] = "";
    int i;
    int found = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 3; i++) {
        int n = ar_ssh_get_hostkey_blob(ctx, algs[i], blob, sizeof(blob));
        if (n > 0 && ar_ssh_describe_key(blob, n, desc, sizeof(desc)) == 0) {
            ar_append(ctx, "%s%s", found > 0 ? "; " : "ssh-hostkey: ", desc);
            found++;
        } else {
            size_t used = strlen(missing);
            snprintf(missing + used, sizeof(missing) - used, "%s%s", used > 0 ? ", " : "", algs[i]);
        }
    }
    if (found > 0 && missing[0] != '\0') {
        ar_append(ctx, "; (not obtained: %s)", missing);
    }
    if (found == 0) {
        ar_out(ctx, "ssh-hostkey: no host key returned (probed ed25519, ecdsa-nistp256, rsa; "
               "needs curve25519-sha256)");
    }
    return 0;
}
