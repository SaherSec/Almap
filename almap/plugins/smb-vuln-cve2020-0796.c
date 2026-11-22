/* smb-vuln-cve2020-0796 - experimental: reports whether the server accepts
 * SMB 3.1.1 and whether its reply carries a compression capabilities context
 * (what SMBGhost needs). Not decided: no vulnerable Windows target to verify a
 * verdict against. */
#include "arsenal_smbx.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int d311[1] = {ARX_D_311};
    ArxSmb2Neg n;
    int r;

    if (!ar_valid(ctx)) {
        return 1;
    }
    r = arx_smb2_negotiate(ctx, d311, 1, &n, NULL);
    if (r == 1 && n.dialect == ARX_D_311) {
        ar_out(ctx, "smb-vuln-cve2020-0796: INFO SMB 3.1.1 is accepted, compression context in the reply: %s; "
               "CVE-2020-0796 is not decided (no Windows target with the flaw to verify it against)",
               n.compression_ctx ? "yes" : "no");
    } else if (r >= 0) {
        ar_out(ctx, "smb-vuln-cve2020-0796: INFO SMB 3.1.1 is not accepted; CVE-2020-0796 is not decided");
    } else {
        ar_out(ctx, "smb-vuln-cve2020-0796: INFO no SMB response; CVE-2020-0796 is not decided");
    }
    return 0;
}
