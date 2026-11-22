/* smb-vuln-ms08-067 - experimental: reports which SMB dialects answer and says plainly
 * that MS08-067 (CVE-2008-4250) is not decided. It needs SMB1 and the SRVSVC pipe. */
#include "arsenal_smbx.h"

int almap_script_run(AlScriptContext *ctx) {
    ArxSmb1Neg n1;
    int r;

    if (!ar_valid(ctx)) {
        return 1;
    }
    r = arx_smb1_negotiate(ctx, &n1, NULL);
    if (r == 1) {
        ar_out(ctx, "smb-vuln-ms08-067: INFO SMB1 (NT LM 0.12) is accepted; MS08-067 (CVE-2008-4250) is not decided: the pipe probe is not implemented, there is no Windows target with the flaw to verify it against");
    } else if (r == 0) {
        ar_out(ctx, "smb-vuln-ms08-067: INFO SMB1 is not accepted; MS08-067 (CVE-2008-4250) is not decided");
    } else {
        ar_out(ctx, "smb-vuln-ms08-067: INFO no SMB response; MS08-067 (CVE-2008-4250) is not decided");
    }
    return 0;
}
