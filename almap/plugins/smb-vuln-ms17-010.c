/* smb-vuln-ms17-010 - experimental: reports which SMB dialects answer and says plainly
 * that MS17-010 (CVE-2017-0143 to 0148) is not decided. It needs SMB1. */
#include "arsenal_smbx.h"

int almap_script_run(AlScriptContext *ctx) {
    ArxSmb1Neg n1;
    int r;

    if (!ar_valid(ctx)) {
        return 1;
    }
    r = arx_smb1_negotiate(ctx, &n1, NULL);
    if (r == 1) {
        ar_out(ctx, "smb-vuln-ms17-010: INFO SMB1 (NT LM 0.12) is accepted; MS17-010 (CVE-2017-0143 to 0148) is not decided: the PeekNamedPipe probe is not implemented, there is no Windows target with the flaw to verify it against");
    } else if (r == 0) {
        ar_out(ctx, "smb-vuln-ms17-010: INFO SMB1 is not accepted; MS17-010 (CVE-2017-0143 to 0148) is not decided");
    } else {
        ar_out(ctx, "smb-vuln-ms17-010: INFO no SMB response; MS17-010 (CVE-2017-0143 to 0148) is not decided");
    }
    return 0;
}
