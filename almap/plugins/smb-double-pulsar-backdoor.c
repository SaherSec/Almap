/* smb-double-pulsar-backdoor - experimental: reports which SMB dialects answer and says plainly
 * that the DoublePulsar implant is not decided. It needs SMB1. */
#include "arsenal_smbx.h"

int almap_script_run(AlScriptContext *ctx) {
    ArxSmb1Neg n1;
    int r;

    if (!ar_valid(ctx)) {
        return 1;
    }
    r = arx_smb1_negotiate(ctx, &n1, NULL);
    if (r == 1) {
        ar_out(ctx, "smb-double-pulsar-backdoor: INFO SMB1 (NT LM 0.12) is accepted; the DoublePulsar implant is not decided: the implant's Trans2 probe is not implemented, there is no infected target to verify it against");
    } else if (r == 0) {
        ar_out(ctx, "smb-double-pulsar-backdoor: INFO SMB1 is not accepted; the DoublePulsar implant is not decided");
    } else {
        ar_out(ctx, "smb-double-pulsar-backdoor: INFO no SMB response; the DoublePulsar implant is not decided");
    }
    return 0;
}
