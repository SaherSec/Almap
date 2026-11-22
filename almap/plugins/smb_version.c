/* smb_version - the dialect the server picks when offered every SMB dialect.
 * Tries an SMB2 NEGOTIATE first (all five SMB2/3 dialects), then SMB1. */
#include "arsenal_smbx.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int all[5] = {ARX_D_202, ARX_D_210, ARX_D_300, ARX_D_302, ARX_D_311};
    ArxSmb2Neg n2;
    ArxSmb1Neg n1;
    int r2, r1;

    if (!ar_valid(ctx)) {
        return 1;
    }
    r2 = arx_smb2_negotiate(ctx, all, 5, &n2, NULL);
    if (r2 == 1) {
        const char *name = arx_smb2_name(n2.dialect);
        if (name != NULL) {
            ar_out(ctx, "smb_version: %s", name);
        } else {
            ar_out(ctx, "smb_version: SMB2 dialect 0x%04x", n2.dialect);
        }
        return 0;
    }
    r1 = arx_smb1_negotiate(ctx, &n1, NULL);
    if (r1 == 1) {
        ar_out(ctx, "smb_version: SMB1 (NT LM 0.12)");
        return 0;
    }
    if (r2 < 0 && r1 < 0) {
        ar_out(ctx, "smb_version: no SMB response");
    } else {
        ar_out(ctx, "smb_version: no SMB dialect accepted");
    }
    return 0;
}
