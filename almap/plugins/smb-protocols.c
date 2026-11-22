/* smb-protocols - which SMB dialects the server accepts. One NEGOTIATE per
 * dialect (SMB1 NT LM 0.12, then SMB 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1), so the
 * answer is the set the server accepts, not only its favourite. */
#include "arsenal_smbx.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int dial[5] = {ARX_D_202, ARX_D_210, ARX_D_300, ARX_D_302, ARX_D_311};
    ArxSmb2Neg n2;
    ArxSmb1Neg n1;
    int any_reply = 0;
    int found = 0;
    int i, r;

    if (!ar_valid(ctx)) {
        return 1;
    }
    ar_out(ctx, "smb-protocols:");
    r = arx_smb1_negotiate(ctx, &n1, NULL);
    if (r >= 0) {
        any_reply = 1;
    }
    if (r == 1) {
        ar_append(ctx, "%s NT LM 0.12", found ? ";" : "");
        found++;
    }
    for (i = 0; i < 5; i++) {
        r = arx_smb2_negotiate(ctx, &dial[i], 1, &n2, NULL);
        if (r >= 0) {
            any_reply = 1;
        }
        if (r == 1 && n2.dialect == dial[i]) {
            ar_append(ctx, "%s %s", found ? ";" : "", arx_smb2_name(dial[i]));
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, any_reply ? "smb-protocols: no SMB dialect accepted" : "smb-protocols: no SMB response");
    }
    return 0;
}
