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
    char silent[96] = "";
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
    } else if (r < 0) {
        strncat(silent, " NT LM 0.12", sizeof(silent) - strlen(silent) - 1);
    }
    for (i = 0; i < 5; i++) {
        r = arx_smb2_negotiate(ctx, &dial[i], 1, &n2, NULL);
        if (r >= 0) {
            any_reply = 1;
        }
        if (r == 1 && n2.dialect == dial[i]) {
            ar_append(ctx, "%s %s", found ? ";" : "", arx_smb2_name(dial[i]));
            found++;
        } else if (r < 0) {
            strncat(silent, " ", sizeof(silent) - strlen(silent) - 1);
            strncat(silent, arx_smb2_name(dial[i]), sizeof(silent) - strlen(silent) - 1);
        }
    }
    if (found == 0) {
        ar_out(ctx, any_reply ? "smb-protocols: no SMB dialect accepted" : "smb-protocols: no SMB response");
        if (any_reply && silent[0]) {
            ar_append(ctx, "; no reply for:%s (not decided)", silent);
        }
    } else if (silent[0]) {
        /* silence is not evidence: a dialect that got no reply is not reported as refused */
        ar_append(ctx, "; no reply for:%s (not decided)", silent);
    }
    return 0;
}
