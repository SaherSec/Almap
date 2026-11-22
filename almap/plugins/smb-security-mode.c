/* smb-security-mode - message signing and authentication mode announced in
 * the NEGOTIATE reply (SMB2: signing enabled/required; SMB1: also user-level
 * authentication and challenge/response). Nothing is authenticated. */
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
    r1 = arx_smb1_negotiate(ctx, &n1, NULL);
    if (r2 != 1 && r1 != 1) {
        ar_out(ctx, (r2 < 0 && r1 < 0) ? "smb-security-mode: no SMB response"
                                       : "smb-security-mode: no SMB dialect accepted");
        return 0;
    }
    ar_out(ctx, "smb-security-mode:");
    if (r2 == 1) {
        ar_append(ctx, " SMB2 message signing %s",
                  (n2.security_mode & 2u) ? "required"
                  : (n2.security_mode & 1u) ? "enabled but not required" : "not enabled");
    }
    if (r1 == 1) {
        ar_append(ctx, "%s SMB1 message signing %s, %s authentication, %s",
                  r2 == 1 ? ";" : "",
                  (n1.security_mode & 8u) ? "required"
                  : (n1.security_mode & 4u) ? "enabled but not required" : "not enabled",
                  (n1.security_mode & 1u) ? "user-level" : "share-level",
                  (n1.security_mode & 2u) ? "challenge/response passwords" : "plaintext passwords");
    }
    return 0;
}
