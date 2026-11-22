/* smb-os-discovery - names the server announces before any authentication.
 * SMB1 (when offered): native OS, LAN Manager and primary domain strings of
 * the SESSION_SETUP reply. SMB1 and SMB2: the computer and domain names in
 * the NTLMSSP CHALLENGE. Only the NTLMSSP NEGOTIATE is sent; no credentials. */
#include "arsenal_smbx.h"

static void ntlm_items(AlScriptContext *ctx, const ArxNtlm *n) {
    if (!n->ok) {
        return;
    }
    if (n->nb_computer[0]) ar_append(ctx, "; NetBIOS computer %s", n->nb_computer);
    if (n->nb_domain[0]) ar_append(ctx, "; NetBIOS domain %s", n->nb_domain);
    if (n->dns_computer[0]) ar_append(ctx, "; DNS computer %s", n->dns_computer);
    if (n->dns_domain[0]) ar_append(ctx, "; DNS domain %s", n->dns_domain);
    if (n->has_version) ar_append(ctx, "; NTLM version %u.%u build %u", n->os_major, n->os_minor, n->os_build);
}

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int all[5] = {ARX_D_202, ARX_D_210, ARX_D_300, ARX_D_302, ARX_D_311};
    ArxSmb1Neg n1;
    ArxSmb1Sess s1;
    ArxSmb2Neg n2;
    ArxSmb2Sess s2;
    int fd = -1;
    int r;

    if (!ar_valid(ctx)) {
        return 1;
    }
    r = arx_smb1_probe(ctx, &n1, &s1);
    if (r == 1) {
        ar_out(ctx, "smb-os-discovery: via SMB1");
        if (s1.native_os[0]) ar_append(ctx, "; OS %s", s1.native_os);
        if (s1.native_lanman[0]) ar_append(ctx, "; LAN Manager %s", s1.native_lanman);
        if (s1.primary_domain[0]) ar_append(ctx, "; workgroup %s", s1.primary_domain);
        ntlm_items(ctx, &s1.ntlm);
        return 0;
    }
    r = arx_smb2_negotiate(ctx, all, 5, &n2, &fd);
    if (r == 1) {
        r = arx_smb2_session(fd, ctx->timeout_ms, &s2);
        close(fd);
        if (r == 1 && s2.ntlm.ok) {
            ar_out(ctx, "smb-os-discovery: via SMB2");
            ntlm_items(ctx, &s2.ntlm);
            return 0;
        }
        ar_out(ctx, "smb-os-discovery: SMB2 answered but no NTLMSSP challenge was returned");
        return 0;
    }
    ar_out(ctx, r < 0 ? "smb-os-discovery: no SMB response"
                      : "smb-os-discovery: no SMB dialect accepted");
    return 0;
}
