/* tests/test_smb.c - unit tests for plugins/arsenal_smbx.h: the SMB1/SMB2
 * NEGOTIATE and SESSION_SETUP parsers against replies captured from real Samba
 * servers (tests/smb_vectors.h), every truncation of those replies, the NTLMSSP
 * CHALLENGE parser, the Samba version parser with every range boundary, and the
 * time budget against a silent peer.
 * Build: gcc -std=c99 -Wall -Wextra -Werror -Wno-unused-function -I c -I plugins tests/test_smb.c
 */
#define _GNU_SOURCE
#include "../plugins/arsenal_smbx.h"
#include "smb_vectors.h"

#include <signal.h>
#include <sys/wait.h>

static int failures;
#define CHECK(c, what) do { if (!(c)) { printf("FAIL %s\n", what); failures++; } } while (0)

static void samba_case(const char *s, int ok, int ma, int mi, int pa, int vendor) {
    ArxSambaVer v;
    char what[160];
    arx_samba_parse(s, &v);
    snprintf(what, sizeof(what), "samba parse '%s'", s);
    CHECK(v.ok == ok, what);
    if (ok) {
        CHECK(v.major == ma && v.minor == mi && v.patch == pa && v.vendor == vendor, what);
    }
}

/* expected decisions: 1 inside, 2 outside, 0 undecided */
static void range_case(const char *s, int c7494, int c44142) {
    ArxSambaVer v;
    char what[160];
    arx_samba_parse(s, &v);
    snprintf(what, sizeof(what), "CVE-2017-7494 for '%s'", s);
    CHECK(arx_samba_cve_2017_7494(&v) == c7494, what);
    snprintf(what, sizeof(what), "CVE-2021-44142 for '%s'", s);
    CHECK(arx_samba_cve_2021_44142(&v) == c44142, what);
}

int main(void) {
    ArxSmb2Neg n2;
    ArxSmb1Neg n1;
    ArxSmb1Sess s1;
    ArxSmb2Sess s2;
    ArxNtlm nt;
    int i;

    /* ---- SMB2 NEGOTIATE reply (real: Samba 4.23.8) ---- */
    arx_smb2_neg_parse(cap_smb2neg_311, sizeof(cap_smb2neg_311), &n2);
    CHECK(n2.ok && n2.dialect == ARX_D_311 && (n2.security_mode & 3u) == 1u, "smb2 3.1.1, signing enabled not required");
    CHECK(!n2.compression_ctx, "no compression context from Samba");
    arx_smb2_neg_parse(cap_smb2neg_311_req, sizeof(cap_smb2neg_311_req), &n2);
    CHECK(n2.ok && (n2.security_mode & 2u) == 2u, "smb2 signing required");
    arx_smb2_neg_parse(cap_smb2neg_21, sizeof(cap_smb2neg_21), &n2);
    CHECK(n2.ok && n2.dialect == ARX_D_210, "smb2 2.1");
    for (i = 0; i < (int)sizeof(cap_smb2neg_311); i++) {
        arx_smb2_neg_parse(cap_smb2neg_311, i, &n2);
        if (i < 128 && n2.ok) { CHECK(0, "truncated smb2 negotiate accepted"); break; }
    }
    {
        unsigned char bad[sizeof(cap_smb2neg_311)];
        memcpy(bad, cap_smb2neg_311, sizeof(bad));
        bad[8] = 0xBB; bad[9] = 0; bad[10] = 0; bad[11] = 0xC0;   /* STATUS_NOT_SUPPORTED */
        arx_smb2_neg_parse(bad, sizeof(bad), &n2);
        CHECK(!n2.ok && n2.status == 0xC00000BBu, "error status refused");
        memcpy(bad, cap_smb2neg_311, sizeof(bad));
        bad[0] = 0xFF;
        arx_smb2_neg_parse(bad, sizeof(bad), &n2);
        CHECK(!n2.ok, "wrong protocol id refused");
        /* a compression context (type 3) in the reply is reported */
        memcpy(bad, cap_smb2neg_311, sizeof(bad));
        {
            unsigned int off = arx_le32(bad + 124);
            bad[off] = 3;
            arx_smb2_neg_parse(bad, sizeof(bad), &n2);
            CHECK(n2.ok && n2.compression_ctx, "compression context seen");
        }
    }

    /* ---- the request we build ---- */
    {
        unsigned char req[512];
        static const unsigned int d311[1] = {ARX_D_311};
        static const unsigned int d21[1] = {ARX_D_210};
        size_t len = arx_smb2_neg_req(req, sizeof(req), d311, 1);
        CHECK(len > 100 && arx_le32(req + 92) % 8 == 0 && arx_le16(req + 96) == 1, "3.1.1 request has an aligned preauth context");
        CHECK(arx_le16(req + (size_t)arx_le32(req + 92)) == 1, "context type is preauth integrity");
        len = arx_smb2_neg_req(req, sizeof(req), d21, 1);
        CHECK(len == 102 && arx_le16(req + 96) == 0, "2.1 request has no contexts");
        CHECK(arx_smb2_neg_req(req, sizeof(req), d21, 0) == 0, "no dialects refused");
    }

    /* ---- SMB1 NEGOTIATE + SESSION_SETUP replies (real: Samba 4.6.3 and 4.23.8) ---- */
    arx_smb1_neg_parse(cap_smb1neg_463, sizeof(cap_smb1neg_463), &n1);
    CHECK(n1.ok && (n1.security_mode & 3u) == 3u && (n1.security_mode & 0x0Cu) == 0, "smb1 4.6.3: user level, challenge/response, signing not enabled");
    arx_smb1_neg_parse(cap_smb1neg_4238, sizeof(cap_smb1neg_4238), &n1);
    CHECK(n1.ok && (n1.security_mode & 8u) == 8u, "smb1 4.23.8: signing required");
    for (i = 0; i < (int)sizeof(cap_smb1neg_463); i++) {
        arx_smb1_neg_parse(cap_smb1neg_463, i, &n1);
        if (i < 57 && n1.ok) { CHECK(0, "truncated smb1 negotiate accepted"); break; }
    }
    arx_smb1_sess_parse(cap_smb1sess_463, sizeof(cap_smb1sess_463), &s1);
    CHECK(s1.ok && strcmp(s1.native_lanman, "Samba 4.6.3") == 0 && strcmp(s1.native_os, "Windows 6.1") == 0 &&
          strcmp(s1.primary_domain, "MYGROUP") == 0, "smb1 session 4.6.3 strings");
    CHECK(s1.ntlm.ok && s1.ntlm.nb_computer[0] != '\0', "smb1 session 4.6.3 ntlm names");
    arx_smb1_sess_parse(cap_smb1sess_4238, sizeof(cap_smb1sess_4238), &s1);
    CHECK(s1.ok && strcmp(s1.native_lanman, "Samba 4.23.8") == 0, "smb1 session 4.23.8 lan manager");
    for (i = 0; i < (int)sizeof(cap_smb1sess_463); i++) {
        arx_smb1_sess_parse(cap_smb1sess_463, i, &s1);
        if (i < 43 && s1.ok) { CHECK(0, "truncated smb1 session accepted"); break; }
        /* never reads past the buffer: run under the sanitizer in CI, here just survive */
    }

    /* ---- SMB2 SESSION_SETUP reply (real: Samba 4.23.8) ---- */
    arx_smb2_sess_parse(cap_smb2sess, sizeof(cap_smb2sess), &s2);
    CHECK(s2.ok && s2.ntlm.ok && strcmp(s2.ntlm.nb_computer, "LABSMB") == 0, "smb2 session ntlm computer name");
    for (i = 0; i < (int)sizeof(cap_smb2sess); i++) {
        arx_smb2_sess_parse(cap_smb2sess, i, &s2);
        if (i < 72 && s2.ok) { CHECK(0, "truncated smb2 session accepted"); break; }
    }

    /* ---- NTLMSSP CHALLENGE: hostile offsets and lengths ---- */
    {
        unsigned char b[128];
        memset(b, 0, sizeof(b));
        memcpy(b, "NTLMSSP\0", 8);
        arx_put32(b + 8, 2);
        arx_put16(b + 40, 0xFFFF);          /* target info longer than the buffer */
        arx_put32(b + 44, 48);
        arx_ntlm_parse(b, sizeof(b), &nt);
        CHECK(!nt.ok, "oversize target info refused");
        arx_put16(b + 40, 8);
        arx_put32(b + 44, 0xFFFFFFF0u);     /* offset wrapping around */
        arx_ntlm_parse(b, sizeof(b), &nt);
        CHECK(!nt.ok, "wrapping target info offset refused");
        arx_put32(b + 8, 1);                /* a NEGOTIATE is not a CHALLENGE */
        arx_put32(b + 44, 48);
        arx_ntlm_parse(b, sizeof(b), &nt);
        CHECK(!nt.ok, "NTLM type 1 is not a challenge");
        /* an AV pair whose length runs past the target info */
        arx_put32(b + 8, 2);
        arx_put16(b + 40, 8);
        arx_put16(b + 48, 1); arx_put16(b + 50, 60);
        arx_ntlm_parse(b, sizeof(b), &nt);
        CHECK(nt.ok && nt.nb_computer[0] == '\0', "AV pair longer than the info ignored");
    }
    {
        char o[8];
        arx_u16((const unsigned char *)"a\0b\0\xe9\0c\0d\0e\0f\0g\0h\0", 18, o, sizeof(o));
        CHECK(strcmp(o, "ab?cdef") == 0, "utf16 to ascii, non-ascii becomes ?, cut at the buffer");
    }

    /* ---- Samba version parser ---- */
    samba_case("Samba 4.6.3", 1, 4, 6, 3, 0);
    samba_case("Samba 4.23.8", 1, 4, 23, 8, 0);
    samba_case("Samba 3.6.25", 1, 3, 6, 25, 0);
    samba_case("Samba 4.9.5-Debian", 1, 4, 9, 5, 1);
    samba_case("Samba 4.15.13-Ubuntu", 1, 4, 15, 13, 1);
    samba_case("Samba 4.20.0rc2", 1, 4, 20, 0, 1);
    samba_case("Windows Server 2016 Standard 6.3", 0, 0, 0, 0, 0);
    samba_case("Samba 4.6", 0, 0, 0, 0, 0);
    samba_case("Samba 4", 0, 0, 0, 0, 0);
    samba_case("Samba x.y.z", 0, 0, 0, 0, 0);
    samba_case("Samba 4.6.99999", 0, 0, 0, 0, 0);
    samba_case("Samba 400.6.3", 0, 0, 0, 0, 0);
    samba_case("Samba 4.99999999999999999999.3", 0, 0, 0, 0, 0);
    samba_case("", 0, 0, 0, 0, 0);
    samba_case("Samba", 0, 0, 0, 0, 0);

    /* every boundary: 1 inside, 2 outside, 0 undecided */
    range_case("Samba 3.4.17", 2, 0);     /* before 3.5.0: not in the SambaCry range; below 4.1 undecided for fruit */
    range_case("Samba 3.5.0", 1, 0);
    range_case("Samba 4.0.26", 1, 0);
    range_case("Samba 4.1.0", 1, 1);
    range_case("Samba 4.4.13", 1, 1);
    range_case("Samba 4.4.14", 2, 1);
    range_case("Samba 4.4.99", 2, 1);
    range_case("Samba 4.5.9", 1, 1);
    range_case("Samba 4.5.10", 2, 1);
    range_case("Samba 4.6.3", 1, 1);
    range_case("Samba 4.6.4", 2, 1);
    range_case("Samba 4.7.0", 2, 1);
    range_case("Samba 4.12.2", 2, 1);
    range_case("Samba 4.13.16", 2, 1);
    range_case("Samba 4.13.17", 2, 2);
    range_case("Samba 4.14.0", 2, 1);
    range_case("Samba 4.14.11", 2, 1);
    range_case("Samba 4.14.12", 2, 2);
    range_case("Samba 4.15.0", 2, 1);
    range_case("Samba 4.15.4", 2, 1);
    range_case("Samba 4.15.5", 2, 2);
    range_case("Samba 4.16.0", 2, 2);
    range_case("Samba 4.23.8", 2, 2);
    range_case("Samba 5.0.0", 2, 2);
    range_case("Windows", 0, 0);

    /* ---- time budget: a silent peer must not hold the exchange past 2 x timeout ---- */
    {
        int srv = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a;
        socklen_t al = sizeof(a);
        pid_t pid;
        AlScriptContext ctx;
        ArxSmb1Neg neg;
        long long t0, took;
        int r;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(srv, 1) != 0 ||
            getsockname(srv, (struct sockaddr *)&a, &al) != 0) {
            printf("FAIL cannot listen\n");
            return 1;
        }
        pid = fork();
        if (pid == 0) {
            int c = accept(srv, NULL, NULL);
            (void)c;
            sleep(8);
            _exit(0);
        }
        memset(&ctx, 0, sizeof(ctx));
        ctx.target_ip = INADDR_LOOPBACK;
        ctx.port = ntohs(a.sin_port);
        ctx.timeout_ms = 500;
        t0 = arx_now_ms();
        r = arx_smb1_negotiate(&ctx, &neg, NULL);
        took = arx_now_ms() - t0;
        CHECK(r == -1 && took < 2500, "silent peer: negotiate gives up within the budget");
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        close(srv);
    }

    /* ---- a reply announcing more than the buffer holds is refused, not read ---- */
    {
        int sv[2];
        unsigned char resp[64];
        unsigned char big[4] = {0, 0xFF, 0xFF, 0xFF};
        AlScriptContext ctx;
        unsigned char msg[40];
        int r;
        memset(&ctx, 0, sizeof(ctx));
        memset(msg, 0, sizeof(msg));
        (void)ctx;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { printf("FAIL socketpair\n"); return 1; }
        (void)!write(sv[1], big, 4);
        arx_deadline_ms = arx_now_ms() + 1000;
        r = arx_txrx(sv[0], msg, sizeof(msg), resp, sizeof(resp), 500);
        CHECK(r == -1, "oversize announced reply refused");
        close(sv[0]); close(sv[1]);
    }

    if (failures == 0) {
        printf("test_smb: all checks passed\n");
    }
    return failures == 0 ? 0 : 1;
}
