# Batch 11.3: SMB (family `smb`)

54 source files become 10 checks: 6 verified in the lab, 4 that stay `experimental`; 31 names are removed (see `docs/plans/plugin-renames.tsv`). Targets: `tests/lab/smb` (six pods, host ports 19301-19306, all on 127.0.0.1). **No Windows server is in the lab**: every result below is about Samba.

## Lab targets (images pinned by digest in `tests/lab/smb/images.tsv`)

| Port | Server | SMB1 | Dialects | Signing | CVE-2017-7494 | CVE-2021-44142 |
|---|---|---|---|---|---|---|
| 19301 | `vulhub/samba` 4.6.3 (Vulhub's image for CVE-2017-7494) | yes | NT1, 2.0.2-3.1.1 | not required | **inside** | inside |
| 19302 | `dperson/samba` 4.12.2 with `server min protocol = NT1` | yes | NT1, 2.0.2-3.1.1 | not required | outside | **inside** |
| 19303 | `servercontainers/samba` 4.23.8, defaults | no | 2.0.2-3.1.1 | not required | outside | outside |
| 19304 | same image, `server min protocol = NT1`, `server signing = mandatory` | yes | NT1, 2.0.2-3.1.1 | **required** | outside | outside |
| 19305 | same image, `server max protocol = SMB2_10` | no | 2.0.2, 2.1 | not required | outside | outside |
| 19306 | same image, `server min protocol = SMB3_00` | no | 3.0, 3.0.2, 3.1.1 | not required | outside | outside |

Ground truth for every port: `smbd -V` inside the container, the `smb.conf` options set in `pod.yaml`, and `smbclient` (Samba 4.25.1) with its minimum and maximum protocol pinned to one dialect per connection. `nmap`'s `smb-*` scripts could not be used: they only run on ports 139/445 and a rootless pod cannot publish those.

## What the lab showed about the shipped code

Run against the real servers before any change:

- `smb_version` printed `SMB version: SMB 2.???` for **every** server, including the SMB1 ones: it sent an SMB1 negotiate that also offered "SMB 2.???", and the servers answered with the SMB2 wildcard dialect, which it printed as a version.
- `smb-security-mode`: `probe did not match` on every server. `smb-os-discovery`: `unknown dialect: PC NETWORK PROGRAM 1.0` on every server.
- `smb-vuln-ms17-010-full` said `SMBv1 PC NETWORK PROGRAM 1.0 ... IPC$ tree connect denied (status 0xFFFFFFFF)` on 19303, where SMB1 is not offered at all. Its non-extended-security session setup is rejected by current servers (Samba and Windows both negotiate extended security).
- `smb-enum-shares` said `none accessible via null session` for a server that offers a guest share; `smb-vuln-cve2017-7494-4` printed `os= lan=; verify CVE-2017-7494` and never read a version.

## Checks

| Check | Merges | Tier | Evidence | What it does |
|---|---|---|---|---|
| `smb_version` | `smb_version` | info | lab | SMB2 NEGOTIATE offering all five dialects (with the pre-authentication context SMB 3.1.1 needs), then SMB1 `NT LM 0.12`. Prints the dialect the server picks |
| `smb-protocols` | `smb-protocols-check-4` | info | lab | One NEGOTIATE per dialect (SMB1, 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1): the accepted set. Compared with `smbclient` pinned to each dialect (`oracle:protocols`) |
| `smb-security-mode` | `smb-security-mode` (+`-2`, `-3`, `-check-4`) | info | lab | Signing enabled/required from the SMB2 reply; for SMB1 also user-level vs share-level and challenge/response. Compared with a second client written from [MS-SMB2] and [MS-CIFS] (`oracle:signing`), and the two configured extremes are pinned in `cases.tsv` |
| `smb-os-discovery` | `smb-os-discovery` (+`-2`, `-3`) | info | lab | SMB1 (when offered): native OS, LAN Manager and primary domain strings and the NTLMSSP challenge names. SMB2: the NTLMSSP challenge names only. Only the NTLMSSP negotiate message is sent |
| `smb-cve-2017-7494` | `smb-vuln-cve2017-7494-4` | detect | lab | `DETECTED` when the SMB1 LAN Manager string says Samba 3.5.0 up to 4.4.13, 4.5.0-4.5.9 or 4.6.0-4.6.3; otherwise `NOT DETECTED`; `INFO` for vendor builds, non-Samba strings and servers without SMB1 |
| `smb-cve-2021-44142` | `smb-vuln-cve2021-44142-5` | detect | lab | Same for 4.1 up to 4.13.16, 4.14.0-4.14.11, 4.15.0-4.15.4 (and only with `vfs_fruit` loaded, which a banner cannot show) |
| `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-double-pulsar-backdoor`, `smb-vuln-cve2020-0796` | the numbered copies of each | experimental | - | Report whether SMB1 (or SMB 3.1.1 and its compression context) is accepted and say the vulnerability is **not decided**. They need a Windows target that has the flaw |

Removed names: every enumeration (`smb-enum-*`), `smb-ls`, `smb-mbenum`, `smb-brute`, `smb-null-session-check` (they need an authenticated session or DCE/RPC over named pipes: a transport that does not exist in the plugin helpers), and the checks for flaws that are not in SMB (`ms06-025`, `ms07-029`, `ms10-054`, `ms10-061`, `cve2020-1472`, `cve2021-34527`, `cve2022-24521`) and `smb-check-vulns`. Cost if wrong: these names disappear until someone writes the transport. They were not kept as `experimental` for the same reason as in the SSH batch.

## Why the CVE checks are `detect`, not `vuln`

A banner proves the version, not the vulnerability (backports; `vfs_fruit` must be loaded for CVE-2021-44142; `nt pipe support = no` mitigates CVE-2017-7494). The output says "banner only". Only SMB1 carries the Samba version: **current Samba and Windows ship with SMB1 off, so on a current server both checks say `INFO` (version not disclosed)**. That is the honest answer and is a lab case (19303, 19305, 19306).

The affected ranges: CVE-2017-7494 from the samba.org advisory (all versions from 3.5.0, fixed 4.4.14, 4.5.10, 4.6.4). CVE-2021-44142: the fixed releases 4.13.17, 4.14.12, 4.15.5 are confirmed by the Samba release notes; the lower bound 4.1 comes from Samba bug 14914 ("4.1 and newer product line"); the advisory page itself was not retrieved verbatim. Versions below 4.1 print `INFO`.

## Decisions

- Verdict words only in `detect` output; everything else is a fact line.
- The SMB checks never authenticate. `smb-os-discovery` stops after the server's NTLMSSP CHALLENGE.
- Every connection has a total time budget of twice `--timeout` (a dripping or silent peer cannot hold the plugin), and a reply that announces more than the buffer is refused unread.
- `NetBIOS domain LABSMB` for a server configured with workgroup `LABGROUP`: Samba's standalone-server challenge names its own computer as the domain; the plugin prints what the server sends, and the SMB1 `workgroup` field shows the configured name. The lab pins both.
- The NTLM `version 6.1 build 0` Samba sends is fixed text, not a real OS build. It is printed because Windows servers send a real one.

## Evidence summary (46 lab cases, `tests/lab/smb/cases.tsv`)

- Six Samba servers for every check; `smb-protocols` against `smbclient`, `smb-security-mode` against an independent client. A non-SMB control (real nginx bytes, replayed) must give "no SMB response" / `INFO no SMB response`, and for the CVE checks never `DETECTED`.
- `tests/test_smb.c`: parsers against eight replies captured byte for byte from the lab (`tests/smb_vectors.h`), every truncation of them (also under ASan/UBSan), hostile NTLM offsets, every Samba version boundary (4 mutations of the boundary and parser code are each caught), a silent peer, an oversized announced reply.
- Not covered by any target: **any Windows server** (so `smb-os-discovery` on Windows, the SMB2 signing bit on Windows, a compression context in a real SMBGhost-era reply), a vendor build against a live server (`4.9.5-Debian` is unit-tested only), servers that throttle or rate-limit connections, a server offering only SMB 3.1.1 with encryption required.

## Review of the batch (Sonnet subagent plus the automated security review) and what changed

No Critical. Fixed (test first where a test can show it): a 32-bit wrap in the SMB2 negotiate-context loop (a hostile offset near 2^32 was read; ASan SEGV before, clean after); `smb-protocols` printed a dialect that got no reply as if it were refused, it now says `no reply for: ... (not decided)`; the NEGOTIATE request wrote the client GUID over the Capabilities field (Capabilities claimed 0x706D6C41), now Capabilities is 0 and the GUID sits at offset 76; the SMB2 wildcard dialect 0x02FF was accepted as a dialect; the NTLM version was taken from a challenge that failed validation; `smb-cve-*` said "SMB1 not accepted" when SMB1 was accepted but the session reply was unusable; `poll` interrupted by a signal counted as a timeout. Wording: the CHANGELOG now says what the lab proves for the two `detect` checks, and the README states the per-plugin connection count.

Kept as is / deferred: no lab case for a silent peer, an immediate close, a garbage frame or the vendor-build path (unit-tested for the parsers and the silent peer only); the signing oracle shares its author with the plugin, so only the two configured extremes are independent ground truth; the CVE-2021-44142 lower bound 4.1 rests on Samba bug 14914, not the advisory text.
