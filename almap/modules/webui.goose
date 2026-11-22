import std;
import modules.target;
import modules.output;
namespace webui;

// modules/webui.goose - Step 28: Web UI (Zenmap Killer).
// Lightweight HTTP server serving a single-page dark-mode frontend
// and a JSON API for scans. Dependency-free: raw HTML/CSS/JS embedded
// via Goose string construction, POSIX sockets via c/http.c.
//
// Routes (Goose owns routing; C owns sockets/child processes):
//   GET  /            -> index HTML page
//   GET  /api/status  -> {"status":"ok","version":"5.0.0",...}
//   POST /api/scan    -> JSON {targets,ports,scan_type,fast,os,
//                        service,evasion,discover,timeout,retries,
//                        script}
//                        spawns the ALmap binary (self exe) with
//                        --json and returns its JSON result.
//   else              -> 404 JSON
//
// Access control (every request): the Host header must be localhost or
// an IPv4 literal with the listening port (blocks DNS rebinding); an
// Origin header, when sent, must be http://<Host> (blocks cross-site
// requests). Every /api/ route also needs "Authorization: Bearer
// <token>"; the random token is printed at startup. The server binds
// 127.0.0.1 unless --web-bind says otherwise.
//
// Scan request JSON (all keys optional except targets/ports):
//   "targets":   comma list, e.g. "127.0.0.1" (required)
//   "ports":     ports string, e.g. "80,443" (required unless discovery)
//   "scan_type": "connect" (default) | "syn" | "udp" | "discovery"
//   "fast":      bool --fast (connect only)
//   "os":        bool --os  (syn only)
//   "service":   bool --service (connect only)
//   "evasion":   bool -f/--fragment (syn/connect only)
//   "discover":  bool --discover (sets discovery when true)
//   "timeout":   int ms 1..60000 (default 1000)
//   "retries":   int 0..10 (default 3; extra --fast timeout retries)
//   "script":    plugin NAME from the plugins/ directory next to the
//                binary, e.g. "http_title" (optional; paths rejected)
//
// Validation mirrors the CLI in almap.goose: fast requires connect and
// cannot combine with service/evasion/os; os requires syn; service
// requires connect; evasion requires syn/connect; udp cannot combine
// with service; discovery cannot combine with ports. Targets/ports are
// checked with modules/target parsers before the child is spawned.
// Child failures return 500 with {"error":...,"exit_code":...}.
//
// C bindings: single client at a time (sequential). Fixed buffers
// use the verified first-element reference form (u8& crosses as
// uint8_t*); slices cross as {data,len} and do not match the C
// pointer signatures, so callers pass buf[0] with an explicit cap.

extern fn almap_http_listen(bind_addr: const u8&, port: i32) -> i32;
extern fn almap_http_accept(listen_fd: i32) -> i32;
extern fn almap_http_next(listen_fd: i32, buf: u8&, cap: i32, client_fd: i32&, kind: i32&) -> i32;
extern fn almap_http_send(client_fd: i32, buf: const u8&, len: i32) -> i32;
extern fn almap_http_close(fd: i32) -> i32;
extern fn almap_http_close_linger(fd: i32) -> i32;
extern fn almap_http_self_exe(buf: u8&, cap: i32) -> i32;
extern fn almap_http_random_token(buf: u8&, cap: i32) -> i32;
extern fn almap_http_resolve_plugin(name: const u8&, out: u8&, cap: i32) -> i32;
extern fn almap_http_scan_start(client_fd: i32, targets: const u8&, ports: const u8&, scan_type: const u8&, fast: i32, os_flag: i32, service_flag: i32, evasion_flag: i32, discover_flag: i32, timeout_ms: i32, retries: i32, script: const u8&) -> i32;
extern fn almap_http_scan_result(head: u8&, head_cap: i32, exit_code: i32&, state: i32&) -> i32;
extern fn almap_http_scan_send_body(client_fd: i32) -> i32;
extern fn almap_http_scan_running() -> i32;
extern fn almap_http_out_cap() -> i32;
extern fn almap_http_scan_limit_s() -> i32;

fn version_string() -> const u8[:] {
    return "5.0.0";
}

fn default_port() -> i64 {
    return 8080;
}

fn valid_port(port: i64) -> bool {
    if port < 1 { return false; }
    if port > 65535 { return false; }
    return true;
}

fn parse_port(s: const u8[:]) -> i64, bool {
    let t = trim(s);
    if t.len == 0 { return 0, false; }
    if t[0] == '-' || t[0] == '+' { return 0, false; }
    let v, ok = parse_int(t);
    if !ok { return 0, false; }
    if v < 1 || v > 65535 { return 0, false; }
    return v, true;
}

fn is_ws(c: u8) -> bool {
    if c == ' ' || c == '\t' || c == '\n' || c == '\r' { return true; }
    return false;
}

fn starts_with(s: const u8[:], prefix: const u8[:]) -> bool {
    if prefix.len > s.len { return false; }
    var i: i64 = 0;
    while i < prefix.len {
        if s[i] != prefix[i] { return false; }
        i++;
    }
    return true;
}

fn find_substring(hay: const u8[:], needle: const u8[:]) -> i64 {
    if needle.len == 0 { return 0; }
    if needle.len > hay.len { return -1; }
    var i: i64 = 0;
    while i + needle.len <= hay.len {
        var j: i64 = 0;
        var ok = true;
        while j < needle.len {
            if hay[i + j] != needle[j] { ok = false; break; }
            j++;
        }
        if ok { return i; }
        i++;
    }
    return -1;
}

// Method/path routing helpers (pure, unit-tested).

fn is_status_request(method: const u8[:], path: const u8[:]) -> bool {
    if method != "GET" { return false; }
    if path == "/api/status" { return true; }
    if starts_with(path, "/api/status?") { return true; }
    return false;
}

fn is_scan_request(method: const u8[:], path: const u8[:]) -> bool {
    if method != "POST" { return false; }
    if path == "/api/scan" { return true; }
    if starts_with(path, "/api/scan?") { return true; }
    return false;
}

fn is_index_request(method: const u8[:], path: const u8[:]) -> bool {
    if method != "GET" { return false; }
    if path == "/" { return true; }
    if path == "/index.html" { return true; }
    return false;
}

fn parse_request_line(req: const u8[:], method_out: u8[>..]&, path_out: u8[>..]&) -> bool {
    let nl = position(req, '\n');
    if nl < 0 { return false; }
    let line = trim(req[..nl]);
    if line.len == 0 { return false; }
    let parts = split(line, ' ');
    if parts.len < 2 { return false; }
    method_out.append(parts[0]);
    path_out.append(parts[1]);
    return true;
}

fn lower_byte(c: u8) -> u8 {
    if c >= 'A' && c <= 'Z' { return c + 32; }
    return c;
}

fn eq_ci(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    var i: i64 = 0;
    while i < a.len {
        if lower_byte(a[i]) != lower_byte(b[i]) { return false; }
        i++;
    }
    return true;
}

// Value of the first header called `name` (case-insensitive), trimmed.
// Only the header block (after the request line, before the blank
// line) is searched, so a body cannot inject headers.
fn header_value(req: const u8[:], name: const u8[:], out: u8[>..]&) -> bool {
    var end = find_substring(req, "\r\n\r\n");
    if end < 0 { end = find_substring(req, "\n\n"); }
    if end < 0 { end = req.len; }
    let first_nl = position(req[..end], '\n');
    if first_nl < 0 { return false; }
    var i = first_nl + 1;
    while i < end {
        var j = i;
        while j < end && req[j] != '\n' { j++; }
        var k = j;
        if k > i && req[k - 1] == '\r' { k--; }
        let colon = position(req[i..k], ':');
        if colon > 0 && eq_ci(trim(req[i..i + colon]), name) {
            out.append(trim(req[i + colon + 1..k]));
            return true;
        }
        i = j + 1;
    }
    return false;
}

// True when the Content-Type media type is application/json
// (case-insensitive; parameters such as "; charset=utf-8" are allowed).
fn json_content_type(req: const u8[:]) -> bool {
    var ct: u8[>..] = [];
    if !header_value(req, "Content-Type", ct) { return false; }
    var end = position(ct, ';');
    if end < 0 { end = ct.len; }
    return eq_ci(trim(ct[..end]), "application/json");
}

fn is_alnum(c: u8) -> bool {
    if c >= 'a' && c <= 'z' { return true; }
    if c >= 'A' && c <= 'Z' { return true; }
    if c >= '0' && c <= '9' { return true; }
    return false;
}

// Host must be "localhost" or an IPv4 literal, with ":<port>" (or no
// port only when port is 80). Hostnames are refused: a DNS-rebinding
// page always arrives with the attacker's hostname in Host.
fn host_allowed(host: const u8[:], port: i64) -> bool {
    if host.len == 0 || host.len > 255 { return false; }
    var name_end = host.len;
    let colon = position(host, ':');
    if colon >= 0 {
        let p, ok = parse_port(host[colon + 1..]);
        if !ok || p != port { return false; }
        name_end = colon;
    } else if port != 80 {
        return false;
    }
    let name = host[..name_end];
    if eq_ci(name, "localhost") { return true; }
    if name.len == 0 || name[0] < '0' || name[0] > '9' { return false; }
    let _ip, ipok = target::parse_ipv4(name);
    return ipok;
}

// A browser Origin must be exactly http://<Host>.
fn origin_allowed(origin: const u8[:], host: const u8[:]) -> bool {
    if origin.len != host.len + 7 { return false; }
    if !eq_ci(origin[..7], "http://") { return false; }
    return eq_ci(origin[7..], host);
}

// Constant-time comparison (no early exit on the first differing byte).
fn token_equal(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len || a.len == 0 { return false; }
    var diff: u8 = 0;
    var i: i64 = 0;
    while i < a.len {
        diff |= a[i] ^ b[i];
        i++;
    }
    return diff == 0;
}

fn bearer_ok(req: const u8[:], token: const u8[:]) -> bool {
    var auth: u8[>..] = [];
    if !header_value(req, "Authorization", auth) { return false; }
    if auth.len < 8 || !eq_ci(auth[..7], "Bearer ") { return false; }
    return token_equal(trim(auth[7..]), token);
}

// Access check for one request: 0 = allowed, else the HTTP status to
// return (403 bad Host/Origin, 401 missing or wrong API token).
fn check_access(req: const u8[:], path: const u8[:], port: i64, token: const u8[:]) -> i64 {
    var host: u8[>..] = [];
    if !header_value(req, "Host", host) || !host_allowed(host, port) { return 403; }
    var origin: u8[>..] = [];
    if header_value(req, "Origin", origin) && !origin_allowed(origin, host) { return 403; }
    if starts_with(path, "/api/") && !bearer_ok(req, token) { return 401; }
    return 0;
}

// A plugin name: 1..128 chars of [A-Za-z0-9_.-], alphanumeric first,
// no "..". No slashes, so it can only name a file inside plugins/.
fn valid_plugin_name(s: const u8[:]) -> bool {
    if s.len == 0 || s.len > 128 { return false; }
    if !is_alnum(s[0]) { return false; }
    for c in s {
        if !(is_alnum(c) || c == '_' || c == '-' || c == '.') { return false; }
    }
    if find_substring(s, "..") >= 0 { return false; }
    return true;
}

fn extract_body(req: const u8[:]) -> const u8[:] {
    let idx = find_substring(req, "\r\n\r\n");
    if idx >= 0 { return req[idx + 4..]; }
    let idx2 = find_substring(req, "\n\n");
    if idx2 >= 0 { return req[idx2 + 2..]; }
    return "";
}

// Minimal JSON field helpers (pure). Values with escapes are
// rejected: targets/ports/scan_type never need escapes, so a backslash
// in the raw value means an escaped char we do not decode.

fn json_string(body: const u8[:], key: const u8[:], out: u8[>..]&) -> bool {
    var qkey: u8[>..] = [];
    qkey.push('"');
    qkey.append(key);
    qkey.push('"');
    let kpos = find_substring(body, qkey);
    if kpos < 0 { return false; }
    var i = kpos + qkey.len;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != ':' { return false; }
    i++;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != '"' { return false; }
    i++;
    var start = i;
    while i < body.len && body[i] != '"' {
        if body[i] == '\\' { return false; }
        i++;
    }
    if i >= body.len { return false; }
    out.append(body[start..i]);
    return true;
}

// True when the string value of `key` (located exactly as json_string
// does) contains a backslash escape. json_string refuses such a value;
// callers use this to answer 400 instead of treating it as absent.
fn json_string_escaped(body: const u8[:], key: const u8[:]) -> bool {
    var qkey: u8[>..] = [];
    qkey.push('"');
    qkey.append(key);
    qkey.push('"');
    let kpos = find_substring(body, qkey);
    if kpos < 0 { return false; }
    var i = kpos + qkey.len;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != ':' { return false; }
    i++;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != '"' { return false; }
    i++;
    while i < body.len && body[i] != '"' {
        if body[i] == '\\' { return true; }
        i++;
    }
    return false;
}

// Name of the first string field the API reads whose value contains an
// escape the parser does not decode, or "" when none does.
fn escaped_string_field(body: const u8[:]) -> const u8[:] {
    if json_string_escaped(body, "targets") { return "targets"; }
    if json_string_escaped(body, "ports") { return "ports"; }
    if json_string_escaped(body, "scan_type") { return "scan_type"; }
    if json_string_escaped(body, "script") { return "script"; }
    return "";
}

fn json_bool(body: const u8[:], key: const u8[:]) -> bool, bool {
    var qkey: u8[>..] = [];
    qkey.push('"');
    qkey.append(key);
    qkey.push('"');
    let kpos = find_substring(body, qkey);
    if kpos < 0 { return false, false; }
    var i = kpos + qkey.len;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != ':' { return false, false; }
    i++;
    while i < body.len && is_ws(body[i]) { i++; }
    if i + 4 <= body.len && body[i..i + 4] == "true" { return true, true; }
    if i + 5 <= body.len && body[i..i + 5] == "false" { return false, true; }
    return false, false;
}

fn json_int(body: const u8[:], key: const u8[:]) -> i64, bool {
    var qkey: u8[>..] = [];
    qkey.push('"');
    qkey.append(key);
    qkey.push('"');
    let kpos = find_substring(body, qkey);
    if kpos < 0 { return 0, false; }
    var i = kpos + qkey.len;
    while i < body.len && is_ws(body[i]) { i++; }
    if i >= body.len || body[i] != ':' { return 0, false; }
    i++;
    while i < body.len && is_ws(body[i]) { i++; }
    var start = i;
    if i < body.len && (body[i] == '-' || body[i] == '+') { i++; }
    var digits: i64 = 0;
    while i < body.len && body[i] >= '0' && body[i] <= '9' { i++; digits++; }
    if digits == 0 { return 0, false; }
    let v, ok = parse_int(body[start..i]);
    if !ok { return 0, false; }
    return v, true;
}

fn is_valid_scan_type(s: const u8[:]) -> bool {
    if s == "connect" { return true; }
    if s == "syn" { return true; }
    if s == "udp" { return true; }
    if s == "discovery" { return true; }
    if s == "discover" { return true; }
    return false;
}

fn is_discovery_type(s: const u8[:]) -> bool {
    if s == "discovery" { return true; }
    if s == "discover" { return true; }
    return false;
}

fn copy_cstr(dst: u8[:], src: const u8[:]) -> bool {
    if src.len >= dst.len { return false; }
    var i: i64 = 0;
    while i < src.len {
        dst[i] = src[i];
        i++;
    }
    dst[src.len] = 0;
    return true;
}

fn status_text(code: i64) -> const u8[:] {
    if code == 200 { return "OK"; }
    if code == 400 { return "Bad Request"; }
    if code == 401 { return "Unauthorized"; }
    if code == 403 { return "Forbidden"; }
    if code == 404 { return "Not Found"; }
    if code == 409 { return "Conflict"; }
    if code == 413 { return "Payload Too Large"; }
    if code == 415 { return "Unsupported Media Type"; }
    if code == 504 { return "Gateway Timeout"; }
    return "Internal Server Error";
}

fn status_json(out: u8[>..]&) {
    out.append("{\"status\":\"ok\",\"version\":\"");
    output::json_escape(out, version_string());
    out.append("\",\"service\":\"almap-web\",\"scan_running\":");
    if almap_http_scan_running() != 0 {
        out.append("true");
    } else {
        out.append("false");
    }
    out.append("}");
}

fn error_json(out: u8[>..]&, message: const u8[:]) {
    out.append("{\"error\":\"");
    output::json_escape(out, message);
    out.append("\"}");
}

fn send_response(client: i32, code: i64, ctype: const u8[:], body: const u8[:]) {
    var hdr: u8[>..] = [];
    hdr.append("HTTP/1.1 ");
    format(hdr, code);
    hdr.append(" ");
    hdr.append(status_text(code));
    hdr.append("\r\nContent-Type: ");
    hdr.append(ctype);
    hdr.append("\r\nContent-Length: ");
    format(hdr, body.len);
    hdr.append("\r\nConnection: close\r\n\r\n");
    let _ = almap_http_send(client, hdr[0], hdr.len as i32);
    if body.len > 0 {
        let _ = almap_http_send(client, body[0], body.len as i32);
    }
}

fn index_html(out: u8[>..]&) {
    out.append("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>ALmap Web UI - Zenmap Killer</title>
        <style>
        :root{color-scheme:dark}
        *{box-sizing:border-box}
        body{margin:0;background:#0f1419;color:#e6edf3;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
        .container{max-width:920px;margin:0 auto;padding:28px 20px 40px}
        header{margin-bottom:18px}
        h1{margin:0 0 6px;font-size:30px;letter-spacing:.2px}
        .sub{color:#9aa7b4;margin:0 0 10px}
        .status{display:inline-block;padding:4px 10px;border:1px solid #30363d;border-radius:999px;background:#161c22;font-size:13px;color:#9aa7b4}
        .dot{color:#f0883e}
        .dot.on{color:#3fb950}
        .card{background:#161c22;border:1px solid #30363d;border-radius:12px;padding:18px;margin:14px 0}
        .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
        label{display:block;font-size:13px;color:#9aa7b4}
        label input,label select{width:100%;margin-top:6px;padding:9px 10px;border-radius:8px;border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-size:14px}
        label input:focus,label select:focus{outline:none;border-color:#58a6ff}
        .flags{display:flex;flex-wrap:wrap;gap:16px;margin:14px 0}
        .flags label{display:flex;align-items:center;gap:7px;color:#e6edf3}
        .flags input{width:auto}
        button{background:#238636;color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:14px;font-weight:600;cursor:pointer}
        button:hover{background:#2ea043}
        button:disabled{opacity:.6;cursor:not-allowed}
        .hint{color:#8b949e;font-size:13px;margin:12px 0 0}
        h2{font-size:18px;margin:18px 0 8px}
        .terminal{background:#0b0e11;border:1px solid #30363d;border-radius:10px;padding:14px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;white-space:pre-wrap;word-break:break-word;min-height:260px;max-height:520px;overflow:auto}
        .ok{color:#7ee787}
        .err{color:#ffa198}
        @media (max-width:640px){.grid{grid-template-columns:1fr}}
        </style>
        </head>
        <body>
        <div class="container">
        <header>
        <h1>ALmap Web UI</h1>
        <p class="sub">High-performance Nmap alternative - async engine, evasion, C plugins, Regex DB, OS DB (Zenmap Killer)</p>
        <span class="status"><span id="dot" class="dot">&#9679;</span> <span id="statusText">connecting...</span></span>
        </header>
        <form id="scanForm" class="card">
        <div class="grid">
        <label>Targets<input id="targets" name="targets" value="127.0.0.1" placeholder="127.0.0.1, 192.168.1.0/24" autocomplete="off" required></label>
        <label>Ports<input id="ports" name="ports" value="80,443" placeholder="80,443 or 1-1024" autocomplete="off"></label>
        <label>Scan type<select id="scan_type" name="scan_type"><option value="connect">Connect</option><option value="syn">SYN</option><option value="udp">UDP</option><option value="discovery">Discovery</option></select></label>
        <label>Timeout (ms)<input id="timeout" name="timeout" type="number" value="1000" min="1" max="60000"></label>
        <label>Retries<input id="retries" name="retries" type="number" value="3" min="0" max="10"></label>
        <label>AlScript plugin<input id="script" name="script" placeholder="http_title (optional)" autocomplete="off" list="scripts"><datalist id="scripts"><option value="http_title"><option value="http_title"><option value="ftp_anon"><option value="ssh_version"><option value="http_methods"><option value="redis_info"><option value="sample_banner"><option value="smb_version"><option value="dns_version"><option value="snmp_sysdescr"><option value="rdp_info"><option value="vnc_auth"><option value="ntp_version"><option value="ldap_rootdse"><option value="sip_options"><option value="ike_version"><option value="http_webdav"></datalist></label>
        </div>
        <div class="flags">
        <label><input type="checkbox" id="fast" name="fast"> Fast (async engine)</label>
        <label><input type="checkbox" id="os" name="os"> OS fingerprinting</label>
        <label><input type="checkbox" id="service" name="service"> Service detection</label>
        <label><input type="checkbox" id="evasion" name="evasion"> Evasion</label>
        </div>
        <button id="runBtn" type="submit">Run scan</button>
        <p class="hint">Use only on networks you own or have permission to scan. SYN/UDP/OS need root or CAP_NET_RAW.</p>
        </form>
        <h2>Results</h2>
        <pre id="output" class="terminal">Ready.</pre>
        </div>
        <script>
        const out=document.getElementById('output');
        const btn=document.getElementById('runBtn');
        const dot=document.getElementById('dot');
        const st=document.getElementById('statusText');
        const tok=(()=>{const m=location.hash.match(/token=([0-9a-f]+)/);if(m){sessionStorage.setItem('almap_token',m[1]);history.replaceState(null,'',location.pathname);}return sessionStorage.getItem('almap_token')||'';})();
        const auth={'Authorization':'Bearer '+tok};
        async function checkStatus(){if(!tok){st.textContent='no API token - open the URL printed by almap --web';return;}try{const r=await fetch('/api/status',{headers:auth});if(r.status===401){st.textContent='API token rejected - open the URL printed by almap --web';return;}const j=await r.json();dot.classList.add('on');st.textContent='online - v'+(j.version||'')+' - '+r.status;}catch(e){st.textContent='offline';}}
        checkStatus();
        document.getElementById('scanForm').addEventListener('submit',async(e)=>{e.preventDefault();btn.disabled=true;out.textContent='Running...';const payload={targets:document.getElementById('targets').value.trim(),ports:document.getElementById('ports').value.trim(),scan_type:document.getElementById('scan_type').value,fast:document.getElementById('fast').checked,os:document.getElementById('os').checked,service:document.getElementById('service').checked,evasion:document.getElementById('evasion').checked,timeout:parseInt(document.getElementById('timeout').value,10)||1000,retries:document.getElementById('retries').value===''?3:parseInt(document.getElementById('retries').value,10),script:document.getElementById('script').value.trim()};if(payload.scan_type==='discovery'){payload.discover=true;}try{const r=await fetch('/api/scan',{method:'POST',headers:{...auth,'Content-Type':'application/json'},body:JSON.stringify(payload)});const t=await r.text();try{out.textContent=JSON.stringify(JSON.parse(t),null,2);}catch(_){out.textContent=(r.status>399?'Error '+r.status+': ':'')+t;}out.className='terminal '+(r.ok?'':'err');}catch(err){out.textContent='Request failed: '+err.message;out.className='terminal err';}btn.disabled=false;});
        </script>
        </body>
        </html>
        """);
}

// Returns true when the C layer took ownership of `client` (a scan was
// started; the reply comes later via ALMAP_EV_SCAN_DONE), else false
// (the reply was sent; the caller closes the client).
fn handle_scan(client: i32, body: const u8[:]) -> bool {
    let bad_field = escaped_string_field(body);
    if bad_field.len > 0 {
        var err: u8[>..] = [];
        var msg: u8[>..] = [];
        msg.append("invalid string escape in field ");
        msg.append(bad_field);
        error_json(err, msg);
        send_response(client, 400, "application/json", err);
        return false;
    }
    var targets: u8[>..] = [];
    var ports: u8[>..] = [];
    var scan_type: u8[>..] = [];
    var script_path: u8[>..] = [];
    let has_targets = json_string(body, "targets", targets);
    let has_ports = json_string(body, "ports", ports);
    let has_scan = json_string(body, "scan_type", scan_type);
    let has_script = json_string(body, "script", script_path);
    let fast_v, fast_found = json_bool(body, "fast");
    let os_v, os_found = json_bool(body, "os");
    let service_v, service_found = json_bool(body, "service");
    let evasion_v, evasion_found = json_bool(body, "evasion");
    let discover_v, discover_found = json_bool(body, "discover");
    let timeout_v, timeout_found = json_int(body, "timeout");
    let retries_v, retries_found = json_int(body, "retries");
    var is_fast = false;
    var is_os = false;
    var is_service = false;
    var is_evasion = false;
    var discover = false;
    var timeout_ms: i64 = 1000;
    var retries: i64 = 3;
    if fast_found && fast_v { is_fast = true; }
    if os_found && os_v { is_os = true; }
    if service_found && service_v { is_service = true; }
    if evasion_found && evasion_v { is_evasion = true; }
    if discover_found && discover_v { discover = true; }
    if timeout_found { timeout_ms = timeout_v; }
    if retries_found { retries = retries_v; }
    if !has_scan || scan_type.len == 0 {
        scan_type.append("connect");
    }
    if is_discovery_type(scan_type) { discover = true; }
    if !has_targets || targets.len == 0 {
        var err: u8[>..] = [];
        error_json(err, "targets is required");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if !discover && (!has_ports || ports.len == 0) {
        var err: u8[>..] = [];
        error_json(err, "ports is required");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if !is_valid_scan_type(scan_type) {
        var err: u8[>..] = [];
        error_json(err, "invalid scan_type (expected connect, syn, udp, or discovery)");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if timeout_ms < 1 || timeout_ms > 60000 {
        var err: u8[>..] = [];
        error_json(err, "invalid timeout (expected 1..60000)");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if retries < 0 || retries > 10 {
        var err: u8[>..] = [];
        error_json(err, "invalid retries (expected 0..10)");
        send_response(client, 400, "application/json", err);
        return false;
    }
    let is_syn = scan_type == "syn";
    let is_udp = scan_type == "udp";
    if is_fast && (discover || !is_syn && scan_type != "connect") {
        var err: u8[>..] = [];
        error_json(err, "--fast requires connect scan");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if is_fast && (is_service || is_evasion || is_os) {
        var err: u8[>..] = [];
        error_json(err, "--fast cannot be combined with service, evasion, or os");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if is_os && !is_syn {
        var err: u8[>..] = [];
        error_json(err, "os requires syn scan");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if is_service && (discover || is_syn || is_udp) {
        var err: u8[>..] = [];
        error_json(err, "service requires connect scan");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if is_evasion && (discover || is_udp) {
        var err: u8[>..] = [];
        error_json(err, "evasion requires syn or connect scan");
        send_response(client, 400, "application/json", err);
        return false;
    }
    var use_script = false;
    if has_script && script_path.len > 0 {
        use_script = true;
        if discover || is_udp {
            var err: u8[>..] = [];
            error_json(err, "script requires connect or syn scan");
            send_response(client, 400, "application/json", err);
            return false;
        }
        if is_fast {
            var err: u8[>..] = [];
            error_json(err, "script cannot be combined with fast");
            send_response(client, 400, "application/json", err);
            return false;
        }
        if is_service || is_os || is_evasion {
            var err: u8[>..] = [];
            error_json(err, "script cannot be combined with service, os, or evasion");
            send_response(client, 400, "application/json", err);
            return false;
        }
        if !valid_plugin_name(script_path) {
            var err: u8[>..] = [];
            error_json(err, "script must be a plugin name from the plugins/ directory (e.g. http_title), not a path");
            send_response(client, 400, "application/json", err);
            return false;
        }
    }
    let tl, tstatus = target::parse_mixed_target_list(targets);
    if tstatus != 0 {
        var err: u8[>..] = [];
        error_json(err, "invalid targets");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if !target::targets_allowed_mixed(tl) {
        var err: u8[>..] = [];
        error_json(err, "CIDR prefix too large; use /24 (IPv4) or /112 (IPv6) or smaller");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if !discover {
        let _prs, pok = target::parse_ports(ports);
        if !pok {
            var err: u8[>..] = [];
            error_json(err, "invalid ports");
            send_response(client, 400, "application/json", err);
            return false;
        }
    }
    var targets_c: u8[1024] = [0; 1024];
    var ports_c: u8[512] = [0; 512];
    var scan_c: u8[32] = [0; 32];
    var script_c: u8[512] = [0; 512];
    if !copy_cstr(targets_c[..], targets) {
        var err: u8[>..] = [];
        error_json(err, "targets too long");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if !discover && !copy_cstr(ports_c[..], ports) {
        var err: u8[>..] = [];
        error_json(err, "ports too long");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if !copy_cstr(scan_c[..], scan_type) {
        var err: u8[>..] = [];
        error_json(err, "scan_type too long");
        send_response(client, 400, "application/json", err);
        return false;
    }
    if use_script && !copy_cstr(script_c[..], script_path) {
        var err: u8[>..] = [];
        error_json(err, "script name too long");
        send_response(client, 400, "application/json", err);
        return false;
    }
    // Only a regular file directly inside <binary dir>/plugins/ is ever
    // handed to the scanner (and so to dlopen).
    var plugin_path: u8[4096] = [0; 4096];
    if use_script {
        let rn = almap_http_resolve_plugin(script_c[0], plugin_path[0], plugin_path.len as i32);
        if rn < 0 {
            var err: u8[>..] = [];
            err.append("{\"error\":\"unknown plugin '");
            output::json_escape(err, script_path);
            err.append("' (no such .so in the plugins/ directory)\"}");
            send_response(client, 400, "application/json", err);
            return false;
        }
    }
    let fast_i: i32 = if is_fast { 1 } else { 0 };
    let os_i: i32 = if is_os { 1 } else { 0 };
    let service_i: i32 = if is_service { 1 } else { 0 };
    let evasion_i: i32 = if is_evasion { 1 } else { 0 };
    let discover_i: i32 = if discover { 1 } else { 0 };
    let rc = almap_http_scan_start(client, targets_c[0], ports_c[0], scan_c[0], fast_i, os_i, service_i, evasion_i, discover_i, timeout_ms as i32, retries as i32, plugin_path[0]);
    if rc == 0 - 1 {
        var err: u8[>..] = [];
        error_json(err, "a scan is already running");
        send_response(client, 409, "application/json", err);
        return false;
    }
    if rc < 0 {
        var err: u8[>..] = [];
        error_json(err, "failed to start scan");
        send_response(client, 500, "application/json", err);
        return false;
    }
    return true;
}

// A scan ended (ALMAP_EV_SCAN_DONE): answer the requester, if any. The
// caller closes `client` afterwards when it is >= 0.
fn finish_scan(client: i32) {
    var head: u8[4096] = [0; 4096];
    var exit_buf: i32[1] = [0];
    var state_buf: i32[1] = [0];
    let hn = almap_http_scan_result(head[0], head.len as i32, exit_buf[0], state_buf[0]);
    if hn < 0 || client < 0 {
        return;
    }
    let state = state_buf[0];
    if state == 0 {
        let _ = almap_http_scan_send_body(client);
        return;
    }
    var err: u8[>..] = [];
    if state == 1 {
        err.append("{\"error\":\"");
        output::json_escape(err, head[..hn as i64]);
        err.append("\",\"exit_code\":");
        format(err, exit_buf[0]);
        err.append("}");
        send_response(client, 500, "application/json", err);
    } else if state == 2 {
        err.append("{\"error\":\"scan output exceeded ");
        format(err, almap_http_out_cap());
        err.append(" bytes\",\"truncated\":true}");
        send_response(client, 500, "application/json", err);
    } else if state == 3 {
        err.append("{\"error\":\"scan exceeded ");
        format(err, almap_http_scan_limit_s());
        err.append(" s wall-clock limit\"}");
        send_response(client, 504, "application/json", err);
    }
}

fn default_bind() -> const u8[:] {
    return "127.0.0.1";
}

fn serve(port: i64, bind_addr: const u8[:]) -> bool {
    if !valid_port(port) {
        print("error: invalid web port");
        return false;
    }
    var bind_c: u8[64] = [0; 64];
    if !copy_cstr(bind_c[..], bind_addr) {
        print("error: invalid --web-bind address");
        return false;
    }
    var tok_buf: u8[64] = [0; 64];
    if almap_http_random_token(tok_buf[0], tok_buf.len as i32) != 32 {
        print("error: cannot generate an API token (/dev/urandom unreadable)");
        return false;
    }
    let token = tok_buf[..32];
    let listen_fd = almap_http_listen(bind_c[0], port as i32);
    if listen_fd < 0 {
        print("error: cannot listen on ", bind_addr, ":", port);
        return false;
    }
    print("ALmap Web UI listening on ", bind_addr, ":", port, " (Ctrl+C to stop)");
    if bind_addr == "0.0.0.0" {
        print("open: http://<this-host-ip>:", port, "/#token=", token);
    } else {
        print("open: http://", bind_addr, ":", port, "/#token=", token);
    }
    print("API token: ", token, " (send as 'Authorization: Bearer <token>')");
    if bind_addr != "127.0.0.1" {
        print("warning: the Web UI is reachable beyond this machine; anyone with the token can run scans as this user");
    }
    loop {
        var req_buf: u8[8192] = [0; 8192];
        var fd_out: i32[1] = [0 - 1];
        var kind_out: i32[1] = [0];
        let n = almap_http_next(listen_fd, req_buf[0], req_buf.len as i32, fd_out[0], kind_out[0]);
        let client = fd_out[0];
        let kind = kind_out[0];
        if kind == 2 || kind == 3 {
            var err: u8[>..] = [];
            var st: i32 = 400;
            if kind == 2 {
                error_json(err, "request too large");
                st = 413;
            } else {
                error_json(err, "bad request");
            }
            send_response(client, st, "application/json", err);
            almap_http_close_linger(client);
            continue;
        }
        if kind == 4 {
            finish_scan(client);
            if client >= 0 { almap_http_close(client); }
            continue;
        }
        if kind != 1 || client < 0 || n <= 0 {
            if client >= 0 { almap_http_close(client); }
            continue;
        }
        let req = req_buf[..n as i64];
        var method: u8[>..] = [];
        var path: u8[>..] = [];
        let ok = parse_request_line(req, method, path);
        if !ok {
            var err: u8[>..] = [];
            error_json(err, "bad request");
            send_response(client, 400, "application/json", err);
            almap_http_close(client);
            continue;
        }
        let denied = check_access(req, path, port, token);
        if denied != 0 {
            var err: u8[>..] = [];
            if denied == 401 {
                error_json(err, "missing or invalid API token (Authorization: Bearer <token>)");
            } else {
                error_json(err, "forbidden Host or Origin");
            }
            send_response(client, denied, "application/json", err);
            almap_http_close(client);
            continue;
        }
        if is_status_request(method, path) {
            var body: u8[>..] = [];
            status_json(body);
            send_response(client, 200, "application/json", body);
        } else if is_scan_request(method, path) {
            if !json_content_type(req) {
                var err: u8[>..] = [];
                error_json(err, "Content-Type must be application/json");
                send_response(client, 415, "application/json", err);
                almap_http_close(client);
                continue;
            }
            if handle_scan(client, extract_body(req)) {
                continue; // the scan owns the client until it finishes
            }
        } else if is_index_request(method, path) {
            var body: u8[>..] = [];
            index_html(body);
            send_response(client, 200, "text/html; charset=utf-8", body);
        } else {
            var err: u8[>..] = [];
            error_json(err, "not found");
            send_response(client, 404, "application/json", err);
        }
        almap_http_close(client);
    }
}
