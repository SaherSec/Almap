/* Unit tests for the pure HTTP helpers in c/http.c.
 * Build: gcc -std=c99 -Wall -Wextra -I c tests/test_http.c c/http.c -o /tmp/test_http */
#include <stdio.h>
#include <string.h>

#include "http.h"

static int failures = 0;

static void check_cl(const char *name, const char *hdr, int want_rc,
                     long want_val) {
    long v = -7;
    int rc = almap_http_parse_content_length((const unsigned char *)hdr,
                                             (int)strlen(hdr), &v);

    if (rc != want_rc || (want_rc == 1 && v != want_val)) {
        printf("FAIL %s: rc=%d (want %d) val=%ld (want %ld)\n", name, rc,
               want_rc, v, want_val);
        failures++;
    } else {
        printf("ok   %s\n", name);
    }
}

#define H(extra) "POST /api/scan HTTP/1.1\r\nHost: x\r\n" extra "\r\n"

int main(void) {
    check_cl("absent", H(""), 0, 0);
    check_cl("12", H("Content-Length: 12\r\n"), 1, 12);
    check_cl("zero", H("Content-Length: 0\r\n"), 1, 0);
    check_cl("max 8192", H("Content-Length: 8192\r\n"), 1, 8192);
    check_cl("8193 too large", H("Content-Length: 8193\r\n"), -1, 0);
    check_cl("23 digits", H("Content-Length: 99999999999999999999999\r\n"), -1, 0);
    check_cl("negative", H("Content-Length: -1\r\n"), -1, 0);
    check_cl("trailing junk", H("Content-Length: 1x\r\n"), -1, 0);
    check_cl("empty value", H("Content-Length:\r\n"), -1, 0);
    check_cl("lower-case name", H("content-length: 5\r\n"), 1, 5);
    check_cl("conflicting duplicates",
             H("Content-Length: 5\r\nContent-Length: 6\r\n"), -1, 0);
    check_cl("not a content-length header",
             H("X-Content-Length: 5\r\n"), 0, 0);
    if (ALMAP_HTTP_ERR_TOO_LARGE != -413 || ALMAP_HTTP_ERR_BAD_LENGTH != -400) {
        printf("FAIL error constants\n");
        failures++;
    }
    return failures ? 1 : 0;
}
