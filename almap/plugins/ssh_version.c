/* ssh_version - SSH protocol and software version from the identification line. */
#include "arsenal_ssh.h"

int almap_script_run(AlScriptContext *ctx) {
    char banner[256];
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = ar_ssh_open(ctx, banner, sizeof(banner));
    if (fd < 0) {
        ar_out(ctx, "ssh_version: no SSH identification line");
        return 0;
    }
    close(fd);
    {
        /* SSH-<protocol>-<software>[ <comment>] */
        char *dash = strchr(banner + 4, '-');
        if (dash == NULL) {
            ar_out(ctx, "ssh_version: malformed identification line '%s'", banner);
            return 0;
        }
        *dash = '\0';
        ar_out(ctx, "ssh_version: protocol %s, software %s", banner + 4, dash + 1);
    }
    return 0;
}
