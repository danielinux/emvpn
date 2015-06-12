#include "emvpn.h"
#include <fcntl.h>
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <unistd.h>


struct drv_stdio_ctx {
  struct emvpn_dev *dev;
  int fd_in;
  int fd_out;
};

static struct drv_stdio_ctx stdio;

static int drv_stdio_xmit(void *data, int len)
{
    return write(stdio.fd_out, data, len);
}

static struct emvpn_dev dev = {
    .name = "",
    .context = &stdio,
    .xmit = drv_stdio_xmit

};

int drv_stdio_init(char *name, void *opts)
{
    (void)opts;

    emvpn_dev_setup(&dev);

    stdio.fd_in = dup(STDIN_FILENO);
    stdio.fd_out = dup(STDOUT_FILENO);
    if (stdio.fd_in < 0 || stdio.fd_out < 0) {
        fprintf(stderr, "Error opening stdio: %s\n", strerror(errno));
    }
    return stdio.fd_in;
}
