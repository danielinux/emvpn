#include "emvpn.h"
#include <fcntl.h>
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <unistd.h>


struct drv_tap_ctx {
  struct emvpn_dev *dev;
  int fd;
};

static struct drv_tap_ctx tap;

static int drv_tap_xmit(void *data, int len)
{
    return write(tap.fd, data, len);
}

static struct emvpn_dev dev = {
    .name = "",
    .context = &tap,
    .xmit = drv_tap_xmit

};
int drv_tap_init(char *name, void *opts)
{
    struct ifreq ifr;
    (void)opts;

    emvpn_dev_setup(&dev);

    tap.fd = open("/dev/net/tun", O_RDWR);
    if (tap.fd < 0) {
        fprintf(stderr, "Error opening tap: %s\n", strerror(errno));
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if(ioctl(tap.fd, TUNSETIFF, &ifr) < 0) {
        return(-1);
    }
    return tap.fd;
}
