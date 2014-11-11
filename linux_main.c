#include "vpn.h"
#include <stdio.h>
#include <libevquick.h>

#ifdef VPN_SERVER

int vpn_get_key(char *user, struct vpn_key *key)
{
    const uint8_t secret[VPN_KEY_LEN] = "01234567890123456789012345678901";
    memcpy(key->key, secret, VPN_KEY_LEN);
    memcpy(key->iv, secret, VPN_IV_LEN);
    return 0;
}

int vpn_get_ipconf(char *user, union vpn_ipconfig *ipconf)
{
    return -1;
}


#endif



int main(int argc, char *argv[])
{
    evquick_init();
    
    for(;;) {
        evquick_loop();
    }

    return 0;
}
