#include "vpn.h"
#include <stdio.h>
#include <libevquick.h>



int main(int argc, char *argv[])
{
    evquick_init();
    
    for(;;) {
        evquick_loop();

    }

    return 0;
}
