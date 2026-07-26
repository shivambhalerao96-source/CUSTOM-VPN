#include <cstdlib>
#include "setup.h"
#include "read.h"

int main() {

    int tun_fd = create_tun_interface();
    if (tun_fd < 0) {
        return 1;
    }
    read_packets(tun_fd);


    // if (system("g++ setup.cpp -o setup") != 0)
    //     return 1;

    // if (system("sudo setcap cap_net_admin+ep ./setup") != 0)
    //     return 1;

    // return system("./setup");
}