#include <cstdlib>
//#include "setup.h"

int main() {

    //create_tun_interface();



    if (system("g++ initialize.cpp setup.cpp -o initialize") != 0)
        return 1;

    if (system("sudo setcap cap_net_admin+ep ./initialize") != 0)
        return 1;

    return system("./initialize");
}