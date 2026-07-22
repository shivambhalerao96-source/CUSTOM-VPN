#include <cstdlib>

int main() {

    if (system("g++ setup.cpp -o setup") != 0)
        return 1;

    if (system("sudo setcap cap_net_admin+ep ./setup") != 0)
        return 1;

    return system("./setup");
}