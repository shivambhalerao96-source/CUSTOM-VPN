#include <cstdlib>

// re route all the ip packets to tun 

int main() {
    system("default dev tun0");
}