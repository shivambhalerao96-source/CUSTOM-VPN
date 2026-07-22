// to close the tun interface and remove the ip route to tun
#include <cstdlib>


int main()
{
    return system("sudo ip link delete tun0");
}