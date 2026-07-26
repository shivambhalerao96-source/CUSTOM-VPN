#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include "setup.h"

using namespace std;


void reroute(){
    system("sudo ip route replace default dev tun0");
}

void close_tun(){
    system("sudo ip link delete tun0");
}

int up(){
    return system("sudo ip link set dev tun0 up");
    cout<<"setted to up"<<endl;

}

int assign_ipaddress(){
     return system("sudo ip addr add 10.0.0.1/24 dev tun0");
}


// int main() {
//     create_tun_interface();
//     return 0;
// }

int create_tun_interface() {

    

int fd = open("/dev/net/tun", O_RDWR); // opens the file /dev/net/tun in read/write mode
if(fd < 0) {
    perror("Failed to create interface");
    return -1 ;
}

struct ifreq ifr = {};
ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // flag says that create a TUN device and do not provide packet information

// IFF_NO_PI does not include packet info 
strcpy(ifr.ifr_name, "tun0");

int f=ioctl(fd, TUNSETIFF, &ifr);
if(f < 0) {
    perror("Failed to set interface");
   
    return  -1;
}
if (assign_ipaddress() != 0) {
    perror("Failed to set ip address");
    return -1 ;
}

up();
reroute();
return fd;
}


