#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <cstdio>
//#include "setup.h"

using namespace std;


string get_router_ip() {

    // command to get only the ip address of next hop which is the router
    string command =
        "ip route show default | awk '/via/ {for (i=1; i<=NF; i++) if ($i==\"via\") {print $(i+1); exit}}'";

         

        // go parse the kernel output into string to be used later
    FILE* pipe = popen(command.c_str(), "r");

    if (pipe == nullptr) {
        
        return "";
    }

    // buffer used to not read garbage value
    char buffer[128];
    string result;

    
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
       
        result += buffer;
    }

    // cout<<"outside llop"<<endl;
    // cout<<"result="<<result<<endl;

    int status = pclose(pipe);

    // Remove trailing newline
    while (!result.empty() &&
           (result.back() == '\n' )) {
        result.pop_back();
    }

    return result;
}

void reroute(){

    string router= get_router_ip();// gets the router ip address

   

    if(router.empty()){ // error handling
       
        return;
    }

    // formulates the command to be executed

    // make ip packets with destination vpn server go through the wifi 
    string cmd= string("sudo ip route add 35.245.27.43 via ")+ router+ " dev wlo1";
    system(cmd.c_str());
    // make ip packets with destination other than vpn server go through tun0
    int status = system("sudo ip route add default dev tun0 metric 50");
    if( status <0){
        cout<<"tun0 not default"<<endl;
        return ;
    }
}



void close_tun(){
    system("sudo ip link delete tun0");
}

int up(){
    // makes tun0 active
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


