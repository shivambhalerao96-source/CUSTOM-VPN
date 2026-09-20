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

    

    int status = pclose(pipe);

    // Remove trailing newline
    while (!result.empty() &&
           (result.back() == '\n' )) {
        result.pop_back();
    }

    return result;
}

static string detect_external_iface() {

    string command =
        "ip route show default | awk '{for(i=1;i<=NF;i++) if ($i==\"dev\") {print $(i+1); exit}}'";

    FILE* pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) {
        return "";
    }

    char buffer[128];
    string iface;

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        iface += buffer;
    }

    pclose(pipe);

    while (!iface.empty() &&
           (iface.back() == '\n' || iface.back() == '\r' ||
            iface.back() == ' ' || iface.back() == '\t')) {
        iface.pop_back();
    }

    return iface;
}

void reroute(){

    string router= get_router_ip();// gets the router ip address
    string iface = detect_external_iface();

   

    if(router.empty()){ // error handling
       
        return;
    }

    // formulates the command to be executed

    if (iface.empty()) {
        cerr << "Failed to detect default network interface." << endl;
        return;
    }

    // make ip packets with destination vpn server go through the physical interface
    string cmd = string("sudo ip route add 35.226.148.101 via ") + router +
                 " dev " + iface;
    system(cmd.c_str());
    // make ip packets with destination other than vpn server go through tun0
    int status = system("sudo ip route add default dev tun0 metric 50");
    if( status <0){
        cout<<"tun0 not default"<<endl;
        return ;
    }

    // IPv6: route all IPv6 traffic through the tunnel too, so IPv6 can't
    // bypass the VPN via the physical interface. Note the encrypted UDP
    // tunnel to the server is still plain IPv4 (see client1.cpp's socket),
    // so unlike the IPv4 case above there is no "server IP" exception route
    // needed here.
    system("sudo ip -6 route add default dev tun0 metric 50");
}



void close_tun(){
    system("sudo ip link delete tun0");
}

int up(){
    // makes tun0 active
    return system("sudo ip link set dev tun0 up");
    cout<<"setted to up"<<endl;

}

int assign_ipaddress(const string & vpn_ip ){
    string cmd= "sudo ip addr add " + vpn_ip + " dev tun0";
     return system(cmd.c_str());
}

int assign_ipv6_address(const string & vpn_ipv6){
    // vpn_ipv6 is the bare address (e.g. "fd00:dead:beef::7"); the server's
    // allocation always hands out addresses from its /64 VPN range, so the
    // prefix length is fixed here the same way the IPv4 /24 is implied by
    // the "10.0.0.x" convention above.
    string cmd = "sudo ip -6 addr add " + vpn_ipv6 + "/64 dev tun0";
    return system(cmd.c_str());
}


// int main() {
//     create_tun_interface();
//     return 0;
// }

int create_tun_interface(const string & vpn_ipv4, const string & vpn_ipv6) {

    

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
if (assign_ipaddress(vpn_ipv4) != 0) {
    perror("Failed to set ip address");
    return -1 ;
}

// Assign the IPv6 address the server handed out alongside the IPv4 one, so
// the same TUN device carries both families. If the server (for whatever
// reason) didn't send one, skip this rather than failing the whole tunnel
// so IPv4-only behavior stays intact.
if (!vpn_ipv6.empty() && assign_ipv6_address(vpn_ipv6) != 0) {
    perror("Failed to set IPv6 address");
    return -1;
}

up();
reroute();
return fd;
}
