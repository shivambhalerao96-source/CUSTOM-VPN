#ifndef SETUP_H
#define SETUP_H
#include<string>

using namespace std;

int up();
int assign_ipaddress(const string &vpn_ip);
int assign_ipv6_address(const string &vpn_ipv6);
int create_tun_interface(const string &vpn_ipv4, const string &vpn_ipv6, const string &vpn_server_ip);
void reroute(const char * vpn_server_ip);
void close_tun();

#endif