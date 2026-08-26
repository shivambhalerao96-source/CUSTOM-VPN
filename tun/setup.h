#ifndef SETUP_H
#define SETUP_H
#include<string>

using namespace std;

int up();
int assign_ipaddress(const string &vpn_ip);
int create_tun_interface(const string &vpn_ip);
void reroute();
void close_tun();

#endif   