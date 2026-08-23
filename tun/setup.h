#ifndef SETUP_H
#define SETUP_H

int up();
int assign_ipaddress();
int create_tun_interface(string vpn_ip);
void reroute();
void close_tun();

#endif   