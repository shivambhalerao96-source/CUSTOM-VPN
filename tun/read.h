#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <iostream>
#include "setup.h"
using namespace std;


#ifndef READ_H
#define READ_H

void read_packets(int fd);


void read_packets(int fd){

    cout<<"Reading from tun interface"<<endl;


char buffer[2000];
#include <fcntl.h>
#include <unistd.h>

//nt fd= create_tun_interface();

while (true) {
    int n = read(fd, buffer, sizeof(buffer));

    if (n < 0) {
        perror("read");
        break;
    }

    printf("Received packet of %d bytes\n", n);
}
}
#endif