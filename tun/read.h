#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include "setup.h"


#ifndef READ_H
#define READ_H

void read_packets(int fd);


void read_packets(int fd){

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

}
}
#endif
