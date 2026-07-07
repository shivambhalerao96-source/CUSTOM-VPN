These are my Notes and the tech which I am going to use in this vpn construction

Packet accessing use a c++ file to first access the packets
We use netfilter library to access and modify the ip packets to use this we use hooks to trap the packets  there are various positions from where we can acquire the ip packet

sk_buff is a custom class which stores pointers to the memory where the ip packets are stored

how to execute the c++ program in kernel space it is suggested ebpf
