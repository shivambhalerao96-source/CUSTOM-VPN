

#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/skbuff.h>



static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if(!skb) {
        return NF_ACCEPT;
    }

    struct iphdr *ip_hd = (struct iphdr *)skb_network_header(skb);

    if(skb-> protocol==htons(ETH_P_IPV6)){
        printk(KERN_INFO "IPv6 packet received\n");
    }
    else if(skb->protocol==htons(ETH_P_IP)){
        printk(KERN_INFO "IPv4 packet received\n");
    }
    else{
        printk(KERN_INFO "Unknown packet type received\n");
    }
    return NF_ACCEPT;

}