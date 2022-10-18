#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/timer.h>

#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <asm/uaccess.h>
#include <net/ip.h>
#include "cdev.c"
//#include "rule.c"
//#include "connection_header.c"
//#include "log.c"
#include "nat.c"

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("wxk");

void skb_to_connection(struct sk_buff *skb,Connection * pkg,int protocol){
    
    if(protocol == PROTOCOL_TCP){
        struct iphdr * ip = ip_hdr(skb);
        struct tcphdr *tcp = tcp_hdr(skb);
        //Connection pkg;
        pkg->src_ip = ntohl(ip->saddr);
        pkg->dst_ip = ntohl(ip->daddr);
        pkg->src_port = ntohs(tcp->source);
        pkg->dst_port = ntohs(tcp->dest);
        pkg->protocol = ip->protocol;
    }else if(protocol ==PROTOCOL_UDP){
        struct udphdr * udp = udp_hdr(skb);
        struct iphdr * ip = ip_hdr(skb);
        pkg->src_ip = ntohl(ip->saddr);
        pkg->dst_ip = ntohl(ip->daddr);
        pkg->src_port = ntohs(udp->source);
        pkg->dst_port = ntohs(udp->dest);
        pkg->protocol = ip->protocol;
        
    }else if(protocol==PROTOCOL_ICMP){
        struct iphdr * ip = ip_hdr(skb);
        struct icmphdr * icmp = icmp_hdr(skb);
        pkg->src_ip = ntohl(ip->saddr);
        pkg->dst_ip = ntohl(ip->daddr);
        //pkg->src_port = (icmp->type <<8)|(icmp->code);
        //pkg->dst_port = icmp->checksum;
        pkg->src_port = 0;//icmp default port 0
        pkg->dst_port = 0;
        pkg->protocol = ip->protocol;
    }
}

void connection_to_rule(Rule * tmp,Connection * pkg){
    tmp->src_ip = pkg->src_ip;
    tmp->dst_ip = pkg->dst_ip;
    tmp->src_port = pkg->src_port;
    tmp->dst_port = pkg->dst_port;
    tmp->protocol = pkg->protocol;
}

void connection_to_log(Connection * pkg,Log *tmp,int action){
    tmp->src_ip = pkg->src_ip;
    tmp->dst_ip = pkg->dst_ip;
    tmp->src_port = pkg->src_port;
    tmp->dst_port = pkg->dst_port;
    tmp->protocol = pkg->protocol;
    tmp->action = action;
}

void call_log(Connection * pkg,int action){
    Log tmp;
    connection_to_log(pkg,&tmp,action);
    print_log(&tmp);       
}

unsigned int process_tcp(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    Connection pkg;
    struct tcphdr * tcp = tcp_hdr(skb);
    skb_to_connection(skb,&pkg,PROTOCOL_TCP);
    if(exist_connection(&pkg)){
        call_log(&pkg,ACTION_PERMIT);
        return NF_ACCEPT;
    }
    if(tcp->syn&&(!tcp->ack)){
        Rule tmp;
        connection_to_rule(&tmp,&pkg);
        if(is_rule_allow(&tmp)){
            add_connection(&pkg);
            call_log(&pkg,ACTION_PERMIT);
            return NF_ACCEPT;
        }
    }
    call_log(&pkg,ACTION_REJECT);
    return NF_DROP;
}



unsigned int process_udp(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    Connection pkg;
    struct icmphdr *icmph;
    icmph = icmp_hdr(skb);
    skb_to_connection(skb,&pkg,PROTOCOL_UDP);
    if(exist_connection(&pkg)){
        call_log(&pkg,ACTION_PERMIT);
        return NF_ACCEPT;
    }
    Rule tmp;
    connection_to_rule(&tmp,&pkg);
    if(is_rule_allow(&tmp)){
        add_connection(&pkg);
        call_log(&pkg,ACTION_PERMIT);
        return NF_ACCEPT;
    }
    call_log(&pkg,ACTION_REJECT);
    return NF_DROP;
}
unsigned int process_icmp(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    Connection pkg;
    skb_to_connection(skb,&pkg,PROTOCOL_ICMP);
    if(exist_connection(&pkg)){
        call_log(&pkg,ACTION_PERMIT);
        return NF_ACCEPT;
    }
    Rule tmp;
    connection_to_rule(&tmp,&pkg);
    if(is_rule_allow(&tmp)){
        add_connection(&pkg);
        call_log(&pkg,ACTION_PERMIT);
        return NF_ACCEPT;
    }
    call_log(&pkg,ACTION_REJECT);
    return NF_DROP;
}

//the main check func
unsigned int packet_check(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    struct iphdr * ip = ip_hdr(skb);
    if(ip->protocol == PROTOCOL_TCP){
        return process_tcp(priv,skb,state);
    }else if(ip->protocol == PROTOCOL_UDP){
        return process_udp(priv,skb,state);
    } else if (ip->protocol == PROTOCOL_ICMP){
        return process_icmp(priv,skb,state);
    }else{
        return NF_ACCEPT;
    }
    return NF_ACCEPT;
};

unsigned int local_out_hook(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return NF_ACCEPT;
};

unsigned int post_routing_hook(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return packet_check(priv,skb,state);
};

unsigned int pre_routing_hook(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return packet_check(priv,skb,state);
};

unsigned int local_in_hook(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return NF_ACCEPT;
};

unsigned int forward_hook(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return NF_ACCEPT;
};



// unsigned int pre_routing_nat_hook(void *priv,struct sk_buff *skb,const struct nf_hook_state * state){
//     //get dst_ip check whether need DNAT
//     if(exist_nat()){
//         DNAT_change();
//     }
//     return NF_ACCEPT;
// }

// unsigned int post_routing_nat_hook(void *priv,struct sk_buff *skb,const struct nf_hook_state * state){
//     //get src_ip check whether need SNAT
//     if(exist_nat()){
//         SNAT_change();
//     }
//     return NF_ACCEPT;
// }

//nat
// static struct nf_hook_ops pre_routing_nat={
//     .hook = pre_routing_nat_hook,
//     .pf = PF_INET,
//     .hooknum = NF_INET_PRE_ROUTING,
//     .priority = NF_IP_PRI_NAT_DST
// };
// static struct nf_hook_ops post_routing_nat = {
//     .hook = post_routing_nat_hook,
//     .pf = PF_INET,
//     .hooknum = NF_INET_POST_ROUTING,
//     .priority = NF_IP_PRI_NAT_SRC,
// };
//connect
static struct nf_hook_ops pre_routing={
    .hook = pre_routing_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops forward={
    .hook = forward_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_FORWARD,
    .priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops post_routing={
    .hook = post_routing_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops local_in={
    .hook = local_in_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops local_out={
    .hook = local_out_hook,//function pointer
    .pf = PF_INET, //ipv4
    .hooknum = NF_INET_LOCAL_OUT, //which position to hook
    .priority = NF_IP_PRI_FIRST // priority
};


static int begin_hook(void){
    //init lock
    spin_lock_init(&con_lock);
    spin_lock_init(&rule_lock);
    spin_lock_init(&nat_lock);
    //netfilter hook
    printk("hook register!\n");
    nf_register_net_hook(&init_net,&pre_routing);
    nf_register_net_hook(&init_net,&post_routing);
    
    //cdev register
    printk("begin register cdev!\n");
    cdev_init(&cdev,&cdev_fops);
	alloc_chrdev_region(&devid,2,255,MYNAME);//output first_minor_num the_num_of_distributed_devices device_name
	printk(KERN_INFO "MAJOR Number is %d\n",MAJOR(devid));
	printk(KERN_INFO "MINOR Number is %d\n",MINOR(devid));
    printk("use command `cat /proc/devices | grep %s` to see the major number\n",MYNAME);
    printk("use command `mknod /dev/%s c %d %d` to create the node\n",MYNAME,MAJOR(devid),MINOR(devid));//attention : authority
	cdev_add(&cdev,devid,255);//cdev devid(major and minor) the_num_of_distributed_devices
    //create node
    cls = class_create(THIS_MODULE,MYNAME);
    class_dev = device_create(cls, NULL, devid, NULL, MYNAME);

    return 0;
}

static void exit_hook(void){
    // hook unregister
    nf_unregister_net_hook(&init_net,&pre_routing);
    nf_unregister_net_hook(&init_net,&post_routing);
    printk("hook unregister!\n");
    // destroy device
    device_destroy(cls, devid);
    class_destroy(cls);
    // cdev unregister
	cdev_del(&cdev);
	unregister_chrdev_region(devid,255);
    printk("cdev unregister!\n");
}

module_init(begin_hook);
module_exit(exit_hook);