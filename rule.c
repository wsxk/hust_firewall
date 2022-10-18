#include <linux/spinlock.h>
#define MAX_RULE_NUM 100

#define DEFAULT_ALLOW 100
#define DEFAULT_DENY  10

#define ACTION_PERMIT 1
#define ACTION_REJECT 0

#define PROTOCOL_TCP IPPROTO_TCP
#define PROTOCOL_UDP IPPROTO_UDP
#define PROTOCOL_ICMP IPPROTO_ICMP
#define ADD_RULE 1
#define DEL_RULE 2
#define SHOW_ALL_RULE 3


typedef struct {
    unsigned src_ip;
    unsigned dst_ip;
    unsigned src_port;
    unsigned dst_port;
    int protocol;
    int action;
}Rule;
Rule rules[MAX_RULE_NUM];
unsigned rule_num = 0;
unsigned default_strategy= DEFAULT_ALLOW;
spinlock_t rule_lock;

int rule_matching(Rule * tmp,Rule * rule_in_table){
    if(tmp->src_ip==rule_in_table->src_ip&&tmp->dst_ip==rule_in_table->dst_ip&&tmp->src_port==rule_in_table->src_port&&tmp->dst_port==rule_in_table->dst_port&&tmp->protocol==rule_in_table->protocol){
        return 1;    
    }else if(tmp->src_ip==rule_in_table->dst_ip&&tmp->dst_ip==rule_in_table->src_ip&&tmp->src_port==rule_in_table->dst_port&&tmp->dst_port==rule_in_table->src_port&&tmp->protocol==rule_in_table->protocol){
        return 1;
    }
    return 0;
}

int is_rule_equal(Rule * tmp1,Rule * tmp2){
    int i = (tmp1->src_ip == tmp2->src_ip) && (tmp1->src_port == tmp2->src_port);
    int j = (tmp1->dst_ip == tmp2->dst_ip) && (tmp1->dst_port == tmp2->dst_port);
    int y = (tmp1->action == tmp2->action) && (tmp1->protocol == tmp2->protocol);
    return (i&j&y);
}

int is_rule_allow(Rule * tmp){
    unsigned i;
    for(i=0;i<rule_num;i++){
        if(rule_matching(tmp,rules+i)){
            if((rules+i)->action==ACTION_PERMIT){
                return 1;
            }else{
                return 0;
            }
        }    
    }
    if(default_strategy==DEFAULT_ALLOW){
        return 1;
    }    
    return 0;
};

void rule_copy(Rule * dst,Rule * src){
    dst->action = src->action;
    dst->protocol = src->protocol;
    dst->src_ip = src->src_ip;
    dst->src_port = src->src_port;
    dst->dst_ip = src->dst_ip;
    dst->dst_port = src->dst_port;
}


int add_rule(Rule *pkg){
    if(rule_num<MAX_RULE_NUM){
        spin_lock(&rule_lock);
        rule_copy(&(rules[rule_num]),pkg);
        rule_num+=1;
        spin_unlock(&rule_lock);
        return 1;
    }else{
        printk("error! max_rule_num!\n");
    }
    return 0;
}

int del_rule(Rule *pkg){
    int i=0;
    for(i=0;i<rule_num;i++){
        if(is_rule_equal(pkg,&(rules[i]))){
            spin_lock(&rule_lock);
            rule_copy(&(rules[i]),&(rules[rule_num]));
            rule_num -=1;
            spin_unlock(&rule_lock);
            return 1;            
        }
    }
    printk("error! the rule doesn't exist!\n");
    return 0;
}