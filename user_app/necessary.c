#include <stdio.h>
#include <stdlib.h>
#define ADD_RULE 1
#define DEL_RULE 2
#define SHOW_ALL_RULE 3
#define MAX_RULE_NUM 100

typedef struct {
    unsigned src_ip;
    unsigned dst_ip;
    unsigned src_port;
    unsigned dst_port;
    int protocol;
    int action;
}Rule;
Rule rule_cache[MAX_RULE_NUM];

int ip_one(unsigned ip){
    return (ip>>24)&255;
}
int ip_two(unsigned ip){
    return (ip>>16)&255;
}
int ip_three(unsigned ip){
    return (ip>>8)&255;
}
int ip_four(unsigned ip){
    return ip&255;
}
unsigned value_to_ip(int a1,int a2,int a3,int a4){
    return (a1<<24)|(a2<<16)|(a3<<8)|(a4);
}

void get_info(Rule *pkg,unsigned cmd){
    int a1,a2,a3,a4,port,protocol,action;
    //get src_ip
    scanf("%d.%d.%d.%d",&a1,&a2,&a3,&a4);
    pkg->src_ip = value_to_ip(a1,a2,a3,a4);
    //get src_port
    scanf("%d",&port);
    pkg->src_port = port;
    //get dst_ip
    scanf("%d.%d.%d.%d",&a1,&a2,&a3,&a4);
    pkg->dst_ip= value_to_ip(a1,a2,a3,a4);
    //get dst_port
    scanf("%d",&port);
    pkg->dst_port = port;
    //get protocol
    scanf("%d",&protocol);
    pkg->protocol = protocol;
    //get action
    scanf("%d",&action);
    pkg->action = action;
    pkg->action = pkg->action | (cmd << 24);
    // test
    printf("pkg test:\n");
    printf("src_ip:%d src_port:%d\n",pkg->src_ip,pkg->src_port);
    printf("dst_ip:%d dst_port:%d\n",pkg->dst_ip,pkg->dst_port);
    printf("protocol:%d action:%d\n",pkg->protocol,pkg->action);
}

void show_rule(int fd){
    int i=read(fd,(char *)rule_cache,MAX_RULE_NUM*sizeof(Rule));
    printf("--------------------rules-------------------\n");
    for(int j=0;j<i;j++){
        printf("src_ip: %d.%d.%d.%d src_port: %d\n",ip_one(rule_cache[j].src_ip),ip_two(rule_cache[j].src_ip),ip_three(rule_cache[j].src_ip),ip_four(rule_cache[j].src_ip),rule_cache[j].src_port);
        printf("dst_ip: %d.%d.%d.%d dst_port: %d\n",ip_one(rule_cache[j].dst_ip),ip_two(rule_cache[j].dst_ip),ip_three(rule_cache[j].dst_ip),ip_four(rule_cache[j].dst_ip),rule_cache[j].dst_port);
        printf("protocol: %d\n",rule_cache[j].protocol);
        printf("action: %d\n",rule_cache[j].action);
    }
    printf("--------------------ends--------------------\n");
}