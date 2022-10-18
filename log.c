#define MAX_LOG_NUM 100

typedef struct {
    unsigned src_ip;
    unsigned dst_ip;
    unsigned src_port;
    unsigned dst_port;
    int protocol;
    int action;
}Log;
Log Logs[MAX_LOG_NUM];

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

void print_log(Log *pkg){
    printk("--------------------------log_begin----------------------------------\n");
    printk("src_ip: %d.%d.%d.%d src_port: %d\n",ip_one(pkg->src_ip),ip_two(pkg->src_ip),ip_three(pkg->src_ip),ip_four(pkg->src_ip),pkg->src_port);
    printk("dst_ip: %d.%d.%d.%d dst_port: %d\n",ip_one(pkg->dst_ip),ip_two(pkg->dst_ip),ip_three(pkg->dst_ip),ip_four(pkg->dst_ip),pkg->dst_port);
    printk("protocol: %d \n",pkg->protocol);
    printk("action: %d\n",pkg->action);
    printk("--------------------------log_end------------------------------------\n\n");
}