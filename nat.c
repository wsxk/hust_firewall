#include <linux/spinlock.h>
#include "connection_header.c"
#define MAX_NAT_NUM 100

spinlock_t nat_lock;

typedef struct {
    unsigned src_ip;
    unsigned src_port;
    unsigned changed_ip;
    unsigned changed_port;
}Nat;
Nat nat_table[MAX_NAT_NUM];
unsigned nat_num = 0;
unsigned firewall_protect_ip = -1062670971; //192.168.237.133
unsigned firewall_protect_port = 888;//nat_ip

// int exist_nat(Connection *pkg){

// }

