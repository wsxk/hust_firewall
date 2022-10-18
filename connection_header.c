#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>

spinlock_t con_lock;

#define MAX_CONNECTION_NUM 100
#define tick_num 200 // 2s
struct connection_structure{
    unsigned src_ip;
    unsigned dst_ip;
    unsigned src_port;
    unsigned dst_port;
    int protocol;
    unsigned long time;
    struct connection_structure * next;
};
typedef struct connection_structure Connection;
Connection * connections[MAX_CONNECTION_NUM]={0};

int time_out(unsigned long time){
    if(time_before(jiffies,time)){
        return 1;
    }else{
        return 0;
    }
}

unsigned long time_reset(void){
    return jiffies+ tick_num;
}


int compare_connection(Connection * position,Connection * pkg){
    if(position->src_ip==pkg->src_ip && position->dst_ip == pkg->dst_ip && position->src_port == pkg->src_port && position->dst_port == pkg->dst_port && position->protocol == pkg->protocol){
        return 1;
    }else if(position->src_ip==pkg->dst_ip && position->dst_ip == pkg->src_ip && position->src_port == pkg->dst_port && position->dst_port == pkg->src_port && position->protocol == pkg->protocol){
        return 1;
    }    
    return 0;
}

int copy_connection_data(Connection *dst,Connection * src){
    dst->src_ip = src->src_ip;
    dst->src_port = src->src_port;
    dst->dst_ip = src->dst_ip;
    dst->dst_port = src->dst_port;
    dst->protocol = src->protocol;
    return 1;
}

int create_hash_index(unsigned src_ip,unsigned src_port,unsigned dst_ip,unsigned dst_port,unsigned protocol){
    return (src_ip^src_port^dst_ip^dst_port^protocol)%MAX_CONNECTION_NUM;
}

int exist_connection(Connection *pkg){
    int index = create_hash_index(pkg->src_ip,pkg->src_port,pkg->dst_ip,pkg->dst_port,pkg->protocol);
    Connection * position = connections[index]; 
    while(position){
        if(compare_connection(position,pkg)){
            spin_lock(&con_lock);
            position->time = time_reset();
            spin_unlock(&con_lock);
            return 1;
        }
        position = position->next;
    }
    return 0;
}
int del_connection(Connection *pkg){
    int index = create_hash_index(pkg->src_ip,pkg->src_port,pkg->dst_ip,pkg->dst_port,pkg->protocol);
    Connection * position = connections[index];
    if(compare_connection(position,pkg)){
        connections[index]=position->next;
        kfree(position);
        return 1;
    }
    while(position->next){
        if(compare_connection(position->next,pkg)){
            Connection * tmp = position->next;
            position->next = tmp->next;
            kfree(tmp);
            tmp = 0;
            return 1;
        }
        position = position->next;
    }
    return 0;
};
void update_connection_chains(Connection * position){
    while(position){
        Connection * tmp = position->next;
        if(time_out(position->time)){
            del_connection(position);
        }
        position = tmp;
    }
}

int add_connection(Connection *pkg){
    spin_lock(&con_lock);
    int index = create_hash_index(pkg->src_ip,pkg->src_port,pkg->dst_ip,pkg->dst_port,pkg->protocol);
    Connection * position = connections[index];
    // before add,check the connection chain to del the time_out connections;
    update_connection_chains(position);
    if(position==NULL){
        position = (Connection *)kmalloc(sizeof(Connection),GFP_KERNEL);
        copy_connection_data(position,pkg);
        position->time = time_reset();
        position->next=NULL;
        connections[index]=position;        
    }else{
        while(position->next !=NULL){
            position = position->next;
        }
        Connection * tmp = (Connection *)kmalloc(sizeof(Connection),GFP_KERNEL);
        copy_connection_data(tmp,pkg);
        tmp->next = NULL;
        tmp->time = time_reset();
        position->next = tmp;
    }
    spin_unlock(&con_lock);
    return 1;
}

