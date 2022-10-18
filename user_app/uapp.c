#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include "necessary.c"

void help(){
    printf("optional command:\n");
    printf("1. add rule (example: 1 src_ip src_port dst_ip dst_port protocol action(1 or 0))\n");
    printf("2. show all rules\n");
    printf("3. del rule (example: 1 src_ip src_port dst_ip dst_port protocol \n");
    printf("4. show log(use dmesg)\n");
    //printf("98. help\n");
    printf("99. exit\n");
    printf("use command dmesg tructures get logs\n");
    return;
}

void add_rule(int fd){
    Rule pkg;
    get_info(&pkg,ADD_RULE);
    write(fd,&pkg,sizeof(pkg));
}

void show_all_rules(int fd){
    //Rule pkg;
    //pkg.cmd = SHOW_ALL_RULE;
    //write(fd,&pkg,sizeof(pkg));
    show_rule(fd);
    return 0;
}
void del_rule(int fd){
    Rule pkg;
    get_info(&pkg,DEL_RULE);
    write(fd,&pkg,sizeof(pkg));
    return 0;
}

int main(){
    int cmd;
    int fd = open("/dev/wxk_cdev", O_RDWR);//need root
    if(fd<0){
        printf("error! open device error!\n");
    }
    //char tmp[100]={0};
    //add_rule(fd);
    //fflush(stdin);
    //add_rule(fd);
    //read(fd,tmp,10);  
    //printf("%s\n",tmp);  
    //write(fd,tmp,10);
    help();
    while (1)
    {
        printf("wsxk_cmd>");
        fflush(stdin);
        scanf("%d",&cmd);
        switch (cmd)
        {
        case 1:
            add_rule(fd);
            break;
        case 2:
            show_all_rules(fd);
            break;
        case 3:
            del_rule(fd);
            break;
        case 4:
            system("dmesg");
            break;
        case 99:
            printf("Bye~\n");
            return 0;
            break;
        default:
            printf("unknown cmd\n");
            help();    
            break;
        }

    }
    return 0;
}