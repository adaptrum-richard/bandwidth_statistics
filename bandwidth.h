#ifndef __BANDWIDTH_H__
#define __BANDWIDTH_H__
#include <linux/types.h>

#define NIPQUAD(addr) \
    ((unsigned char*)&addr)[0], \
    ((unsigned char*)&addr)[1], \
    ((unsigned char*)&addr)[2], \
    ((unsigned char*)&addr)[3]  

struct bandwidth_info
{
    uint64_t current_traffic;
    __be32 ipinfo;
};

#define BR0_IFNAME "br0"
#define WAN_IFNAME "eth1"

#endif