#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netfilter_ipv4.h>
#include <linux/rwlock.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/semaphore.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif
#include "bandwidth.h"
#include "tree_map.h"

static __be32 local_ipaddr = 0;
static __be32 local_subnet_mask = 0;
static __be32 pre_local_ipaddr = 0;
static __be32 pre_local_subnet_mask = 0;
static long_map *bw_map_upload = NULL;
static long_map *bw_map_download = NULL;
static spinlock_t bandwidth_lock_upload = __SPIN_LOCK_UNLOCKED(bandwidth_lock_upload);
static spinlock_t bandwidth_lock_download = __SPIN_LOCK_UNLOCKED(bandwidth_lock_download);
DEFINE_SEMAPHORE(userspace_lock_upload);
DEFINE_SEMAPHORE(userspace_lock_download);
struct timer_list local_bw_timer;

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *bw_procdir_upload;
static struct proc_dir_entry *bw_procdir_download;
#endif

/* 
 * set max bandwidth to be max possible using 63 of the
 * 64 bits in our record.  In some systems uint64_t is treated
 * like signed, so to prevent errors, use only 63 bits
 */
static uint64_t pow64(uint64_t base, uint64_t pow)
{
    uint64_t val = 1;
    if(pow > 0)
    {
        val = base*pow64(base, pow-1);
    }
    return val;
}
static uint64_t get_bw_record_max(void) /* called by init to set global variable */
{
    return  (pow64(2,62)) + (pow64(2,62)-1);
}
static uint64_t bandwidth_record_max;


#define ADD_UP_TO_MAX(original,add,is_check) \
    (bandwidth_record_max - original > add && is_check== 0) ? \
        original+add : (is_check ? original : bandwidth_record_max);

static long_map *init_bw_map_upload(void)
{
    unsigned long num_destroyed = 0;
    down(&userspace_lock_upload);
    spin_lock_bh(&bandwidth_lock_upload);
    if(bw_map_upload)
        destroy_long_map(bw_map_upload, DESTROY_MODE_FREE_VALUES, &num_destroyed);
    bw_map_upload = initialize_long_map();
    if(NULL == bw_map_upload)
    {
        printk("init_bw_map_upload initialize_long_map failed\n");
    }
    spin_unlock_bh(&bandwidth_lock_upload);
    up(&userspace_lock_upload);
    return bw_map_upload;
}
static long_map *init_bw_map_download(void)
{
    unsigned long num_destroyed = 0;
    down(&userspace_lock_download);
    spin_lock_bh(&bandwidth_lock_download);
    if(bw_map_download)
        destroy_long_map(bw_map_download, DESTROY_MODE_FREE_VALUES, &num_destroyed);
    bw_map_download = initialize_long_map();
    if(NULL == bw_map_download)
    {
        printk("init_bw_map_download initialize_long_map failed\n");
    }
    spin_unlock_bh(&bandwidth_lock_download);
    up(&userspace_lock_download);
    return bw_map_download;
}

static void get_local_info(void)
{
    struct net_device *each_dev = NULL;
    struct in_device *in_dev = NULL;

    read_lock(&dev_base_lock);
    for_each_netdev(&init_net, each_dev)
    {
        if(each_dev && !strcmp(each_dev->name, BR0_IFNAME))
        {
            rcu_read_lock();
            if ((in_dev = __in_dev_get_rcu(each_dev)) != NULL && in_dev->ifa_list)
            {
                local_ipaddr = in_dev->ifa_list->ifa_local;
                local_subnet_mask = in_dev->ifa_list->ifa_mask;
            }
            rcu_read_unlock();
        }
    }
    read_unlock(&dev_base_lock);
}


static void local_bw_time_func(unsigned long data)
{
    if(local_ipaddr == 0 || local_subnet_mask == 0)
    {
        get_local_info();
        if(local_ipaddr == 0 || local_subnet_mask == 0 )
        {
             mod_timer(&local_bw_timer,jiffies + 2*HZ);
             goto out;
        }
        printk("Get ip = %d.%d.%d.%d,mask = %d.%d.%d.%d\n", NIPQUAD(local_ipaddr),
            NIPQUAD(local_subnet_mask));
        pre_local_ipaddr = local_ipaddr;
        pre_local_subnet_mask = local_subnet_mask;
        mod_timer(&local_bw_timer,jiffies + 30*HZ);
        goto out;
    }
    else
    {
        if(pre_local_ipaddr != local_ipaddr || pre_local_subnet_mask != local_subnet_mask)
        {
            get_local_info();
            pre_local_ipaddr = local_ipaddr;
            pre_local_subnet_mask = local_subnet_mask;
            mod_timer(&local_bw_timer,jiffies + 30*HZ);
            printk("local change to ip = %d.%d.%d.%d,mask = %d.%d.%d.%d\n", NIPQUAD(local_ipaddr),
                NIPQUAD(local_subnet_mask));
            init_bw_map_download();
            init_bw_map_upload();
            goto out;
        }
        get_local_info();
    }
    mod_timer(&local_bw_timer,jiffies + 10*HZ);
out:
    return;
}

static void init_local_bw_timer(void)
{
    setup_timer(&local_bw_timer,local_bw_time_func,(unsigned long)"local__timer");
    local_bw_timer.expires = jiffies + 3*HZ;
    add_timer(&local_bw_timer);
}
static void exit_local_bw_timer(void)
{
    del_timer(&local_bw_timer);
}



static int compare_ipaddr_to_lan(__be32 ip)
{
    if(!local_ipaddr || !local_subnet_mask || !ip)
        return -1;

    return ((local_ipaddr & local_subnet_mask ) == (ip & local_subnet_mask) ? 0 : -1); 
}

static struct bandwidth_info *init_bandwidth_info(void)
{
    struct bandwidth_info *bw_info = NULL;
    bw_info = (struct bandwidth_info *)malloc(sizeof(struct bandwidth_info));
    if(bw_info)
    {
        bw_info->ipinfo = 0;
        bw_info->current_traffic = 0;
    }
    return bw_info;
}

static unsigned int bandwidth_upload(unsigned int hooknum,
                      struct sk_buff *skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *))
{

    struct iphdr *iph = ip_hdr(skb);
    __be32 ipaddr;
    struct bandwidth_info *bw_info = NULL;
    /*-o eth1 && -s 192.168.8.0/24*/
    if(!strcmp(out->name,WAN_IFNAME) && !compare_ipaddr_to_lan(iph->saddr))
    {
        //printk("upload %d = %d.%d.%d.%d\n", i++, NIPQUAD(iph->saddr));
        ipaddr = iph->saddr;
        spin_lock_bh(&bandwidth_lock_upload);
        bw_info = (struct bandwidth_info *)get_long_map_element(bw_map_upload, 
            (unsigned long)ipaddr);
        if(bw_info == NULL)
        {
            bw_info = init_bandwidth_info();
            if(!bw_info)
            {
                printk("init_bandwidth_info failed\n");
                spin_unlock_bh(&bandwidth_lock_upload);
                goto out;
            }
            bw_info->ipinfo = ipaddr;
            printk("upload map add ip %d.%d.%d.%d\n", NIPQUAD(ipaddr));
            set_long_map_element(bw_map_upload, (unsigned long)ipaddr, (void*)bw_info);
        }
        bw_info->current_traffic = ADD_UP_TO_MAX(bw_info->current_traffic, 
            (uint64_t)skb->len, 0);
        spin_unlock_bh(&bandwidth_lock_upload);
    }

out:
    return NF_ACCEPT;
}

static unsigned int bandwidth_download(unsigned int hooknum,
                      struct sk_buff *skb,
                      const struct net_device *in,
                      const struct net_device *out,
                      int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    __be32 ipaddr;
    struct bandwidth_info *bw_info = NULL;
    /*-i eth1 -d 192.168.8.0/24*/
    if(!strcmp(in->name, WAN_IFNAME) && !compare_ipaddr_to_lan(iph->daddr))
    {
        ipaddr = iph->daddr;
        spin_lock_bh(&bandwidth_lock_download);
        bw_info = (struct bandwidth_info *)get_long_map_element(bw_map_download, 
            (unsigned long)ipaddr);
        if(bw_info == NULL)
        {
            bw_info = init_bandwidth_info();
            if(!bw_info)
            {
                printk("init_bandwidth_info failed\n");
                spin_unlock_bh(&bandwidth_lock_download);
                goto out;
            }
            bw_info->ipinfo = ipaddr;
            printk("download map add ip %d.%d.%d.%d\n", NIPQUAD(ipaddr));
            set_long_map_element(bw_map_download, (unsigned long)ipaddr, (void*)bw_info);
        }

        bw_info->current_traffic = ADD_UP_TO_MAX(bw_info->current_traffic, 
            (uint64_t)skb->len, 0);
        spin_unlock_bh(&bandwidth_lock_download);
    }

out:
    return NF_ACCEPT;
}

static struct nf_hook_ops bandwidth_download_hook = 
{
    .hook = bandwidth_download,
    .hooknum = NF_INET_FORWARD,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FILTER - 1,   /* 高于iptables的filter表 */
};

static struct nf_hook_ops bandwidth_upload_hook = 
{
    .hook = bandwidth_upload,
    .hooknum = NF_INET_POST_ROUTING,
    .pf = PF_INET,
    .priority = NF_IP_PRI_MANGLE - 1,   /* 高于iptables的mangle表 */
};

#ifdef CONFIG_PROC_FS

static struct seq_file *global_download_seq_file = NULL;
static struct seq_file *global_upload_seq_file = NULL;
void bw_apply_download(unsigned long key,void *value)
{
    struct bandwidth_info *info = (struct bandwidth_info *)value;
    if(global_download_seq_file)
    {
        seq_printf(global_download_seq_file, "%d.%d.%d.%d,%lu\n", 
            NIPQUAD(info->ipinfo),
            info->current_traffic);
    }
}

static int bw_proc_show_download(struct seq_file *s_file, void *v)
{

    down(&userspace_lock_download);
    spin_lock_bh(&bandwidth_lock_download);
    global_download_seq_file = s_file;
    apply_to_every_long_map_value(bw_map_download, bw_apply_download);
    global_download_seq_file = NULL;
    spin_unlock_bh(&bandwidth_lock_download);
    up(&userspace_lock_download);
    return 0;
}

static int bw_proc_open_download(struct inode *inode, struct file *file) 
{  
    return single_open(file, bw_proc_show_download, PDE_DATA(inode));
}  

static const struct file_operations bw_download_proc_fops = {
    .owner   = THIS_MODULE,
    .open    = bw_proc_open_download,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

void bw_apply_upload(unsigned long key,void *value)
{
    struct bandwidth_info *info = (struct bandwidth_info *)value;
    if(global_upload_seq_file)
    {
        seq_printf(global_upload_seq_file, "%d.%d.%d.%d,%lu\n", 
            NIPQUAD(info->ipinfo),
            info->current_traffic);
    }
}

static int bw_proc_show_upload(struct seq_file *s_file, void *v)
{

    down(&userspace_lock_upload);
    spin_lock_bh(&bandwidth_lock_upload);
    global_upload_seq_file = s_file;
    apply_to_every_long_map_value(bw_map_upload, bw_apply_upload);
    global_upload_seq_file = NULL;
    spin_unlock_bh(&bandwidth_lock_upload);
    up(&userspace_lock_upload);
    return 0;
}

static int bw_proc_open_upload(struct inode *inode, struct file *file) 
{  
    return single_open(file, bw_proc_show_upload, PDE_DATA(inode));
}  

static const struct file_operations bw_upload_proc_fops = {
    .owner   = THIS_MODULE,
    .open    = bw_proc_open_upload,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = single_release,
};

#endif

static int __init bandwidth_init(void)
{
    int result = 0;
    unsigned long num_destroyed = 0;
    get_local_info();
    bandwidth_record_max = get_bw_record_max();

    if(NULL == init_bw_map_download())
    {
        printk("init_bw_map_download failed\n");
        result = -1;
        goto out;
    }
    if(NULL == init_bw_map_upload())
    {
        printk("init_bw_map_upload failed\n");
        destroy_long_map(bw_map_download, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        result = -1;
        goto out;
    }
    result = nf_register_hook(&bandwidth_download_hook);  
    if(result)
    {
        printk("nf_register_hook bandwidth_download_hook failed\n");
        destroy_long_map(bw_map_upload, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        destroy_long_map(bw_map_download, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        goto out;
    }

    result = nf_register_hook(&bandwidth_upload_hook);   
    if(result)
    {
        printk("nf_register_hook bandwidth_upload_hook failed\n");
        nf_unregister_hook(&bandwidth_download_hook);
        destroy_long_map(bw_map_upload, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        destroy_long_map(bw_map_download, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        goto out;
    }
    
    init_local_bw_timer();
#ifdef CONFIG_PROC_FS
    //bw_procdir = proc_mkdir("bandwidth", init_net.proc_net);
    bw_procdir_upload = proc_create_data("bandwidth_upload", S_IRUSR, 
        init_net.proc_net, &bw_upload_proc_fops, NULL);
    if(!bw_procdir_upload)
    {
        printk("Unable to proc dir entry\n");
        result = -ENOMEM;
        nf_unregister_hook(&bandwidth_upload_hook);
        nf_unregister_hook(&bandwidth_download_hook);
        destroy_long_map(bw_map_upload, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        destroy_long_map(bw_map_download, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        exit_local_bw_timer();
        goto out;
    }

    bw_procdir_download = proc_create_data("bandwidth_download", S_IRUSR, 
        init_net.proc_net, &bw_download_proc_fops, NULL);
    if(!bw_procdir_download)
    {
        printk("Unable to proc dir entry\n");
        result = -ENOMEM;
        proc_remove(bw_procdir_upload);
        nf_unregister_hook(&bandwidth_upload_hook);
        nf_unregister_hook(&bandwidth_download_hook);
        destroy_long_map(bw_map_upload, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        destroy_long_map(bw_map_download, DESTROY_MODE_FREE_VALUES, &num_destroyed);
        exit_local_bw_timer();
        goto out;
    }
#endif 
    printk("bandwidth init ok\n");

out:
    return result;
}

static void __exit bandwidth_exit(void)
{
    unsigned long num_destroyed = 0;
    down(&userspace_lock_upload);
    spin_lock_bh(&bandwidth_lock_upload);
    exit_local_bw_timer();
#ifdef CONFIG_PROC_FS
    proc_remove(bw_procdir_upload);
#endif
    nf_unregister_hook(&bandwidth_upload_hook);
	destroy_long_map(bw_map_upload, DESTROY_MODE_FREE_VALUES, &num_destroyed);
    spin_unlock_bh(&bandwidth_lock_upload);
    up(&userspace_lock_upload);

    down(&userspace_lock_download);
    spin_lock_bh(&bandwidth_lock_download);
#ifdef CONFIG_PROC_FS
    proc_remove(bw_procdir_download);
#endif
    nf_unregister_hook(&bandwidth_download_hook);
    destroy_long_map(bw_map_download, DESTROY_MODE_FREE_VALUES, &num_destroyed);
    spin_unlock_bh(&bandwidth_lock_download);
    up(&userspace_lock_download);
    printk("bandwidth exit\n");
}

module_init(bandwidth_init);                             
module_exit(bandwidth_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Richard.dai");
MODULE_DESCRIPTION("bandwidth statistics lan client traffic");
