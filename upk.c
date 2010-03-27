// Copyright 2010 Garret Kelly. All Rights Reserved.
// Author: gkelly@gkelly.org (Garret Kelly)

#include <linux/module.h>

#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

MODULE_AUTHOR("Garret Kelly");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("A tiny port-knocking implementation that guards a single "
    "port from access with a user-specified knocking sequence");
MODULE_PARM_DESC(upk_protected_port, "The port to which access will be denied "
    "until the correct knocking sequence is recieved");
MODULE_PARM_DESC(upk_timeout, "The timeout, in jiffies, before the entered "
    "sequence resets itself if it has not been completed");
MODULE_PARM_DESC(upk_sequence, "The sequence of ports that must be 'knocked' "
    "upon for the protected port to be made accessbile");

#define UPK_MAX_SEQUENCE_LENGTH 10
#define UPK_INFO KERN_INFO "upk: "

static int upk_protected_port = 22;
static int upk_timeout = 5 * HZ;
static int upk_sequence[UPK_MAX_SEQUENCE_LENGTH] = {1234, 4321, 4444, 0};
static int upk_sequence_length = UPK_MAX_SEQUENCE_LENGTH;

module_param(upk_protected_port, int, 0);
module_param(upk_timeout, int, 0);
module_param_array(upk_sequence, int, &upk_sequence_length, 0);

static int upk_open = false;
static int upk_sequence_index = 0;
static unsigned long upk_sequence_timestamp = 0;
static struct nf_hook_ops upk_netfilter_hook;

static void upk_reset(void)
{
  upk_open = false;
  upk_sequence_index = 0;
  upk_sequence_timestamp = 0;
}

static unsigned int upk_filter_function(unsigned int hooknum,
    struct sk_buff *skb, const struct net_device *in,
    const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  struct iphdr *ip_header;
  struct tcphdr *tcp_header;

  ip_header = ip_hdr(skb);
  if (!ip_header || ip_header->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
  }

  tcp_header = (struct tcphdr *)(skb->data + (ip_header->ihl * 4));
  if (tcp_header->dest == htons(upk_protected_port)) {
    if (upk_open) {
      return NF_ACCEPT;
    }
    return NF_DROP;
  } else {
    if ((jiffies - upk_sequence_timestamp) > upk_timeout) {
      upk_reset();
    }
    if (tcp_header->dest == htons(upk_sequence[upk_sequence_index])) {
      upk_sequence_timestamp = jiffies;
      upk_sequence_index++;
      if (upk_sequence[upk_sequence_index] == 0) {
        upk_open = true;
      }
    }
  }

  return NF_ACCEPT;
}

static int __init upk_init(void)
{
  upk_reset();
  upk_sequence[upk_sequence_length] = 0;

  upk_netfilter_hook.hook = upk_filter_function;
  upk_netfilter_hook.hooknum = NF_INET_PRE_ROUTING;
  upk_netfilter_hook.pf = PF_INET;
  upk_netfilter_hook.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&upk_netfilter_hook);

  printk(UPK_INFO "loaded\n");

  return 0;
}

static void __exit upk_exit(void)
{
  nf_unregister_hook(&upk_netfilter_hook);

  printk(UPK_INFO "unloaded\n");
}

module_init(upk_init);
module_exit(upk_exit);
