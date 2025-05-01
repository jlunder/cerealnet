#include "etherslip.h"

#define ARP_CACHE_SIZE_BITS 16
#define ARP_CACHE_SIZE (1UL << ARP_CACHE_SIZE_BITS)
#define ARP_CACHE_ASSOC 8
#define ARP_CACHE_PRIME 939193UL

struct arp_cache_entry {
  struct in_addr ip_addr;
  uint32_t last_use;
};

uint32_t arp_use_count = 0;

struct arp_cache_entry arp_cache[ARP_CACHE_SIZE];

static uint32_t arp_entry_base(struct in_addr ip_addr) {
  return (((uint32_t)ip_addr.s_addr * ARP_CACHE_PRIME) >>
          (32 - ARP_CACHE_SIZE_BITS)) &
         (ARP_CACHE_SIZE - 1);
}

static bool arp_valid_addr(struct in_addr ip_addr) {
  return ip_addr.s_addr != 0;
}

uint32_t arp_lookup(struct in_addr ip_addr) {
  assert(arp_valid_addr(ip_addr));

  uint32_t base = arp_entry_base(ip_addr);
  ++arp_use_count;
  for (uint32_t i = 0; i < ARP_CACHE_ASSOC; ++i) {
    uint32_t bin = (base + i) & (ARP_CACHE_SIZE - 1);
    if (arp_cache[bin].ip_addr.s_addr == ip_addr.s_addr) {
      arp_cache[bin].last_use = arp_use_count;
      return bin;
    }
  }

  return ARP_CACHE_SIZE;
}

bool arp_process_request(struct eth_packet *frame) {
  (void)frame;
  return false;
}

bool arp_process_announce(struct eth_packet *frame) {
  (void)frame;
  return false;
}

void arp_snoop_ip_frame(struct eth_packet const *frame) { (void)frame; }

bool arp_fetch_address(struct in_addr const *ip_addr,
                       struct ether_addr *found_eth_addr) {
  (void)ip_addr;
  (void)found_eth_addr;
  return false;
}

bool arp_announce(struct in_addr const *ip_addr,
                  struct ether_addr *found_eth_addr) {
  (void)ip_addr;
  (void)found_eth_addr;
  return false;
}
