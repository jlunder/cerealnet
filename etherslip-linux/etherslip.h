#ifndef ETHERSLIP_H_INCLUDED
#define ETHERSLIP_H_INCLUDED

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#if defined(__STDC__) && defined(__STDC_VERSION__)

#if __STDC_VERSION__ < 201112L

// Adapted from https://stackoverflow.com/a/807586 (Stephen C. Steel)

// combine arguments (after expanding arguments)
#define GLUE(a, b) __GLUE(a, b)
#define __GLUE(a, b) a##b
#define static_assert(expr) \
  typedef char GLUE(compiler_verify_, __COUNTER__)[(expr) ? (+1) : (-1)]

#elif __STDC_VERSION__ < 202311L

#ifdef static_assert
#undef static_assert
#endif

#define static_assert(x) _Static_assert(x, #x)

#else
// do nothing -- static_assert should be properly defined already
#endif

#endif

#ifndef USE_IF_ETH
#define USE_IF_ETH 1
#endif

#ifndef USE_IF_PKT
#define USE_IF_PKT (!USE_IF_ETH)
#endif

#if USE_IF_PKT == USE_IF_ETH
#error "Exactly one of USE_IF_PKT or USE_IF_ETH, please"
#endif

#ifndef stdlog
#define stdlog stderr
#endif

#define logf(...) fprintf(stdlog, __VA_ARGS__)

#define IS_POW2(x) (((x - 1) | ((x - 1) >> 1)) == (x - 1))

// big enough for a 9k jumbo frame
#define MAX_PACKET_SIZE (1024 * 10 - sizeof(size_t))
#define PACKET_POOL_SIZE 8

static_assert(IS_POW2(PACKET_POOL_SIZE));

#define SER_IDX 0
#if USE_IF_ETH
#define ETH_IDX 1
#endif
#if USE_IF_PKT
#define PKT_IDX 1
#endif
#define FDS_SIZE 2

// SLIP implementation adapted from sample code in RFC 1055
// SLIP special character codes
#define SLIP_END 0300     /* indicates end of packet */
#define SLIP_ESC 0333     /* indicates byte stuffing */
#define SLIP_ESC_END 0334 /* ESC ESC_END means END data byte */
#define SLIP_ESC_ESC 0335 /* ESC ESC_ESC means ESC data byte */

// clang-format off

// NOTES ABOUT ENDIANNESS

// Seems that endianness is a bit of a mess in ye olde Unix network headers!
// Here's our policy:
// - Things in packet structs are always in network order
// - Things outside packet structs (so in local variables, or in internal
//   structs like the arp_cache_entry or dhcp_info or whatever) are always in
//   host order
// - Except for MAC addresses which are always ALWAYS in network order
// - AND except for any "struct in_addr" which is ALSO always in network order
// - BUT NOT IPv4 addresses that are locals or constants in in_addr_t or
//   uint32_t variables, which are again in host order!
// - BUT also because that's SUPER confusing, it's additionally policy that IPv4
//   addresses should ALWAYS be in "struct in_addr" when passed as parameters or
//   stored in locals

// clang-format on

struct dhcp_msg {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  struct in_addr ciaddr;
  struct in_addr yiaddr;
  struct in_addr siaddr;
  struct in_addr giaddr;
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint8_t options[312];
} __attribute__((packed));

struct ip_packet {
  union {
    struct iphdr hdr;
    uint8_t ip_raw[MAX_PACKET_SIZE - sizeof(struct ethhdr)];
  };
} __attribute__((packed));

struct eth_packet {
  union {
    struct {
      struct ethhdr hdr;
      union {
        struct ether_arp arp;
        struct ip_packet ip;
      };
    } __attribute__((packed));
    uint8_t eth_raw[MAX_PACKET_SIZE];
  };
  size_t recv_size;
} __attribute__((packed));

static_assert(sizeof(struct ethhdr) == ETH_HLEN);

struct dhcp_info {
  struct ether_addr client_mac;
  struct ether_addr server_mac;
  struct in_addr client_ip;
  struct in_addr server_ip;
  struct ether_addr chaddr;
  bool client_to_broadcast;
  bool client_to_server;
  bool server_to_client;
  bool bootp_request;
  bool is_discover;
  bool is_ack;
  bool options_in_file;
  bool options_in_sname;
};

typedef uint32_t time_ms_t;

#define ETH_IP_SIZE(frame) (frame->recv_size - sizeof(struct ethhdr))

extern bool recv_log;
extern bool send_log;
extern bool verbose_log;
extern bool very_verbose_log;

extern uint32_t ser_bps;

extern time_ms_t now_ms;

extern bool client_ready;

// the MAC address we're applying to packets bridged from the SLIP interface
extern struct ether_addr client_mac;
extern struct ether_addr host_mac;
extern struct ether_addr const broadcast_mac;
extern struct ether_addr const zero_mac;

extern struct in_addr client_ip;
extern struct in_addr client_network;
extern struct in_addr client_netmask;
extern struct in_addr client_broadcast;
extern struct in_addr client_gateway;
static struct in_addr const this_host_ip = {INADDR_ANY};

extern struct eth_packet packet_pool[PACKET_POOL_SIZE];
extern struct eth_packet *packet_pool_unallocated[PACKET_POOL_SIZE];
extern size_t packet_pool_unallocated_count;

static inline time_ms_t time_ms_from_timespec(struct timespec ts) {
  return (time_ms_t)((ts.tv_sec * 1000000000LL + ts.tv_nsec) / 1000000LL);
}
static inline time_ms_t time_since_ms(time_ms_t t_ms, time_ms_t base_ms) {
  return t_ms - base_ms;
}
static inline bool is_time_past_ms(time_ms_t t_ms, time_ms_t ref_ms) {
  return time_since_ms(t_ms, ref_ms) <= UINT32_MAX / 2;
}
static inline int32_t diff_ms(time_ms_t x_ms, time_ms_t y_ms) {
  return (int32_t)x_ms - (int32_t)y_ms;
}
static inline bool is_reasonable_time_ms(time_ms_t t_ms) {
  return t_ms <= UINT32_MAX / 4;
}
static inline bool is_reasonable_time_since_ms(time_ms_t t_ms,
                                               time_ms_t ref_ms) {
  return is_reasonable_time_ms(time_since_ms(t_ms, ref_ms));
}

void parse_args(int argc, char *argv[]);

void print_usage_and_exit(char const *argv0, char const *extra_message,
                          int result);

void poll_loop(void);

void client_process_frame(struct eth_packet *frame);
bool client_forward_net_frame(struct eth_packet *frame);

// Process a received frame (used by poll_loop)
void net_process_frame(struct eth_packet *frame);

// Send a forwarded frame to the client via ser (internal)
bool net_forward_client_frame(struct eth_packet *frame);

// Send a link-level frame via eth or pkt (used by client, arp)
bool net_send_link_frame(struct eth_packet *frame);

void net_process_queued(void);

bool net_waiting(void);

bool arp_process_frame(struct eth_packet *frame);
void arp_snoop_ip_frame(struct eth_packet const *frame);
bool arp_fetch_address(struct in_addr const requesting_ip,
                       struct in_addr const ip_addr, bool permissive,
                       struct ether_addr *out_mac_addr);

void arp_merge_entry(struct ether_addr merge_mac, struct in_addr merge_ip);

// Format and emit a frame with an announcement of our IP address
void arp_send_announce(struct ether_addr announce_mac,
                       struct in_addr announce_ip);

void arp_idle(void);

// bool dhcp_snoop_request(struct eth_packet *frame);
// bool dhcp_snoop_response(struct eth_packet *frame);

struct dhcp_msg *dhcp_parse_packet(struct eth_packet *frame,
                                   struct dhcp_info *out_info);

bool dhcp_parse_options(uint8_t const *opts, size_t len,
                        struct dhcp_info *out_info);

void ser_init(char const *ser_dev_name);
void ser_setup_pollfd(struct pollfd *pfd);
void ser_read_available(void);
void ser_accumulate_bytes(uint8_t *data, size_t size);
bool ser_send(struct eth_packet *frame);
bool ser_has_work(void);
void ser_try_write_all_queued(void);

#if USE_IF_ETH
void eth_init(char const *eth_dev_name);
void eth_setup_pollfd(struct pollfd *pfd);
void eth_read_available(void);
bool eth_send(struct eth_packet *frame);
bool eth_has_work(void);
void eth_try_write_all_queued(void);
#endif

#if USE_IF_PKT
void pkt_init(void);
void pkt_setup_pollfd(struct pollfd *pfd);
void pkt_read_available(void);
bool pkt_send(struct eth_packet *frame);
bool pkt_has_work(void);
void pkt_try_write_all_queued(void);
#endif

static inline struct in_addr ip_get_daddr(struct ip_packet const *ip_frame) {
  struct in_addr result = {ntohl(ip_frame->hdr.daddr)};
  return result;
}

static inline void ip_set_daddr(struct ip_packet *ip_frame,
                                struct in_addr daddr) {
  ip_frame->hdr.daddr = htonl(daddr.s_addr);
}

static inline struct in_addr ip_get_saddr(struct ip_packet const *ip_frame) {
  struct in_addr result = {ntohl(ip_frame->hdr.saddr)};
  return result;
}

static inline void ip_set_saddr(struct ip_packet *ip_frame,
                                struct in_addr saddr) {
  ip_frame->hdr.saddr = htonl(saddr.s_addr);
}

uint16_t ip_header_checksum(struct ip_packet const *ip_frame,
                            size_t header_size);
bool validate_eth_ip_frame(struct eth_packet const *frame);
bool validate_ip_frame(struct ip_packet const *ip_frame, size_t size);

static inline bool eth_is_proper_mac(struct ether_addr mac_addr) {
  return (memcmp(&mac_addr, &zero_mac, ETH_ALEN) != 0) &&
         (memcmp(&mac_addr, &broadcast_mac, ETH_ALEN) != 0);
}

static inline bool ip_equals(struct in_addr a, struct in_addr b) {
  return a.s_addr == b.s_addr;
}

static inline bool ip_is_broadcast(struct in_addr ip_addr) {
  return ip_addr.s_addr == htonl(INADDR_BROADCAST);
}

static inline bool ip_is_proper_or_broadcast(struct in_addr ip_addr) {
  // Reserved addresses! But especially ones that should not be picked up as if
  // they were real host addresses. Note this doesn't include the net-local
  // broadcast or "zero" address, because you need to know the network/netmask
  // to determine those.
  // clang-format off
  // 0.0.0.0/8: this host
  // 127.0.0.0/8 : loopback
  // 169.254.0.0/16: link-local
  // 255.255.255.255/32: broadcast
  // clang-format on
  uint32_t addr = ip_addr.s_addr;
  return ((addr & htonl(0xFF000000UL)) != htonl(0x00000000UL)) &&
         ((addr & htonl(0xFF000000UL)) != htonl(0x7F000000UL)) &&
         ((addr & htonl(0xFFC00000UL)) != htonl(0x64400000UL)) &&
         ((addr & htonl(0xFFFF0000UL)) != htonl(0xA9FE0000UL));
}

static inline bool ip_is_proper(struct in_addr ip_addr) {
  return !ip_is_broadcast(ip_addr) && ip_is_proper_or_broadcast(ip_addr);
}

// "this host" is for devices in the process of figuring out what their own IP
// address is (e.g. DHCP)
static inline bool ip_is_this_host(struct in_addr ip_addr) {
  return ntohl(ip_addr.s_addr) == INADDR_ANY;
}

struct eth_packet *alloc_packet_buf(void);
void free_packet_buf(struct eth_packet *packet);

void hex_dump(FILE *f, void const *buf, size_t size);

#endif  // ETHERSLIP_H_INCLUDED
