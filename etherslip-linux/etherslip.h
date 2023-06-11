#ifndef ETHERSLIP_H_INCLUDED
#define ETHERSLIP_H_INCLUDED

#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
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
#include <time.h>
#include <unistd.h>

#if !defined(USE_IF_PKT) && !defined(USE_IF_ETH)
#define USE_IF_PKT
#endif

#define stdlog stderr
#define logf(...) fprintf(stdlog, __VA_ARGS__)

// big enough for a 9k jumbo frame
#define MAX_PACKET_SIZE (1024 * 10 - sizeof(size_t))
#define PACKET_POOL_SIZE 6

#define SER_IDX 0
#ifdef USE_IF_ETH
#define ETH_IDX 1
#endif
#ifdef USE_IF_PKT
#define PKT_IDX 1
#endif
#define FDS_SIZE 2

// SLIP implementation adapted from sample code in RFC 1055
// SLIP special character codes
#define SLIP_END 0300     /* indicates end of packet */
#define SLIP_ESC 0333     /* indicates byte stuffing */
#define SLIP_ESC_END 0334 /* ESC ESC_END means END data byte */
#define SLIP_ESC_ESC 0335 /* ESC ESC_ESC means ESC data byte */

struct dhcp_msg {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr;
  uint32_t giaddr;
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint8_t options[312];
} __attribute__((packed));

struct arp_msg {
  uint16_t hrd;  // 1 or 6?
  uint16_t pro;  // ETH_P_IP
  uint8_t hln;   // 6 -- MAC len
  uint8_t pln;   // 4 -- IPv4 address len
  uint16_t op;   // 1=ARP req, rep, 3=RARP req, rep, 5=DRARP req, rep, err,
                 // 8=InARP req, rep
  uint8_t addrs[255 * 4];
  // sha, spa, tha, tpa
} __attribute__((packed));

struct ip_packet {
  union {
    struct {
      struct iphdr hdr;
      union {
        uint8_t ip_payload[MAX_PACKET_SIZE - sizeof(struct iphdr) -
                           sizeof(struct ethhdr)];
        struct dhcp_msg dhcp;
        struct arp_msg arp;
      };
    } __attribute__((packed));
    uint8_t ip_raw[MAX_PACKET_SIZE - sizeof(struct ethhdr)];
  };
} __attribute__((packed));

struct eth_packet {
  union {
    struct {
      struct ethhdr hdr;
      struct ip_packet ip;
    } __attribute__((packed));
    uint8_t eth_raw[MAX_PACKET_SIZE];
    size_t recv_size;
  };
} __attribute__((packed));

#define ETH_IP_SIZE(eth_frame) (eth_frame->recv_size - sizeof(struct ethhdr))

extern bool verbose_log;
extern bool very_verbose_log;

// Round up to align to 16 bytes
#define MAX_SLIP_EXPANSION(size) ((size * 2 + 2 + 0xF) & ~0xFLU)
#define SER_WRITE_QUEUE_SIZE MAX_SLIP_EXPANSION(MAX_PACKET_SIZE)

extern struct eth_packet packet_pool[PACKET_POOL_SIZE];
extern struct eth_packet *packet_pool_unallocated[PACKET_POOL_SIZE];
extern size_t packet_pool_unallocated_count;

extern struct eth_packet *ser_read_accum;
extern size_t ser_read_accum_used;
extern bool ser_read_accum_esc;

extern uint8_t ser_write_queue[SER_WRITE_QUEUE_SIZE];
extern size_t ser_write_queue_head;
extern size_t ser_write_queue_tail;

extern int ser_fd;

#ifdef USE_IF_ETH
extern int eth_socket;
extern struct eth_packet *eth_write_queue;
#endif

#ifdef USE_IF_PKT
extern int pkt_send_socket;
extern int pkt_recv_socket;
extern struct eth_packet *pkt_write_queue;
#endif

// the MAC address we're applying to packets bridged from the SLIP interface
extern struct ether_addr client_mac;
extern struct ether_addr broadcast_mac;

void parse_args(int argc, char *argv[]);

void print_usage_and_exit(char const *argv0, char const *extra_message,
                          int result);

void poll_loop(void);

void client_process_frame(struct eth_packet *eth_frame);
bool client_process_dhcp_request(struct eth_packet *eth_frame);
void net_process_frame(struct eth_packet *eth_frame);
bool net_process_dhcp_response(struct eth_packet *eth_frame);
bool net_process_arp_request(struct eth_packet *eth_frame);

void ser_init(char const *ser_dev_name);
void ser_read_available(void);
void ser_accumulate_bytes(uint8_t *data, size_t size);
void ser_send(struct eth_packet *eth_frame);
void ser_try_write_all_queued(void);

#ifdef USE_IF_ETH
void eth_init(char const *eth_dev_name, bool force_eth_mac);
void eth_read_available(void);
void eth_send(struct eth_packet *eth_frame);
void eth_try_write_all_queued(void);

void eth_get_hwaddr(int eth_socket, char const *dev_name,
                    struct ether_addr *hwaddr);
#endif

#ifdef USE_IF_PKT
void pkt_init(void);
void pkt_read_available(void);
void pkt_send(struct eth_packet *eth_frame);
void pkt_try_write_all_queued(void);
#endif

uint16_t ip_header_checksum(struct ip_packet const *ip_frame,
                            size_t header_size);
bool validate_eth_ip_frame(struct eth_packet const *eth_frame);
bool validate_ip_frame(struct ip_packet const *ip_frame, size_t size);

struct eth_packet *alloc_packet_buf(void);
void free_packet_buf(struct eth_packet *packet);

int sock_get_ifindex(int eth_socket, char const *dev_name);

void hex_dump(FILE *f, void const *buf, size_t size);

#endif  // ETHERSLIP_H_INCLUDED
