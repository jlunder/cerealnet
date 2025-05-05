#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/ether.h>
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

#ifndef stdlog
#define stdlog stderr
#endif

#define logf(...) fprintf(stdlog, __VA_ARGS__)

#define RAW_FRAME_STRUCT_SIZE (1024 * 10)
#define MAX_PACKET_SIZE (RAW_FRAME_STRUCT_SIZE - sizeof(size_t))
#define IP_MAX_PAYLOAD \
  (MAX_PACKET_SIZE - sizeof(struct iphdr) - sizeof(struct ethhdr))
#define ARP_MAX_PAYLOAD 500

// Should be big enough for a 9k jumbo frame (9038 bytes, plus a little grace)
static_assert(MAX_PACKET_SIZE > 9100);

struct ip_packet {
  struct iphdr hdr;
  // dhcp
  uint8_t payload[IP_MAX_PAYLOAD];
} __attribute__((packed));

struct arp_eth_ip {
  struct ether_addr sha;
  struct in_addr spa;
  struct ether_addr tha;
  struct in_addr tpa;
} __attribute__((packed));

struct arp_packet {
  struct arphdr hdr;
  union {
    struct arp_eth_ip eth_ip;
    uint8_t payload[ARP_MAX_PAYLOAD];
  };
} __attribute__((packed));

struct eth_packet {
  union {
    struct {
      struct ethhdr hdr;
      union {
        struct ip_packet ip;
        struct arp_packet arp;
        uint8_t packet[MAX_PACKET_SIZE - sizeof(struct iphdr) -
                       sizeof(struct ethhdr)];
      };
    } __attribute__((packed));
    uint8_t eth_raw[MAX_PACKET_SIZE];
  };
  size_t recv_size;
} __attribute__((packed));

static_assert(sizeof(struct eth_packet) == RAW_FRAME_STRUCT_SIZE);

bool validate_ip_frame(struct ip_packet const *ip_frame, size_t size);

int main(int argc, char *argv[]) {
  // Create a raw socket
  int eth_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (eth_socket < 0) {
    perror("socket() failed for ethernet socket");
    exit(1);
  }

  struct ether_addr client_mac = {{0x00, 0x00, 0x00, 0x22, 0x34, 0x66}};
  struct in_addr client_ip = {inet_addr("169.254.12.13")};
  struct ether_addr host_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
  struct ether_addr const broadcast_mac = {
      {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
  char const *host_eth_dev = "wlp3s0";

  struct ifreq if_ioreq;
  int if_index;

  for (int i = 1; i < 20; ++i) {
    memset(&if_ioreq, 0, sizeof if_ioreq);
    if_ioreq.ifr_ifindex = i;
    if (ioctl(eth_socket, SIOCGIFNAME, &if_ioreq) < 0) {
      perror("get socket interface name failed");
      break;
    }
    logf("interface %d: %s\n", i, if_ioreq.ifr_name);
  }

  memset(&if_ioreq, 0, sizeof if_ioreq);
  snprintf(if_ioreq.ifr_name, IFNAMSIZ, "%s", host_eth_dev);
  if (ioctl(eth_socket, SIOCGIFINDEX, &if_ioreq) < 0) {
    perror("get socket interface index failed");
    exit(1);
  }
  if_index = if_ioreq.ifr_ifindex;
  logf("interface %s: index %i\n", host_eth_dev, if_index);

  memset(&if_ioreq, 0, sizeof if_ioreq);
  snprintf(if_ioreq.ifr_name, IFNAMSIZ, "%s", host_eth_dev);
  if (ioctl(eth_socket, SIOCGIFHWADDR, &if_ioreq) < 0) {
    perror("get socket hardware address failed");
    exit(1);
  }
  memcpy(&host_mac, if_ioreq.ifr_hwaddr.sa_data, ETH_ALEN);

  logf("Host MAC (%s): %s\n", host_eth_dev, ether_ntoa(&host_mac));

  struct eth_packet frame;

  memcpy(&frame.hdr.h_dest, &broadcast_mac, ETH_ALEN);
  memcpy(&frame.hdr.h_source, &client_mac, ETH_ALEN);
  frame.hdr.h_proto = htons(ETH_P_ARP);
  frame.arp.hdr.ar_hrd = htons(ARPHRD_ETHER);
  frame.arp.hdr.ar_pro = htons(ETH_P_IP);
  frame.arp.hdr.ar_hln = ETH_ALEN;
  frame.arp.hdr.ar_pln = sizeof(struct in_addr);
  frame.arp.hdr.ar_op = htons(ARPOP_REQUEST);
  memcpy(&frame.arp.eth_ip.sha, &client_mac, ETH_ALEN);
  frame.arp.eth_ip.spa = client_ip;
  memcpy(&frame.arp.eth_ip.tha, &host_mac, ETH_ALEN);
  frame.arp.eth_ip.tpa.s_addr = 0;
  frame.recv_size =
      sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct arp_eth_ip);

  ssize_t res;
  struct sockaddr_ll dest_sa;
  memset(&dest_sa, 0, sizeof dest_sa);
  // dest_sa.sll_family = AF_PACKET;
  // dest_sa.sll_protocol = frame.hdr.h_proto;
  dest_sa.sll_ifindex = if_index;
  // dest_sa.sll_halen = ETH_ALEN;
  // memcpy(&dest_sa.sll_addr, frame.hdr.h_dest, ETH_ALEN);
#if 0
  {
    char srcaddr[20], destaddr[20];
    inet_ntop(AF_INET, &eth_write_queue->ip.hdr.saddr, srcaddr, sizeof srcaddr);
    inet_ntop(AF_INET, &eth_write_queue->ip.hdr.daddr, destaddr,
              sizeof destaddr);
    logf(
        "eth write queued frame, %lu bytes, dest mac=%s; "
        "hdr tot_len=%lu, proto=%02X, sa=%s, da=%s\n",
        (unsigned long)eth_write_queue->recv_size,
        ether_ntoa((struct ether_addr const *)&eth_write_queue->hdr.h_dest),
        (unsigned long)ntohs(eth_write_queue->ip.hdr.tot_len),
        (int)eth_write_queue->ip.hdr.protocol, srcaddr, destaddr);
  }
#endif
  res = sendto(eth_socket, &frame, frame.recv_size, MSG_DONTWAIT,
               (struct sockaddr *)&dest_sa, sizeof dest_sa);
  if (res < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      perror("eth sendto() blocking");
    }
    perror("eth sendto() failed");
  }

  close(eth_socket);

  return 0;
}

uint16_t ip_header_checksum(struct ip_packet const *ip_frame,
                            size_t header_size) {
  uint8_t const *const buf = (uint8_t const *)ip_frame;
  uint32_t checksum = 0;

  for (size_t i = 0; i < header_size / 2; ++i) {
    checksum += ((uint16_t const *)buf)[i];
  }

  checksum = ((checksum >> 16) + (checksum & 0xFFFF));
  checksum = ((checksum >> 16) + (checksum & 0xFFFF));
  return ~checksum & 0xFFFF;
}

bool validate_eth_ip_frame(struct eth_packet const *frame) {
  uint16_t proto = ntohs(frame->hdr.h_proto);

  if (frame->recv_size < sizeof(struct ethhdr)) {
    return false;
  }
  if (proto < ETH_P_802_3_MIN) {
    // size = proto;
    // proto = ETH_P_802_3;
    return false;
  }
  if (proto != ETH_P_IP) {
    return false;
  }
  return validate_ip_frame(&frame->ip,
                           frame->recv_size - sizeof(struct ethhdr));
}

bool validate_ip_frame(struct ip_packet const *ip_frame, size_t size) {
  if (size < sizeof(struct iphdr)) {
    logf("invalid IP packet: truncated header (runt)\n");
    return false;
  }
  // The order of these tests is important -- some of them depend on prior
  // tests passing to be safe, e.g. checking the header checksum after
  // verifying that the received packet isn't truncated
  if (ip_frame->hdr.version != 4) {
    logf("invalid IP packet: bad version (%d)\n", (int)ip_frame->hdr.version);
    return false;
  }
  size_t header_size = ip_frame->hdr.ihl * 4;
  if (header_size < sizeof(struct iphdr)) {
    logf("invalid IP packet: bad header size (%d)\n", (int)header_size);
    return false;
  }
  if (size < header_size) {
    logf("invalid IP packet: truncated header\n");
    return false;
  }
  uint16_t checksum = ip_header_checksum(ip_frame, header_size);
  if (checksum != 0) {
    logf("invalid IP packet: bad header checksum\n");
    return false;
  }
  if (size < ntohs(ip_frame->hdr.tot_len)) {
    logf("invalid IP packet: truncated packet (%d of %d)\n", (int)size,
         (int)ntohs(ip_frame->hdr.tot_len));
    return false;
  }

  return true;
}

void hex_dump(FILE *f, void const *buf, size_t size) {
  static char const hex_chars[] = "0123456789ABCDEF";
  char line[128];
  size_t k;
  for (size_t i = 0; i < size; i += 16) {
    k = 0;
    line[k++] = hex_chars[(i >> 12) & 0xF];
    line[k++] = hex_chars[(i >> 8) & 0xF];
    line[k++] = hex_chars[(i >> 4) & 0xF];
    line[k++] = hex_chars[(i >> 0) & 0xF];
    line[k++] = ':';
    line[k++] = ' ';
    size_t n = (size - i) < 16 ? (size - i) : 16;
    for (size_t j = 0; j < n; ++j) {
      line[k++] = ' ';
      uint8_t v = ((uint8_t const *)buf)[i + j];
      line[k++] = hex_chars[(v >> 4) & 0xF];
      line[k++] = hex_chars[(v >> 0) & 0xF];
    }
    memset(line + k, ' ', (16 - n) * 3);
    k += (16 - n) * 3;
    line[k++] = ' ';
    line[k++] = '|';
    for (size_t j = 0; j < n; ++j) {
      uint8_t v = ((uint8_t const *)buf)[i + j];
      line[k++] = ((v >= 32) && (v < 127)) ? v : '.';
    }
    memset(line + k, '-', 16 - n);
    k += 16 - n;
    line[k++] = '|';
    line[k++] = '\n';
    line[k++] = '\0';
    fputs(line, f);
  }
}
