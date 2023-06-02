#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
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
#include <time.h>
#include <unistd.h>

// /sys/class/net/?/address
// /sys/class/net/?/carrier

void hex_dump(void const *buf, size_t size) {
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
    fputs(line, stdout);
  }
}

#define MAX_PACKET_BUF 8192
#define BUF_POOL_SIZE 6
#define SLIP_SEND_QUEUE_SIZE 2
#define ETH_SEND_QUEUE_SIZE 2

// #define SER_IDX 0
#define ETH_IDX 0
#define FDS_SIZE 1

uint8_t ser_send_queue[SLIP_SEND_QUEUE_SIZE][MAX_PACKET_BUF];
uint8_t eth_send_queue[ETH_SEND_QUEUE_SIZE][MAX_PACKET_BUF];
size_t ser_send_head = 0;
size_t ser_send_tail = 0;
size_t eth_send_head = 0;
size_t eth_send_tail = 0;

size_t ser_recv_so_far = 0;

struct pollfd poll_fds[FDS_SIZE];
struct timespec timeout = {1, 0};

int ser_socket;
int eth_socket;

uint16_t ip_header_checksum(void const *frame, size_t header_size) {
  uint8_t const *const buf = (uint8_t const *)frame;
  uint32_t checksum = 0;

  for (size_t i = 0; i < header_size / 2; ++i) {
    checksum += ntohs(((uint16_t const *)buf)[i]);
  }

  checksum = ((checksum >> 16) + (checksum & 0xFFFF));
  checksum = ((checksum >> 16) + (checksum & 0xFFFF));
  return ~checksum & 0xFFFF;
}

bool validate_ip_frame(void const *eth_frame, size_t eth_size) {
  uint8_t const *buf = (uint8_t const *)eth_frame;
  struct ethhdr const *eth_header = (struct ethhdr const *)eth_frame;

  printf("dest: ");
  for (size_t i = 0; i < ETH_ALEN; ++i) {
    if (i > 0) printf(":");
    printf("%02X", (int)eth_header->h_dest[i]);
  }

  printf(", src: ");
  for (size_t i = 0; i < ETH_ALEN; ++i) {
    if (i > 0) printf(":");
    printf("%02X", (int)eth_header->h_source[i]);
  }

  uint16_t proto = ntohs(eth_header->h_proto);
  size_t size = 0;
  printf(", proto: 0x%X, eth_size:%lu\n", (unsigned)proto,
         (unsigned long)eth_size);

  if (proto < ETH_P_802_3_MIN) {
    size = 0;
    proto = ETH_P_802_3;
  } else if ((proto == ETH_P_IP) &&
             (eth_size >= sizeof(struct ethhdr) + sizeof(struct iphdr))) {
    // The order of these tests is important -- some of them depend on prior
    // tests passing to be safe, e.g. checking the header checksum after
    // verifying that the received packet isn't truncated
    struct iphdr const *header =
        (struct iphdr const *)(buf + sizeof(struct ethhdr));
    if (header->version != 4) {
      printf("  bad version\n");
      return false;
    }
    size_t header_size = header->ihl * 4;
    if (header_size < sizeof(struct iphdr)) {
      printf("  bad header size\n");
      return false;
    }
    if (eth_size < sizeof(struct ethhdr) + header_size) {
      printf("  truncated header\n");
      return false;
    }
    uint16_t checksum = ip_header_checksum(header, header_size);
    if (checksum != 0) {
      printf("  bad header checksum\n");
      return false;
    }
    size = ntohs(header->tot_len);
    if (eth_size < sizeof(struct ethhdr) + size) {
      printf("  truncated packet\n");
      return false;
    }
    printf("  ip_size: %lu\n", (unsigned long)size);
  } else {
    // nothing
  }

  return size > 0;
}

void *get_ip_frame(void *eth_frame) {
  uint8_t *buf = (uint8_t *)eth_frame;
  return buf + sizeof(struct ethhdr);
}

size_t get_ip_frame_size(void *frame) {
  uint8_t *buf = (uint8_t *)frame;
  struct iphdr const *header = (struct iphdr const *)buf;
  return ntohs(header->tot_len);
}

uint8_t *get_ip_payload(void *eth_frame, size_t *out_payload_size) {
  struct iphdr *header = (struct iphdr *)get_ip_frame(eth_frame);
  size_t header_size = header->ihl * 4;
  if (out_payload_size != NULL) {
    *out_payload_size = ntohs(header->tot_len) - header_size;
  }
  return (uint8_t *)header + header_size;
}

void read_ser(void) {}

void read_eth(void) {
  // Try reading the ethernet interface
  uint8_t *packet_buf = ser_send_queue[ser_send_tail];
  struct sockaddr_storage packet_addr;
  socklen_t packet_addr_len = sizeof packet_addr;
  ssize_t recv_size;

  recv_size = recvfrom(eth_socket, packet_buf, MAX_PACKET_BUF, MSG_DONTWAIT,
                       (struct sockaddr *)&packet_addr, &packet_addr_len);
  if (recv_size < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      // No message waiting after all
    } else {
      perror("recvfrom failed");
      exit(1);
    }
  } else if ((recv_size > MAX_PACKET_BUF) ||
             (packet_addr_len > sizeof packet_addr)) {
    // Ignore packet,it too big
    fprintf(stderr, "packet too big: %lu/%lu\n", (unsigned long)recv_size,
            (unsigned long)(sizeof packet_addr));  // packet_addr_len);
  } else if (validate_ip_frame(packet_buf, (size_t)recv_size)) {
    // A complete packet!
    void *ip_frame = get_ip_frame(packet_buf);
    if (ip_frame == NULL) {
      printf("packet badly formed (%lu bytes):\n", (unsigned long)recv_size);
      hex_dump(packet_buf, recv_size > 64 ? 64 : (size_t)recv_size);
      if (recv_size > 64) {
        printf("  ...\n");
      }
    } else {
      size_t ip_frame_size = get_ip_frame_size(ip_frame);
      if (ip_frame_size > recv_size) {
        printf("  bad frame size!\n");
      } else {
        hex_dump(ip_frame, ip_frame_size);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  // Create a raw socket
  eth_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

  if (eth_socket < 0) {
    perror("socket failed for ethernet socket");
    exit(1);
  }

  struct ifreq if_ioreq;
  // char if_name[IFNAMSIZ];
  struct sockaddr_ll if_mac;

  memset(&if_mac, 0, sizeof if_mac);

  memset(&if_ioreq, 0, sizeof if_ioreq);
  strncpy(if_ioreq.ifr_name, "enp0s25", IFNAMSIZ - 1);
  if (ioctl(eth_socket, SIOCGIFINDEX, &if_ioreq) < 0) {
    perror("get socket index failed");
    exit(1);
  }
  if_mac.sll_ifindex = if_ioreq.ifr_ifindex;

  memset(&if_ioreq, 0, sizeof if_ioreq);
  strncpy(if_ioreq.ifr_name, "enp0s25", IFNAMSIZ - 1);
  if (ioctl(eth_socket, SIOCGIFHWADDR, &if_ioreq) < 0) {
    perror("get socket hardware address failed");
    exit(1);
  }
  if_mac.sll_halen = ETH_ALEN;
  memcpy(if_mac.sll_addr, if_ioreq.ifr_hwaddr.sa_data, ETH_ALEN);
  printf("%s mac address %02X:%02X:%02X:%02X:%02X:%02X\n", if_ioreq.ifr_name,
         if_ioreq.ifr_hwaddr.sa_data[0] & 0xFF,
         if_ioreq.ifr_hwaddr.sa_data[1] & 0xFF,
         if_ioreq.ifr_hwaddr.sa_data[2] & 0xFF,
         if_ioreq.ifr_hwaddr.sa_data[3] & 0xFF,
         if_ioreq.ifr_hwaddr.sa_data[4] & 0xFF,
         if_ioreq.ifr_hwaddr.sa_data[5] & 0xFF);

  for (;;) {
    /*
    poll_fds[SER_IDX].fd = eth_socket;
    poll_fds[SER_IDX].events = POLLIN;
    poll_fds[SER_IDX].revents = 0;
    */

    poll_fds[ETH_IDX].fd = eth_socket;
    poll_fds[ETH_IDX].events = POLLIN;
    poll_fds[ETH_IDX].revents = 0;

    printf("Waiting for packet\n");

    int poll_res = poll(poll_fds, 1, 500);

    if (poll_res < 0) {
      perror("poll failed");
      exit(1);
    } else if (poll_res == 0) {
      // Nothing ready yet, check again
      struct ping_pkt_struct {
        struct ethhdr eth;
        struct iphdr ip;
        struct icmphdr ping;
        uint8_t payload[32];
      } __attribute__((packed)) ping_pkt;

      memcpy(&ping_pkt.eth.h_source, if_mac.sll_addr, ETH_ALEN);
      memcpy(&ping_pkt.eth.h_dest, if_mac.sll_addr, ETH_ALEN);
      memset(&ping_pkt, 0, sizeof ping_pkt);
      ping_pkt.eth.h_proto = ETH_P_IP;
      ping_pkt.ip.version = 4;
      ping_pkt.ip.ihl = 5;
      ping_pkt.ip.tos = 0;
      ping_pkt.ip.tot_len =
          htons(offsetof(struct ping_pkt_struct, payload[32]) -
                offsetof(struct ping_pkt_struct, ip));
      ping_pkt.ip.id = htons(0x3103);
      ping_pkt.ip.frag_off = htons(0);
      ping_pkt.ip.ttl = 0x80;
      ping_pkt.ip.protocol = 0x01;
      // ping_pkt.ip.check
      ping_pkt.ip.saddr = htonl(0xC0A80078);
      ping_pkt.ip.daddr = htonl(0xC0A800DC);
      ping_pkt.ping.type = 0x08;
      ping_pkt.ping.code = 0x00;
      // ping_pkt.ping.checksum
      ping_pkt.ping.un.echo.id = htons(0x0001);
      ping_pkt.ping.un.echo.sequence = htons(0x001A);
      strncpy(ping_pkt.payload, "abcdefghijklmnopqrstuvwabcdefghi", 32);
      // memcpy(((struct ethhdr *)ping_pkt)->h_dest, if_mac.sll_addr, ETH_ALEN);
      ping_pkt.ip.check =
          htons(ip_header_checksum(&ping_pkt.ip, sizeof(struct iphdr)));
      ping_pkt.ping.checksum = htons(ip_header_checksum(
          &ping_pkt.ping, offsetof(struct ping_pkt_struct, payload[32]) -
                              offsetof(struct ping_pkt_struct, ping)));

      /*
      printf("  ping_pkt checksum: %04X\n",
        ip_header_checksum(
          ping_pkt + sizeof (struct ethhdr) + sizeof (struct iphdr),
          sizeof ping_pkt - sizeof (struct ethhdr) - sizeof (struct iphdr)));
      */
      printf("sending ping packet\n");
      hex_dump(&ping_pkt.ip, offsetof(struct ping_pkt_struct, payload[32]) -
                                 offsetof(struct ping_pkt_struct, ip));
      int send_res =
          sendto(eth_socket, &ping_pkt, sizeof ping_pkt, MSG_DONTWAIT,
                 (struct sockaddr const *)&if_mac, sizeof if_mac);
      //        send(eth_socket, ping_pkt, sizeof ping_pkt, MSG_DONTWAIT);
      if (send_res < 0) {
        perror("send ping packet failed");
        exit(1);
      }
      if (send_res != sizeof ping_pkt) {
        printf("send sent the wrong size?\n");
        exit(1);
      }
      continue;
    }

    // Data available somewhere!
    /*
    if ((poll_fds[SER_IDX].revents & ~POLLIN) != 0) {
      int re = poll_fds[SER_IDX].revents;
      fprintf(stderr, "While polling ethernet interface: %d ( %s%s%s)", re,
        (re & POLLERR) != 0 ? "ERR " : "",(re & POLLHUP) != 0 ? "HUP " : "",
        (re & POLLNVAL) != 0 ? "INVAL " : "");
    }
    */

    if ((poll_fds[ETH_IDX].revents & ~POLLIN) != 0) {
      int re = poll_fds[ETH_IDX].revents;
      fprintf(stderr, "While polling serial interface: %d ( %s%s%s)", re,
              (re & POLLERR) != 0 ? "ERR " : "",
              (re & POLLHUP) != 0 ? "HUP " : "",
              (re & POLLNVAL) != 0 ? "INVAL " : "");
    }

    /*
    if ((poll_fds[SER_IDX].revents & POLLIN) != 0) {
      read_ser();
    }
    */
    if ((poll_fds[ETH_IDX].revents & POLLIN) != 0) {
      read_eth();
    }
  }

  return 0;
}
