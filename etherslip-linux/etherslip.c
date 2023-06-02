#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <errno.h>
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
#include <time.h>
#include <unistd.h>

#define logf(...) fprintf(stderr, __VA_ARGS__)

#define MAX_PACKET_BUF 16384
#define BUF_POOL_SIZE 6
#define SLIP_SEND_QUEUE_SIZE 2
#define ETH_SEND_QUEUE_SIZE 2

#define SER_IDX 0
#define ETH_IDX 1
#define FDS_SIZE 2

struct icmpechopkt {
  struct ethhdr eth;
  struct iphdr ip;
  struct icmphdr icmp;
  uint8_t payload[32];
} __attribute__((packed));

uint8_t ser_send_queue[SLIP_SEND_QUEUE_SIZE][MAX_PACKET_BUF];
uint8_t eth_send_queue[ETH_SEND_QUEUE_SIZE][MAX_PACKET_BUF];
size_t ser_send_head = 0;
size_t ser_send_tail = 0;
size_t eth_send_head = 0;
size_t eth_send_tail = 0;

size_t ser_recv_so_far = 0;

int ser_socket;
int eth_socket;

// the MAC address we're applying to packets bridged from the SLIP interface
struct ether_addr eth_mac;
struct ether_addr broadcast_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// the MAC address the SLIP device uses for itself (only in DHCP packets)
struct ether_addr ser_dhcp_mac;

void parse_args(int argc, char *argv[]);

void print_usage_and_exit(char const *argv0, char const *extra_message,
                          int result);

void poll_loop(void);

void ser_read_available(void);

void ser_accumulate_bytes(uint8_t *data, size_t size);
void ser_process(void *frame);
bool ser_process_dhcp_request(void *frame);

void eth_read_available(void);

bool eth_process_dhcp_response(void *eth_frame);
bool eth_process_arp_request(void *eth_frame);

int eth_get_ifindex(int eth_socket, char const *dev_name);
void eth_get_hwaddr(int eth_socket, char const *dev_name,
                    struct ether_addr *hwaddr);

uint16_t ip_header_checksum(void const *frame, size_t header_size);
bool validate_ip_frame(void const *eth_frame, size_t eth_size);
void *get_ip_frame(void *eth_frame);
size_t get_ip_frame_size(void *frame);
uint8_t *get_ip_payload(void *eth_frame, size_t *out_payload_size);

int main(int argc, char *argv[]) {
  parse_args(argc, argv);

  poll_loop();

  return 0;
}

void parse_args(int argc, char *argv[]) {
  char ser_dev_name[PATH_MAX] = "";
  char eth_dev_name[IFNAMSIZ] = "";
  struct ether_addr const *tmp_mac;

  bool force_eth_mac = false;

  int opt;
  int res;
  while ((opt = getopt(argc, argv, "s:e:m:Mh")) != -1) {
    switch (opt) {
      case 'm':
        force_eth_mac = true;
        if ((tmp_mac = ether_aton(optarg)) == NULL) {
          print_usage_and_exit(argv[0], "Bad arg: expected MAC address", 1);
        }
        memcpy(&eth_mac, tmp_mac, sizeof(struct ether_addr));
        break;
      case 's':
        snprintf(ser_dev_name, PATH_MAX, "%s", optarg);
        break;
      case 'e':
        snprintf(eth_dev_name, IFNAMSIZ, "%s", optarg);
        break;
      case 'h':
        print_usage_and_exit(argv[0], NULL, 0);
        break;
      default:
        print_usage_and_exit(argv[0], "Invalid option", 1);
        break;
    }
  }

  // TODO enumerate serial devices
  // if (strlen(rx_dev_name) == 0) {
  //   snprintf(rx_dev_name, sizeof rx_dev_name, "wlp3s0");
  // }

  // TODO enumerate ethernet devices
  // if (strlen(tx_dev_name) == 0) {
  //   snprintf(tx_dev_name, sizeof tx_dev_name, "enp0s25");
  // }

  ser_socket = open(ser_dev_name);
  if (ser_socket < 0) {
    perror("open() failed for serial socket");
    exit(1);
  }

  // Create a raw socket
  eth_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (eth_socket < 0) {
    perror("socket() failed for ethernet socket");
    exit(1);
  }

  if (!force_eth_mac && strlen(eth_dev_name) > 0) {
    get_device_address(eth_socket, &eth_mac, eth_dev_name);
  }
}

void print_usage_and_exit(char const *argv0, char const *extra_message,
                          int result) {
  if (extra_message != NULL) {
    logf("%s\n\n", extra_message);
  }
  logf("Usage: %s [-s SERIALDEV] [-e ETHDEV] [-m MAC | -M]\n", argv0);
  exit(result);
}

void poll_loop(void) {
  struct pollfd poll_fds[FDS_SIZE];

  struct timespec last_keepalive_time;
  clock_gettime(CLOCK_MONOTONIC, &last_keepalive_time);

  for (;;) {
    poll_fds[SER_IDX].fd = ser_socket;
    poll_fds[SER_IDX].events = POLLIN;
    poll_fds[SER_IDX].revents = 0;

    poll_fds[ETH_IDX].fd = eth_socket;
    poll_fds[ETH_IDX].events = POLLIN;
    poll_fds[ETH_IDX].revents = 0;

    int poll_res = poll(poll_fds, 1, 100);

    if (poll_res < 0) {
      perror("poll failed");
      exit(1);
    } else {
      if (poll_res == 0) {
        // Nothing ready yet, check again
        continue;
      }
    }

#if 1
    struct timespec cur_time;
    clock_gettime(CLOCK_MONOTONIC, &cur_time);
    int64_t dmsec =
        ((cur_time.tv_sec - last_keepalive_time.tv_sec) * 1000000000LL +
         (cur_time.tv_nsec - last_keepalive_time.tv_nsec)) /
        1000000LL;

    if (dmsec > 2000) {
      last_keepalive_time = cur_time;
    }
#endif

    // Data available somewhere!
    if ((poll_fds[SER_IDX].revents & ~POLLIN) != 0) {
      int re = poll_fds[SER_IDX].revents;
      logf("While polling ethernet interface: %d ( %s%s%s)", re,
           (re & POLLERR) != 0 ? "ERR " : "", (re & POLLHUP) != 0 ? "HUP " : "",
           (re & POLLNVAL) != 0 ? "INVAL " : "");
    }

    if ((poll_fds[ETH_IDX].revents & ~POLLIN) != 0) {
      int re = poll_fds[ETH_IDX].revents;
      logf("While polling serial interface: %d ( %s%s%s)", re,
           (re & POLLERR) != 0 ? "ERR " : "", (re & POLLHUP) != 0 ? "HUP " : "",
           (re & POLLNVAL) != 0 ? "INVAL " : "");
    }

    if ((poll_fds[SER_IDX].revents & POLLIN) != 0) {
      ser_read_available();
    }
    if ((poll_fds[ETH_IDX].revents & POLLIN) != 0) {
      eth_read_available();
    }
  }
}

void ser_read_available(void) {
  // TODO implement
}

void ser_accumulate_bytes(uint8_t *data, size_t size) {
  // TODO implement
}

void ser_process(void *frame) {
  // TODO implement
}

bool ser_process_dhcp_request(void *frame) {
  // TODO implement
  // first, check if an eth frame is available for the response
}

void eth_read_available(void) {
  // Try reading the ethernet interface -- despite the name it's okay to stop
  // at reading/processing a single packet
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
  } else if ((memcmp(((struct ethhdr const *)packet_buf)->h_dest, &eth_mac,
                     ETH_ALEN) != 0) &&
             (memcmp(((struct ethhdr const *)packet_buf)->h_dest,
                     &broadcast_mac, ETH_ALEN) != 0)) {
    // Ignore, wrong dest
  } else if ((recv_size > MAX_PACKET_BUF) ||
             (packet_addr_len > sizeof packet_addr)) {
    // Ignore packet,it too big
    logf("packet too big: %lu/%lu\n", (unsigned long)recv_size,
         (unsigned long)(sizeof packet_addr));  // packet_addr_len);
  } else if (validate_ip_frame(packet_buf, (size_t)recv_size)) {
    // A complete packet!
    void *ip_frame = get_ip_frame(packet_buf);
    if (ip_frame == NULL) {
      logf("  packet badly formed (%lu bytes):\n", (unsigned long)recv_size);
      hex_dump(packet_buf, recv_size > 64 ? 64 : (size_t)recv_size);
      if (recv_size > 64) {
        logf("  ...\n");
      }
    } else {
      size_t ip_frame_size = get_ip_frame_size(ip_frame);
      if (ip_frame_size > recv_size) {
        logf("  bad frame size!\n");
      } else {
        if (ip_frame_size + sizeof(struct ethhdr) < recv_size) {
          logf("  runt IP frame!\n");
        }
        hex_dump(ip_frame, ip_frame_size > 64 ? 64 : (size_t)ip_frame_size);
        if (ip_frame_size > 64) {
          logf("  ...\n");
        }
      }
    }
  }
}

bool eth_process_dhcp_response(void *eth_frame) {
  // TODO implement
  // first, check if a ser frame is available for the response
}

bool eth_process_arp_request(void *eth_frame) {
  // TODO implement
#if 0
  struct icmpechopkt ping_pkt;

  memset(&ping_pkt, 0, sizeof ping_pkt);

  memcpy(&ping_pkt.eth.h_source, &source_mac.ether_addr_octet, ETH_ALEN);
  memcpy(&ping_pkt.eth.h_dest, &dest_mac.ether_addr_octet, ETH_ALEN);
  ping_pkt.eth.h_proto = htons(ETH_P_IP);

  ping_pkt.ip.version = 4;
  ping_pkt.ip.ihl = 5;
  ping_pkt.ip.tos = 0;
  ping_pkt.ip.tot_len = htons(offsetof(struct ping_pkt_struct, payload[32]) -
                              offsetof(struct ping_pkt_struct, ip));
  ping_pkt.ip.id = htons(0x3103);
  ping_pkt.ip.frag_off = htons(0);
  ping_pkt.ip.ttl = 0x80;
  ping_pkt.ip.protocol = 0x01;
  // ping_pkt.ip.check
  // ping_pkt.ip.saddr = htonl(0xC0A80078);
  // ping_pkt.ip.daddr = htonl(0xC0A800DC);
  ping_pkt.ip.saddr = source_ip.s_addr;
  ping_pkt.ip.daddr = dest_ip.s_addr;
  ping_pkt.ip.check = ip_header_checksum(&ping_pkt.ip, sizeof(struct iphdr));

  ping_pkt.icmp.type = 0x08;
  ping_pkt.icmp.code = 0x00;
  // ping_pkt.ping.checksum
  struct timespec cur_time;
  clock_gettime(CLOCK_MONOTONIC, &cur_time);
  ping_pkt.icmp.un.echo.id =
      htons(((cur_time.tv_nsec / 1000) ^ cur_time.tv_sec) & 0xFFFF);
  ping_pkt.icmp.un.echo.sequence = htons(1);
  strncpy(ping_pkt.payload, "abcdefghijklmnopqrstuvwabcdefghi", 32);
  ping_pkt.icmp.checksum = ip_header_checksum(
      &ping_pkt.icmp, offsetof(struct ping_pkt_struct, payload[32]) -
                          offsetof(struct ping_pkt_struct, icmp));
#endif
}

int eth_get_ifindex(int eth_socket, char const *dev_name) {
  struct ifreq if_ioreq;

  memset(&if_ioreq, 0, sizeof if_ioreq);
  snprintf(if_ioreq.ifr_name, IFNAMSIZ, "%s", dev_name);
  if (ioctl(eth_socket, SIOCGIFINDEX, &if_ioreq) < 0) {
    perror("get socket index failed");
    exit(1);
  }
  return if_ioreq.ifr_ifindex;
}

void eth_get_hwaddr(int eth_socket, char const *dev_name,
                    struct ether_addr *hwaddr) {
  struct ifreq if_ioreq;

  memset(&if_ioreq, 0, sizeof if_ioreq);
  snprintf(if_ioreq.ifr_name, IFNAMSIZ, "%s", dev_name);
  if (ioctl(eth_socket, SIOCGIFHWADDR, &if_ioreq) < 0) {
    perror("get socket hardware address failed");
    exit(1);
  }
  memcpy(hwaddr, if_ioreq.ifr_hwaddr.sa_data, ETH_ALEN);
}

uint16_t ip_header_checksum(void const *frame, size_t header_size) {
  uint8_t const *const buf = (uint8_t const *)frame;
  uint32_t checksum = 0;

  for (size_t i = 0; i < header_size / 2; ++i) {
    checksum += ((uint16_t const *)buf)[i];
  }

  checksum = ((checksum >> 16) + (checksum & 0xFFFF));
  checksum = ((checksum >> 16) + (checksum & 0xFFFF));
  return ~checksum & 0xFFFF;
}

bool validate_ip_frame(void const *eth_frame, size_t eth_size) {
  uint8_t const *buf = (uint8_t const *)eth_frame;
  struct ethhdr const *eth_header = (struct ethhdr const *)eth_frame;

  logf("dest: ");
  for (size_t i = 0; i < ETH_ALEN; ++i) {
    if (i > 0) logf(":");
    logf("%02X", (int)eth_header->h_dest[i]);
  }

  logf(", src: ");
  for (size_t i = 0; i < ETH_ALEN; ++i) {
    if (i > 0) logf(":");
    logf("%02X", (int)eth_header->h_source[i]);
  }

  uint16_t proto = ntohs(eth_header->h_proto);
  size_t size = 0;
  logf(", proto: 0x%X, eth_size:%lu\n", (unsigned)proto,
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
      logf("  bad version\n");
      return false;
    }
    size_t header_size = header->ihl * 4;
    if (header_size < sizeof(struct iphdr)) {
      logf("  bad header size\n");
      return false;
    }
    if (eth_size < sizeof(struct ethhdr) + header_size) {
      logf("  truncated header\n");
      return false;
    }
    uint16_t checksum = ip_header_checksum(header, header_size);
    if (checksum != 0) {
      logf("  bad header checksum\n");
      return false;
    }
    size = ntohs(header->tot_len);
    if (eth_size < sizeof(struct ethhdr) + size) {
      logf("  truncated packet\n");
      return false;
    }
    logf("  ip_size: %lu\n", (unsigned long)size);
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
