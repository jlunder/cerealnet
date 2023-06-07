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

#define stdlog stderr
#define logf(...) fprintf(stdlog, __VA_ARGS__)

#define MAX_PACKET_SIZE (1024 * 10) /* big enough for a 9k jumbo frame */
#define PACKET_POOL_SIZE 6

#define SER_IDX 0
#define ETH_IDX 1
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
  };
} __attribute__((packed));

// Round up to align to 16 bytes
#define MAX_SLIP_EXPANSION(size) ((size * 2 + 2 + 0xF) & ~0xFLU)
#define SER_BUF_SIZE MAX_SLIP_EXPANSION(MAX_PACKET_SIZE)

struct eth_packet packet_pool[PACKET_POOL_SIZE];
struct eth_packet *packet_pool_unallocated[PACKET_POOL_SIZE];
size_t packet_pool_unallocated_count = 0;

struct eth_packet ser_read_accum;
size_t ser_read_accum_used = 0;
bool ser_read_accum_esc = false;

uint8_t ser_write_buf[SER_BUF_SIZE];
size_t ser_write_buf_head = 0;
size_t ser_write_buf_tail = 0;

size_t ser_send_head = 0;
size_t ser_send_tail = 0;

size_t eth_send_head = 0;
size_t eth_send_tail = 0;

int ser_fd;
int eth_socket;

// the MAC address we're applying to packets bridged from the SLIP interface
struct ether_addr eth_mac;
struct ether_addr broadcast_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// the MAC address the SLIP device uses for itself (only in DHCP packets)
#define ser_dhcp_mac (ser_read_accum.eth.h_source)

void parse_args(int argc, char *argv[]);

void print_usage_and_exit(char const *argv0, char const *extra_message,
                          int result);

void poll_loop(void);

void ser_read_available(void);

void ser_accumulate_bytes(uint8_t *data, size_t size);
void ser_process(struct ip_packet *ip_frame);
bool ser_process_dhcp_request(struct ip_packet *ip_frame);

void ser_send(struct ip_packet const *ip_frame);

bool ser_try_write_pending(void);

void eth_read_available(void);

void eth_process_frame(struct eth_packet *eth_frame);
bool eth_process_dhcp_response(struct eth_packet *eth_frame);
bool eth_process_arp_request(struct eth_packet *eth_frame);

void eth_send(struct ip_packet *ip_frame);

int eth_get_ifindex(int eth_socket, char const *dev_name);
void eth_get_hwaddr(int eth_socket, char const *dev_name,
                    struct ether_addr *hwaddr);

uint16_t ip_header_checksum(struct ip_packet const *ip_frame,
                            size_t header_size);
bool validate_eth_ip_frame(struct eth_packet const *eth_frame, size_t eth_size);
bool validate_ip_frame(struct ip_packet const *ip_frame, size_t size);

struct eth_packet *alloc_packet_buf(void);
void free_packet_buf(struct eth_packet *packet);

void hex_dump(FILE *f, void const *buf, size_t size);

int main(int argc, char *argv[]) {
  for (size_t i = 0; i < PACKET_POOL_SIZE; ++i) {
    free_packet_buf(&packet_pool[i]);
  }

  parse_args(argc, argv);

  logf("etherslip starting.\n");

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

  if (strlen(ser_dev_name) > 0) {
    ser_fd = open(ser_dev_name, O_RDWR | O_NOCTTY);
    if (ser_fd < 0) {
      perror("open() failed for serial socket");
      exit(1);
    }
  } else {
    ser_fd = -1;
  }

  // Create a raw socket
  eth_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (eth_socket < 0) {
    perror("socket() failed for ethernet socket");
    exit(1);
  }

  if (!force_eth_mac && strlen(eth_dev_name) > 0) {
    eth_get_hwaddr(eth_socket, eth_dev_name, &eth_mac);
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
    poll_fds[SER_IDX].fd = ser_fd;
    poll_fds[SER_IDX].events = POLLIN;
    poll_fds[SER_IDX].revents = 0;

    poll_fds[ETH_IDX].fd = eth_socket;
    poll_fds[ETH_IDX].events = POLLIN;
    poll_fds[ETH_IDX].revents = 0;

    int poll_res = poll(poll_fds, FDS_SIZE, 100);

    if (poll_res < 0) {
      perror("poll failed");
      exit(1);
    }

#if 1
    struct timespec cur_time;
    clock_gettime(CLOCK_MONOTONIC, &cur_time);
    int64_t dmsec =
        ((cur_time.tv_sec - last_keepalive_time.tv_sec) * 1000000000LL +
         (cur_time.tv_nsec - last_keepalive_time.tv_nsec)) /
        1000000LL;
    bool keepalive = false;

    if (dmsec > 2000) {
      last_keepalive_time.tv_sec += 2;
      keepalive = true;
    }
#endif

    if (keepalive) {
      logf("%lu: alive (%d)\n",
           cur_time.tv_sec * 1000LU + cur_time.tv_nsec / 1000000LU, poll_res);
    }
    if (poll_res > 0) {
      // Data available somewhere!
      // if ((poll_fds[SER_IDX].revents & ~POLLIN) != 0) {
      //   int re = poll_fds[SER_IDX].revents;
      //   logf("While polling ethernet interface: %d ( %s%s%s)", re,
      //        (re & POLLERR) != 0 ? "ERR " : "",
      //        (re & POLLHUP) != 0 ? "HUP " : "",
      //        (re & POLLNVAL) != 0 ? "INVAL " : "");
      // }

      if ((poll_fds[ETH_IDX].revents & ~POLLIN) != 0) {
        int re = poll_fds[ETH_IDX].revents;
        logf("While polling serial interface: %d ( %s%s%s)", re,
             (re & POLLERR) != 0 ? "ERR " : "",
             (re & POLLHUP) != 0 ? "HUP " : "",
             (re & POLLNVAL) != 0 ? "INVAL " : "");
      }

      // if ((poll_fds[SER_IDX].revents & POLLIN) != 0) {
      //   ser_read_available();
      // }
      if ((poll_fds[ETH_IDX].revents & POLLIN) != 0) {
        eth_read_available();
      }
    }
  }
}

void ser_read_available(void) {
  // TODO implement
}

void ser_accumulate_bytes(uint8_t *data, size_t size) {
  // Cache in local vars
  size_t used = ser_read_accum_used;
  bool esc = ser_read_accum_esc;

  // Sit in a loop reading bytes until we put together a whole packet. Make sure
  // not to copy them into the packet if we run out of room.
  size_t i = 0;
  while (i < size) {
    // If the last character was ESC, apply special processing to this one
    if (esc) {
      uint8_t c = data[i++];
      assert(used < sizeof ser_read_accum.ip.ip_raw);
      switch (c) {
        case SLIP_ESC_END:
          ser_read_accum.ip.ip_raw[used++] = SLIP_END;
          break;
        case SLIP_ESC_ESC:
          ser_read_accum.ip.ip_raw[used++] = SLIP_ESC;
          break;
        // If "c" is not one of these two, then we have a protocol violation.
        // The best bet seems to be to leave the byte alone and just stuff it
        // into the packet.
        default:
          ser_read_accum.ip.ip_raw[used++] = c;
          break;
      }
      esc = false;
      // Stop if we've emptied the input buffer
      if (i >= size) {
        break;
      }
    }

    // Consume as many non-special bytes as possible
    size_t j = i;
    while ((j < size) && (data[j] != SLIP_END) && (data[j] != SLIP_ESC)) {
      ++j;
    }
    // Any found?
    if (j > i) {
      size_t amount = j - i;
      assert(used + amount <= sizeof ser_read_accum.ip.ip_raw);
      // Copy the entire block of non-special bytes at once
      memcpy(ser_read_accum.ip.ip_raw + used, data + i, amount);
      used += amount;
      i = j;
      // Stop if we've emptied the input buffer
      if (i >= size) {
        break;
      }
    }

    // Finally, if we've got a special (ESC/END) character, consume/process it
    assert(i < size);  // Previous consuming clauses should break if empty
    uint8_t c = data[i++];
    // Handle bytestuffing if necessary
    switch (c) {
      // If it's an END character then we're done with the packet
      case SLIP_END:
        if (!validate_ip_frame(&ser_read_accum.ip, used)) {
          // Ignore packet, not valid IP
          logf("ser packet not valid ip (%lu bytes):\n", (unsigned long)used);
          hex_dump(stdlog, ser_read_accum.ip.ip_raw, used);
          // size_t ext_size = sizeof(struct ethhdr) + used;
          // hex_dump(stdlog, ser_read_accum.eth_raw,
          //          ext_size > 64 ? 64 : ext_size);
          // if (ext_size > 64) {
          //   logf("  ...\n");
          // }
        } else {
          ser_process(&ser_read_accum.ip);
        }
        // Packet has either been discarded or processed, start a new one
        used = 0;
        break;
      // If it's the same code as an ESC character, wait and get another
      // character and then figure out what to store in the packet based on
      // that.
      case SLIP_ESC:
        esc = true;
        break;
      // There shouldn't be anything but special characters if we got in here?
      default:
        assert(!"Should have been handled as a non-special character");
        break;
    }
  }

  // Commit to statics
  ser_read_accum_used = used;
  ser_read_accum_esc = esc;
}

void ser_process(struct ip_packet *ip_frame) {
  // TODO implement
  logf("received SLIP packet:\n");
  hex_dump(stdlog, ip_frame->ip_raw, ntohs(ip_frame->hdr.tot_len));
}

bool ser_process_dhcp_request(struct ip_packet *ip_frame) {
  // TODO implement
}

bool ser_process_arp_request(struct ip_packet *ip_frame) {
  // TODO implement
}

bool ser_process_arp_response(struct ip_packet *ip_frame) {
  // TODO implement
}

void ser_send(struct ip_packet const *ip_frame) {
  assert(ser_write_buf_head == 0);

  logf("ser_send packet:\n");
  hex_dump(stdlog, ip_frame, ntohs(ip_frame->hdr.tot_len));

  assert(validate_ip_frame(ip_frame, sizeof *ip_frame));
  size_t size = ntohs(ip_frame->hdr.tot_len);
  // For each byte in the packet, send the appropriate character sequence
  size_t i = 0;
  size_t j = 0;
  assert(j + 1 <= SER_BUF_SIZE);
  // Send an initial END character to flush out any data that may have
  // accumulated in the receiver due to line noise
  ser_write_buf[j++] = SLIP_END;
  while (i < size) {
    uint8_t c = ip_frame->ip_raw[i];
    switch (c) {
      // If it's the same code as an END character, we send a special two
      // character code so as not to make the receiver think we sent an END
      case SLIP_END: {
        assert(j + 2 <= SER_BUF_SIZE);
        ser_write_buf[j++] = SLIP_ESC;
        ser_write_buf[j++] = SLIP_ESC_END;
        ++i;
      } break;

      // If it's the same code as an ESC character, we send a special two
      // character code so as not to make the receiver think we sent an ESC
      case SLIP_ESC: {
        assert(j + 2 <= SER_BUF_SIZE);
        ser_write_buf[j++] = SLIP_ESC;
        ser_write_buf[j++] = SLIP_ESC_ESC;
        ++i;
      } break;

      // Otherwise, we just send the character
      default: {
        size_t k = i + 1;
        // But also keep looking in case more regular characters can be sent all
        // at once
        while ((k < size) && (ip_frame->ip_raw[k] != SLIP_END) &&
               (ip_frame->ip_raw[k] != SLIP_ESC)) {
          ++k;
        }
        size_t amount = k - i;
        assert(j + amount <= SER_BUF_SIZE);
        memcpy(ser_write_buf + i, ip_frame->ip_raw + i, amount);
        i = k;
        j += amount;
      } break;
    }
  }
  assert(j + 1 <= SER_BUF_SIZE);
  ser_write_buf[j++] = SLIP_END;

  ser_write_buf_tail = 0;
  ser_write_buf_head = j;

  ser_try_write_pending();
}

bool ser_try_write_pending(void) {
  if (ser_write_buf_tail == ser_write_buf_head) {
    return true;
  }

  // Write the buffer to the serial port
  ssize_t amount = ser_write_buf_head - ser_write_buf_tail;
  ssize_t result = amount;  // write(ser_fd, ser_write_buf + ser_write_buf_tail,
                            // (size_t)amount);
  ser_accumulate_bytes(ser_write_buf + ser_write_buf_tail, amount);
  if (result < 0) {
    perror("write to ser failed");
    ser_write_buf_head = 0;
    ser_write_buf_tail = 0;
    return true;
  } else if (result < amount) {
    ser_write_buf_tail += result;
    return false;
  } else {
    ser_write_buf_head = 0;
    ser_write_buf_tail = 0;
    return true;
  }
}

void eth_read_available(void) {
  // Try reading the ethernet interface -- despite the name it's okay to stop
  // at reading/processing a single packet
  struct eth_packet *eth_frame = alloc_packet_buf();
  if (eth_frame == NULL) {
    logf("eth packet alloc failed!\n");
    return;
  }

  struct sockaddr_storage packet_addr;
  socklen_t packet_addr_len = sizeof packet_addr;
  ssize_t recv_size;

  assert(sizeof *eth_frame == MAX_PACKET_SIZE);
  recv_size = recvfrom(eth_socket, eth_frame, MAX_PACKET_SIZE, MSG_DONTWAIT,
                       (struct sockaddr *)&packet_addr, &packet_addr_len);
  if (recv_size < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      // No message waiting after all
    } else {
      perror("recvfrom failed");
      exit(1);
    }
  } else if (recv_size < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    logf("eth packet runt frame (%lu bytes)\n", (unsigned long)recv_size);
  } else if ((memcmp(((struct ethhdr const *)eth_frame)->h_dest, &eth_mac,
                     ETH_ALEN) != 0) &&
             (memcmp(((struct ethhdr const *)eth_frame)->h_dest, &broadcast_mac,
                     ETH_ALEN) != 0)) {
    // Ignore packet, wrong dest
  } else if ((recv_size > MAX_PACKET_SIZE) ||
             (packet_addr_len > sizeof packet_addr)) {
    // Ignore packet, it too big
    logf("eth packet truncated (too big, got %lu of %lu bytes)\n",
         (unsigned long)(sizeof packet_addr), (unsigned long)recv_size);
  } else if (!validate_eth_ip_frame(eth_frame, (size_t)recv_size)) {
    // Ignore packet, not valid IP
    // logf("eth packet not valid ip (%lu bytes):\n", (unsigned long)recv_size);
    // hex_dump(stdlog, eth_frame, recv_size > 64 ? 64 : (size_t)recv_size);
    // if (recv_size > 64) {
    //   logf("  ...\n");
    // }
  } else {
    // A complete packet!
    eth_process_frame(eth_frame);
  }
  free_packet_buf(eth_frame);
}

void eth_process_frame(struct eth_packet *eth_frame) {
  ser_send(&eth_frame->ip);
}

bool eth_process_dhcp_response(struct eth_packet *eth_frame) {
  // TODO implement
  // first, check if a ser frame is available for the response
}

bool eth_process_arp_request(struct eth_packet *eth_frame) {
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

void eth_send(struct ip_packet *ip_frame) {
  // TODO implement
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

bool validate_eth_ip_frame(struct eth_packet const *eth_frame,
                           size_t eth_size) {
  uint16_t proto = ntohs(eth_frame->hdr.h_proto);

  if (proto < ETH_P_802_3_MIN) {
    // size = proto;
    // proto = ETH_P_802_3;
    return false;
  }
  if (proto != ETH_P_IP) {
    return false;
  }
  return validate_ip_frame(&eth_frame->ip, eth_size - sizeof(struct ethhdr));
}

bool validate_ip_frame(struct ip_packet const *ip_frame, size_t size) {
  if (size < sizeof(struct iphdr)) {
    logf("invalid IP packet: truncated header\n");
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

struct eth_packet *alloc_packet_buf(void) {
  if (packet_pool_unallocated_count > 0) {
    --packet_pool_unallocated_count;
    struct eth_packet *result =
        packet_pool_unallocated[packet_pool_unallocated_count];
    assert(result != NULL);
    packet_pool_unallocated[packet_pool_unallocated_count] = NULL;
    return result;
  } else {
    return NULL;
  }
}

void free_packet_buf(struct eth_packet *packet) {
  assert(packet != NULL);
  assert(packet_pool_unallocated_count < PACKET_POOL_SIZE);
  packet_pool_unallocated[packet_pool_unallocated_count] = packet;
  ++packet_pool_unallocated_count;
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
