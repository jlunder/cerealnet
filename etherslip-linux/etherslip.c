#include "etherslip.h"

bool verbose_log = false;
bool very_verbose_log = false;

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

int ser_fd;

#ifdef USE_IF_ETH
size_t eth_send_head = 0;
size_t eth_send_tail = 0;
int eth_socket;
#endif

#ifdef USE_IF_PKT
int pkt_socket;
#endif

// the MAC address we're applying to packets bridged from the SLIP interface
struct ether_addr eth_mac;
struct ether_addr broadcast_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

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
  while ((opt = getopt(argc, argv,
                       "s:"
#ifdef USE_IF_ETH
                       "e:m:"
#endif
#ifdef USE_IF_PKT
#endif
                       "vh")) != -1) {
    switch (opt) {
      case 's': {
        snprintf(ser_dev_name, PATH_MAX, "%s", optarg);
      } break;

#ifdef USE_IF_ETH
      case 'm': {
        force_eth_mac = true;
        if ((tmp_mac = ether_aton(optarg)) == NULL) {
          print_usage_and_exit(argv[0], "Bad arg: expected MAC address", 1);
        }
        memcpy(&eth_mac, tmp_mac, sizeof(struct ether_addr));
      } break;
      case 'e': {
        snprintf(eth_dev_name, IFNAMSIZ, "%s", optarg);
      } break;
#endif

#ifdef USE_IF_PKT
#endif

#if 0
      case 'T': {
        struct ip_packet pkt;
        pkt.hdr.version = 4;
        pkt.hdr.ihl = 5;
        pkt.hdr.tos = 0x00;
        pkt.hdr.tot_len = htons(offsetof(struct ip_packet, ip_payload[256]));
        pkt.hdr.frag_off = htons(0);
        pkt.hdr.ttl = 0x40;
        pkt.hdr.id = 0x01;
        pkt.hdr.check = 0;
        pkt.hdr.daddr = inet_addr("192.168.86.255");
        pkt.hdr.saddr = inet_addr("192.168.86.43");
        for (size_t i = 0; i < 256; ++i) {
          pkt.ip_payload[i] = (uint8_t)i;
        }
        pkt.hdr.check = ip_header_checksum(&pkt, pkt.hdr.ihl * 4);
        ser_send(&pkt);
        exit(0);
      } break;
#endif

      case 'v': {
        if (verbose_log) {
          very_verbose_log = true;
        } else {
          verbose_log = true;
        }
      } break;
      case 'h': {
        print_usage_and_exit(argv[0], NULL, 0);
      } break;
      default: {
        print_usage_and_exit(argv[0], "Invalid option", 1);
      } break;
    }
  }

  ser_init(ser_dev_name);
  eth_init(eth_dev_name, force_eth_mac);
}

void print_usage_and_exit(char const *argv0, char const *extra_message,
                          int result) {
  if (extra_message != NULL) {
    logf("%s\n\n", extra_message);
  }
  logf(
      "Usage: %s [-s SERIALDEV]"

#ifdef USE_IF_ETH
      " [-e ETHDEV] [-m MAC ]"
#endif

#ifdef USE_IF_PKT
#endif

      "\n",
      argv0);
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

#ifdef USE_IF_ETH
    poll_fds[ETH_IDX].fd = eth_socket;
    poll_fds[ETH_IDX].events = POLLIN;
    poll_fds[ETH_IDX].revents = 0;
#endif

#ifdef USE_IF_PKT
    poll_fds[PKT_IDX].fd = pkt_socket;
    poll_fds[PKT_IDX].events = POLLIN;
    poll_fds[PKT_IDX].revents = 0;
#endif

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

    if (keepalive && verbose_log) {
      logf("%lu: alive (%d)\n",
           cur_time.tv_sec * 1000LU + cur_time.tv_nsec / 1000000LU, poll_res);
    }
    if (poll_res > 0) {
      // Data available somewhere!
      if ((poll_fds[SER_IDX].revents & ~POLLIN) != 0) {
        int re = poll_fds[SER_IDX].revents;
        logf("While polling ethernet interface: %d ( %s%s%s)", re,
             (re & POLLERR) != 0 ? "ERR " : "",
             (re & POLLHUP) != 0 ? "HUP " : "",
             (re & POLLNVAL) != 0 ? "INVAL " : "");
      }

      if ((poll_fds[ETH_IDX].revents & ~POLLIN) != 0) {
        int re = poll_fds[ETH_IDX].revents;
        logf("While polling serial interface: %d ( %s%s%s)", re,
             (re & POLLERR) != 0 ? "ERR " : "",
             (re & POLLHUP) != 0 ? "HUP " : "",
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
