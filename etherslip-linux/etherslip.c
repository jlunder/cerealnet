#include "etherslip.h"

bool recv_log = false;
bool send_log = false;
bool verbose_log = false;
bool very_verbose_log = false;

struct eth_packet packet_pool[PACKET_POOL_SIZE];
struct eth_packet *packet_pool_unallocated[PACKET_POOL_SIZE];
size_t packet_pool_unallocated_count = 0;

struct eth_packet *ser_read_accum = NULL;
size_t ser_read_accum_used = 0;
bool ser_read_accum_esc = false;

uint8_t ser_write_queue[SER_WRITE_QUEUE_SIZE];
size_t ser_write_queue_head = 0;
size_t ser_write_queue_tail = 0;

size_t ser_send_head = 0;
size_t ser_send_tail = 0;

int ser_fd;

#if USE_IF_ETH
int eth_socket = -1;
struct eth_packet *eth_write_queue = NULL;
#elif USE_IF_PKT
int pkt_send_socket = -1;
int pkt_recv_socket = -1;
struct eth_packet *pkt_write_queue = NULL;
#else
#error "Must specify an interface type"
#endif

struct ether_addr client_mac;
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
#if USE_IF_ETH
  char eth_dev_name[IFNAMSIZ] = "";
  struct ether_addr const *tmp_mac;
  bool force_eth_mac = false;
#endif

  int opt;
  while ((opt = getopt(argc, argv,
                       "s:"
#if USE_IF_ETH
                       "e:m:"
#elif USE_IF_PKT
#else
#error "Must specify an interface type"
#endif
                       "RSvh")) != -1) {
    switch (opt) {
      case 's': {
        snprintf(ser_dev_name, PATH_MAX, "%s", optarg);
      } break;

#if USE_IF_ETH
      case 'm': {
        force_eth_mac = true;
        if ((tmp_mac = ether_aton(optarg)) == NULL) {
          print_usage_and_exit(argv[0], "Bad arg: expected MAC address", 1);
        }
        memcpy(&client_mac, tmp_mac, sizeof(struct ether_addr));
      } break;
      case 'e': {
        snprintf(eth_dev_name, IFNAMSIZ, "%s", optarg);
      } break;
#elif USE_IF_PKT
#else
#error "Must specify an interface type"
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

      case 'R': {
        recv_log = true;
      } break;
      case 'S': {
        send_log = true;
      } break;
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
#if USE_IF_ETH
  eth_init(eth_dev_name, force_eth_mac);
#elif USE_IF_PKT
  pkt_init();
#else
#error "Must specify an interface type"
#endif
}

void print_usage_and_exit(char const *argv0, char const *extra_message,
                          int result) {
  if (extra_message != NULL) {
    logf("%s\n\n", extra_message);
  }
  logf(
      "Usage: %s [-s SERIALDEV]"

#if USE_IF_ETH
      " [-e ETHDEV] [-m MAC ]"
#elif USE_IF_PKT
#else
#error "Must specify an interface type"
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
    if (ser_write_queue_head != ser_write_queue_tail) {
      poll_fds[SER_IDX].events |= POLLOUT;
    }
    poll_fds[SER_IDX].revents = 0;

#if USE_IF_ETH
    poll_fds[ETH_IDX].fd = eth_socket;
    poll_fds[ETH_IDX].events = POLLIN;
    if (eth_write_queue != NULL) {
      poll_fds[ETH_IDX].events |= POLLOUT;
    }
    poll_fds[ETH_IDX].revents = 0;
#elif USE_IF_PKT
    poll_fds[PKT_IDX].fd = pkt_recv_socket;
    poll_fds[PKT_IDX].events = POLLIN;
    if (pkt_write_queue != NULL) {
      poll_fds[PKT_IDX].events |= POLLOUT;
    }
    poll_fds[PKT_IDX].revents = 0;
#else
#error "Must specify an interface type"
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

      // Check for errors
      if ((poll_fds[SER_IDX].revents & ~POLLIN) != 0) {
        int re = poll_fds[SER_IDX].revents;
        logf("While polling ser interface: %d ( %s%s%s)", re,
             (re & POLLERR) != 0 ? "ERR " : "",
             (re & POLLHUP) != 0 ? "HUP " : "",
             (re & POLLNVAL) != 0 ? "INVAL " : "");
      }
      // Check for data
      if ((poll_fds[SER_IDX].revents & POLLIN) != 0) {
        ser_read_available();
      }

#if USE_IF_ETH
      // Check for errors
      if ((poll_fds[ETH_IDX].revents & ~POLLIN) != 0) {
        int re = poll_fds[ETH_IDX].revents;
        logf("While polling eth interface: %d ( %s%s%s)", re,
             (re & POLLERR) != 0 ? "ERR " : "",
             (re & POLLHUP) != 0 ? "HUP " : "",
             (re & POLLNVAL) != 0 ? "INVAL " : "");
      }
      // Check for data
      if ((poll_fds[ETH_IDX].revents & POLLIN) != 0) {
        eth_read_available();
      }
#elif USE_IF_PKT
      // Check for errors
      if ((poll_fds[PKT_IDX].revents & ~POLLIN) != 0) {
        int re = poll_fds[PKT_IDX].revents;
        logf("While polling pkt interface: %d ( %s%s%s)", re,
             (re & POLLERR) != 0 ? "ERR " : "",
             (re & POLLHUP) != 0 ? "HUP " : "",
             (re & POLLNVAL) != 0 ? "INVAL " : "");
      }
      // Check for data
      if ((poll_fds[PKT_IDX].revents & POLLIN) != 0) {
        pkt_read_available();
      }
#else
#error "Must specify an interface type"
#endif

      ser_try_write_all_queued();

#if USE_IF_ETH
      eth_try_write_all_queued();
#elif USE_IF_PKT
      pkt_try_write_all_queued();
#else
#error "Must specify an interface type"
#endif
    }
  }
}

void client_process_frame(struct eth_packet *frame) {
  if (frame->recv_size < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    if (verbose_log && send_log) {
      logf("client packet runt frame (%lu bytes)\n",
           (unsigned long)frame->recv_size);
    }
  } else if (!validate_ip_frame(&frame->ip, ETH_IP_SIZE(frame))) {
    // Ignore packet, not valid IP
    if (verbose_log && send_log) {
      logf("client packet not valid (%lu bytes):\n",
           (unsigned long)ETH_IP_SIZE(frame));
      hex_dump(stdlog, ser_read_accum->ip.ip_raw, ETH_IP_SIZE(frame));
    }
  } else {
    if (very_verbose_log && send_log) {
      char srcaddr[20], destaddr[20];
      inet_ntop(AF_INET, &ser_read_accum->ip.hdr.saddr, srcaddr,
                sizeof srcaddr);
      inet_ntop(AF_INET, &ser_read_accum->ip.hdr.daddr, destaddr,
                sizeof destaddr);
      logf(
          "client packet ok, %lu bytes; hdr tot_len=%lu, proto=%02X, "
          "sa=%s, da=%s\n",
          (unsigned long)ETH_IP_SIZE(frame),
          (unsigned long)ntohs(ser_read_accum->ip.hdr.tot_len),
          (int)ser_read_accum->ip.hdr.protocol, srcaddr, destaddr);
    }
    memcpy(&ser_read_accum->hdr.h_dest, &client_mac, sizeof(struct ether_addr));
    memcpy(&ser_read_accum->hdr.h_source, &broadcast_mac,
           sizeof(struct ether_addr));
    ser_read_accum->hdr.h_proto = ETH_P_IP;
    if (!client_process_dhcp_request(frame)) {
#if USE_IF_ETH
      eth_send(frame);
#elif USE_IF_PKT
#else
      pkt_send(frame);
#error "Must specify an interface type"
#endif
    }
  }
}

bool client_process_dhcp_request(struct eth_packet *frame) {
  (void)frame;
  return false;
}

void net_process_frame(struct eth_packet *frame) {
  if (frame->recv_size < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    if (verbose_log && recv_log) {
      logf("net packet runt frame (%lu bytes)\n",
           (unsigned long)frame->recv_size);
    }
#if USE_IF_ETH
  } else if ((memcmp(&frame->hdr.h_dest, &client_mac, ETH_ALEN) != 0) &&
             (memcmp(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN) != 0)) {
    // Ignore packet, not for us
    // TODO multicast support? Not sure how this works
    if (very_verbose_log && recv_log) {
      logf("net packet for another host (%s)\n",
           ether_ntoa((struct ether_addr const *)&frame->hdr.h_dest));
    }
#endif
  } else if (frame->recv_size > MAX_PACKET_SIZE) {
    // Ignore packet, too big (extra jumbo frame? We can't handle it)
    logf("net packet too big (trucated to %lu of %lu bytes)\n",
         (unsigned long)(MAX_PACKET_SIZE), (unsigned long)frame->recv_size);
  } else if (!validate_eth_ip_frame(frame)) {
    // Ignore packet, not valid IP
    if (verbose_log && recv_log) {
      logf("net packet not valid (%lu bytes):\n",
           (unsigned long)frame->recv_size);
      hex_dump(stdlog, &frame->eth_raw, frame->recv_size);
    }
  } else {
    // A complete packet!
    if (very_verbose_log && recv_log) {
      char srcaddr[20], destaddr[20];
      inet_ntop(AF_INET, &frame->ip.hdr.saddr, srcaddr, sizeof srcaddr);
      inet_ntop(AF_INET, &frame->ip.hdr.daddr, destaddr, sizeof destaddr);
      logf(
          "net packet ok, %lu bytes; hdr tot_len=%lu, proto=%02X, "
          "sa=%s, da=%s\n",
          (unsigned long)frame->recv_size,
          (unsigned long)ntohs(frame->ip.hdr.tot_len),
          (int)frame->ip.hdr.protocol, srcaddr, destaddr);
    }
    if (!net_process_dhcp_response(frame) && !net_process_arp_request(frame)) {
      ser_send(frame);
    }
    // Don't free frame, it's handed off to the other processors
    return;
  }

  free_packet_buf(frame);
}

bool net_process_dhcp_response(struct eth_packet *frame) {
  (void)frame;
  return false;
}

bool net_process_arp_request(struct eth_packet *frame) {
  (void)frame;
  return false;
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
  return validate_ip_frame(&frame->ip, ETH_IP_SIZE(frame));
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

struct eth_packet *alloc_packet_buf(void) {
  if (packet_pool_unallocated_count > 0) {
    --packet_pool_unallocated_count;
    struct eth_packet *result =
        packet_pool_unallocated[packet_pool_unallocated_count];
    assert(result != NULL);
    packet_pool_unallocated[packet_pool_unallocated_count] = NULL;
    if (very_verbose_log) {
      logf("alloc buf, %lu available\n",
           (unsigned long)packet_pool_unallocated_count);
    }
    return result;
  } else {
    if (very_verbose_log) {
      logf("alloc buf fail, none available\n");
    }
    return NULL;
  }
}

void free_packet_buf(struct eth_packet *packet) {
  assert(packet != NULL);
  assert(packet_pool_unallocated_count < PACKET_POOL_SIZE);
  packet_pool_unallocated[packet_pool_unallocated_count] = packet;
  ++packet_pool_unallocated_count;
  if (very_verbose_log) {
    logf("free buf, %lu available\n",
         (unsigned long)packet_pool_unallocated_count);
  }
}

int sock_get_ifindex(int fd, char const *dev_name) {
  struct ifreq if_ioreq;

  memset(&if_ioreq, 0, sizeof if_ioreq);
  snprintf(if_ioreq.ifr_name, IFNAMSIZ, "%s", dev_name);
  if (ioctl(fd, SIOCGIFINDEX, &if_ioreq) < 0) {
    perror("get socket index failed");
    exit(1);
  }
  return if_ioreq.ifr_ifindex;
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
