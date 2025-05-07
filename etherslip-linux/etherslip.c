#include "etherslip.h"

bool recv_log = false;
bool send_log = false;
bool verbose_log = false;
bool very_verbose_log = false;

bool client_ready = false;
uint32_t ser_bps = 115200;

time_ms_t now_ms = 0;

struct eth_packet packet_pool[PACKET_POOL_SIZE];
struct eth_packet *packet_pool_unallocated[PACKET_POOL_SIZE];
size_t packet_pool_unallocated_count = 0;

struct ether_addr client_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
struct ether_addr host_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
struct ether_addr const broadcast_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
struct ether_addr const zero_mac = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

struct in_addr client_ip = {0};

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
  char net_if_name[IF_NAMESIZE] = "";
  struct ether_addr const *tmp_mac;
#endif

  int opt;
  while ((opt = getopt(argc, argv,
                       "s:"
#if USE_IF_ETH
                       "Dpe:m:"
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
      case 'D': {
        break;
      }
      case 'p': {
        break;
      }
      case 'm': {
        if ((tmp_mac = ether_aton(optarg)) == NULL) {
          print_usage_and_exit(argv[0],
                               "Bad argument to -m: expected MAC address", 1);
        }
        memcpy(&client_mac, tmp_mac, sizeof(struct ether_addr));
        client_ready = true;
      } break;
      case 'e': {
        snprintf(net_if_name, IF_NAMESIZE, "%s", optarg);
      } break;
#elif USE_IF_PKT
#else
#error "Must specify an interface type"
#endif

      case 'R': {
        recv_log = true;
      } break;
      case 'S': {
        send_log = true;
      } break;
      case 'v': {
        if (verbose_log) {
          // logf("very verbose logging\n");
          very_verbose_log = true;
        } else {
          // logf("verbose logging\n");
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
  eth_init(net_if_name);
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
#if USE_IF_ETH
      "Usage: %s [-bempsD...]"
      "\n"
      "    -p          Proxy mode: use the host machine's MAC address\n"
      "    -s <DEV>    Offer SLIP bridge to a client on DEV\n"
      "    -b <BPS>    Set serial port speed to BPS (default: 115200)"
      "    -e <DEV>    Bridge ethernet device DEV\n"
      "    -m <MAC>    Use MAC, instead of autodetecting/proxying\n"
      //"    -a <IP>     Enable rudimentary masquerading (ARP and rewriting)\n"
      "    -D          Disable snooping of DHCP\n"
      "\n"
      "Cerealnet etherslip is a SLIP-to-ethernet bridge that can send and\n"
      "receive packets via a unique MAC address, as if the bridged device\n"
      "was a separate adapter sharing media with the host machine, without\n"
      "messing with firewall rules and routing tables.\n"
#elif USE_IF_PKT
      "Usage: %s [-s SERIALDEV]"
#else
#error "Must specify an interface type"
#endif
      "",
      argv0);
  exit(result);
}

void poll_loop(void) {
  struct pollfd poll_fds[FDS_SIZE];

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  time_ms_t last_ms = time_ms_from_timespec(ts);
  time_ms_t keepalive_ms = 0;

  ser_setup_pollfd(&poll_fds[SER_IDX]);
#if USE_IF_ETH
  eth_setup_pollfd(&poll_fds[ETH_IDX]);
#elif USE_IF_PKT
  pkt_setup_pollfd(&poll_fds[PKT_IDX]);
#else
#error "Must specify an interface type"
#endif

  for (;;) {
    int poll_timeout = 100;
    if (ser_has_work() || net_has_work()
#if USE_IF_ETH
        || eth_has_work()
#elif USE_IF_PKT
        || pkt_has_work()
#else
#error "Must specify an interface type"
#endif
        || arp_has_work()) {
      poll_timeout = 0;
    } else if (net_waiting()) {
      poll_timeout = 1;
    }
    int poll_res = poll(poll_fds, FDS_SIZE, poll_timeout);
    if (poll_res < 0) {
      perror("poll failed");
      exit(1);
    }

    // Update the now_ms clock (right after a potentially long poll() wait is
    // the proper time)
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_ms_t read_ms = time_ms_from_timespec(ts);
    now_ms += time_since_ms(read_ms, last_ms);
    last_ms = read_ms;

    // Check if any data was returned in the poll() call
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

      arp_process_queued();

      // Do any queued writes resulting from the reads
      ser_try_write_all_queued();
#if USE_IF_ETH
      eth_try_write_all_queued();
#elif USE_IF_PKT
      pkt_try_write_all_queued();
#else
#error "Must specify an interface type"
#endif

      // Do ARP table cleanup
      arp_idle();

      if ((keepalive_ms - now_ms > 2000) && verbose_log) {
        keepalive_ms += 2000;
        logf("%lu: alive (%d)\n", (unsigned long)now_ms, poll_res);
      }
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
  } else
    // validate_ip_frame not validate_eth_ip_frame, because the ethernet frame
    // is forged for client (SLIP) packets anyway
    if (!validate_ip_frame(&frame->ip, ETH_IP_SIZE(frame))) {
      // Ignore packet, not valid IP
      if (verbose_log && send_log) {
        logf("client packet not valid (%lu bytes):\n",
             (unsigned long)ETH_IP_SIZE(frame));
        hex_dump(stdlog, frame->ip.ip_raw, ETH_IP_SIZE(frame));
      }
    } else if (client_forward_frame(frame)) {
      frame = NULL;
    }

  if (frame != NULL) {
    free_packet_buf(frame);
  }
}

bool client_forward_frame(struct eth_packet *frame) {
  if (very_verbose_log && send_log) {
    logf(
        "client packet ok, %lu bytes; hdr tot_len=%lu, proto=%02X, "
        "sa=%s, ",
        (unsigned long)ETH_IP_SIZE(frame),
        (unsigned long)ntohs(frame->ip.hdr.tot_len),
        (int)frame->ip.hdr.protocol,
        inet_ntoa(*(struct in_addr *)&frame->ip.hdr.saddr));
    logf("da=%s\n", inet_ntoa(*(struct in_addr *)&frame->ip.hdr.daddr));
  }

  frame->hdr.h_proto = htons(ETH_P_IP);
  net_send_link_frame(frame);

  return true;
}

void net_process_frame(struct eth_packet *frame) {
  if (frame->recv_size < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    if (verbose_log && recv_log) {
      logf("net packet runt frame (%lu bytes)\n",
           (unsigned long)frame->recv_size);
    }
  } else if (frame->recv_size > MAX_PACKET_SIZE) {
    // Ignore packet, too big (extra jumbo frame? We can't handle it)
    logf("net packet too big (trucated to %lu of %lu bytes)\n",
         (unsigned long)(MAX_PACKET_SIZE), (unsigned long)frame->recv_size);
  } else if (arp_process_frame(frame)) {
    frame = NULL;
  } else if (validate_eth_ip_frame(frame)) {
    // Valid IP frame...
    arp_snoop_ip_frame(frame);
#if USE_IF_ETH
    if ((!client_ready ||
         memcmp(&frame->hdr.h_dest, &client_mac, ETH_ALEN) != 0) &&
        (memcmp(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN) != 0)) {
      // TODO multicast support? Not sure how this works
      if (very_verbose_log && recv_log) {
        logf("net packet for another host (%s)\n",
             ether_ntoa((struct ether_addr const *)&frame->hdr.h_dest));
      }
    } else {
#endif
      if (client_ready && net_forward_frame(frame)) {
        frame = NULL;
      }
#if USE_IF_ETH
    }
#endif
  } else {
    // Ignore packet: it's not valid IP
    if (very_verbose_log && recv_log) {
      if ((client_ready &&
           memcmp(&frame->hdr.h_dest, &client_mac, ETH_ALEN) == 0) ||
          (memcmp(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN) == 0)) {
        logf("net packet not recognized (%lu bytes):\n",
             (unsigned long)frame->recv_size);
        hex_dump(stdlog, &frame->eth_raw, frame->recv_size);
      }
    }
  }

  if (frame != NULL) {
    free_packet_buf(frame);
  }
}

bool net_forward_frame(struct eth_packet *frame) {
  // Caller promises this is actually a valid IP packet
  assert(validate_eth_ip_frame(frame));

  // A complete packet and we're ready for it!
  if (very_verbose_log && recv_log) {
    logf(
        "net packet ok, %lu bytes; hdr tot_len=%lu, proto=%02X, "
        "sa=%s, ",
        (unsigned long)frame->recv_size,
        (unsigned long)ntohs(frame->ip.hdr.tot_len),
        (int)frame->ip.hdr.protocol,
        inet_ntoa(*(struct in_addr *)&frame->ip.hdr.saddr));
    logf("da=%s\n", inet_ntoa(*(struct in_addr *)&frame->ip.hdr.daddr));
  }

  // TODO rewrite IP addresses for masquerading if needed
  // TODO filter in only IP packets actually sent to the client

  // Pass frame on to serial send
  ser_send(frame);
  return true;
}

void net_send_link_frame(struct eth_packet *frame) {
#if USE_IF_ETH
  eth_send(frame);
#elif USE_IF_PKT
  pkt_send(frame);
#else
#error "Must specify an interface type"
#endif
}

bool net_has_work(void) { return false; }

bool net_waiting(void) { return false; }

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
    // IPv6 is common enough we don't want to spam about it unbidden
    if ((ip_frame->hdr.version != 6) || very_verbose_log) {
      logf("invalid IP packet: bad version (%d)\n", (int)ip_frame->hdr.version);
    }
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
    // if (very_verbose_log) {
    //   logf("alloc buf, %lu available\n",
    //        (unsigned long)packet_pool_unallocated_count);
    // }
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
  // if (very_verbose_log) {
  //   logf("free buf, %lu available\n",
  //        (unsigned long)packet_pool_unallocated_count);
  // }
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
