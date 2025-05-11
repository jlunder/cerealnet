#include "etherslip.h"

#define NET_FORWARD_QUEUE_SIZE 2

static_assert(IS_POW2(NET_FORWARD_QUEUE_SIZE));

struct udp_pseudoip {
  struct in_addr saddr;
  struct in_addr daddr;
  uint8_t pad;
  uint8_t protocol;
  uint16_t udplen;
} __attribute__((packed));

struct net_forward_queue_entry {
  struct eth_packet *frame;
  time_ms_t submitted_ms;
};

uint16_t udp_checksum(struct ip_packet const *ip_frame, size_t udp_size);

bool recv_log = false;
bool send_log = false;
bool verbose_log = false;
bool very_verbose_log = false;

uint32_t ser_bps = 115200;

time_ms_t now_ms = 0;

bool client_ready = false;

struct ether_addr client_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
struct ether_addr host_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
struct ether_addr const broadcast_mac = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
struct ether_addr const zero_mac = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

struct in_addr client_ip = {INADDR_ANY};
struct in_addr client_network = {INADDR_ANY};
struct in_addr client_netmask = {INADDR_ANY};
struct in_addr client_broadcast = {INADDR_BROADCAST};
struct in_addr client_gateway = {INADDR_BROADCAST};

struct eth_packet packet_pool[PACKET_POOL_SIZE];
struct eth_packet *packet_pool_unallocated[PACKET_POOL_SIZE];
size_t packet_pool_unallocated_count = 0;

struct net_forward_queue_entry net_forward_queue[NET_FORWARD_QUEUE_SIZE];
size_t net_forward_queue_tail = 0;
size_t net_forward_queue_count = 0;

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
        if (strcasecmp(optarg, "gen") == 0) {
          struct timespec ts;
          if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
            ts.tv_sec = time(NULL);
            ts.tv_nsec = 0;
          }
          srand(ts.tv_sec + ts.tv_nsec);
          for (int i = 0; i < ETH_ALEN; ++i) {
            client_mac.ether_addr_octet[i] = (rand() >> 2) & 0xFF;
          }
          client_mac.ether_addr_octet[0] |= 0x02;
          logf("eth: generated client MAC %s\n", ether_ntoa(&client_mac));
        } else {
          tmp_mac = ether_aton(optarg);
          if (tmp_mac == NULL) {
            print_usage_and_exit(argv[0],
                                 "Bad argument to -m: expected MAC address", 1);
          }
          memcpy(&client_mac, tmp_mac, sizeof(struct ether_addr));
        }
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
      "    -p          Proxy mode: use the host's MAC address and ARP\n"
      "    -s <DEV>    Offer SLIP bridge to a client on DEV\n"
      "    -b <BPS>    Set serial port speed to BPS (default: 115200)"
      "    -e <DEV>    Bridge ethernet device DEV\n"
      "    -m <MAC>    Use MAC, instead of autodetecting/proxying\n"
      "    -m gen      Generate a random MAC\n"
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
    if (ser_has_work()
#if USE_IF_ETH
        || eth_has_work()
#elif USE_IF_PKT
        || pkt_has_work()
#else
#error "Must specify an interface type"
#endif
    ) {
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

      // Process/send packets waiting on ARP replies etc.
      net_process_queued();

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
  if (frame->len < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    if (verbose_log && send_log) {
      logf("client packet runt frame (%lu bytes)\n", (unsigned long)frame->len);
    }
  } else
    // validate_ip_frame not validate_eth_ip_frame, because the ethernet frame
    // is forged for client (SLIP) packets anyway
    if (!validate_ip_frame(&frame->ip, ETH_IP_SIZE(frame))) {
      // Ignore packet, not valid IP
      if (verbose_log && send_log) {
        logf("client packet not valid (%lu bytes):\n",
             (unsigned long)ETH_IP_SIZE(frame));
        hex_dump(stdlog, frame->ip.raw, ETH_IP_SIZE(frame));
      }
    } else if (net_forward_client_frame(frame)) {
      frame = NULL;
    }

  if (frame != NULL) {
    free_packet_buf(frame);
  }
}

bool client_forward_net_frame(struct eth_packet *frame) {
  // Caller promises this is actually a valid IP packet
  assert(validate_eth_ip_frame(frame));

  // A complete packet and we're ready for it!
  if (very_verbose_log && recv_log) {
    logf(
        "net packet ok, %lu bytes; hdr tot_len=%lu, proto=%02X, "
        "sa=%s, ",
        (unsigned long)frame->len, (unsigned long)ntohs(frame->ip.hdr.tot_len),
        (int)frame->ip.hdr.protocol, inet_ntoa(ip_get_saddr(&frame->ip)));
    logf("da=%s\n", inet_ntoa(ip_get_daddr(&frame->ip)));
  }

  // TODO rewrite IP addresses for masquerading if needed
  // TODO filter in only IP packets actually sent to the client

  // Pass frame on to serial send
  ser_send(frame);
  return true;
}

void net_process_frame(struct eth_packet *frame) {
  if (frame->len < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    if (verbose_log && recv_log) {
      logf("net packet runt frame (%lu bytes)\n", (unsigned long)frame->len);
    }
  } else if (frame->len > MAX_PACKET_SIZE) {
    // Ignore packet, too big (extra jumbo frame? We can't handle it)
    logf("net packet too big (trucated to %lu of %lu bytes)\n",
         (unsigned long)(MAX_PACKET_SIZE), (unsigned long)frame->len);
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
      if (client_ready && client_forward_net_frame(frame)) {
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
             (unsigned long)frame->len);
        hex_dump(stdlog, &frame->raw, frame->len);
      }
    }
  }

  if (frame != NULL) {
    free_packet_buf(frame);
  }
}

bool net_forward_client_frame(struct eth_packet *frame) {
  if (very_verbose_log && send_log) {
    logf(
        "client packet ok, %lu bytes; hdr tot_len=%lu, proto=%d, "
        "sa=%s, ",
        (unsigned long)ETH_IP_SIZE(frame),
        (unsigned long)ntohs(frame->ip.hdr.tot_len),
        (int)frame->ip.hdr.protocol, inet_ntoa(ip_get_saddr(&frame->ip)));
    logf("da=%s\n", inet_ntoa(ip_get_daddr(&frame->ip)));
    hex_dump(stdlog, frame->raw, frame->len);
  }

  assert(validate_ip_frame(&frame->ip, ETH_IP_SIZE(frame)));

  if (!ip_is_proper(client_ip) && ip_is_proper(ip_get_saddr(&frame->ip))) {
    if (verbose_log) {
      logf("net: updating client IP from %s", inet_ntoa(client_ip));
      logf(" to %s (snooped outgoing)\n",
           inet_ntoa(*(struct in_addr *)&frame->ip.hdr.saddr));
    }
    client_ip = *(struct in_addr *)&frame->ip.hdr.saddr;
  }

  if (frame->ip.hdr.protocol == IPPROTO_UDP) {
    struct iphdr *ip = &frame->ip.hdr;
    size_t header_len = ip->ihl * 4;
    if (header_len + sizeof(struct udphdr) > ntohs(ip->tot_len)) {
      // Not well formed
      if (verbose_log) {
        logf("net: runt UDP datagram from client, not forwarding\n");
      }
      return false;
    }
    struct udphdr *udp = (struct udphdr *)&frame->ip.raw[header_len];
    size_t req_tot_len = header_len + ntohs(udp->len);
    if (req_tot_len > ntohs(ip->tot_len)) {
      // Not well formed
      if (verbose_log) {
        logf("net: UDP length %d does not match IP length %d, not forwarding\n",
             (int)(header_len + ntohs(udp->len)), (int)ntohs(ip->tot_len));
      }
      return false;
    }
    if (udp->check != 0) {
      uint16_t check = udp_checksum(&frame->ip, ntohs(udp->len));
      if (check != 0xFFFF) {
        if (verbose_log) {
          logf(
              "net: UDP checksum 0x%04X does not match computed 0x%04X, not "
              "forwarding\n",
              (unsigned)udp->check, (unsigned)check);
        }
        return false;
      }
    }

    // Snoop/masquerade DHCP
    struct dhcp_info info;
    struct dhcp_msg *dhcp = dhcp_parse_packet(frame, &info);
    if (dhcp != NULL) {
      if (!client_ready &&
          (info.client_to_broadcast || info.client_to_server)) {
        if (eth_is_proper_mac(*(struct ether_addr *)&dhcp->chaddr)) {
          logf("net: adopting client MAC %s from BOOTP/DHCP request\n",
               ether_ntoa((struct ether_addr *)&dhcp->chaddr));
          memcpy(&client_mac, &dhcp->chaddr, ETH_ALEN);
          client_ready = true;
        }
        if (ip_is_proper(*(struct in_addr *)&dhcp->ciaddr)) {
          logf("net: adopting initial client IP %s from BOOTP/DHCP request\n",
               inet_ntoa(dhcp->ciaddr));
          client_ip = dhcp->ciaddr;
        }
      }

      if (verbose_log && !ip_equals(client_ip, dhcp->ciaddr)) {
        logf("net: client supplied suspicious ciaddr %s",
             inet_ntoa(dhcp->ciaddr));
        logf("in snooped DHCP, expected %s\n", inet_ntoa(client_ip));
      }

      // Rewrite client MAC address in packet
      memcpy(&dhcp->chaddr, &client_mac, ETH_ALEN);
      udp->check = htons(0);
      udp->check = udp_checksum(&frame->ip, ntohs(udp->len));

      // re-parse
      dhcp = dhcp_parse_packet(frame, &info);
      logf("net: snooping client DHCP");
      logf(" from %s@%s", inet_ntoa(info.client_ip),
           ether_ntoa(&info.client_mac));
      logf(" to %s@%s\n", inet_ntoa(info.server_ip),
           ether_ntoa(&info.server_mac));
      logf("net: DHCP info, chaddr=%s", ether_ntoa(&info.chaddr));
      if (info.client_to_broadcast) {
        logf(" C->BC");
      }
      if (info.client_to_server) {
        logf(" C->S");
      }
      if (info.server_to_client) {
        logf(" S->C");
      }
      if (info.bootp_request) {
        logf(" BREQ");
      } else {
        logf(" BREP");
      }
      if (info.is_discover) {
        logf(" DISC");
      }
      if (info.is_ack) {
        logf(" ACK");
      }
      logf("\n");
    }
  }

  struct in_addr dest_ip = ip_get_daddr(&frame->ip);
  if (!ip_is_proper_or_broadcast(dest_ip)) {
    if (verbose_log) {
      logf("net: client packet with improper destination %s, not forwarding\n",
           inet_ntoa(dest_ip));
    }
    return false;
  }

  // This should have been reset, it's actually critical in order for the ARP
  // request to be checked/retried later
  assert(memcmp(&frame->hdr.h_dest, &zero_mac, ETH_ALEN) == 0);

  // Try to get the last bit, dest MAC, and send immediately
  if (client_ready &&
      arp_fetch_address(client_ip, dest_ip, true,
                        (struct ether_addr *)&frame->hdr.h_dest)) {
    if (net_send_link_frame(frame)) {
      return true;
    }
  }

  // Find an open spot in the send queue
  for (size_t i = 0; i < NET_FORWARD_QUEUE_SIZE; ++i) {
    if (net_forward_queue[net_forward_queue_tail].frame == NULL) {
      break;
    }
    net_forward_queue_tail =
        (net_forward_queue_tail + 1) & (NET_FORWARD_QUEUE_SIZE - 1);
  }

  if (net_forward_queue[net_forward_queue_tail].frame != NULL) {
    if (verbose_log) {
      logf("net: forward queue full, not forwarding\n");
    }
    return false;
  }

  net_forward_queue[net_forward_queue_tail].frame = frame;
  net_forward_queue[net_forward_queue_tail].submitted_ms = now_ms;
  ++net_forward_queue_count;

  return true;
}

bool net_send_link_frame(struct eth_packet *frame) {
#if USE_IF_ETH
  // Fill out info we definitely have
  frame->hdr.h_proto = htons(ETH_P_IP);
  *(struct ether_addr *)&frame->hdr.h_source = client_mac;

  return eth_send(frame);
#elif USE_IF_PKT
  return pkt_send(frame);
#else
#error "Must specify an interface type"
#endif
}

void net_process_queued(void) {
  net_forward_queue_count = 0;

  for (size_t i = 0; i < NET_FORWARD_QUEUE_SIZE; ++i) {
    struct net_forward_queue_entry *entry =
        &net_forward_queue[(net_forward_queue_tail + i) &
                           (NET_FORWARD_QUEUE_SIZE - 1)];
    if (entry->frame == NULL) {
      continue;
    }

    if (time_since_ms(now_ms, entry->submitted_ms) > 5000UL) {
      // Aged out
      free_packet_buf(entry->frame);
      entry->frame = NULL;
      continue;
    }

    bool has_h_dest =
        (memcmp(&entry->frame->hdr.h_dest, &zero_mac, ETH_ALEN) != 0);
    if (!has_h_dest) {
      // No destination MAC yet, retry ARP
      has_h_dest =
          arp_fetch_address(client_ip, ip_get_daddr(&entry->frame->ip), true,
                            (struct ether_addr *)&entry->frame->hdr.h_dest);
    }
    if (has_h_dest && net_send_link_frame(entry->frame)) {
      // Successfully sent!
      entry->frame = NULL;
    }

    if (entry->frame != NULL) {
      ++net_forward_queue_count;
    }
  }
}

bool net_waiting(void) { return net_forward_queue_count > 0; }

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

uint16_t udp_checksum(struct ip_packet const *ip_frame, size_t udp_size) {
  struct udp_pseudoip pseudo_ip;
  pseudo_ip.saddr = ip_get_saddr(ip_frame);
  pseudo_ip.daddr = ip_get_daddr(ip_frame);
  pseudo_ip.pad = 0;
  pseudo_ip.protocol = IPPROTO_UDP;
  pseudo_ip.udplen = htons(udp_size);

  assert(udp_size < 65535);
  // This checksum can't overflow a uint32 for a valid-sized UDP packet, but the
  // size restriction imposed by UDP is critical. At max packet size of 64k, we
  // will sum to 32768 * 65535, which is getting close to INT32_MAX
  uint32_t checksum = 0;

  // Checksum the pseudo-IP header
  for (size_t i = 0; i < sizeof(pseudo_ip) / 2; ++i) {
    checksum += ntohs(((uint16_t const *)&pseudo_ip)[i]);
  }
  // Checksum the datagram
  for (size_t i = 0; i < udp_size / 2; ++i) {
    checksum += ntohs(((uint16_t const *)(ip_frame->raw + ip_frame->hdr.ihl * 4))[i]);
  }
  // For odd size, add in an implicitly padded last word
  if ((udp_size & 1) != 0) {
    checksum += ntohs((ip_frame->raw + ip_frame->hdr.ihl * 4)[udp_size - 1]);
  }

  checksum = ((checksum >> 16) + (checksum & 0xFFFF));
  checksum = ((checksum >> 16) + (checksum & 0xFFFF));
  assert(checksum <= 0xFFFF);
  checksum = ~checksum & 0xFFFF;
  if (checksum == 0) {
    checksum = 0xFFFF;
  }
  return htons(checksum);
}

struct dhcp_msg *dhcp_parse_packet(struct eth_packet *frame,
                                   struct dhcp_info *out_info) {
  assert(out_info != NULL);

  struct iphdr *ip = &frame->ip.hdr;
  size_t header_len = ip->ihl * 4;
  struct udphdr *udp = (struct udphdr *)&frame->ip.raw[header_len];

  // These should already have been checked -- is it valid UDP?
  assert(frame->ip.hdr.protocol == IPPROTO_UDP);
  assert(header_len + sizeof(struct udphdr) <= ntohs(ip->tot_len));
  assert(header_len + ntohs(udp->len) == ntohs(ip->tot_len));

  // Clear our output struct
  memset(out_info, 0, sizeof *out_info);

  // In theory, we should compute/check the checksum, if it's set

  if ((ntohs(udp->source) == 68) && (ntohs(udp->dest) == 67)) {
    if (ip->daddr == INADDR_BROADCAST) {
      out_info->client_to_broadcast = true;
    } else {
      out_info->client_to_server = true;
    }
    memcpy(&out_info->client_mac, &frame->hdr.h_source, ETH_ALEN);
    out_info->client_ip = ip_get_saddr(&frame->ip);
    memcpy(&out_info->server_mac, &frame->hdr.h_dest, ETH_ALEN);
    out_info->server_ip = ip_get_daddr(&frame->ip);
  } else if ((udp->source == 67) && (udp->dest == 68)) {
    out_info->server_to_client = true;
    memcpy(&out_info->client_mac, &frame->hdr.h_dest, ETH_ALEN);
    out_info->client_ip = ip_get_daddr(&frame->ip);
    memcpy(&out_info->server_mac, &frame->hdr.h_source, ETH_ALEN);
    out_info->server_ip = ip_get_saddr(&frame->ip);
  } else {
    // Probably not BOOTP/DHCP at all
    if (very_verbose_log) {
      logf("dhcp_parse: ignoring packet from source port %u to dest port %u\n",
           (unsigned short)ntohs(udp->source),
           (unsigned short)ntohs(udp->dest));
    }
    return NULL;
  }

  if (ntohs(udp->len) < offsetof(struct dhcp_msg, options) + 4) {
    if (verbose_log) {
      logf("dhcp_parse: truncated datagram, %d\n", (int)ntohs(udp->len));
    }
    return NULL;
  }

  struct dhcp_msg *dhcp =
      (struct dhcp_msg *)&frame->ip.raw[header_len + sizeof(struct udphdr)];

  if ((dhcp->htype != ARPHRD_ETHER) || (dhcp->hlen != ETH_ALEN)) {
    if (verbose_log) {
      logf("dhcp_parse: invalid htype/hlen %d/%d\n", (int)dhcp->htype,
           (int)dhcp->hlen);
    }
    return NULL;
  }
  if (ntohl(*(uint32_t *)dhcp->options) != 0x63825363) {
    if (verbose_log) {
      logf("dhcp_parse: invalid options magic %08lX\n",
           (unsigned long)*(uint32_t *)dhcp->options);
    }
    return NULL;
  }

  memcpy(&out_info->chaddr, &dhcp->chaddr, ETH_ALEN);

  if (dhcp->op == 1) {
    out_info->bootp_request = true;
  } else if (dhcp->op == 2) {
    out_info->bootp_request = false;
  } else {
    if (verbose_log) {
      logf("dhcp_parse: invalid bootp op %d\n", (int)dhcp->op);
    }
    return NULL;
  }

  uint8_t *opts_end = &frame->ip.raw[ntohs(ip->tot_len)];
  if (!dhcp_parse_options(dhcp->options + 4, opts_end - (dhcp->options + 4),
                          out_info)) {
    return NULL;
  }
  if (out_info->options_in_file) {
    if (!dhcp_parse_options(dhcp->file, sizeof dhcp->file, out_info)) {
      return NULL;
    }
  }
  if (out_info->options_in_sname) {
    if (!dhcp_parse_options(dhcp->sname, sizeof dhcp->sname, out_info)) {
      return NULL;
    }
  }
  return dhcp;
}

bool dhcp_parse_options(uint8_t const *opts, size_t len,
                        struct dhcp_info *out_info) {
  size_t i = 0;
  bool proper_termination = false;
  while (i < len) {
    uint8_t optcode = opts[i++];
    if (optcode == 0x00) continue;
    if (optcode == 0xFF) {
      proper_termination = true;
      break;
    }
    if (i >= len) {
      if (verbose_log) {
        logf("dhcp_parse: option %d overruns buffer at %d/%d\n", (int)optcode,
             (int)(i - 1), (int)len);
      }
      return false;
    }
    uint8_t optlen = opts[i++];
    if (i + optlen > len) {
      if (verbose_log) {
        logf("dhcp_parse: option %d with length %d overruns buffer at %d/%d\n",
             (int)optcode, (int)optlen, (int)(i - 2), (int)len);
      }
      return false;
    }
    switch (optcode) {
      case 52: {
        if (optlen != 1) return false;
        if (opts[i] < 1 || opts[i] > 3) {
          if (verbose_log) {
            logf(
                "dhcp_parse: invalid option 52 (Option Overload), %d at "
                "%d/%d\n",
                (int)opts[i], (int)i, (int)len);
          }
          return false;
        }
        if ((opts[i] == 1) || (opts[i] == 3)) {
          out_info->options_in_file = true;
        }
        if ((opts[i] == 2) || (opts[i] == 3)) {
          out_info->options_in_sname = true;
        }
      } break;
      case 53: {
        if (optlen != 1) return false;
        if (opts[i] < 1 || opts[i] > 8) {
          if (verbose_log) {
            logf(
                "dhcp_parse: invalid option 53 (DHCP Message Type), %d at "
                "%d/%d\n",
                (int)opts[i], (int)i, (int)len);
          }
          return false;
        }
        if (opts[i] == 1) {
          out_info->is_discover = true;
        } else if (opts[i] == 5) {
          out_info->is_ack = true;
        }
      } break;
      default: {
        // ignore
      }
    }
    i += optlen;
  }
  if (!proper_termination && verbose_log) {
    logf("dhcp_parse: options not properly terminated, at %d\n", (int)len);
  }
  return true;
}

bool validate_eth_ip_frame(struct eth_packet const *frame) {
  uint16_t proto = ntohs(frame->hdr.h_proto);

  if (frame->len < sizeof(struct ethhdr)) {
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
