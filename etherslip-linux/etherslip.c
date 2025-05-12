#include "etherslip.h"

#define NET_FORWARD_QUEUE_SIZE 2

static_assert(IS_POW2(NET_FORWARD_QUEUE_SIZE));

struct net_forward_queue_entry {
  struct eth_packet *frame;
  time_ms_t submitted_ms;
};

bool log_verbose = false;
bool log_very_verbose = false;

bool log_alloc = false;
bool log_arp_cache = false;
bool log_arp_states = false;
bool log_arp_traffic = false;
bool log_arp_usage = false;
bool log_client_inbound = false;
bool log_client_outbound = false;
bool log_net_inbound = false;
bool log_net_outbound = false;
bool log_forwarding = false;
bool log_dhcp_processing = false;

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

struct ether_addr dhcp_last_chaddr = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

struct eth_packet packet_pool[PACKET_POOL_SIZE];
struct eth_packet *packet_pool_unallocated[PACKET_POOL_SIZE];
size_t packet_pool_unallocated_count = 0;
size_t next_tracking_id = 1;

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
                       "s:i:n:g:"
#if USE_IF_ETH
                       "Dpe:m:"
#elif USE_IF_PKT
#else
#error "Must specify an interface type"
#endif
                       "L:vh")) != -1) {
    switch (opt) {
      case 's': {
        snprintf(ser_dev_name, PATH_MAX, "%s", optarg);
      } break;

      case 'i': {
        // client IP
      } break;
      case 'n': {
        // client network/netmask
      } break;
      case 'g': {
        // gateway
      } break;

#if USE_IF_ETH
      case 'D': {
        break;
      }
      case 'p': {
        break;
      }
      case 'e': {
        snprintf(net_if_name, IF_NAMESIZE, "%s", optarg);
      } break;
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
#elif USE_IF_PKT
#else
#error "Must specify an interface type"
#endif

      case 'L': {
        for (char const *p = optarg; *p; ++p) {
          switch (*p) {
              // clang-format off
            case 'a': log_alloc = true; break;
            case 'c': log_arp_cache = true; break;
            case 's': log_arp_states = true; break;
            case 't': log_arp_traffic = true; break;
            case 'u': log_arp_usage = true; break;
            case 'i': log_client_inbound = true; break;
            case 'o': log_client_outbound = true; break;
            case 'I': log_net_inbound = true; break;
            case 'O': log_net_outbound = true; break;
            case 'f': log_forwarding = true; break;
            case 'd': log_dhcp_processing = true; break;
              // clang-format on
          }
        }
      } break;
      case 'v': {
        if (log_verbose) {
          logf("log: enabling very verbose logging\n");
          log_very_verbose = true;
        } else {
          log_verbose = true;
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

      if ((keepalive_ms - now_ms > 2000) && log_verbose) {
        keepalive_ms += 2000;
        logf("%lu: alive (%d)\n", (unsigned long)now_ms, poll_res);
      }
    }
  }
}

void client_process_frame(struct eth_packet *frame) {
  if (frame->x.len < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    if (log_client_inbound) {
      logf("client packet runt frame (%lu bytes)\n",
           (unsigned long)frame->x.len);
    }
  } else
    // ip_validate_packet not ip_validate_frame, because the ethernet frame
    // is forged for client (SLIP) packets anyway
    if (!ip_validate_packet(frame)) {
      // Ignore packet, not valid IP
      if (log_client_inbound) {
        logf("client: packet not valid (%lu bytes)\n",
             (unsigned long)ip_len(frame));
        hex_dump(stdlog, "client:   ", frame->ip.raw, ip_len(frame));
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
  assert(ip_validate_frame(frame));

  if ((memcmp(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN) == 0) &&
      !ip_is_broadcast(ip_get_daddr(&frame->ip))) {
    // TODO permit network-local broadcast
    if (log_forwarding) {
      logf(
          "client: sus packet with direct IP %s via broadcast MAC, not "
          "forwarding\n",
          inet_ntoa(ip_get_daddr(&frame->ip)));
    }
    return false;
  }

  // A complete packet and we're ready for it!
  if (frame->ip.hdr.protocol == IPPROTO_UDP) {
    struct udphdr *udp = udp_parse_ip_packet(frame);

    if (udp && client_ready &&
        (memcmp(&frame->hdr.h_dest, &client_mac, ETH_ALEN) == 0)) {
      // Snoop/masquerade DHCP
      struct dhcp_info info;
      struct dhcp_msg *dhcp = dhcp_parse_udp_packet(frame, &info);
      if (dhcp != NULL) {
        if (log_dhcp_processing) {
          logf("client: snooping net DHCP; ");
          dhcp_dump_info_line(&info);
        }

        // Does this chaddr match the client's? I.e. should we convert back
        if (memcmp(&dhcp->chaddr, &client_mac, ETH_ALEN) == 0) {
          if (info.is_ack && ip_is_this_host(client_ip)) {
            client_ip = info.yiaddr;
          }
          if (info.is_ack && ip_is_this_host(client_network)) {
            client_netmask = info.subnet_mask;
            client_network.s_addr = client_ip.s_addr & client_netmask.s_addr;
            client_gateway = info.router;
          }

          if (log_dhcp_processing) {
            logf("client: rewriting chaddr from %s ",
                 ether_ntoa(&dhcp->chaddr));
            logf("to %s\n", ether_ntoa(&dhcp_last_chaddr));
          }
          // Rewrite client MAC address in packet
          memcpy(&dhcp->chaddr, &dhcp_last_chaddr, ETH_ALEN);
          udp->check = htons(0);
          udp->check = udp_checksum(&frame->ip, ntohs(udp->len));
        }
      }
    }
  }

  // TODO rewrite IP addresses for masquerading if needed

  // Pass frame on to serial send
  ser_send(frame);
  return true;
}

void net_process_frame(struct eth_packet *frame) {
  if (frame->x.len < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    if (log_verbose) {
      logf("net: runt frame (%lu bytes), tid %lu\n",
           (unsigned long)frame->x.len, (unsigned long)frame->x.tracking_id);
    }
  } else if (arp_process_frame(frame)) {
    frame = NULL;
  } else if (ip_validate_frame(frame)) {
    // Valid IP frame...
    arp_snoop_ip_frame(frame);
#if USE_IF_ETH
    if ((!client_ready ||
         memcmp(&frame->hdr.h_dest, &client_mac, ETH_ALEN) != 0) &&
        (memcmp(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN) != 0)) {
      // TODO multicast support? Not sure how this works
      if (log_forwarding && log_very_verbose) {
        logf("net: packet for another host (%s), tid %lu\n",
             ether_ntoa((struct ether_addr const *)&frame->hdr.h_dest),
             (unsigned long)frame->x.tracking_id);
      }
    } else {
#endif
      if (client_ready) {
        if (log_forwarding) {
          logf("net: attempting to forward to client, tid %lu\n",
               (unsigned long)frame->x.tracking_id);
        }
        if (client_forward_net_frame(frame)) {
          frame = NULL;
        }
      }
#if USE_IF_ETH
    }
#endif
  } else {
    // Ignore packet: it's not valid IP
    if (log_forwarding && log_very_verbose) {
      if ((client_ready &&
           memcmp(&frame->hdr.h_dest, &client_mac, ETH_ALEN) == 0) ||
          (memcmp(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN) == 0)) {
        logf("net: packet not valid IP, tid %lu\n", (unsigned long)frame->x.len,
             (unsigned long)frame->x.tracking_id);
      }
    }
  }

  if (frame != NULL) {
    free_packet_buf(frame);
  }
}

bool net_forward_client_frame(struct eth_packet *frame) {
  assert(ip_validate_packet(frame));

  if (ip_is_this_host(client_ip) && ip_is_proper(ip_get_saddr(&frame->ip))) {
    if (log_forwarding && log_verbose) {
      logf("net: updating client IP from %s", inet_ntoa(client_ip));
      logf(" to %s (snooped outgoing)\n",
           inet_ntoa(*(struct in_addr *)&frame->ip.hdr.saddr));
    }
    client_ip = *(struct in_addr *)&frame->ip.hdr.saddr;
  }

  if (frame->ip.hdr.protocol == IPPROTO_UDP) {
    struct udphdr *udp = udp_parse_ip_packet(frame);

    if (udp != NULL) {
      // Snoop/masquerade DHCP
      struct dhcp_info info;
      struct dhcp_msg *dhcp = dhcp_parse_udp_packet(frame, &info);
      if (dhcp != NULL) {
        // Snarf the MAC address that the client thinks is its own
        memcpy(&dhcp_last_chaddr, &dhcp->chaddr, ETH_ALEN);

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

        if (log_dhcp_processing && !ip_equals(client_ip, dhcp->ciaddr)) {
          logf("net: client supplied suspicious ciaddr %s",
               inet_ntoa(dhcp->ciaddr));
          logf("in snooped DHCP, expected %s\n", inet_ntoa(client_ip));
        }

        // Rewrite client MAC address in packet
        memcpy(&dhcp->chaddr, &client_mac, ETH_ALEN);
        udp->check = htons(0);
        udp->check = udp_checksum(&frame->ip, ntohs(udp->len));

        if (log_dhcp_processing) {
          // Re-parse
          dhcp = dhcp_parse_udp_packet(frame, &info);
          logf("net: snooping client DHCP; ");
          dhcp_dump_info_line(&info);
        }
      }
    }
  }

  struct in_addr dest_ip = ip_get_daddr(&frame->ip);
  if (!ip_is_proper_or_broadcast(dest_ip)) {
    if (log_forwarding) {
      logf("net: client packet with improper destination %s, not forwarding\n",
           inet_ntoa(dest_ip));
    }
    return false;
  }

  // Fill out info we definitely have
  frame->hdr.h_proto = htons(ETH_P_IP);
  *(struct ether_addr *)&frame->hdr.h_source = client_mac;

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
    if (log_forwarding || log_verbose) {
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
  return eth_send(frame);
#elif USE_IF_PKT
  return pkt_send(frame);
#else
#error "Must specify an interface type"
#endif
}

void net_process_queued(void) {
  if (log_forwarding && log_very_verbose && (net_forward_queue_count > 0)) {
    logf("net: trying to send %lu queued packets\n",
         (unsigned long)net_forward_queue_count);
  }

  net_forward_queue_count = 0;

  for (size_t i = 0; i < NET_FORWARD_QUEUE_SIZE; ++i) {
    struct net_forward_queue_entry *entry =
        &net_forward_queue[(net_forward_queue_tail + i) &
                           (NET_FORWARD_QUEUE_SIZE - 1)];
    if (entry->frame == NULL) {
      continue;
    }

    if (time_since_ms(now_ms, entry->submitted_ms) > 5000UL) {
      if (log_forwarding || log_verbose) {
        logf("net: ageing out packet tid %lu, unable to send\n",
             (unsigned long)entry->frame->x.tracking_id);
      }
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

struct eth_packet *alloc_packet_buf(void) {
  if (packet_pool_unallocated_count > 0) {
    --packet_pool_unallocated_count;
    struct eth_packet *result =
        packet_pool_unallocated[packet_pool_unallocated_count];
    assert(result != NULL);
    assert(result->x.tracking_id == 0);
    packet_pool_unallocated[packet_pool_unallocated_count] = NULL;
    result->x.tracking_id = next_tracking_id++;

    if (log_alloc) {
      logf("alloc: alloc buf #%lu, tid %lu, %lu available\n",
           (unsigned long)(result - packet_pool),
           (unsigned long)result->x.tracking_id,
           (unsigned long)packet_pool_unallocated_count);
    }

    return result;
  } else {
    if (log_alloc) {
      logf("alloc: alloc requested but no buffers are available\n");
    }
    return NULL;
  }
}

void free_packet_buf(struct eth_packet *packet) {
  assert(packet != NULL);
  assert(packet_pool_unallocated_count < PACKET_POOL_SIZE);
  assert(packet->x.tracking_id != 0);

  if (log_alloc) {
    logf("alloc: free buf #%lu, tid %lu, %lu available\n",
         (unsigned long)(packet - packet_pool),
         (unsigned long)packet->x.tracking_id,
         (unsigned long)(packet_pool_unallocated_count + 1));
  }

  packet->x.tracking_id = 0;
  packet_pool_unallocated[packet_pool_unallocated_count] = packet;
  ++packet_pool_unallocated_count;
}

void log_frame(char const *msg, char const *prefix, struct eth_packet *frame) {
  logf("%s tid %lu, %lu bytes, src mac=%s, ", msg,
       (unsigned long)frame->x.tracking_id, (unsigned long)frame->x.len,
       ether_ntoa((struct ether_addr const *)&frame->hdr.h_dest));
  logf("dest mac=%s, eth proto=%04X; ",
       ether_ntoa((struct ether_addr const *)&frame->hdr.h_source),
       (unsigned)ntohs(frame->hdr.h_proto));
  logf("hdr tot_len=%lu, proto=%d, sa=%s, ",
       (unsigned long)ntohs(frame->ip.hdr.tot_len), (int)frame->ip.hdr.protocol,
       inet_ntoa(ip_get_saddr(&frame->ip)));
  logf("da=%s\n", inet_ntoa(ip_get_daddr(&frame->ip)));
  if (log_very_verbose) {
    hex_dump(stdlog, prefix, frame->raw, frame->x.len);
  }
}

void hex_dump(FILE *f, char const *prefix, void const *buf, size_t size) {
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
    fprintf(f, "%s%s", prefix, line);
  }
}
