#include "etherslip.h"

#ifdef USE_IF_ETH

void eth_init(char const *eth_dev_name, bool force_eth_mac) {
  // TODO enumerate ethernet devices
  // if (strlen(tx_dev_name) == 0) {
  //   snprintf(tx_dev_name, sizeof tx_dev_name, "enp0s25");
  // }

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
  } else if ((size_t)recv_size < sizeof(struct ethhdr)) {
    // Runt ethernet frame? Not long enough for MAC??
    if (verbose_log) {
      logf("eth packet received, runt frame (%lu bytes)\n",
           (unsigned long)recv_size);
    }
  } else if ((memcmp(&eth_frame->hdr.h_dest, &eth_mac, ETH_ALEN) != 0) &&
             (memcmp(&eth_frame->hdr.h_dest, &broadcast_mac, ETH_ALEN) != 0)) {
    // Ignore packet, not for us
    // TODO multicast support? Not sure how this works
    if (very_verbose_log) {
      logf("eth packet received, for another host (%s)\n",
           ether_ntoa((struct ether_addr const *)&eth_frame->hdr.h_dest));
    }
  } else if (recv_size > MAX_PACKET_SIZE) {
    // Ignore packet, too big (extra jumbo frame? We can't handle it)
    logf("eth packet received, too big (trucated to %lu of %lu bytes)\n",
         (unsigned long)(MAX_PACKET_SIZE), (unsigned long)recv_size);
  } else if (!validate_eth_ip_frame(eth_frame, (size_t)recv_size)) {
    // Ignore packet, not valid IP
    if (verbose_log) {
      logf("eth packet received, not valid ip (%lu bytes):\n",
           (unsigned long)recv_size);
      hex_dump(stdlog, &eth_frame->eth_raw, recv_size);
    }
  } else {
    // A complete packet!
    if (very_verbose_log) {
      char srcaddr[20], destaddr[20];
      inet_ntop(AF_INET, &eth_frame->ip.hdr.saddr, srcaddr, sizeof srcaddr);
      inet_ntop(AF_INET, &eth_frame->ip.hdr.daddr, destaddr, sizeof destaddr);
      logf(
          "eth packet received, %lu bytes; hdr tot_len=%lu, proto=%02X, "
          "sa=%s, da=%s\n",
          (unsigned long)recv_size,
          (unsigned long)ntohs(eth_frame->ip.hdr.tot_len),
          (int)eth_frame->ip.hdr.protocol, srcaddr, destaddr);
    }
    eth_process_frame(eth_frame);
  }
  free_packet_buf(eth_frame);
}

void eth_process_frame(struct eth_packet *eth_frame) {
  ser_send(&eth_frame->ip);
}

bool eth_process_dhcp_response(struct eth_packet *eth_frame) {
  // TODO implement
  (void)eth_frame;
  return true;
}

void eth_send(struct ip_packet *ip_frame) {
  assert(validate_ip_frame(ip_frame, sizeof *ip_frame));

  if (very_verbose_log) {
    logf("ser_send packet:\n");
    hex_dump(stdlog, ip_frame, ntohs(ip_frame->hdr.tot_len));
  }

  // TODO implement
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

#endif
