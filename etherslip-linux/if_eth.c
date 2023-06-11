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
    eth_get_hwaddr(eth_socket, eth_dev_name, &client_mac);
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
    free_packet_buf(eth_frame);
  } else {
    eth_frame->recv_size = (size_t)recv_size;
    net_process_frame(eth_frame);
  }
}

void eth_send(struct eth_packet *eth_frame) {
  assert(validate_eth_ip_frame(eth_frame));

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
