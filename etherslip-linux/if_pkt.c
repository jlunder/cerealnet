#include "etherslip.h"

#ifdef USE_IF_PKT

void pkt_init(void) {
  pkt_send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (pkt_send_socket < 0) {
    perror("socket() failed for raw send socket");
    exit(1);
  }
  // int opt;
  // opt = 1;
  // if (setsockopt(pkt_send_socket, SOL_SOCKET, IP_HDRINCL, &opt, sizeof opt) <
  //     0) {
  //   perror("setsockopt(pkt_send_socket, .., IP_HDRINCL, ...) failed");
  //   exit(1);
  // }
  pkt_recv_socket = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
  if (pkt_recv_socket < 0) {
    perror("socket() failed for packet recv socket");
    exit(1);
  }
  // struct packet_mreq mreq;
  // memset(&mreq, 0, sizeof mreq);
  // mreq.mr_ifindex = -1;
  // mreq.mr_type = PACKET_MR_ALLMULTI;
  // if (setsockopt(pkt_recv_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
  // sizeof mreq) < 0) {
  //   perror("setsockopt");
  //   exit(1);
  // }
}

void pkt_read_available(void) {
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
  recv_size =
      recvfrom(pkt_recv_socket, &eth_frame->ip, sizeof eth_frame->ip.ip_raw,
               MSG_DONTWAIT, (struct sockaddr *)&packet_addr, &packet_addr_len);
  if (recv_size < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      // No message waiting after all
    } else {
      perror("recvfrom failed");
      exit(1);
    }
    free_packet_buf(eth_frame);
  } else {
    memcpy(&eth_frame->hdr.h_dest, &client_mac, sizeof(struct ether_addr));
    memcpy(&eth_frame->hdr.h_source, &broadcast_mac, sizeof(struct ether_addr));
    eth_frame->hdr.h_proto = ETH_P_IP;

    eth_frame->recv_size = sizeof(struct ethhdr) + recv_size;
    net_process_frame(eth_frame);
  }
}

void pkt_send(struct eth_packet *eth_frame) {
  assert(validate_ip_frame(&eth_frame->ip, sizeof eth_frame->ip));

  if (very_verbose_log) {
    logf("pkt_send packet:\n");
    hex_dump(stdlog, &eth_frame->ip, ntohs(eth_frame->ip.hdr.tot_len));
  }

  // TODO implement
}

#endif
