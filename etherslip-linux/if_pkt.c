#include "etherslip.h"

#if USE_IF_PKT

int pkt_send_socket = -1;
int pkt_recv_socket = -1;
struct eth_packet *pkt_write_queue = NULL;

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

void ser_setup_pollfd(struct pollfd *pfd) {
  pfd->fd = pkt_recv_socket;
  pfd->events = POLLIN;
  if (pkt_write_queue != NULL) {
    pfd->events |= POLLOUT;
  }
  pfd->revents = 0;
}

void pkt_read_available(void) {
  // Try reading the ethernet interface -- despite the name it's okay to stop
  // at reading/processing a single packet
  struct eth_packet *frame = alloc_packet_buf();
  if (frame == NULL) {
    logf("eth packet alloc failed!\n");
    return;
  }

  struct sockaddr_storage packet_addr;
  socklen_t packet_addr_len = sizeof packet_addr;
  ssize_t len;

  assert(sizeof frame->eth_raw == MAX_PACKET_SIZE);
  len =
      recvfrom(pkt_recv_socket, &frame->ip, sizeof frame->ip.ip_raw,
               MSG_DONTWAIT, (struct sockaddr *)&packet_addr, &packet_addr_len);
  if (len < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      // No message waiting after all
    } else {
      perror("recvfrom failed");
      exit(1);
    }
    free_packet_buf(frame);
  } else {
    memcpy(&frame->hdr.h_dest, &client_mac, sizeof(struct ether_addr));
    memcpy(&frame->hdr.h_source, &broadcast_mac, sizeof(struct ether_addr));
    frame->hdr.h_proto = htons(ETH_P_IP);

    frame->len = sizeof(struct ethhdr) + len;
    net_process_frame(frame);
  }
}

bool pkt_send(struct eth_packet *frame) {
  assert(frame != NULL);

  if (pkt_write_queue != NULL) {
    return false;
  }

  struct ip_packet *ip_frame = &frame->ip;
  assert(validate_ip_frame(ip_frame, ETH_IP_SIZE(frame)));

  if (very_verbose_log && send_log) {
    logf("pkt_send packet:\n");
    hex_dump(stdlog, &frame->ip, ntohs(frame->ip.hdr.tot_len));
  }

  pkt_write_queue = frame;
  pkt_try_write_all_queued();
}

bool pkt_has_work(void) { return pkt_write_queue != NULL; }

void pkt_try_write_all_queued(void) {
  if (pkt_write_queue == NULL) {
    return;
  }

  ssize_t res;
  struct sockaddr_in dest_sa;
  memset(&dest_sa, 0, sizeof dest_sa);
  dest_sa.sin_family = AF_INET;
  memcpy(&dest_sa.sin_addr, &pkt_write_queue->ip.hdr.daddr,
         sizeof dest_sa.sin_addr);
  dest_sa.sin_port = 0;
  if (very_verbose_log && send_log) {
    logf(
        "pkt write queued frame, %lu bytes, dest mac=%s; "
        "hdr tot_len=%lu, proto=%02X, sa=%s, ",
        (unsigned long)pkt_write_queue->len,
        ether_ntoa((struct ether_addr const *)&pkt_write_queue->hdr.h_dest),
        (unsigned long)ntohs(pkt_write_queue->ip.hdr.tot_len),
        (int)pkt_write_queue->ip.hdr.protocol,
        inet_ntoa(ip_get_saddr(&pkt_write_queue->ip)));
    logf("da=%s\n", inet_ntoa(ip_get_daddr(&pkt_write_queue->ip)));
  }
  res = sendto(pkt_send_socket, pkt_write_queue, pkt_write_queue->len,
               MSG_DONTWAIT, (struct sockaddr *)&dest_sa, sizeof dest_sa);
  if (res < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      return;
    }
    perror("pkt sendto() failed");
  }
  free_packet_buf(pkt_write_queue);
  pkt_write_queue = NULL;
}

#endif
