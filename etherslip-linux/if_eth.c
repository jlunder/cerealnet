#include "etherslip.h"

#if USE_IF_ETH

int eth_ifindex = -1;
char eth_ifname[IF_NAMESIZE];
int eth_socket = -1;
struct eth_packet *eth_write_queue = NULL;

void eth_init(char const *if_name) {
  // Create a raw socket
  eth_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (eth_socket < 0) {
    perror("socket() failed for ethernet socket");
    exit(1);
  }

  struct ifreq ioc_req;
  if (*if_name == '\0') {
    if (verbose_log) {
      logf("eth: no interface specified, scanning\n");
    }

    for (int i = 1; i < 100; ++i) {
      memset(&ioc_req, 0, sizeof ioc_req);
      ioc_req.ifr_ifindex = i;
      if (ioctl(eth_socket, SIOCGIFNAME, &ioc_req) < 0) {
        goto autoconf_fail;
      }
      if (verbose_log) {
        logf("eth: found interface at index %d: %s\n", i, ioc_req.ifr_name);
      }
      if (ioctl(eth_socket, SIOCGIFFLAGS, &ioc_req) < 0) {
        if (very_verbose_log) {
          logf("eth: couldn't get flags for interface %s\n", ioc_req.ifr_name);
          continue;
        }
      }
      if (very_verbose_log) {
        logf("eth: interface %s flags =%s%s%s\n", ioc_req.ifr_name,
             ioc_req.ifr_flags & IFF_UP ? " UP" : " DOWN",
             ioc_req.ifr_flags & IFF_LOOPBACK ? " LOOPBACK" : "",
             ioc_req.ifr_flags & IFF_RUNNING ? " RUNNING" : "");
      }
      if ((eth_ifindex < 0) && (ioc_req.ifr_flags & IFF_UP) &&
          !(ioc_req.ifr_flags & IFF_LOOPBACK) &&
          (ioc_req.ifr_flags & IFF_RUNNING)) {
        eth_ifindex = i;
        snprintf(eth_ifname, IF_NAMESIZE, "%s", ioc_req.ifr_name);
        goto autoconf_success;
      }
    }

  autoconf_fail:
    logf("eth: no suitable interface found\n");
    exit(1);
  autoconf_success:
  } else {
    snprintf(eth_ifname, IF_NAMESIZE, "%s", if_name);
  }

  logf("eth: using interface %s\n", eth_ifname);

  memset(&ioc_req, 0, sizeof ioc_req);
  snprintf(ioc_req.ifr_name, IF_NAMESIZE, "%s", eth_ifname);
  if (ioctl(eth_socket, SIOCGIFHWADDR, &ioc_req) < 0) {
    perror("get socket hardware address failed");
    exit(1);
  }
  memcpy(&host_mac, ioc_req.ifr_hwaddr.sa_data, ETH_ALEN);
  logf("eth: host MAC address %s\n", ether_ntoa(&host_mac));

  struct sockaddr_ll ifaddr;
  memset(&ifaddr, 0, sizeof ifaddr);
  ifaddr.sll_family = AF_PACKET;
  ifaddr.sll_ifindex = eth_ifindex;
  bind(eth_socket, (struct sockaddr *)&ifaddr, sizeof ifaddr);

  // memset(&if_ioreq, 0, sizeof if_ioreq);
  // snprintf(if_ioreq.ifr_name, IFNAMSIZ, "%s", dev_name);
  // if (ioctl(eth_socket, SIOCGIFHWADDR, &if_ioreq) < 0) {
  //   perror("get socket hardware address failed");
  //   exit(1);
  // }
  // memcpy(hwaddr, if_ioreq.ifr_hwaddr.sa_data, ETH_ALEN);
}

void eth_setup_pollfd(struct pollfd *pfd) {
  pfd->fd = eth_socket;
  pfd->events = POLLIN;
  if (eth_write_queue != NULL) {
    pfd->events |= POLLOUT;
  }
  pfd->revents = 0;
}

void eth_read_available(void) {
  // Try reading the ethernet interface -- despite the name it's okay to stop
  // at reading/processing a single packet
  struct eth_packet *frame = alloc_packet_buf();
  if (frame == NULL) {
    logf("eth packet alloc failed!\n");
    return;
  }

  ssize_t recv_size;

  assert(sizeof frame->eth_raw == MAX_PACKET_SIZE);
  recv_size =
      recvfrom(eth_socket, frame, MAX_PACKET_SIZE, MSG_DONTWAIT, NULL, NULL);
  if (recv_size < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      // No message waiting after all
    } else {
      perror("recvfrom failed");
      exit(1);
    }
    free_packet_buf(frame);
  } else {
    frame->recv_size = (size_t)recv_size;
    net_process_frame(frame);
  }
}

bool eth_send(struct eth_packet *frame) {
  assert(frame != NULL);

  if (eth_write_queue != NULL) {
    return false;
  }

  assert(validate_eth_ip_frame(frame));

  if (!client_ready) {
    // We need a MAC address to send, but if we're not ready it's uninitialized
    if (verbose_log) {
      logf("eth: client sending while not ready, dropping packet\n");
    }
    free_packet_buf(frame);
    return true;
  }

  eth_write_queue = frame;
  eth_try_write_all_queued();
  return true;
}

bool eth_has_work(void) { return eth_write_queue != NULL; }

void eth_try_write_all_queued(void) {
  if (eth_write_queue == NULL) {
    return;
  }

  ssize_t res;
  struct sockaddr_ll dest_sa;
  memset(&dest_sa, 0, sizeof dest_sa);
  dest_sa.sll_ifindex = AF_PACKET;
  dest_sa.sll_halen = ETH_ALEN;
  dest_sa.sll_hatype = PACKET_OUTGOING;
  memcpy(&dest_sa.sll_addr, eth_write_queue->hdr.h_dest, ETH_ALEN);
  if (very_verbose_log && send_log) {
    logf(
        "eth write queued frame, %lu bytes, dest mac=%s; "
        "hdr tot_len=%lu, proto=%02X, sa=%s, ",
        (unsigned long)eth_write_queue->recv_size,
        ether_ntoa((struct ether_addr const *)&eth_write_queue->hdr.h_dest),
        (unsigned long)ntohs(eth_write_queue->ip.hdr.tot_len),
        (int)eth_write_queue->ip.hdr.protocol,
        inet_ntoa(ip_get_saddr(&eth_write_queue->ip)));
    logf("da=%s\n", inet_ntoa(ip_get_daddr(&eth_write_queue->ip)));
    hex_dump(stdlog, eth_write_queue->eth_raw, eth_write_queue->recv_size);
  }
  res = sendto(eth_socket, eth_write_queue, eth_write_queue->recv_size,
               MSG_DONTWAIT, (struct sockaddr *)&dest_sa, sizeof dest_sa);
  if (res < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      return;
    }
    perror("eth sendto() failed");
  }
  free_packet_buf(eth_write_queue);
  eth_write_queue = NULL;
}

#endif
