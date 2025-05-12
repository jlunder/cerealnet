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
    perror("eth: socket() failed for ethernet socket");
    exit(1);
  }

  struct ifreq ioc_req;
  if (*if_name == '\0') {
    if (log_verbose) {
      logf("eth: no interface specified, scanning\n");
    }

    for (int i = 1; i < 100; ++i) {
      memset(&ioc_req, 0, sizeof ioc_req);
      ioc_req.ifr_ifindex = i;
      if (ioctl(eth_socket, SIOCGIFNAME, &ioc_req) < 0) {
        goto autoconf_fail;
      }
      if (log_verbose) {
        logf("eth: found interface at index %d: %s\n", i, ioc_req.ifr_name);
      }
      if (ioctl(eth_socket, SIOCGIFFLAGS, &ioc_req) < 0) {
        if (log_very_verbose) {
          logf("eth: couldn't get flags for interface %s\n", ioc_req.ifr_name);
          continue;
        }
      }
      if (log_very_verbose) {
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
    memset(&ioc_req, 0, sizeof ioc_req);
    snprintf(ioc_req.ifr_name, IF_NAMESIZE, "%s", if_name);
    if (ioctl(eth_socket, SIOCGIFINDEX, &ioc_req) < 0) {
      perror("eth: get interface index failed");
      exit(1);
    }
    if (ioc_req.ifr_ifindex < 1) {
      logf("eth: ioctl(.., SIOCGIFINDEX, ..) returned implausible index %d\n",
           ioc_req.ifr_ifindex);
      exit(1);
    }
    eth_ifindex = ioc_req.ifr_ifindex;
  }

  assert(eth_ifindex > 0);

  logf("eth: using interface %s\n", eth_ifname);

  memset(&ioc_req, 0, sizeof ioc_req);
  snprintf(ioc_req.ifr_name, IF_NAMESIZE, "%s", eth_ifname);
  if (ioctl(eth_socket, SIOCGIFHWADDR, &ioc_req) < 0) {
    perror("eth: get interface hardware address failed");
    exit(1);
  }
  memcpy(&host_mac, ioc_req.ifr_hwaddr.sa_data, ETH_ALEN);
  logf("eth: host MAC address %s\n", ether_ntoa(&host_mac));

  struct sockaddr_ll ifaddr;
  memset(&ifaddr, 0, sizeof ifaddr);
  ifaddr.sll_family = AF_PACKET;
  ifaddr.sll_ifindex = eth_ifindex;
  if (bind(eth_socket, (struct sockaddr *)&ifaddr, sizeof ifaddr) < 0) {
    perror("eth: bind() to interface failed");
    exit(1);
  }
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
    if (log_verbose) {
      logf("eth: packet alloc fail in eth_read_available\n");
    }
    return;
  }

  ssize_t recv_size;

  assert(sizeof frame->raw == MAX_PACKET_SIZE);
  recv_size =
      recvfrom(eth_socket, frame, MAX_PACKET_SIZE, MSG_DONTWAIT, NULL, NULL);
  if (recv_size < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      // No message waiting after all
      free_packet_buf(frame);
      return;
    } else {
      perror("eth: recvfrom() failed");
      exit(1);
    }
  } else {
    if(recv_size > MAX_PACKET_SIZE) {
      logf("eth: recvfrom() returned unbelievable size %lu\n", (unsigned long)recv_size);
      exit(1);
    }
    frame->x.len = (size_t)recv_size;
    if (log_net_inbound) {
      log_frame("eth: read frame,", "eth:   ", frame);
    }
    net_process_frame(frame);
  }
}

bool eth_send(struct eth_packet *frame) {
  assert(frame != NULL);

  if (eth_write_queue != NULL) {
    return false;
  }

  if (!client_ready) {
    // We need a MAC address to send, but if we're not ready it's uninitialized
    if (log_net_outbound || log_verbose) {
      logf("eth: client trying to send while not ready, dropping packet\n");
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
  dest_sa.sll_ifindex = eth_ifindex;
  if (log_net_outbound) {
    logf("eth: writing queued frame, tid %lu, %lu bytes, ");
  }
  res = sendto(eth_socket, eth_write_queue, eth_write_queue->x.len,
               MSG_DONTWAIT, (struct sockaddr *)&dest_sa, sizeof dest_sa);
  if (res < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      if (log_net_outbound) {
        logf("send would block (waiting to retry)\n");
      }
      return;
    }
    perror("sendto() failed");
  } else {
    if (log_net_outbound) {
      logf("sent\n");
    }
  }
  free_packet_buf(eth_write_queue);
  eth_write_queue = NULL;
}

#endif
