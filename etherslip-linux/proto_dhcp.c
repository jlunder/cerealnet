#include "etherslip.h"

struct dhcp_msg *dhcp_parse_udp_packet(struct eth_packet *frame,
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

  out_info->ciaddr = dhcp->ciaddr;
  out_info->siaddr = dhcp->siaddr;
  out_info->yiaddr = dhcp->yiaddr;
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
      case 1: {  // Subnet mask
        if (optlen != sizeof(struct in_addr)) return false;
        memcpy(&out_info->subnet_mask, &opts[i], sizeof(struct in_addr));
      } break;
      case 3: {  // Gateway IPs
        if (optlen < sizeof(struct in_addr)) return false;
        if ((optlen % sizeof(struct in_addr)) != 0) return false;
        memcpy(&out_info->router, &opts[i], sizeof(struct in_addr));
      } break;
      case 28: {  // Broadcast address
        if (optlen != sizeof(struct in_addr)) return false;
        memcpy(&out_info->broadcast, &opts[i], sizeof(struct in_addr));
      } break;
      case 52: {  // Options overload (parse extra opts in file/sname fields)
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
      case 53: {  // Message type
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

void dhcp_dump_info_line(struct dhcp_info const *info) {
  logf("from %s@%s", inet_ntoa(info->client_ip), ether_ntoa(&info->client_mac));
  logf(" to %s@%s", inet_ntoa(info->server_ip), ether_ntoa(&info->server_mac));
  logf(", chaddr=%s", ether_ntoa(&info->chaddr));
  if (info->client_to_broadcast) {
    logf(" C->BC");
  }
  if (info->client_to_server) {
    logf(" C->S");
  }
  if (info->server_to_client) {
    logf(" S->C");
  }
  if (info->bootp_request) {
    logf(" BREQ");
  } else {
    logf(" BREP");
  }
  if (info->is_discover) {
    logf(" DISC");
  }
  if (info->is_ack) {
    logf(" ACK");
  }
  logf("\n");
}

bool ip_validate_frame(struct eth_packet const *frame) {
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
  return ip_validate_packet(&frame->ip, ip_len(frame));
}
