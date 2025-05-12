#include "etherslip.h"

struct udp_pseudoip {
  struct in_addr saddr;
  struct in_addr daddr;
  uint8_t pad;
  uint8_t protocol;
  uint16_t udplen;
} __attribute__((packed));

bool ip_validate_frame(struct eth_packet const *frame) {
  uint16_t proto = ntohs(frame->hdr.h_proto);

  if (frame->x.len < sizeof(struct ethhdr)) {
    logf("ip: invalid IP frame: truncated ethernet header (runt)\n");
    return false;
  }
  if (proto < ETH_P_802_3_MIN) {
    logf(
        "ip: invalid IP frame: not ethernet II (proto %u maybe matches size "
        "%lu?)\n",
        (unsigned)proto, (unsigned long)frame->x.len);
    // size = proto;
    // proto = ETH_P_802_3;
    return false;
  }
  if (proto != ETH_P_IP) {
    logf("ip: invalid IP frame: wrong protocol (%u)\n", (unsigned)proto);
    return false;
  }
  return ip_validate_packet(frame);
}

bool ip_validate_packet(struct eth_packet const *frame) {
  size_t size = ip_len(frame);

  if (size < sizeof(struct iphdr)) {
    logf("ip: invalid IP packet: truncated header (runt)\n");
    return false;
  }
  // The order of these tests is important -- some of them depend on prior
  // tests passing to be safe, e.g. checking the header checksum after
  // verifying that the received packet isn't truncated
  if (frame->ip.hdr.version != 4) {
    // IPv6 is common enough we don't want to spam about it unbidden
    if ((frame->ip.hdr.version != 6) || log_very_verbose) {
      logf("ip: invalid IP packet: bad version (%d)\n",
           (int)frame->ip.hdr.version);
    }
    return false;
  }
  size_t header_size = frame->ip.hdr.ihl * 4;
  if (header_size < sizeof(struct iphdr)) {
    logf("ip: invalid IP packet: bad header size (%d)\n", (int)header_size);
    return false;
  }
  if (size < header_size) {
    logf("ip: invalid IP packet: truncated header\n");
    return false;
  }
  uint16_t checksum = ip_header_checksum(&frame->ip, header_size);
  if (checksum != 0) {
    logf("ip: invalid IP packet: bad header checksum\n");
    return false;
  }
  if (size < ntohs(frame->ip.hdr.tot_len)) {
    logf("ip: invalid IP packet: truncated packet (%d of %d)\n", (int)size,
         (int)ntohs(frame->ip.hdr.tot_len));
    return false;
  }

  return true;
}

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

struct udphdr *udp_parse_ip_packet(struct eth_packet *frame) {
  assert(ip_validate_packet(frame));

  size_t header_len = frame->ip.hdr.ihl * 4;
  if (header_len + sizeof(struct udphdr) > ntohs(frame->ip.hdr.tot_len)) {
    // Not well formed
    if (log_very_verbose) {
      logf("udp: runt datagram\n");
    }
    return NULL;
  }
  struct udphdr *udp = (struct udphdr *)&frame->ip.raw[header_len];
  size_t req_tot_len = header_len + ntohs(udp->len);
  if (req_tot_len > ntohs(frame->ip.hdr.tot_len)) {
    // Not well formed
    if (log_very_verbose) {
      logf("udp: length %d does not match IP length %d\n",
           (int)(header_len + ntohs(udp->len)),
           (int)ntohs(frame->ip.hdr.tot_len));
    }
    return NULL;
  }
  if (udp->check != 0) {
    uint16_t check = udp_checksum(&frame->ip, udp, ntohs(udp->len));
    if (check != 0xFFFF) {
      if (log_verbose) {
        logf("udp: checksum 0x%04X does not match computed 0x%04X\n",
             (unsigned)udp->check, (unsigned)check);
      }
      return NULL;
    }
  }

  return udp;
}

uint16_t udp_checksum(struct ip_packet const *ip, struct udphdr *udp,
                      size_t udp_size) {
  struct udp_pseudoip pseudo_ip;
  pseudo_ip.saddr = ip_get_saddr(ip);
  pseudo_ip.daddr = ip_get_daddr(ip);
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
    checksum += ntohs(((uint16_t const *)udp)[i]);
  }
  // For odd size, add in an implicitly padded last word
  if ((udp_size & 1) != 0) {
    checksum += (uint16_t)((uint8_t const *)udp)[udp_size - 1] << 8;
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
