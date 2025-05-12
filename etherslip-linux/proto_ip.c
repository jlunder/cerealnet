#include "etherslip.h"

struct udp_pseudoip {
  struct in_addr saddr;
  struct in_addr daddr;
  uint8_t pad;
  uint8_t protocol;
  uint16_t udplen;
} __attribute__((packed));

uint16_t udp_checksum(struct ip_packet const *ip_frame, size_t udp_size);

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

struct udphdr *udp_parse_ip_packet(struct ip_packet *ip, size_t len) {
  assert(ip_validate_packet(ip, len));

  size_t header_len = ip->hdr.ihl * 4;
  if (header_len + sizeof(struct udphdr) > ntohs(ip->hdr.tot_len)) {
    // Not well formed
    if (very_verbose_log) {
      logf("udp: runt datagram\n");
    }
    return NULL;
  }
  struct udphdr *udp = (struct udphdr *)&ip->raw[header_len];
  size_t req_tot_len = header_len + ntohs(udp->len);
  if (req_tot_len > ntohs(ip->hdr.tot_len)) {
    // Not well formed
    if (very_verbose_log) {
      logf("udp: length %d does not match IP length %d\n",
           (int)(header_len + ntohs(udp->len)), (int)ntohs(ip->hdr.tot_len));
    }
    return NULL;
  }
  if (udp->check != 0) {
    uint16_t check = udp_checksum(ip, ntohs(udp->len));
    if (check != 0xFFFF) {
      if (verbose_log) {
        logf("udp: checksum 0x%04X does not match computed 0x%04X\n",
             (unsigned)udp->check, (unsigned)check);
      }
      return NULL;
    }
  }

  return udp;
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
    checksum +=
        ntohs(((uint16_t const *)(ip_frame->raw + ip_frame->hdr.ihl * 4))[i]);
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
