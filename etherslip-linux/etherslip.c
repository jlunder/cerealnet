#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

// /sys/class/net/?/address
// /sys/class/net/?/carrier



void hex_dump(void const * buf, size_t size) {
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
    fputs(line, stdout);
  }
}


#define MAX_PACKET_BUF 8192
#define BUF_POOL_SIZE 6
#define SLIP_SEND_QUEUE_SIZE 2
#define ETH_SEND_QUEUE_SIZE 2

//#define SER_IDX 0
#define ETH_IDX 0
#define FDS_SIZE 1


uint8_t ser_send_queue[SLIP_SEND_QUEUE_SIZE][MAX_PACKET_BUF];
uint8_t eth_send_queue[ETH_SEND_QUEUE_SIZE][MAX_PACKET_BUF];
size_t ser_send_head = 0;
size_t ser_send_tail = 0;
size_t eth_send_head = 0;
size_t eth_send_tail = 0;

size_t ser_recv_so_far = 0;

struct pollfd poll_fds[FDS_SIZE];
struct timespec timeout = {1, 0};

int ser_socket;
int eth_socket;


size_t ip_header_padded_size(size_t raw_size) {
  return (raw_size + 3) & ~3;
}


size_t compute_ip_header_size(void const * frame) {
  struct iphdr const * ip_header = (struct iphdr const *)frame;
  size_t size = ip_header->tot_len;
  
  if (size < sizeof (struct iphdr)) {
    return 0;
  }
  
  size_t max_options_size = size - sizeof (struct iphdr);
  if (max_options_size > (64 - sizeof (struct iphdr))) {
    max_options_size = 64 - sizeof (struct iphdr);
  }
  
  uint8_t const * options_buf =
    (uint8_t const *)frame + sizeof (struct iphdr);
  size_t options_size = 0;
  while (options_buf[options_size] != 0) {
    size_t size = options_buf[options_size + 1];
    if (options_size + 1 + size + 1 > max_options_size) {
      // badly formed options
      return 0;
    }
  }
  ++options_size;
  return ip_header_padded_size(sizeof (struct iphdr) + options_size);
}


uint16_t ip_header_checksum(void const * frame, size_t header_size) {
  uint8_t const * const buf = (uint8_t const *)frame;
  uint32_t checksum = 0;
  
  for (size_t i = 0; i + 1 < header_size; i += 2) {
    checksum += ntohs(*(uint16_t const *)(buf + i));
  }

  return ~((checksum >> 16) + (checksum & 0xFFFF));
}


bool validate_ip_header(void const * frame) {
  size_t header_size = compute_ip_header_size(frame);
  if (header_size == 0) {
    return false;
  }
  if (ip_header_checksum(frame, header_size) != 0) {
    return false;
  }
  return true;
}


bool validate_ip_frame(void const * eth_frame, size_t eth_size) {
  uint8_t const * buf = (uint8_t const *)eth_frame;
  struct ethhdr const * eth_header = (struct ethhdr const *)eth_frame;
  
  printf("dest address: ");
  for (size_t i = 0; i < ETH_ALEN; ++i) {
    if (i > 0) printf(":");
    printf("%02X", (int)eth_header->h_dest[i]);
  }
  
  printf(", source address: ");
  for (size_t i = 0; i < ETH_ALEN; ++i) {
    if (i > 0) printf(":");
    printf("%02X", (int)eth_header->h_source[i]);
  }
  
  uint16_t proto = ntohs(eth_header->h_proto);
  size_t size = 0;
  
  if (proto < ETH_P_802_3_MIN) {
    size = 0;
    proto = ETH_P_802_3;
  } else if ((proto == ETH_P_IP)
      && (eth_size >= sizeof (struct ethhdr) + sizeof (struct iphdr))) {
    struct iphdr const * header =
      (struct iphdr const *)(buf + sizeof (struct ethhdr));
    size = ntohs(header->tot_len);
    if ((size > eth_size - sizeof (struct ethhdr))
        || !validate_ip_header(header)) {
      size = 0;
    }
  } else {
    // nothing
  }
  printf(", proto: %lX, size: %ld\n", (long)proto, (long)size);
  
  return size > 0;
}


void * get_ip_frame(void * eth_frame) {
  uint8_t * buf = (uint8_t *)eth_frame;
  return buf + sizeof (struct ethhdr);
}


size_t get_ip_frame_size(void * eth_frame) {
  uint8_t * buf = (uint8_t *)get_ip_frame(eth_frame);
  struct iphdr const * header = (struct iphdr const *)buf;
  return ntohs(header->tot_len);
}


uint8_t * get_ip_payload(void * eth_frame, size_t * out_payload_size) {
  uint8_t * buf = (uint8_t *)get_ip_frame(eth_frame);
  size_t header_size = compute_ip_header_size(buf);
  if (out_payload_size != NULL) {
    *out_payload_size = ((struct iphdr const *)buf)->tot_len - header_size;
  }
  return buf + header_size;
}


void read_ser(void) {
}


void read_eth(void) {
  // Try reading the ethernet interface
  uint8_t * packet_buf = ser_send_queue[ser_send_tail];
  struct sockaddr_storage packet_addr;
  socklen_t packet_addr_len = sizeof packet_addr;
  ssize_t recv_size;
  
  recv_size = recvfrom(eth_socket, packet_buf, MAX_PACKET_BUF,
    MSG_DONTWAIT, (struct sockaddr *)&packet_addr, &packet_addr_len);
  if (recv_size < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      // No message waiting after all
    } else {
      perror("recvfrom failed");
      exit(1);
    }
  } else if ((recv_size > MAX_PACKET_BUF)
      || (packet_addr_len > sizeof packet_addr)) {
    // Ignore packet,it too big
    fprintf(stderr, "packet too big: %lu/%lu\n", (unsigned long)recv_size,
      (unsigned long)(sizeof packet_addr));//packet_addr_len);
  } else if(validate_ip_frame(packet_buf, (size_t)recv_size)) {
    // A complete packet!
    void * ip_frame = get_ip_frame(packet_buf);
    if (ip_frame == NULL) {
      printf("packet badly formed (%lu bytes):\n", (unsigned long)recv_size);
      hex_dump(packet_buf, recv_size > 64 ? 64 : (size_t)recv_size);
      if (recv_size > 64) {
        printf("  ...\n");
      }
    } else {
      size_t ip_frame_size = get_ip_frame_size(ip_frame);
      hex_dump(ip_frame, ip_frame_size);
    }
  }
}


int main(int argc, char * argv[]) {
  //Create a raw socket
  eth_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  
  if (eth_socket < 0) {
    perror("socket failed for ethernet socket");
    exit(1);
  }
  
  for ( ;; ) {
    /*
    poll_fds[SER_IDX].fd = eth_socket;
    poll_fds[SER_IDX].events = POLLIN;
    poll_fds[SER_IDX].revents = 0;
    */
    
    poll_fds[ETH_IDX].fd = eth_socket;
    poll_fds[ETH_IDX].events = POLLIN;
    poll_fds[ETH_IDX].revents = 0;
    
    printf("Waiting for packet\n");
    
    int poll_res = poll(poll_fds, 1, 1000);
    
    if (poll_res < 0) {
      perror("poll failed");
      exit(1);
    } else if (poll_res == 0) {
      // Nothing ready yet, check again
      continue;
    }
    
    // Data available somewhere!
    /*
    if ((poll_fds[SER_IDX].revents & ~POLLIN) != 0) {
      int re = poll_fds[SER_IDX].revents;
      fprintf(stderr, "While polling ethernet interface: %d ( %s%s%s)", re,
        (re & POLLERR) != 0 ? "ERR " : "",(re & POLLHUP) != 0 ? "HUP " : "",
        (re & POLLNVAL) != 0 ? "INVAL " : "");
    }
    */

    if ((poll_fds[ETH_IDX].revents & ~POLLIN) != 0) {
      int re = poll_fds[ETH_IDX].revents;
      fprintf(stderr, "While polling serial interface: %d ( %s%s%s)", re,
        (re & POLLERR) != 0 ? "ERR " : "",(re & POLLHUP) != 0 ? "HUP " : "",
        (re & POLLNVAL) != 0 ? "INVAL " : "");
    }
    
    /*
    if ((poll_fds[SER_IDX].revents & POLLIN) != 0) {
      read_ser();
    }
    */
    if ((poll_fds[ETH_IDX].revents & POLLIN) != 0) {
      read_eth();
    }
  }
  
  return 0;
}

