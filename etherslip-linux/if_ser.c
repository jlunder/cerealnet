#include "etherslip.h"

// Round up to align to 16 bytes
#define MAX_SLIP_EXPANSION(size) ((size * 2 + 2 + 0xF) & ~0xFLU)
#define SER_WRITE_QUEUE_SIZE MAX_SLIP_EXPANSION(MAX_PACKET_SIZE)

struct eth_packet *ser_read_accum = NULL;
bool ser_read_accum_esc = false;
bool ser_read_discarding = false;

// There are two write buffers exactly, because we want one to encode into while
// the other is sending. This shouldn't in theory help *much*, but it should
// allow us to cover small pipeline gaps where we don't start encoding the next
// packet until after the previous one finishes writing. This way there's at
// least one more packet ready to go immediately, and then we can encode the
// subsequent one while it's transmitting.

// In practice probably there's enough serial send buffer in the kernel to cover
// this situation on any Linux host, but if we target embedded it could matter.

uint8_t ser_write_buf[2][SER_WRITE_QUEUE_SIZE];

size_t ser_encode_index = 0;

size_t ser_encode_head = 0;
size_t ser_encode_tail = 0;

size_t ser_send_head = 0;
size_t ser_send_tail = 0;

int ser_fd;

void ser_decode(uint8_t *data, size_t size);

void ser_init(char const *ser_dev_name) {
  // TODO enumerate serial devices
  // if (strlen(rx_dev_name) == 0) {
  //   snprintf(rx_dev_name, sizeof rx_dev_name, "wlp3s0");
  // }
  if (strlen(ser_dev_name) > 0) {
    ser_fd = open(ser_dev_name, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (ser_fd < 0) {
      perror("open() failed for serial socket");
      exit(1);
    }

    // TODO switches for speed/parity/stop bits/flow control
    // TODO is there 7-bit SLIP? That must require a whole other mode...
    struct termios ser_saved_attrs;
    struct termios ser_attrs;
    if (tcgetattr(ser_fd, &ser_saved_attrs) != 0) {
      perror("ser_init failed to save line attributes (tcgetattr)");
    }
    cfmakeraw(&ser_attrs);
    if (cfsetspeed(&ser_attrs, B115200) != 0) {
      perror("ser_init failed to set desired speed (cfsetspeed)");
    }
    ser_attrs.c_cflag &= ~PARENB;
    ser_attrs.c_cflag &= ~PARODD;
    ser_attrs.c_cflag &= ~CSTOPB;
    ser_attrs.c_cflag &= ~CSIZE;
    ser_attrs.c_cflag |= CS8;
    ser_attrs.c_cflag &= ~CRTSCTS;
    // ser_attrs.c_cflag |= CRTSCTS;
    if (tcsetattr(ser_fd, TCSANOW, &ser_attrs) != 0) {
      perror("ser_init failed to set line attributes (tcsetattr)");
    }
  } else {
    ser_fd = -1;
  }
}

// TODO serial shutdown? atexit?

void ser_setup_pollfd(struct pollfd *pfd) {
  pfd->fd = ser_fd;
  pfd->events = POLLIN;
  if (ser_send_head != ser_send_tail) {
    pfd->events |= POLLOUT;
  }
  pfd->revents = 0;
}

void ser_read_available(void) {
  uint8_t read_buf[512];
  ssize_t res;

  do {
    res = read(ser_fd, read_buf, sizeof read_buf);
    if (res < 0) {
      if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
        res = 0;
      } else {
        perror("ser: read() failed for serial socket");
        exit(1);
      }
    }

    if ((size_t)res > sizeof read_buf) {
      logf("ser: read() returned bad size %lu > %lu", (unsigned long)res,
           (unsigned long)sizeof read_buf);
      exit(1);
    }

    ser_decode(read_buf, (size_t)res);
  } while (res == sizeof read_buf);
}

void ser_decode(uint8_t *data, size_t size) {
  size_t i = 0;

  // Discard the remainder of the packet if we're supposed to do that
  if (ser_read_discarding) {
    // Reset the buffer if we have already allocated one
    if (ser_read_accum != NULL) {
      ser_read_accum->x.len = 0;
    }
    // Consume input until end-of-packet
    while ((i < size) && (data[i] != SLIP_END)) ++i;
    ser_read_accum_esc = false;
    ser_read_discarding = false;
    // And continue on with normal processing!
  }

  // Prepare the packet buffer we'll be accumulating into, if we don't already
  // have one set up
  if (ser_read_accum == NULL) {
    ser_read_accum = alloc_packet_buf();
    if (ser_read_accum == NULL) {
      if (log_verbose) {
        logf("ser: packet alloc fail in ser_decode\n");
      }
      return;
    }
    memset(&ser_read_accum->hdr, 0, sizeof ser_read_accum->hdr);
    ser_read_accum->hdr.h_proto = htons(ETH_P_IP);
    ser_read_accum->x.len = 0;
  }

  // Cache in local vars
  size_t used = ser_read_accum->x.len;
  bool esc = ser_read_accum_esc;
  uint8_t *decode_buf = ser_read_accum->ip.raw;

  // Sit in a loop reading bytes until we put together a whole packet. Make sure
  // not to copy them into the packet if we run out of room.
  while (i < size) {
    if (used >= sizeof ser_read_accum->ip.raw) {
      goto overrun;
    }

    // If the last character was ESC, apply special processing to this one
    if (esc) {
      uint8_t c = data[i++];
      assert(used < sizeof ser_read_accum->ip.raw);
      switch (c) {
        case SLIP_ESC_END: {
          decode_buf[used++] = SLIP_END;
        } break;
        case SLIP_ESC_ESC: {
          decode_buf[used++] = SLIP_ESC;
        } break;
        // If "c" is not one of these two, then we have a protocol violation.
        // The best bet seems to be to leave the byte alone and just stuff it
        // into the packet.
        default: {
          decode_buf[used++] = c;
        } break;
      }
      esc = false;
      // Stop if we've emptied the input buffer
      if (i >= size) {
        break;
      }
    }

    // Consume as many non-special bytes as possible
    size_t j = i;
    while ((j < size) && (data[j] != SLIP_END) && (data[j] != SLIP_ESC)) {
      if (used + j - i >= sizeof ser_read_accum->ip.raw) {
        goto overrun;
      }
      ++j;
    }
    // Any found?
    if (j > i) {
      size_t amount = j - i;
      assert(used + amount <= sizeof ser_read_accum->ip.raw);
      // Copy the entire block of non-special bytes at once
      memcpy(decode_buf + used, data + i, amount);
      used += amount;
      i = j;
      // Stop if we've emptied the input buffer
      if (i >= size) {
        break;
      }
    }

    // Finally, if we've got a special (ESC/END) character, consume/process it
    assert(i < size);  // Previous consuming clauses should break if empty
    uint8_t c = data[i++];
    // Handle bytestuffing if necessary
    switch (c) {
      // If it's an END character then we're done with the packet
      case SLIP_END: {
        if (used == 0) {
          // Ignore silently, probably just a spacer put in by the client to
          // increase noise resistance
          if (log_very_verbose) {
            logf("ser: ignoring zero-length\n");
          }
          // In this case, we haven't actually started processing, so it's safe
          // to continue with state as-is
        } else {
          if (log_verbose && esc) {
            logf(
                "ser: SLIP decoding error, packet from client ends mid-escape");
          }
          ser_read_accum->x.len = sizeof(struct ethhdr) + used;
          if (log_client_inbound) {
            log_frame("ser: read complete frame,", "ser:  ", ser_read_accum);
          }
          client_process_frame(ser_read_accum);
          // Reset state
          ser_read_accum = NULL;
          ser_read_accum_esc = false;
          assert(!ser_read_discarding);
          // Recurse to process any further data
          if (i < size) {
            ser_decode(data + i, size - i);
          }
          return;
        }
        // Packet has either been discarded or processed, start a new one
        used = 0;
      } break;
      // If it's the same code as an ESC character, wait and get another
      // character and then figure out what to store in the packet based on
      // that.
      case SLIP_ESC: {
        esc = true;
      } break;
      // There shouldn't be anything but special characters if we got in here?
      default: {
        assert(!"Should have been handled as a non-special character");
      } break;
    }
  }

  assert(i == size);

  // Commit state
  ser_read_accum_esc = esc;
  ser_read_accum->x.len = used;
  return;

overrun:
  if (log_verbose) {
    logf("ser: SLIP decoding error, packet overran max size\n");
  }
  // Flag that we're supposed to discard the remainder
  ser_read_discarding = true;
  // Recurse to restart processing
  ser_decode(data + i, size - i);
}

bool ser_send(struct eth_packet *frame) {
  assert(frame != NULL);

  if (ser_encode_tail != 0) {
    // We have encoded data waiting to write already, no sense in trying to
    // queue more right now, just tell the higher layer we're full up
    return false;
  }

  assert(ip_validate_packet(frame, NULL));

  struct ip_packet *ip_frame = &frame->ip;

  if (log_client_outbound) {
    log_frame("ser: writing frame,", "ser:  ", frame);
  }

  size_t size = ntohs(ip_frame->hdr.tot_len);
  uint8_t *encode_buf = ser_write_buf[ser_encode_index];
  // For each byte in the packet, send the appropriate character sequence
  size_t i = 0;
  size_t j = 0;
  assert(j + 1 <= SER_WRITE_QUEUE_SIZE);
  // Send an initial END character to flush out any data that may have
  // accumulated in the receiver due to line noise
  encode_buf[j++] = SLIP_END;
  while (i < size) {
    uint8_t c = ip_frame->raw[i];
    switch (c) {
      // If it's the same code as an END character, we send a special two
      // character code so as not to make the receiver think we sent an END
      case SLIP_END: {
        assert(j + 2 <= SER_WRITE_QUEUE_SIZE);
        encode_buf[j++] = SLIP_ESC;
        encode_buf[j++] = SLIP_ESC_END;
        ++i;
      } break;

      // If it's the same code as an ESC character, we send a special two
      // character code that disambiguates from END escape
      case SLIP_ESC: {
        assert(j + 2 <= SER_WRITE_QUEUE_SIZE);
        encode_buf[j++] = SLIP_ESC;
        encode_buf[j++] = SLIP_ESC_ESC;
        ++i;
      } break;

      // Otherwise, we just send the character
      default: {
        size_t k = i + 1;
        // But also keep looking in case more regular characters can be sent all
        // at once
        while ((k < size) && (ip_frame->raw[k] != SLIP_END) &&
               (ip_frame->raw[k] != SLIP_ESC)) {
          ++k;
        }
        size_t amount = k - i;
        assert(j + amount <= SER_WRITE_QUEUE_SIZE);
        memcpy(encode_buf + j, ip_frame->raw + i, amount);
        i = k;
        j += amount;
      } break;
    }
  }
  assert(j + 1 <= SER_WRITE_QUEUE_SIZE);
  encode_buf[j++] = SLIP_END;

  ser_encode_tail = 0;
  ser_encode_head = j;

  free_packet_buf(frame);

  ser_try_write_all_queued();

  return true;
}

bool ser_has_work(void) {
  return (ser_encode_tail != ser_encode_head) ||
         (ser_send_tail != ser_send_head);
}

void ser_try_write_all_queued(void) {
  if (ser_send_tail == ser_send_head) {
    if (ser_encode_tail == ser_encode_head) {
      // Nothing to do, bail early
      return;
    }
    // Our send buffer is empty, but there's stuff in the encode buffer --
    // swap buffers and let's go!
    ser_send_head = ser_encode_head;
    ser_send_tail = ser_encode_tail;
    ser_encode_head = 0;
    ser_encode_tail = 0;
    ser_encode_index = !ser_encode_index;
  }

  if (ser_fd == -1) {
    // Woops, actually, we haven't been init'd properly
    ser_send_head = 0;
    ser_send_tail = 0;
    return;
  }

  // Write the buffer to the serial port
  // The buffer we want is the one we're NOT encoding into
  assert(ser_send_head > ser_send_tail);
  uint8_t *send_buf = ser_write_buf[!ser_encode_index];
  ssize_t amount = ser_send_head - ser_send_tail;
  ssize_t result = write(ser_fd, send_buf + ser_send_tail, (size_t)amount);

  if (result < 0) {
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
      // Try again, but later
      return;
    }
    perror("write to ser failed");
    ser_send_head = 0;
    ser_send_tail = 0;
  } else if (result == amount) {
    ser_send_head = 0;
    ser_send_tail = 0;
    // Try to send more right now
    ser_try_write_all_queued();
  } else {
    ser_send_tail += result;
  }
}
