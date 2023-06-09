#include "etherslip.h"

void ser_read_available(void) {
  // TODO implement
}

void ser_accumulate_bytes(uint8_t *data, size_t size) {
  // Cache in local vars
  size_t used = ser_read_accum_used;
  bool esc = ser_read_accum_esc;

  // Sit in a loop reading bytes until we put together a whole packet. Make sure
  // not to copy them into the packet if we run out of room.
  size_t i = 0;
  while (i < size) {
    // If the last character was ESC, apply special processing to this one
    if (esc) {
      uint8_t c = data[i++];
      assert(used < sizeof ser_read_accum.ip.ip_raw);
      switch (c) {
        case SLIP_ESC_END: {
          ser_read_accum.ip.ip_raw[used++] = SLIP_END;
        } break;
        case SLIP_ESC_ESC: {
          ser_read_accum.ip.ip_raw[used++] = SLIP_ESC;
        } break;
        // If "c" is not one of these two, then we have a protocol violation.
        // The best bet seems to be to leave the byte alone and just stuff it
        // into the packet.
        default: {
          ser_read_accum.ip.ip_raw[used++] = c;
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
      ++j;
    }
    // Any found?
    if (j > i) {
      size_t amount = j - i;
      assert(used + amount <= sizeof ser_read_accum.ip.ip_raw);
      // Copy the entire block of non-special bytes at once
      memcpy(ser_read_accum.ip.ip_raw + used, data + i, amount);
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
          if (very_verbose_log) {
            logf("ser packet received, zero-length\n");
          }
        } else if (!validate_ip_frame(&ser_read_accum.ip, used)) {
          // Ignore packet, not valid IP
          if (verbose_log) {
            logf("ser packet received, not valid ip (%lu bytes):\n",
                 (unsigned long)used);
            hex_dump(stdlog, ser_read_accum.ip.ip_raw, used);
          }
        } else {
          if (very_verbose_log) {
            char srcaddr[20], destaddr[20];
            inet_ntop(AF_INET, &ser_read_accum.ip.hdr.saddr, srcaddr,
                      sizeof srcaddr);
            inet_ntop(AF_INET, &ser_read_accum.ip.hdr.daddr, destaddr,
                      sizeof destaddr);
            logf(
                "ser packet received, %lu bytes; hdr tot_len=%lu, proto=%02X, "
                "sa=%s, da=%s\n",
                (unsigned long)used,
                (unsigned long)ntohs(ser_read_accum.ip.hdr.tot_len),
                (int)ser_read_accum.ip.hdr.protocol, srcaddr, destaddr);
          }
          ser_process(&ser_read_accum.ip);
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

  // Commit to statics
  ser_read_accum_used = used;
  ser_read_accum_esc = esc;
}

void ser_process(struct ip_packet *ip_frame) {
  // TODO implement
}

bool ser_process_dhcp_request(struct ip_packet *ip_frame) {
  // TODO implement
}

void ser_send(struct ip_packet const *ip_frame) {
  assert(ser_write_buf_head == 0);
  assert(validate_ip_frame(ip_frame, sizeof *ip_frame));

  if (very_verbose_log) {
    logf("ser_send packet:\n");
    hex_dump(stdlog, ip_frame, ntohs(ip_frame->hdr.tot_len));
  }

  size_t size = ntohs(ip_frame->hdr.tot_len);
  // For each byte in the packet, send the appropriate character sequence
  size_t i = 0;
  size_t j = 0;
  assert(j + 1 <= SER_BUF_SIZE);
  // Send an initial END character to flush out any data that may have
  // accumulated in the receiver due to line noise
  ser_write_buf[j++] = SLIP_END;
  while (i < size) {
    uint8_t c = ip_frame->ip_raw[i];
    switch (c) {
      // If it's the same code as an END character, we send a special two
      // character code so as not to make the receiver think we sent an END
      case SLIP_END: {
        assert(j + 2 <= SER_BUF_SIZE);
        ser_write_buf[j++] = SLIP_ESC;
        ser_write_buf[j++] = SLIP_ESC_END;
        ++i;
      } break;

      // If it's the same code as an ESC character, we send a special two
      // character code so as not to make the receiver think we sent an ESC
      case SLIP_ESC: {
        assert(j + 2 <= SER_BUF_SIZE);
        ser_write_buf[j++] = SLIP_ESC;
        ser_write_buf[j++] = SLIP_ESC_ESC;
        ++i;
      } break;

      // Otherwise, we just send the character
      default: {
        size_t k = i + 1;
        // But also keep looking in case more regular characters can be sent all
        // at once
        while ((k < size) && (ip_frame->ip_raw[k] != SLIP_END) &&
               (ip_frame->ip_raw[k] != SLIP_ESC)) {
          ++k;
        }
        size_t amount = k - i;
        assert(j + amount <= SER_BUF_SIZE);
        memcpy(ser_write_buf + j, ip_frame->ip_raw + i, amount);
        i = k;
        j += amount;
      } break;
    }
  }
  assert(j + 1 <= SER_BUF_SIZE);
  ser_write_buf[j++] = SLIP_END;

  ser_write_buf_tail = 0;
  ser_write_buf_head = j;

  // logf("SLIP encoded:\n");
  // hex_dump(stdlog, ser_write_buf, j);
  ser_try_write_pending();
}

bool ser_try_write_pending(void) {
  if (ser_write_buf_tail == ser_write_buf_head) {
    return true;
  }

  // Write the buffer to the serial port
  ssize_t amount = ser_write_buf_head - ser_write_buf_tail;
  ssize_t result =
      write(ser_fd, ser_write_buf + ser_write_buf_tail, (size_t)amount);

  if (result < 0) {
    perror("write to ser failed");
    ser_write_buf_head = 0;
    ser_write_buf_tail = 0;
    return true;
  } else if (result < amount) {
    ser_write_buf_tail += result;
    return false;
  } else {
    ser_write_buf_head = 0;
    ser_write_buf_tail = 0;
    return true;
  }
}
