#include "etherslip.h"

#if defined(NDEBUG)
// 10 bits is 1024 entries, which should probably be plenty for like.. a few
// hundred hosts, which is far more than any 486 wants to talk to on their local
// subnet. 10 entries is probably a more realistic maximum! But memory is cheap.
#define ARP_CACHE_SIZE_BITS 10
#else
#define ARP_CACHE_SIZE_BITS 4
#endif

#define ARP_CACHE_SIZE (1UL << ARP_CACHE_SIZE_BITS)

#if defined(NDEBUG)
#define ARP_CACHE_ASSOC 8
#else
#define ARP_CACHE_ASSOC 2
#endif

#define ARP_CACHE_PRIME 939193UL

#define ARP_IMPORTANCE_MAX INT16_MAX

#define ARP_STATE_UNUSED 0
#define ARP_STATE_REQUESTED 1
#define ARP_STATE_COOLDOWN 2
#define ARP_STATE_CONTENDED 3
#define ARP_STATE_REFRESHING 4
#define ARP_STATE_VALID 7

// These ARP timeouts are designed with the ideas in mind that (a) the cost of
// making an individual ARP request is not high, like tens per second in the
// extreme is probably fine; (b) we will udpate the cache every time we receive
// an expected packet from a host, so if we're sending a lot of packets to the
// same host, we don't even need to induce this (small) cost; (c) it's hard to
// notice that the MAC address for a host has changed, because we don't get
// receipt acknowledgement at the link layer, so we're better off checking in
// frequently to find out if the MAC address has changed for a host.

// After an initial request, wait at least 1ms for an ARP response, then back
// off exponentially (2ms, then 4ms, ...) up to (1 << 10) = 1024ms when sending
// repeat requests for the same host. The max interval is also used for refresh
// requests -- since we already have a nominally valid MAC address, those are
// less urgent.
#define ARP_REQUEST_RETRY_INITIAL_MS (1UL)
#define ARP_REQUEST_RETRY_BACKOFF_MAX 10

// The first time we request an address, wait an extra 50ms after we see the
// first ARP response, to give a chance for multiple hosts to respond -- this is
// to avoid sending our (notionally private) packet to the wrong host if someone
// is trying to butt in on our conversation
#define ARP_COOLDOWN_MS (50UL)

// If we haven't seen confirmation that this MAC address is correct for more
// than 5s, send an ARP packet to confirm we have have the right address (but in
// this interval, we still send to the old address we have)
#define ARP_REFRESH_MS (5UL * 1000UL)

// If we observe contention for an address, hold on to the entry longer, 5
// minutes, so that the contention is more noticeable
#define ARP_KEEP_CONTENDED_MS (300UL * 1000UL)

// If we haven't seen confirmation that this MAC address is correct for more
// than 1 hour, forget it entirely and invalidate the entry
#define ARP_INVALIDATE_MS (60UL * 60UL * 1000UL)

#if defined(NDEBUG)
// Go through the whole table once every minute
#define ARP_IDLE_SCAN_PERIOD_MS (60UL * 1000UL)
#else
#define ARP_IDLE_SCAN_PERIOD_MS (10UL * 1000UL)
#endif

// Don't announce our address too often -- at most once every 1s, in general
#define ARP_ANNOUNCE_COOLDOWN_MS (1000UL)

typedef uint16_t arp_importance_t;
typedef uint8_t arp_state_t;

struct arp_cache_entry {
  struct in_addr ip_addr;
  struct ether_addr mac_addr;
  uint8_t pad_mac[2];
  arp_state_t state;
  uint8_t backoff;
  arp_importance_t importance;
  time_ms_t last_seen_ms;
  time_ms_t last_state_ms;
  uint8_t pad[8];
} __attribute__((packed));

static_assert(sizeof(struct arp_cache_entry) == 32);

// This is *almost* a hopscotch hash -- each item gets hashed into a
// neighborhood, which is a linear section of the otherwise flat cache. Adjacent
// neighborhoods mostly overlap, they're not entirely distinct. The neighborhood
// size is just the associativity, so if we have associativity 8, then the
// neighborhoods overlap by 8-1 = 7 elements, just like with hopscotch hashing.
// The only difference is I didn't bother implementing the actual hopscotch
// algorithm; instead there's an LFU eviction policy with exponential decay.
// Even that is probably massive overkill, if we're honest.

// The only reason to implement neighborhoods is I don't like buckets, like, I
// don't know that the neighborhoods have better or worse properties
// mathematically and our cache is likely to be very very sparsely populated in
// practice so it really doesn't matter. This just makes me happy.

// If we do ever have problems with cache pressure, and you don't want to just
// increase the cache size for whatever reason, implementing the hopscotch
// algorithm would be a relatively simple change. It should be run from
// arp_find_entry_to_evict first, and then idle scan could also proactively and
// incrementally check for full neighborhoods, and shuffle elements around to
// reduce pressure.

// At that point you might also want to think about adaptively culling older
// entries (or at least zero-importance ones) but oh man. It's already
// overengineered and unless you're transplanting the code into some like
// industrial grade router firmware or something I don't see why you would do
// any of that. (And why you would want to use this code is beyond me when such
// things probably need content-addressable memory or other crazy hardware
// acceleration anyway...)

struct arp_cache_entry arp_cache[ARP_CACHE_SIZE];

uint32_t arp_idle_check_counter = 0;
time_ms_t arp_idle_target_ms = 0;
bool arp_announce_cooling_down = false;
time_ms_t arp_last_announce_ms = 0;

static_assert(((uint64_t)ARP_CACHE_SIZE * (uint64_t)ARP_IDLE_SCAN_PERIOD_MS) <
              UINT32_MAX);
static_assert(IS_POW2(ARP_CACHE_SIZE));

static uint32_t arp_find_entry(uint32_t base, struct in_addr ip_addr);
static uint32_t arp_find_entry_to_evict(uint32_t base);

// Format and emit a frame with a request for some other IP address
void arp_send_request(struct ether_addr from_mac, struct in_addr from_ip,
                      struct in_addr requesting_ip);
void arp_send_response(struct ether_addr from_mac, struct in_addr from_ip,
                       struct ether_addr to_mac, struct in_addr to_ip);

static inline uint32_t arp_entry_base(struct in_addr ip_addr) {
  // Take the top bits -- they should be best-mixed by the prime
  return (((uint32_t)ip_addr.s_addr * ARP_CACHE_PRIME) >>
          (32 - ARP_CACHE_SIZE_BITS)) &
         (ARP_CACHE_SIZE - 1);
}

static inline struct in_addr arp_get_spa(struct ether_arp *arp) {
  return *(struct in_addr *)&arp->arp_spa;
}

static inline struct in_addr arp_get_tpa(struct ether_arp *arp) {
  return *(struct in_addr *)&arp->arp_tpa;
}

static void arp_age_entry(struct arp_cache_entry *entry);

bool arp_fetch_address(struct in_addr requesting_ip, struct in_addr ip_addr,
                       bool permissive, struct ether_addr *out_mac_addr) {
  // Shortcut for global or subnet broadcast
  if (ip_is_broadcast(ip_addr) || (ip_equals(ip_addr, client_broadcast))) {
    *out_mac_addr = broadcast_mac;
    return true;
  }

  assert(ip_is_proper(ip_addr));
  assert(out_mac_addr != NULL);

  // Is there already a valid or in-flight cache entry?
  uint32_t base = arp_entry_base(ip_addr);
  uint32_t best_bin = arp_find_entry(base, ip_addr);
  if (best_bin < ARP_CACHE_SIZE) {
    struct arp_cache_entry *entry = &arp_cache[best_bin];
    assert(ip_equals(entry->ip_addr, ip_addr));
    switch (entry->state) {
      case ARP_STATE_REQUESTED: {
        // There's an in-flight entry, but let's see if it's time to retry
        time_ms_t wait_ms = time_since_ms(now_ms, entry->last_state_ms);
        assert(entry->backoff <= ARP_REQUEST_RETRY_BACKOFF_MAX);
        time_ms_t backoff_ms = wait_ms << ((time_ms_t)entry->backoff);
        assert(backoff_ms >= ARP_REQUEST_RETRY_INITIAL_MS);
        if (wait_ms > backoff_ms) {
          arp_send_request(client_mac, ip_addr, requesting_ip);
          entry->last_state_ms = now_ms;
          if (entry->backoff < ARP_REQUEST_RETRY_BACKOFF_MAX) {
            ++entry->backoff;
          }
        }
        return false;
      }
      case ARP_STATE_COOLDOWN:
      case ARP_STATE_CONTENDED:
      case ARP_STATE_REFRESHING:
      case ARP_STATE_VALID: {
        if (!permissive && ((entry->state == ARP_STATE_COOLDOWN) ||
                            (entry->state == ARP_STATE_CONTENDED))) {
          return false;
        }
        if (entry->state == ARP_STATE_REFRESHING) {
          if (time_since_ms(now_ms, entry->last_state_ms) >
              (ARP_REQUEST_RETRY_INITIAL_MS
               << (time_ms_t)ARP_REQUEST_RETRY_BACKOFF_MAX)) {
            arp_send_request(client_mac, ip_addr, requesting_ip);
            entry->last_state_ms = now_ms;
          }
        }
        *out_mac_addr = entry->mac_addr;
        if (entry->importance < ARP_IMPORTANCE_MAX) {
          ++entry->importance;
        }
        return true;
      }
      default: {
        return false;
      }
    }
  }

  best_bin = arp_find_entry_to_evict(base);

  struct arp_cache_entry *entry = &arp_cache[best_bin];

  if (very_verbose_log && (entry->state != ARP_STATE_UNUSED)) {
    logf(
        "arp: neighborhood of %lu full, evicting entry %lu (%s, importance "
        "%lu) ",
        (unsigned long)base, (unsigned long)best_bin, inet_ntoa(entry->ip_addr),
        (unsigned long)entry->importance);
    logf("to hold request for %s\n", inet_ntoa(ip_addr));
  }

  entry->ip_addr = ip_addr;
  entry->mac_addr = broadcast_mac;
  entry->state = ARP_STATE_REQUESTED;
  entry->backoff = 0;
  entry->importance = 1;
  entry->last_seen_ms = now_ms;
  entry->last_state_ms = now_ms;

  arp_send_request(client_mac, ip_addr, requesting_ip);

  return false;
}

bool arp_process_frame(struct eth_packet *frame) {
  // Find any relevant entry and update it
  if (ntohs(frame->hdr.h_proto) != ETH_P_ARP) {
    // Not even trying to be ARP?
    return false;
  }

  // We take ownership of the packet from here, and are responsible for
  // deallocating it! Be careful about returning early.
  if ((frame->len >= sizeof frame->hdr + sizeof frame->arp) &&
      ((ntohs(frame->arp.arp_hrd) == 1) || (ntohs(frame->arp.arp_hrd) == 6)) &&
      (frame->arp.arp_hln == ETH_ALEN) &&
      (frame->arp.arp_pln == sizeof(struct in_addr)) &&
      (ntohs(frame->arp.arp_pro) == ETH_P_IP)) {
    // Packet is basically well-formed, but do some more checks
    if (memcmp(&frame->hdr.h_source, &broadcast_mac, ETH_ALEN) == 0) {
      if (verbose_log) {
        logf("arp: dropping bad packet; from broadcast address\n");
        if (very_verbose_log) {
          hex_dump(stdlog, frame->raw, frame->len);
        }
      }
      goto skip_processing;
    }
    if (memcmp(&frame->arp.arp_sha, &frame->hdr.h_source, ETH_ALEN) != 0) {
      if (verbose_log) {
        logf("arp: dropping bad packet; from %s, ",
             ether_ntoa((struct ether_addr *)&frame->hdr.h_dest));
        logf("but arp arp_sha is %s\n",
             ether_ntoa((struct ether_addr *)&frame->arp.arp_sha));
      }
      goto skip_processing;
    }
    bool is_request = (ntohs(frame->arp.arp_op) == ARPOP_REQUEST);
    bool to_broadcast =
        (memcmp(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN) == 0);
    if (!is_request && to_broadcast) {
      if (verbose_log) {
        logf(
            "arp: dropping bad packet; non-request from %s, to broadcast "
            "address",
            ether_ntoa((struct ether_addr *)&frame->hdr.h_source));
      }
      goto skip_processing;
    }
    if (is_request && !to_broadcast) {
      if (very_verbose_log) {
        logf("arp: dropping bad packet; request from %s, ",
             ether_ntoa((struct ether_addr *)&frame->hdr.h_source));
        logf("to non-broadcast %s\n",
             ether_ntoa((struct ether_addr *)&frame->hdr.h_dest));
      }
      goto skip_processing;
    }

    if (client_ready &&
        (memcmp(&frame->hdr.h_source, &client_mac, ETH_ALEN) == 0)) {
      if (verbose_log) {
        logf("arp: dropping bad packet; appears to be from self");
      }
      goto skip_processing;
    }

    if (client_ready && ip_equals(arp_get_spa(&frame->arp), client_ip)) {
      // Somebody else has our address?
      logf("arp: conflict! address %s also claimed by %s (we are %s)\n",
           inet_ntoa(client_ip),
           ether_ntoa((struct ether_addr *)&frame->hdr.h_source),
           ether_ntoa((struct ether_addr *)&client_mac));
      arp_send_announce(client_mac, client_ip);
      goto skip_processing;
    } else if (ip_is_proper(*(struct in_addr *)&frame->arp.arp_spa)) {
      arp_merge_entry(*(struct ether_addr *)&frame->hdr.h_source,
                      *(struct in_addr *)frame->arp.arp_spa);
    }

    if (is_request && ip_equals(arp_get_tpa(&frame->arp), client_ip) &&
        ip_is_proper(client_ip)) {
      // Proper request, make a reply!
      arp_send_response(client_mac, client_ip,
                        *(struct ether_addr *)&frame->arp.arp_sha,
                        *(struct in_addr *)&frame->arp.arp_spa);
    }
  }
skip_processing:
  free_packet_buf(frame);
  return true;
}

void arp_snoop_ip_frame(struct eth_packet const *frame) {
  // Find any relevant entry and update it
  // TODO implement
  (void)frame;
}

void arp_merge_entry(struct ether_addr merge_mac, struct in_addr merge_ip) {
  // You can't tell me to send packets to broadcast, sorry
  assert(memcmp(&merge_mac, &broadcast_mac, ETH_ALEN) != 0);
  assert(memcmp(&merge_mac, &zero_mac, ETH_ALEN) != 0);
  // This should be a specific external IP address we could plausibly send to
  assert(ip_is_proper(merge_ip));
  // And it should not be *our* IP address -- ideally that kind of conflict is
  // something we would notify the user about (but it should be logged
  // elsewhere)
  assert(!ip_equals(merge_ip, client_ip));

  // Is there already a valid or in-flight cache entry?
  uint32_t base = arp_entry_base(merge_ip);
  uint32_t best_bin = arp_find_entry(base, merge_ip);
  if (best_bin >= ARP_CACHE_SIZE) {
    if (very_verbose_log) {
      logf("arp: trying to place %s, looking for a free entry\n",
           inet_ntoa(merge_ip));
    }
    best_bin = arp_find_entry_to_evict(base);
  }
  if (best_bin >= ARP_CACHE_SIZE) {
    // No room in the cache, just forget it
    return;
  }

  struct arp_cache_entry *entry = &arp_cache[best_bin];
  if ((entry->state != ARP_STATE_UNUSED) &&
      !ip_equals(entry->ip_addr, merge_ip)) {
    // This is an unsolicited ARP: if we had asked for it, there should be a
    // matching entry in ARP_STATE_REQUESTED with nonzero importance. We should
    // be careful not to evict anything more important -- conflict markers or
    // things explicitly requested (i.e. with nonzero importance).
    if ((entry->importance > 0) || (entry->state == ARP_STATE_CONTENDED)) {
      return;
    }
    if (very_verbose_log && (entry->state != ARP_STATE_UNUSED)) {
      logf(
          "arp: neighborhood of %lu full, evicting entry %lu (%s, importance "
          "%lu) ",
          (unsigned long)base, (unsigned long)best_bin,
          inet_ntoa(entry->ip_addr), (unsigned long)entry->importance);
      logf("to hold unsolicited %s\n", inet_ntoa(merge_ip));
    }
    memset(entry, 0, sizeof *entry);
    assert(entry->state == ARP_STATE_UNUSED);
  }

  if (entry->state == ARP_STATE_UNUSED) {
    // First observation of an unsolicited ARP -- init and get out
    entry->ip_addr = merge_ip;
    entry->mac_addr = merge_mac;
    entry->state = ARP_STATE_COOLDOWN;
    assert(entry->backoff == 0);
    assert(entry->importance == 0);
    entry->last_seen_ms = now_ms;
    entry->last_state_ms = now_ms;
    return;
  }

  // At this point we should have a valid entry (which we sorta check now), and
  // it is not fresh (which we check in stages) and should have been aged
  // properly (which we don't really check)
  assert(entry->state != ARP_STATE_UNUSED);
  assert(ip_equals(entry->ip_addr, merge_ip));

  // Update the last-seen time
  entry->last_seen_ms = now_ms;

  if (entry->state == ARP_STATE_REQUESTED) {
    // First response we've seen for this entry, record it and go to cooldown
    assert(memcmp(&entry->mac_addr, &broadcast_mac, ETH_ALEN) == 0);
    entry->state = ARP_STATE_COOLDOWN;
    entry->mac_addr = merge_mac;
  } else if (memcmp(&merge_mac, &entry->mac_addr, ETH_ALEN) != 0) {
    // Conflicting advertisement! Go to contended if we're not already there and
    // (re)start the timeout
    entry->state = ARP_STATE_CONTENDED;
    if (very_verbose_log) {
      logf("arp: contention over %s; previously observed %s, ",
           inet_ntoa(entry->ip_addr), ether_ntoa(&entry->mac_addr));
      logf("now claimed by %s\n", ether_ntoa(&merge_mac));
    }
    entry->last_state_ms = now_ms;
  } else if (entry->state == ARP_STATE_REFRESHING) {
    assert(memcmp(&merge_mac, &entry->mac_addr, ETH_ALEN) == 0);
    entry->state = ARP_STATE_VALID;
  } else {
    assert(memcmp(&merge_mac, &entry->mac_addr, ETH_ALEN) == 0);
    assert((entry->state == ARP_STATE_COOLDOWN) ||
           (entry->state == ARP_STATE_CONTENDED) ||
           (entry->state == ARP_STATE_VALID));
    // Nothing to do except the last-seen update we already did!
  }
}

void arp_send_announce(struct ether_addr announce_mac,
                       struct in_addr announce_ip) {
  if (arp_announce_cooling_down &&
      (time_since_ms(now_ms, arp_last_announce_ms) <
       ARP_ANNOUNCE_COOLDOWN_MS)) {
    return;
  }

  arp_send_request(announce_mac, announce_ip, announce_ip);

  arp_announce_cooling_down = true;
  arp_last_announce_ms = now_ms;
}

void arp_send_request(struct ether_addr from_mac, struct in_addr from_ip,
                      struct in_addr requesting_ip) {
  if (!ip_is_proper(from_ip) ||
      (memcmp(&from_mac, &broadcast_mac, ETH_ALEN) == 0)) {
    return;
  }

  struct eth_packet *frame = alloc_packet_buf();
  if (frame == NULL) {
    // Alloc fail -- not fatal
    if (verbose_log) {
      logf("arp: packet alloc fail in arp_send_announce\n");
    }
    return;
  }

  // An announce is constructed as if we were asking ourselves for our own
  // address
  memcpy(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN);
  memcpy(&frame->hdr.h_source, &from_mac, ETH_ALEN);
  frame->hdr.h_proto = htons(ETH_P_ARP);
  frame->arp.arp_hrd = htons(ARPHRD_ETHER);
  frame->arp.arp_pro = htons(ETH_P_IP);
  frame->arp.arp_hln = sizeof(struct ether_addr);
  frame->arp.arp_pln = sizeof(struct in_addr);
  frame->arp.arp_op = htons(1);
  *(struct ether_addr *)&frame->arp.arp_sha = from_mac;
  *(struct in_addr *)&frame->arp.arp_spa = from_ip;
  memset(&frame->arp.arp_tha, 0, sizeof frame->arp.arp_tha);
  *(struct in_addr *)&frame->arp.arp_tpa = requesting_ip;

  frame->len = sizeof(frame->hdr) + sizeof(frame->arp);

  net_send_link_frame(frame);
}

void arp_send_response(struct ether_addr from_mac, struct in_addr from_ip,
                       struct ether_addr to_mac, struct in_addr to_ip) {
  assert(ip_is_proper(from_ip) && ip_is_proper(to_ip));
  if (!client_ready || !ip_is_proper(client_ip) ||
      (memcmp(&client_mac, &broadcast_mac, ETH_ALEN) == 0)) {
    // We aren't properly configured, let's not share
    return;
  }

  struct eth_packet *frame = alloc_packet_buf();
  if (frame == NULL) {
    // Alloc fail -- not fatal
    if (verbose_log) {
      logf("arp: packet alloc fail in arp_send_response\n");
    }
    return;
  }

  memcpy(&frame->hdr.h_dest, &to_mac, ETH_ALEN);
  memcpy(&frame->hdr.h_source, &from_mac, ETH_ALEN);
  frame->hdr.h_proto = htons(ETH_P_ARP);
  frame->arp.arp_hrd = htons(ARPHRD_ETHER);
  frame->arp.arp_pro = htons(ETH_P_IP);
  frame->arp.arp_hln = sizeof(struct ether_addr);
  frame->arp.arp_pln = sizeof(struct in_addr);
  frame->arp.arp_op = htons(1);
  *(struct ether_addr *)&frame->arp.arp_sha = from_mac;
  *(struct in_addr *)&frame->arp.arp_spa = from_ip;
  *(struct ether_addr *)&frame->arp.arp_tha = to_mac;
  *(struct in_addr *)&frame->arp.arp_tpa = to_ip;

  frame->len = sizeof(frame->hdr) + sizeof(frame->arp);

  net_send_link_frame(frame);
}

void arp_idle(void) {
  // Check and clear the cooldown timer so it doesn't do anything wonky if we
  // don't announce for a really really long time
  if (arp_announce_cooling_down &&
      (time_since_ms(now_ms, arp_last_announce_ms) >=
       ARP_ANNOUNCE_COOLDOWN_MS)) {
    arp_announce_cooling_down = false;
  }

  time_ms_t prev_cycle_ms =
      arp_idle_check_counter * ARP_IDLE_SCAN_PERIOD_MS / ARP_CACHE_SIZE;
  uint32_t check_count;
  assert(prev_cycle_ms < ARP_IDLE_SCAN_PERIOD_MS);
  if (is_time_past_ms(now_ms, arp_idle_target_ms + prev_cycle_ms +
                                  ARP_IDLE_SCAN_PERIOD_MS)) {
    // We are very far behind (or just experienced some kind of clock hiccup).
    // Reset the time reference and check the whole table.
    arp_idle_target_ms = now_ms - prev_cycle_ms + ARP_IDLE_SCAN_PERIOD_MS;
    check_count = ARP_CACHE_SIZE;
  } else {
    check_count = time_since_ms(now_ms, arp_idle_target_ms) * ARP_CACHE_SIZE /
                      ARP_IDLE_SCAN_PERIOD_MS -
                  arp_idle_check_counter;
    assert(check_count <= ARP_CACHE_SIZE);
    if (is_time_past_ms(now_ms, arp_idle_target_ms + ARP_IDLE_SCAN_PERIOD_MS)) {
      arp_idle_target_ms += ARP_IDLE_SCAN_PERIOD_MS;
    }
  }
  assert(arp_idle_check_counter < ARP_CACHE_SIZE);
  if (check_count == 0) {
    return;
  }
  if (very_verbose_log) {
    logf("arp: idle, checking %lu/%lu entries", (unsigned long)check_count,
         (unsigned long)ARP_CACHE_SIZE);
  }
  for (uint32_t j = 0; j < check_count; ++j) {
#if !defined(NDEBUG)
    if (very_verbose_log && (arp_idle_check_counter == 0)) {
      logf("\narp: ARP cache debug dump\n");
      logf("arp: || %15s || %16s || %9s || %2s || %6s || %10s || %10s ||\n",
           "IP address", "MAC address", "state", "bk", "import", "seen age",
           "state age");
      for (uint32_t i = 0; i < ARP_CACHE_SIZE; ++i) {
        struct arp_cache_entry *entry = &arp_cache[i];
        char const *state_str;
        char unk_state_buf[14];
        switch (entry->state) {
          case ARP_STATE_UNUSED:
            state_str = "UNUSED";
            break;
          case ARP_STATE_REQUESTED:
            state_str = "REQUESTED";
            break;
          case ARP_STATE_COOLDOWN:
            state_str = "COOLDOWN";
            break;
          case ARP_STATE_CONTENDED:
            state_str = "CONTENDED";
            break;
          case ARP_STATE_REFRESHING:
            state_str = "REFRESHING";
            break;
          case ARP_STATE_VALID:
            state_str = "VALID";
            break;
          default:
            snprintf(unk_state_buf, sizeof unk_state_buf, "<#%d>",
                     (int)entry->state);
            state_str = unk_state_buf;
            break;
        }
        logf("arp: | %16s | %17s | %10s | %3d | %7lu | %11lu | %11lu |\n",
             inet_ntoa(entry->ip_addr), ether_ntoa(&entry->mac_addr), state_str,
             (int)entry->backoff, (unsigned long)entry->importance,
             (unsigned long)time_since_ms(now_ms, entry->last_seen_ms),
             (unsigned long)time_since_ms(now_ms, entry->last_state_ms));
      }
      logf("arp: continue idle check");
    }
#endif

    if (very_verbose_log) {
      logf(".");
    }
    struct arp_cache_entry *entry = &arp_cache[arp_idle_check_counter];
    arp_age_entry(entry);
    arp_idle_check_counter =
        (arp_idle_check_counter + 1) & (ARP_CACHE_SIZE - 1);
    switch (entry->state) {
      case ARP_STATE_UNUSED: {
        // Entry not in use
      } break;
      case ARP_STATE_REQUESTED:
      case ARP_STATE_VALID:
      case ARP_STATE_CONTENDED: {
        if (entry->importance > 1) {
          // Reduce importance logarithmically, but not all the way to 0;
          // that's reserved for addresses that were snooped and never used at
          // all. Actually used entries should always be preferred over
          // speculatively recorded ones, regardless of age.
          if (very_verbose_log) {
            logf("(reduce %s; %u->%u)",
                 inet_ntoa(*(struct in_addr *)&entry->ip_addr),
                 (unsigned)entry->importance,
                 (unsigned)(entry->importance >> 1));
          }
          entry->importance >>= 1;
        }
      } break;
    }
  }
  if (very_verbose_log) {
    logf("\n");
  }
}

uint32_t arp_find_entry(uint32_t base, struct in_addr ip_addr) {
  assert(ip_is_proper(ip_addr));

  for (uint32_t i = 0; i < ARP_CACHE_ASSOC; ++i) {
    struct arp_cache_entry *entry =
        &arp_cache[(base + i) & (ARP_CACHE_SIZE - 1)];
    arp_age_entry(entry);

    if (ip_equals(entry->ip_addr, ip_addr) &&
        (entry->state != ARP_STATE_UNUSED)) {
      return entry - arp_cache;
    }
  }
  return UINT32_MAX;
}

uint32_t arp_find_entry_to_evict(uint32_t base) {
  uint32_t best_bin = UINT32_MAX;
  int best_state_class = INT_MAX;
  arp_importance_t best_importance = ARP_IMPORTANCE_MAX;
  time_ms_t best_age = 0;
  for (uint32_t i = 0; i < ARP_CACHE_ASSOC; ++i) {
    if (very_verbose_log && (i > 0)) {
      logf("arp: exploring neighborhood of %lu: %lu\n", (unsigned long)base,
           (unsigned long)i);
    }
    struct arp_cache_entry *entry =
        &arp_cache[(base + i) & (ARP_CACHE_SIZE - 1)];
    arp_age_entry(entry);
    int entry_state_class = 0;
    switch (entry->state) {
      default:
        assert(entry->state == ARP_STATE_UNUSED);
      case ARP_STATE_UNUSED:
        // Short-circuit: unused entries have zero cost so we should always
        // take the first available if there is one
        best_bin = entry - arp_cache;
        goto best_bin_early_out;
      case ARP_STATE_VALID:
      case ARP_STATE_REFRESHING:
        // If the entry is valid, at least we did send (or could have sent)
        // some packets to the address, so evicting this entry doesn't imply
        // we're impeding progress
        entry_state_class = 1;
        break;
      case ARP_STATE_REQUESTED:
      case ARP_STATE_COOLDOWN:
        // If the entry is requested or in cooldown, evicting it may cause
        // starvation, so we want to artificially raise the importance of
        // those entries
        entry_state_class = 2;
        break;
      case ARP_STATE_CONTENDED:
        // If the entry is contended, we actually want to hang on to it with
        // greater priority or we risk security failure.
        entry_state_class = 3;
        break;
    }

    if (best_bin < ARP_CACHE_SIZE) {
      // Only start comparing if we have a possibility to compare
      if (entry->importance == 0) {
        // This entry has never actually been fetched by another system. The
        // only thing more important is another such record that's newer.
        if ((best_importance == 0) &&
            (time_since_ms(now_ms, entry->last_seen_ms) >= best_age)) {
          continue;
        }
      } else if (entry_state_class > best_state_class) {
        // Ruled out -- this entry is a more important state class
        continue;
      } else if (entry_state_class == best_state_class) {
        // Equivalent state class
        if (entry->importance > best_importance) {
          // Ruled out -- this entry is more important
          continue;
        } else if (entry->importance == best_importance) {
          // Equivalent importance
          if (time_since_ms(now_ms, entry->last_seen_ms) >= best_age) {
            // Ruled out -- this entry is at least as old
            continue;
          }
          // Otherwise fall through
        }
      }
    }
    // If it's not ruled out, it's ruled in!
    best_bin = entry - arp_cache;
    best_importance = entry->importance;
    best_state_class = entry_state_class;
    best_age = time_since_ms(now_ms, entry->last_seen_ms);
  }
best_bin_early_out:
  assert(best_bin < UINT32_MAX);
  return best_bin;
}

static void arp_age_entry(struct arp_cache_entry *entry) {
  assert((entry->state == ARP_STATE_UNUSED) ||
         (entry->state == ARP_STATE_REQUESTED) ||
         (entry->state == ARP_STATE_COOLDOWN) ||
         (entry->state == ARP_STATE_CONTENDED) ||
         (entry->state == ARP_STATE_REFRESHING) ||
         (entry->state == ARP_STATE_VALID));

  if (entry->state == ARP_STATE_UNUSED) {
    // Do nothing
    return;
  }

  assert(ip_is_proper(entry->ip_addr));
  assert(memcmp(&entry->mac_addr, &broadcast_mac, ETH_ALEN) != 0);
  assert(memcmp(&entry->mac_addr, &zero_mac, ETH_ALEN) != 0);

  time_ms_t entry_age = time_since_ms(now_ms, entry->last_seen_ms);

  if (((entry->state == ARP_STATE_CONTENDED) &&
       (entry_age >= ARP_KEEP_CONTENDED_MS)) ||
      (entry_age >= ARP_INVALIDATE_MS)) {
    // Invalidate entry -- it's very very stale, or it's a contention record
    // that's past due
    if (very_verbose_log) {
      logf("(age-out %s%s)", inet_ntoa(*(struct in_addr *)&entry->ip_addr),
           entry->state == ARP_STATE_CONTENDED ? " CTD" : "");
    }
    memset(entry, 0, sizeof *entry);
    assert(entry->state == ARP_STATE_UNUSED);
    assert(ip_is_this_host(entry->ip_addr));
    return;
  }

  if ((entry->state == ARP_STATE_COOLDOWN) &&
      (time_since_ms(now_ms, entry->last_state_ms) >= ARP_COOLDOWN_MS)) {
    entry->state = ARP_STATE_VALID;
    // Fall through! A very stale "cooldown" should go direct to "refreshing",
    // via the following logic. This shouldn't be a common case, but suppose a
    // packet gets dropped from the send queue while it's still pending ARP
    // confirmation -- then the send code will stop reconfirming status here,
    // and it could be arbitrarily long (depending on the arp_idle) before
    // that entry gets looked at again.
  }

  if ((entry->state == ARP_STATE_VALID) && (entry_age >= ARP_REFRESH_MS)) {
    entry->state = ARP_STATE_REFRESHING;
  }
}
