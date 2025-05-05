#include "etherslip.h"

// 10 bits is 1024 entries, which should probably be plenty for like.. a few
// hundred hosts, which is far more than any 486 wants to talk to on their local
// subnet. 10 entries is probably a more realistic maximum! But memory is cheap.
#define ARP_CACHE_SIZE_BITS 10
#define ARP_CACHE_SIZE (1UL << ARP_CACHE_SIZE_BITS)
#define ARP_CACHE_ASSOC 8
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
// off exponentially (2ms, then 4ms, ...) up to 128ms when sending repeat
// requests for the same host. The max interval of 128ms is also used for
// refresh requests -- since we already have a nominally valid MAC address,
// those are less urgent.
#define ARP_REQUEST_RETRY_INITIAL_MS (1UL)
#define ARP_REQUEST_RETRY_MAX_MS (128UL)

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

// Go through the whole table once every minute
#define ARP_IDLE_SCAN_PERIOD_MS (60UL * 1000UL)

typedef uint16_t arp_importance_t;
typedef uint8_t arp_state_t;

struct arp_cache_entry {
  struct in_addr ip_addr;
  struct ether_addr mac_addr;
  uint8_t pad_mac[2];
  arp_state_t state;
  uint8_t pad[1];
  arp_importance_t importance;
  time_ms_t last_seen_ms;
  time_ms_t last_request_ms;
  time_ms_t last_backoff_ms;
  struct in_addr last_requesting_ip;
} __attribute__((packed));

static_assert(sizeof(struct arp_cache_entry) == 32);

struct arp_cache_entry arp_cache[ARP_CACHE_SIZE];
uint32_t arp_idle_check_counter = 0;
time_ms_t arp_idle_cycle_start_ms = 0;

static_assert(((uint64_t)ARP_CACHE_SIZE * (uint64_t)ARP_IDLE_SCAN_PERIOD_MS) <
              UINT32_MAX);
static_assert(((ARP_CACHE_SIZE - 1) | ((ARP_CACHE_SIZE - 1) >> 1)) ==
              (ARP_CACHE_SIZE - 1));

static uint32_t arp_find_entry(uint32_t base, struct in_addr ip_addr);
static uint32_t arp_find_entry_to_evict(uint32_t base);

// Format and emit a frame with a request for some other IP address
static void arp_send_request(struct in_addr requesting_ip,
                             struct in_addr target_ip);

static inline uint32_t arp_entry_base(struct in_addr ip_addr) {
  // Take the top bits -- they should be best-mixed by the prime
  return (((uint32_t)ip_addr.s_addr * ARP_CACHE_PRIME) >>
          (32 - ARP_CACHE_SIZE_BITS)) &
         (ARP_CACHE_SIZE - 1);
}

static void arp_age_entry(struct arp_cache_entry *entry);

bool arp_fetch_address(struct in_addr requesting_ip, struct in_addr ip_addr,
                       bool permissive, struct ether_addr *out_mac_addr) {
  assert(is_proper_ip_address(ip_addr));
  assert(out_mac_addr != NULL);

  // Is there already a valid or in-flight cache entry?
  uint32_t base = arp_entry_base(ip_addr);
  uint32_t best_bin = arp_find_entry(base, ip_addr);
  if (best_bin < ARP_CACHE_SIZE) {
    struct arp_cache_entry *entry = &arp_cache[best_bin];
    assert(entry->ip_addr.s_addr == ip_addr.s_addr);
    switch (entry->state) {
      case ARP_STATE_REQUESTED: {
        // There's an in-flight entry, but let's see if it's time to retry
        time_ms_t wait_ms = time_since_ms(now_ms, entry->last_request_ms);
        time_ms_t backoff_ms = entry->last_backoff_ms;
        assert(backoff_ms <= ARP_REQUEST_RETRY_MAX_MS);
        assert(backoff_ms >= ARP_REQUEST_RETRY_INITIAL_MS);
        if (wait_ms > backoff_ms) {
          backoff_ms *= 2;
          if (backoff_ms > ARP_REQUEST_RETRY_MAX_MS) {
            backoff_ms = ARP_REQUEST_RETRY_MAX_MS;
          }
          entry->last_backoff_ms = backoff_ms;
          entry->last_request_ms = now_ms;
          entry->last_requesting_ip = requesting_ip;
          arp_send_request(requesting_ip, ip_addr);
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
          if (time_since_ms(now_ms, entry->last_request_ms) >
              ARP_REQUEST_RETRY_MAX_MS) {
            entry->last_backoff_ms = ARP_REQUEST_RETRY_MAX_MS;
            entry->last_request_ms = now_ms;
            entry->last_requesting_ip = requesting_ip;
            arp_send_request(requesting_ip, ip_addr);
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
  entry->ip_addr = ip_addr;
  entry->mac_addr = broadcast_mac;
  entry->state = ARP_STATE_REQUESTED;
  entry->importance = 1;
  entry->last_backoff_ms = ARP_REQUEST_RETRY_INITIAL_MS;
  entry->last_seen_ms = now_ms;
  entry->last_request_ms = now_ms;
  entry->last_requesting_ip = requesting_ip;

  arp_send_request(requesting_ip, ip_addr);

  return false;
}

bool arp_process_frame(struct eth_packet *frame) {
  // Find any relevant entry and update it
  if (ntohs(frame->hdr.h_proto) != ETH_P_ARP) {
    // Not even trying to be ARP
    return false;
  }

  // TODO finish implementation

  // We take ownership of the packet from here, and are responsible for
  // deallocating it! Be careful about returning early.
  if ((frame->recv_size >= sizeof frame->arp) &&
      ((ntohs(frame->arp.hrd) == 1) || (ntohs(frame->arp.hrd) == 6)) &&
      (frame->arp.hln == ETH_ALEN) && (frame->arp.pln == IP_CHECKSUM)) {
    switch (ntohs(frame->arp.op)) {
      case ARPOP_REQUEST: {
        ///if(frame->hdr.)
      } break;
      case ARPOP_REPLY: {
      } break;
      default:  // Do nothing
        break;
    }
  }

  free_packet_buf(frame);
  return true;
}

void arp_snoop_ip_frame(struct eth_packet const *frame) {
  // Find any relevant entry and update it
  // TODO implement
  (void)frame;
}

void arp_send_request(struct in_addr requesting_ip, struct in_addr target_ip) {
  struct eth_packet *frame = alloc_packet_buf();
  if (frame == NULL) {
    // alloc fail
    return;
  }

  memcpy(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN);
  memcpy(&frame->hdr.h_source, &client_mac, ETH_ALEN);
  frame->hdr.h_proto = htons(ETH_P_ARP);
  frame->arp.hrd = htons(ETH_P_ARP);
  frame->arp.pro = htons(ETH_P_IP);
  frame->arp.hln = sizeof(struct ether_addr);
  frame->arp.pln = sizeof(struct in_addr);
  frame->arp.op = htons(1);
  frame->arp.sha = client_mac;
  frame->arp.spa = requesting_ip;
  frame->arp.tha = broadcast_mac;
  frame->arp.tpa = target_ip;
  frame->recv_size = sizeof(frame->hdr) + sizeof(frame->arp);

  net_send_link_frame(frame);
}

void arp_send_announce(struct in_addr ip_addr, struct ether_addr mac_addr) {
  struct eth_packet *frame = alloc_packet_buf();
  if (frame == NULL) {
    // alloc fail
    return;
  }

  memcpy(&frame->hdr.h_dest, &broadcast_mac, ETH_ALEN);
  memcpy(&frame->hdr.h_source, &client_mac, ETH_ALEN);
  frame->hdr.h_proto = htons(ETH_P_ARP);
  frame->arp.hrd = htons(ARPHRD_ETHER);
  frame->arp.pro = htons(ETH_P_IP);
  frame->arp.hln = sizeof(struct ether_addr);
  frame->arp.pln = sizeof(struct in_addr);
  frame->arp.op = htons(1);
  frame->arp.sha = mac_addr;
  frame->arp.spa = ip_addr;
  memset(&frame->arp.tha, 0, sizeof frame->arp.tha);
  frame->arp.tpa = ip_addr;
  frame->recv_size = sizeof(frame->hdr) + sizeof(frame->arp);

  net_send_link_frame(frame);
}

bool arp_has_work(void) { return false; }

void arp_process_queued(void) {}

void arp_idle(void) {
  time_ms_t cycle_ms = time_since_ms(now_ms, arp_idle_cycle_start_ms);
  uint32_t check_counter_target;
  if (cycle_ms < ARP_IDLE_SCAN_PERIOD_MS * 2) {
    check_counter_target = cycle_ms * ARP_CACHE_SIZE / ARP_IDLE_SCAN_PERIOD_MS;
  } else {
    // We are very far behind (or just experienced some kind of clock hiccup).
    // Reset the time reference and set the target so we check half the table --
    // if this was just a hiccup, that's probably not *too* much, and if we're
    // behind at least we're making progress.
    check_counter_target =
        (arp_idle_check_counter + ARP_CACHE_SIZE / 2) & (ARP_CACHE_SIZE - 1);
    arp_idle_cycle_start_ms = now_ms;
  }
  assert(arp_idle_check_counter < ARP_CACHE_SIZE);
  if (arp_idle_check_counter != check_counter_target) {
    return;
  }
  if (very_verbose_log) {
    logf(
        "arp: idle %lu ms into %lu ms cycle, checking %lu entries, to %lu (of "
        "%lu)",
        (unsigned long)cycle_ms, (unsigned long)ARP_IDLE_SCAN_PERIOD_MS,
        (unsigned long)((check_counter_target + ARP_CACHE_SIZE -
                         arp_idle_check_counter) %
                        (ARP_CACHE_SIZE - 1)),
        (unsigned long)check_counter_target, (unsigned long)ARP_CACHE_SIZE);
  }
  while (arp_idle_check_counter != check_counter_target) {
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
            char ip_str[20];
            inet_ntop(AF_INET, &entry->ip_addr, ip_str, sizeof ip_str);
            logf("(reduce %s; %u->%u)", ip_str, (unsigned)entry->importance,
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
  assert(is_proper_ip_address(ip_addr));

  for (uint32_t i = 0; i < ARP_CACHE_ASSOC; ++i) {
    struct arp_cache_entry *entry =
        &arp_cache[(base + i) & (ARP_CACHE_SIZE - 1)];
    arp_age_entry(entry);

    if ((entry->ip_addr.s_addr == ip_addr.s_addr) &&
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
    struct arp_cache_entry *entry =
        &arp_cache[(base + i) & (ARP_CACHE_SIZE - 1)];
    arp_age_entry(entry);
    int entry_state_class = 0;
    switch (entry->state) {
      default:
        assert(entry->state == ARP_STATE_UNUSED);
      case ARP_STATE_UNUSED:
        // Short-circuit: unused entries have zero cost so we should always take
        // the first available if there is one
        best_bin = entry - arp_cache;
        goto best_bin_early_out;
      case ARP_STATE_VALID:
      case ARP_STATE_REFRESHING:
        // If the entry is valid, at least we did send (or could have sent) some
        // packets to the address, so evicting this entry doesn't imply we're
        // impeding progress
        entry_state_class = 1;
        break;
      case ARP_STATE_REQUESTED:
      case ARP_STATE_COOLDOWN:
        // If the entry is requested or in cooldown, evicting it may cause
        // starvation, so we want to artificially raise the importance of those
        // entries
        entry_state_class = 2;
        break;
      case ARP_STATE_CONTENDED:
        // If the entry is contended, we actually want to hang on to it with
        // greater priority or we risk security failure.
        entry_state_class = 3;
        break;
    }

    if (entry->importance == 0) {
      // This entry has never actually been fetched by another system, so
      // whatever state it's in we only got there by observing random packets;
      // in that special case, forget about it.

      // Contention over IP addresses we're not interacting with can't affect
      // our behaviour. If we begin an interaction later, we'll use the normal
      // cooldown process to try to ensure safety at that time, and if that's
      // not a good enough solution we are redesigning this whole thing anyway.
      // This is networking, it's all "best effort"!

      best_bin = entry - arp_cache;
      goto best_bin_early_out;
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

  assert(is_proper_ip_address(entry->ip_addr));
  assert(!memcmp(&entry->mac_addr, &broadcast_mac, sizeof(entry->mac_addr)));

  time_ms_t entry_age = time_since_ms(now_ms, entry->last_seen_ms);

  if (((entry->state == ARP_STATE_CONTENDED) &&
       (entry_age >= ARP_KEEP_CONTENDED_MS)) ||
      (entry_age >= ARP_INVALIDATE_MS)) {
    // Invalidate entry -- it's very very stale, or it's a contention record
    // that's past due
    if (very_verbose_log) {
      char ip_str[20];
      inet_ntop(AF_INET, &entry->ip_addr, ip_str, sizeof ip_str);
      logf("(age-out %s%s)", ip_str,
           entry->state == ARP_STATE_CONTENDED ? " CTD" : "");
    }
    memset(entry, 0, sizeof *entry);
    assert(entry->state == ARP_STATE_UNUSED);
    assert(is_this_host_ip_address(entry->ip_addr));
    return;
  }

  if ((entry->state == ARP_STATE_COOLDOWN) && (entry_age >= ARP_COOLDOWN_MS)) {
    entry->state = ARP_STATE_VALID;
    // Fall through! A very stale "cooldown" should go direct to "refreshing",
    // via the following logic. This shouldn't be a common case, but suppose a
    // packet gets dropped from the send queue while it's still pending ARP
    // confirmation -- then the send code will stop reconfirming status here,
    // and it could be arbitrarily long (depending on the arp_idle) before that
    // entry gets looked at again.
  }

  if ((entry->state == ARP_STATE_VALID) && (entry_age >= ARP_REFRESH_MS)) {
    entry->state = ARP_STATE_REFRESHING;
  }
}
