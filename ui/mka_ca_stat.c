/* mka_ca_stat.c
 * MKA (MACsec Key Agreement) Connectivity Association analysis engine.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include "ui/mka_ca_stat.h"

/* ---- hashing helpers for fixed-length byte keys ---- */

static unsigned
sci_hash(const void *key) {
  const uint8_t *p = (const uint8_t *)key;
  unsigned h = 0;

  for (unsigned i = 0; i < MKA_CA_SCI_LEN; i++) {
    h = h * 31u + p[i];
  }

  return h;
}

static gboolean
sci_equal(const void *a, const void *b) {
  return memcmp(a, b, MKA_CA_SCI_LEN) == 0;
}

static unsigned
ckn_hash(const void *key) {
  const uint8_t *p = (const uint8_t *)key;
  unsigned h = 0;

  for (unsigned i = 0; i < MKA_CA_CKN_LEN; i++) {
    h = h * 31u + p[i];
  }

  return h;
}

static gboolean
ckn_equal(const void *a, const void *b) {
  return memcmp(a, b, MKA_CA_CKN_LEN) == 0;
}

static unsigned
mi_hash(const void *key) {
  const uint8_t *p = (const uint8_t *)key;
  unsigned h = 0;

  for (unsigned i = 0; i < MKA_CA_MI_LEN; i++) {
    h = h * 31u + p[i];
  }

  return h;
}

static gboolean
mi_equal(const void *a, const void *b) {
  return memcmp(a, b, MKA_CA_MI_LEN) == 0;
}

/* ---- allocation / free ---- */

static mka_ca_peer_t *
peer_new(const uint8_t *sci) {
  mka_ca_peer_t *peer = g_new0(mka_ca_peer_t, 1);

  memcpy(peer->sci, sci, MKA_CA_SCI_LEN);

  peer->mis = g_ptr_array_new_with_free_func(g_free);
  peer->live_peers = g_ptr_array_new_with_free_func(g_free);
  peer->potential_peers = g_ptr_array_new_with_free_func(g_free);

  return peer;
}

static void
peer_free(void *p) {
  mka_ca_peer_t *peer = (mka_ca_peer_t *)p;

  g_ptr_array_free(peer->mis, TRUE);
  g_ptr_array_free(peer->live_peers, TRUE);
  g_ptr_array_free(peer->potential_peers, TRUE);
  g_free(peer);
}

static void
form_free(void *p) {
  mka_form_t *form = (mka_form_t *)p;

  g_hash_table_destroy(form->peers);
  g_free(form);
}

static void
ca_free(void *p) {
  mka_ca_t *ca = (mka_ca_t *)p;

  g_hash_table_destroy(ca->peers);
  g_hash_table_destroy(ca->mi_to_sci);
  g_ptr_array_free(ca->forms, TRUE);
  g_ptr_array_free(ca->key_servers, TRUE);
  g_free(ca);
}

static mka_ca_t *
ca_get(mka_ca_stat_t *st, const mka_ca_tap_t *tap) {
  mka_ca_t *ca = (mka_ca_t *)g_hash_table_lookup(st->cas, tap->ckn);

  if (ca == NULL) {
    ca = g_new0(mka_ca_t, 1);
    ca->ckn_info = tap->ckn_info;
    if (tap->ckn_len <= MKA_CA_CKN_LEN) {
      memcpy(ca->ckn, tap->ckn, tap->ckn_len);
      ca->ckn_len = tap->ckn_len;
    }
    ca->peers = g_hash_table_new_full(sci_hash, sci_equal, NULL, peer_free);
    ca->mi_to_sci = g_hash_table_new_full(mi_hash, mi_equal, g_free, g_free);
    ca->forms = g_ptr_array_new_with_free_func(form_free);
    ca->key_servers = g_ptr_array_new_with_free_func(g_free);

    uint8_t *key = g_malloc0(MKA_CA_CKN_LEN);
    memcpy(key, ca->ckn, ca->ckn_len);
    g_hash_table_insert(st->cas, key, ca);
  } else if (ca->ckn_info == NULL && tap->ckn_info != NULL) {
    /* The CKN later appeared in the table (or a CAK was configured). */
    ca->ckn_info = tap->ckn_info;
  }

  return ca;
}

static mka_ca_peer_t *
ca_get_peer(mka_ca_t *ca, const uint8_t *sci) {
  mka_ca_peer_t *peer = (mka_ca_peer_t *)g_hash_table_lookup(ca->peers, sci);

  if (peer == NULL) {
    peer = peer_new(sci);
    g_hash_table_insert(ca->peers, peer->sci, peer);
  }

  return peer;
}

/* Record an MI -> SCI mapping observed from a Basic Parameter Set. */
static void
ca_note_mi(mka_ca_t *ca, const uint8_t *mi, const uint8_t *sci) {
  if (g_hash_table_lookup(ca->mi_to_sci, mi) != NULL) {
    return;
  }

  uint8_t *k = g_malloc(MKA_CA_MI_LEN);
  uint8_t *v = g_malloc(MKA_CA_SCI_LEN);

  memcpy(k, mi, MKA_CA_MI_LEN);
  memcpy(v, sci, MKA_CA_SCI_LEN);
  g_hash_table_insert(ca->mi_to_sci, k, v);
}

/* Record a key server identity (SCI + server MI) that distributed a SAK.
 * Returns true if this is a key server change: a different SCI, or the same
 * SCI with a new MI (a key server restart). */
static bool
ca_note_key_server(mka_ca_t *ca, const uint8_t *sci, const uint8_t *mi, uint32_t frame, const nstime_t *ts) {
  if (ca->key_servers->len > 0) {
    mka_ks_t *last = (mka_ks_t *)g_ptr_array_index(ca->key_servers, ca->key_servers->len - 1);
    if (memcmp(last->sci, sci, MKA_CA_SCI_LEN) == 0 &&
        memcmp(last->mi, mi, MKA_CA_MI_LEN) == 0) {
      last->last_frame = frame;
      return false;
    }
  }

  mka_ks_t *ks = g_new0(mka_ks_t, 1);
  memcpy(ks->sci, sci, MKA_CA_SCI_LEN);
  memcpy(ks->mi, mi, MKA_CA_MI_LEN);
  ks->first_frame = frame;
  ks->last_frame = frame;
  ks->first_time = *ts;

  g_ptr_array_add(ca->key_servers, ks);

  return ca->key_servers->len > 1;
}

/* ---- formation episode handling ---- */

static mka_form_t *
form_new(mka_form_kind_t kind, const uint8_t *ki, uint8_t an, uint32_t kn, uint32_t frame, const nstime_t *ts) {
  mka_form_t *form = g_new0(mka_form_t, 1);

  form->kind = kind;
  if (ki != NULL) {
    memcpy(form->ki, ki, MKA_CA_KI_LEN);
    form->have_ki = true;
  }

  form->an = an;
  form->kn = kn;
  form->trigger_frame = frame;
  form->end_frame = frame;
  form->trigger_time = *ts;
  form->peers = g_hash_table_new_full(sci_hash, sci_equal, NULL, g_free);

  return form;
}

static void
form_add_expected(mka_form_t *form, const uint8_t *sci, const uint8_t *mi) {
  if (g_hash_table_lookup(form->peers, sci) != NULL) {
    return;
  }

  mka_form_peer_t *fp = g_new0(mka_form_peer_t, 1);
  memcpy(fp->sci, sci, MKA_CA_SCI_LEN);
  if (mi != NULL) {
    memcpy(fp->mi, mi, MKA_CA_MI_LEN);
    fp->have_mi = true;
  }

  g_hash_table_insert(form->peers, fp->sci, fp);
}

/* An existing formation episode for the same SAK (full KI), or NULL. The
 * distributed SAK always carries the full KI, which is unique per SAK even
 * when the key number resets after a key server restart. */
static mka_form_t *
form_find(mka_ca_t *ca, const uint8_t *ki) {
  for (unsigned i = 0; i < ca->forms->len; i++) {
    mka_form_t *form = (mka_form_t *)g_ptr_array_index(ca->forms, i);
    /* Skip superseded episodes so a wrapped (reused) key number creates a
     * fresh episode rather than matching a long-closed one. */
    if (form->superseded) {
      continue;
    }
    if (form->have_ki && memcmp(form->ki, ki, MKA_CA_KI_LEN) == 0) {
      return form;
    }
  }

  return NULL;
}

/* Find the form peer (by SCI) for the most recent episode matching a SAK.
 * When the peer reports a non-zero key server MI, match by full KI;
 * otherwise match by (AN, KN), preferring the most recent episode since the
 * key number can repeat after a key server restart. */
static mka_form_peer_t *
form_find_peer(mka_ca_t *ca, const uint8_t *sci, uint8_t an, uint32_t kn, const uint8_t *ki, bool ki_server_mi_set, mka_form_t **out_form) {
  for (int i = (int)ca->forms->len - 1; i >= 0; i--) {
    mka_form_t *form = (mka_form_t *)g_ptr_array_index(ca->forms, i);
    bool match;

    /* Skip superseded episodes so a key number that recurs after the key
     * number space wraps does not re-match (and extend) a long-closed
     * episode. */
    if (form->superseded) {
      continue;
    }

    if (ki_server_mi_set) {
      match = form->have_ki && memcmp(form->ki, ki, MKA_CA_KI_LEN) == 0;
    } else {
      match = (form->an == an && form->kn == kn);
    }

    if (match) {
      if (out_form != NULL) {
        *out_form = form;
      }
      return (mka_form_peer_t *)g_hash_table_lookup(form->peers, sci);
    }
  }
  return NULL;
}

/* Record a peer (by SCI) transmitting with a SAK (ltx or otx). */
static void
form_record_activation(mka_ca_t *ca, const uint8_t *sci, uint8_t an, uint32_t kn,
                       const uint8_t *ki, bool ki_server_mi_set, const nstime_t *ts, uint32_t frame) {
  mka_form_t *form = NULL;
  mka_form_peer_t *fp = form_find_peer(ca, sci, an, kn, ki, ki_server_mi_set, &form);
  if (fp != NULL && !fp->has_activated) {
    fp->activated = *ts;
    fp->has_activated = true;
    fp->activated_frame = frame;
    if (form != NULL && frame > form->end_frame) {
      form->end_frame = frame;
    }
  }
}

/* Record a peer (by SCI) installing a SAK for receive (rx flag set),
 * stamping the first such sighting. */
static void
form_record_installation(mka_ca_t *ca, const uint8_t *sci, uint8_t an, uint32_t kn,
                         const uint8_t *ki, bool ki_server_mi_set, const nstime_t *ts, uint32_t frame) {
  mka_form_peer_t *fp = form_find_peer(ca, sci, an, kn, ki, ki_server_mi_set, NULL);
  if (fp != NULL && !fp->has_installed) {
    fp->installed = *ts;
    fp->has_installed = true;
    fp->installed_frame = frame;
  }
}

/* Record a peer (by SCI) reporting a SAK present in its latest slot (lrx or
 * ltx), stamping the first such sighting. Used as the start of the retirement
 * interval. When extend_end is set and the peer has not yet activated the SAK
 * for transmit, also extends the episode end to this frame, so an incomplete
 * formation spans until the last receive activity. A frame that distributes a
 * newer SAK does not extend the previous episode (extend_end is false). */
static void
form_record_latest_slot(mka_ca_t *ca, const uint8_t *sci, uint8_t an, uint32_t kn,
                        const uint8_t *ki, bool ki_server_mi_set,
                        const nstime_t *ts, uint32_t frame, bool extend_end) {
  mka_form_t *form = NULL;
  mka_form_peer_t *fp = form_find_peer(ca, sci, an, kn, ki, ki_server_mi_set, &form);
  if (fp != NULL) {
    if (!fp->has_latest_slot) {
      fp->latest_slot = *ts;
      fp->has_latest_slot = true;
    }
    if (extend_end && !fp->has_activated && form != NULL && frame > form->end_frame) {
      form->end_frame = frame;
    }
  }
}

/* Record a peer (by SCI) reporting a SAK (by KI) demoted to the old slot,
 * stamping the first such sighting. Matches episodes by full KI. */
static void
form_record_demotion(mka_ca_t *ca, const uint8_t *sci, const uint8_t *ki, const nstime_t *ts, uint32_t frame) {
  for (int i = (int)ca->forms->len - 1; i >= 0; i--) {
    mka_form_t *form = (mka_form_t *)g_ptr_array_index(ca->forms, i);

    if (form->have_ki && memcmp(form->ki, ki, MKA_CA_KI_LEN) == 0) {
      mka_form_peer_t *fp = (mka_form_peer_t *)g_hash_table_lookup(form->peers, sci);
      if (fp != NULL && !fp->has_demoted) {
        fp->demoted = *ts;
        fp->has_demoted = true;
        fp->demoted_frame = frame;
      }

      return;
    }
  }
}

static void
copy_mi_array(GPtrArray *dst, wmem_array_t *src) {
  unsigned n = src ? wmem_array_get_count(src) : 0;

  for (unsigned i = 0; i < n; i++) {
    uint8_t *mi = g_malloc(MKA_CA_MI_LEN);
    memcpy(mi, wmem_array_index(src, i), MKA_CA_MI_LEN);
    g_ptr_array_add(dst, mi);
  }
}

/* ---- public API ---- */

mka_ca_stat_t *
mka_ca_stat_new(void) {
  mka_ca_stat_t *st = g_new0(mka_ca_stat_t, 1);

  st->cas = g_hash_table_new_full(ckn_hash, ckn_equal, g_free, ca_free);
  return st;
}

void
mka_ca_stat_reset(mka_ca_stat_t *st) {
  if (st != NULL) {
    g_hash_table_remove_all(st->cas);
    st->have_start = false;
  }
}

void
mka_ca_stat_free(mka_ca_stat_t *st) {
  if (st != NULL) {
    g_hash_table_destroy(st->cas);
    g_free(st);
  }
}

void
mka_ca_stat_process(mka_ca_stat_t *st, const mka_ca_tap_t *tap) {
  if (tap->ckn_len == 0) {
    return;
  }

  if (!st->have_start || nstime_cmp(&tap->abs_ts, &st->start_time) < 0) {
    st->start_time = tap->abs_ts;
    st->have_start = true;
  }

  mka_ca_t *ca = ca_get(st, tap);
  ca_note_mi(ca, tap->actor_mi, tap->actor_sci);

  /* A new SCI is a new peer; a new MI under a known SCI is a peer reset. */
  mka_ca_peer_t *existing = (mka_ca_peer_t *)g_hash_table_lookup(ca->peers, tap->actor_sci);
  bool is_new_peer = (existing == NULL);
  bool is_reset = (existing != NULL && memcmp(existing->mi, tap->actor_mi, MKA_CA_MI_LEN) != 0);

  /* Startup origin: if the first MKPDU seen in this CA is a key server
   * announcement, the key server initiated the association. That frame is the
   * startup trigger only while it remains the start of the formation that
   * produces the first SAK. The origin is discarded if the key server
   * announces again before any peer engages (keepalive into an empty CA), or
   * if a peer resets (new MI) before the SAK forms; in those cases the
   * trigger becomes the key server's response to the (latest) peer
   * engagement. */
  if (!ca->seen_any_mkpdu) {
    ca->seen_any_mkpdu = true;
    if (tap->key_server) {
      ca->ks_origin_frame = tap->frame_num;
      ca->ks_origin_time = tap->abs_ts;
      ca->have_ks_origin = true;
    }
  } else if (ca->have_ks_origin && ((tap->key_server && !ca->any_peer_seen) || is_reset)) {
    ca->have_ks_origin = false;
  }

  if (!tap->key_server) {
    ca->any_peer_seen = true;
  }

  /* Formation trigger tracking. A peer first appearing or resetting (new MI)
   * starts a fresh formation round; the key server's first announcement after
   * that is the trigger (the key server responding to the peer). Ordinary
   * peer chatter does not move the trigger, and a stale announcement into an
   * empty or departed CA is discounted. */
  if (!tap->key_server && (is_new_peer || is_reset)) {
    ca->peer_engaged = true;
  } else if (tap->key_server && ca->peer_engaged) {
    ca->ks_response_frame = tap->frame_num;
    ca->ks_response_time = tap->abs_ts;
    memcpy(ca->ks_response_mi, tap->actor_mi, MKA_CA_MI_LEN);
    ca->have_ks_response = true;
    ca->peer_engaged = false;
  }

  /* Key server change trigger: a key_server MKPDU whose SCI differs from the
   * previously seen key server SCI (a different device taking over). */
  if (tap->key_server) {
    if (ca->have_last_ks_sci &&
        memcmp(ca->last_ks_sci, tap->actor_sci, MKA_CA_SCI_LEN) != 0) {
      ca->ks_change_frame = tap->frame_num;
      ca->ks_change_time = tap->abs_ts;
      memcpy(ca->ks_change_sci, tap->actor_sci, MKA_CA_SCI_LEN);
      ca->have_ks_change = true;
    }
    memcpy(ca->last_ks_sci, tap->actor_sci, MKA_CA_SCI_LEN);
    ca->have_last_ks_sci = true;
  }

  /* Extend the active window of a known key server identity whenever it is
   * heard from, not only when it distributes a SAK. */
  for (unsigned i = 0; i < ca->key_servers->len; i++) {
    mka_ks_t *ks = (mka_ks_t *)g_ptr_array_index(ca->key_servers, i);
    if (memcmp(ks->mi, tap->actor_mi, MKA_CA_MI_LEN) == 0) {
      if (tap->frame_num > ks->last_frame) {
        ks->last_frame = tap->frame_num;
      }
      break;
    }
  }

  /* Update the actor's peer record, keyed by SCI. */
  mka_ca_peer_t *actor = ca_get_peer(ca, tap->actor_sci);
  memcpy(actor->mi, tap->actor_mi, MKA_CA_MI_LEN);

  /* A reset (same SCI, new MI) that comes up with no active key clears the
   * had-key state, so a key server that reset and restarted keyless is a
   * fresh startup rather than carrying its prior key state. */
  if (is_reset) {
    bool reports_active_key = tap->has_sak_use &&
        ((tap->latest_ki_valid && mka_ki_kn(tap->latest_ki) != 0) ||
         (tap->old_ki_valid && mka_ki_kn(tap->old_ki) != 0));
    if (!reports_active_key) {
      actor->had_active_key = false;
    }
  }

  /* Track each MI seen for this SCI and its most recent appearance. */
  {
    mka_ca_mi_t *entry = NULL;
    for (unsigned i = 0; i < actor->mis->len; i++) {
      mka_ca_mi_t *e = (mka_ca_mi_t *)g_ptr_array_index(actor->mis, i);
      if (memcmp(e->mi, tap->actor_mi, MKA_CA_MI_LEN) == 0) {
        entry = e;
        break;
      }
    }

    if (entry == NULL) {
      entry = g_new0(mka_ca_mi_t, 1);
      memcpy(entry->mi, tap->actor_mi, MKA_CA_MI_LEN);
      entry->first_frame = tap->frame_num;
      entry->first_seen = tap->abs_ts;
      g_ptr_array_add(actor->mis, entry);
    }

    entry->last_seen = tap->abs_ts;
    entry->last_frame = tap->frame_num;
  }

  actor->key_server = tap->key_server;
  actor->last_heard = tap->abs_ts;
  actor->last_frame = tap->frame_num;

  g_ptr_array_set_size(actor->live_peers, 0);
  g_ptr_array_set_size(actor->potential_peers, 0);
  copy_mi_array(actor->live_peers, tap->live_peers);
  copy_mi_array(actor->potential_peers, tap->potential_peers);

  /* Whether this (key server) actor already had an active key before this
   * MKPDU: a key server with no prior key is a fresh startup. Captured before
   * this frame's SAK Use (which may report the key just distributed). */
  bool actor_had_key_before = actor->had_active_key;

  if (tap->has_sak_use) {
    actor->has_sak_use = true;
    actor->latest_an = tap->latest_an;
    actor->latest_tx = tap->latest_tx;
    actor->latest_rx = tap->latest_rx;
    actor->latest_ki_valid = tap->latest_ki_valid;

    if (tap->latest_ki_valid) {
      memcpy(actor->latest_ki, tap->latest_ki, MKA_CA_KI_LEN);
    }

    actor->old_an = tap->old_an;
    actor->old_tx = tap->old_tx;
    actor->old_rx = tap->old_rx;
    actor->old_ki_valid = tap->old_ki_valid;

    if (tap->old_ki_valid) {
      memcpy(actor->old_ki, tap->old_ki, MKA_CA_KI_LEN);
    }

    if ((tap->latest_ki_valid && mka_ki_kn(tap->latest_ki) != 0) ||
        (tap->old_ki_valid && mka_ki_kn(tap->old_ki) != 0)) {
      actor->had_active_key = true;
    }
  }

  if ((is_new_peer || is_reset) && !tap->key_server) {
    ca->pending_new_peer = true;
  }

  /* Scenarios 1, 2 and 4: the key server distributes a SAK. */
  if (tap->key_server && tap->has_dist_sak) {
    /* Distributing a SAK means this key server now has a key installed, so
     * any subsequent distribution from it is not a fresh startup. */
    actor->had_active_key = true;

    /* Did a different key server SCI distribute before this one? */
    bool ks_sci_changed = false;
    if (ca->key_servers->len > 0) {
      mka_ks_t *last = (mka_ks_t *)g_ptr_array_index(ca->key_servers, ca->key_servers->len - 1);
      ks_sci_changed = memcmp(last->sci, tap->actor_sci, MKA_CA_SCI_LEN) != 0;
    }

    ca_note_key_server(ca, tap->actor_sci, tap->actor_mi, tap->frame_num, &tap->abs_ts);

    if (form_find(ca, tap->dist_sak_ki) == NULL) {
      mka_form_kind_t kind;

      /* Classification (per MKA semantics):
       *  - Key Server Change: a different key server SCI distributed before
       *    this one (a different device took over the key server role).
       *  - Startup: same (or first) key server SCI with no active key of its
       *    own before this distribution (a fresh key server, or a same-SCI
       *    reset that came up with no SAK Use).
       *  - New Peer: same SCI with a key, and a peer joined since the
       *    previous distribution.
       *  - Rekey: otherwise. */
      bool fresh_new_peer = ca->pending_new_peer &&
            (!ca->have_last_dist ||
             (ca->have_ks_response && ca->ks_response_frame > ca->last_dist_frame));

      if (ks_sci_changed) {
        kind = MKA_FORM_KS_CHANGE;
      } else if (!actor_had_key_before) {
        kind = MKA_FORM_STARTUP;
      } else if (fresh_new_peer) {
        kind = MKA_FORM_NEW_PEER;
      } else {
        kind = MKA_FORM_REKEY;
      }

      /* Any still-open prior episode is superseded by this new SAK. */
      for (unsigned i = 0; i < ca->forms->len; i++) {
        mka_form_t *prior = (mka_form_t *)g_ptr_array_index(ca->forms, i);
        if (!prior->superseded) {
          prior->superseded = true;
        }
      }

      /* Trigger timing per scenario:
       *  - startup: the key server's first announcement if it initiated the
       *    association (origin), else its response to peer engagement;
       *  - new peer: the key server's response to the new/reset peer;
       *  - key server change: the key server's new-MI announcement;
       *  - rekey: the SAK distribution. */
      uint32_t trigger_frame = tap->frame_num;
      nstime_t trigger_time = tap->abs_ts;

      if (kind == MKA_FORM_STARTUP && ca->have_ks_origin) {
        trigger_frame = ca->ks_origin_frame;
        trigger_time = ca->ks_origin_time;

      } else if (kind == MKA_FORM_STARTUP && ca->have_ks_response &&
                 memcmp(ca->ks_response_mi, tap->actor_mi, MKA_CA_MI_LEN) == 0) {
        trigger_frame = ca->ks_response_frame;
        trigger_time = ca->ks_response_time;

      } else if (kind == MKA_FORM_KS_CHANGE && ca->have_ks_change &&
                 memcmp(ca->ks_change_sci, tap->actor_sci, MKA_CA_SCI_LEN) == 0) {
        trigger_frame = ca->ks_change_frame;
        trigger_time = ca->ks_change_time;
      }

      mka_form_t *form = form_new(kind, tap->dist_sak_ki, tap->dist_sak_an, tap->dist_sak_kn, trigger_frame, &trigger_time);
      memcpy(form->ks_sci, tap->actor_sci, MKA_CA_SCI_LEN);
      memcpy(form->ks_mi, tap->actor_mi, MKA_CA_MI_LEN);

      if (tap->dist_sak_len != 0 && tap->dist_sak_len <= MKA_MAX_SAK_LEN) {
        memcpy(form->sak, tap->dist_sak, tap->dist_sak_len);
        form->sak_len = tap->dist_sak_len;
      }

      /* Expected participants: the key server's live peer list at
       * distribution time (resolved MI -> SCI), plus the key server itself.
       * The formation completes only when every participant, including the
       * key server, has activated the SAK for transmit. Peers that have left
       * the CA are not in this list and do not count. */
      form_add_expected(form, tap->actor_sci, tap->actor_mi);

      unsigned n_live = tap->live_peers ? wmem_array_get_count(tap->live_peers) : 0;
      for (unsigned i = 0; i < n_live; i++) {
        const uint8_t *mi = (const uint8_t *)wmem_array_index(tap->live_peers, i);
        const uint8_t *sci = (const uint8_t *)g_hash_table_lookup(ca->mi_to_sci, mi);

        if (sci == NULL) {
          continue;   /* MI not yet mapped to an SCI; cannot track. */
        }

        if (memcmp(sci, tap->actor_sci, MKA_CA_SCI_LEN) != 0) {
          form_add_expected(form, sci, mi);
        }
      }

      /* Mark peers whose (SCI, MI) was not in the immediately-preceding
       * formation as new. A node that reset keeps its SCI but presents a new
       * MI, which makes it a new participant in the group. The first
       * formation has no predecessor, so nothing is marked there. */
      mka_form_t *prev_form = (ca->forms->len > 0)
          ? (mka_form_t *)g_ptr_array_index(ca->forms, ca->forms->len - 1)
          : NULL;

      if (prev_form != NULL) {
        GHashTableIter fpit;
        void *fk, *fv;
        bool any_new = false;

        g_hash_table_iter_init(&fpit, form->peers);

        while (g_hash_table_iter_next(&fpit, &fk, &fv)) {
          mka_form_peer_t *fp = (mka_form_peer_t *)fv;
          mka_form_peer_t *prev_fp =
              (mka_form_peer_t *)g_hash_table_lookup(prev_form->peers, fp->sci);
          bool same = (prev_fp != NULL) && fp->have_mi && prev_fp->have_mi &&
                      (memcmp(fp->mi, prev_fp->mi, MKA_CA_MI_LEN) == 0);
          bool is_ks = (memcmp(fp->sci, form->ks_sci, MKA_CA_SCI_LEN) == 0);

          if (!same) {
            fp->is_new = true;
            if (!is_ks) {
              any_new = true;
            }
          }
        }

        /* A rekey that actually gained a peer (new MI relative to the prior
         * formation) is a new-peer event. Startup and key-server-change keep
         * their classification. */
        if (any_new && form->kind == MKA_FORM_REKEY) {
          form->kind = MKA_FORM_NEW_PEER;
        }
      }

      g_ptr_array_add(ca->forms, form);
      ca->pending_new_peer = false;
    }
    ca->last_dist_frame = tap->frame_num;
    ca->have_last_dist = true;
  }

  /* Record when a SAK first appears in a participant's latest slot (lrx or
   * ltx), the start of the retirement interval. Applies to the key server
   * too, which is an expected participant. */
  if (tap->has_sak_use && tap->latest_ki_valid && mka_ki_kn(tap->latest_ki) != 0) {
    uint32_t latest_kn = mka_ki_kn(tap->latest_ki);
    bool server_mi_set = false;

    for (unsigned i = 0; i < MKA_CA_MI_LEN; i++) {
      if (tap->latest_ki[i] != 0) {
        server_mi_set = true;
        break;
      }
    }

    form_record_latest_slot(ca, tap->actor_sci, tap->latest_an, latest_kn,
                            tap->latest_ki, server_mi_set, &tap->abs_ts,
                            tap->frame_num, !tap->has_dist_sak);
  }

  /* Record installation: a participant reporting a SAK with the rx flag set
   * (installed for receive), via the latest slot (lrx) or the old slot
   * (orx). */
  if (tap->has_sak_use && tap->latest_rx && tap->latest_ki_valid && mka_ki_kn(tap->latest_ki) != 0) {
    uint32_t latest_kn = mka_ki_kn(tap->latest_ki);
    bool server_mi_set = false;

    for (unsigned i = 0; i < MKA_CA_MI_LEN; i++) {
      if (tap->latest_ki[i] != 0) {
        server_mi_set = true;
        break;
      }
    }

    form_record_installation(ca, tap->actor_sci, tap->latest_an, latest_kn,
                             tap->latest_ki, server_mi_set, &tap->abs_ts,
                             tap->frame_num);
  }

  if (tap->has_sak_use && tap->old_rx && tap->old_ki_valid && mka_ki_kn(tap->old_ki) != 0) {
    uint32_t old_kn = mka_ki_kn(tap->old_ki);
    bool server_mi_set = false;

    for (unsigned i = 0; i < MKA_CA_MI_LEN; i++) {
      if (tap->old_ki[i] != 0) {
        server_mi_set = true;
        break;
      }
    }

    form_record_installation(ca, tap->actor_sci, tap->old_an, old_kn,
                             tap->old_ki, server_mi_set, &tap->abs_ts,
                             tap->frame_num);
  }

  /* Record activation: a participant (peer or key server) transmitting with a
   * SAK, via the latest slot (ltx) or, for implementations that move the key
   * straight to the old slot, via the old slot (otx). */
  if (tap->has_sak_use && tap->latest_tx && tap->latest_ki_valid) {
    uint32_t latest_kn = mka_ki_kn(tap->latest_ki);

    bool server_mi_set = false;
    for (unsigned i = 0; i < MKA_CA_MI_LEN; i++) {
      if (tap->latest_ki[i] != 0) {
        server_mi_set = true;
        break;
      }
    }

    form_record_activation(ca, tap->actor_sci, tap->latest_an, latest_kn,
                           tap->latest_ki, server_mi_set, &tap->abs_ts,
                           tap->frame_num);
  }

  if (tap->has_sak_use && tap->old_tx && tap->old_ki_valid && mka_ki_kn(tap->old_ki) != 0) {
    uint32_t old_kn = mka_ki_kn(tap->old_ki);

    bool server_mi_set = false;
    for (unsigned i = 0; i < MKA_CA_MI_LEN; i++) {
      if (tap->old_ki[i] != 0) {
        server_mi_set = true;
        break;
      }
    }

    form_record_activation(ca, tap->actor_sci, tap->old_an, old_kn,
                           tap->old_ki, server_mi_set, &tap->abs_ts,
                           tap->frame_num);
  }

  /* Record demotion: a peer reporting a non-zero old key (SAK moved to the
   * old slot). */
  if (tap->has_sak_use && tap->old_ki_valid && mka_ki_kn(tap->old_ki) != 0) {
    form_record_demotion(ca, tap->actor_sci, tap->old_ki, &tap->abs_ts,
                         tap->frame_num);
  }
}

const uint8_t *
mka_ca_lookup_sci(const mka_ca_t *ca, const uint8_t *mi) {
  return (const uint8_t *)g_hash_table_lookup(ca->mi_to_sci, mi);
}

uint32_t
mka_ki_kn(const uint8_t *ki) {
  return ((uint32_t)ki[MKA_CA_MI_LEN] << 24) |
         ((uint32_t)ki[MKA_CA_MI_LEN + 1] << 16) |
         ((uint32_t)ki[MKA_CA_MI_LEN + 2] << 8) |
         ((uint32_t)ki[MKA_CA_MI_LEN + 3]);
}

const char *
mka_form_kind_str(mka_form_kind_t kind) {
  switch (kind) {
    case MKA_FORM_STARTUP:   return "Key Server Startup";
    case MKA_FORM_REKEY:     return "Key Server Rekey";
    case MKA_FORM_NEW_PEER:  return "New Peer(s)";
    case MKA_FORM_KS_CHANGE: return "Key Server Change";
  }
  return "Unknown";
}

double
mka_form_time(const mka_form_t *form, bool *all_activated,
              unsigned *num_activated, unsigned *num_total) {
  double max_sec = -1.0;
  unsigned activated = 0;
  unsigned total = g_hash_table_size(form->peers);

  GHashTableIter iter;
  void *k, *v;

  g_hash_table_iter_init(&iter, form->peers);

  while (g_hash_table_iter_next(&iter, &k, &v)) {
    mka_form_peer_t *fp = (mka_form_peer_t *)v;
    if (fp->has_activated) {
      nstime_t d;
      nstime_delta(&d, &fp->activated, &form->trigger_time);

      double sec = nstime_to_sec(&d);
      if (sec > max_sec) {
        max_sec = sec;
      }

      activated++;
    }
  }

  if (all_activated != NULL) {
    *all_activated = (total > 0 && activated == total);
  }

  if (num_activated != NULL) {
    *num_activated = activated;
  }

  if (num_total != NULL) {
    *num_total = total;
  }

  return max_sec;
}
