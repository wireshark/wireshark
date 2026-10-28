/* mka_ca_stat.h
 * MKA (MACsec Key Agreement) Connectivity Association analysis engine.
 * Shared by the tshark "-z mka,ca" tap and the Qt MKA CA dialog.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MKA_CA_STAT_H__
#define __MKA_CA_STAT_H__

#include <glib.h>
#include <wsutil/nstime.h>
#include "epan/dissectors/packet-mka.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MKA_CA_MI_LEN  12U
#define MKA_CA_CKN_LEN 32U
#define MKA_CA_KI_LEN  16U
#define MKA_CA_SCI_LEN 8U

/* Classification of a key-formation episode. */
typedef enum {
  MKA_FORM_STARTUP,    /* key server distributed the first SAK */
  MKA_FORM_REKEY,      /* new SAK with no new peer or key server change */
  MKA_FORM_NEW_PEER,   /* a new/reset peer triggered key distribution */
  MKA_FORM_KS_CHANGE   /* a new or restarted key server distributed the SAK */
} mka_form_kind_t;

/* One expected peer within a formation episode. */
typedef struct mka_form_peer_s {
  uint8_t  sci[MKA_CA_SCI_LEN];

  uint8_t  mi[MKA_CA_MI_LEN];   /* peer MI at episode trigger time */
  bool     have_mi;
  bool     is_new;              /* first formation this peer appears in */

  nstime_t activated;          /* first time transmitting with this SAK */
  bool     has_activated;
  uint32_t activated_frame;

  nstime_t installed;          /* first time receiving with this SAK (rx set) */
  bool     has_installed;
  uint32_t installed_frame;

  nstime_t latest_slot;        /* first time this SAK was in the latest slot */
  bool     has_latest_slot;

  nstime_t demoted;            /* first time this SAK appears in the old slot */
  bool     has_demoted;

  uint32_t demoted_frame;
} mka_form_peer_t;

/* A key-formation episode. */
typedef struct mka_form_s {
  mka_form_kind_t kind;

  uint8_t  ki[MKA_CA_KI_LEN];
  bool     have_ki;

  uint8_t  an;
  uint32_t kn;

  uint32_t trigger_frame;
  uint32_t end_frame;       /* last peer activation/demotion frame */
  nstime_t trigger_time;

  GHashTable *peers;        /* key: SCI -> mka_form_peer_t* */

  bool     superseded;

  uint8_t  ks_sci[MKA_CA_SCI_LEN];
  uint8_t  ks_mi[MKA_CA_MI_LEN];   /* distributing key server MI */

  uint8_t  sak[MKA_MAX_SAK_LEN];   /* unwrapped SAK (if the KEK was known) */
  unsigned sak_len;                /* 0 if the SAK was not unwrapped */
} mka_form_t;

/* One observed key server identity (SCI + server MI). */
typedef struct mka_ks_s {
  uint8_t  sci[MKA_CA_SCI_LEN];
  uint8_t  mi[MKA_CA_MI_LEN];

  uint32_t first_frame;
  uint32_t last_frame;
  nstime_t first_time;
} mka_ks_t;

/* One observed MI for a peer SCI, with its first and most recent appearance. */
typedef struct mka_ca_mi_s {
  uint8_t  mi[MKA_CA_MI_LEN];

  nstime_t first_seen;
  nstime_t last_seen;
  uint32_t first_frame;
  uint32_t last_frame;
} mka_ca_mi_t;

/* Per-peer state within a CA, keyed by SCI. */
typedef struct mka_ca_peer_s {
  uint8_t  sci[MKA_CA_SCI_LEN];

  uint8_t  mi[MKA_CA_MI_LEN];     /* most recent MI for this SCI */
  GPtrArray *mis;                /* mka_ca_mi_t*, all MIs seen, in order */

  bool     key_server;
  nstime_t last_heard;
  uint32_t last_frame;

  bool     has_sak_use;
  uint8_t  latest_an;
  bool     latest_tx;
  bool     latest_rx;
  uint8_t  latest_ki[MKA_CA_KI_LEN];
  bool     latest_ki_valid;

  uint8_t  old_an;
  bool     old_tx;
  bool     old_rx;
  uint8_t  old_ki[MKA_CA_KI_LEN];
  bool     old_ki_valid;

  /* This participant has reported an active (non-zero) key at some point.
   * For a key server, false before its first key means a fresh startup. */
  bool     had_active_key;

  GPtrArray *live_peers;         /* of uint8_t[MKA_CA_MI_LEN] */
  GPtrArray *potential_peers;    /* of uint8_t[MKA_CA_MI_LEN] */
} mka_ca_peer_t;

/* Per-CA state keyed by the known CKN info pointer. */
typedef struct mka_ca_s {
  const mka_ckn_info_t *ckn_info;  /* NULL if the CKN is not in the table */
  uint8_t     ckn[MKA_CA_CKN_LEN]; /* raw CKN bytes (CA identity) */
  unsigned    ckn_len;
  GHashTable *peers;        /* key: SCI -> mka_ca_peer_t* */
  GHashTable *mi_to_sci;    /* key: MI -> uint8_t[8] SCI */
  GPtrArray  *forms;        /* of mka_form_t* in chronological order */
  GPtrArray  *key_servers;  /* of mka_ks_t* in order first seen */

  bool        pending_new_peer;

  /* Formation trigger tracking. A formation begins when the key server
   * responds to recent peer engagement (a non-key-server peer MKPDU,
   * especially a new/reset MI). ks_response_frame is the key server's first
   * announcement after the most recent peer engagement; it is used as the
   * startup / key server change trigger. */
  uint32_t    ks_response_frame;
  nstime_t    ks_response_time;
  uint8_t     ks_response_mi[MKA_CA_MI_LEN];
  bool        have_ks_response;

  /* a peer MKPDU seen since the last KS response */
  bool        peer_engaged;

  /* Key server change trigger: the first announcement of a different key
   * server SCI (a different device taking over the key server role). */
  uint32_t    ks_change_frame;
  nstime_t    ks_change_time;
  uint8_t     ks_change_sci[MKA_CA_SCI_LEN];
  bool        have_ks_change;
  uint8_t     last_ks_sci[MKA_CA_SCI_LEN];
  bool        have_last_ks_sci;

  /* Startup origin: set when the first MKPDU in the CA is a key server
   * announcement (the key server initiated, with no prior peer or key server
   * activity). That frame is the startup trigger. */
  uint32_t    ks_origin_frame;
  nstime_t    ks_origin_time;
  bool        have_ks_origin;

  bool        seen_any_mkpdu;
  bool        any_peer_seen;
  /* A participant reported an active SAK before any distribution was
   * captured: the group pre-existed, so the first distribution is a rekey. */
  bool        pre_existing_sak;
  /* The distributing key server was seen announcing with no key of its own:
   * it started the group from scratch, so the first distribution is startup. */
  bool        ks_fresh_start;
  /* Frame of the previous SAK distribution, to tell whether a peer engaged
   * since then (fresh new-peer) versus a stale earlier engagement. */
  uint32_t    last_dist_frame;
  bool        have_last_dist;
} mka_ca_t;

/* Opaque analysis state. */
typedef struct mka_ca_stat_s {
  GHashTable *cas;          /* key: ckn_info ptr -> mka_ca_t* */
  nstime_t    start_time;   /* earliest MKPDU time seen (capture start) */
  bool        have_start;
} mka_ca_stat_t;

/* Allocate an empty analysis state. */
mka_ca_stat_t *mka_ca_stat_new(void);

/* Free an analysis state and all contained data. */
void mka_ca_stat_free(mka_ca_stat_t *st);

/* Discard all accumulated data, keeping the state usable. */
void mka_ca_stat_reset(mka_ca_stat_t *st);

/* Fold one MKA CA tap record into the analysis state. */
void mka_ca_stat_process(mka_ca_stat_t *st, const mka_ca_tap_t *tap);

/* Resolve a peer MI to its SCI within a CA, or NULL if unknown. */
const uint8_t *mka_ca_lookup_sci(const mka_ca_t *ca, const uint8_t *mi);

/* Key number from a Key Identifier (its trailing 4 bytes, big-endian). */
uint32_t mka_ki_kn(const uint8_t *ki);

/* Human-readable name for a formation episode kind. */
const char *mka_form_kind_str(mka_form_kind_t kind);

/* Longest per-peer activation time for an episode, in seconds; negative if
 * no peer has activated. Sets *all_activated to whether every expected peer
 * activated, and *num_activated / *num_total to the counts. */
double mka_form_time(const mka_form_t *form, bool *all_activated, unsigned *num_activated, unsigned *num_total);

#ifdef __cplusplus
}
#endif

#endif /* __MKA_CA_STAT_H__ */
