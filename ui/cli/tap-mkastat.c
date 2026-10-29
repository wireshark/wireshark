/* tap-mkastat.c
 * MKA (MACsec Key Agreement) Connectivity Association analysis tap.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/to_str.h>
#include <epan/addr_resolv.h>

#include <wsutil/cmdarg_err.h>

#include "ui/mka_ca_stat.h"

void register_tap_listener_mkastat(void);

/* ---- tap callbacks ---- */

static void
mkastat_reset(void *arg) {
  mka_ca_stat_reset((mka_ca_stat_t *)arg);
}

static tap_packet_status
mkastat_packet(void *arg, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_) {
  mka_ca_stat_t *st = (mka_ca_stat_t *)arg;
  const mka_ca_tap_t *tap = (const mka_ca_tap_t *)data;

  if (tap->ckn_len == 0) {
    return TAP_PACKET_DONT_REDRAW;
  }

  mka_ca_stat_process(st, tap);

  return TAP_PACKET_REDRAW;
}

/* ---- drawing ---- */

/* Formatting helpers write into a caller-supplied buffer to avoid allocating
 * memory that would otherwise have to be freed by each caller. */
#define MI_STR_LEN   (MKA_CA_MI_LEN * 2 + 1)
#define SCI_STR_LEN  128

static const char *
mi_str(const uint8_t *mi, char *buf, size_t buflen) {
  for (unsigned i = 0; i < MKA_CA_MI_LEN; i++) {
    snprintf(buf + i * 2, buflen - i * 2, "%02x", mi[i]);
  }
  return buf;
}

static const char *
sci_raw_str(const uint8_t *sci, char *buf, size_t buflen) {
  /* Raw SCI: 6-byte MAC system id (hex) / 4-digit hex port, never resolved. */
  snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x/%04x",
           sci[0], sci[1], sci[2], sci[3], sci[4], sci[5],
           (sci[6] << 8) | sci[7]);
  return buf;
}

static const char *
sci_str(const uint8_t *sci, char *buf, size_t buflen) {
  /* SCI label. With physical address resolution on, replace the MAC portion
   * with Wireshark's resolved name (matching the packet view). With it off,
   * show the raw SCI with the OUI vendor appended. */
  if (gbl_resolv_flags.mac_name) {
    const char *name = get_ether_name(sci);
    if (name != NULL && name[0] != '\0') {
      snprintf(buf, buflen, "%s/%04x", name, (sci[6] << 8) | sci[7]);
      return buf;
    }
    return sci_raw_str(sci, buf, buflen);
  }

  const char *manuf = get_manuf_name_if_known(sci, MKA_CA_SCI_LEN - 2);
  if (manuf != NULL) {
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x/%04x (%s)",
             sci[0], sci[1], sci[2], sci[3], sci[4], sci[5],
             (sci[6] << 8) | sci[7], manuf);
    return buf;
  }
  return sci_raw_str(sci, buf, buflen);
}

static void
print_form(const mka_form_t *form) {
  char b1[SCI_STR_LEN], b2[MI_STR_LEN];
  printf("      %s (frames %u - %u):\n", mka_form_kind_str(form->kind), form->trigger_frame, form->end_frame);
  printf("        Key server SCI: %s\n", sci_str(form->ks_sci, b1, sizeof(b1)));
  printf("        Key server MI:  %s\n", mi_str(form->ks_mi, b2, sizeof(b2)));

  if (form->have_ki) {
    if (form->sak_len != 0) {
      char *sak = bytes_to_str(NULL, form->sak, form->sak_len);
      printf("        Target SAK: AN %u, KN %u, SAK %s\n", form->an, form->kn, sak);
      wmem_free(NULL, sak);
    } else {
      printf("        Target SAK: AN %u, KN %u, <Unable to unwrap SAK>\n",
             form->an, form->kn);
    }
  }

  unsigned activated, total;
  double max_sec = mka_form_time(form, NULL, &activated, &total);

  if (total == 0) {
    printf("        Formation Time: no peers to activate\n");
  } else if (activated == 0) {
    printf("        Formation Time: none activated (0/%u peers)\n", total);
  } else {
    printf("        Formation Time: %.3f ms (%u/%u peers)\n",
           max_sec * 1000.0, activated, total);
  }

  GHashTableIter iter;
  void *k, *v;

  printf("        Peers (%u):\n", g_hash_table_size(form->peers));
  g_hash_table_iter_init(&iter, form->peers);

  while (g_hash_table_iter_next(&iter, &k, &v)) {
    mka_form_peer_t *fp = (mka_form_peer_t *)v;
    bool is_ks = (memcmp(fp->sci, form->ks_sci, MKA_CA_SCI_LEN) == 0);
    bool is_new = !is_ks && fp->is_new;

    printf("          %s%s%s:\n", sci_str(fp->sci, b1, sizeof(b1)), is_ks ? " [KS]" : "", is_new ? " [New]" : "");

    /* With resolution on, the label shows the resolved name; print the raw
     * SCI so the underlying identifier stays visible. */
    if (gbl_resolv_flags.mac_name) {
      printf("            SCI:               %s\n", sci_raw_str(fp->sci, b1, sizeof(b1)));
    }
    if (fp->have_mi) {
      printf("            MI:                %s\n", mi_str(fp->mi, b2, sizeof(b2)));
    }

    if (fp->has_installed) {
      nstime_t in;
      nstime_delta(&in, &fp->installed, &form->trigger_time);
      printf("            Installation Time: %.3f ms\n", nstime_to_sec(&in) * 1000.0);
    } else {
      printf("            Installation Time: not installed\n");
    }

    if (fp->has_activated) {
      nstime_t d;
      nstime_delta(&d, &fp->activated, &form->trigger_time);
      printf("            Formation Time:    %.3f ms\n", nstime_to_sec(&d) * 1000.0);
    } else {
      printf("            Formation Time:    not activated\n");
    }

    if (fp->has_demoted && !fp->has_latest_slot) {
      /* Moved to the old slot without being seen in the latest slot first: retirement is immediate. */
      printf("            Retirement Time:   immediate\n");
    } else if (fp->has_latest_slot && fp->has_demoted) {
      /* Latest slot until the SAK is rotated to the old slot. */
      nstime_t r;
      nstime_delta(&r, &fp->demoted, &fp->latest_slot);
      printf("            Retirement Time:   %.3f ms\n", nstime_to_sec(&r) * 1000.0);
    } else {
      printf("            Retirement Time:   not retired\n");
    }
  }
}

static void
print_peer(const mka_ca_t *ca _U_, mka_ca_peer_t *peer, const mka_ca_stat_t *st) {
  char b1[SCI_STR_LEN], b2[MI_STR_LEN];
  printf("    Peer SCI %s%s:\n", sci_str(peer->sci, b1, sizeof(b1)), peer->key_server ? " [Key Server]" : "");

  /* With resolution on, the label shows the resolved name; print the raw SCI
   * so the underlying identifier stays visible. */
  if (gbl_resolv_flags.mac_name) {
    printf("      SCI: %s\n", sci_raw_str(peer->sci, b1, sizeof(b1)));
  }

  unsigned n_mis = peer->mis ? peer->mis->len : 0;
  printf("      Detected MIs (%u):\n", n_mis);

  for (unsigned i = 0; i < n_mis; i++) {
    const mka_ca_mi_t *m = (const mka_ca_mi_t *)g_ptr_array_index(peer->mis, i);
    char range[32];

    if (m->first_frame == m->last_frame) {
      snprintf(range, sizeof(range), "Frame %u", m->first_frame);
    } else {
      snprintf(range, sizeof(range), "Frames %u - %u", m->first_frame, m->last_frame);
    }

    if (st->have_start) {
      nstime_t first_rel, last_rel;
      nstime_delta(&first_rel, &m->first_seen, &st->start_time);
      nstime_delta(&last_rel, &m->last_seen, &st->start_time);
      printf("        %s  %s  +%.6f s - +%.6f s\n",
             mi_str(m->mi, b2, sizeof(b2)), range, nstime_to_sec(&first_rel),
             nstime_to_sec(&last_rel));
    } else {
      printf("        %s  %s\n", mi_str(m->mi, b2, sizeof(b2)), range);
    }
  }
}

static void
mkastat_draw(void *arg) {
  mka_ca_stat_t *st = (mka_ca_stat_t *)arg;

  printf("\n");
  printf("=======================================================================\n");
  printf("MKA Connectivity Associations (known CKN/CAK only)\n");
  printf("=======================================================================\n");

  GHashTableIter ca_iter;
  void *ck, *cv;

  g_hash_table_iter_init(&ca_iter, st->cas);

  while (g_hash_table_iter_next(&ca_iter, &ck, &cv)) {
    mka_ca_t *ca = (mka_ca_t *)cv;
    const mka_ckn_info_t *info = ca->ckn_info;

    printf("\nCA: %s\n",
           (info && info->name) ? info->name : "<CKN not in table>");

    if (ca->ckn_len > 0) {
      char *ckn = bytes_to_str(NULL, ca->ckn, ca->ckn_len);
      printf("  CKN: %s\n", ckn);
      wmem_free(NULL, ckn);
    }

    printf("  Peers (%u):\n", g_hash_table_size(ca->peers));

    GHashTableIter piter;
    void *pk, *pv;

    g_hash_table_iter_init(&piter, ca->peers);

    while (g_hash_table_iter_next(&piter, &pk, &pv)) {
      print_peer(ca, (mka_ca_peer_t *)pv, st);
    }

    printf("  Key Server History (%u):\n", ca->key_servers->len);

    for (unsigned i = 0; i < ca->key_servers->len; i++) {
      mka_ks_t *ks = (mka_ks_t *)g_ptr_array_index(ca->key_servers, i);
      char b1[SCI_STR_LEN], b2[MI_STR_LEN];

      if (ks->first_frame == ks->last_frame) {
        printf("    %u. SCI %s, MI %s (frame %u)\n", i + 1,
               sci_str(ks->sci, b1, sizeof(b1)), mi_str(ks->mi, b2, sizeof(b2)), ks->first_frame);
      } else {
        printf("    %u. SCI %s, MI %s (frames %u - %u)\n", i + 1,
               sci_str(ks->sci, b1, sizeof(b1)), mi_str(ks->mi, b2, sizeof(b2)), ks->first_frame, ks->last_frame);
      }
    }

    printf("  Peer Group Formations (%u):\n", ca->forms->len);
    for (unsigned i = 0; i < ca->forms->len; i++) {
      print_form((mka_form_t *)g_ptr_array_index(ca->forms, i));
    }
  }

  printf("=======================================================================\n");
}

static void
mkastat_finish(void *arg) {
  mka_ca_stat_free((mka_ca_stat_t *)arg);
}

static bool
mkastat_init(const char *opt_arg _U_, void *userdata _U_) {
  mka_ca_stat_t *st = mka_ca_stat_new();

  GString *error = register_tap_listener("mka_ca", st, NULL, TL_REQUIRES_NOTHING,
                                         mkastat_reset, mkastat_packet,
                                         mkastat_draw, mkastat_finish);
  if (error != NULL) {
    cmdarg_err("Couldn't register mka,ca tap: %s", error->str);
    mka_ca_stat_free(st);
    g_string_free(error, TRUE);
    return false;
  }

  return true;
}

static stat_tap_ui mkastat_ui = {
  REGISTER_STAT_GROUP_GENERIC,
  "MKA Connectivity Associations",
  "mka,ca",
  mkastat_init,
  0,
  NULL
};

void
register_tap_listener_mkastat(void) {
  register_stat_tap_ui(&mkastat_ui, NULL);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
