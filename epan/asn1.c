/* asn1.c
 * Common routines for ASN.1
 * 2007  Anders Broman
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <epan/packet.h>

#include "asn1.h"

void asn1_ctx_init(asn1_ctx_t *actx, asn1_enc_e encoding, gboolean aligned, packet_info *pinfo) {
  memset(actx, '\0', sizeof(*actx));
  actx->signature = ASN1_CTX_SIGNATURE;
  actx->encoding = encoding;
  actx->aligned = aligned;
  actx->pinfo = pinfo;
}

gboolean asn1_ctx_check_signature(asn1_ctx_t *actx) {
  return actx->signature == ASN1_CTX_SIGNATURE;
}

void asn1_ctx_clean_external(asn1_ctx_t *actx) {
  memset(&actx->external, '\0', sizeof(actx->external));
  actx->external.hf_index = -1;
}

double asn1_get_real(const guint8 *real_ptr, gint real_len) {
  guint8 octet;
  const guint8 *p;
  guint8 *buf;
  double val = 0;

  if (real_len < 1) return val;
  octet = real_ptr[0];
  p = real_ptr + 1;
  real_len -= 1;
  if (octet & 0x80) {  /* binary encoding */
  } else if (octet & 0x40) {  /* SpecialRealValue */
    switch (octet & 0x3F) {
      case 0x00: val = HUGE_VAL; break;
      case 0x01: val = -HUGE_VAL; break;
    }
  } else {  /* decimal encoding */
    buf = ep_alloc0(real_len + 1);
    memcpy(buf, p, real_len);
    val = atof(buf);
  }

  return val;
}
