/* asn1.h
 * Common data for ASN.1
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

#ifndef __ASN1_H__
#define __ASN1_H__

typedef enum {
  ASN1_ENC_BER,  /* X.690 - BER, CER, DER */
  ASN1_ENC_PER,  /* X.691 - PER */
  ASN1_ENC_ECN,  /* X.692 - ECN */
  ASN1_ENC_XER   /* X.693 - XER */
} asn1_enc_e;

typedef struct _asn1_ctx_t {
  asn1_enc_e encoding;
  gboolean aligned;
  packet_info *pinfo;
  proto_item *created_item;
  void *value_ptr;
  void *private_data;
  struct {
    tvbuff_t *data_value_descriptor;
    int hf_index;
    union {
      struct {
        void *dummy;
      } ber;
      struct {
        int (*type_cb)(tvbuff_t*, int, struct _asn1_ctx_t*, proto_tree*, int);
        tvbuff_t *direct_reference;
        gint32 indirect_reference;
        guint32 encoding;
        tvbuff_t *single_asn1_type;
        tvbuff_t *octet_aligned;
        tvbuff_t *arbitrary;
      } per;
    };
  } external;
} asn1_ctx_t;

#endif  /* __ASN1_H__ */
