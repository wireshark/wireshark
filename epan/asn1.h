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

#define ASN1_CTX_SIGNATURE 0x41435458  /* "ACTX" */

typedef struct _asn1_ctx_t {
  guint32 signature;
  asn1_enc_e encoding;
  gboolean aligned;
  packet_info *pinfo;
  proto_item *created_item;
  void *value_ptr;
  void *private_data;
  struct {
    tvbuff_t *data_value_descriptor;
    int hf_index;
    const char *direct_reference;
    gint32 indirect_reference;
    guint32 encoding;
    tvbuff_t *single_asn1_type;
    tvbuff_t *octet_aligned;
    tvbuff_t *arbitrary;
    union {
      struct {
		int (*ber_callback)(gboolean imp_tag, tvbuff_t *tvb, int offset, struct _asn1_ctx_t* ,proto_tree *tree, int hf_index );
        tvbuff_t *direct_reference;
        gint32 indirect_reference;
        guint32 encoding;
        tvbuff_t *single_asn1_type;
        tvbuff_t *octet_aligned;
        tvbuff_t *arbitrary;
      } ber;
      struct {
        int (*type_cb)(tvbuff_t*, int, struct _asn1_ctx_t*, proto_tree*, int);
      } per;
    };
  } external;
} asn1_ctx_t;

extern void asn1_ctx_init(asn1_ctx_t *actx, asn1_enc_e encoding, gboolean aligned, packet_info *pinfo);
extern gboolean asn1_ctx_check_signature(asn1_ctx_t *actx);
extern void asn1_ctx_clean_external(asn1_ctx_t *actx);

extern double asn1_get_real(const guint8 *real_ptr, gint real_len);

/* flags */
#define ASN1_EXT_ROOT 0x01
#define ASN1_EXT_EXT  0x02
#define ASN1_OPT      0x04
#define ASN1_DFLT     0x08

#define ASN1_HAS_EXT(f) ((f)&(ASN1_EXT_ROOT|ASN1_EXT_EXT))


#endif  /* __ASN1_H__ */
