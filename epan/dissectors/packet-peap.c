/* packet-peap.c
 * Routines for PEAP (Protected Extensible Authentication Protocol)
 * draft-kamath-pppext-peapv0
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>

#include <epan/packet.h>
#include <epan/eap.h>
#include <epan/expert.h>
#include <wsutil/pint.h>
#include <epan/proto_data.h>

void proto_register_peap(void);
void proto_reg_handoff_peap(void);

static int proto_peap;
static int proto_eap;

static dissector_handle_t peap_handle;
static dissector_handle_t eap_handle;

/*
  From draft-kamath-pppext-peapv0, sec 1.1

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |   Identifier  |            Length             | <-- NOT sent
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |   Value...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   This matches the format of an EAP header but...
    * 'Code', 'Identifier' and 'Length' are NOT sent over the wire
    * 'Code' and 'Identifier' are extracted from the *outer* EAP header
    * 'Length' is derived from the PEAP packet (ie. TLS data frame)
    * ...when 'Type' is 33, the full EAP header is sent
*/

#define EAP_TLS_FLAGS_OFFSET   5
#define EAP_TLS_FLAGS_VERSION  0x07 /* mask */

static int
dissect_peap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int version;
  int len;
  int offset = 0;
  tvbuff_t *eap_tvb, *eap_len_tvb, *next_tvb;
  unsigned char *eap_len_buf;
  uint32_t tls_group = pinfo->curr_proto_layer_num << 16;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "PEAP");
  col_clear(pinfo->cinfo, COL_INFO);

  len = tvb_reported_length(tvb);

  eap_tvb = (tvbuff_t *)p_get_proto_data(pinfo->pool, pinfo, proto_eap, PROTO_DATA_EAP_TVB | tls_group);
  version = tvb_get_uint8(eap_tvb, EAP_TLS_FLAGS_OFFSET) & EAP_TLS_FLAGS_VERSION;
  if (version > 0) {	/* FIXME support v1 and v2 */
    goto ret;
  }

  if (!(   len >= 5
        && tvb_get_bits(tvb, offset, 16, ENC_BIG_ENDIAN) == tvb_get_bits(eap_tvb, 0, 16, ENC_BIG_ENDIAN)
        && tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN) <= tvb_get_uint16(eap_tvb, 2, ENC_BIG_ENDIAN)
        && (
                (tvb_get_uint8(eap_tvb, 0) == EAP_REQUEST && tvb_get_uint8(tvb, offset + 4) == EAP_TYPE_ID)
             || tvb_get_uint8(tvb, offset + 4) == EAP_TYPE_MSAUTH_TLV
           ))) {
    eap_len_buf = (unsigned char *)wmem_alloc(pinfo->pool, 2);
    eap_len_tvb = tvb_new_child_real_data(tvb, eap_len_buf, 2, 2);
    phton16(eap_len_buf, 4 + len);

    next_tvb = tvb_new_composite();
    tvb_composite_append(next_tvb, tvb_new_subset_length(eap_tvb, 0, 2));
    tvb_composite_append(next_tvb, eap_len_tvb);
    tvb_composite_append(next_tvb, tvb_new_subset_length(tvb, offset, 4 + len));
    tvb_composite_finalize(next_tvb);

    add_new_data_source(pinfo, next_tvb, "Pseudo EAP");
  } else {
    next_tvb = tvb;
  }

  call_dissector(eap_handle, next_tvb, pinfo, tree);

ret:
  return len;
}

void
proto_register_peap(void)
{
  proto_peap = proto_register_protocol("Protected Extensible Authentication Protocol",
                                       "PEAP", "peap");
  peap_handle = register_dissector("peap", dissect_peap, proto_peap);
}

void
proto_reg_handoff_peap(void)
{
  proto_eap = proto_get_id_by_filter_name("eap");
  eap_handle = find_dissector_add_dependency("eap", proto_peap);
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
