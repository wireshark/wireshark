/* packet-enc.c
 *
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/aftypes.h>
#include <wsutil/pint.h>

void proto_register_enc(void);
void proto_reg_handoff_enc(void);

/* The header in OpenBSD Encapsulating Interface files. */

struct enchdr {
  guint32 af;
  guint32 spi;
  guint32 flags;
};
#define BSD_ENC_HDRLEN    12

#define BSD_ENC_M_CONF          0x0400  /* payload encrypted */
#define BSD_ENC_M_AUTH          0x0800  /* payload authenticated */
#define BSD_ENC_M_COMP          0x1000  /* payload compressed */
#define BSD_ENC_M_AUTH_AH       0x2000  /* header authenticated */

static dissector_table_t enc_dissector_table;

/* header fields */
static int proto_enc = -1;
static int hf_enc_af = -1;
static int hf_enc_spi = -1;
static int hf_enc_flags = -1;
static int hf_enc_flags_payload_enc = -1;
static int hf_enc_flags_payload_auth = -1;
static int hf_enc_flags_payload_compress = -1;
static int hf_enc_flags_header_auth = -1;

static gint ett_enc = -1;
static gint ett_enc_flag = -1;

static gboolean
capture_enc(const guchar *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  guint32 af;

  if (!BYTES_ARE_IN_FRAME(0, len, BSD_ENC_HDRLEN))
    return FALSE;

  af = pntoh32(pd);
  return try_capture_dissector("enc", af, pd, BSD_ENC_HDRLEN, len, cpinfo, pseudo_header);
}

static const value_string af_vals[] = {
  { BSD_AF_INET,  "IPv4" },
  { BSD_AF_INET6_BSD, "IPv6" },
  { 0, NULL }
};

static int
dissect_enc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  struct enchdr  ench;
  tvbuff_t      *next_tvb;
  proto_tree    *enc_tree;
  proto_item    *ti;

  static const int *flags[] = {
    &hf_enc_flags_payload_enc,
    &hf_enc_flags_payload_auth,
    &hf_enc_flags_payload_compress,
    &hf_enc_flags_header_auth,
    NULL
  };

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENC");

  ench.af = tvb_get_ntohl(tvb, 0);
  ench.spi = tvb_get_ntohl(tvb, 4);

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_enc, tvb, 0,
                                        BSD_ENC_HDRLEN,
                                        "Enc %s, SPI 0x%8.8x",
                                        val_to_str(ench.af, af_vals, "unknown (%u)"),
                                        ench.spi);
    enc_tree = proto_item_add_subtree(ti, ett_enc);

    proto_tree_add_item(enc_tree, hf_enc_af, tvb, 0, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(enc_tree, hf_enc_spi, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(enc_tree, tvb, 8, hf_enc_flags, ett_enc_flag, flags, ENC_BIG_ENDIAN);
  }

  /* Set the tvbuff for the payload after the header */
  next_tvb = tvb_new_subset_remaining(tvb, BSD_ENC_HDRLEN);
  if (!dissector_try_uint(enc_dissector_table, ench.af, next_tvb, pinfo, tree))
    call_data_dissector(next_tvb, pinfo, tree);

  return tvb_captured_length(tvb);
}

void
proto_register_enc(void)
{
  static hf_register_info hf[] = {
    { &hf_enc_af,
      { "Address Family", "enc.af", FT_UINT32, BASE_DEC, VALS(af_vals), 0x0,
        "Protocol (IPv4 vs IPv6)", HFILL }},
    { &hf_enc_spi,
      { "SPI", "enc.spi", FT_UINT32, BASE_HEX, NULL, 0x0,
        "Security Parameter Index", HFILL }},
    { &hf_enc_flags,
      { "Flags", "enc.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
        "ENC flags", HFILL }},
    { &hf_enc_flags_payload_enc,
      { "Payload encrypted", "enc.flags.payload_enc", FT_BOOLEAN, 32, NULL, BSD_ENC_M_CONF,
        NULL, HFILL }},
    { &hf_enc_flags_payload_auth,
      { "Payload encrypted", "enc.flags.payload_auth", FT_BOOLEAN, 32, NULL, BSD_ENC_M_AUTH,
        NULL, HFILL }},
    { &hf_enc_flags_payload_compress,
      { "Payload encrypted", "enc.flags.payload_compress", FT_BOOLEAN, 32, NULL, BSD_ENC_M_COMP,
        NULL, HFILL }},
    { &hf_enc_flags_header_auth,
      { "Payload encrypted", "enc.flags.header_auth", FT_BOOLEAN, 32, NULL, BSD_ENC_M_AUTH_AH,
        NULL, HFILL }},
  };
  static gint *ett[] =
  {
      &ett_enc,
      &ett_enc_flag
  };

  proto_enc = proto_register_protocol("OpenBSD Encapsulating device",
                                      "ENC", "enc");
  proto_register_field_array(proto_enc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  enc_dissector_table = register_dissector_table("enc", "OpenBSD Encapsulating device", proto_enc, FT_UINT32, BASE_DEC);
  register_capture_dissector_table("enc", "ENC");
}

void
proto_reg_handoff_enc(void)
{
  dissector_handle_t enc_handle;

  enc_handle  = create_dissector_handle(dissect_enc, proto_enc);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ENC, enc_handle);

  register_capture_dissector("wtap_encap", WTAP_ENCAP_ENC, capture_enc, proto_enc);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
