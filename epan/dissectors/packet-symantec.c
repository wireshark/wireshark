/* packet-symantec.c
 * Routines for dissection of packets from the Axent Raptor firewall/
 * Symantec Enterprise Firewall/Symantec Gateway Security appliance
 * v2/Symantec Gateway Security appliance v3.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/etypes.h>

void proto_register_symantec(void);
void proto_reg_handoff_symantec(void);

static dissector_handle_t symantec_handle;

static dissector_table_t ethertype_dissector_table;

/* protocols and header fields */
static int proto_symantec = -1;
static int hf_symantec_if = -1;
static int hf_symantec_etype = -1;

static gint ett_symantec = -1;

static int
dissect_symantec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_item *ti;
   proto_tree *symantec_tree;
   guint16 etypev2, etypev3;
   tvbuff_t *next_tvb;

   /*
    * Symantec records come in two variants:
    *
    * The older variant, dating from Axent days and continuing until
    * the SGS v2.0.1 code level, is 44 bytes long.
    * The first 4 bytes are the IPv4 address of the interface that
    * captured the data, followed by 2 bytes of 0, then an Ethernet
    * type, followed by 36 bytes of 0.
    *
    * The newer variant, introduced either in SGS v3.0 or v3.0.1
    * (possibly in concert with VLAN support), is 56 bytes long.
    * The first 4 bytes are the IPv4 address of the interface that
    * captured the data, followed by 6 bytes of 0, then an Ethernet
    * type, followed by 44 bytes of 0.
    *
    * Unfortunately, there is no flag to distiguish between the two
    * flavours.  The only indication of which flavour you have is the
    * offset of the ETHERTYPE field.  Fortunately, Symantec didn't
    * use ETHERTYPE_UNK as a valid value.
    */

   etypev2 = tvb_get_ntohs(tvb, 6);
   etypev3 = tvb_get_ntohs(tvb, 10);

   /* a valid packet can't be both v2 and v3 or neither v2 nor v3, */
   if ((etypev2 == 0) == (etypev3 == 0))
      return 12;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "Symantec");

   if (etypev3 == 0) {    /* SEF and SGS v2 processing */
      col_set_str(pinfo->cinfo, COL_INFO, "Symantec Enterprise Firewall");

      ti = proto_tree_add_protocol_format(tree, proto_symantec, tvb,
            0, 44, "Symantec firewall");
      symantec_tree = proto_item_add_subtree(ti, ett_symantec);
      proto_tree_add_item(symantec_tree, hf_symantec_if, tvb,
            0, 4, ENC_BIG_ENDIAN);
      proto_tree_add_uint(symantec_tree, hf_symantec_etype, tvb,
            6, 2, etypev2);

      next_tvb = tvb_new_subset_remaining(tvb, 44);
      dissector_try_uint(ethertype_dissector_table, etypev2, next_tvb, pinfo,
            tree);
   }

   if (etypev2 == 0) {    /* SGS v3 processing */
      col_set_str(pinfo->cinfo, COL_INFO, "Symantec SGS v3");

      ti = proto_tree_add_protocol_format(tree, proto_symantec, tvb,
            0, 56, "Symantec SGSv3");
      symantec_tree = proto_item_add_subtree(ti, ett_symantec);
      proto_tree_add_item(symantec_tree, hf_symantec_if, tvb,
            0, 4, ENC_BIG_ENDIAN);
      proto_tree_add_uint(symantec_tree, hf_symantec_etype, tvb,
            10, 2, etypev3);

      /*
       * Dissection of VLAN information will have to wait until
       * availability of a capture file from an SGSv3 box using VLAN
       * tagging.
       */
      next_tvb = tvb_new_subset_remaining(tvb, 56);
      dissector_try_uint(ethertype_dissector_table, etypev3, next_tvb, pinfo,
            tree);
   }
   return tvb_captured_length(tvb);
}

void
proto_register_symantec(void)
{
   static hf_register_info hf[] = {
      { &hf_symantec_if,
         { "Interface", "symantec.if", FT_IPv4,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
      { &hf_symantec_etype,
         { "Type",    "symantec.type", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
            NULL, HFILL }},
   };
   static gint *ett[] = {
      &ett_symantec,
   };

   proto_symantec = proto_register_protocol("Symantec Enterprise Firewall",
         "Symantec", "symantec");
   symantec_handle = register_dissector("symantec", dissect_symantec,
         proto_symantec);
   proto_register_field_array(proto_symantec, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_symantec(void)
{
   ethertype_dissector_table = find_dissector_table("ethertype");
   dissector_add_uint("wtap_encap", WTAP_ENCAP_SYMANTEC, symantec_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
