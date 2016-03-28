/* packet-bencode.c
 * Routines for bencode dissection
 * Copyright (C) 2004,2013 Jelmer Vernooij <jelmer@samba.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/strutil.h>

void proto_register_bencode(void);

static int proto_bencode = -1;

static gint hf_bencode_str_length     = -1;
static gint hf_bencode_str            = -1;
static gint hf_bencode_int            = -1;
static gint hf_bencode_dict           = -1;
static gint hf_bencode_dict_entry     = -1;
static gint hf_bencode_list           = -1;
static gint hf_bencode_truncated_data = -1;

static gint ett_bencode_dict = -1;
static gint ett_bencode_dict_entry = -1;
static gint ett_bencode_list = -1;

static expert_field ei_bencode_str        = EI_INIT;
static expert_field ei_bencode_str_length = EI_INIT;
static expert_field ei_bencode_int        = EI_INIT;
static expert_field ei_bencode_nest       = EI_INIT;
static expert_field ei_bencode_dict_key   = EI_INIT;
static expert_field ei_bencode_dict_value = EI_INIT;
static expert_field ei_bencode_invalid    = EI_INIT;

static int dissect_bencoding_str(tvbuff_t *tvb, packet_info *pinfo,
                                 int offset, int length, proto_tree *tree, proto_item *ti, int treeadd)
{
   guint8 ch;
   int stringlen = 0, nextstringlen;
   int used;
   int izero = 0;

   if (length < 2) {
      proto_tree_add_expert(tree, pinfo, &ei_bencode_str, tvb, offset, length);
      return -1;
   }

   used = 0;

   while (length >= 1) {
      ch = tvb_get_guint8(tvb, offset + used);
      length--;
      used++;

      if ((ch == ':') && (used > 1)) {
         if ((stringlen > length) || (stringlen < 0)) {
            proto_tree_add_expert(tree, pinfo, &ei_bencode_str_length, tvb, offset, length);
            return -1;
         }
         if (tree) {
            proto_tree_add_uint(tree, hf_bencode_str_length, tvb, offset, used, stringlen);
            proto_tree_add_item(tree, hf_bencode_str, tvb, offset + used, stringlen, ENC_ASCII|ENC_NA);

            if (treeadd == 1) {
               proto_item_append_text(ti, " Key: %s",
                                      format_text((guchar *)tvb_memdup(wmem_packet_scope(),
                                                                       tvb, offset + used, stringlen), stringlen));
            }
            if (treeadd == 2) {
               proto_item_append_text(ti, "  Value: %s",
                                      format_text((guchar *)tvb_memdup(wmem_packet_scope(),
                                                                       tvb, offset + used, stringlen), stringlen));
            }
         }
         return used + stringlen;
      }

      if (!izero && (ch >= '0') && (ch <= '9')) {
         if ((ch == '0') && (used == 1)) {
            izero = 1;
         }

         nextstringlen = (stringlen * 10) + (ch - '0');
         if (nextstringlen >= stringlen) {
            stringlen = nextstringlen;
            continue;
         }
      }

      proto_tree_add_expert(tree, pinfo, &ei_bencode_str, tvb, offset, length);
      return -1;
   }

   proto_tree_add_item(tree, hf_bencode_truncated_data, tvb, offset, length, ENC_NA);
   return -1;
}

static int dissect_bencoding_int(tvbuff_t *tvb, packet_info *pinfo,
                                 int offset, int length, proto_tree *tree, proto_item *ti, int treeadd)
{
   gint32 ival  = 0;
   int    neg   = 0;
   int    izero = 0;
   int    used;
   guint8 ch;

   if (length<3) {
      proto_tree_add_expert(tree, pinfo, &ei_bencode_int, tvb, offset, length);
      return -1;
   }

   length--;
   used = 1;

   while (length >= 1) {
      ch = tvb_get_guint8(tvb, offset + used);
      length--;
      used++;

      switch (ch) {
      case 'e':
         if (tree) {
            if (neg) ival = -ival;
            proto_tree_add_int(tree, hf_bencode_int, tvb, offset, used, ival);
            if (treeadd == 2) {
               proto_item_append_text(ti, "  Value: %d", ival);
            }
         }
         return used;

      case '-':
         if (used == 2) {
            neg = 1;
            break;
         }
         /* Fall through */

      default:
         if (!((ch == '0') && (used == 3) && neg)) { /* -0 is invalid */
            if ((ch == '0') && (used == 2)) { /* as is 0[0-9]+ */
               izero = 1;
               break;
            }
            if (!izero && (ch >= '0') && (ch <= '9')) {
               ival = (ival * 10) + (ch - '0');
               break;
            }
         }

         proto_tree_add_expert(tree, pinfo, &ei_bencode_int, tvb, offset, length);
         return -1;
      }
   }

   proto_tree_add_item(tree, hf_bencode_truncated_data, tvb, offset, length, ENC_NA);
   return -1;
}

static int dissect_bencoding_rec(tvbuff_t *tvb, packet_info *pinfo,
                                 int offset, int length, proto_tree *tree, int level, proto_item *treei, int treeadd)
{
   guint8 op;
   int oplen = 0, op1len, op2len;
   int used;

   proto_item *ti = NULL, *td = NULL;
   proto_tree *itree = NULL, *dtree = NULL;

   if (level > 10) {
      proto_tree_add_expert(tree, pinfo, &ei_bencode_nest, tvb, offset, -1);
      return -1;
   }
   if (length < 1) {
      proto_tree_add_item(tree, hf_bencode_truncated_data, tvb, offset, -1, ENC_NA);
      return length;
   }

   op = tvb_get_guint8(tvb, offset);
   oplen = dissect_bencoding_rec(tvb, pinfo, offset, length, NULL, level + 1, NULL, 0);
   if (oplen < 0)
      oplen = length;

   switch (op) {
   case 'd':
      td = proto_tree_add_item(tree, hf_bencode_dict, tvb, offset, oplen, ENC_NA);
      dtree = proto_item_add_subtree(td, ett_bencode_dict);

      used = 1;
      length--;

      while (length >= 1) {
         op = tvb_get_guint8(tvb, offset + used);

         if (op == 'e') {
            return used + 1;
         }

         op1len = dissect_bencoding_str(tvb, pinfo, offset + used, length, NULL, NULL, 0);
         if (op1len < 0) {
            proto_tree_add_expert(dtree, pinfo, &ei_bencode_dict_key, tvb, offset + used, -1);
            return op1len;
         }

         op2len = -1;
         if ((length - op1len) > 2)
            op2len = dissect_bencoding_rec(tvb, pinfo, offset + used + op1len, length - op1len, NULL, level + 1, NULL, 0);
         if (op2len < 0) {
            proto_tree_add_expert(dtree, pinfo, &ei_bencode_dict_value, tvb, offset + used + op1len, -1);
            return op2len;
         }

         ti = proto_tree_add_item(dtree, hf_bencode_dict_entry, tvb, offset + used, op1len + op2len, ENC_NA);
         itree = proto_item_add_subtree(ti, ett_bencode_dict_entry);

         dissect_bencoding_str(tvb, pinfo, offset + used, length, itree, ti, 1);
         dissect_bencoding_rec(tvb, pinfo, offset + used + op1len, length - op1len, itree, level + 1, ti, 2);

         used   += op1len + op2len;
         length -= op1len + op2len;
      }

      proto_tree_add_item(dtree, hf_bencode_truncated_data, tvb, offset + used, -1, ENC_NA);
      return -1;

   case 'l':
      ti = proto_tree_add_item(tree, hf_bencode_list, tvb, offset, oplen, ENC_NA);
      itree = proto_item_add_subtree(ti, ett_bencode_list);

      used = 1;
      length--;

      while (length >= 1) {
         op = tvb_get_guint8(tvb, offset + used);

         if (op == 'e') {
            return used + 1;
         }

         oplen = dissect_bencoding_rec(tvb, pinfo, offset + used, length, itree, level + 1, ti, 0);
         if (oplen < 1) return oplen;

         used   += oplen;
         length -= oplen;
      }

      proto_tree_add_item(itree, hf_bencode_truncated_data, tvb, offset + used, -1, ENC_NA);
      return -1;

   case 'i':
      return dissect_bencoding_int(tvb, pinfo, offset, length, tree, treei, treeadd);

   default:
      if ((op >= '1') && (op <= '9')) {
         return dissect_bencoding_str(tvb, pinfo, offset, length, tree, treei, treeadd);
      }

      proto_tree_add_expert(tree, pinfo, &ei_bencode_invalid, tvb, offset, -1);
   }

   return -1;
}

static int dissect_bencoding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   dissect_bencoding_rec(tvb, pinfo, 0, tvb_reported_length(tvb), tree, 0, NULL, 0);
   return tvb_captured_length(tvb);
}

void
proto_register_bencode(void)
{
   static hf_register_info hf[] = {
      { &hf_bencode_str_length,
        { "String Length", "bencode.str.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bencode_str,
        { "String", "bencode.str", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bencode_int,
        { "Integer", "bencode.int", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bencode_dict,
        { "Dictionary", "bencode.dict", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bencode_dict_entry,
        { "Entry", "bencode.dict.entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bencode_list,
        { "List", "bencode.list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
      { &hf_bencode_truncated_data,
        { "Truncated Data", "bencode.truncated_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
      },
   };

   static gint *ett[] = {
      &ett_bencode_dict,
      &ett_bencode_dict_entry,
      &ett_bencode_list,
   };

   static ei_register_info ei[] = {
      { &ei_bencode_str, { "bencode.str.invalid", PI_MALFORMED, PI_ERROR, "Decode Aborted: Invalid String", EXPFILL }},
      { &ei_bencode_str_length, { "bencode.str.length.invalid", PI_MALFORMED, PI_ERROR, "Decode Aborted: Invalid String Length", EXPFILL }},
      { &ei_bencode_int, { "bencode.int.invalid", PI_MALFORMED, PI_ERROR, "Decode Aborted: Invalid Integer", EXPFILL }},
      { &ei_bencode_nest, { "bencode.nest", PI_MALFORMED, PI_ERROR, "Decode Aborted: Nested Too Deep", EXPFILL }},
      { &ei_bencode_dict_key, { "bencode.dict.key_invalid", PI_MALFORMED, PI_ERROR, "Decode Aborted: Invalid Dictionary Key", EXPFILL }},
      { &ei_bencode_dict_value, { "bencode.dict.value_invalid", PI_MALFORMED, PI_ERROR, "Decode Aborted: Invalid Dictionary Value", EXPFILL }},
      { &ei_bencode_invalid, { "bencode.invalid", PI_MALFORMED, PI_ERROR, "Invalid Bencoding", EXPFILL }},
   };

   expert_module_t* expert_bencode;

   proto_bencode = proto_register_protocol("Bencode", "Bencode", "bencode");
   register_dissector("bencode", dissect_bencoding, proto_bencode);
   proto_register_field_array(proto_bencode, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
   expert_bencode = expert_register_protocol(proto_bencode);
   expert_register_field_array(expert_bencode, ei, array_length(ei));
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
