/* packet-2dparityfec.c
 * Mark Lewis <mlewis@altera.com>
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

/*
** RTP Payload dissector for packets as specified in:
** Pro-MPEG Code of Practice #3 release 2
**
** This protocol defines a format for FEC data embedded within RTP packets with
** a payload type of 96 (0x60). The format of the FEC packets, which reside within
** the RTP payload, is as follows...
**
**   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**   |         SNBase low bits       |        Length Recovery        |
**   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**   |E| PT recovery |                    Mask                       |
**   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**   |                           TS recovery                         |
**   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**   |X|D|type |index|    Offset     |       NA      |SNBase ext bits|
**   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**   |                                                               |
**   :                          FEC Payload                          :
**   |                                                               |
**   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**
** For more information on this protocol see...
** http://www.pro-mpeg.org/publications/pdf/Vid-on-IP-CoP3-r2.pdf
**
**
** Notes:
**
** This protocol always resides in RTP packets with payload type 96. However,
** type 96 is dynamic and may refer to other protocols. As Pro-MPEG FEC must
** function in the absence of a control channel, and because this data is
** likely to be transmitted within closed networks, no automatic mechanism
** exists for specifying the existance of Pro-MPEG FEC on payload type 96.
** This dissector is thus disabled by default. Dissection of this protocol
** may be enabled from the 2dparityfec panel under Preferences->Protocols.
**
** Mark Lewis - 20th June 2006
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>

/* forward reference */
void proto_reg_handoff_2dparityfec(void);

static gboolean dissect_fec = FALSE;

static int proto_2dparityfec = -1;
static int fec_rtp_payload_type = 96;
static gint ett_2dparityfec = -1;

static int hf_2dparityfec_snbase_low      = -1;
static int hf_2dparityfec_length_recovery = -1;
static int hf_2dparityfec_rfc2733_ext     = -1;
static int hf_2dparityfec_pt_recovery     = -1;
static int hf_2dparityfec_mask            = -1;
static int hf_2dparityfec_ts_recovery     = -1;
static int hf_2dparityfec_ts_pro_mpeg_ext = -1;
static int hf_2dparityfec_row_flag        = -1;
static int hf_2dparityfec_type            = -1;
static int hf_2dparityfec_index           = -1;
static int hf_2dparityfec_offset          = -1;
static int hf_2dparityfec_na              = -1;
static int hf_2dparityfec_snbase_ext      = -1;
static int hf_2dparityfec_payload         = -1;

static const value_string fec_type_names[] = {
   {0, "XOR"},
   {1, "Hamming"},
   {2, "Reed-Solomon"},
   {0, NULL}
};

static void dissect_2dparityfec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   guint8   OffsetField;
   guint8   NAField;
   guint32  SNBase;
   guint8   D;

   /* Extract SNBase */
   SNBase  = (guint32)tvb_get_guint8(tvb, 0)<<8;
   SNBase |= (guint32)tvb_get_guint8(tvb, 1);
   SNBase |= (guint32)tvb_get_guint8(tvb, 15)<<16;

   /* Extract D */
   D = (tvb_get_guint8(tvb, 12)>>6) & 0x1;

   /* Extract Offset and NA */
   OffsetField    = tvb_get_guint8(tvb, 13);
   NAField        = tvb_get_guint8(tvb, 14);

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "2dFEC");

   /* Configure the info column */
   if(D)
   {
      col_add_fstr(pinfo->cinfo, COL_INFO, "Row FEC - SNBase=%u, Offset=%u, NA=%u",
                   SNBase, OffsetField, NAField);
   }
   else
   {
      col_add_fstr(pinfo->cinfo, COL_INFO, "Column FEC - SNBase=%u, Offset=%u, NA=%u",
                   SNBase, OffsetField, NAField);
   }

   if(tree)
   {
      /* we are being asked for details */
      proto_item *ti = NULL;
      proto_tree *tree_2dparityfec = NULL;
      gint offset = 0;

      ti = proto_tree_add_item(tree, proto_2dparityfec, tvb, 0, -1, FALSE);
      tree_2dparityfec = proto_item_add_subtree(ti, ett_2dparityfec);

      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_snbase_low,      tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_length_recovery, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_rfc2733_ext,     tvb, offset, 1, FALSE);
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_pt_recovery,     tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_mask,            tvb, offset, 3, FALSE); offset += 3;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_ts_recovery,     tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_ts_pro_mpeg_ext, tvb, offset, 1, FALSE);
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_row_flag,        tvb, offset, 1, FALSE);
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_type,            tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_index,           tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_offset,          tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_na,              tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_snbase_ext,      tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, hf_2dparityfec_payload,         tvb, offset, -1, ENC_NA);
   }
}

void proto_register_2dparityfec(void)
{
   module_t *module_2dparityfec;

/* Payload type definitions */
static hf_register_info hf[] = {
   {&hf_2dparityfec_snbase_low,
      {   "SNBase low",
         "2dparityfec.snbase_low",
         FT_UINT16,
         BASE_DEC,
         NULL,
         0x0,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_length_recovery,
      {  "Length recovery",
         "2dparityfec.lr",
         FT_UINT16,
         BASE_HEX,
         NULL,
         0x0,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_rfc2733_ext,
      {  "RFC2733 Extension (E)",
         "2dparityfec.e",
         FT_BOOLEAN,
         8,
         NULL,
         0x80,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_pt_recovery,
      {  "Payload Type recovery",
         "2dparityfec.ptr",
         FT_UINT8,
         BASE_HEX,
         NULL,
         0x7f,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_mask,
      {  "Mask",
         "2dparityfec.mask",
         /*FT_UINT32*/FT_UINT24,
         BASE_HEX,
         NULL,
         /*0x00ffffff*/0x0,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_ts_recovery,
      {  "Timestamp recovery",
         "2dparityfec.tsr",
         FT_UINT32,
         BASE_HEX,
         NULL,
         0x0,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_ts_pro_mpeg_ext,
      {  "Pro-MPEG Extension (X)",
         "2dparityfec.x",
         FT_BOOLEAN,
         8,
         NULL,
         0x80,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_row_flag,
      {  "Row FEC (D)",
         "2dparityfec.d",
         FT_BOOLEAN,
         8,
         NULL,
         0x40,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_type,
      {  "Type",
         "2dparityfec.type",
         FT_UINT8,
         BASE_DEC,
         VALS(fec_type_names),
         0x38,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_index,
      {  "Index",
         "2dparityfec.index",
         FT_UINT8,
         BASE_DEC,
         NULL,
         0x07,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_offset,
      {  "Offset",
         "2dparityfec.offset",
         FT_UINT8,
         BASE_DEC,
         NULL,
         0x0,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_na,
      {  "NA",
         "2dparityfec.na",
         FT_UINT8,
         BASE_DEC,
         NULL,
         0x0,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_snbase_ext,
      {  "SNBase ext",
         "2dparityfec.snbase_ext",
         FT_UINT8,
         BASE_DEC,
         NULL,
         0x0,
         NULL,
         HFILL}   },

   {&hf_2dparityfec_payload,
      {  "FEC Payload",
         "2dparityfec.payload",
         FT_BYTES,
         BASE_NONE,
         NULL,
         0x0,
         NULL,
         HFILL}   }


};

/* Setup protocol subtree array */
static gint *ett[] = {
   &ett_2dparityfec,
};

   proto_2dparityfec = proto_register_protocol(
      "Pro-MPEG Code of Practice #3 release 2 FEC Protocol",   /* name */
      "2dparityfec",            /* short name */
      "2dparityfec");           /* abbrev */

   proto_register_field_array(proto_2dparityfec, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));

   module_2dparityfec = prefs_register_protocol(proto_2dparityfec,
                                                proto_reg_handoff_2dparityfec);

   prefs_register_bool_preference(module_2dparityfec, "enable",
        "Decode Pro-MPEG FEC on RTP dynamic payload type 96",
        "Enable this option to recognise all traffic on RTP dynamic payload type 96 (0x60) "
        "as FEC data corresponding to Pro-MPEG Code of Practice #3 release 2",
        &dissect_fec);

}

void proto_reg_handoff_2dparityfec(void)
{
   static dissector_handle_t handle_2dparityfec = NULL;

   if (!handle_2dparityfec) {
      handle_2dparityfec = create_dissector_handle(dissect_2dparityfec,
                                                   proto_2dparityfec);
   }

   if (dissect_fec) {
      dissector_add_uint("rtp.pt", fec_rtp_payload_type, handle_2dparityfec);
   } else {
      dissector_delete_uint("rtp.pt", fec_rtp_payload_type, handle_2dparityfec);
   }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 3
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=3 expandtab:
 * :indentSize=3:tabSize=3:noTabs=true:
 */
