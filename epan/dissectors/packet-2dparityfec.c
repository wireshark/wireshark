/* packet-2dparityfec.c
 * Mark Lewis <mlewis@altera.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
** exists for specifying the existence of Pro-MPEG FEC on payload type 96.
** This dissector is thus disabled by default. Dissection of this protocol
** may be enabled from the 2dparityfec panel under Preferences->Protocols.
**
** Mark Lewis - 20th June 2006
*/

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

/* forward reference */
void proto_register_2dparityfec(void);
void proto_reg_handoff_2dparityfec(void);

static dissector_handle_t handle_2dparityfec = NULL;

static gboolean dissect_fec = FALSE;

static int fec_rtp_payload_type = 96;
static gint ett_2dparityfec = -1;

static header_field_info *hfi_2dparityfec = NULL;

#define _2DPARITYFEC_HFI_INIT HFI_INIT(proto_2dparityfec)

static header_field_info hfi_2dparityfec_snbase_low _2DPARITYFEC_HFI_INIT =
{  "SNBase low",
   "2dparityfec.snbase_low",
   FT_UINT16,
   BASE_DEC,
   NULL,
   0x0,
   NULL,
   HFILL};

static header_field_info hfi_2dparityfec_length_recovery _2DPARITYFEC_HFI_INIT =
{ "Length recovery",
  "2dparityfec.lr",
  FT_UINT16,
  BASE_HEX,
  NULL,
  0x0,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_rfc2733_ext _2DPARITYFEC_HFI_INIT =
{ "RFC2733 Extension (E)",
  "2dparityfec.e",
  FT_BOOLEAN,
  8,
  NULL,
  0x80,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_pt_recovery _2DPARITYFEC_HFI_INIT =
{ "Payload Type recovery",
  "2dparityfec.ptr",
  FT_UINT8,
  BASE_HEX,
  NULL,
  0x7f,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_mask _2DPARITYFEC_HFI_INIT =
{ "Mask",
  "2dparityfec.mask",
  /*FT_UINT32*/FT_UINT24,
  BASE_HEX,
  NULL,
  /*0x00ffffff*/0x0,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_ts_recovery _2DPARITYFEC_HFI_INIT =
{ "Timestamp recovery",
  "2dparityfec.tsr",
  FT_UINT32,
  BASE_HEX,
  NULL,
  0x0,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_ts_pro_mpeg_ext _2DPARITYFEC_HFI_INIT =
{ "Pro-MPEG Extension (X)",
  "2dparityfec.x",
  FT_BOOLEAN,
  8,
  NULL,
  0x80,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_row_flag _2DPARITYFEC_HFI_INIT =
{ "Row FEC (D)",
  "2dparityfec.d",
  FT_BOOLEAN,
  8,
  NULL,
  0x40,
  NULL,
  HFILL};

static const value_string fec_type_names[] = {
   {0, "XOR"},
   {1, "Hamming"},
   {2, "Reed-Solomon"},
   {0, NULL}
};

static header_field_info hfi_2dparityfec_type _2DPARITYFEC_HFI_INIT =
{ "Type",
  "2dparityfec.type",
  FT_UINT8,
  BASE_DEC,
  VALS(fec_type_names),
  0x38,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_index _2DPARITYFEC_HFI_INIT =
{ "Index",
  "2dparityfec.index",
  FT_UINT8,
  BASE_DEC,
  NULL,
  0x07,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_offset _2DPARITYFEC_HFI_INIT =
{ "Offset",
  "2dparityfec.offset",
  FT_UINT8,
  BASE_DEC,
  NULL,
  0x0,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_na _2DPARITYFEC_HFI_INIT =
{ "NA",
  "2dparityfec.na",
  FT_UINT8,
  BASE_DEC,
  NULL,
  0x0,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_snbase_ext _2DPARITYFEC_HFI_INIT =
{ "SNBase ext",
  "2dparityfec.snbase_ext",
  FT_UINT8,
  BASE_DEC,
  NULL,
  0x0,
  NULL,
  HFILL};

static header_field_info hfi_2dparityfec_payload _2DPARITYFEC_HFI_INIT =
{ "FEC Payload",
  "2dparityfec.payload",
  FT_BYTES,
  BASE_NONE,
  NULL,
  0x0,
  NULL,
  HFILL};


static int dissect_2dparityfec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
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
      proto_item *ti;
      proto_tree *tree_2dparityfec;
      gint offset = 0;

      ti = proto_tree_add_item(tree, hfi_2dparityfec, tvb, 0, -1, ENC_NA);
      tree_2dparityfec = proto_item_add_subtree(ti, ett_2dparityfec);

      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_snbase_low,      tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_length_recovery, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_rfc2733_ext,     tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_pt_recovery,     tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_mask,            tvb, offset, 3, ENC_BIG_ENDIAN); offset += 3;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_ts_recovery,     tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_ts_pro_mpeg_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_row_flag,        tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_type,            tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_index,           tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_offset,          tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_na,              tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_snbase_ext,      tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
      proto_tree_add_item(tree_2dparityfec, &hfi_2dparityfec_payload,         tvb, offset, -1, ENC_NA);
   }

   return tvb_captured_length(tvb);
}

void proto_register_2dparityfec(void)
{
   module_t *module_2dparityfec;

#ifndef HAVE_HFI_SECTION_INIT
/* Payload type definitions */
   static header_field_info *hfi[] = {
      &hfi_2dparityfec_snbase_low,
      &hfi_2dparityfec_length_recovery,
      &hfi_2dparityfec_rfc2733_ext,
      &hfi_2dparityfec_pt_recovery,
      &hfi_2dparityfec_mask,
      &hfi_2dparityfec_ts_recovery,
      &hfi_2dparityfec_ts_pro_mpeg_ext,
      &hfi_2dparityfec_row_flag,
      &hfi_2dparityfec_type,
      &hfi_2dparityfec_index,
      &hfi_2dparityfec_offset,
      &hfi_2dparityfec_na,
      &hfi_2dparityfec_snbase_ext,
      &hfi_2dparityfec_payload,
   };
#endif

/* Setup protocol subtree array */
   static gint *ett[] = {
      &ett_2dparityfec,
   };

   int proto_2dparityfec;

   proto_2dparityfec = proto_register_protocol(
      "Pro-MPEG Code of Practice #3 release 2 FEC Protocol",   /* name */
      "2dparityfec",            /* short name */
      "2dparityfec");           /* abbrev */
   hfi_2dparityfec = proto_registrar_get_nth(proto_2dparityfec);

   proto_register_fields(proto_2dparityfec, hfi, array_length(hfi));
   proto_register_subtree_array(ett, array_length(ett));

   module_2dparityfec = prefs_register_protocol(proto_2dparityfec,
                                                proto_reg_handoff_2dparityfec);

   prefs_register_bool_preference(module_2dparityfec, "enable",
                                  "Decode Pro-MPEG FEC on RTP dynamic payload type 96",
                                  "Enable this option to recognise all traffic on RTP dynamic payload type 96 (0x60) "
                                  "as FEC data corresponding to Pro-MPEG Code of Practice #3 release 2",
                                  &dissect_fec);

      handle_2dparityfec = create_dissector_handle(dissect_2dparityfec,
                                                   proto_2dparityfec);
}

void proto_reg_handoff_2dparityfec(void)
{
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
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
