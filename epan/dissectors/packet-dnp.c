/* packet-DNP3.c
 * Routines for DNP dissection
 * Copyright 2003, Graham Bloice <graham.bloice@trihedral.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include "reassemble.h"

/* DNP 3.0 constants */
#define DNP_HDR_LEN     10
#define TCP_PORT_DNP    20000
#define DNP3_CTL_DIR    0x80
#define DNP3_CTL_PRM    0x40
#define DNP3_CTL_FCB    0x20
#define DNP3_CTL_FCV    0x10
#define DNP3_CTL_RES    0x20
#define DNP3_CTL_DFC    0x10
#define DNP3_CTL_FUNC   0x0f

#define DNP3_DL_LEN_OFFS  0x02
#define DNP3_DL_CTL_OFFS  0x03
#define DNP3_DL_DST_OFFS  0x04
#define DNP3_DL_SRC_OFFS  0x06

#define DNP3_TR_FIR   0x40
#define DNP3_TR_FIN   0x80
#define DNP3_TR_SEQ   0x3f

#define AL_MAX_CHUNK_SIZE 16

#define DNP3_AL_CON   0x20
#define DNP3_AL_FIN   0x40
#define DNP3_AL_FIR   0x80
#define DNP3_AL_SEQ   0x1f
#define DNP3_AL_FUNC  0xff

#define DNP3_AL_CTL_OFFS  0x0
#define DNP3_AL_FUNC_OFFS 0x1

/* DL Function codes */
#define DL_FUNC_RESET_LINK  0x0
#define DL_FUNC_RESET_PROC  0x1
#define DL_FUNC_TEST_LINK 0x2
#define DL_FUNC_USER_DATA 0x3
#define DL_FUNC_UNC_DATA  0x4
#define DL_FUNC_LINK_STAT 0x9

#define DL_FUNC_ACK   0x0
#define DL_FUNC_NACK    0x1
#define DL_FUNC_STAT_LINK 0xB
#define DL_FUNC_NO_FUNC   0xE
#define DL_FUNC_NOT_IMPL  0xF

/* AL Function codes */
#define DL_AL_FUNC_CONFIRM  0x0
#define DL_AL_FUNC_READ     0x01
#define DL_AL_FUNC_WRITE    0x02
#define DL_AL_FUNC_DIROP    0x05
#define DL_AL_FUNC_RESPON   0x81

/* Initialize the protocol and registered fields */
static int proto_dnp3 = -1;
static int hf_dnp3_start = -1;
static int hf_dnp3_len = -1;
static int hf_dnp3_ctl = -1;
static int hf_dnp3_ctl_prifunc = -1;
static int hf_dnp3_ctl_secfunc = -1;
static int hf_dnp3_ctl_dir = -1;
static int hf_dnp3_ctl_prm = -1;
static int hf_dnp3_ctl_fcb = -1;
static int hf_dnp3_ctl_fcv = -1;
static int hf_dnp3_ctl_dfc = -1;
static int hf_dnp3_dst = -1;
static int hf_dnp3_src = -1;
static int hf_dnp_hdr_CRC = -1;
static int hf_dnp_hdr_CRC_bad = -1;
static int hf_dnp3_tr_ctl = -1;
static int hf_dnp3_tr_fin = -1;
static int hf_dnp3_tr_fir = -1;
static int hf_dnp3_tr_seq = -1;
static int hf_dnp3_al_ctl = -1;
static int hf_dnp3_al_fir = -1;
static int hf_dnp3_al_fin = -1;
static int hf_dnp3_al_con = -1;
static int hf_dnp3_al_seq = -1;
static int hf_dnp3_al_func = -1;

/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int hf_fragments = -1;
static int hf_fragment = -1;
static int hf_fragment_overlap = -1;
static int hf_fragment_overlap_conflict = -1;
static int hf_fragment_multiple_tails = -1;
static int hf_fragment_too_long_fragment = -1;
static int hf_fragment_error = -1;
static int hf_fragment_reassembled_in = -1;

/* Control Function Code Values */
static const value_string dnp3_ctl_func_pri_vals[] = {
  { DL_FUNC_RESET_LINK, "Reset of remote link" },
  { DL_FUNC_RESET_PROC, "Reset of user process" },
  { DL_FUNC_TEST_LINK,  "Test function for link" },
  { DL_FUNC_USER_DATA,  "User Data" },
  { DL_FUNC_UNC_DATA,   "Unconfirmed User Data" },
  { DL_FUNC_LINK_STAT,  "Request Link Status" },
  { 0, NULL }
};

static const value_string dnp3_ctl_func_sec_vals[] = {
  { DL_FUNC_ACK,        "ACK" },
  { DL_FUNC_NACK,       "NACK" },
  { DL_FUNC_STAT_LINK,  "Status of Link" },
  { DL_FUNC_NO_FUNC,    "Link service not functioning" },
  { DL_FUNC_NOT_IMPL,   "Link service not used or implemented" },
  { 0,  NULL }
};

static const value_string dnp3_ctl_flags_pri_vals[] = {
  { DNP3_CTL_DIR, "DIR" },
  { DNP3_CTL_PRM, "PRM" },
  { DNP3_CTL_FCB, "FCB" },
  { DNP3_CTL_FCV, "FCV" },
  { 0,  NULL }
};

static const value_string dnp3_ctl_flags_sec_vals[] = {
  { DNP3_CTL_DIR, "DIR" },
  { DNP3_CTL_PRM, "PRM" },
  { DNP3_CTL_RES, "RES" },
  { DNP3_CTL_DFC, "DFC" },
  { 0,  NULL }
};

static const value_string dnp3_tr_flags_vals[] = {
  { DNP3_TR_FIN,  "FIN" },
  { DNP3_TR_FIR,  "FIR" },
  { 0,  NULL }
};

static const value_string dnp3_al_flags_vals[] = {
  { DNP3_AL_FIR,  "FIR" },
  { DNP3_AL_FIN,  "FIN" },
  { DNP3_AL_CON,  "CON" },
  { 0,  NULL }
};

/* Control Function Code Values */
static const value_string dnp3_al_func_vals[] = {
  { DL_AL_FUNC_CONFIRM, "Confirm" },
  { DL_AL_FUNC_READ,    "Read" },
  { DL_AL_FUNC_WRITE,   "Write" },
  { DL_AL_FUNC_DIROP,   "Direct Operate" },
  { DL_AL_FUNC_RESPON,  "Response" },
  { 0, NULL }
};

/* Initialize the subtree pointers */
static gint ett_dnp3 = -1;
static gint ett_dnp3_dl = -1;
static gint ett_dnp3_dl_ctl = -1;
static gint ett_dnp3_tr_ctl = -1;
static gint ett_dnp3_al_data = -1;
static gint ett_dnp3_al = -1;
static gint ett_dnp3_al_ctl = -1;
static gint ett_fragment = -1;
static gint ett_fragments = -1;

/* Tables for reassembly of fragments. */
static GHashTable *al_fragment_table = NULL;
static GHashTable *al_reassembled_table = NULL;

static const fragment_items frag_items = {
  &ett_fragment,
  &ett_fragments,
  &hf_fragments,
  &hf_fragment,
  &hf_fragment_overlap,
  &hf_fragment_overlap_conflict,
  &hf_fragment_multiple_tails,
  &hf_fragment_too_long_fragment,
  &hf_fragment_error,
  &hf_fragment_reassembled_in,
  "fragments"
};

/*****************************************************************/
/*                                                               */
/* CRC LOOKUP TABLE                                              */
/* ================                                              */
/* The following CRC lookup table was generated automagically    */
/* by the Rocksoft^tm Model CRC Algorithm Table Generation       */
/* Program V1.0 using the following model parameters:            */
/*                                                               */
/*    Width   : 2 bytes.                                         */
/*    Poly    : 0x3D65                                           */
/*    Reverse : TRUE.                                            */
/*                                                               */
/* For more information on the Rocksoft^tm Model CRC Algorithm,  */
/* see the document titled "A Painless Guide to CRC Error        */
/* Detection Algorithms" by Ross Williams                        */
/* (ross@guest.adelaide.edu.au.). This document is likely to be  */
/* in the FTP archive "ftp.adelaide.edu.au/pub/rocksoft".        */
/*                                                               */
/*****************************************************************/

static guint16 crctable[256] =
{
 0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
 0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
 0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
 0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
 0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
 0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
 0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
 0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
 0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
 0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
 0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
 0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
 0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
 0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
 0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
 0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
 0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
 0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
 0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
 0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
 0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
 0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
 0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
 0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
 0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
 0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
 0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
 0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
 0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
 0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
 0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
 0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235
};

/*****************************************************************/
/*                   End of CRC Lookup Table                     */
/*****************************************************************/

/* calculates crc given a buffer of characters and a length of buffer */
static guint16
calculateCRC(const void *buf, guint len) {
  guint16 crc = 0;
  const guint8 *p = (const guint8 *)buf;
  while(len-- > 0)
    crc = crctable[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return ~crc;
}

/* function to print list of bit flags */
static guint
flags_to_str(guint8 val, const value_string *vs, gchar *const str)
{
  guint i, fpos;

  i = fpos = 0;
  while (vs[i].strptr) {
    if (val & vs[i].value) {
      if (fpos) {
        strcpy(&str[fpos], ", ");
        fpos += 2;
      }
      strcpy(&str[fpos], vs[i].strptr);
      fpos += strlen(vs[i].strptr);
    }
    i++;
  }
  return fpos;
}

/* Code to actually dissect the packets */

/* Application layer dissector */
static void
dissect_dnp3_al(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  guint8        al_ctl, al_seq, al_func;
  gboolean      al_fir, al_fin, al_con;
  gchar         flags[64] = "<None>";
  guint         fpos = 0;
  int           offset = 0;
  proto_item   *ti = NULL, *tc;
  proto_tree   *al_tree = NULL, *field_tree = NULL;
  const gchar  *func_code_str;

  /* Handle the control byte and function code */
  al_ctl = tvb_get_guint8(tvb, DNP3_AL_CTL_OFFS);
  al_seq = al_ctl & DNP3_AL_SEQ;
  al_fir = al_ctl & DNP3_AL_FIR;
  al_fin = al_ctl & DNP3_AL_FIN;
  al_con = al_ctl & DNP3_AL_CON;
  al_func = tvb_get_guint8(tvb, DNP3_AL_FUNC_OFFS);
  func_code_str = val_to_str(al_func, dnp3_al_func_vals, "Unknown function (0x%02x)");

  if (tree) {
    /* format up the text representation */

    fpos = flags_to_str(al_ctl, dnp3_al_flags_vals, flags);
    if (fpos) {
      strcpy(&flags[fpos], ", ");
      fpos += 2;
    }
    flags[fpos] = '\0';

    /* Add the al tree branch */
    ti = proto_tree_add_text(tree, tvb, offset, -1,
           "Application Layer: (%sSequence %d, %s)",
           flags, al_seq, func_code_str);
    al_tree = proto_item_add_subtree(ti, ett_dnp3_al);

    /* al control byte subtree */
    tc = proto_tree_add_uint_format(al_tree, hf_dnp3_al_ctl, tvb, offset, 1, al_ctl,
            "Control: 0x%02x (%sSequence %d)", al_ctl, flags, al_seq);
    field_tree = proto_item_add_subtree(tc, ett_dnp3_al_ctl);
    proto_tree_add_boolean(field_tree, hf_dnp3_al_fir, tvb, offset, 1, al_ctl);
    proto_tree_add_boolean(field_tree, hf_dnp3_al_fin, tvb, offset, 1, al_ctl);
    proto_tree_add_boolean(field_tree, hf_dnp3_al_con, tvb, offset, 1, al_ctl);
    proto_tree_add_item(field_tree, hf_dnp3_al_seq, tvb, offset, 1, al_ctl);
    offset += 1;

    /* AL function code byte  */
    proto_tree_add_uint_format(al_tree, hf_dnp3_al_func, tvb, offset, 1, al_func,
                "Function Code: %s (0x%02x)", func_code_str, al_func);
    offset += 1;
  }
  else
    offset += 2;  /* No tree, correct offset */


}

/* Data Link and Transport layer dissector */
static void
dissect_dnp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item   *ti = NULL, *tdl, *tc, *al_chunks;
    proto_tree   *dnp3_tree = NULL, *dl_tree = NULL, *tr_tree = NULL, *field_tree = NULL, *al_tree = NULL;
    int           offset = 0;
    gboolean      dl_prm, tr_fir, tr_fin;
    guint8        dl_len, dl_ctl, dl_func, tr_ctl, tr_seq;
    guint         fpos = 0;
    gchar         flags[64] = "<None>";
    const gchar  *func_code_str;
    guint16       dl_dst, dl_src, dl_crc, calc_dl_crc;
    guint8       *tmp = NULL, *tmp_ptr;
    guint8        data_len;
    gboolean      crc_OK = FALSE;
    tvbuff_t     *al_tvb = NULL;
    guint         i;
    static guint  seq_number = 0;

/* Make entries in Protocol column and Info column on summary display */
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNP 3.0");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  dl_len = tvb_get_guint8(tvb, DNP3_DL_LEN_OFFS);
  dl_ctl = tvb_get_guint8(tvb, DNP3_DL_CTL_OFFS);
  dl_dst = tvb_get_letohs(tvb, DNP3_DL_DST_OFFS);
  dl_src = tvb_get_letohs(tvb, DNP3_DL_SRC_OFFS);
  dl_func = dl_ctl & DNP3_CTL_FUNC;
  dl_prm = dl_ctl & DNP3_CTL_PRM;
  func_code_str = val_to_str(dl_func, dl_prm ? dnp3_ctl_func_pri_vals : dnp3_ctl_func_sec_vals,
           "Unknown function (0x%02x)");

  if (check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "len=%d, from %d to %d, %s",
            dl_len, dl_src, dl_dst, func_code_str);

  if (tree) {

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dnp3, tvb, offset, -1, FALSE);
    dnp3_tree = proto_item_add_subtree(ti, ett_dnp3);

    /* format up the text representation of the flags and function code */
    fpos = flags_to_str(dl_ctl, dl_prm ? dnp3_ctl_flags_pri_vals : dnp3_ctl_flags_sec_vals, flags);
    if (fpos) {
      strcpy(&flags[fpos], ", ");
      fpos += 2;
    }
    strcpy(&flags[fpos], func_code_str);
    fpos += strlen(func_code_str);
    flags[fpos] = '\0';

    /* create subtree for data link layer */
    tdl = proto_tree_add_text(dnp3_tree, tvb, offset, DNP_HDR_LEN,
            "Data Link Layer, Len: %d, From: %d, To: %d, %s",
            dl_len, dl_src, dl_dst, flags);
    dl_tree = proto_item_add_subtree(tdl, ett_dnp3_dl);

    /* start bytes */
    proto_tree_add_item(dl_tree, hf_dnp3_start, tvb, offset, 2, FALSE);
    offset += 2;

    /* add length field */
    proto_tree_add_item(dl_tree, hf_dnp3_len, tvb, offset, 1, FALSE);
    offset += 1;

    /* add control byte subtree */
    tc = proto_tree_add_uint_format(dl_tree, hf_dnp3_ctl, tvb, offset, 1, dl_ctl,
            "Control: 0x%02x (%s)", dl_ctl, flags);
    field_tree = proto_item_add_subtree(tc, ett_dnp3_dl_ctl);

    if (dl_prm) {
      proto_tree_add_boolean(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, dl_ctl);
      proto_tree_add_boolean(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, dl_ctl);
      proto_tree_add_boolean(field_tree, hf_dnp3_ctl_fcb, tvb, offset, 1, dl_ctl);
      proto_tree_add_boolean(field_tree, hf_dnp3_ctl_fcv, tvb, offset, 1, dl_ctl);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_prifunc, tvb, offset, 1, FALSE);
    }
    else {
      proto_tree_add_boolean(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, dl_ctl);
      proto_tree_add_boolean(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, dl_ctl);
      proto_tree_add_boolean(field_tree, hf_dnp3_ctl_dfc, tvb, offset, 1, dl_ctl);
      proto_tree_add_item(field_tree, hf_dnp3_ctl_secfunc, tvb, offset, 1, FALSE);
    }
      offset += 1;

    /* add destination and source addresses */
    proto_tree_add_item(dl_tree, hf_dnp3_dst, tvb, offset, 2, TRUE);
    offset += 2;
    proto_tree_add_item(dl_tree, hf_dnp3_src, tvb, offset, 2, TRUE);
    offset += 2;

    /* and header CRC */
    dl_crc = tvb_get_letohs(tvb, offset);
    calc_dl_crc = calculateCRC(tvb_get_ptr(tvb, 0, DNP_HDR_LEN - 2), DNP_HDR_LEN - 2);
    if (dl_crc == calc_dl_crc)
      proto_tree_add_uint_format(dl_tree, hf_dnp_hdr_CRC, tvb, offset, 2,
               dl_crc, "CRC: 0x%04x (correct)", dl_crc);
    else {
      proto_tree_add_boolean_hidden(dl_tree, hf_dnp_hdr_CRC_bad, tvb,
                  offset, 2, TRUE);
      proto_tree_add_uint_format(dl_tree, hf_dnp_hdr_CRC, tvb,
               offset, 2, dl_crc, "CRC: 0x%04x (incorrect, should be 0x%04x)",
                     dl_crc, calc_dl_crc);
    }
    offset += 2;
  }
  else
    offset += 10; /* No tree so correct offset */

  /* get the transport layer byte */
  tr_ctl = tvb_get_guint8(tvb, offset);
  tr_seq = tr_ctl & DNP3_TR_SEQ;
  tr_fir = tr_ctl & DNP3_TR_FIR;
  tr_fin = tr_ctl & DNP3_TR_FIN;

  if (tree) {
    /* format up the text representation */
    strcpy(flags, "<NONE>");

    fpos = flags_to_str(tr_ctl, dnp3_tr_flags_vals, flags);
    if (fpos) {
      strcpy(&flags[fpos], ", ");
      fpos += 2;
    }
    flags[fpos] = '\0';

    tc = proto_tree_add_uint_format(dnp3_tree, hf_dnp3_tr_ctl, tvb, offset, 1, tr_ctl,
            "Transport Layer: 0x%02x (%sSequence %d)", tr_ctl, flags, tr_seq);
    tr_tree = proto_item_add_subtree(tc, ett_dnp3_tr_ctl);
    proto_tree_add_boolean(tr_tree, hf_dnp3_tr_fin, tvb, offset, 1, tr_ctl);
    proto_tree_add_boolean(tr_tree, hf_dnp3_tr_fir, tvb, offset, 1, tr_ctl);
    proto_tree_add_item(tr_tree, hf_dnp3_tr_seq, tvb, offset, 1, tr_ctl);
  }

  /* Allocate AL chunk tree */
  if (tree != NULL) {
    al_chunks = proto_tree_add_text(tr_tree, tvb, offset + 1, -1, "Application data chunks");
    al_tree = proto_item_add_subtree(al_chunks, ett_dnp3_al_data);
  }

  /* extract the application layer data, validating the CRCs */

  data_len = dl_len - 5;
  tmp = g_malloc(data_len);
  tmp_ptr = tmp;
  i = 0;
  while(data_len > 0) {
    guint8 chk_size;
    guint16 calc_crc, act_crc;
    chk_size = MIN(data_len, AL_MAX_CHUNK_SIZE);
    tvb_memcpy(tvb, tmp_ptr, offset, chk_size);
    calc_crc = calculateCRC(tmp_ptr, chk_size);
    offset += chk_size;
    tmp_ptr += chk_size;
    act_crc = tvb_get_letohs(tvb, offset);
    offset += 2;
    crc_OK = calc_crc == act_crc;
    if (crc_OK)
    {
      if (tree)
        proto_tree_add_text(al_tree, tvb, offset - (chk_size + 2), chk_size,
                "Application Chunk %d Len: %d CRC 0x%04x",
                i, chk_size, act_crc);
      data_len -= chk_size;
    }
    else
    {
      if (tree)
        proto_tree_add_text(al_tree, tvb, offset - (chk_size + 2), chk_size,
                "Application Chunk %d Len: %d Bad CRC got 0x%04x expected 0x%04x",
                i, chk_size, act_crc, calc_crc);
      data_len = 0;
      break;
    }
    i++;
  }

  /* if all crc OK, set up new tvb */
  if (crc_OK) {
    al_tvb = tvb_new_real_data(&tmp[1], tmp_ptr-tmp, tmp_ptr-tmp);
    tvb_set_free_cb(al_tvb, g_free);
    tvb_set_child_real_data_tvbuff(tvb, al_tvb);

    /* Check for fragmented packet */
    if (! (tr_fir && tr_fin)) {
      /* A fragmented packet */

      fragment_data *fd_head;

      /* if first fragment, update sequence id */
      if (tr_fir) seq_number++;

      /*
      * If we've already seen this frame, look it up in the
      * table of reassembled packets, otherwise add it to
      * whatever reassembly is in progress, if any, and see
      * if it's done.
      */
      fd_head = fragment_add_seq_check(al_tvb, 0, pinfo, seq_number,
               al_fragment_table,
               al_reassembled_table,
               tr_seq,
               tvb_reported_length(al_tvb),
               !tr_fin);
      if (fd_head != NULL) {
        /* We have the complete payload */
        al_tvb = tvb_new_real_data(fd_head->data, fd_head->len, fd_head->len);
        tvb_set_child_real_data_tvbuff(tvb, al_tvb);
        add_new_data_source(pinfo, al_tvb, "Reassembled DNP 3.0 Application Layer message");

        if (tree)
          /* Show all fragments. */
          show_fragment_seq_tree(fd_head, &frag_items, tr_tree, pinfo, al_tvb);
      }
      else {
        /* We don't have the complete reassembled payload. */
        al_tvb = NULL;
        if (check_col (pinfo->cinfo, COL_INFO))
          col_append_str (pinfo->cinfo, COL_INFO,
              " (Application Layer Message unreassembled)");
      }
    }
    else {
      /* No reassembly required */
      add_new_data_source(pinfo, al_tvb, "DNP 3.0 Application Layer message");
    }
  }
  else if (tree)
      proto_tree_add_text(dnp3_tree, tvb, 11, -1,
              "Application tvb allocation failed %d chunks", i);

  if (!al_tvb && tmp) g_free(tmp);

  if (al_tvb)
    dissect_dnp3_al(al_tvb, pinfo, dnp3_tree);
}

static void
al_defragment_init(void)
{
  fragment_table_init(&al_fragment_table);
  reassembled_table_init(&al_reassembled_table);
}

/* Register the protocol with Ethereal */

void
proto_register_dnp3(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_dnp3_start,
    { "Start Bytes", "dnp3.start", FT_UINT16, BASE_HEX, NULL, 0x0, "Start Bytes", HFILL }},

    { &hf_dnp3_len,
    { "Length", "dnp3.len", FT_UINT8, BASE_DEC, NULL, 0x0, "Frame Data Length", HFILL }},

    { &hf_dnp3_ctl,
    { "Control", "dnp3.ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "Frame Control Byte", HFILL }},

    { &hf_dnp3_ctl_prifunc,
    { "Control Function Code", "dnp3.ctl.prifunc", FT_UINT8, BASE_DEC,
      VALS(dnp3_ctl_func_pri_vals), DNP3_CTL_FUNC, "Frame Control Function Code", HFILL }},

    { &hf_dnp3_ctl_secfunc,
    { "Control Function Code", "dnp3.ctl.secfunc", FT_UINT8, BASE_DEC,
      VALS(dnp3_ctl_func_sec_vals), DNP3_CTL_FUNC, "Frame Control Function Code", HFILL }},

    { &hf_dnp3_ctl_dir,
    { "Direction", "dnp3.ctl.dir", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_DIR, "", HFILL }},

    { &hf_dnp3_ctl_prm,
    { "Primary", "dnp3.ctl.prm", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_PRM, "", HFILL }},

    { &hf_dnp3_ctl_fcb,
    { "Frame Count Bit", "dnp3.ctl.fcb", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_FCB, "", HFILL }},

    { &hf_dnp3_ctl_fcv,
    { "Frame Count Valid", "dnp3.ctl.fcv", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_FCV, "", HFILL }},

    { &hf_dnp3_ctl_dfc,
    { "Data Flow Control", "dnp3.ctl.dfc", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_CTL_DFC, "", HFILL }},

    { &hf_dnp3_dst,
    { "Destination", "dnp3.dst", FT_UINT16, BASE_DEC, NULL, 0x0, "Destination Address", HFILL }},

    { &hf_dnp3_src,
    { "Source", "dnp3.src", FT_UINT16, BASE_DEC, NULL, 0x0, "Source Address", HFILL }},

    { &hf_dnp_hdr_CRC,
    { "CRC", "dnp.hdr.CRC", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},

    { &hf_dnp_hdr_CRC_bad,
    { "Bad CRC", "dnp.hdr.CRC_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_dnp3_tr_ctl,
    { "Transport Control", "dnp3.tr.ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "Tranport Layer Control Byte", HFILL }},

    { &hf_dnp3_tr_fin,
    { "Final", "dnp3.tr.fin", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_TR_FIN, "", HFILL }},

    { &hf_dnp3_tr_fir,
    { "First", "dnp3.tr.fir", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_TR_FIR, "", HFILL }},

    { &hf_dnp3_tr_seq,
    { "Sequence", "dnp3.tr.seq", FT_UINT8, BASE_DEC, NULL, DNP3_TR_SEQ, "Frame Sequence Number", HFILL }},

    { &hf_dnp3_al_ctl,
    { "Application Control", "dnp3.al.ctl", FT_UINT8, BASE_HEX, NULL, 0x0, "Application Layer Control Byte", HFILL }},

    { &hf_dnp3_al_fir,
    { "First", "dnp3.al.fir", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_AL_FIR, "", HFILL }},

    { &hf_dnp3_al_fin,
    { "Final", "dnp3.al.fin", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_AL_FIN, "", HFILL }},

    { &hf_dnp3_al_con,
    { "Confirm", "dnp3.al.con", FT_BOOLEAN, 8, TFS(&flags_set_truth), DNP3_AL_CON, "", HFILL }},

    { &hf_dnp3_al_seq,
    { "Sequence", "dnp3.al.seq", FT_UINT8, BASE_DEC, NULL, DNP3_AL_SEQ, "Frame Sequence Number", HFILL }},

    { &hf_dnp3_al_func,
    { "Application Layer Function Code", "dnp3.al.func", FT_UINT8, BASE_DEC,
      VALS(dnp3_al_func_vals), DNP3_AL_FUNC, "Application Function Code", HFILL }},

    { &hf_fragment,
    { "DNP 3.0 AL Fragment", "al.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0, "DNP 3.0 Application Layer Fragment", HFILL }},

    { &hf_fragments,
    { "DNP 3.0 AL Fragments", "al.fragments", FT_NONE, BASE_NONE, NULL, 0x0, "DNP 3.0 Application Layer Fragments", HFILL }},

    { &hf_fragment_overlap,
    { "Fragment overlap", "al.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

    { &hf_fragment_overlap_conflict,
    { "Conflicting data in fragment overlap", "al.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Overlapping fragments contained conflicting data", HFILL }},

    { &hf_fragment_multiple_tails,
    { "Multiple tail fragments found", "al.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Several tails were found when defragmenting the packet", HFILL }},

    { &hf_fragment_too_long_fragment,
    { "Fragment too long", "al.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
      "Fragment contained data past end of packet", HFILL }},

    { &hf_fragment_error,
    { "Defragmentation error", "al.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
      "Defragmentation error due to illegal fragments", HFILL }},
    { &hf_fragment_reassembled_in,
    { "Reassembled PDU In Frame", "al.fragment.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
      "This PDU is reassembled in this frame", HFILL }}
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_dnp3,
    &ett_dnp3_dl,
    &ett_dnp3_dl_ctl,
    &ett_dnp3_tr_ctl,
    &ett_dnp3_al_data,
    &ett_dnp3_al,
    &ett_dnp3_al_ctl,
    &ett_fragment,
    &ett_fragments
  };

/* Register the protocol name and description */
  proto_dnp3 = proto_register_protocol("Distributed Network Protocol 3.0",
                   "DNP 3.0", "dnp3");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_dnp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  al_defragment_init();
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_dnp3(void)
{
  dissector_handle_t dnp3_handle;

  dnp3_handle = create_dissector_handle(dissect_dnp3, proto_dnp3);
  dissector_add("tcp.port", TCP_PORT_DNP, dnp3_handle);
}
