/* packet-dcerpc-krb5rpc.c
 *
 * Routines for dcerpc DCE/KRB5 interface
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/security.tar.gz security/idl/krb5rpc.idl
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
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-kerberos.h"
#include "packet-dcerpc-dce122.h"

static int proto_krb5rpc = -1;

static gint ett_krb5rpc = -1;


static e_uuid_t uuid_krb5rpc =
  { 0x8f73de50, 0x768c, 0x11ca, {0xbf, 0xfc, 0x08, 0x00, 0x1e, 0x03, 0x94,
				 0x31}
};
static guint16 ver_krb5rpc = 1;
static int hf_krb5rpc_opnum = -1;
static int hf_krb5rpc_sendto_kdc_rqst_keysize = -1;
static int hf_krb5rpc_sendto_kdc_rqst_spare1 = -1;
static int hf_krb5rpc_sendto_kdc_resp_len = -1;
static int hf_krb5rpc_sendto_kdc_resp_max = -1;
static int hf_krb5rpc_sendto_kdc_resp_spare1 = -1;
static int hf_krb5rpc_sendto_kdc_resp_keysize = -1;
static int hf_krb5rpc_sendto_kdc_resp_st = -1;
static int hf_krb5rpc_krb5 = -1;
static gint ett_krb5rpc_krb5 = -1;

static int
krb5rpc_dissect_sendto_kdc_rqst (tvbuff_t * tvb, int offset,
				 packet_info * pinfo, proto_tree * tree,
				 guint8 *drep)
{
  guint32 keysize, spare1, remain;
  proto_item *item;
  tvbuff_t *krb5_tvb;
  proto_tree *subtree;


  /*
   *        [in]        handle_t        h,
   *        [in]        unsigned32      len,
   *        [in, size_is(len)]
   *        byte            message[],
   *        [in]        unsigned32      out_buf_len,
   */

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_krb5rpc_sendto_kdc_rqst_keysize, &keysize);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_krb5rpc_sendto_kdc_rqst_spare1, &spare1);
  item = proto_tree_add_item (tree, hf_krb5rpc_krb5, tvb, offset, -1, TRUE);
  subtree = proto_item_add_subtree (item, ett_krb5rpc_krb5);

  remain = tvb_length_remaining(tvb, offset);
  krb5_tvb = tvb_new_subset (tvb, offset, remain, remain);
  offset = dissect_kerberos_main (krb5_tvb, pinfo, subtree, TRUE, NULL);


  return offset;
}


static int
krb5rpc_dissect_sendto_kdc_resp (tvbuff_t * tvb, int offset,
				 packet_info * pinfo, proto_tree * tree,
				 guint8 *drep)
{
  guint32 resp_len, maxsize, spare1, keysize, remain;
  proto_item *item;
  tvbuff_t *krb5_tvb;
  proto_tree *subtree;


  /*
   *
   *        [out]       unsigned32      *resp_len,
   *        [out, length_is(*resp_len), size_is(out_buf_len)]
   *        byte            out_buf[],
   *        [out]       error_status_t  *st unsigned long
   *
   */

  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_krb5rpc_sendto_kdc_resp_len, &resp_len);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_krb5rpc_sendto_kdc_resp_max, &maxsize);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_krb5rpc_sendto_kdc_resp_spare1, &spare1);
  offset =
    dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
			hf_krb5rpc_sendto_kdc_resp_keysize, &keysize);


  item = proto_tree_add_item (tree, hf_krb5rpc_krb5, tvb, offset, -1, TRUE);
  subtree = proto_item_add_subtree (item, ett_krb5rpc_krb5);
  remain = tvb_length_remaining(tvb, offset);
  krb5_tvb = tvb_new_subset (tvb, offset, remain, remain);

  offset = dissect_kerberos_main (krb5_tvb, pinfo, subtree, TRUE, NULL);
  offset += 16; /* no idea what this is, probably just extended encrypted text. */

  return offset;
}


static dcerpc_sub_dissector krb5rpc_dissectors[] = {
  {0, "rsec_krb5rpc_sendto_kdc", krb5rpc_dissect_sendto_kdc_rqst,
   krb5rpc_dissect_sendto_kdc_resp},
  {0, NULL, NULL, NULL},
};


void
proto_register_krb5rpc (void)
{
  static hf_register_info hf[] = {
    {&hf_krb5rpc_opnum,
     {"hf_krb5rpc_opnum", "hf_krb5rpc_opnum", FT_UINT16, BASE_DEC, NULL, 0x0,
      "", HFILL }},
    {&hf_krb5rpc_sendto_kdc_rqst_keysize,
     {"hf_krb5rpc_sendto_kdc_rqst_keysize",
      "hf_krb5rpc_sendto_kdc_rqst_keysize", FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL}},
    {&hf_krb5rpc_sendto_kdc_rqst_spare1,
     {"hf_krb5rpc_sendto_kdc_rqst_spare1",
      "hf_krb5rpc_sendto_kdc_rqst_spare1", FT_UINT32, BASE_DEC, NULL, 0x0, "",
      HFILL}},
    {&hf_krb5rpc_sendto_kdc_resp_len,
     {"hf_krb5rpc_sendto_kdc_resp_len", "hf_krb5rpc_sendto_kdc_resp_len",
      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_krb5rpc_sendto_kdc_resp_max,
     {"hf_krb5rpc_sendto_kdc_resp_max", "hf_krb5rpc_sendto_kdc_resp_max",
      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_krb5rpc_sendto_kdc_resp_spare1,
     {"hf_krb5rpc_sendto_kdc_resp_spare1",
      "hf_krb5rpc_sendto_kdc_resp_spare1", FT_UINT32, BASE_DEC, NULL, 0x0, "",
      HFILL}},
    {&hf_krb5rpc_sendto_kdc_resp_keysize,
     {"hf_krb5rpc_sendto_kdc_resp_keysize",
      "hf_krb5rpc_sendto_kdc_resp_keysize", FT_UINT32, BASE_DEC, NULL, 0x0,
      "", HFILL}},
    {&hf_krb5rpc_sendto_kdc_resp_st,
     {"hf_krb5rpc_sendto_kdc_resp_st", "hf_krb5rpc_sendto_kdc_resp_st",
      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL}},
    {&hf_krb5rpc_krb5,
     {"hf_krb5rpc_krb5", "hf_krb5rpc_krb5", FT_BYTES, BASE_HEX, NULL, 0x0,
      "krb5_blob", HFILL}},

  };

  static gint *ett[] = {
    &ett_krb5rpc,
    &ett_krb5rpc_krb5,
  };
  proto_krb5rpc =
    proto_register_protocol ("DCE/RPC Kerberos V", "KRB5RPC", "krb5rpc");
  proto_register_field_array (proto_krb5rpc, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_krb5rpc (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_krb5rpc, ett_krb5rpc, &uuid_krb5rpc, ver_krb5rpc,
		    krb5rpc_dissectors, hf_krb5rpc_opnum);
}
