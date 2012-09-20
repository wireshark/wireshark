/* packet-aim.c
 * Routines for AIM Instant Messenger (OSCAR) dissection
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>

#include "packet-aim.h"

/* SNAC families */
#define FAMILY_OFT        0xfffe

static int proto_aim_oft = -1;

/*static int ett_aim_recvfile = -1;
static int ett_aim_sendfile = -1;*/

/* 
 * cookie (8 chars)
 * encrypt (uint16)
 * compress (uint16)
 * totfiles (uint16)
 * filesleft (uint16)
 * totparts (uint16)
 * partsleft (uint16)
 * totsize (uint32)
 * size (uint32)
 * modtime (uint32)
 * checksum (uint32)
 * rfrcsum (uint32)
 * rfsize (uint32)
 * cretime (uint32)
 * rfcsum (uint32)
 * nrecvd (uint32)
 * recvscum (uint32)
 * idstring (32 chars)
 * flags (uint8)
 * lnameoffset (uint8)
 * lsizeoffset (uint8)
 * unknown (69 chars)
 * macfileinfo (16 chars)
 * nencode (uint16)
 * nlanguage (uint16)
 * filename (raw, 64 chars)
 * 
 * length of file (uint16)
 * file data
 */


/* Register the protocol with Wireshark */
void
proto_register_aim_oft(void)
{

/* Setup list of header fields */
/*  static hf_register_info hf[] = {
  };*/

/* Setup protocol subtree array */
/*  static gint *ett[] = {
  };*/

/* Register the protocol name and description */
  proto_aim_oft = proto_register_protocol("AIM OFT", "AIM OFT", "aim_oft");

/* Required function calls to register the header fields and subtrees used */
/*  proto_register_field_array(proto_aim_oft, hf, array_length(hf));*/
/*	proto_register_subtree_array(ett, array_length(ett));*/
}

void
proto_reg_handoff_aim_oft(void)
{
/*  dissector_handle_t aim_handle;*/

  /* FIXME 
  aim_handle = new_create_dissector_handle(dissect_aim, proto_aim);
  dissector_add_uint("tcp.port", TCP_PORT_AIM, aim_handle);*/
}
