/* packet-osi.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 * Main entrance point and common functions
 *
 * $Id: packet-osi.c,v 1.42 2001/04/01 05:48:14 hagbard Exp $
 * Laurent Deniel <deniel@worldnet.fr>
 * Ralf Schneider <Ralf.Schneider@t-online.de>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <glib.h>
#include "packet.h"
#include "llcsaps.h"
#include "aftypes.h"
#include "nlpid.h"
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-esis.h"


gchar *calc_checksum( tvbuff_t *tvb, int offset, u_int len, u_int checksum) {
  u_int   calc_sum = 0;
  u_int   count    = 0;
  const gchar *buffer;
  guint   available_len;

  if ( 0 == checksum )
    return( "Not Used" );

  available_len = tvb_length_remaining( tvb, offset );
  if ( available_len < len )
    return( "Not checkable - not all of packet was captured" );

  buffer = tvb_get_ptr( tvb, offset, len );
  for ( count = 0; count < len; count++ ) {
    calc_sum += (u_int) buffer[count];
  }
  calc_sum %= 255;  /* modulo 255 divison */
  
  if ( 0 == calc_sum )
    return( "Is good" );
  else
    return( "Is wrong" );	/* XXX - what should the checksum be? */
}


/* main entry point */

const value_string nlpid_vals[] = {
	{ NLPID_NULL,            "NULL" },
	{ NLPID_T_70,            "T.70" },
	{ NLPID_X_633,           "X.633" },
	{ NLPID_Q_931,           "Q.931" },
	{ NLPID_Q_2931,          "Q.2931" },
	{ NLPID_Q_2119,          "Q.2119" },
	{ NLPID_SNAP,            "SNAP" },
	{ NLPID_ISO8473_CLNP,    "CLNP" },
	{ NLPID_ISO9542_ESIS,    "ESIS" },
	{ NLPID_ISO10589_ISIS,   "ISIS" },
	{ NLPID_ISO10747_IDRP,   "IDRP" },
	{ NLPID_ISO9542X25_ESIS, "ESIS (X.25)" },
	{ NLPID_ISO10030,        "ISO 10030" },
	{ NLPID_ISO11577,        "ISO 11577" },
	{ NLPID_COMPRESSED,      "Data compression protocol" },
	{ NLPID_IP,              "IP" },
	{ NLPID_PPP,             "PPP" },
	{ 0,                     NULL },
};

dissector_table_t osinl_subdissector_table;

static void dissect_osi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
  guint8 nlpid;

  pinfo->current_proto = "OSI";

  nlpid = tvb_get_guint8(tvb, 0);

  /* do lookup with the subdissector table */
  if (dissector_try_port(osinl_subdissector_table, nlpid, tvb, pinfo, tree))
      return;

  switch (nlpid) {

    /* ESIS (X.25) is not currently decoded */

    case NLPID_ISO9542X25_ESIS:
      if (check_col(pinfo->fd, COL_PROTOCOL)) {
	col_set_str(pinfo->fd, COL_PROTOCOL, "ESIS (X.25)");
      }
      dissect_data(tvb, 0, pinfo, tree);
      break;
    case NLPID_ISO10747_IDRP:
      if (check_col(pinfo->fd, COL_PROTOCOL)) {
        col_set_str(pinfo->fd, COL_PROTOCOL, "IDRP");
      }
      dissect_data(tvb, 0, pinfo, tree);
      break;
    default:
      if (check_col(pinfo->fd, COL_PROTOCOL)) {
	col_set_str(pinfo->fd, COL_PROTOCOL, "ISO");
      }
      if (check_col(pinfo->fd, COL_INFO)) {
	col_add_fstr(pinfo->fd, COL_INFO, "Unknown ISO protocol (%02x)", nlpid);
      }
      dissect_data(tvb, 0, pinfo, tree);
      break;
  }
} /* dissect_osi */

void
proto_register_osi(void)
{
	/* There's no "OSI" protocol *per se*, but we do register a
	   dissector table so various protocols running at the
	   network layer can register themselves. */
	osinl_subdissector_table = register_dissector_table("osinl");
}

void
proto_reg_handoff_osi(void)
{
	dissector_add("llc.dsap", SAP_OSINL, dissect_osi, -1);
	dissector_add("null.type", BSD_AF_ISO, dissect_osi, -1);
}
