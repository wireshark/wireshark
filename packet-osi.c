/* packet-osi.c
 * Routines for ISO/OSI network and transport protocol packet disassembly
 * Main entrance point and common functions
 *
 * $Id: packet-osi.c,v 1.52 2001/12/10 00:25:31 guy Exp $
 * Laurent Deniel <deniel@worldnet.fr>
 * Ralf Schneider <Ralf.Schneider@t-online.de>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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
#include "ppptypes.h"
#include "packet-osi.h"
#include "packet-isis.h"
#include "packet-esis.h"


cksum_status_t
calc_checksum( tvbuff_t *tvb, int offset, u_int len, u_int checksum) {
  const gchar *buffer;
  guint   available_len;
  const guint8 *p;
  guint32 c0, c1;
  u_int   seglen;
  u_int   i;

  if ( 0 == checksum )
    return( NO_CKSUM );

  available_len = tvb_length_remaining( tvb, offset );
  if ( available_len < len )
    return( DATA_MISSING );

  buffer = tvb_get_ptr( tvb, offset, len );

  /*
   * The maximum values of c0 and c1 will occur if all bytes have the
   * value 255; if so, then c0 will be len*255 and c1 will be
   * (len*255 + (len-1)*255 + ... + 255), which is
   * (len + (len - 1) + ... + 1)*255, or 255*(len*(len + 1))/2.
   * This means it can overflow if "len" is 5804 or greater.
   *
   * (A+B) mod 255 = ((A mod 255) + (B mod 255) mod 255, so
   * we can solve this by taking c0 and c1 mod 255 every
   * 5803 bytes.
   */
  p = buffer;
  c0 = 0;
  c1 = 0;
  while (len != 0) {
    seglen = len;
    if (seglen > 5803)
      seglen = 5803;
    for (i = 0; i < seglen; i++) {
      c0 = c0 + *(p++);
      c1 += c0;
    }

    c0 = c0 % 255;
    c1 = c1 % 255;

    len -= seglen;
  }
  if (c0 != 0 || c1 != 0)
    return( CKSUM_NOT_OK );	/* XXX - what should the checksum be? */
  else
    return( CKSUM_OK );
}


/* main entry point */

/*
 * These assume the NLPID is a secondary protocol identifier, not an
 * initial protocol identifier.
 *
 * This is an issue only if, in any packet where an NLPID appears, it's
 * an initial protocol identifier *AND* it can have the value 1, which
 * means T.70 for an IPI and X.29 for an SPI.
 */
const value_string nlpid_vals[] = {
	{ NLPID_NULL,            "NULL" },
	{ NLPID_SPI_X_29,        "X.29" },
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
	{ NLPID_IP6,             "IPv6" },
	{ NLPID_PPP,             "PPP" },
	{ 0,                     NULL },
};

dissector_table_t osinl_subdissector_table;
static dissector_handle_t data_handle;

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
      if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESIS (X.25)");
      }
      call_dissector(data_handle,tvb, pinfo, tree);
      break;
    case NLPID_ISO10747_IDRP:
      if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "IDRP");
      }
      call_dissector(data_handle,tvb, pinfo, tree);
      break;
    default:
      if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO");
      }
      if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown ISO protocol (%02x)", nlpid);
      }
      call_dissector(data_handle,tvb, pinfo, tree);
      break;
  }
} /* dissect_osi */

void
proto_register_osi(void)
{
	/* There's no "OSI" protocol *per se*, but we do register a
	   dissector table so various protocols running at the
	   network layer can register themselves. */
	osinl_subdissector_table = register_dissector_table("osinl",
	    "OSI NLPID", FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_osi(void)
{
	dissector_handle_t osi_handle;

	osi_handle = create_dissector_handle(dissect_osi, -1);
	dissector_add("llc.dsap", SAP_OSINL, osi_handle);
        dissector_add("ppp.protocol", PPP_OSI, osi_handle);
	dissector_add("null.type", BSD_AF_ISO, osi_handle);
	dissector_add("gre.proto", SAP_OSINL, osi_handle);
	data_handle = find_dissector("data");
}
