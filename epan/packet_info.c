/* packet_info.c
 * Routines for handling packet information
 *
 * $Id: packet_info.c,v 1.4 2001/11/03 00:58:52 guy Exp $
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

#include <glib.h>

#include "packet_info.h"

void blank_packetinfo(void)
{
  pi.dl_src.type = AT_NONE;
  pi.dl_dst.type = AT_NONE;
  pi.net_src.type = AT_NONE;
  pi.net_dst.type = AT_NONE;
  pi.src.type = AT_NONE;
  pi.dst.type = AT_NONE;
  pi.ethertype  = 0;
  pi.ipproto  = 0;
  pi.ipxptype = 0;
  pi.in_error_pkt = FALSE;
  pi.ptype = PT_NONE;
  pi.srcport  = 0;
  pi.destport = 0;
  pi.current_proto = "<Missing Protocol Name>";
  pi.p2p_dir = P2P_DIR_UNKNOWN;
  pi.private_data = NULL;
}


