/* sna-utils.c
 * Routines for SNA
 * Gilbert Ramirez <gram@alumni.rice.edu>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include "packet_info.h"
#include "pint.h"
#include "sna-utils.h"
#include "emem.h"

gchar *
sna_fid_to_str(const address *addr)
{
  gchar	*cur;

  cur=ep_alloc(14);
  sna_fid_to_str_buf(addr, cur);
  return cur;
}

void
sna_fid_to_str_buf(const address *addr, gchar *buf)
{
  struct sna_fid_type_4_addr sna_fid_type_4_addr;

  switch (addr->len) {

  case 1:
    sprintf(buf, "%04X", addr->data[0]);
    break;

  case 2:
    sprintf(buf, "%04X", pntohs(&addr->data[0]));
    break;

  case SNA_FID_TYPE_4_ADDR_LEN:
    /* FID Type 4 */
    memcpy(&sna_fid_type_4_addr, addr->data, SNA_FID_TYPE_4_ADDR_LEN);
    sprintf(buf, "%08X.%04X", sna_fid_type_4_addr.saf,
	    sna_fid_type_4_addr.ef);
    break;
  }
}
