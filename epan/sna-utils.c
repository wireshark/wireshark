/* sna-utils.c
 * Routines for SNA
 * Gilbert Ramirez <gram@alumni.rice.edu>
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

#include <string.h>

#include "packet_info.h"
#include "wsutil/pint.h"
#include "sna-utils.h"
#include "emem.h"

gchar *
sna_fid_to_str(const address *addr)
{
  gchar	*cur;

  cur=(gchar *)ep_alloc(14);
  sna_fid_to_str_buf(addr, cur, 14);
  return cur;
}

void
sna_fid_to_str_buf(const address *addr, gchar *buf, int buf_len)
{
  const guint8 *addrdata;
  struct sna_fid_type_4_addr sna_fid_type_4_addr;

  switch (addr->len) {

  case 1:
    addrdata = (const guint8 *)addr->data;
    g_snprintf(buf, buf_len, "%04X", addrdata[0]);
    break;

  case 2:
    addrdata = (const guint8 *)addr->data;
    g_snprintf(buf, buf_len, "%04X", pntoh16(&addrdata[0]));
    break;

  case SNA_FID_TYPE_4_ADDR_LEN:
    /* FID Type 4 */
    memcpy(&sna_fid_type_4_addr, addr->data, SNA_FID_TYPE_4_ADDR_LEN);
    g_snprintf(buf, buf_len, "%08X.%04X", sna_fid_type_4_addr.saf,
	    sna_fid_type_4_addr.ef);
    break;
  }
}
