/* atalk-utils.c
 * Routines for Appletalk utilities (DDP, currently).
 *
 * $Id$
 *
 * Simon Wilkinson <sxw@dcs.ed.ac.uk>
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

#include "atalk-utils.h"
#include "emem.h"

gchar *
atalk_addr_to_str(const struct atalk_ddp_addr *addrp)
{
  gchar	*cur;

  cur=ep_alloc(14);
  atalk_addr_to_str_buf(addrp, cur, 14);
  return cur;
}

void
atalk_addr_to_str_buf(const struct atalk_ddp_addr *addrp, gchar *buf, int buf_len)
{
  g_snprintf(buf, buf_len, "%u.%u", addrp->net, addrp->node );
}
