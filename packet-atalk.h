/* packet-atalk.h
 * Definitions for Appletalk packet disassembly (DDP, currently).
 *
 * $Id: packet-atalk.h,v 1.1 1999/10/22 08:11:40 guy Exp $
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

/*
 * Structure used to represent a DDP address; gives the layout of the
 * data pointed to by an AT_ATALK "address" structure.
 */
struct atalk_ddp_addr {
	guint16	net;
	guint8	node;
	guint8	port;
};

/*
 * Routine to take a DDP address and generate a string.
 */
extern gchar *atalk_addr_to_str(const struct atalk_ddp_addr *addrp);
