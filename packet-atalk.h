/* packet-atalk.h
 * Definitions for Appletalk packet disassembly (DDP, currently).
 *
 * $Id: packet-atalk.h,v 1.3 2000/05/28 22:59:18 guy Exp $
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
 * DDP packet types.
 */
#define DDP_RTMPDATA	0x01
#define DDP_NBP		0x02
#define DDP_ATP		0x03
#define DDP_AEP		0x04
#define DDP_RTMPREQ	0x05
#define DDP_ZIP		0x06
#define DDP_ADSP	0x07
#define DDP_EIGRP	0x58

/*
 * Routine to take a DDP address and generate a string.
 */
extern gchar *atalk_addr_to_str(const struct atalk_ddp_addr *addrp);

void dissect_ddp(const u_char *, int, frame_data *, proto_tree *);

