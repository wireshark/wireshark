/* packet-wap.h (c) 2000 Neil Hunter
 * Based on original work by Ben Fowler
 *
 * Declarations for WAP packet disassembly
 *
 * $Id: packet-wap.h,v 1.1 2000/11/04 03:30:40 guy Exp $
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
 *
 */

#ifndef __PACKET_WAP_H__
#define __PACKET_WAP_H__

/* Port Numbers as per IANA */
/* < URL:http://www.isi.edu/in-notes/iana/assignments/port-numbers/ > */
#define UDP_PORT_WSP			9200		/* wap-wsp			*/
#define UDP_PORT_WTP_WSP		9201		/* wap-wsp-wtp		*/
#define UDP_PORT_WTLS_WSP		9202		/* wap-wsp-s		*/
#define UDP_PORT_WTLS_WTP_WSP	9203		/* wap-wsp-wtp-s	*/

#define HF_EMPTY	( -1 )
#define ETT_EMPTY	( -1 )

enum
{
	bo_big_endian		= 0,
	bo_little_endian	= 1
};

#endif /* packet-wap.h */
