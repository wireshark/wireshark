/* packet-isis-hello.h
 * Declares for hello handling inside isis.
 *
 * $Id: packet-isis-hello.h,v 1.4 2001/06/23 19:45:12 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
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
 *
 *
 */

#ifndef _PACKET_ISIS_HELLO_H
#define _PACKET_ISIS_HELLO_H

/*
 * Declarations for L1/L2 hello base header.  
 */
#define ISIS_HELLO_CTYPE_MASK		0x03
#define ISIS_HELLO_CT_RESERVED_MASK	0xfc
#define ISIS_HELLO_PRIORITY_MASK	0x7f
#define ISIS_HELLO_P_RESERVED_MASK	0x80

#define ISIS_HELLO_TYPE_RESERVED	0
#define ISIS_HELLO_TYPE_LEVEL_1		1
#define ISIS_HELLO_TYPE_LEVEL_2		2
#define ISIS_HELLO_TYPE_LEVEL_12	3

/*
 * detail clv information on l1 hello packets
 */
#define ISIS_CLV_L1H_AREA_ADDRESS	 1
#define ISIS_CLV_L1H_IS_NEIGHBORS	 6
#define ISIS_CLV_L1H_PADDING		 8
#define ISIS_CLV_L1H_NLPID		 129
#define ISIS_CLV_L1H_IP_INTERFACE_ADDR	 132
#define ISIS_CLV_L1H_MT                  229
#define ISIS_CLV_L1H_IPv6_INTERFACE_ADDR 232

/*
 * Note, the spec say 133, but everyone seems to use 10. Any clue on why
 * this is would be appreciated!
 */
#define ISIS_CLV_L1H_AUTHENTICATION_NS	10	/*non spec */
#define ISIS_CLV_L1H_AUTHENTICATION	133

/*
 * detail clv information on l2 hello packets
 */
#define ISIS_CLV_L2H_AREA_ADDRESS	 1
#define ISIS_CLV_L2H_IS_NEIGHBORS	 6
#define ISIS_CLV_L2H_PADDING		 8
#define ISIS_CLV_L2H_NLPID		 129
#define ISIS_CLV_L2H_IP_INTERFACE_ADDR	 132
#define ISIS_CLV_L2H_MT                  229
#define ISIS_CLV_L2H_IPv6_INTERFACE_ADDR 232
/*
 * Note, the spec say 133, but everyone seems to use 10. Any clue on why
 * this is would be appreciated!
 */
#define ISIS_CLV_L2H_AUTHENTICATION_NS	10	/*non spec */
#define ISIS_CLV_L2H_AUTHENTICATION	133

/*
 * detail clv information on PTP hello packets
 */
#define ISIS_CLV_PTP_AREA_ADDRESS	 1
#define ISIS_CLV_PTP_PADDING		 8
#define ISIS_CLV_PTP_NLPID		 129
#define ISIS_CLV_PTP_IP_INTERFACE_ADDR	 132
#define ISIS_CLV_PTP_MT                  229
#define ISIS_CLV_PTP_IPv6_INTERFACE_ADDR 232
#define ISIS_CLV_PTP_ADJ                 240
/*
 * Note, the spec say 133, but everyone seems to use 10. Any clue on why
 * this is would be appreciated!
 */
#define ISIS_CLV_PTP_AUTHENTICATION_NS	10	/*non spec */
#define ISIS_CLV_PTP_AUTHENTICATION	133

/*
 * Published API functions.  NOTE, this are "local" API functions and
 * are only valid from with isis decodes.
 */
extern void isis_dissect_isis_hello(int hello_type, int header_length,
	int id_length, const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree);
#endif /* _PACKET_ISIS_HELLO_H */
