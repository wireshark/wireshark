/* packet-isis.h
 * Defines and such for core isis protcol decode.
 *
 * $Id: packet-isis.h,v 1.2 2000/01/13 06:07:52 guy Exp $
 * Stuart Stanley <stuarts@mxmail.net>
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

#ifndef _PACKET_ISIS_H
#define _PACKET_ISIS_H

/*
 * The version we support is 1
 */
#define ISIS_REQUIRED_VERSION 1

/*
 * ISIS type field values
 */
#define ISIS_TYPE_L1_HELLO		15
#define ISIS_TYPE_L2_HELLO		16
#define ISIS_TYPE_PTP_HELLO		17
#define ISIS_TYPE_L1_LSP		18
#define ISIS_TYPE_L2_LSP		20
#define ISIS_TYPE_L1_CSNP		24
#define ISIS_TYPE_L2_CSNP		25
#define ISIS_TYPE_L1_PSNP		26
#define ISIS_TYPE_L2_PSNP		27

/*
 * The common first 8 octets of the ISIS protocol header.
 */
typedef struct {
	guint8	isis_irpd;		/* Intradomain Routing Protocol Descriminator.  Must be 0x83 */
	guint8	isis_header_length;	/* header length in octets */
	guint8	isis_version;		/* isis version, must be 0x01 */
	guint8	isis_reserved;		/* res byte, must be 0 */
	guint8	isis_type_reserved;	/* packet type & reserved */
#define ISIS_TYPE_MASK 	0x1f
#define ISIS_R8_MASK	0x80
#define ISIS_R7_MASK	0x40
#define ISIS_R6_MASK	0x20
	guint8	isis_version2;		/* another version(?!), must be 0x01 */

	guint8	isis_eco;		/* ECO, must be 0 */
	guint8	isis_user_eco;		/* user ECO, must be 0 */
} isis_hdr_t;

#define isis_type isis_type_reserved&ISIS_TYPE_MASK
#define isis_r8 isis_type_reserved&ISIS_R8_MASK
#define isis_r7 isis_type_reserved&ISIS_R7_MASK
#define isis_r6 isis_type_reserved&ISIS_R6_MASK

/*
 * published API functions
 */
extern char *isis_address_to_string ( const u_char *pd, int offset, int len );
extern void dissect_isis(const u_char *pd, int offset, frame_data *fd, 
		proto_tree *tree);
extern void proto_register_isis(void);
extern void isis_dissect_unknown(int offset,guint length,proto_tree *tree,frame_data *fd,
                char *fmat, ...);

#endif /* _PACKET_ISIS_H */
