/* packet-isis-lsp.h
 * Defines and such for LSP and their CLV decodes
 *
 * $Id: packet-isis-lsp.h,v 1.2 2000/06/19 08:33:49 guy Exp $
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

#ifndef _PACKET_ISIS_LSP_H
#define _PACKET_ISIS_LSP_H

/*
 * Declarations for L1/L2 LSP base header.  
 */

#define ISIS_LSP_PARTITION_MASK	0x80
#define ISIS_LSP_ATT_MASK	0x78
#define ISIS_LSP_ATT_SHIFT	3
#define ISIS_LSP_HIPPITY_MASK	0x04
#define ISIS_LSP_IS_TYPE_MASK	0x03

#define ISIS_LSP_PARTITION(x)	(x&ISIS_LSP_PARTITION_MASK)
#define ISIS_LSP_ATT(x)		((x&ISIS_LSP_ATT_MASK)>>ISIS_LSP_ATT_SHIFT)
#define ISIS_LSP_HIPPITY(x)	(x&ISIS_LSP_HIPPITY_MASK)
#define ISIS_LSP_IS_TYPE(x)	(x&ISIS_LSP_IS_TYPE_MASK)

#define ISIS_LSP_TYPE_UNUSED0		0
#define ISIS_LSP_TYPE_LEVEL_1		1
#define ISIS_LSP_TYPE_UNUSED2		2
#define ISIS_LSP_TYPE_LEVEL_2		3

#define ISIS_LSP_CLV_METRIC_SUPPORTED(x)	((x)&0xf0)
#define ISIS_LSP_CLV_METRIC_RESERVED(x)		((x)&0x40)
#define ISIS_LSP_CLV_METRIC_VALUE(x)		((x)&0x3f)

/*
 * detail clv information on L1 lsp packets
 */
#define ISIS_CLV_L1_LSP_AREA_ADDRESS		1
#define ISIS_CLV_L1_LSP_IS_NEIGHBORS		2
#define ISIS_CLV_L1_LSP_ES_NEIGHBORS		3
#define ISIS_CLV_L1_LSP_IP_INT_REACHABLE	128
#define ISIS_CLV_L1_LSP_NLPID			129
#define ISIS_CLV_L1_LSP_IP_INTERFACE_ADDR	132
/* 
 * Note, the spec say 133, but everyone seems to use 10. Any clue on why
 * this is would be appreciated!
 */
#define ISIS_CLV_L1_LSP_AUTHENTICATION_NS	10	/* non spec */
#define ISIS_CLV_L1_LSP_AUTHENTICATION		133

/*
 * detail clv information on L2 lsp packets
 */
#define ISIS_CLV_L2_LSP_AREA_ADDRESS		1
#define ISIS_CLV_L2_LSP_IS_NEIGHBORS		2
#define ISIS_CLV_L2_LSP_PARTITION_DIS		4
#define ISIS_CLV_L2_LSP_PREFIX_NEIGHBORS	5
#define ISIS_CLV_L2_LSP_IP_INT_REACHABLE	128
#define ISIS_CLV_L2_LSP_NLPID			129
#define ISIS_CLV_L2_LSP_IP_EXT_REACHABLE	130
#define ISIS_CLV_L2_LSP_IDRP_INFO		131
#define ISIS_CLV_L2_LSP_IP_INTERFACE_ADDR	132
/* 
 * Note, the spec say 133, but everyone seems to use 10. Any clue on why
 * this is would be appreciated!
 */
#define ISIS_CLV_L2_LSP_AUTHENTICATION_NS	10  	/*non spec */
#define ISIS_CLV_L2_LSP_AUTHENTICATION		133

/*
 * Published API functions.  NOTE, this are "local" API functions and
 * are only valid from with isis decodes.
 */
extern void isis_dissect_isis_lsp(int hello_type, int header_length,
	int id_length, const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree);
extern void isis_lsp_decode_lsp_id(char *tstr, proto_tree *tree,
	const u_char *pd, int offset, int id_length);

#endif /* _PACKET_ISIS_LSP_H */
