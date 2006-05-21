/* packet-wsp.h
 *
 * Declarations for disassembly of WSP component of WAP traffic.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
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

#ifndef __PACKET_WSP_H__
#define __PACKET_WSP_H__


/* These reason codes are used in the WTP dissector as the WTP user is
 * assumed to be WSP */
extern const value_string vals_wsp_reason_codes[];

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libwireshark.dll, we need a special declaration.
 */
ETH_VAR_IMPORT const value_string vals_pdu_type[];
ETH_VAR_IMPORT const value_string vals_status[];
/*
 * exported functionality
 */
void add_post_data (proto_tree *, tvbuff_t *, guint, const char *,
		packet_info *);
guint32 add_content_type (proto_tree *tree, tvbuff_t *tvb,
		guint32 val_start,
		guint32 *well_known_content, const char **textual_content);

/* statistics */
typedef struct _wsp_info_value_t	/* see README.tapping and tap-wspstat.c */
{
	gint status_code;		
	guint8 pdut;
} wsp_info_value_t;
#endif /* packet-wsp.h */
