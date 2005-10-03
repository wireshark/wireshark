/* packet-t38.h
 *
 * Routines for T38 dissection
 * 2003 Hans Viens
 * 2004 Alejandro Vaquero, add support to conversation
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

#define MAX_T38_DATA_ITEMS 4
typedef struct _t38_packet_info {
	guint16 seq_num;	/* UDPTLPacket sequence number */
	guint32 type_msg;	/* 0=t30-indicator    1=data */
	guint32 t30ind_value;
	guint32 data_value;	/* standard and speed */

	int t38_info_data_item_index; /* this will have the number of Data Items in the packet and is used as the index when decoding the packet */
	guint32 data_type[MAX_T38_DATA_ITEMS];
	guint8 *data[MAX_T38_DATA_ITEMS];
	gint data_len[MAX_T38_DATA_ITEMS];
} t38_packet_info;


/* Info to save in T38 conversation / packet-info */
#define MAX_T38_SETUP_METHOD_SIZE 7
struct _t38_conversation_info
{
	gchar   method[MAX_T38_SETUP_METHOD_SIZE + 1];
	guint32 frame_number;
};

/* Add an T38 conversation with the given details */
void t38_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, guint32 setup_frame_number);

ETH_VAR_IMPORT const value_string t30_indicator_vals[];
