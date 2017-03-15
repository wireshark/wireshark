/* packet-coap.h
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

#ifndef __PACKET_COAP_H__
#define __PACKET_COAP_H__

/* CoAP Message information */
typedef struct {
	const gchar *ctype_str;
	guint ctype_value;
	guint block_number;
	guint block_mflag;
	wmem_strbuf_t *uri_str_strbuf;	/* the maximum is 1024 > 510 = Uri-Host:255 + Uri-Path:255 x 2 */
	wmem_strbuf_t *uri_query_strbuf;	/* the maximum is 1024 >         765 = Uri-Query:255 x 3 */
} coap_info;

/* CoAP Conversation information */
typedef struct {
	wmem_map_t *messages;
} coap_conv_info;

/* CoAP Transaction tracking information */
typedef struct {
	guint32  req_frame;
	guint32  rsp_frame;
	nstime_t req_time;
	wmem_strbuf_t *uri_str_strbuf;
} coap_transaction;

#endif /* __PACKET_COAP_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
