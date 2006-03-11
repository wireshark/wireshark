/* packet-sccp.h
 * Definitions for Signalling Connection Control Part (SCCP) dissection
 *
 * $Id: $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
#ifndef __PACKET_SCCP_H 
#define __PACKET_SCCP_H

typedef enum _sccp_payload_t {
    SCCP_PLOAD_NONE,
    SCCP_PLOAD_RANAP,
    SCCP_PLOAD_TCAP,
    SCCP_PLOAD_CAMEL
} sccp_payload_t;

/* obscure to SCCP, to be defined by users */
typedef struct _sccp_payload_data_t sccp_payload_data_t;

typedef struct _sccp_assoc_info_t {
    guint32 calling_dpc;
    guint32 called_dpc;
    guint8 calling_ssn;
    guint8 called_ssn;
	gboolean has_calling_key;
	gboolean has_called_key;
    sccp_payload_t pload;
    sccp_payload_data_t* private_data;
} sccp_assoc_info_t;

#endif
