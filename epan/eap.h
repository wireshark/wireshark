/* eap.h
 * Extenal definitions for EAP Extensible Authentication Protocol dissection
 * RFC 2284, RFC 3748
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __EAP_H__
#define __EAP_H__

#define EAP_REQUEST     1
#define EAP_RESPONSE    2
#define EAP_SUCCESS     3
#define EAP_FAILURE     4

WS_VAR_IMPORT const value_string eap_code_vals[];

#define EAP_TYPE_ID     1
#define EAP_TYPE_NOTIFY 2
#define EAP_TYPE_NAK    3
#define EAP_TYPE_MD5    4
#define EAP_TYPE_TLS   13
#define EAP_TYPE_LEAP  17
#define EAP_TYPE_SIM   18
#define EAP_TYPE_TTLS  21
#define EAP_TYPE_AKA   23
#define EAP_TYPE_PEAP  25
#define EAP_TYPE_MSCHAPV2 26
#define EAP_TYPE_FAST  43
#define EAP_TYPE_EXT  254

WS_VAR_IMPORT const value_string eap_type_vals[];

#endif
