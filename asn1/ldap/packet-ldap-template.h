/* packet-ldap.h
 * Routines for ros packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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

#ifndef __PACKET_LDAP_H__
#define __PACKET_LDAP_H__

# include <epan/packet.h>  /* for dissector_*_t types */

/*
 * These are all APPLICATION types; the value is the type tag.
 */
#define LDAP_REQ_BIND               0
#define LDAP_REQ_UNBIND             2
#define LDAP_REQ_SEARCH             3
#define LDAP_REQ_MODIFY             6
#define LDAP_REQ_ADD                8
#define LDAP_REQ_DELETE             10
#define LDAP_REQ_MODRDN             12
#define LDAP_REQ_COMPARE            14
#define LDAP_REQ_ABANDON            16
#define LDAP_REQ_EXTENDED           23	/* LDAP V3 only */

#define LDAP_RES_BIND               1
#define LDAP_RES_SEARCH_ENTRY       4
#define LDAP_RES_SEARCH_REF         19	/* LDAP V3 only */
#define LDAP_RES_SEARCH_RESULT      5
#define LDAP_RES_MODIFY             7
#define LDAP_RES_ADD                9
#define LDAP_RES_DELETE             11
#define LDAP_RES_MODRDN             13
#define LDAP_RES_COMPARE            15
#define LDAP_RES_EXTENDED           24	/* LDAP V3 only */

/*
 * These are all CONTEXT types; the value is the type tag.
 */

/* authentication type tags */
#define LDAP_AUTH_SIMPLE        0
#define LDAP_AUTH_KRBV4LDAP     1	/* LDAP V2 only */
#define LDAP_AUTH_KRBV4DSA      2	/* LDAP V2 only */
#define LDAP_AUTH_SASL          3	/* LDAP V3 only */

/* filter type tags */
#define LDAP_FILTER_AND         0
#define LDAP_FILTER_OR          1
#define LDAP_FILTER_NOT         2
#define LDAP_FILTER_EQUALITY    3
#define LDAP_FILTER_SUBSTRINGS  4
#define LDAP_FILTER_GE          5
#define LDAP_FILTER_LE          6
#define LDAP_FILTER_PRESENT     7
#define LDAP_FILTER_APPROX      8
#define LDAP_FILTER_EXTENSIBLE  9	/* LDAP V3 only */

#define LDAP_MOD_ADD            0
#define LDAP_MOD_DELETE         1
#define LDAP_MOD_REPLACE        2

typedef struct ldap_call_response {
  gboolean is_request;
  guint32 req_frame;
  nstime_t req_time;
  guint32 rep_frame;
  guint messageId;
  guint protocolOpTag;
} ldap_call_response_t;

void register_ldap_name_dissector_handle(const char *attr_type, dissector_handle_t dissector);
void register_ldap_name_dissector(const char *attr_type, dissector_t dissector, int proto);

/*#include "packet-ldap-exp.h" */

#endif  /* PACKET_LDAP_H */


