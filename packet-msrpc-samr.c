/* packet-msrpc-samr.c
 * Routines for SMB \\PIPE\\samr packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-msrpc-samr.c,v 1.1 2001/11/12 08:58:43 guy Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include "packet.h"
#include "packet-dcerpc.h"
#include "packet-msrpc-samr.h"

static int proto_msrpc_samr = -1;
static gint ett_msrpc_samr = -1;

static e_uuid_t uuid_msrpc_samr = {
        0x12345778, 0x1234, 0xabcd, 
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac}
};

static guint16 ver_msrpc_samr = 1;

static dcerpc_sub_dissector msrpc_samr_dissectors[] = {
        { SAMR_CONNECT_ANON, "SAMR_CONNECT_ANON", NULL, NULL },
        { SAMR_CLOSE_HND, "SAMR_CLOSE_HND", NULL, NULL },
        { SAMR_UNKNOWN_2, "SAMR_UNKNOWN_2", NULL, NULL },
        { SAMR_QUERY_SEC_OBJECT, "SAMR_QUERY_SEC_OBJECT", NULL, NULL },
        { SAMR_UNKNOWN_4, "SAMR_UNKNOWN_4", NULL, NULL },
        { SAMR_LOOKUP_DOMAIN, "SAMR_LOOKUP_DOMAIN", NULL, NULL },
        { SAMR_ENUM_DOMAINS, "SAMR_ENUM_DOMAINS", NULL, NULL },
        { SAMR_OPEN_DOMAIN, "SAMR_OPEN_DOMAIN", NULL, NULL },
        { SAMR_QUERY_DOMAIN_INFO, "SAMR_QUERY_DOMAIN_INFO", NULL, NULL },
        { SAMR_CREATE_DOM_GROUP, "SAMR_CREATE_DOM_GROUP", NULL, NULL },
        { SAMR_ENUM_DOM_GROUPS, "SAMR_ENUM_DOM_GROUPS", NULL, NULL },
        { SAMR_ENUM_DOM_USERS, "SAMR_ENUM_DOM_USERS", NULL, NULL },
        { SAMR_CREATE_DOM_ALIAS, "SAMR_CREATE_DOM_ALIAS", NULL, NULL },
        { SAMR_ENUM_DOM_ALIASES, "SAMR_ENUM_DOM_ALIASES", NULL, NULL },
        { SAMR_QUERY_USERALIASES, "SAMR_QUERY_USERALIASES", NULL, NULL },
        { SAMR_LOOKUP_NAMES, "SAMR_LOOKUP_NAMES", NULL, NULL },
        { SAMR_LOOKUP_RIDS, "SAMR_LOOKUP_RIDS", NULL, NULL },
        { SAMR_OPEN_GROUP, "SAMR_OPEN_GROUP", NULL, NULL },
        { SAMR_QUERY_GROUPINFO, "SAMR_QUERY_GROUPINFO", NULL, NULL },
        { SAMR_SET_GROUPINFO, "SAMR_SET_GROUPINFO", NULL, NULL },
        { SAMR_ADD_GROUPMEM, "SAMR_ADD_GROUPMEM", NULL, NULL },
        { SAMR_DELETE_DOM_GROUP, "SAMR_DELETE_DOM_GROUP", NULL, NULL },
        { SAMR_DEL_GROUPMEM, "SAMR_DEL_GROUPMEM", NULL, NULL },
        { SAMR_QUERY_GROUPMEM, "SAMR_QUERY_GROUPMEM", NULL, NULL },
        { SAMR_UNKNOWN_1A, "SAMR_UNKNOWN_1A", NULL, NULL },
        { SAMR_OPEN_ALIAS, "SAMR_OPEN_ALIAS", NULL, NULL },
        { SAMR_QUERY_ALIASINFO, "SAMR_QUERY_ALIASINFO", NULL, NULL },
        { SAMR_SET_ALIASINFO, "SAMR_SET_ALIASINFO", NULL, NULL },
        { SAMR_DELETE_DOM_ALIAS, "SAMR_DELETE_DOM_ALIAS", NULL, NULL },
        { SAMR_ADD_ALIASMEM, "SAMR_ADD_ALIASMEM", NULL, NULL },
        { SAMR_DEL_ALIASMEM, "SAMR_DEL_ALIASMEM", NULL, NULL },
        { SAMR_QUERY_ALIASMEM, "SAMR_QUERY_ALIASMEM", NULL, NULL },
        { SAMR_OPEN_USER, "SAMR_OPEN_USER", NULL, NULL },
        { SAMR_DELETE_DOM_USER, "SAMR_DELETE_DOM_USER", NULL, NULL },
        { SAMR_QUERY_USERINFO, "SAMR_QUERY_USERINFO", NULL, NULL },
        { SAMR_SET_USERINFO2, "SAMR_SET_USERINFO2", NULL, NULL },
        { SAMR_QUERY_USERGROUPS, "SAMR_QUERY_USERGROUPS", NULL, NULL },
        { SAMR_QUERY_DISPINFO, "SAMR_QUERY_DISPINFO", NULL, NULL },
        { SAMR_UNKNOWN_29, "SAMR_UNKNOWN_29", NULL, NULL },
        { SAMR_UNKNOWN_2a, "SAMR_UNKNOWN_2a", NULL, NULL },
        { SAMR_UNKNOWN_2b, "SAMR_UNKNOWN_2b", NULL, NULL },
        { SAMR_GET_USRDOM_PWINFO, "SAMR_GET_USRDOM_PWINFO", NULL, NULL },
        { SAMR_UNKNOWN_2D, "SAMR_UNKNOWN_2D", NULL, NULL },
        { SAMR_UNKNOWN_2e, "SAMR_UNKNOWN_2e", NULL, NULL },
        { SAMR_UNKNOWN_2f, "SAMR_UNKNOWN_2f", NULL, NULL },
        { SAMR_QUERY_DISPINFO3, "SAMR_QUERY_DISPINFO3", NULL, NULL },
        { SAMR_UNKNOWN_31, "SAMR_UNKNOWN_31", NULL, NULL },
        { SAMR_CREATE_USER, "SAMR_CREATE_USER", NULL, NULL },
        { SAMR_QUERY_DISPINFO4, "SAMR_QUERY_DISPINFO4", NULL, NULL },
        { SAMR_ADDMULTI_ALIASMEM, "SAMR_ADDMULTI_ALIASMEM", NULL, NULL },
        { SAMR_UNKNOWN_35, "SAMR_UNKNOWN_35", NULL, NULL },
        { SAMR_UNKNOWN_36, "SAMR_UNKNOWN_36", NULL, NULL },
        { SAMR_CHGPASSWD_USER, "SAMR_CHGPASSWD_USER", NULL, NULL },
        { SAMR_GET_DOM_PWINFO, "SAMR_GET_DOM_PWINFO", NULL, NULL },
        { SAMR_CONNECT, "SAMR_CONNECT", NULL, NULL },
        { SAMR_SET_USERINFO, "SAMR_SET_USERINFO", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_msrpc_samr(void)
{
        static gint *ett[] = {
                &ett_msrpc_samr,
        };

        proto_msrpc_samr = proto_register_protocol(
                "Microsoft Security Account Manager", "SAMR", "samr");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_msrpc_samr(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_msrpc_samr, ett_msrpc_samr, &uuid_msrpc_samr,
                         ver_msrpc_samr, msrpc_samr_dissectors);
}
