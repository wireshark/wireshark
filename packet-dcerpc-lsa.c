/* packet-dcerpc-lsa.c
 * Routines for SMB \\PIPE\\lsarpc packet disassembly
 * Copyright 2001, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-dcerpc-lsa.c,v 1.1 2001/11/21 02:08:57 guy Exp $
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
#include "packet-dcerpc-lsa.h"

static int proto_dcerpc_lsa = -1;
static gint ett_dcerpc_lsa = -1;

static e_uuid_t uuid_dcerpc_lsa = {
        0x12345778, 0x1234, 0xabcd, 
        { 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
};

static guint16 ver_dcerpc_lsa = 0;

static dcerpc_sub_dissector dcerpc_lsa_dissectors[] = {
        { LSA_CLOSE, "LSA_CLOSE", NULL, NULL },
        { LSA_DELETE, "LSA_DELETE", NULL, NULL },
        { LSA_ENUM_PRIVS, "LSA_ENUM_PRIVS", NULL, NULL },
        { LSA_QUERYSECOBJ, "LSA_QUERYSECOBJ", NULL, NULL },
        { LSA_SETSECOBJ, "LSA_SETSECOBJ", NULL, NULL },
        { LSA_CHANGEPASSWORD, "LSA_CHANGEPASSWORD", NULL, NULL },
        { LSA_OPENPOLICY, "LSA_OPENPOLICY", NULL, NULL },
        { LSA_QUERYINFOPOLICY, "LSA_QUERYINFOPOLICY", NULL, NULL },
        { LSA_SETINFOPOLICY, "LSA_SETINFOPOLICY", NULL, NULL },
        { LSA_CLEARAUDITLOG, "LSA_CLEARAUDITLOG", NULL, NULL },
        { LSA_CREATEACCOUNT, "LSA_CREATEACCOUNT", NULL, NULL },
        { LSA_ENUM_ACCOUNTS, "LSA_ENUM_ACCOUNTS", NULL, NULL },
        { LSA_CREATETRUSTDOM, "LSA_CREATETRUSTDOM", NULL, NULL },
        { LSA_ENUMTRUSTDOM, "LSA_ENUMTRUSTDOM", NULL, NULL },
        { LSA_LOOKUPNAMES, "LSA_LOOKUPNAMES", NULL, NULL },
        { LSA_LOOKUPSIDS, "LSA_LOOKUPSIDS", NULL, NULL },
        { LSA_CREATESECRET, "LSA_CREATESECRET", NULL, NULL },
        { LSA_OPENACCOUNT, "LSA_OPENACCOUNT", NULL, NULL },
        { LSA_ENUMPRIVSACCOUNT, "LSA_ENUMPRIVSACCOUNT", NULL, NULL },
        { LSA_ADDPRIVS, "LSA_ADDPRIVS", NULL, NULL },
        { LSA_REMOVEPRIVS, "LSA_REMOVEPRIVS", NULL, NULL },
        { LSA_GETQUOTAS, "LSA_GETQUOTAS", NULL, NULL },
        { LSA_SETQUOTAS, "LSA_SETQUOTAS", NULL, NULL },
        { LSA_GETSYSTEMACCOUNT, "LSA_GETSYSTEMACCOUNT", NULL, NULL },
        { LSA_SETSYSTEMACCOUNT, "LSA_SETSYSTEMACCOUNT", NULL, NULL },
        { LSA_OPENTRUSTDOM, "LSA_OPENTRUSTDOM", NULL, NULL },
        { LSA_QUERYTRUSTDOM, "LSA_QUERYTRUSTDOM", NULL, NULL },
        { LSA_SETINFOTRUSTDOM, "LSA_SETINFOTRUSTDOM", NULL, NULL },
        { LSA_OPENSECRET, "LSA_OPENSECRET", NULL, NULL },
        { LSA_SETSECRET, "LSA_SETSECRET", NULL, NULL },
        { LSA_QUERYSECRET, "LSA_QUERYSECRET", NULL, NULL },
        { LSA_LOOKUPPRIVVALUE, "LSA_LOOKUPPRIVVALUE", NULL, NULL },
        { LSA_LOOKUPPRIVNAME, "LSA_LOOKUPPRIVNAME", NULL, NULL },
        { LSA_PRIV_GET_DISPNAME, "LSA_PRIV_GET_DISPNAME", NULL, NULL },
        { LSA_DELETEOBJECT, "LSA_DELETEOBJECT", NULL, NULL },
        { LSA_ENUMACCTWITHRIGHT, "LSA_ENUMACCTWITHRIGHT", NULL, NULL },
        { LSA_ENUMACCTRIGHTS, "LSA_ENUMACCTRIGHTS", NULL, NULL },
        { LSA_ADDACCTRIGHTS, "LSA_ADDACCTRIGHTS", NULL, NULL },
        { LSA_REMOVEACCTRIGHTS, "LSA_REMOVEACCTRIGHTS", NULL, NULL },
        { LSA_QUERYTRUSTDOMINFO, "LSA_QUERYTRUSTDOMINFO", NULL, NULL },
        { LSA_SETTRUSTDOMINFO, "LSA_SETTRUSTDOMINFO", NULL, NULL },
        { LSA_DELETETRUSTDOM, "LSA_DELETETRUSTDOM", NULL, NULL },
        { LSA_STOREPRIVDATA, "LSA_STOREPRIVDATA", NULL, NULL },
        { LSA_RETRPRIVDATA, "LSA_RETRPRIVDATA", NULL, NULL },
        { LSA_OPENPOLICY2, "LSA_OPENPOLICY2", NULL, NULL },
        { LSA_UNK_GET_CONNUSER, "LSA_UNK_GET_CONNUSER", NULL, NULL },

        {0, NULL, NULL,  NULL },
};

void 
proto_register_dcerpc_lsa(void)
{
        static gint *ett[] = {
                &ett_dcerpc_lsa,
        };

        proto_dcerpc_lsa = proto_register_protocol(
                "Microsoft Local Security Architecture", "LSA", "lsa");

        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dcerpc_lsa(void)
{
        /* Register protocol as dcerpc */

        dcerpc_init_uuid(proto_dcerpc_lsa, ett_dcerpc_lsa, &uuid_dcerpc_lsa,
                         ver_dcerpc_lsa, dcerpc_lsa_dissectors);
}
