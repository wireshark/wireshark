/* packet-dcerpc-sysact.c
 * Routines for the ISystemActivator interface
 * Copyright 2004, Jelmer Vernooij <jelmer@samba.org>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcom.h"


static int proto_ISystemActivator = -1;

static int hf_opnum = -1;
static int hf_sysact_unknown = -1;

static gint ett_ISystemActivator = -1;

static e_uuid_t uuid_ISystemActivator = { 0x000001a0, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };
static guint16  ver_ISystemActivator = 0;


static int
dissect_remsysact_remotecreateinstance_rqst(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_dcom_this(tvb, offset, pinfo, tree, drep);

    /* XXX - what is this? */
    offset = dissect_dcom_nospec_data(tvb, offset, pinfo, tree, drep, 
        4);

	offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 
						hf_sysact_unknown, NULL /* XXX */);

	return offset;
}


static int
dissect_remsysact_remotecreateinstance_resp(tvbuff_t *tvb, int offset,
	packet_info *pinfo, proto_tree *tree, guint8 *drep)
{

    offset = dissect_dcom_that(tvb, offset, pinfo, tree, drep);

	offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, drep, 
						hf_sysact_unknown, NULL /* XXX */);

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, drep, 
					 NULL /* pu32HResult */);

	return offset;
}




static dcerpc_sub_dissector ISystemActivator_dissectors[] = {
    { 0, "QueryInterfaceIRemoteSCMActivator", NULL, NULL },
    { 1, "AddRefIRemoteISCMActivator", NULL, NULL },
    { 2, "ReleaseIRemoteISCMActivator", NULL, NULL },
    { 3, "RemoteGetClassObject", NULL, NULL },
    { 4, "RemoteCreateInstance", dissect_remsysact_remotecreateinstance_rqst, dissect_remsysact_remotecreateinstance_resp },
    { 0, NULL, NULL, NULL },
};

void
proto_register_ISystemActivator (void)
{
	static hf_register_info hf[] = {
		{ &hf_opnum,
		  { "Operation", "isystemactivator.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_sysact_unknown,
		{ "IUnknown", "isystemactivator.unknown", FT_NONE, BASE_HEX, NULL, 0x0, "", HFILL }},
	};
	static gint *ett[] = {
		&ett_ISystemActivator
	};
	proto_ISystemActivator = proto_register_protocol ("ISystemActivator ISystemActivator Resolver", "ISystemActivator", "isystemactivator");
	proto_register_field_array (proto_ISystemActivator, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_ISystemActivator (void)
{
	/* Register the protocol as dcerpc */
	dcerpc_init_uuid (proto_ISystemActivator, ett_ISystemActivator, &uuid_ISystemActivator, ver_ISystemActivator, ISystemActivator_dissectors, hf_opnum);
}
