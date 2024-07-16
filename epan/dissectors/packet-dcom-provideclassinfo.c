/* packet-dcom-provideclassinfo.c
 * Routines for DCOM IProvideClassInfo
 *
 * Copyright 2019, Alex Sirr <alexsirruw@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* see packet-dcom.c for details about DCOM */

#include "config.h"

#include <epan/packet.h>
#include "packet-dcerpc.h"
#include "packet-dcom.h"

void proto_register_dcom_provideclassinfo(void);
void proto_reg_handoff_dcom_provideclassinfo(void);

static int hf_provideclassinfo_opnum;
static int hf_typeinfo;

static e_guid_t uuid_provideclassinfo = { 0xb196b283, 0xbab4, 0x101a, { 0xB6, 0x9C, 0x00, 0xAA, 0x00, 0x34, 0x1D, 0x07} };
static uint16_t ver_provideclassinfo;
static int ett_provideclassinfo;
static int proto_provideclassinfo;

static int dissect_IProvideClassInfo_GetClassInfo_rqst(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep)
{
    offset = dissect_dcom_this(tvb, offset, pinfo, tree, di, drep);

    return offset;
}

static int dissect_IProvideClassInfo_GetClassInfo_resp(tvbuff_t *tvb, int offset,
                                            packet_info *pinfo, proto_tree *tree, dcerpc_info *di, uint8_t *drep)
{
    uint32_t u32HResult;

    offset = dissect_dcom_that(tvb, offset, pinfo, tree, di, drep);

    offset = dissect_dcom_PMInterfacePointer(tvb, offset, pinfo, tree, di, drep,
                    hf_typeinfo, NULL);

    offset = dissect_dcom_HRESULT(tvb, offset, pinfo, tree, di, drep,
                                  &u32HResult);

    return offset;
}

/* sub dissector table of IProvideClassInfo interface */
static const dcerpc_sub_dissector provideclassinfo_dissectors[] = {
    {3, "GetClassInfo", dissect_IProvideClassInfo_GetClassInfo_rqst, dissect_IProvideClassInfo_GetClassInfo_resp},
    {0, NULL, NULL, NULL},
};

void proto_register_dcom_provideclassinfo(void)
{
    static hf_register_info hf_provideclassinfo_array[] = {
        {&hf_provideclassinfo_opnum,
         {"Operation", "provideclassinfo.opnum", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        { &hf_typeinfo,
         { "ITypeInfo", "provideclassinfo.itypeinfo", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_provideclassinfo,
    };

    proto_provideclassinfo = proto_register_protocol("DCOM IProvideClassInfo", "IProvideClassInfo", "provideclassinfo");
    proto_register_field_array(proto_provideclassinfo, hf_provideclassinfo_array, array_length(hf_provideclassinfo_array));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dcom_provideclassinfo(void)
{
    dcerpc_init_uuid(proto_provideclassinfo, ett_provideclassinfo,
                     &uuid_provideclassinfo, ver_provideclassinfo,
                     provideclassinfo_dissectors, hf_provideclassinfo_opnum);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
