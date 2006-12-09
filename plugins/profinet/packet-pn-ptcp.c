/* packet-pn-ptcp.c
 * Routines for PN-PTCP (PROFINET Precision Time Clock Protocol) 
 * packet dissection.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-dcerpc.h>
#include <epan/oui.h>
#include <epan/expert.h>

static int proto_pn_ptcp = -1;

static int hf_pn_ptcp = -1;
static int hf_pn_ptcp_data = -1;
static int hf_pn_ptcp_header = -1;
static int hf_pn_ptcp_block = -1;
static int hf_pn_ptcp_block_tlvheader = -1;

static int hf_pn_ptcp_res1 = -1;
static int hf_pn_ptcp_res2 = -1;
static int hf_pn_ptcp_delay10ns = -1;
static int hf_pn_ptcp_seq_id = -1;
static int hf_pn_ptcp_delay1ns = -1;
static int hf_pn_ptcp_padding8 = -1;
static int hf_pn_ptcp_padding16 = -1;
static int hf_pn_ptcp_delay1ps = -1;

static int hf_pn_ptcp_tl_length = -1;
static int hf_pn_ptcp_tl_type = -1;

static int hf_pn_ptcp_master_source_address = -1;
static int hf_pn_ptcp_subdomain_uuid = -1;

static int hf_pn_ptcp_request_source_address = -1;
static int hf_pn_ptcp_request_port_id = -1;
static int hf_pn_ptcp_sync_id = -1;

static int hf_pn_ptcp_t2portrxdelay = -1;
static int hf_pn_ptcp_t3porttxdelay = -1;

static int hf_pn_ptcp_seconds = -1;
static int hf_pn_ptcp_nanoseconds = -1;

static int hf_pn_ptcp_flags = -1;
static int hf_pn_ptcp_epochnumber = -1;
static int hf_pn_ptcp_currentutcoffset = -1;

static int hf_pn_ptcp_clock_uuid = -1;
static int hf_pn_ptcp_clockstratum = -1;
static int hf_pn_ptcp_clockvariance = -1;
static int hf_pn_ptcp_clockrole = -1;

static int hf_pn_ptcp_oui = -1;
static int hf_pn_ptcp_unknown_subtype = -1;
static int hf_pn_ptcp_profinet_subtype = -1;
static int hf_pn_ptcp_irdata_uuid = -1;

static gint ett_pn_ptcp = -1;
static gint ett_pn_ptcp_header = -1;
static gint ett_pn_ptcp_block = -1;
static gint ett_pn_ptcp_block_header = -1;

#define OUI_PROFINET_MULTICAST		0x010ECF	/* PROFIBUS Nutzerorganisation e.V. */


static const value_string pn_ptcp_block_type[] = {
	{ 0x00, "End" },
	{ 0x01, "Subdomain"},
	{ 0x02, "Time"},
	{ 0x03, "TimeExtension"},
	{ 0x04, "Master"},
	{ 0x05, "PortParameter"},
	{ 0x06, "DelayParameter"},
    /*0x07 - 0x7E Reserved */
	{ 0x7F, "Organizationally Specific"},

    { 0, NULL }
};

static const value_string pn_ptcp_clock_stratum_vals[] = {
	{ 0x00, "Force" },
	{ 0x01, "Primary"},
	{ 0x02, "Secondary"},
	{ 0x03, "TimingSignal"},
	{ 0x04, "NoTimingSignal"},
    /*0x05 - 0xFE Reserved */
	{ 0xFF, "Default"},

    { 0, NULL }
};

static const value_string pn_ptcp_clock_role_vals[] = {
	{ 0x00, "Reserved" },
	{ 0x01, "Primary PTCP-Master"},
	{ 0x02, "Secondary PTCP-Master"},
    /*0x03 - 0xFF Reserved */

    { 0, NULL }
};

static const value_string pn_ptcp_oui_vals[] = {
	{ OUI_PROFINET,             "PROFINET" },
	{ OUI_PROFINET_MULTICAST,   "PROFINET" },
	{ 0, NULL }
};

static const value_string pn_ptcp_profinet_subtype_vals[] = {
	{ 0x01, "RTData" },

	{ 0, NULL }
};


/* XXX - use include file instead for these helpers */
extern int dissect_pn_uint8(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                  proto_tree *tree, int hfindex, guint8 *pdata);

extern int dissect_pn_uint16(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, guint16 *pdata);

extern int dissect_pn_uint32(tvbuff_t *tvb, gint offset, packet_info *pinfo,
                       proto_tree *tree, int hfindex, guint32 *pdata);



/* dissect an 8 bit unsigned integer */
int
dissect_pn_uint8(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                  proto_tree *tree, int hfindex, guint8 *pdata)
{
    guint8 data;

    data = tvb_get_guint8 (tvb, offset);
    if (tree) {
        proto_tree_add_uint(tree, hfindex, tvb, offset, 1, data);
    }
    if (pdata)
        *pdata = data;
    return offset + 1;
}

/* dissect a 16 bit unsigned integer */
int
dissect_pn_uint16(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, guint16 *pdata)
{
    guint16 data;

    data = tvb_get_ntohs (tvb, offset);

    if (tree) {
        proto_tree_add_uint(tree, hfindex, tvb, offset, 2, data);
    }
    if (pdata)
        *pdata = data;
    return offset + 2;
}

/* dissect a 32 bit unsigned integer */
int
dissect_pn_uint32(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, guint32 *pdata)
{
    guint32 data;

    data = tvb_get_ntohl (tvb, offset);

    if (tree) {
        proto_tree_add_uint(tree, hfindex, tvb, offset, 4, data);
    }
    if (pdata)
        *pdata = data;
    return offset+4;
}

/* dissect a 16 bit signed integer */
int
dissect_pn_int16(tvbuff_t *tvb, gint offset, packet_info *pinfo _U_,
                       proto_tree *tree, int hfindex, gint16 *pdata)
{
    gint16 data;

    data = tvb_get_ntohs (tvb, offset);

    if (tree) {
        proto_tree_add_int(tree, hfindex, tvb, offset, 2, data);
    }
    if (pdata)
        *pdata = data;
    return offset + 2;
}

/* dissect a 24bit OUI (IEC organizational unique id) */
int 
dissect_pn_oid(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, guint32 *pdata)
{
    guint32 data;

    data = tvb_get_ntoh24(tvb, offset);

    if (tree) {
        proto_tree_add_uint(tree, hfindex, tvb, offset, 3, data);
    }
    if (pdata)
        *pdata = data;
    return offset+3;
}

/* dissect a 6 byte MAC address */
int 
dissect_pn_mac(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, guint8 *pdata)
{
    guint8 data[6];

    tvb_memcpy(tvb, data, offset, 6);
    if(tree)
        proto_tree_add_ether(tree, hfindex, tvb, offset, 6, data);

    if (pdata)
        memcpy(pdata, data, 6);

    return offset + 6;
}

/* dissect a 12 byte UUID address */
int 
dissect_pn_uuid(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
                    proto_tree *tree, int hfindex, e_uuid_t *uuid)
{
    guint8 drep[2] = { 0,0 };

    offset = dissect_dcerpc_uuid_t(tvb, offset, pinfo, tree, drep,
                    hfindex, uuid);

    return offset;
}




static int
dissect_PNPTCP_TLVHeader(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 *type, guint16 *length)
{
    guint16 tl_type;
    guint16 tl_length;


    /* Type */
    dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_ptcp_tl_type, &tl_type);
    *type = tl_type >> 9;

    /* Length */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_ptcp_tl_length, &tl_length);
    *length = tl_length & 0x1FF;

    return offset;
}


static int
dissect_PNPTCP_Subdomain(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint8 mac[6];
    e_uuid_t uuid;

    /* MasterSourceAddress */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_ptcp_master_source_address, mac);

    /* SubdomainUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_ptcp_subdomain_uuid, &uuid);

	proto_item_append_text(item, ": MasterSource=%02x:%02x:%02x:%02x:%02x:%02x", 
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    proto_item_append_text(item, ", Subdomain=%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      uuid.Data1, uuid.Data2, uuid.Data3,
                                      uuid.Data4[0], uuid.Data4[1],
                                      uuid.Data4[2], uuid.Data4[3],
                                      uuid.Data4[4], uuid.Data4[5],
                                      uuid.Data4[6], uuid.Data4[7]);

    return offset;
}


static int
dissect_PNPTCP_Time(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 padding16;
    guint32 Seconds;
    guint32 NanoSeconds;


    /* Padding16 */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_ptcp_padding16, &padding16);

    /* Seconds */
    offset = dissect_pn_uint32(tvb, offset, pinfo, tree, hf_pn_ptcp_seconds, &Seconds);

    /* NanoSeconds */
    offset = dissect_pn_uint32(tvb, offset, pinfo, tree, hf_pn_ptcp_nanoseconds, &NanoSeconds);

	proto_item_append_text(item, ": Seconds=%u NanoSeconds=%u", 
        Seconds, NanoSeconds);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, ", Time: %4us %09uns", Seconds, NanoSeconds);

    return offset;
}


static int
dissect_PNPTCP_TimeExtension(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 Flags;
    guint16 EpochNumber;
    guint16 CurrentUTCOffset;


    /* Flags */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_ptcp_flags, &Flags);

    /* EpochNumber */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_ptcp_epochnumber, &EpochNumber);

    /* CurrentUTCOffset */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_ptcp_currentutcoffset, &CurrentUTCOffset);

	proto_item_append_text(item, ": Flags=0x%x, EpochNumber=%u, CurrentUTCOffset=%u", 
        Flags, EpochNumber, CurrentUTCOffset);

    return offset;
}


static int
dissect_PNPTCP_Master(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    e_uuid_t uuid;
    guint8 ClockStratum;
    gint16 ClockVariance;
    guint8 ClockRole;

    /* ClockVariance */
    offset = dissect_pn_int16(tvb, offset, pinfo, tree, hf_pn_ptcp_clockvariance, &ClockVariance);

    /* ClockUUID */
    offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_ptcp_clock_uuid, &uuid);

    /* ClockStratum */
    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_ptcp_clockstratum, &ClockStratum);

    /* ClockRole */
    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_ptcp_clockrole, &ClockRole);

    proto_item_append_text(item, ": ClockUUID=%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      uuid.Data1, uuid.Data2, uuid.Data3,
                                      uuid.Data4[0], uuid.Data4[1],
                                      uuid.Data4[2], uuid.Data4[3],
                                      uuid.Data4[4], uuid.Data4[5],
                                      uuid.Data4[6], uuid.Data4[7]);

	proto_item_append_text(item, ", ClockStratum=%s, ClockVariance=%d", 
        val_to_str(ClockStratum, pn_ptcp_clock_stratum_vals, "(Reserved: 0x%x)"), ClockVariance);

    return offset;
}


static int
dissect_PNPTCP_PortParameter(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint16 padding16;
    guint32 t2portrxdelay;
    guint32 t3porttxdelay;


    /* Padding16 */
    offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_ptcp_padding16, &padding16);

    /* T2PortRxDelay */
    offset = dissect_pn_uint32(tvb, offset, pinfo, tree, hf_pn_ptcp_t2portrxdelay, &t2portrxdelay);

    /* T3PortTxDelay */
    offset = dissect_pn_uint32(tvb, offset, pinfo, tree, hf_pn_ptcp_t3porttxdelay, &t3porttxdelay);

	proto_item_append_text(item, ": T2PortRxDelay=%uns, T3PortTxDelay=%uns", 
        t2portrxdelay, t3porttxdelay);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, ", T2Rx=%uns, T3Tx=%uns", 
        t2portrxdelay, t3porttxdelay);

    return offset;
}


static int
dissect_PNPTCP_DelayParameter(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    guint8 mac[6];
    guint8 requestportid;
    guint8 syncid;


    /* RequestSourceAddress */
    offset = dissect_pn_mac(tvb, offset, pinfo, tree, hf_pn_ptcp_request_source_address, mac);

    /* RequestPortID */
    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_ptcp_request_port_id, &requestportid);

    /* SyncID */
    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_ptcp_sync_id, &syncid);

    
    proto_item_append_text(item, ": RequestSource=%02x:%02x:%02x:%02x:%02x:%02x", 
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    proto_item_append_text(item, ", RequestPortID=0x%02x, SyncID=0x%02x", 
        requestportid, syncid);

    return offset;
}


static int
dissect_PNPTCP_Option_PROFINET(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length)
{
    guint8 subType;
    guint16 padding16;
    e_uuid_t uuid;
    proto_item *unknown_item;

    /* OUI already dissected! */

    /* SubType */
    offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_ptcp_profinet_subtype, &subType);
    length --;

    switch(subType) {
    case 1: /* RTData */
        /* Padding16 */
        offset = dissect_pn_uint16(tvb, offset, pinfo, tree, hf_pn_ptcp_padding16, &padding16);

        /* IRDataUUID */
        offset = dissect_pn_uuid(tvb, offset, pinfo, tree, hf_pn_ptcp_irdata_uuid, &uuid);
        proto_item_append_text(item, ": IRDataUUID=%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                      uuid.Data1, uuid.Data2, uuid.Data3,
                                      uuid.Data4[0], uuid.Data4[1],
                                      uuid.Data4[2], uuid.Data4[3],
                                      uuid.Data4[4], uuid.Data4[5],
                                      uuid.Data4[6], uuid.Data4[7]);

        break;
    default:
        unknown_item = proto_tree_add_string_format(tree, hf_pn_ptcp_data, tvb, offset, length, "data", 
            "PROFINET Data: %d bytes", length);
        expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_WARN,
			"Unknown subType %u, %u bytes",
			subType, length);
        break;
    }

    return offset;
}


static int
dissect_PNPTCP_Option(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length)
{
	guint32 oui;
	guint8 subType;
    proto_item *unknown_item;


    /* verify remaining TLV length */
	if (length < 4)
	{
        if (tree) {
            proto_tree_add_string_format(tree, hf_pn_ptcp_data, tvb, offset, length, "data", 
                "Length: %u (too short, must be >= 4)", length);
        }
		return (offset);
	}

	/* OUI (organizational unique id) */
    offset = dissect_pn_oid(tvb, offset, pinfo,tree, hf_pn_ptcp_oui, &oui);
    length -= 3;
	
	switch (oui)
	{
	case OUI_PROFINET:
	case OUI_PROFINET_MULTICAST:
        proto_item_append_text(item, ": PROFINET");
        offset = dissect_PNPTCP_Option_PROFINET(tvb, offset, pinfo, tree, item, length);
		break;
	default:
        /* SubType */
        offset = dissect_pn_uint8(tvb, offset, pinfo, tree, hf_pn_ptcp_unknown_subtype, &subType);
        length --;
        unknown_item = proto_tree_add_string_format(tree, hf_pn_ptcp_data, tvb, offset, length, "data", 
            "Unknown OUI Data: %d bytes", length);
        expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_WARN,
			"Unknown OUI Data %u bytes", length);
	}
	
	return (offset);
}


static int
dissect_PNPTCP_block(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item _U_, gboolean *end)
{
    guint16 type;
    guint16 length;

	proto_item *sub_item;
	proto_tree *sub_tree;
	proto_item *tlvheader_item;
	proto_tree *tlvheader_tree;
	guint32 u32SubStart;
    proto_item *unknown_item;


    *end = FALSE;

    /* block subtree */
    sub_item = proto_tree_add_item(tree, hf_pn_ptcp_block, tvb, offset, 0, FALSE);
	sub_tree = proto_item_add_subtree(sub_item, ett_pn_ptcp_block);
    u32SubStart = offset;

    /* tlvheader subtree */
    tlvheader_item = proto_tree_add_item(sub_tree, hf_pn_ptcp_block_tlvheader, tvb, offset, 2 /* len */, FALSE);
	tlvheader_tree = proto_item_add_subtree(tlvheader_item, ett_pn_ptcp_block_header);

    offset = dissect_PNPTCP_TLVHeader(tvb, offset, pinfo, tlvheader_tree, sub_item, &type, &length);

	proto_item_append_text(sub_item, "%s", 
        val_to_str(type, pn_ptcp_block_type, "Unknown"));

	proto_item_append_text(tlvheader_item, ": Type=%s (%x), Length=%u", 
        val_to_str(type, pn_ptcp_block_type, "Unknown"), type, length);

    switch(type) {
    case(0x00): /* End, no content */
        *end = TRUE;
        break;
    case(0x01): /* Subdomain */
        dissect_PNPTCP_Subdomain(tvb, offset, pinfo, sub_tree, sub_item);
        break;
    case(0x02): /* Time */
        dissect_PNPTCP_Time(tvb, offset, pinfo, sub_tree, sub_item);
        break;
    case(0x03): /* TimeExtension */
        dissect_PNPTCP_TimeExtension(tvb, offset, pinfo, sub_tree, sub_item);
        break;
    case(0x04): /* Master */
        dissect_PNPTCP_Master(tvb, offset, pinfo, sub_tree, sub_item);
        break;
    case(0x05): /* PortParameter */
        dissect_PNPTCP_PortParameter(tvb, offset, pinfo, sub_tree, sub_item);
        break;
    case(0x06): /* DelayParameter */
        dissect_PNPTCP_DelayParameter(tvb, offset, pinfo, sub_tree, sub_item);
        break;
    case(0x7F): /* Organizational Specific */
        dissect_PNPTCP_Option(tvb, offset, pinfo, sub_tree, sub_item, length);
        break;
    default:
        unknown_item = proto_tree_add_string_format(sub_tree, hf_pn_ptcp_data, tvb, offset, length, "data", 
            "PN-PTCP Unknown BlockType 0x%x, Data: %d bytes", type, length);
        expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_WARN,
			"Unknown BlockType 0x%x, %u bytes", type, length);
    }
    offset += length;

	proto_item_set_len(sub_item, offset - u32SubStart);

    return offset;
}


static int
dissect_PNPTCP_blocks(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{
    gboolean end = FALSE;

    /* as long as we have some bytes, try a new block */
    while(!end) {
        offset = dissect_PNPTCP_block(tvb, offset, pinfo, tree, item, &end);
    }

    return offset;
}


static int
dissect_PNPTCP_Header(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, gboolean delay_valid)
{
	proto_item *header_item;
	proto_tree *header_tree;
    guint32 res_1;
    guint32 res_2;
    guint32 delay10ns;
    guint16 seq_id;
    guint8 delay1ns;
    guint8 padding8;
    guint16 padding16;
    guint16 delay1ps;
    guint64 delayns;
    guint32 delayms;


    header_item = proto_tree_add_item(tree, hf_pn_ptcp_header, tvb, offset, 20 /* len */, FALSE);
	header_tree = proto_item_add_subtree(header_item, ett_pn_ptcp_header);

    /* Reserved_1 */
    offset = dissect_pn_uint32(tvb, offset, pinfo, header_tree, hf_pn_ptcp_res1, &res_1);

    /* Reserved_2 */
    offset = dissect_pn_uint32(tvb, offset, pinfo, header_tree, hf_pn_ptcp_res2, &res_2);

    /* Delay10ns */
    offset = dissect_pn_uint32(tvb, offset, pinfo, header_tree, hf_pn_ptcp_delay10ns, &delay10ns);

    /* SequenceID */
    offset = dissect_pn_uint16(tvb, offset, pinfo, header_tree, hf_pn_ptcp_seq_id, &seq_id);

    /* Delay1ns */
    offset = dissect_pn_uint8(tvb, offset, pinfo, header_tree, hf_pn_ptcp_delay1ns, &delay1ns);

    /* Padding8 */
    offset = dissect_pn_uint8(tvb, offset, pinfo, header_tree, hf_pn_ptcp_padding8, &padding8);

    /* Delay1ps */
    offset = dissect_pn_uint16(tvb, offset, pinfo, header_tree, hf_pn_ptcp_delay1ps, &delay1ps);

    /* Padding16 */
    offset = dissect_pn_uint16(tvb, offset, pinfo, header_tree, hf_pn_ptcp_padding16, &padding16);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, "Seq=%3u", seq_id);
    proto_item_append_text(item, ": Sequence=%u", seq_id);
    proto_item_append_text(header_item, ": Sequence=%u", seq_id);

    /* the delay field is meaningful only in specific PDU's */
    if(delay_valid) {
        delayns = ((guint64) delay10ns) * 10 + delay1ns;
        delayms = (guint32) (delayns / (1000 * 1000));

        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_fstr(pinfo->cinfo, COL_INFO, ", Delay=%11" PRIu64 "ns", 
            delayns);
          proto_item_append_text(item, ", Delay=%" PRIu64 "ns", delayns);

        if(delayns != 0) {
            proto_item_append_text(header_item, ", Delay=%" PRIu64 "ns (%u.%03u,%03u,%03u sec)", 
                delayns, 
                delayms / 1000,
                delayms % 1000,
                (delay10ns % (1000*100)) / 100, 
                 delay10ns % 100 * 10 + delay1ns);
        } else {
            proto_item_append_text(header_item, ", Delay=%" PRIu64 "ns", 
                delayns);
        }
    }

    return offset;
}


static int
dissect_PNPTCP_FollowUpPDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 u16FrameID)
{

    switch(u16FrameID) {
    case(0xFF20):
	    proto_item_append_text(item, "%s", "FollowUp (Clock)");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "FollowUp (Clock), ");
        break;
    case(0xFF21):
	    proto_item_append_text(item, "%s", "FollowUp (Time)");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "FollowUp (Time) , ");
        break;
    default:
	    proto_item_append_text(item, "%s", "FollowUp");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "FollowUp, ");
    }

    /* dissect the header */
    offset = dissect_PNPTCP_Header(tvb, offset, pinfo, tree, item, FALSE /* !delay_valid*/);
    
    /* dissect the PDU */
    offset = dissect_PNPTCP_blocks(tvb, offset, pinfo, tree, item);

    return offset;
}


static int
dissect_PNPTCP_RTASyncPDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 u16FrameID)
{

    switch(u16FrameID) {
    case(0x0000):
    case(0x0020):
	    proto_item_append_text(item, "%s", "RTASync (Clock)");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "RTASync  (Clock), ");
    break;
    case(0x0001):
    case(0x0021):
	    proto_item_append_text(item, "%s", "RTASync (Time)");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "RTASync  (Time) , ");
    break;
    default:
	    proto_item_append_text(item, "%s", "RTASync");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "RTASync,  ");
    }

    /* dissect the header */
    offset = dissect_PNPTCP_Header(tvb, offset, pinfo, tree, item, FALSE /* !delay_valid*/);
    
    /* dissect the PDU */
    offset = dissect_PNPTCP_blocks(tvb, offset, pinfo, tree, item);

    return offset;
}


static int
dissect_PNPTCP_RTCSyncPDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_str(pinfo->cinfo, COL_INFO, "RTCSync,   ");

	proto_item_append_text(item, "%s", "RTCSync");

    /* dissect the header */
    offset = dissect_PNPTCP_Header(tvb, offset, pinfo, tree, item, FALSE /* !delay_valid*/);
    
    /* dissect the PDU */
    offset = dissect_PNPTCP_blocks(tvb, offset, pinfo, tree, item);

    return offset;
}


static int
dissect_PNPTCP_AnnouncePDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 u16FrameID)
{

    switch(u16FrameID) {
    case(0xFF00):
	    proto_item_append_text(item, "%s", "Announce (Clock)");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "Announce (Clock), ");
    break;
    case(0xFF01):
	    proto_item_append_text(item, "%s", "Announce (Time)");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "Announce (Time) , ");
    break;
    default:
	    proto_item_append_text(item, "%s", "Announce");
        if (check_col(pinfo->cinfo, COL_INFO))
          col_append_str(pinfo->cinfo, COL_INFO, "Announce,  ");
    }

    /* dissect the header */
    offset = dissect_PNPTCP_Header(tvb, offset, pinfo, tree, item, FALSE /* !delay_valid*/);
    
    /* dissect the PDU */
    offset = dissect_PNPTCP_blocks(tvb, offset, pinfo, tree, item);

    return offset;
}


static int
dissect_PNPTCP_DelayReqPDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_str(pinfo->cinfo, COL_INFO, "DelayReq,   ");

	proto_item_append_text(item, "%s", "DelayReq");

    /* dissect the header */
    offset = dissect_PNPTCP_Header(tvb, offset, pinfo, tree, item, FALSE /* !delay_valid*/);
    
    /* dissect the PDU */
    offset = dissect_PNPTCP_blocks(tvb, offset, pinfo, tree, item);

    return offset;
}


static int
dissect_PNPTCP_DelayResPDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_str(pinfo->cinfo, COL_INFO, "DelayRes,   ");

	proto_item_append_text(item, "%s", "DelayRes");

    /* dissect the header */
    offset = dissect_PNPTCP_Header(tvb, offset, pinfo, tree, item, TRUE /* delay_valid*/);
    
    /* dissect the PDU */
    offset = dissect_PNPTCP_blocks(tvb, offset, pinfo, tree, item);

    return offset;
}


static int
dissect_PNPTCP_DelayFuResPDU(tvbuff_t *tvb, int offset, 
	packet_info *pinfo, proto_tree *tree, proto_item *item)
{

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_str(pinfo->cinfo, COL_INFO, "DelayFuRes, ");

	proto_item_append_text(item, "%s", "DelayFuRes");

    /* dissect the header */
    offset = dissect_PNPTCP_Header(tvb, offset, pinfo, tree, item, TRUE /* delay_valid*/);
    
    /* dissect the PDU */
    offset = dissect_PNPTCP_blocks(tvb, offset, pinfo, tree, item);

    return offset;
}


/* possibly dissect a PN-RT packet (frame ID must be in the appropriate range) */
static gboolean
dissect_PNPTCP_Data_heur(tvbuff_t *tvb, 
	packet_info *pinfo, proto_tree *tree)
{
    guint16 u16FrameID;
    proto_item *item = NULL;
    proto_tree *ptcp_tree = NULL;
    int offset = 0;
	guint32 u32SubStart;
    proto_item *unknown_item = NULL;


    /* the tvb will NOT contain the frame_id here, so get it from our private data! */
    u16FrameID = GPOINTER_TO_UINT(pinfo->private_data);

	/* frame id must be in valid range (acyclic Real-Time, DCP) */
    /* 0x0000 - 0x007F: RTASyncPDU */
    /* 0x0080 - 0x00FF: RTCSyncPDU */
    /* 0xFF00 - 0xFF1F: AnnouncePDU */
    /* 0xFF20 - 0xFF3F: FollowUpPDU */
    /* 0xFF40 - 0xFF5F: Delay...PDU */
	if ( (u16FrameID >= 0x0100 && u16FrameID < 0xFF00) || (u16FrameID > 0xFF5F) ) {
        /* we are not interested in this packet */
        return FALSE;
    }

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "PN-PTCP");
    if (check_col(pinfo->cinfo, COL_INFO))
      col_add_str(pinfo->cinfo, COL_INFO, "");

    /* subtree for PTCP */
	item = proto_tree_add_protocol_format(tree, proto_pn_ptcp, tvb, 0, 0, "PROFINET PTCP, ");
	ptcp_tree = proto_item_add_subtree(item, ett_pn_ptcp);
    u32SubStart = offset;

    switch(u16FrameID) {
    /* range 1 (0x0000 - 0x007F) */
    case(0x0000):
    case(0x0001):
        /* Send clock and phase synchronization */
        offset = dissect_PNPTCP_RTASyncPDU(tvb, offset, pinfo, ptcp_tree, item, u16FrameID);
        break;
        /* 0x0002 - 0x001F reserved */
    case(0x0020):
    case(0x0021):
        /* Time synchronization */
        offset = dissect_PNPTCP_RTASyncPDU(tvb, offset, pinfo, ptcp_tree, item, u16FrameID);
        break;
        /* 0x0022 - 0x007F reserved */

    /* range 2 (0x0080 - 0x00FF) */
    case(0x0080):
        /* class 3 synchronization */
        offset = dissect_PNPTCP_RTCSyncPDU(tvb, offset, pinfo, ptcp_tree, item);
        break;
        /* 0x0081 - 0x00FF reserved */

    /* range 7 (0xFF00 - 0xFF5F) */
    case(0xff00):
    case(0xff01):
        offset = dissect_PNPTCP_AnnouncePDU(tvb, offset, pinfo, ptcp_tree, item, u16FrameID);
        break;
        /* 0xFF02 - 0xFF1F reserved */
    case(0xff20):
    case(0xff21):
        offset = dissect_PNPTCP_FollowUpPDU(tvb, offset, pinfo, ptcp_tree, item, u16FrameID);
        break;
        /* 0xFF22 - 0xFF3F reserved */
    case(0xff40):
        offset = dissect_PNPTCP_DelayReqPDU(tvb, offset, pinfo, ptcp_tree, item);
        break;
    case(0xff41):
        offset = dissect_PNPTCP_DelayResPDU(tvb, offset, pinfo, ptcp_tree, item);
        break;
    case(0xff42):
        offset = dissect_PNPTCP_DelayFuResPDU(tvb, offset, pinfo, ptcp_tree, item);
        break;
    case(0xff43):
        offset = dissect_PNPTCP_DelayResPDU(tvb, offset, pinfo, ptcp_tree, item);
        break;
        /* 0xFF44 - 0xFF5F reserved */
    default:
        unknown_item = proto_tree_add_string_format(ptcp_tree, hf_pn_ptcp_data, tvb, offset, tvb_length_remaining(tvb, offset), "data", 
            "PN-PTCP Reserved FrameID 0x%04x, Data: %d bytes", u16FrameID, tvb_length_remaining(tvb, offset));
        expert_add_info_format(pinfo, unknown_item, PI_UNDECODED, PI_WARN,
			"Reserved FrameID 0x%04x, %u bytes", u16FrameID, tvb_length_remaining(tvb, offset));

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, "Reserved FrameID 0x%04x", u16FrameID);

		proto_item_append_text(item, "Reserved FrameID 0x%04x", u16FrameID);

        offset += tvb_length_remaining(tvb, offset);
    }

	proto_item_set_len(item, offset - u32SubStart);

    return TRUE;
}


void
proto_register_pn_ptcp (void)
{
	static hf_register_info hf[] = {
	{ &hf_pn_ptcp,
		{ "PROFINET PTCP", "pn_ptcp", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
    { &hf_pn_ptcp_data,
        { "Undecoded Data", "pn_ptcp.data", FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_header,
        { "Header", "pn_ptcp.header", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_block,
        { "", "pn_ptcp.block", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_block_tlvheader,
        { "TLVHeader", "pn_ptcp.tlvheader", FT_NONE, BASE_NONE, NULL, 0x0, "", HFILL }},

	{ &hf_pn_ptcp_res1,
		{ "Reserved 1", "pn_ptcp.res1", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_res2,
		{ "Reserved 2", "pn_ptcp.res2", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_delay10ns,
		{ "Delay10ns", "pn_ptcp.delay10ns", FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_seq_id,
		{ "SequenceID", "pn_ptcp.sequence_id", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_delay1ns,
		{ "Delay1ns", "pn_ptcp.delay1ns", FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_padding8,
		{ "Padding", "pn_ptcp.padding8", FT_UINT8, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_padding16,
		{ "Padding", "pn_ptcp.padding16", FT_UINT16, BASE_HEX, NULL, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_delay1ps,
		{ "Delay1ps", "pn_ptcp.delay1ps", FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }},

	{ &hf_pn_ptcp_tl_length,
        { "TypeLength.Length", "pn_ptcp.tl_length", FT_UINT16, BASE_DEC, 0x0, 0x1FF, "", HFILL }},
	{ &hf_pn_ptcp_tl_type, 
        { "TypeLength.Type", "pn_ptcp.tl_type", FT_UINT16, BASE_DEC, 0x0, 0xFE00, "", HFILL }},

	{ &hf_pn_ptcp_master_source_address,
        { "MasterSourceAddress", "pn_ptcp.master_source_address", FT_ETHER, BASE_HEX, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_subdomain_uuid,
        { "SubdomainUUID", "pn_ptcp.subdomain_uuid", FT_GUID, BASE_NONE, 0x0, 0x0, "", HFILL }},
	
    { &hf_pn_ptcp_request_source_address,
        { "RequestSourceAddress", "pn_ptcp.request_source_address", FT_ETHER, BASE_HEX, 0x0, 0x0, "", HFILL }},
    { &hf_pn_ptcp_request_port_id,
        { "RequestPortID", "pn_ptcp.request_port_id", FT_UINT8, BASE_HEX, 0x0, 0x0, "", HFILL }},
    { &hf_pn_ptcp_sync_id,
        { "SyncID", "pn_ptcp.sync_id", FT_UINT8, BASE_HEX, 0x0, 0x0, "", HFILL }},

	{ &hf_pn_ptcp_t2portrxdelay,
        { "T2PortRxDelay (ns)", "pn_ptcp.t2portrxdelay", FT_UINT32, BASE_DEC, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_t3porttxdelay,
        { "T3PortTxDelay (ns)", "pn_ptcp.t3porttxdelay", FT_UINT32, BASE_DEC, 0x0, 0x0, "", HFILL }},

	{ &hf_pn_ptcp_seconds,
        { "Seconds", "pn_ptcp.seconds", FT_UINT32, BASE_DEC, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_nanoseconds,
        { "NanoSeconds", "pn_ptcp.nanoseconds", FT_UINT32, BASE_DEC, 0x0, 0x0, "", HFILL }},

	{ &hf_pn_ptcp_flags,
        { "Flags", "pn_ptcp.flags", FT_UINT16, BASE_HEX, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_epochnumber,
        { "EpochNumber", "pn_ptcp.epochnumber", FT_UINT16, BASE_DEC, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_currentutcoffset,
        { "CurrentUTCOffset", "pn_ptcp.currentutcoffset", FT_UINT16, BASE_DEC, 0x0, 0x0, "", HFILL }},


	{ &hf_pn_ptcp_clock_uuid,
        { "ClockUUID", "pn_ptcp.clock_uuid", FT_GUID, BASE_NONE, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_clockstratum,
        { "ClockStratum", "pn_ptcp.clockstratum", FT_UINT8, BASE_HEX, VALS(pn_ptcp_clock_stratum_vals), 0x0, "", HFILL }},
	{ &hf_pn_ptcp_clockvariance,
        { "ClockVariance", "pn_ptcp.clockvariance", FT_INT16, BASE_DEC, 0x0, 0x0, "", HFILL }},
	{ &hf_pn_ptcp_clockrole,
        { "ClockRole", "pn_ptcp.clockrole", FT_UINT8, BASE_HEX, VALS(pn_ptcp_clock_role_vals), 0x0, "", HFILL }},

	{ &hf_pn_ptcp_oui,
		{ "Organizationally Unique Identifier",	"pn_ptcp.oui", FT_UINT24, BASE_HEX,
	   	VALS(pn_ptcp_oui_vals), 0x0, "", HFILL }},
	{ &hf_pn_ptcp_profinet_subtype,
		{ "Subtype",	"pn_ptcp.subtype", FT_UINT8, BASE_HEX,
	   	VALS(pn_ptcp_profinet_subtype_vals), 0x0, "PROFINET Subtype", HFILL }},
	{ &hf_pn_ptcp_unknown_subtype,
		{ "Subtype",	"pn_ptcp.subtype", FT_UINT8, BASE_HEX, 0x0, 0x0, "Unkown Subtype", HFILL }},
        
	{ &hf_pn_ptcp_irdata_uuid,
        { "IRDataUUID", "pn_ptcp.irdata_uuid", FT_GUID, BASE_NONE, 0x0, 0x0, "", HFILL }},
	};

	static gint *ett[] = {
		&ett_pn_ptcp,
		&ett_pn_ptcp_header,
        &ett_pn_ptcp_block,
        &ett_pn_ptcp_block_header
    };
	proto_pn_ptcp = proto_register_protocol ("PROFINET PTCP", "PN-PTCP", "pn_ptcp");
	proto_register_field_array (proto_pn_ptcp, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_pn_ptcp (void)
{
    /* register ourself as an heuristic pn-rt payload dissector */
	heur_dissector_add("pn_rt", dissect_PNPTCP_Data_heur, proto_pn_ptcp);
}
