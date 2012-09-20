/* packet-dcerpc-epm.c
 * Routines for dcerpc endpoint mapper dissection
 * Copyright 2001, Todd Sabin <tas@webspan.net>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"


static int proto_epm3 = -1;
static int proto_epm4 = -1;

static int hf_epm_opnum = -1;
static int hf_epm_inquiry_type = -1;
static int hf_epm_object = -1;
static int hf_epm_if_id = -1;
static int hf_epm_ver_maj = -1;
static int hf_epm_ver_min = -1;
static int hf_epm_ver_opt = -1;
static int hf_epm_hnd = -1;
static int hf_epm_max_ents = -1;
static int hf_epm_num_ents = -1;
static int hf_epm_uuid = -1;
static int hf_epm_tower_length = -1;
static int hf_epm_tower_data = -1;
static int hf_epm_max_towers = -1;
static int hf_epm_num_towers = -1;
static int hf_epm_rc = -1;
static int hf_epm_replace = -1;
static int hf_epm_tower_num_floors = -1;
static int hf_epm_tower_rhs_len = -1;
static int hf_epm_tower_lhs_len = -1;
static int hf_epm_tower_proto_id = -1;
static int hf_epm_annotation = -1;
static int hf_epm_ann_offset = -1;
static int hf_epm_ann_len = -1;
static int hf_epm_proto_named_pipes = -1;
static int hf_epm_proto_netbios_name = -1;
static int hf_epm_proto_ip = -1;
static int hf_epm_proto_udp_port = -1;
static int hf_epm_proto_tcp_port = -1;
static int hf_epm_proto_http_port = -1;

static gint ett_epm = -1;
static gint ett_epm_tower_floor = -1;
static gint ett_epm_entry = -1;

/* the UUID is identical for interface versions 3 and 4 */
static e_uuid_t uuid_epm = { 0xe1af8308, 0x5d1f, 0x11c9, { 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa } };
static guint16  ver_epm3 = 3;
static guint16  ver_epm4 = 4;



static const value_string ep_service[] = {
    { 0, "rpc_c_ep_all_elts" },
    { 1, "rpc_c_ep_match_by_if" },
    { 2, "rpc_c_ep_match_by_obj" },
    { 3, "rpc_c_ep_match_by_both" },
    { 0, NULL },
};

/* typedef struct {
      unsigned int tower_len,
      [size_is(tower_len)] char tower[];
   } twr_t, *twr_p_t;
*/
static int epm_dissect_tower (tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint8 *drep);


static int
epm_dissect_pointer_IF_ID(tvbuff_t *tvb, int offset,
                          packet_info *pinfo, proto_tree *tree,
                          guint8 *drep)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
                                 di->hf_index, NULL);
    offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_ver_maj, NULL);
    offset = dissect_ndr_uint16 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_ver_min, NULL);
    return offset;
}

static int
epm_dissect_pointer_UUID(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    dcerpc_info *di;

    di=pinfo->private_data;
    offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
                                 di->hf_index, NULL);
    return offset;
}

static int
epm_dissect_ept_lookup_rqst (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_inquiry_type, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_pointer_UUID, NDR_POINTER_PTR,
                             "Object:", hf_epm_object);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_pointer_IF_ID, NDR_POINTER_PTR,
                             "Interface:", hf_epm_if_id);

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_ver_opt, NULL);

    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_max_ents, NULL);
    return offset;
}


static int
epm_dissect_ept_entry_t(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *parent_tree,
                             guint8 *drep)
{
    proto_item *item=NULL;
    proto_tree *tree=NULL;
    int old_offset=offset;
    guint32 len;
    dcerpc_info *di;
    const char *str;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    if(parent_tree){
        item = proto_tree_add_text(parent_tree, tvb, offset, -1, "Entry:");
        tree = proto_item_add_subtree(item, ett_epm_entry);
    }

    offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
                                 hf_epm_object, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower, NDR_POINTER_PTR,
                             "Tower pointer:", -1);

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_ann_offset, NULL);
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_ann_len, &len);
    str=tvb_get_ephemeral_string(tvb, offset, len);
    proto_tree_add_item(tree, hf_epm_annotation, tvb, offset, len, ENC_ASCII|ENC_NA);
    offset += len;

    if(str&&str[0]){
        if(parent_tree) {
            proto_item_append_text(item, " Service:%s ", str);
            proto_item_append_text(tree->parent, " Service:%s ", str);
        }
        if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Service:%s", str);
        }
    }

    proto_item_set_len(item, offset-old_offset);
    return offset;
}

static int
epm_dissect_ept_entry_t_array(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
                             epm_dissect_ept_entry_t);

    return offset;
}

static int
epm_dissect_ept_lookup_resp (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_num_ents, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_ept_entry_t_array, NDR_POINTER_REF,
                             "Entries:", -1);

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_rc, NULL);

    return offset;
}

static int
epm_dissect_uuid (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_uuid_t (tvb, offset, pinfo, tree, drep,
                                  hf_epm_uuid, NULL);
    return offset;
}

#define PROTO_ID_OSI_OID        0x00
#define PROTO_ID_DNA_SESSCTL    0x02
#define PROTO_ID_DNA_SESSCTL_V3 0x03
#define PROTO_ID_DNA_NSP        0x04
#define PROTO_ID_OSI_TP4        0x05
#define PROTO_ID_OSI_CLNS       0x06
#define PROTO_ID_TCP            0x07
#define PROTO_ID_UDP            0x08
#define PROTO_ID_IP             0x09
#define PROTO_ID_RPC_CL         0x0a
#define PROTO_ID_RPC_CO         0x0b
#define PROTO_ID_SPX            0x0c    /* from DCOM spec (is this correct?) */
#define PROTO_ID_UUID           0x0d
#define PROTO_ID_IPX            0x0e    /* from DCOM spec (is this correct?) */
#define PROTO_ID_NAMED_PIPES    0x0f
#define PROTO_ID_NAMED_PIPES_2  0x10
#define PROTO_ID_NETBIOS        0x11
#define PROTO_ID_NETBEUI        0x12
#define PROTO_ID_NETWARE_SPX    0x13
#define PROTO_ID_NETWARE_IPX    0x14
#define PROTO_ID_ATALK_STREAM   0x16
#define PROTO_ID_ATALK_DATAGRAM 0x17
#define PROTO_ID_ATALK          0x18
#define PROTO_ID_NETBIOS_2      0x19
#define PROTO_ID_VINES_SPP      0x1a
#define PROTO_ID_VINES_IPC      0x1b
#define PROTO_ID_STREETTALK     0x1c
#define PROTO_ID_HTTP           0x1f
#define PROTO_ID_UNIX_DOMAIN    0x20
#define PROTO_ID_NULL           0x21
#define PROTO_ID_NETBIOS_3      0x22

static const value_string proto_id_vals[] = {
    { PROTO_ID_OSI_OID,         "OSI OID"},
    { PROTO_ID_DNA_SESSCTL,     "DNA Session Control"},
    { PROTO_ID_DNA_SESSCTL_V3,  "DNA Session Control V3"},
    { PROTO_ID_DNA_NSP,         "DNA NSP Transport"},
    { PROTO_ID_OSI_TP4,         "OSI TP4"},
    { PROTO_ID_OSI_CLNS,        "OSI CLNS or DNA Routing"},
    { PROTO_ID_TCP,             "DOD TCP"},
    { PROTO_ID_UDP,             "DOD UDP"},
    { PROTO_ID_IP,              "DOD IP"},
    { PROTO_ID_RPC_CL,          "RPC connectionless protocol"},
    { PROTO_ID_RPC_CO,          "RPC connection-oriented protocol"},
    { PROTO_ID_SPX,             "SPX?"},
    { PROTO_ID_UUID,            "UUID"},
    { PROTO_ID_IPX,             "IPX?"},
    { PROTO_ID_NAMED_PIPES,     "Named Pipes"},
    { PROTO_ID_NAMED_PIPES_2,   "Named Pipes"},
    { PROTO_ID_NETBIOS,         "NetBIOS"},
    { PROTO_ID_NETBEUI,         "NetBEUI"},
    { PROTO_ID_NETWARE_SPX,     "Netware SPX"},
    { PROTO_ID_NETWARE_IPX,     "Netware IPX"},
    { PROTO_ID_ATALK_STREAM,    "Appletalk Stream"},
    { PROTO_ID_ATALK_DATAGRAM,  "Appletalk Datagram"},
    { PROTO_ID_ATALK,           "Appletalk"},
    { PROTO_ID_NETBIOS_2,       "NetBIOS"},
    { PROTO_ID_VINES_SPP,       "Vines SPP"},
    { PROTO_ID_VINES_IPC,       "Vines IPC"},
    { PROTO_ID_STREETTALK,      "StreetTalk"},
    { PROTO_ID_HTTP,            "RPC over HTTP"},
    { PROTO_ID_UNIX_DOMAIN,     "Unix Domain Socket"},
    { PROTO_ID_NULL,            "null"},
    { PROTO_ID_NETBIOS_3,       "NetBIOS"},
    { 0, NULL},
};


/* XXX this function assumes LE encoding. can not use the NDR routines
   since they assume padding.
*/
static int
epm_dissect_tower_data (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep _U_)
{
    guint16 num_floors, i;
    dcerpc_info *di;
    const char *uuid_name;
    guint8   u8little_endian = DREP_LITTLE_ENDIAN;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    num_floors = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(tree, hf_epm_tower_num_floors, tvb, offset, 2, num_floors);
    offset += 2;

    for(i=1;i<=num_floors;i++){
        proto_item *it = NULL;
        proto_tree *tr = NULL;
        int old_offset = offset;
        guint16 len;
        guint8 proto_id;
        e_uuid_t uuid;
        proto_item *pi;

        it = proto_tree_add_text(tree, tvb, offset, 0, "Floor %d ", i);
        tr = proto_item_add_subtree(it, ett_epm_tower_floor);

        len = tvb_get_letohs(tvb, offset);
        proto_tree_add_uint(tr, hf_epm_tower_lhs_len, tvb, offset, 2, len);
        offset += 2;

        proto_id = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tr, hf_epm_tower_proto_id, tvb, offset, 1, proto_id);

        switch(proto_id){
        case PROTO_ID_UUID:
            dcerpc_tvb_get_uuid (tvb, offset+1, &u8little_endian, &uuid);

            uuid_name = guids_get_uuid_name(&uuid);

            if(uuid_name != NULL) {
                proto_tree_add_guid_format (tr, hf_epm_uuid, tvb, offset+1, 16, (e_guid_t *) &uuid,
                              "UUID: %s (%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x)",
                              uuid_name,
                              uuid.Data1, uuid.Data2, uuid.Data3,
                              uuid.Data4[0], uuid.Data4[1],
                              uuid.Data4[2], uuid.Data4[3],
                              uuid.Data4[4], uuid.Data4[5],
                              uuid.Data4[6], uuid.Data4[7]);
            } else {
                proto_tree_add_guid_format (tr, hf_epm_uuid, tvb, offset+1, 16, (e_guid_t *) &uuid,
                              "UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                              uuid.Data1, uuid.Data2, uuid.Data3,
                              uuid.Data4[0], uuid.Data4[1],
                              uuid.Data4[2], uuid.Data4[3],
                              uuid.Data4[4], uuid.Data4[5],
                              uuid.Data4[6], uuid.Data4[7]);
            }
            proto_tree_add_text(tr, tvb, offset+17, 2, "Version %d.%d", tvb_get_guint8(tvb, offset+17), tvb_get_guint8(tvb, offset+18));

            {
                guint16 version = tvb_get_ntohs(tvb, offset+17);
                const char *service = dcerpc_get_proto_name(&uuid, version);
                if (service || uuid_name) {
                    const char *s = service ? service : uuid_name;
                    proto_item_append_text(tr, "UUID: %s", s);
                    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", s);
                } else {
                    proto_item_append_text(tr, "UUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x Version %d.%d", uuid.Data1, uuid.Data2, uuid.Data3,
                                           uuid.Data4[0], uuid.Data4[1],
                                           uuid.Data4[2], uuid.Data4[3],
                                           uuid.Data4[4], uuid.Data4[5],
                                           uuid.Data4[6], uuid.Data4[7],
                                           tvb_get_guint8(tvb, offset+17),
                                           tvb_get_guint8(tvb, offset+18));
                }
            }
            break;
        }
        offset += len;

        len = tvb_get_letohs(tvb, offset);
        pi = proto_tree_add_uint(tr, hf_epm_tower_rhs_len, tvb, offset, 2, len);
        offset += 2;

        switch(proto_id){

        case PROTO_ID_UUID:
            /* XXX - is this big or little endian? */
            proto_tree_add_item(tr, hf_epm_ver_min, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        case PROTO_ID_TCP: /* this one is always big endian */
            proto_tree_add_item(tr, hf_epm_proto_tcp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(tr, "TCP Port:%d", tvb_get_ntohs(tvb, offset));
            break;

        case PROTO_ID_UDP: /* this one is always big endian */
            proto_tree_add_item(tr, hf_epm_proto_udp_port, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(tr, "UDP Port:%d", tvb_get_ntohs(tvb, offset));
            break;

        case PROTO_ID_IP: /* this one is always big endian */
            proto_tree_add_item(tr, hf_epm_proto_ip, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_item_append_text(tr, "IP:%s", tvb_ip_to_str(tvb, offset));
            break;

        case PROTO_ID_RPC_CO:
            proto_item_append_text(tr, "RPC connection-oriented protocol");
            break;

        case PROTO_ID_RPC_CL:
            proto_item_append_text(tr, "RPC connectionless protocol");
            /* XXX - is this big or little endian? */
            proto_tree_add_item(tr, hf_epm_ver_min, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;

        case PROTO_ID_NAMED_PIPES: /* \\PIPE\xxx   named pipe */
            proto_tree_add_item(tr, hf_epm_proto_named_pipes, tvb, offset, len, ENC_ASCII|ENC_NA);
            proto_item_append_text(tr, "NamedPipe:%s", tvb_get_ephemeral_string(tvb, offset, len));
            break;

        case PROTO_ID_NAMED_PIPES_2: /* PIPENAME  named pipe */
            proto_tree_add_item(tr, hf_epm_proto_named_pipes, tvb, offset, len, ENC_ASCII|ENC_NA);
            proto_item_append_text(tr, "PIPE:%s", tvb_get_ephemeral_string(tvb, offset, len));
            break;

        case PROTO_ID_NETBIOS: /* \\NETBIOS   netbios name */
            proto_tree_add_item(tr, hf_epm_proto_netbios_name, tvb, offset, len, ENC_ASCII|ENC_NA);
            proto_item_append_text(tr, "NetBIOS:%s", tvb_get_ephemeral_string(tvb, offset, len));
            break;
        case PROTO_ID_HTTP: /* RPC over HTTP */
            proto_tree_add_item(tr, hf_epm_proto_http_port, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_append_text(tr, "RPC over HTTP Port:%d", tvb_get_ntohs(tvb, offset));
            break;

        default:
            if(len){
                expert_add_info_format(pinfo, pi, PI_UNDECODED, PI_WARN, "RightHandSide not decoded yet for proto_id 0x%x",
                    proto_id);
                tvb_ensure_bytes_exist(tvb, offset, len);
                proto_tree_add_text(tr, tvb, offset, len, "RightHandSide not decoded yet for proto_id 0x%x", proto_id);
            }
        }
        offset += len;

        proto_item_set_len(it, offset-old_offset);
    }
    return offset;
}

/* typedef struct {
      unsigned int tower_len,
      [size_is(tower_len)] char tower[];
   } twr_t, *twr_p_t;
*/
static int
epm_dissect_tower (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    guint3264 len;
    dcerpc_info *di;

    di=pinfo->private_data;
    if(di->conformant_run){
        return offset;
    }

    /* first one is the header of the conformant array, second one is the
       length field */
    offset = dissect_ndr_uint3264 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_tower_length, &len);
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_tower_length, NULL);
    offset = epm_dissect_tower_data(tvb, offset, pinfo, tree, drep);

    return offset;
}
static int
epm_dissect_tower_pointer (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower, NDR_POINTER_PTR,
                             "Tower pointer:", -1);
    return offset;
}
static int
epm_dissect_tower_array (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower_pointer);

    return offset;
}

static int
epm_dissect_ept_map_rqst (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    /* [in, ptr] uuid_p_t object */
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_uuid, NDR_POINTER_PTR,
                             "UUID pointer:", -1);

    /* [in, ptr] twr_p_t map_tower */
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower, NDR_POINTER_PTR,
                             "Tower pointer:", -1);

    /* [in, out] ept_lookup_handle_t *entry_handle */
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    /* [in] unsigned32 max_towers */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_max_towers, NULL);

    return offset;
}

static int
epm_dissect_ept_map_resp (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    /* [in, out] ept_lookup_handle_t *entry_handle */
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    /* [out, ptr] unsigned32 *num_towers */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_num_towers, NULL);

    /* [out, length_is(*num_towers), size_is(max_towers), ptr] twr_p_t towers[] */
    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_tower_array, NDR_POINTER_REF,
                             "Tower array:", -1);

    /* [out] error_status_t *status */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_rc, NULL);

    return offset;
}

static int
epm_dissect_ept_entry_t_ucarray(tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, drep,
                             epm_dissect_ept_entry_t);

    return offset;
}

static int
epm_dissect_ept_insert_rqst (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_num_ents, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_ept_entry_t_ucarray, NDR_POINTER_REF,
                             "Entries:", -1);

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_replace, NULL);

    return offset;
}



static int
epm_dissect_ept_insert_resp (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    /* [out] error_status_t *status */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_rc, NULL);

    return offset;
}


static int
epm_dissect_ept_delete_rqst (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_num_ents, NULL);

    offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
                             epm_dissect_ept_entry_t_ucarray, NDR_POINTER_REF,
                             "Entries:", -1);

    return offset;
}



static int
epm_dissect_ept_delete_resp (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    /* [out] error_status_t *status */
    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_rc, NULL);

    return offset;
}



static int
epm_dissect_ept_lookup_handle_free_rqst (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    /* [in, out] ept_lookup_handle_t *entry_handle */
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    return offset;
}

static int
epm_dissect_ept_lookup_handle_free_resp (tvbuff_t *tvb, int offset,
                             packet_info *pinfo, proto_tree *tree,
                             guint8 *drep)
{
    /* [in, out] ept_lookup_handle_t *entry_handle */
    offset = dissect_ndr_ctx_hnd (tvb, offset, pinfo, tree, drep,
                                  hf_epm_hnd, NULL);

    offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, drep,
                                 hf_epm_rc, NULL);

    return offset;
}


static dcerpc_sub_dissector epm_dissectors[] = {
    { 0, "Insert",
        epm_dissect_ept_insert_rqst,
        epm_dissect_ept_insert_resp },
    { 1, "Delete",
        epm_dissect_ept_delete_rqst,
        epm_dissect_ept_delete_resp },
    { 2, "Lookup",
        epm_dissect_ept_lookup_rqst,
        epm_dissect_ept_lookup_resp },
    { 3, "Map",
        epm_dissect_ept_map_rqst,
        epm_dissect_ept_map_resp },
    { 4, "LookupHandleFree",
        epm_dissect_ept_lookup_handle_free_rqst,
        epm_dissect_ept_lookup_handle_free_resp },
    { 5, "InqObject", NULL, NULL },
    { 6, "MgmtDelete", NULL, NULL },
    { 0, NULL, NULL, NULL }
};

void
proto_register_epm (void)
{
    static hf_register_info hf[] = {
        { &hf_epm_opnum,
          { "Operation", "epm.opnum", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_epm_inquiry_type,
          { "Inquiry type", "epm.inq_type", FT_UINT32, BASE_DEC, VALS(ep_service), 0x0, NULL, HFILL }},
        { &hf_epm_object,
          { "Object", "epm.object", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_if_id,
          { "Interface", "epm.if_id", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_ver_maj,
          { "Version Major", "epm.ver_maj", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_ver_min,
          { "Version Minor", "epm.ver_min", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_ver_opt,
          { "Version Option", "epm.ver_opt", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_hnd,
          { "Handle", "epm.hnd", FT_BYTES, BASE_NONE, NULL, 0x0, "Context handle", HFILL }},
        { &hf_epm_max_ents,
          { "Max entries", "epm.max_ents", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_num_ents,
          { "Num entries", "epm.num_ents", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_uuid,
          { "UUID", "epm.uuid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_annotation,
          { "Annotation", "epm.annotation", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_proto_named_pipes,
          { "Named Pipe", "epm.proto.named_pipe", FT_STRING, BASE_NONE, NULL, 0x0, "Name of the named pipe for this service", HFILL }},
        { &hf_epm_proto_netbios_name,
          { "NetBIOS Name", "epm.proto.netbios_name", FT_STRING, BASE_NONE, NULL, 0x0, "NetBIOS name where this service can be found", HFILL }},
        { &hf_epm_tower_length,
          { "Length", "epm.tower.len", FT_UINT32, BASE_DEC, NULL, 0x0, "Length of tower data", HFILL }},
        { &hf_epm_tower_data,
          { "Tower", "epm.tower", FT_BYTES, BASE_NONE, NULL, 0x0, "Tower data", HFILL }},
        { &hf_epm_max_towers,
          { "Max Towers", "epm.max_towers", FT_UINT32, BASE_DEC, NULL, 0x0, "Maximum number of towers to return", HFILL }},
        { &hf_epm_num_towers,
          { "Num Towers", "epm.num_towers", FT_UINT32, BASE_DEC, NULL, 0x0, "Number number of towers to return", HFILL }},
        { &hf_epm_ann_offset,
          { "Annotation offset", "epm.ann_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_ann_len,
          { "Annotation length", "epm.ann_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_epm_rc,
          { "Return code", "epm.rc", FT_UINT32, BASE_HEX, NULL, 0x0, "EPM return value", HFILL }},
        { &hf_epm_replace,
          { "Replace", "epm.replace", FT_UINT8, BASE_DEC, NULL, 0x0, "Replace existing objects?", HFILL }},
        { &hf_epm_tower_num_floors,
          { "Number of floors", "epm.tower.num_floors", FT_UINT16, BASE_DEC, NULL, 0x0, "Number of floors in tower", HFILL }},
        { &hf_epm_proto_udp_port,
          { "UDP Port", "epm.proto.udp_port", FT_UINT16, BASE_DEC, NULL, 0x0, "UDP Port where this service can be found", HFILL }},
        { &hf_epm_proto_tcp_port,
          { "TCP Port", "epm.proto.tcp_port", FT_UINT16, BASE_DEC, NULL, 0x0, "TCP Port where this service can be found", HFILL }},
        { &hf_epm_proto_http_port,
          { "TCP Port", "epm.proto.http_port", FT_UINT16, BASE_DEC, NULL, 0x0, "TCP Port where this service can be found", HFILL }},
        { &hf_epm_tower_rhs_len,
          { "RHS Length", "epm.tower.rhs.len", FT_UINT16, BASE_DEC, NULL, 0x0, "Length of RHS data", HFILL }},
        { &hf_epm_tower_lhs_len,
          { "LHS Length", "epm.tower.lhs.len", FT_UINT16, BASE_DEC, NULL, 0x0, "Length of LHS data", HFILL }},
        { &hf_epm_proto_ip,
          { "IP", "epm.proto.ip", FT_IPv4, BASE_NONE, NULL, 0x0, "IP address where service is located", HFILL }},
        { &hf_epm_tower_proto_id,
          { "Protocol", "epm.tower.proto_id", FT_UINT8, BASE_HEX, VALS(proto_id_vals), 0x0, "Protocol identifier", HFILL }}
    };
    static gint *ett[] = {
        &ett_epm,
        &ett_epm_tower_floor,
        &ett_epm_entry
    };

    /* interface version 3 */
    proto_epm3 = proto_register_protocol ("DCE/RPC Endpoint Mapper", "EPM", "epm");
    proto_register_field_array (proto_epm3, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));

    /* interface version 4 */
    proto_epm4 = proto_register_protocol ("DCE/RPC Endpoint Mapper v4", "EPMv4", "epm4");
}

void
proto_reg_handoff_epm (void)
{
    /* Register the protocol as dcerpc */
    dcerpc_init_uuid (proto_epm3, ett_epm, &uuid_epm, ver_epm3, epm_dissectors, hf_epm_opnum);
    dcerpc_init_uuid (proto_epm4, ett_epm, &uuid_epm, ver_epm4, epm_dissectors, hf_epm_opnum);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
