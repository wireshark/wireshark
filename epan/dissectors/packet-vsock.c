/* packet-vsock.c
 * Routines for AF_VSOCK dissection
 * Copyright 2016, Gerard Garcia <ggarcia@deic.uab.cat>
 *
 * Header definition:
 * https://github.com/GerardGarcia/linux/blob/vsockmon/include/uapi/linux/vsockmon.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The AF_VSOCK socket allows zero-configuration communication between guests
 * and hypervisors using the standard socket API.
 */

#include <config.h>
#include <epan/packet.h>
#include <wsutil/pint.h>
#include <epan/address_types.h>
#include <wiretap/wtap.h>

void proto_register_vsock(void);
void proto_reg_handoff_vsock(void);

static int proto_vsock;
static int vsock_address_type = -1;
static dissector_handle_t vsock_handle;

/* Generic header related fields */
static int hf_vsock_src_cid;
static int hf_vsock_src_port;
static int hf_vsock_dst_cid;
static int hf_vsock_dst_port;
static int hf_vsock_op;
static int hf_vsock_t;
static int hf_vsock_t_len;
static int hf_vsock_reserved;
static int hf_vsock_payload;

/* Virtio related fields */
static int hf_virtio_src_cid;
static int hf_virtio_dst_cid;
static int hf_virtio_src_port;
static int hf_virtio_dst_port;
static int hf_virtio_len;
static int hf_virtio_type;
static int hf_virtio_op;
static int hf_virtio_flags;
static int hf_virtio_buf_alloc;
static int hf_virtio_fwd_cnt;

static int ett_vsock;
static int ett_virtio;

static const value_string af_vsockmon_op_names[] = {
    { 0, "Unknown" },
    { 1, "Connect" },
    { 2, "Disconnect" },
    { 3, "Control" },
    { 4, "Payload" },
    { 0, NULL }
};

enum af_vsockmon_t {
    AF_VSOCK_T_UNKNOWN = 0,
    AF_VSOCK_T_NO_INFO = 1,
    AF_VSOCK_T_VIRTIO = 2
};

static const value_string af_vsockmon_t_names[] = {
    { 0, "Unknown" },
    { 1, "No info" },
    { 2, "Virtio" },
    { 0 , NULL }
};

static const value_string virtio_vsock_type_names[] = {
    { 1, "Stream"},
    { 0, NULL }
};

static const value_string virtio_vsock_op_names[] = {
    { 0, "Invalid" },
    { 1, "Request" },
    { 2, "Response" },
    { 3, "Rst" },
    { 4, "Shutdown" },
    { 5, "RW" },
    { 6, "Credit update" },
    { 7, "Credit response" },
    { 0 , NULL }
};

#define VSOCK_MIN_LENGTH 32

static int vsock_addr_to_str(const address* addr, char *buf, int buf_len)
{
    const uint8_t *addrp = (const uint8_t *)addr->data;

    if(pletoh64(&addrp[0])==2){
        (void) g_strlcpy(buf, "host", buf_len);
    } else {
        snprintf(buf, buf_len, "%" PRIu64, pletoh64(&addrp[0]));
    }

    return (int)(strlen(buf)+1);
}

static int vsock_addr_str_len(const address* addr _U_)
{
    /* 2^64 unsigned int len */
    return 19;
}

static int
dissect_vsock(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *virtio_ti;
    proto_tree *vsock_tree, *virtio_tree;

    uint32_t t_len, payload_len, virtio_buf_alloc, op, type,
            virtio_fwd_cnt, virtio_op, virtio_type;
    uint16_t payload_offset = 0, offset = 0;

    if (tvb_reported_length(tvb) < VSOCK_MIN_LENGTH)
        return 0;

    /* Clear column information before start parsing */
    col_clear(pinfo->cinfo, COL_INFO);

    /* Create top tree */
    ti = proto_tree_add_item(tree, proto_vsock, tvb, 0, -1, ENC_NA);
    vsock_tree = proto_item_add_subtree(ti, ett_vsock);

    /* Parse generic header part */
    proto_tree_add_item(vsock_tree, hf_vsock_src_cid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    set_address_tvb(&pinfo->src, vsock_address_type, 8, tvb, offset);
    offset += 8;

    proto_tree_add_item(vsock_tree, hf_vsock_dst_cid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    set_address_tvb(&pinfo->dst, vsock_address_type, 8, tvb, offset);
    offset += 8;

    proto_tree_add_item_ret_uint(vsock_tree, hf_vsock_src_port, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pinfo->srcport);
    offset += 4;

    proto_tree_add_item_ret_uint(vsock_tree, hf_vsock_dst_port, tvb, offset, 4, ENC_LITTLE_ENDIAN, &pinfo->destport);
    offset += 4;

    proto_tree_add_item_ret_uint(vsock_tree, hf_vsock_op, tvb, offset, 2, ENC_LITTLE_ENDIAN, &op);
    offset += 2;

    proto_tree_add_item_ret_uint(vsock_tree, hf_vsock_t, tvb, offset, 2, ENC_LITTLE_ENDIAN, &type);
    offset += 2;

    proto_tree_add_item_ret_uint(vsock_tree, hf_vsock_t_len, tvb, offset, 2, ENC_LITTLE_ENDIAN, &t_len);
    offset += 2;

    proto_tree_add_item(vsock_tree, hf_vsock_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;

    payload_offset = offset + t_len;

    /* Append summary information to top tree */
    proto_item_append_text(ti, ", Op: %s, Transport: %s",
            val_to_str(op, af_vsockmon_op_names, "Unknown (%d)"),
            val_to_str(type, af_vsockmon_t_names, "Unknown (%d)"));

    /* Fill columns */
    col_add_fstr(pinfo->cinfo, COL_INFO, "[%s] %s",
            val_to_str(op, af_vsockmon_op_names, "Unknown (%d)"),
            val_to_str(type, af_vsockmon_t_names, "Unknown (%d)"));
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "vSocket");

    /* Create subtree if there is transport information */
    switch (type) {
        case AF_VSOCK_T_UNKNOWN:
        case AF_VSOCK_T_NO_INFO:
            break;
        case AF_VSOCK_T_VIRTIO:
            virtio_tree = proto_tree_add_subtree(vsock_tree, tvb, offset, 44, ett_virtio, &virtio_ti, "Virtio transport header");

            proto_tree_add_item(virtio_tree, hf_virtio_src_cid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(virtio_tree, hf_virtio_dst_cid, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(virtio_tree, hf_virtio_src_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(virtio_tree, hf_virtio_dst_port, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(virtio_tree, hf_virtio_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item_ret_uint(virtio_tree, hf_virtio_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &virtio_type);
            offset += 2;

            proto_tree_add_item_ret_uint(virtio_tree, hf_virtio_op, tvb, offset, 2, ENC_LITTLE_ENDIAN, &virtio_op);
            offset += 2;

            proto_tree_add_item(virtio_tree, hf_virtio_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            proto_tree_add_item_ret_uint(virtio_tree, hf_virtio_buf_alloc, tvb, offset, 4, ENC_LITTLE_ENDIAN, &virtio_buf_alloc);
            offset += 4;

            proto_tree_add_item_ret_uint(virtio_tree, hf_virtio_fwd_cnt, tvb, offset, 4, ENC_LITTLE_ENDIAN, &virtio_fwd_cnt);
            /*offset += 4;*/

            /* Append virtio information */
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s, Op: %s, Buf alloc: %u, Fwd cnt: %u",
                    val_to_str(virtio_type, virtio_vsock_type_names, "Unknown (%d)"),
                    val_to_str(virtio_op, virtio_vsock_op_names, "Unknown (%d)"),
                    virtio_buf_alloc, virtio_fwd_cnt);
            break;
    }


    /* Append payload */
    payload_len = tvb_reported_length_remaining(tvb, payload_offset);
    if (payload_len)
        proto_tree_add_bytes_format(vsock_tree, hf_vsock_payload, tvb, payload_offset, payload_len,
                NULL, "Payload (%uB)", payload_len);

    return tvb_reported_length(tvb);
}

void
proto_register_vsock(void)
{
    static hf_register_info hf[] = {
        { &hf_vsock_src_cid,
            {"Source cid", "vsock.src_cid", FT_UINT64, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_vsock_dst_cid,
            {"Destination cid", "vsock.dst_cid", FT_UINT64, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_vsock_src_port,
            {"Source port", "vsock.src_port", FT_UINT32, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_vsock_dst_port,
            {"Destination port", "vsock.dst_port", FT_UINT32, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_vsock_op,
            {"Operation", "vsock.op", FT_UINT16, BASE_DEC, VALS(af_vsockmon_op_names),
                0x0, NULL, HFILL }},
        { &hf_vsock_t,
            {"Transport", "vsock.trans", FT_UINT16, BASE_DEC, VALS(af_vsockmon_t_names),
                0x0, NULL, HFILL }},
        { &hf_vsock_t_len,
            {"Transport length", "vsock.trans_len", FT_UINT16, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_vsock_reserved,
            {"Reserved", "vsock.reserved", FT_BYTES, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
        { &hf_vsock_payload,
            { "Payload", "vsock.payload", FT_BYTES, BASE_NONE, NULL,
                0x0, NULL, HFILL}},
        { &hf_virtio_src_cid,
            {"Source cid", "vsock.virtio.src_cid", FT_UINT64, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_virtio_dst_cid,
            {"Destination cid", "vsock.virtio.dst_cid", FT_UINT64, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_virtio_src_port,
            {"Source port", "vsock.virtio.src_prot", FT_UINT32, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_virtio_dst_port,
            {"Destination port", "vsock.virtio.dst_prot", FT_UINT32, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_virtio_len,
            {"Length", "vsock.virtio.len", FT_UINT32, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_virtio_type,
            {"Type", "vsock.virtio.type", FT_UINT16, BASE_DEC, VALS(virtio_vsock_type_names),
                0x0, NULL, HFILL }},
        { &hf_virtio_op,
            {"Operation", "vsock.virtio.op", FT_UINT16, BASE_DEC, VALS(virtio_vsock_op_names),
                0x0, NULL, HFILL }},
        { &hf_virtio_flags,
            {"Flags", "vsock.virtio.flags", FT_UINT32, BASE_HEX, NULL,
                0x0, NULL, HFILL }},
        { &hf_virtio_buf_alloc,
            {"Buf alloc", "vsock.virtio.buf_alloc", FT_UINT32, BASE_DEC, NULL,
                0x0, NULL, HFILL }},
        { &hf_virtio_fwd_cnt,
            {"Fwd cnt", "vsock.virtio.fwd_cnt", FT_UINT32, BASE_DEC, NULL,
                0x0, NULL, HFILL }}
    };
    static int *ett[] = {
        &ett_vsock,
        &ett_virtio
    };

    vsock_address_type = address_type_dissector_register("AT_VSOCK", "vSocket Address",
            vsock_addr_to_str, vsock_addr_str_len, NULL, NULL, NULL, NULL, NULL);

    proto_vsock = proto_register_protocol("vSocket", "vsock", "vsock");
    proto_register_field_array(proto_vsock, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    vsock_handle = register_dissector("vsock", dissect_vsock, proto_vsock);
}

void
proto_reg_handoff_vsock(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_VSOCK, vsock_handle);
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
