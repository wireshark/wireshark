/* packet-rsvd.c
 * Routines for RSVD dissection
 * Copyright 2015, Richard Sharpe <realrichardsharpe@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * RSVD, documented in [MS-RSVD].pdf, by Microsoft, the Remote Shared Virtual
 * Disk protocol.
 */

#include "config.h"

#include <epan/packet.h>

void proto_reg_handoff_rsvd(void);
void proto_register_rsvd(void);

static int proto_rsvd = -1;
static int hf_svhdx_protocol_id = -1;
static int hf_svhdx_protocol_version = -1;
static int hf_svhdx_operation_code = -1;
static int hf_svhdx_status = -1;
static int hf_svhdx_request_id = -1;
static int hf_svhdx_tunnel_scsi_length = -1;
static int hf_svhdx_tunnel_scsi_reserved1 = -1;
static int hf_svhdx_tunnel_scsi_cdb_length = -1;
static int hf_svhdx_tunnel_scsi_sense_info_ex_length = -1;
static int hf_svhdx_tunnel_scsi_data_in = -1;
static int hf_svhdx_tunnel_scsi_reserved2 =  -1;
static int hf_svhdx_tunnel_scsi_srb_flags = -1;
static int hf_svhdx_tunnel_scsi_data_transfer_length = -1;
static int hf_svhdx_tunnel_scsi_reserved3 = -1;
static int hf_svhdx_tunnel_scsi_cdb = -1;
static int hf_svhdx_tunnel_scsi_data = -1;
static int hf_svhdx_tunnel_scsi_auto_generated_sense = -1;
static int hf_svhdx_tunnel_scsi_srb_status = -1;
static int hf_svhdx_tunnel_scsi_sense_data_ex = -1;
static int hf_svhdx_tunnel_scsi_status = -1;
static int hf_svhdx_tunnel_file_info_server_version = -1;
static int hf_svhdx_tunnel_file_info_sector_size = -1;
static int hf_svhdx_tunnel_file_info_physical_sector_size = -1;
static int hf_svhdx_tunnel_file_info_reserved = -1;
static int hf_svhdx_tunnel_file_info_virtual_size = -1;
static int hf_svhdx_tunnel_disk_info_reserved1 = -1;
static int hf_svhdx_tunnel_disk_info_blocksize = -1;
static int hf_svhdx_tunnel_disk_info_linkage_id = -1;
static int hf_svhdx_tunnel_disk_info_disk_type = -1;
static int hf_svhdx_tunnel_disk_info_disk_format = -1;
static int hf_svhdx_tunnel_disk_info_is_mounted = -1;
static int hf_svhdx_tunnel_disk_info_is_4k_aligned = -1;
static int hf_svhdx_tunnel_disk_info_reserved = -1;
static int hf_svhdx_tunnel_disk_info_file_size = -1;
static int hf_svhdx_tunnel_disk_info_virtual_disk_id = -1;
static int hf_svhdx_tunnel_validate_disk_reserved = -1;
static int hf_svhdx_tunnel_validate_disk_is_valid_disk = -1;

static gint ett_rsvd = -1;
static gint ett_svhdx_tunnel_op_header = -1;
static gint ett_svhdx_tunnel_scsi_request = -1;
static gint ett_svhdx_tunnel_file_info_response = -1;

static const value_string rsvd_operation_code_vals[] = {
        { 1, "RSVD_TUNNEL_GET_FILE_INFO" },
        { 2, "RSVD_TUNNEL_SCSI" },
        { 3, "RSVD_TUNNEL_CHECK_CONNECTON_STATUS" },
        { 4, "RSVD_TUNNEL_SRB_STATUS" },
        { 5, "RSVD_TUNNEL_GET_DISK_INFO" },
        { 6, "RSVD_TUNNEL_VALIDATE_DISK" },
        { 0, NULL }
};

static const value_string rsvd_disk_type_vals[] = {
        { 0x02, "VHD_TYPE_FIXED" },
        { 0x03, "VHD_TYPE_DYNAMIC" },
        { 0, NULL }
};

static const value_string rsvd_disk_format_vals[] = {
        { 0x03, "VIRTUAL_STORAGE_TYPE_DEVICE_VHDX" },
        { 0, NULL }
};

static void
dissect_RSVD_GET_FILE_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    if (!request) {
        proto_tree *gfi_sub_tree;
        proto_item *gfi_sub_item _U_;

        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_GET_FILE_INFO_RESPONSE");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_server_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_sector_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_physical_sector_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_file_info_virtual_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
       offset += 8;
    }
}

static void
dissect_RSVD_TUNNEL_SCSI(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    proto_tree *sub_tree;
    proto_item *sub_item;
    guint32 cdb_length;
    guint32 data_transfer_length;
    guint32 sense_info_ex_length;

    sub_tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, len, ett_svhdx_tunnel_scsi_request, &sub_item, "SVHDX_TUNNEL_SCSI_%s", (request ? "REQUEST" : "RESPONSE"));

    if (request) {
        /* tvbuff_t *scsi_cdb = NULL; */

        /* Length */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* Reserved1 */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_reserved1, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* CDBLength */
        cdb_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_cdb_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* SensInfoExLength */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_sense_info_ex_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* DataIn */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data_in, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* Reserved2 */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_reserved2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* SrbFlags */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_srb_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* DataTransferLength */
        data_transfer_length = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data_transfer_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* CDBBuffer */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_cdb, tvb, offset, cdb_length, ENC_NA);
        offset += cdb_length;

        /* Reserved3 */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_reserved3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* DataBuffer */
        if (data_transfer_length) {
            proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data, tvb, offset, data_transfer_length, ENC_NA);
            offset += data_transfer_length;
        }
    } else {
        guint16 statuses = 0;
        guint8 auto_generated_sense = 0;
        guint8 srb_status = 0;
        guint8 scsi_status = 0;

        /* Length */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* A */
        statuses = tvb_get_letohs(tvb, offset); /* Got two bytes here */
        auto_generated_sense = statuses >> 15;
        proto_tree_add_boolean(sub_tree, hf_svhdx_tunnel_scsi_auto_generated_sense, tvb, offset, 1, auto_generated_sense);

        /* SrbStatus */
        srb_status = statuses & 0x07;
        proto_tree_add_uint(sub_tree, hf_svhdx_tunnel_scsi_srb_status, tvb, offset, 1, srb_status);
        offset++;

        /* ScsiStatus */
        scsi_status = statuses >> 8;
        proto_tree_add_uint(sub_tree, hf_svhdx_tunnel_scsi_status, tvb, offset, 1, scsi_status);
        offset++;

        /* CdbLength */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_cdb_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* SensInfoExLength */
        sense_info_ex_length = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_sense_info_ex_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* DataIn */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data_in, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* Reserved */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_reserved2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        /* SrbFlags */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_srb_flags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* DataTransferLength */
        data_transfer_length = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data_transfer_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        /* SenseDataEx */
        proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_sense_data_ex, tvb, offset, sense_info_ex_length, ENC_NA);
        offset += sense_info_ex_length;

        /* DataBuffer */
        if (data_transfer_length) {
            proto_tree_add_item(sub_tree, hf_svhdx_tunnel_scsi_data, tvb, offset, data_transfer_length, ENC_NA);
            offset += data_transfer_length;
        }
    }
}

static void
dissect_RSVD_GET_DISK_INFO(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    if (request) {
        proto_tree *gfi_sub_tree _U_;
        proto_item *gfi_sub_item _U_;

        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_GET_DISK_INFO_REQUEST");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_reserved1, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_blocksize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_linkage_id, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_is_mounted, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_is_4k_aligned, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_file_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_virtual_disk_id, tvb, offset, 16, ENC_NA);
        offset += 16;
    } else {
        proto_tree *gfi_sub_tree _U_;
        proto_item *gfi_sub_item _U_;

        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_GET_DISK_INFO_RESPONSE");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_disk_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_disk_format, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_blocksize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_linkage_id, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_is_mounted, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_is_4k_aligned, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_file_size, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_disk_info_virtual_disk_id, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
}

static void
dissect_RSVD_VALIDATE_DISK(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree, int offset, gint16 len, gboolean request)
{
    if (request) {
        proto_tree *gfi_sub_tree _U_;
        proto_item *gfi_sub_item _U_;

        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_VALIDATE_DISK_REQUEST");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_validate_disk_reserved, tvb, offset, 56, ENC_NA);
        offset += 56;
    } else {
        proto_tree *gfi_sub_tree _U_;
        proto_item *gfi_sub_item _U_;

        gfi_sub_tree = proto_tree_add_subtree(parent_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &gfi_sub_item, "RSVD_TUNNEL_VALIDATE_DISK_RESPONSE");

        proto_tree_add_item(gfi_sub_tree, hf_svhdx_tunnel_validate_disk_is_valid_disk, tvb, offset, 1, ENC_NA);
        offset += 1;
    }
}

static int
dissect_rsvd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
    guint32 header_bytes = 0;
    guint proto_id = 0;
    guint proto_version = 0;
    guint operation_code = 0;
    proto_item *ti;
    proto_tree *rsvd_tree;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint       offset = 0;
    guint16 len;
    gboolean request = *(gboolean *)data;

    len = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSVD");

    col_clear(pinfo->cinfo, COL_INFO);

    /*
     * The header bytes need to be pulled in as a 32bit LE value. And the
     * header is the same in a request or a response ...
     */
    header_bytes = tvb_get_letohl(tvb, 0); /* Get the header bytes */
    proto_id = header_bytes >> 24;
    proto_version = (header_bytes >> 12) & 0x0FFF;
    operation_code = header_bytes & 0x0FFF;

    ti = proto_tree_add_item(parent_tree, proto_rsvd, tvb, offset, -1, ENC_NA);

    rsvd_tree = proto_item_add_subtree(ti, ett_rsvd);

    sub_tree = proto_tree_add_subtree(rsvd_tree, tvb, offset, len, ett_svhdx_tunnel_op_header, &sub_item, "SVHDX_TUNNEL_OPERATION_HEADER");

    /* ProtocolID */
    proto_tree_add_uint(sub_tree, hf_svhdx_protocol_id, tvb, offset, 4, proto_id);

    /* ProtocolVersion */
    proto_tree_add_uint(sub_tree, hf_svhdx_protocol_version, tvb, offset, 4, proto_version);

    /* Operation Code */
    proto_tree_add_uint(sub_tree, hf_svhdx_operation_code, tvb, offset, 4, operation_code);
    offset += 4;

    /* Status */
    proto_tree_add_item(sub_tree, hf_svhdx_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* RequestId */
    proto_tree_add_item(sub_tree, hf_svhdx_request_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

   col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                    val_to_str(operation_code,
                               rsvd_operation_code_vals,
                               "Unknown Operation Code (0x%03X)"),
                    request ? "Request" : "Response");

   proto_item_append_text(ti, ", %s %s",
                          val_to_str(operation_code,
                                     rsvd_operation_code_vals,
                                     "Unknown Operation Code (0x%03X)"),
                          request ? "Request" : "Response");
    /*
     * Now process the individual requests ...
     */
    switch (operation_code) {
    case 0x001:
        dissect_RSVD_GET_FILE_INFO(tvb, pinfo, rsvd_tree, offset, len - offset, request);
        break;

    case 0x002:
        dissect_RSVD_TUNNEL_SCSI(tvb, pinfo, rsvd_tree, offset, len - offset, request);
        break;

    case 0x003:

        /*
         * There is nothing more here.
         */

        break;

    case 0x004:
        break;

    case 0x005:
        dissect_RSVD_GET_DISK_INFO(tvb, pinfo, rsvd_tree, offset, len - offset, request);
        break;

    case 0x006:
        dissect_RSVD_VALIDATE_DISK(tvb, pinfo, rsvd_tree, offset, len - offset, request);
        break;

    default:
        break;
    }

    return len;
}

void
proto_register_rsvd(void)
{

    static hf_register_info hf[] = {
                { &hf_svhdx_protocol_id,
                  { "ProtocolId", "rsvd.svhdx_protocol_id", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_protocol_version,
                  { "ProtocolVersion", "rsvd.svhdx_protocol_version", FT_UINT16, BASE_DEC,
                     NULL, 0, NULL, HFILL }},

                { &hf_svhdx_operation_code,
                  { "OperationCode", "rsvd.svhdx_operation_code", FT_UINT16, BASE_HEX,
                     VALS(rsvd_operation_code_vals), 0, "Operation Code", HFILL }},

                { &hf_svhdx_status,
                  { "Status", "rsvd.svhdx_status", FT_UINT32, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_request_id,
                  { "RequestId", "rsvd.svhdx_request_id", FT_UINT64, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_length,
                  { "Length", "rsvd.svhdx_length", FT_UINT16, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_reserved1,
                  { "Reserved1", "rsvd.svhdx_scsi_reserved1", FT_UINT16, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_cdb_length,
                  { "CDBLength", "rsvd.svhdx_scsi_cdb_length", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_sense_info_ex_length,
                  { "SenseInfoExLength", "rsvd.svhdx_scsi_sense_info_ex_length", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_data_in,
                  { "DataIn", "rsvd.svhdx_scsi_data_in", FT_BOOLEAN, 8,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_reserved2,
                  { "Reserved2", "rsvd.svhdx_scsi_reserved2", FT_UINT8, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_srb_flags,
                  { "SRBFlags", "rsvd.svhdx_scsi_srbflags", FT_UINT32, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_data_transfer_length,
                  { "DataTransferLength", "rsvd.svhdx_scsi_data_transfer_length", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_reserved3,
                  { "Reserved3", "rsvd.svhdx_scsi_reserved3", FT_UINT32, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_cdb,
                  { "CDB", "rsvd.svhdx_scsi_cdb", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_data,
                  {"Data", "rsvd.svhdx_scsi_data", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_auto_generated_sense,
                  {"AutoGeneratedSenseInfo", "rsvd.svhdx_auto_generated_sense_info", FT_BOOLEAN, 8,
                   NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_srb_status,
                  { "SrbStatus", "rsvd.svhdx_srb_status", FT_UINT8, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_status,
                  { "ScsiStatus", "rsvd.svhdx_scsi_status", FT_UINT8, BASE_HEX,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_scsi_sense_data_ex,
                  { "SenseDataEx", "rsvd.svhdx_scsi_sense_data_ex", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_server_version,
                  { "ServerVersion", "rsvd.svhdx_file_info_server_version", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_sector_size,
                  { "SectorSize", "rsvd.svhdx_file_info_sector_size", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_physical_sector_size,
                  { "PhysicalSectorSize", "rsvd.svhdx_file_info_physical_sector_size", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_reserved,
                  { "Reserved", "rsvd.svhdx_file_info_reserved", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_file_info_virtual_size,
                  { "VirtualSize", "rsvd.svhdx_file_info_virtual_size", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},


                { &hf_svhdx_tunnel_disk_info_reserved1,
                  { "Reserved1", "rsvd.svhdx_disk_info_reserved1", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_blocksize,
                  { "BlockSize", "rsvd.svhdx_disk_info_blocksize", FT_UINT32, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_linkage_id,
                  { "LinkageID", "rsvd.svhdx_disk_info_linkage_id", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_disk_type,
                  { "DiskType", "rsvd.svhdx_disk_info_disk_type", FT_UINT16, BASE_HEX,
                     VALS(rsvd_disk_type_vals), 0, "Disk Type", HFILL }},

                { &hf_svhdx_tunnel_disk_info_disk_format,
                  { "DiskFormat", "rsvd.svhdx_disk_info_disk_format", FT_UINT16, BASE_HEX,
                     VALS(rsvd_disk_format_vals), 0, "Disk Format", HFILL }},

                { &hf_svhdx_tunnel_disk_info_is_mounted,
                  { "IsMounted", "rsvd.svhdx_tunnel_disk_info_is_mounted", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_is_4k_aligned,
                  { "Is4KAligned", "rsvd.svhdx_tunnel_disk_info_is_4k_aligned", FT_UINT8, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_reserved,
                  { "Reserved", "rsvd.svhdx_disk_info_reserved", FT_UINT16, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_file_size,
                  { "FileSize", "rsvd.svhdx_disk_info_file_size", FT_UINT64, BASE_DEC,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_disk_info_virtual_disk_id,
                  { "VirtualDiskId", "rsvd.svhdx_disk_info_virtual_disk_id", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_validate_disk_reserved,
                  { "Reserved", "rsvd.svhdx_tunnel_validate_disk_reserved", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},

                { &hf_svhdx_tunnel_validate_disk_is_valid_disk,
                  { "IsValidDisk", "rsvd.svhdx_validate_disk_is_valid_disk", FT_BYTES, BASE_NONE,
                    NULL, 0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_rsvd,
        &ett_svhdx_tunnel_op_header,
        &ett_svhdx_tunnel_scsi_request,
        &ett_svhdx_tunnel_file_info_response
    };

    proto_rsvd = proto_register_protocol("Remote Shared Virtual Disk",
            "RSVD", "rsvd");

    new_register_dissector("rsvd", dissect_rsvd, proto_rsvd);
    proto_register_field_array(proto_rsvd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
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
