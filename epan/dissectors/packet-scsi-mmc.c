/* packet-scsi-mmc.c
 * Ronnie Sahlberg 2006
 * copied from packet-scsi.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002 Gerald Combs
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
#include <epan/conversation.h>
#include <epan/tap.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-mmc.h"
#include "packet-scsi-sbc.h"

void proto_register_scsi_mmc(void);

static int proto_scsi_mmc = -1;
int hf_scsi_mmc_opcode = -1;
static int hf_scsi_mmc_setstreaming_type = -1;
static int hf_scsi_mmc_setstreaming_param_len = -1;
static int hf_scsi_mmc_setstreaming_wrc = -1;
static int hf_scsi_mmc_setstreaming_rdd = -1;
static int hf_scsi_mmc_setstreaming_exact = -1;
static int hf_scsi_mmc_setstreaming_ra = -1;
static int hf_scsi_mmc_setstreaming_start_lba = -1;
static int hf_scsi_mmc_setstreaming_end_lba = -1;
static int hf_scsi_mmc_setstreaming_read_size = -1;
static int hf_scsi_mmc_setstreaming_read_time = -1;
static int hf_scsi_mmc_setstreaming_write_size = -1;
static int hf_scsi_mmc_setstreaming_write_time = -1;
static int hf_scsi_mmc_setcdspeed_rc = -1;
static int hf_scsi_mmc_rbc_block = -1;
static int hf_scsi_mmc_rbc_lob_blocks = -1;
static int hf_scsi_mmc_rbc_alob_blocks = -1;
static int hf_scsi_mmc_rbc_lob_bytes = -1;
static int hf_scsi_mmc_rbc_alob_bytes = -1;
static int hf_scsi_mmc_rti_address_type = -1;
static int hf_scsi_mmc_rti_damage = -1;
static int hf_scsi_mmc_rti_copy = -1;
static int hf_scsi_mmc_rti_track_mode = -1;
static int hf_scsi_mmc_rti_rt = -1;
static int hf_scsi_mmc_rti_blank = -1;
static int hf_scsi_mmc_rti_packet = -1;
static int hf_scsi_mmc_rti_fp = -1;
static int hf_scsi_mmc_rti_data_mode = -1;
static int hf_scsi_mmc_rti_lra_v = -1;
static int hf_scsi_mmc_rti_nwa_v = -1;
static int hf_scsi_mmc_report_key_type_code = -1;
static int hf_scsi_mmc_report_key_vendor_resets = -1;
static int hf_scsi_mmc_report_key_user_changes = -1;
static int hf_scsi_mmc_report_key_region_mask = -1;
static int hf_scsi_mmc_report_key_rpc_scheme = -1;
static int hf_scsi_mmc_key_class = -1;
static int hf_scsi_mmc_key_format = -1;
static int hf_scsi_mmc_disc_info_erasable = -1;
static int hf_scsi_mmc_disc_info_state_of_last_session = -1;
static int hf_scsi_mmc_disc_info_disk_status = -1;
static int hf_scsi_mmc_disc_info_number_of_sessions = -1;
static int hf_scsi_mmc_disc_info_first_track_in_last_session = -1;
static int hf_scsi_mmc_disc_info_last_track_in_last_session = -1;
static int hf_scsi_mmc_disc_info_did_v = -1;
static int hf_scsi_mmc_disc_info_dbc_v = -1;
static int hf_scsi_mmc_disc_info_uru = -1;
static int hf_scsi_mmc_disc_info_dac_v = -1;
static int hf_scsi_mmc_disc_info_dbit = -1;
static int hf_scsi_mmc_disc_info_bgfs = -1;
static int hf_scsi_mmc_disc_info_disc_type = -1;
static int hf_scsi_mmc_disc_info_disc_identification = -1;
static int hf_scsi_mmc_disc_info_last_session_lead_in_start_address = -1;
static int hf_scsi_mmc_disc_info_last_possible_lead_out_start_address = -1;
static int hf_scsi_mmc_disc_info_disc_bar_code = -1;
static int hf_scsi_mmc_readtoc_time = -1;
static int hf_scsi_mmc_readtoc_format = -1;
static int hf_scsi_mmc_readtoc_first_session = -1;
static int hf_scsi_mmc_readtoc_last_track = -1;
static int hf_scsi_mmc_readtoc_last_session = -1;
static int hf_scsi_mmc_q_subchannel_adr = -1;
static int hf_scsi_mmc_q_subchannel_control = -1;
static int hf_scsi_mmc_agid = -1;
static int hf_scsi_mmc_track = -1;
static int hf_scsi_mmc_track_size = -1;
static int hf_scsi_mmc_track_start_address = -1;
static int hf_scsi_mmc_track_start_time = -1;
static int hf_scsi_mmc_lba             = -1;
static int hf_scsi_mmc_session = -1;
static int hf_scsi_mmc_data_length           = -1;
static int hf_scsi_mmc_getconf_rt = -1;
static int hf_scsi_mmc_getconf_starting_feature = -1;
static int hf_scsi_mmc_getconf_current_profile = -1;
static int hf_scsi_mmc_feature = -1;
static int hf_scsi_mmc_feature_version = -1;
static int hf_scsi_mmc_feature_persistent = -1;
static int hf_scsi_mmc_feature_current = -1;
static int hf_scsi_mmc_feature_additional_length = -1;
static int hf_scsi_mmc_feature_lun_sn = -1;
static int hf_scsi_mmc_feature_cdread_dap = -1;
static int hf_scsi_mmc_feature_cdread_c2flag = -1;
static int hf_scsi_mmc_feature_cdread_cdtext = -1;
static int hf_scsi_mmc_feature_dvdrw_write = -1;
static int hf_scsi_mmc_feature_dvdrw_quickstart = -1;
static int hf_scsi_mmc_feature_dvdrw_closeonly = -1;
static int hf_scsi_mmc_feature_dvdr_write = -1;
static int hf_scsi_mmc_feature_tao_buf = -1;
static int hf_scsi_mmc_feature_tao_rwraw = -1;
static int hf_scsi_mmc_feature_tao_rwpack = -1;
static int hf_scsi_mmc_feature_tao_testwrite = -1;
static int hf_scsi_mmc_feature_tao_cdrw = -1;
static int hf_scsi_mmc_feature_tao_rwsubcode = -1;
static int hf_scsi_mmc_feature_dts = -1;
static int hf_scsi_mmc_feature_sao_buf = -1;
static int hf_scsi_mmc_feature_sao_sao = -1;
static int hf_scsi_mmc_feature_sao_rawms = -1;
static int hf_scsi_mmc_feature_sao_raw = -1;
static int hf_scsi_mmc_feature_sao_testwrite = -1;
static int hf_scsi_mmc_feature_sao_cdrw = -1;
static int hf_scsi_mmc_feature_sao_rw = -1;
static int hf_scsi_mmc_feature_sao_mcsl = -1;
static int hf_scsi_mmc_feature_dvdr_buf = -1;
static int hf_scsi_mmc_feature_dvdr_testwrite = -1;
static int hf_scsi_mmc_feature_dvdr_dvdrw = -1;
static int hf_scsi_mmc_feature_profile = -1;
static int hf_scsi_mmc_feature_profile_current = -1;
static int hf_scsi_mmc_feature_isw_buf = -1;
static int hf_scsi_mmc_feature_isw_num_linksize = -1;
static int hf_scsi_mmc_feature_isw_linksize = -1;
static int hf_scsi_mmc_read_compatibility_lba             = -1;
static int hf_scsi_mmc_reservation_size = -1;
static int hf_scsi_mmc_last_recorded_address = -1;
static int hf_scsi_mmc_first_track = -1;
static int hf_scsi_mmc_fixed_packet_size = -1;
static int hf_scsi_mmc_closetrack_immed = -1;
static int hf_scsi_mmc_closetrack_func = -1;
static int hf_scsi_mmc_synccache_immed = -1;
static int hf_scsi_mmc_synccache_reladr = -1;
static int hf_scsi_mmc_num_blocks      = -1;
static int hf_scsi_mmc_next_writable_address = -1;
static int hf_scsi_mmc_free_blocks = -1;
static int hf_scsi_mmc_read_dvd_format = -1;
static int hf_scsi_mmc_disc_book_type = -1;
static int hf_scsi_mmc_disc_book_version = -1;
static int hf_scsi_mmc_disc_size_size = -1;
static int hf_scsi_mmc_disc_size_rate = -1;
static int hf_scsi_mmc_disc_num_layers = -1;
static int hf_scsi_mmc_disc_track_path = -1;
static int hf_scsi_mmc_disc_structure_layer = -1;
static int hf_scsi_mmc_disc_density_length = -1;
static int hf_scsi_mmc_disc_density_pitch = -1;
static int hf_scsi_mmc_disc_first_physical = -1;
static int hf_scsi_mmc_disc_last_physical = -1;
static int hf_scsi_mmc_disc_last_physical_layer0 = -1;
static int hf_scsi_mmc_disc_extended_format_info = -1;
static int hf_scsi_mmc_disc_application_code = -1;
static int hf_scsi_mmc_adip_eib0 = -1;
static int hf_scsi_mmc_adip_eib1 = -1;
static int hf_scsi_mmc_adip_eib2 = -1;
static int hf_scsi_mmc_adip_eib3 = -1;
static int hf_scsi_mmc_adip_eib4 = -1;
static int hf_scsi_mmc_adip_eib5 = -1;
static int hf_scsi_mmc_adip_device_manuf_id = -1;
static int hf_scsi_mmc_adip_media_type_id = -1;
static int hf_scsi_mmc_adip_product_revision_number = -1;
static int hf_scsi_mmc_adip_number_of_physical_info = -1;
static int hf_scsi_mmc_gesn_polled = -1;
static int hf_scsi_mmc_notification_flags = -1;
static int hf_scsi_mmc_gesn_device_busy = -1;
static int hf_scsi_mmc_gesn_multi_initiator = -1;
static int hf_scsi_mmc_gesn_media = -1;
static int hf_scsi_mmc_gesn_external_request = -1;
static int hf_scsi_mmc_gesn_power_mgmt = -1;
static int hf_scsi_mmc_gesn_operational_change = -1;
static int hf_scsi_mmc_prevent_allow_flags = -1;
static int hf_scsi_mmc_prevent_allow_persistent = -1;
static int hf_scsi_mmc_prevent_allow_prevent = -1;
static int hf_scsi_mmc_disk_flags = -1;
static int hf_scsi_mmc_format_flags = -1;
static int hf_scsi_mmc_track_flags = -1;
static int hf_scsi_mmc_data_flags = -1;

static gint ett_scsi_mmc_profile   = -1;
static gint ett_scsi_notifications = -1;
static gint ett_scsi_prevent_allow = -1;
static gint ett_scsi_disk_flags = -1;
static gint ett_scsi_format_flags = -1;
static gint ett_scsi_track_flags = -1;
static gint ett_scsi_data_flags = -1;

static const true_false_string scsi_gesn_path = {
    "POLLED operation requested",
    "ASYNCHRONOUS operation requested"
};
static const true_false_string scsi_track_path = {
    "Opposite Track Path",
    "Parallel Track Path"
};
static const true_false_string scsi_adip_extended_format_info = {
    "Data zone contains extended format info for VPCS",
    "Data zone does NOT contain extended format info"
};
static const value_string scsi_disk_application_code[] = {
    {0x0, "General Purpose Use"},
    {0,NULL}
};
static const value_string scsi_density_length[] = {
    {0x0, "0.133um"},
    {0,NULL}
};
static const value_string scsi_density_pitch[] = {
    {0x0, "0.74um"},
    {0x1, "0.80um"},
    {0x2, "0.615um"},
    {0,NULL}
};
static const value_string scsi_disc_structure[] = {
    {0x0, "Embossed layer"},
    {0x2, "Write-once recording layer"},
    {0x4, "Rewriteable recording layer"},
    {0,NULL}
};
static const value_string scsi_num_layers[] = {
    {0x0, "1 layer"},
    {0x1, "2 layers"},
    {0x2, "3 layers"},
    {0x3, "4 layers"},
    {0,NULL}
};
static const value_string scsi_disc_size[] = {
    {0x0, "120mm"},
    {0x1, "80mm"},
    {0,NULL}
};
static const value_string scsi_disc_rate[] = {
    {0x0, "2.52Mbps"},
    {0x1, "5.04Mbps"},
    {0x2, "10.08Mbps"},
    {0xf, "No maximum transfer rate specified"},
    {0,NULL}
};
static const value_string scsi_disc_category_type[] = {
    {0x0, "DVD-ROM"},
    {0x1, "DVD-RAM"},
    {0x2, "DVD-R"},
    {0x3, "DVD-RW"},
    {0x9, "DVD+RW"},
    {0xa, "DVD+R"},
    {0,NULL}
};

static const value_string scsi_read_dvd_formats[] = {
    {0x00, "Physical Information"},
    {0x01, "Copyright Information"},
    {0x02, "Disk Key obfuscated by a Bus Key"},
    {0x03, "Burst Cutting Area information"},
    {0x04, "Disk Manufacturing Information"},
    {0x05, "copyright Management Information"},
    {0x06, "Media Identifier protected by a Bus Key"},
    {0x07, "Media Key block protected by a Bus Key"},
    {0x08, "DDS information"},
    {0x09, "DVD-RAM Medium status"},
    {0x0a, "DVD-RAM Spare Area information"},
    {0x0b, "DVD-RAM Recording Type information"},
    {0x0c, "DVD-R/-RW RMD"},
    {0x0d, "Specified RMD"},
    {0x0e, "Pre-recorded information"},
    {0x0f, "DVD-R/-RW Media Identifier"},
    {0x10, "DVD-R/-RW Physical Format Information"},
    {0x11, "ADIP information"},
    {0x30, "Disc Control Block"},
    {0x31, "Read MTA ECC Block"},
    {0xc0, "Write Protection Status"},
    {0xff, "READ/SEND DVD STRUCTURE capability"},
    {0,NULL}
};
static value_string_ext scsi_read_dvd_formats_ext = VALUE_STRING_EXT_INIT(scsi_read_dvd_formats);

static const value_string scsi_data_mode_vals[] = {
    {0x01, "Mode 1 (ISO/IEC 10149)"},
    {0x02, "Mode 2 (ISO/IEC 10149 or CD-ROM XA) DDCD"},
    {0x0f, "Data Block Type unknown (no track descriptor block)"},
    {0,NULL}
};
static const value_string scsi_getconf_rt_val[] = {
    {0x00, "Return all features"},
    {0x01, "Return all current features"},
    {0x02, "Return all identified by Starting Feature"},
    {0,NULL}
};
static const value_string scsi_getconf_current_profile_val[] = {
    {0x0000, "Reserved"},
    {0x0001, "Non-removable disk"},
    {0x0002, "Removable disk"},
    {0x0003, "MO Erasable"},
    {0x0004, "Optical Write Once"},
    {0x0005, "AS-MO"},
    {0x0008, "CD-ROM"},
    {0x0009, "CD-R"},
    {0x000a, "CD-RW"},
    {0x0010, "DVD-ROM"},
    {0x0011, "DVD-R"},
    {0x0012, "DVD-RAM"},
    {0x0013, "DVD-RW Restricted Overwrite"},
    {0x0014, "DVD-RW Sequential recording"},
    {0x001a, "DVD+RW"},
    {0x001b, "DVD+R"},
    {0x0020, "DDCD-ROM"},
    {0x0021, "DDCD-R"},
    {0x0022, "DDCD-RW"},
    {0xffff, "Logical unit not conforming to a standard profile"},
    {0,NULL}
};
static value_string_ext scsi_getconf_current_profile_val_ext = VALUE_STRING_EXT_INIT(scsi_getconf_current_profile_val);

static const value_string scsi_feature_val[] = {
    {0x0000, "Profile List"},
    {0x0001, "Core"},
    {0x0002, "Morphing"},
    {0x0003, "Removable Medium"},
    {0x0004, "Write Protect"},
    {0x0010, "Random Readable"},
    {0x001d, "Multi-read"},
    {0x001e, "CD Read"},
    {0x001f, "DVD Read"},
    {0x0020, "Random Writeable"},
    {0x0021, "Incremental Streaming Writeable"},
    {0x0022, "Sector Erasable"},
    {0x0023, "Formattable"},
    {0x0024, "Defect Management"},
    {0x0025, "Write Once"},
    {0x0026, "Restricted Overwrite"},
    {0x0027, "CD-RW CAV Write"},
    {0x0028, "MRW"},
    {0x0029, "Enhanced Defect Reporting"},
    {0x002a, "DVD+RW"},
    {0x002b, "DVD+R"},
    {0x002c, "Rigid Restricted Overwrite"},
    {0x002d, "CD Track At Once"},
    {0x002e, "CD Mastering"},
    {0x002f, "DVD-R/-RW Write"},
    {0x0030, "DDCD Read"},
    {0x0031, "DDCD-R Write"},
    {0x0032, "DDCD-RW Write"},
    {0x0037, "CD-RW Media Write Support"},
    {0x0100, "Power Management"},
    {0x0101, "SMART"},
    {0x0102, "Embedded Changer"},
    {0x0103, "CD Audio analog play"},
    {0x0104, "Microcode Upgrade"},
    {0x0105, "Timeout"},
    {0x0106, "DVD-CSS"},
    {0x0107, "Real Time Streaming"},
    {0x0108, "Logical Unit serial number"},
    {0x010a, "Disc control Block"},
    {0x010b, "DVD CPRM"},
    {0x010c, "Firmware Information"},
    {0,NULL}
};
static value_string_ext scsi_feature_val_ext = VALUE_STRING_EXT_INIT(scsi_feature_val);

static void
dissect_mmc4_getconfiguration (tvbuff_t *tvb_a, packet_info *pinfo,
                               proto_tree *tree, guint offset_a,
                               gboolean isreq, gboolean iscdb,
                               guint payload_len _U_,
                               scsi_task_data_t *cdata)

{
    gint32             len;
    guint              old_offset;

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_mmc_getconf_rt, tvb_a, offset_a+0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_getconf_starting_feature, tvb_a, offset_a+1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb_a, offset_a+6, 2, ENC_BIG_ENDIAN);
        /* we need the alloc_len in the response */
        if(cdata){
            cdata->itlq->alloc_len=tvb_get_ntohs(tvb_a, offset_a+6);
        }
        proto_tree_add_bitmask(tree, tvb_a, offset_a+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    if(!isreq) {
        if(!cdata){
            return;
        }

        TRY_SCSI_CDB_ALLOC_LEN(cdata->itlq->alloc_len);  /* (defines/initializes try_tvb & try_offset) */

        len=tvb_get_ntohl(try_tvb, try_offset+0);
        proto_tree_add_item (tree, hf_scsi_mmc_data_length, try_tvb, try_offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_getconf_current_profile, try_tvb, try_offset+6, 2, ENC_BIG_ENDIAN);
        try_offset+=8;
        len-=4;
        while(len>0){
            guint16 feature;
            guint8 additional_length;
            guint8 num_linksize;

            feature=tvb_get_ntohs(try_tvb, try_offset);
            proto_tree_add_item (tree, hf_scsi_mmc_feature, try_tvb, try_offset, 2, ENC_BIG_ENDIAN);
            try_offset+=2;
            proto_tree_add_item (tree, hf_scsi_mmc_feature_version, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_feature_persistent, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_feature_current, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
            try_offset+=1;
            additional_length=tvb_get_guint8(try_tvb, try_offset);
            proto_tree_add_item (tree, hf_scsi_mmc_feature_additional_length, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
            try_offset+=1;
            old_offset=try_offset;
            switch(feature){
            case 0x0000: /* profile list */
                while(try_offset<(old_offset+additional_length)){
                    proto_item *it=NULL;
                    proto_tree *tr=NULL;
                    guint16 profile;
                    guint8  cur_profile;

                    if(tree){
                        it=proto_tree_add_text(tree, try_tvb, try_offset, 4, "Profile:");
                        tr=proto_item_add_subtree(it, ett_scsi_mmc_profile);
                    }

                    profile=tvb_get_ntohs(try_tvb, try_offset);
                    proto_tree_add_item (tr, hf_scsi_mmc_feature_profile, try_tvb, try_offset, 2, ENC_BIG_ENDIAN);
                    proto_item_append_text(it, "%s", val_to_str_ext(profile, &scsi_getconf_current_profile_val_ext, "Unknown 0x%04x"));

                    cur_profile=tvb_get_guint8(try_tvb, try_offset+2);
                    proto_tree_add_item (tr, hf_scsi_mmc_feature_profile_current, try_tvb, try_offset+2, 1, ENC_BIG_ENDIAN);
                    if(cur_profile&0x01){
                        proto_item_append_text(it, "  [CURRENT PROFILE]");
                    }

                    try_offset+=4;
                }
                break;
            case 0x001d: /* multi-read */
            case 0x001f: /* dvd read feature */
                /* no data for this one */
                break;
            case 0x001e: /* cd read */
                proto_tree_add_item (tree, hf_scsi_mmc_feature_cdread_dap, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_cdread_c2flag, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_cdread_cdtext, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                break;
            case 0x0021: /* incremental streaming writeable */
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dts, try_tvb, try_offset, 2, ENC_BIG_ENDIAN);
                try_offset+=2;
                proto_tree_add_item (tree, hf_scsi_mmc_feature_isw_buf, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                try_offset+=1;
                num_linksize=tvb_get_guint8(try_tvb, try_offset);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_isw_num_linksize, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                try_offset+=1;
                while(num_linksize--){
                    proto_tree_add_item (tree, hf_scsi_mmc_feature_isw_linksize, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                    try_offset+=1;
                }
                break;
            case 0x002a: /* dvd-rw */
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dvdrw_write, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dvdrw_quickstart, try_tvb, try_offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dvdrw_closeonly, try_tvb, try_offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x002b: /* dvd-r */
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dvdr_write, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                break;
            case 0x002d: /* track at once */
                proto_tree_add_item (tree, hf_scsi_mmc_feature_tao_buf, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_tao_rwraw, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_tao_rwpack, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_tao_testwrite, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_tao_cdrw, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_tao_rwsubcode, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dts, try_tvb, try_offset+2, 2, ENC_BIG_ENDIAN);
                break;
            case 0x002e: /* session at once */
                proto_tree_add_item (tree, hf_scsi_mmc_feature_sao_buf, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_sao_sao, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_sao_rawms, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_sao_raw, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_sao_testwrite, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_sao_cdrw, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_sao_rw, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_sao_mcsl, try_tvb, try_offset+1, 3, ENC_BIG_ENDIAN);
                break;
            case 0x002f: /* dvd-r/-rw*/
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dvdr_buf, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dvdr_testwrite, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_feature_dvdr_dvdrw, try_tvb, try_offset, 1, ENC_BIG_ENDIAN);
                break;
            case 0x0108: /* logical unit serial number */
                proto_tree_add_item (tree, hf_scsi_mmc_feature_lun_sn, try_tvb, try_offset, additional_length, ENC_ASCII|ENC_NA);
                break;
            default:
                proto_tree_add_text (tree, try_tvb, try_offset, additional_length,
                                     "SCSI/MMC Unknown Feature data");
                break;
            }
            try_offset=old_offset+additional_length;
            len-=4+additional_length;
        }
        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}


static const value_string scsi_q_subchannel_adr_val[] = {
    {0x0, "Q-Subchannel mode info not supplied"},
    {0x1, "Q-Subchannel encodes current position data"},
    {0x2, "Q-Subchannel encodes media catalog number"},
    {0x3, "Q-Subchannel encodes ISRC"},
    {0,NULL}
};
static const value_string scsi_q_subchannel_control_val[] = {
    {0x0, "2 Audio channels without pre-emphasis (digital copy prohibited)"},
    {0x1, "2 Audio channels with pre-emphasis of 50/15us (digital copy prohibited)"},
    {0x2, "2 Audio channels without pre-emphasis (digital copy permitted)"},
    {0x3, "2 Audio channels with pre-emphasis of 50/15us (digital copy permitted)"},
    {0x4, "Data track, recorded uninterrupted (digital copy prohibited)"},
    {0x5, "Data track, recorded incremental (digital copy prohibited)"},
    {0x6, "Data track, recorded uninterrupted (digital copy permitted)"},
    {0x7, "Data track, recorded incremental (digital copy permitted)"},
    {0x8, "audio channels without pre-emphasis (digital copy prohibited)"},
    {0x9, "2 Audio channels with pre-emphasis of 50/15us (digital copy prohibited)"},
    {0xa, "audio channels without pre-emphasis (digital copy permitted)"},
    {0xb, "2 Audio channels with pre-emphasis of 50/15us (digital copy permitted)"},
    {0,NULL}
};
static value_string_ext scsi_q_subchannel_control_val_ext = VALUE_STRING_EXT_INIT(scsi_q_subchannel_control_val);

static void
dissect_mmc4_readtocpmaatip (tvbuff_t *tvb_a, packet_info *pinfo, proto_tree *tree,
                     guint offset_a, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata)

{
    guint8 format;
    gint16 len;

    if (isreq && iscdb) {
        format=tvb_get_guint8(tvb_a, offset_a+1)&0x0f;
        /* save format so we can decode the response */
        cdata->itlq->flags=format;

        switch(format){
        case 0x00:
        case 0x01:
            proto_tree_add_item (tree, hf_scsi_mmc_readtoc_time, tvb_a, offset_a, 1, ENC_BIG_ENDIAN);
            /* save time so we can pick it up in the response */
            if(tvb_get_guint8(tvb_a, offset_a)&0x02){
                cdata->itlq->flags|=0x0100;
            }
            break;
        }
        proto_tree_add_item (tree, hf_scsi_mmc_readtoc_format, tvb_a, offset_a+1, 1, ENC_BIG_ENDIAN);

        switch(format){
        case 0x00:
            proto_tree_add_item (tree, hf_scsi_mmc_track, tvb_a, offset_a+5, 1, ENC_BIG_ENDIAN);
            /* save track so we can pick it up in the response */
            cdata->itlq->flags|=0x0200;
            break;
        case 0x02:
            proto_tree_add_item (tree, hf_scsi_mmc_session, tvb_a, offset_a+5, 1, ENC_BIG_ENDIAN);
            /* save session so we can pick it up in the response */
            cdata->itlq->flags|=0x0400;
            break;
        }

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb_a, offset_a + 6, 2, ENC_BIG_ENDIAN);
        cdata->itlq->alloc_len = tvb_get_ntohs(tvb_a, offset_a + 6);

        proto_tree_add_bitmask(tree, tvb_a, offset_a+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    if(!isreq) {
        TRY_SCSI_CDB_ALLOC_LEN(cdata->itlq->alloc_len);  /* (defines/initializes try_tvb & try_offset) */
        len=tvb_get_ntohs(try_tvb, try_offset);
        proto_tree_add_item (tree, hf_scsi_mmc_data_length, try_tvb, try_offset, 2, ENC_BIG_ENDIAN);
        if(cdata->itlq->flags&0x0200){
            proto_tree_add_item (tree, hf_scsi_mmc_first_track, try_tvb, try_offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_readtoc_last_track, try_tvb, try_offset+3, 1, ENC_BIG_ENDIAN);
        }
        if(cdata->itlq->flags&0x0400){
            proto_tree_add_item (tree, hf_scsi_mmc_readtoc_first_session, try_tvb, try_offset+2, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_readtoc_last_session, try_tvb, try_offset+3, 1, ENC_BIG_ENDIAN);
        }
        try_offset+=4;
        len-=2;
        switch(cdata->itlq->flags&0x000f){
        case 0x0:
            while(len>0){
                proto_tree_add_item (tree, hf_scsi_mmc_q_subchannel_adr, try_tvb, try_offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_q_subchannel_control, try_tvb, try_offset+1, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (tree, hf_scsi_mmc_track, try_tvb, try_offset+2, 1, ENC_BIG_ENDIAN);
                if(cdata->itlq->flags&0x0100){
                    proto_tree_add_item (tree, hf_scsi_mmc_track_start_time, try_tvb, try_offset+4, 4, ENC_BIG_ENDIAN);
                } else {
                    proto_tree_add_item (tree, hf_scsi_mmc_track_start_address, try_tvb, try_offset+4, 4, ENC_BIG_ENDIAN);
                }
                try_offset+=8;
                len-=8;
            }
            break;
        default:
            proto_tree_add_text (tree, try_tvb, try_offset, len,
                "SCSI/MMC Unknown READ TOC Format:0x%04x",cdata->itlq->flags&0x000f);
            break;
        }
        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

static const value_string scsi_disc_info_sols_val[] = {
    {0x00, "Empty Session"},
    {0x01, "Incomplete Session"},
    {0x02, "Reserved/Damaged Session"},
    {0x03, "Complete Session"},
    {0,NULL}
};

static const value_string scsi_disc_info_disc_status_val[] = {
    {0x00, "Empty Disc"},
    {0x01, "Incomplete Disc"},
    {0x02, "Finalized Disc"},
    {0x03, "Others"},
    {0,NULL}
};

static const value_string scsi_disc_info_bgfs_val[] = {
    {0x00, "Blank or not CD-RW/DVD-RW"},
    {0x01, "Background Format started but is not running nor complete"},
    {0x02, "Background Format in progress"},
    {0x03, "Background Format has completed"},
    {0,NULL}
};

static const value_string scsi_disc_info_disc_type_val[] = {
    {0x00, "CD-DA or CD-ROM Disc"},
    {0x10, "CD-I Disc"},
    {0x20, "CD-ROM XA Disc or DDCD"},
    {0xff, "Undefined"},
    {0,NULL}
};

static void
dissect_mmc4_readdiscinformation (tvbuff_t *tvb_a, packet_info *pinfo, proto_tree *tree,
                     guint offset_a, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata)
{
    if (iscdb) {
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb_a, offset_a + 6, 2, ENC_BIG_ENDIAN);
        if (cdata && cdata->itlq) {
            cdata->itlq->alloc_len = tvb_get_ntohs(tvb_a, offset_a + 6);
        }
        proto_tree_add_bitmask(tree, tvb_a, offset_a+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    if (!isreq) {
        static const int *disk_fields[] = {
            &hf_scsi_mmc_disc_info_erasable,
            &hf_scsi_mmc_disc_info_state_of_last_session,
            &hf_scsi_mmc_disc_info_disk_status,
            NULL
        };
        static const int *format_fields[] = {
            &hf_scsi_mmc_disc_info_did_v,
            &hf_scsi_mmc_disc_info_dbc_v,
            &hf_scsi_mmc_disc_info_uru,
            &hf_scsi_mmc_disc_info_dac_v,
            &hf_scsi_mmc_disc_info_dbit,
            &hf_scsi_mmc_disc_info_bgfs,
            NULL
        };

        TRY_SCSI_CDB_ALLOC_LEN( (cdata && cdata->itlq) ? cdata->itlq->alloc_len : 0);  /* (defines/initializes try_tvb & try_offset) */
        proto_tree_add_item (tree, hf_scsi_mmc_data_length, try_tvb, 0, 2, ENC_BIG_ENDIAN);

        proto_tree_add_bitmask(tree, try_tvb, try_offset + 2, hf_scsi_mmc_disk_flags,
             ett_scsi_disk_flags, disk_fields, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_first_track, try_tvb, try_offset+3, 1, ENC_BIG_ENDIAN);

       /* number of session  try_offset+4 and try_offset+9 */
        proto_tree_add_uint (tree, hf_scsi_mmc_disc_info_number_of_sessions, try_tvb, 4, 1, (tvb_get_guint8(try_tvb, try_offset+9)<<8)|tvb_get_guint8(try_tvb, try_offset+4));

        /* first track in last session  try_offset+5 and try_offset+10 */
        proto_tree_add_uint (tree, hf_scsi_mmc_disc_info_first_track_in_last_session, try_tvb, 5, 1, (tvb_get_guint8(try_tvb, try_offset+10)<<8)|tvb_get_guint8(try_tvb, try_offset+5));

        /*  last track in last session  try_offset+6 and try_offset+11 */
        proto_tree_add_uint (tree, hf_scsi_mmc_disc_info_last_track_in_last_session, try_tvb, 6, 1, (tvb_get_guint8(try_tvb, try_offset+11)<<8)|tvb_get_guint8(try_tvb, try_offset+6));

        proto_tree_add_bitmask(tree, try_tvb, try_offset + 7, hf_scsi_mmc_format_flags,
             ett_scsi_format_flags, format_fields, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_disc_info_disc_type, try_tvb, try_offset+8, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_disc_info_disc_identification, try_tvb, try_offset+12, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_disc_info_last_session_lead_in_start_address, try_tvb, try_offset+16, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_disc_info_last_possible_lead_out_start_address, try_tvb, try_offset+20, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_disc_info_disc_bar_code, try_tvb, try_offset+24, 8, ENC_BIG_ENDIAN);
        /* XXX should add OPC table decoding here ... */
        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

static void
dissect_mmc4_readdiscstructure (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        proto_tree_add_text (tree, tvb, offset+1, 4,
                             "Address: %u",
                             tvb_get_ntohl (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+5, 1,
                             "Layer Number: %u",
                             tvb_get_guint8 (tvb, offset+5));

        cdata->itlq->flags=tvb_get_guint8 (tvb, offset+6);
        proto_tree_add_uint (tree, hf_scsi_mmc_read_dvd_format, tvb, offset+6, 1, cdata->itlq->flags);

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+7, 2, ENC_BIG_ENDIAN);

        flags = tvb_get_guint8 (tvb, offset+9);
        proto_tree_add_text (tree, tvb, offset+9, 1,
                             "AGID: %u",
                             flags & 0xc0);

        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    if(tree && (!isreq)) {
        proto_item *ti;

        ti = proto_tree_add_uint (tree, hf_scsi_mmc_read_dvd_format, tvb, 0, 0, cdata->itlq->flags);
        PROTO_ITEM_SET_GENERATED(ti);

        proto_tree_add_item (tree, hf_scsi_mmc_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 4;


        switch(cdata->itlq->flags) {
        case 0x00: /* Physical Format information */
        case 0x11: /* ADIP Information */

        /* disc category */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_book_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_disc_book_version, tvb, offset, 1, ENC_BIG_ENDIAN);

        /* disc size */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_size_size, tvb, offset+1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_disc_size_rate, tvb, offset+1, 1, ENC_BIG_ENDIAN);

        /* number of layers */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_num_layers, tvb, offset+2, 1, ENC_BIG_ENDIAN);

        /* track path */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_track_path, tvb, offset+2, 1, ENC_BIG_ENDIAN);

        /* disc structure */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_structure_layer, tvb, offset+2, 1, ENC_BIG_ENDIAN);

        /* recording density */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_density_length, tvb, offset+3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_disc_density_pitch, tvb, offset+3, 1, ENC_BIG_ENDIAN);

        /* first physical sector of data zone */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_first_physical, tvb, offset+5, 3, ENC_BIG_ENDIAN);

        /* last physical sector of data zone */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_last_physical, tvb, offset+9, 3, ENC_BIG_ENDIAN);

        if (cdata->itlq->flags == 0x00) {
                /* last physical sector of layer 0 */
                proto_tree_add_item (tree, hf_scsi_mmc_disc_last_physical_layer0, tvb, offset+13, 3, ENC_BIG_ENDIAN);
        }

        /* extended format info */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_extended_format_info, tvb, offset+16, 1, ENC_BIG_ENDIAN);

        /* disk application code */
        proto_tree_add_item (tree, hf_scsi_mmc_disc_application_code, tvb, offset+17, 1, ENC_BIG_ENDIAN);

        /* extended information blocks */
        proto_tree_add_item (tree, hf_scsi_mmc_adip_eib5, tvb, offset+18, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_adip_eib4, tvb, offset+18, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_adip_eib3, tvb, offset+18, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_adip_eib2, tvb, offset+18, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_adip_eib1, tvb, offset+18, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_adip_eib0, tvb, offset+18, 1, ENC_BIG_ENDIAN);

        /* disk manufacturer id */
        proto_tree_add_item (tree, hf_scsi_mmc_adip_device_manuf_id, tvb, offset+19, 8, ENC_ASCII|ENC_NA);

        /* media type id */
        proto_tree_add_item (tree, hf_scsi_mmc_adip_media_type_id, tvb, offset+27, 3, ENC_ASCII|ENC_NA);

        /* product revision number */
        proto_tree_add_item (tree, hf_scsi_mmc_adip_product_revision_number, tvb, offset+30, 1, ENC_BIG_ENDIAN);

        /* number of bytes of physical info */
        proto_tree_add_item (tree, hf_scsi_mmc_adip_number_of_physical_info, tvb, offset+31, 1, ENC_BIG_ENDIAN);


        break;
        default:
            ti = proto_tree_add_text (tree, tvb, 0, 0,
                "SCSI/MMC Unknown Read DVD Format:0x%02x",
                cdata->itlq->flags);
            PROTO_ITEM_SET_GENERATED(ti);
        }
    }
}

static void
dissect_mmc4_getperformance (tvbuff_t *tvb, packet_info *pinfo _U_,
proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    guint8 flags;

    if (tree && isreq && iscdb) {
        flags = tvb_get_guint8 (tvb, offset);
        proto_tree_add_text (tree, tvb, offset, 1,
                             "Data Type: %u",
                             flags & 0x1f);
        proto_tree_add_text (tree, tvb, offset+1, 4,
                             "Starting LBA: %u",
                             tvb_get_ntohl (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+7, 2,
                             "Maximum Number of Descriptors: %u",
                             tvb_get_ntohs (tvb, offset+7));

        flags = tvb_get_guint8 (tvb, offset+9);
        proto_tree_add_text (tree, tvb, offset+9, 1,
                             "Type: %u",
                             flags);

        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static void
dissect_mmc4_synchronizecache (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_mmc_synccache_immed, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_synccache_reladr, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_lba, tvb, offset+1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_num_blocks, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

static const value_string scsi_key_class_val[] = {
    {0x00, "DVD CSS/CPPM or CPRM"},
    {0x01, "ReWriteable Security Service - A"},
    {0,NULL}
};
static const value_string scsi_key_format_val[] = {
    {0x00, "AGID for CSS/CPPM"},
    {0x01, "Challenge Key"},
    {0x02, "Key 1"},
    {0x04, "Title Key"},
    {0x05, "Authentication Success Flag"},
    {0x08, "RPC State"},
    {0x11, "AGID for CPRM"},
    {0x3f, "None"},
    {0,NULL}
};
static const value_string scsi_report_key_type_code_val[] = {
    {0x00, "NONE"},
    {0x01, "SET"},
    {0x02, "LAST CHANCE"},
    {0x03, "PERM"},
    {0,NULL}
};
static const value_string scsi_report_key_rpc_scheme_val[] = {
    {0x00, "Unknown (RPC not enforced)"},
    {0x01, "RPC Phase II"},
    {0,NULL}
};

static void
dissect_mmc4_reportkey (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata)

{
    guint8      agid, key_format, key_class;
    proto_item *ti;

    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_mmc_lba, tvb, offset+1,
                             4, ENC_BIG_ENDIAN);
        key_class=tvb_get_guint8(tvb, offset+6);
        proto_tree_add_item (tree, hf_scsi_mmc_key_class, tvb, offset+6,
                             1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+7, 2, ENC_BIG_ENDIAN);

        agid=tvb_get_guint8(tvb, offset+9)&0xc0;
        key_format=tvb_get_guint8(tvb, offset+9)&0x3f;
        switch(key_format){
        case 0x01:
        case 0x02:
        case 0x04:
        case 0x3f:
            /* agid is only valid for some formats */
            proto_tree_add_uint (tree, hf_scsi_mmc_agid, tvb, offset+9, 1, agid);
            break;
        }
        proto_tree_add_uint (tree, hf_scsi_mmc_key_format, tvb, offset+9, 1, key_format);
        /* save key_class/key_format so we can decode the response */
        cdata->itlq->flags=(key_format<<8)|key_class;

        proto_tree_add_bitmask(tree, tvb, offset+14, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    if(tree && (!isreq)) {
        switch(cdata->itlq->flags){
        case 0x0800: /* format:RPC State  class:00 */
            proto_tree_add_item (tree, hf_scsi_mmc_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_report_key_type_code, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_report_key_vendor_resets, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_report_key_user_changes, tvb, offset+4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_report_key_region_mask, tvb, offset+5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_report_key_rpc_scheme, tvb, offset+6, 1, ENC_BIG_ENDIAN);
            break;
        default:
            ti = proto_tree_add_text (tree, tvb, 0, 0,
                "SCSI/MMC Unknown Format:0x%02x/Class:0x%02x combination",
                cdata->itlq->flags>>8,cdata->itlq->flags&0xff);
            PROTO_ITEM_SET_GENERATED(ti);
            break;
        }
    }
}

static const value_string scsi_rti_address_type_val[] = {
    {0x00, "Logical Block Address"},
    {0x01, "Logical Track Number"},
    {0x02, "Session Number"},
    {0,NULL}
};

static void
dissect_mmc4_readtrackinformation (tvbuff_t *tvb_a, packet_info *pinfo, proto_tree *tree,
                     guint offset_a, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata)

{
    guint8 addresstype;

    if (isreq && iscdb) {
        addresstype=tvb_get_guint8(tvb_a, offset_a)&0x03;
        proto_tree_add_item (tree, hf_scsi_mmc_rti_address_type, tvb_a, offset_a+0, 1, ENC_BIG_ENDIAN);
        switch(addresstype){
        case 0x00: /* logical block address */
            proto_tree_add_item (tree, hf_scsi_mmc_lba, tvb_a, offset_a+1,
                             4, ENC_BIG_ENDIAN);
            break;
        case 0x01: /* logical track number */
            proto_tree_add_item (tree, hf_scsi_mmc_track, tvb_a, offset_a+1,
                             4, ENC_BIG_ENDIAN);
            break;
        case 0x02: /* logical session number */
            proto_tree_add_item (tree, hf_scsi_mmc_session, tvb_a, offset_a+1,
                             4, ENC_BIG_ENDIAN);
            break;
        }

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb_a, offset_a + 6, 2, ENC_BIG_ENDIAN);
        if (cdata) {
            cdata->itlq->alloc_len = tvb_get_ntohs(tvb_a, offset_a + 6);
        }

        proto_tree_add_bitmask(tree, tvb_a, offset_a+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    if (!isreq) {
        static const int *track_fields[] = {
            &hf_scsi_mmc_rti_damage,
            &hf_scsi_mmc_rti_copy,
            &hf_scsi_mmc_rti_track_mode,
            NULL
        };
        static const int *data_fields[] = {
            &hf_scsi_mmc_rti_rt,
            &hf_scsi_mmc_rti_blank,
            &hf_scsi_mmc_rti_packet,
            &hf_scsi_mmc_rti_fp,
            &hf_scsi_mmc_rti_data_mode,
            NULL
        };


        TRY_SCSI_CDB_ALLOC_LEN(cdata->itlq->alloc_len);  /* (defines/initializes try_tvb & try_offset) */
        proto_tree_add_item (tree, hf_scsi_mmc_data_length, try_tvb, 0, 2, ENC_BIG_ENDIAN);
        /* track  try_offset+2 and try_offset+32, only use the high byte if we have it */
        if (tvb_reported_length(try_tvb) < 33) {
            proto_tree_add_uint (tree, hf_scsi_mmc_track, try_tvb, 2, 1, tvb_get_guint8(try_tvb, try_offset + 2));
        } else {
            proto_tree_add_uint (tree, hf_scsi_mmc_track, try_tvb, 2, 1, (tvb_get_guint8(try_tvb, try_offset + 32) << 8) | tvb_get_guint8(try_tvb, try_offset + 2));
        }

        /* session  try_offset+3 and try_offset+33 */
        if (tvb_reported_length(try_tvb) < 34) {
            proto_tree_add_uint (tree, hf_scsi_mmc_session, try_tvb, 3, 1, tvb_get_guint8(try_tvb, try_offset + 3));
        } else {
            proto_tree_add_uint (tree, hf_scsi_mmc_session, try_tvb, 3, 1, (tvb_get_guint8(try_tvb, try_offset + 33) << 8) | tvb_get_guint8(try_tvb, try_offset + 3));
        }

        proto_tree_add_bitmask(tree, try_tvb, try_offset + 5, hf_scsi_mmc_track_flags,
             ett_scsi_track_flags, track_fields, ENC_BIG_ENDIAN);

        proto_tree_add_bitmask(tree, try_tvb, try_offset + 6, hf_scsi_mmc_data_flags,
             ett_scsi_data_flags, data_fields, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_rti_lra_v, try_tvb, 7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_rti_nwa_v, try_tvb, 7, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_track_start_address, try_tvb, try_offset+8, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_next_writable_address, try_tvb, try_offset+12, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_free_blocks, try_tvb, try_offset+16, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_fixed_packet_size, try_tvb, try_offset+20, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_track_size, try_tvb, try_offset+24, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_last_recorded_address, try_tvb, try_offset+28, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_mmc_read_compatibility_lba, try_tvb, try_offset+36, 4, ENC_BIG_ENDIAN);
        END_TRY_SCSI_CDB_ALLOC_LEN;
    }
}

static void
dissect_mmc4_geteventstatusnotification (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    if (tree && isreq && iscdb) {
        static const int *notification_fields[] = {
            &hf_scsi_mmc_gesn_device_busy,
            &hf_scsi_mmc_gesn_multi_initiator,
            &hf_scsi_mmc_gesn_media,
            &hf_scsi_mmc_gesn_external_request,
            &hf_scsi_mmc_gesn_power_mgmt,
            &hf_scsi_mmc_gesn_operational_change,
            NULL
        };

        proto_tree_add_item (tree, hf_scsi_mmc_gesn_polled, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_bitmask(tree, tvb, offset + 3, hf_scsi_mmc_notification_flags,
            ett_scsi_notifications, notification_fields, ENC_BIG_ENDIAN);

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);

        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}


static void
dissect_mmc4_reservetrack (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_mmc_reservation_size, tvb, offset+4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}


static const value_string scsi_closetrack_func_val[] = {
    {0, "Stop background format"},
    {1, "Close track"},
    {2, "Close last incomplete session"},
    {3, "Special case close session"},
    {5, "Close last session and finalize disk, special case"},
    {6, "Close last session and finalize disk"},
    {0, NULL}
};

static void
dissect_mmc4_close_track (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    if (tree && isreq && iscdb) {
        /* immediate */
        proto_tree_add_item (tree, hf_scsi_mmc_closetrack_immed, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* close function */
        proto_tree_add_item (tree, hf_scsi_mmc_closetrack_func, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* reserved */
        offset++;

        /* track number */
        proto_tree_add_item (tree, hf_scsi_mmc_track, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;

        /* reserved */
        offset+=3;

        proto_tree_add_bitmask(tree, tvb, offset, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}


static void
dissect_mmc4_readbuffercapacity (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata)

{
    if (tree && isreq && iscdb) {
        cdata->itlq->flags=0;
        proto_tree_add_item (tree, hf_scsi_mmc_rbc_block, tvb, offset, 1, ENC_BIG_ENDIAN);
        if(tvb_get_guint8(tvb, offset)&0x01){
            cdata->itlq->flags=1;
        }

        proto_tree_add_item (tree, hf_scsi_alloclen16, tvb, offset+6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+8, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    if(tree && (!isreq)) {
        proto_tree_add_item (tree, hf_scsi_mmc_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        if(cdata->itlq->flags){
            proto_tree_add_item (tree, hf_scsi_mmc_rbc_lob_blocks, tvb, offset+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_rbc_alob_blocks, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        } else {
            proto_tree_add_item (tree, hf_scsi_mmc_rbc_lob_bytes, tvb, offset+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_rbc_alob_bytes, tvb, offset+8, 4, ENC_BIG_ENDIAN);
        }
    }
}


static const value_string scsi_setcdspeed_rc_val[] = {
    {0x00, "CLV and none-pure CAV"},
    {0x01, "Pure CAV"},
    {0x02, "Reserved"},
    {0x03, "Reserved"},
    {0,NULL}
};

static void
dissect_mmc4_setcdspeed (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata _U_)

{
    if (tree && isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_mmc_setcdspeed_rc, tvb, offset+0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text (tree, tvb, offset+1, 2,
                             "Logical Unit Read Speed(bytes/sec): %u",
                             tvb_get_ntohs (tvb, offset+1));
        proto_tree_add_text (tree, tvb, offset+3, 2,
                             "Logical Unit Write Speed(bytes/sec): %u",
                             tvb_get_ntohs (tvb, offset+3));
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}


static const value_string scsi_setstreaming_type_val[] = {
    {0x00, "Performance Descriptor"},
    {0x05, "DBI cache zone descriptor"},
    {0,NULL}
};

static void
dissect_mmc4_setstreaming (tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                     guint offset, gboolean isreq, gboolean iscdb,
                     guint payload_len _U_, scsi_task_data_t *cdata)

{
    guint8      type;
    proto_item *ti;

    if (tree && isreq && iscdb) {
        type=tvb_get_guint8(tvb, offset+7);
        cdata->itlq->flags=type;
        proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_type, tvb, offset+7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_param_len, tvb, offset+8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_bitmask(tree, tvb, offset+10, hf_scsi_control,
            ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
    if(tree && isreq && (!iscdb)) {
        switch(cdata->itlq->flags){
        case 0x00: /* performance descriptor */
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_wrc, tvb, offset+0, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_rdd, tvb, offset+0, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_exact, tvb, offset+0, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_ra, tvb, offset+0, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_start_lba, tvb, offset+4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_end_lba, tvb, offset+8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_read_size, tvb, offset+12, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_read_time, tvb, offset+16, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_write_size, tvb, offset+20, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (tree, hf_scsi_mmc_setstreaming_write_time, tvb, offset+24, 4, ENC_BIG_ENDIAN);
            break;
        default:
            ti = proto_tree_add_text (tree, tvb, 0, 0,
                "SCSI/MMC Unknown SetStreaming Type:0x%02x",cdata->itlq->flags);
            PROTO_ITEM_SET_GENERATED(ti);
            break;
        }
    }
}

static void
dissect_mmc_preventallowmediaremoval(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                     guint offset, gboolean isreq, gboolean iscdb,
                                     guint payload_len _U_, scsi_task_data_t *cdata _U_)
{
    if (isreq && iscdb) {
        guint8 flags;
        static const int *prevent_allow_fields[] = {
            &hf_scsi_mmc_prevent_allow_persistent,
            &hf_scsi_mmc_prevent_allow_prevent,
            NULL
        };

        proto_tree_add_bitmask(tree, tvb, offset + 3, hf_scsi_mmc_prevent_allow_flags,
            ett_scsi_prevent_allow, prevent_allow_fields, ENC_BIG_ENDIAN);

        flags = tvb_get_guint8(tvb, offset + 3);
        if (flags & 0x01) {
            col_append_str(pinfo->cinfo, COL_INFO, " PREVENT");
        } else {
            col_append_str(pinfo->cinfo, COL_INFO, " ALLOW");
        }
        if (flags & 0x02) {
            col_append_str(pinfo->cinfo, COL_INFO, " (PERSISTENT)");
        }

        proto_tree_add_bitmask(tree, tvb, offset+4, hf_scsi_control,
                               ett_scsi_control, cdb_control_fields, ENC_BIG_ENDIAN);
    }
}

/* MMC Commands */
#define SCSI_MMC4_READCAPACITY10         0x25
#define SCSI_MMC4_READ10                 0x28
#define SCSI_MMC4_WRITE10                0x2a
#define SCSI_MMC4_SYNCHRONIZECACHE       0x35
#define SCSI_MMC4_READTOCPMAATIP         0x43
#define SCSI_MMC4_GETCONFIGURATION       0x46
#define SCSI_MMC4_GETEVENTSTATUSNOTIFY   0x4a
#define SCSI_MMC4_READDISCINFORMATION    0x51
#define SCSI_MMC4_READTRACKINFORMATION   0x52
#define SCSI_MMC4_RESERVETRACK           0x53
#define SCSI_MMC4_CLOSETRACK             0x5b
#define SCSI_MMC4_READBUFFERCAPACITY     0x5c
#define SCSI_MMC4_REPORTKEY              0xa4
#define SCSI_MMC4_READ12                 0xa8
#define SCSI_MMC4_WRITE12                0xaa
#define SCSI_MMC4_GETPERFORMANCE         0xac
#define SCSI_MMC4_READDISCSTRUCTURE      0xad
#define SCSI_MMC4_SETSTREAMING           0xb6
#define SCSI_MMC4_SETCDSPEED             0xbb
static const value_string scsi_mmc_vals[] = {
    /* 0x00 */    {SCSI_SPC_TESTUNITRDY            , "Test Unit Ready"},
    /* 0x03 */    {SCSI_SPC_REQSENSE               , "Request Sense"},
    /* 0x12 */    {SCSI_SPC_INQUIRY                , "Inquiry"},
    /* 0x1A */    {SCSI_SPC_MODESENSE6             , "Mode Sense(6)"},
    /* 0x1B */    {SCSI_SBC_STARTSTOPUNIT          , "Start Stop Unit"},
    /* 0x1E */    {SCSI_SPC_PREVMEDREMOVAL         , "Prevent/Allow Medium Removal"},
    /* 0x25 */    {SCSI_MMC4_READCAPACITY10        , "Read Capacity(10)"},
    /* 0x28 */    {SCSI_MMC4_READ10                , "Read(10)"},
    /* 0x2a */    {SCSI_MMC4_WRITE10               , "Write(10)"},
    /* 0x35 */    {SCSI_MMC4_SYNCHRONIZECACHE      , "Synchronize Cache"},
    /* 0x3B */    {SCSI_SPC_WRITEBUFFER            , "Write Buffer"},
    /* 0x43 */    {SCSI_MMC4_READTOCPMAATIP        , "Read TOC/PMA/ATIP"},
    /* 0x46 */    {SCSI_MMC4_GETCONFIGURATION      , "Get Configuration"},
    /* 0x4a */    {SCSI_MMC4_GETEVENTSTATUSNOTIFY  , "Get Event Status Notification"},
    /* 0x51 */    {SCSI_MMC4_READDISCINFORMATION   , "Read Disc Information"},
    /* 0x52 */    {SCSI_MMC4_READTRACKINFORMATION  , "Read Track Information"},
    /* 0x53 */    {SCSI_MMC4_RESERVETRACK          , "Reserve Track"},
    /* 0x55 */    {SCSI_SPC_MODESELECT10           , "Mode Select(10)"},
    /* 0x5A */    {SCSI_SPC_MODESENSE10            , "Mode Sense(10)"},
    /* 0x5b */    {SCSI_MMC4_CLOSETRACK            , "Close Track"},
    /* 0x5c */    {SCSI_MMC4_READBUFFERCAPACITY    , "Read Buffer Capacity"},
    /* 0xA0 */    {SCSI_SPC_REPORTLUNS             , "Report LUNs"},
    /* 0xA3 */    {SCSI_SPC_MGMT_PROTOCOL_IN       , "Mgmt Protocol In"},
    /* 0xa4 */    {SCSI_MMC4_REPORTKEY             , "Report Key"},
    /* 0xa8 */    {SCSI_MMC4_READ12                , "Read(12)"},
    /* 0xaa */    {SCSI_MMC4_WRITE12               , "Write(12)"},
    /* 0xac */    {SCSI_MMC4_GETPERFORMANCE        , "Get Performance"},
    /* 0xad */    {SCSI_MMC4_READDISCSTRUCTURE     , "Read DISC Structure"},
    /* 0xb6 */    {SCSI_MMC4_SETSTREAMING          , "Set Streaming"},
    /* 0xbb */    {SCSI_MMC4_SETCDSPEED            , "Set CD Speed"},
    {0, NULL},
};
value_string_ext scsi_mmc_vals_ext = VALUE_STRING_EXT_INIT(scsi_mmc_vals);

static const value_string scsi_track_mode_vals[] = {
    {0x00 , "2 audio channels without pre-emphasis, digital copy prohibited"},
    {0x01 , "2 audio channels with pre-emphasis of 50/15 us, digital copy prohibited"},
    {0x02 , "2 audio channels without pre-emphasis, digital copy permitted"},
    {0x03 , "2 audio channels with pre-emphasis of 50/15 us, digital copy permitted"},
    {0x04 , "Data track, recorded uninterrupted, digital copy prohibited"},
    {0x05 , "Data track, recorded incremental, digital copy prohibited"},
    {0x06 , "Data track, recorded uninterrupted, digital copy permitted"},
    {0x07 , "Data track, recorded incremental, digital copy permitted"},
    {0x08 , "audio channels without pre-emphasis, digital copy prohibited"},
    {0x09 , "audio channels with pre-emphasis of 50/15 us"},
    {0x0a , "audio channels without pre-emphasis, digital copy permitted"},
    {0x0b , "audio channels with pre-emphasis of 50/15 us, digital copy permitted"},
    {0, NULL},
};
static value_string_ext scsi_track_mode_vals_ext = VALUE_STRING_EXT_INIT(scsi_track_mode_vals);

scsi_cdb_table_t scsi_mmc_table[256] = {
/*SPC 0x00*/{dissect_spc_testunitready},
/*MMC 0x01*/{NULL},
/*MMC 0x02*/{NULL},
/*SPC 0x03*/{dissect_spc_requestsense},
/*MMC 0x04*/{NULL},
/*MMC 0x05*/{NULL},
/*MMC 0x06*/{NULL},
/*MMC 0x07*/{NULL},
/*MMC 0x08*/{NULL},
/*MMC 0x09*/{NULL},
/*MMC 0x0a*/{NULL},
/*MMC 0x0b*/{NULL},
/*MMC 0x0c*/{NULL},
/*MMC 0x0d*/{NULL},
/*MMC 0x0e*/{NULL},
/*MMC 0x0f*/{NULL},
/*MMC 0x10*/{NULL},
/*MMC 0x11*/{NULL},
/*SPC 0x12*/{dissect_spc_inquiry},
/*MMC 0x13*/{NULL},
/*MMC 0x14*/{NULL},
/*MMC 0x15*/{NULL},
/*MMC 0x16*/{NULL},
/*MMC 0x17*/{NULL},
/*MMC 0x18*/{NULL},
/*MMC 0x19*/{NULL},
/*MMC 0x1a*/{NULL},
/*MMC 0x1b*/{dissect_sbc_startstopunit},
/*MMC 0x1c*/{NULL},
/*MMC 0x1d*/{NULL},
/*MMC 0x1e*/{dissect_mmc_preventallowmediaremoval},
/*MMC 0x1f*/{NULL},
/*MMC 0x20*/{NULL},
/*MMC 0x21*/{NULL},
/*MMC 0x22*/{NULL},
/*MMC 0x23*/{NULL},
/*MMC 0x24*/{NULL},
/*MMC 0x25*/{dissect_sbc_readcapacity10},
/*MMC 0x26*/{NULL},
/*MMC 0x27*/{NULL},
/*MMC 0x28*/{dissect_sbc_read10},
/*MMC 0x29*/{NULL},
/*MMC 0x2a*/{dissect_sbc_write10},
/*MMC 0x2b*/{NULL},
/*MMC 0x2c*/{NULL},
/*MMC 0x2d*/{NULL},
/*MMC 0x2e*/{NULL},
/*MMC 0x2f*/{NULL},
/*MMC 0x30*/{NULL},
/*MMC 0x31*/{NULL},
/*MMC 0x32*/{NULL},
/*MMC 0x33*/{NULL},
/*MMC 0x34*/{NULL},
/*MMC 0x35*/{dissect_mmc4_synchronizecache},
/*MMC 0x36*/{NULL},
/*MMC 0x37*/{NULL},
/*MMC 0x38*/{NULL},
/*MMC 0x39*/{NULL},
/*MMC 0x3a*/{NULL},
/*SPC 0x3b*/{dissect_spc_writebuffer},
/*MMC 0x3c*/{NULL},
/*MMC 0x3d*/{NULL},
/*MMC 0x3e*/{NULL},
/*MMC 0x3f*/{NULL},
/*MMC 0x40*/{NULL},
/*MMC 0x41*/{NULL},
/*MMC 0x42*/{NULL},
/*MMC 0x43*/{dissect_mmc4_readtocpmaatip},
/*MMC 0x44*/{NULL},
/*MMC 0x45*/{NULL},
/*MMC 0x46*/{dissect_mmc4_getconfiguration},
/*MMC 0x47*/{NULL},
/*MMC 0x48*/{NULL},
/*MMC 0x49*/{NULL},
/*MMC 0x4a*/{dissect_mmc4_geteventstatusnotification},
/*MMC 0x4b*/{NULL},
/*MMC 0x4c*/{NULL},
/*MMC 0x4d*/{NULL},
/*MMC 0x4e*/{NULL},
/*MMC 0x4f*/{NULL},
/*MMC 0x50*/{NULL},
/*MMC 0x51*/{dissect_mmc4_readdiscinformation},
/*MMC 0x52*/{dissect_mmc4_readtrackinformation},
/*MMC 0x53*/{dissect_mmc4_reservetrack},
/*MMC 0x54*/{NULL},
/*SPC 0x55*/{dissect_spc_modeselect10},
/*MMC 0x56*/{NULL},
/*MMC 0x57*/{NULL},
/*MMC 0x58*/{NULL},
/*MMC 0x59*/{NULL},
/*SPC 0x5a*/{dissect_spc_modesense10},
/*MMC 0x5b*/{dissect_mmc4_close_track},
/*MMC 0x5c*/{dissect_mmc4_readbuffercapacity},
/*MMC 0x5d*/{NULL},
/*MMC 0x5e*/{NULL},
/*MMC 0x5f*/{NULL},
/*MMC 0x60*/{NULL},
/*MMC 0x61*/{NULL},
/*MMC 0x62*/{NULL},
/*MMC 0x63*/{NULL},
/*MMC 0x64*/{NULL},
/*MMC 0x65*/{NULL},
/*MMC 0x66*/{NULL},
/*MMC 0x67*/{NULL},
/*MMC 0x68*/{NULL},
/*MMC 0x69*/{NULL},
/*MMC 0x6a*/{NULL},
/*MMC 0x6b*/{NULL},
/*MMC 0x6c*/{NULL},
/*MMC 0x6d*/{NULL},
/*MMC 0x6e*/{NULL},
/*MMC 0x6f*/{NULL},
/*MMC 0x70*/{NULL},
/*MMC 0x71*/{NULL},
/*MMC 0x72*/{NULL},
/*MMC 0x73*/{NULL},
/*MMC 0x74*/{NULL},
/*MMC 0x75*/{NULL},
/*MMC 0x76*/{NULL},
/*MMC 0x77*/{NULL},
/*MMC 0x78*/{NULL},
/*MMC 0x79*/{NULL},
/*MMC 0x7a*/{NULL},
/*MMC 0x7b*/{NULL},
/*MMC 0x7c*/{NULL},
/*MMC 0x7d*/{NULL},
/*MMC 0x7e*/{NULL},
/*MMC 0x7f*/{NULL},
/*MMC 0x80*/{NULL},
/*MMC 0x81*/{NULL},
/*MMC 0x82*/{NULL},
/*MMC 0x83*/{NULL},
/*MMC 0x84*/{NULL},
/*MMC 0x85*/{NULL},
/*MMC 0x86*/{NULL},
/*MMC 0x87*/{NULL},
/*MMC 0x88*/{NULL},
/*MMC 0x89*/{NULL},
/*MMC 0x8a*/{NULL},
/*MMC 0x8b*/{NULL},
/*MMC 0x8c*/{NULL},
/*MMC 0x8d*/{NULL},
/*MMC 0x8e*/{NULL},
/*MMC 0x8f*/{NULL},
/*MMC 0x90*/{NULL},
/*MMC 0x91*/{NULL},
/*MMC 0x92*/{NULL},
/*MMC 0x93*/{NULL},
/*MMC 0x94*/{NULL},
/*MMC 0x95*/{NULL},
/*MMC 0x96*/{NULL},
/*MMC 0x97*/{NULL},
/*MMC 0x98*/{NULL},
/*MMC 0x99*/{NULL},
/*MMC 0x9a*/{NULL},
/*MMC 0x9b*/{NULL},
/*MMC 0x9c*/{NULL},
/*MMC 0x9d*/{NULL},
/*MMC 0x9e*/{NULL},
/*MMC 0x9f*/{NULL},
/*SPC 0xa0*/{dissect_spc_reportluns},
/*MMC 0xa1*/{NULL},
/*MMC 0xa2*/{NULL},
/*SPC 0xa3*/{dissect_spc_mgmt_protocol_in},
/*MMC 0xa4*/{dissect_mmc4_reportkey},
/*MMC 0xa5*/{NULL},
/*MMC 0xa6*/{NULL},
/*MMC 0xa7*/{NULL},
/*MMC 0xa8*/{dissect_sbc_read12},
/*MMC 0xa9*/{NULL},
/*MMC 0xaa*/{dissect_sbc_write12},
/*MMC 0xab*/{NULL},
/*MMC 0xac*/{dissect_mmc4_getperformance},
/*MMC 0xad*/{dissect_mmc4_readdiscstructure},
/*MMC 0xae*/{NULL},
/*MMC 0xaf*/{NULL},
/*MMC 0xb0*/{NULL},
/*MMC 0xb1*/{NULL},
/*MMC 0xb2*/{NULL},
/*MMC 0xb3*/{NULL},
/*MMC 0xb4*/{NULL},
/*MMC 0xb5*/{NULL},
/*MMC 0xb6*/{dissect_mmc4_setstreaming},
/*MMC 0xb7*/{NULL},
/*MMC 0xb8*/{NULL},
/*MMC 0xb9*/{NULL},
/*MMC 0xba*/{NULL},
/*MMC 0xbb*/{dissect_mmc4_setcdspeed},
/*MMC 0xbc*/{NULL},
/*MMC 0xbd*/{NULL},
/*MMC 0xbe*/{NULL},
/*MMC 0xbf*/{NULL},
/*MMC 0xc0*/{NULL},
/*MMC 0xc1*/{NULL},
/*MMC 0xc2*/{NULL},
/*MMC 0xc3*/{NULL},
/*MMC 0xc4*/{NULL},
/*MMC 0xc5*/{NULL},
/*MMC 0xc6*/{NULL},
/*MMC 0xc7*/{NULL},
/*MMC 0xc8*/{NULL},
/*MMC 0xc9*/{NULL},
/*MMC 0xca*/{NULL},
/*MMC 0xcb*/{NULL},
/*MMC 0xcc*/{NULL},
/*MMC 0xcd*/{NULL},
/*MMC 0xce*/{NULL},
/*MMC 0xcf*/{NULL},
/*MMC 0xd0*/{NULL},
/*MMC 0xd1*/{NULL},
/*MMC 0xd2*/{NULL},
/*MMC 0xd3*/{NULL},
/*MMC 0xd4*/{NULL},
/*MMC 0xd5*/{NULL},
/*MMC 0xd6*/{NULL},
/*MMC 0xd7*/{NULL},
/*MMC 0xd8*/{NULL},
/*MMC 0xd9*/{NULL},
/*MMC 0xda*/{NULL},
/*MMC 0xdb*/{NULL},
/*MMC 0xdc*/{NULL},
/*MMC 0xdd*/{NULL},
/*MMC 0xde*/{NULL},
/*MMC 0xdf*/{NULL},
/*MMC 0xe0*/{NULL},
/*MMC 0xe1*/{NULL},
/*MMC 0xe2*/{NULL},
/*MMC 0xe3*/{NULL},
/*MMC 0xe4*/{NULL},
/*MMC 0xe5*/{NULL},
/*MMC 0xe6*/{NULL},
/*MMC 0xe7*/{NULL},
/*MMC 0xe8*/{NULL},
/*MMC 0xe9*/{NULL},
/*MMC 0xea*/{NULL},
/*MMC 0xeb*/{NULL},
/*MMC 0xec*/{NULL},
/*MMC 0xed*/{NULL},
/*MMC 0xee*/{NULL},
/*MMC 0xef*/{NULL},
/*MMC 0xf0*/{NULL},
/*MMC 0xf1*/{NULL},
/*MMC 0xf2*/{NULL},
/*MMC 0xf3*/{NULL},
/*MMC 0xf4*/{NULL},
/*MMC 0xf5*/{NULL},
/*MMC 0xf6*/{NULL},
/*MMC 0xf7*/{NULL},
/*MMC 0xf8*/{NULL},
/*MMC 0xf9*/{NULL},
/*MMC 0xfa*/{NULL},
/*MMC 0xfb*/{NULL},
/*MMC 0xfc*/{NULL},
/*MMC 0xfd*/{NULL},
/*MMC 0xfe*/{NULL},
/*MMC 0xff*/{NULL}
};


void
proto_register_scsi_mmc(void)
{
    static hf_register_info hf[] = {
        { &hf_scsi_mmc_opcode,
          {"MMC Opcode", "scsi_mmc.opcode", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
           &scsi_mmc_vals_ext, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_type,
          {"Type", "scsi_mmc.setstreaming.type", FT_UINT8, BASE_DEC,
           VALS(scsi_setstreaming_type_val), 0, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_param_len,
          {"Parameter Length", "scsi_mmc.setstreaming.param_len", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_wrc,
          {"WRC", "scsi_mmc.setstreaming.wrc", FT_UINT8, BASE_HEX,
           NULL, 0x18, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_rdd,
          {"RDD", "scsi_mmc.setstreaming.rdd", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_exact,
          {"Exact", "scsi_mmc.setstreaming.exact", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_ra,
          {"RA", "scsi_mmc.setstreaming.ra", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_start_lba,
          {"Start LBA", "scsi_mmc.setstreaming.start_lbs", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_end_lba,
          {"End LBA", "scsi_mmc.setstreaming.end_lba", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_read_size,
          {"Read Size", "scsi_mmc.setstreaming.read_size", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_read_time,
          {"Read Time", "scsi_mmc.setstreaming.read_time", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_write_size,
          {"Write Size", "scsi_mmc.setstreaming.write_size", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_setstreaming_write_time,
          {"Write Time", "scsi_mmc.setstreaming.write_time", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_setcdspeed_rc,
          {"Rotational Control", "scsi_mmc.setcdspeed.rc", FT_UINT8, BASE_HEX,
           VALS(scsi_setcdspeed_rc_val), 0x03, NULL, HFILL}},
        { &hf_scsi_mmc_rbc_block,
          {"BLOCK", "scsi_mmc.rbc.block", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_rbc_lob_blocks,
          {"Buffer Len (blocks)", "scsi_mmc.rbc.lob_blocks", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_rbc_alob_blocks,
          {"Available Buffer Len (blocks)", "scsi_mmc.rbc.alob_blocks", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_rbc_lob_bytes,
          {"Buffer Len (bytes)", "scsi_mmc.rbc.lob_bytes", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_rbc_alob_bytes,
          {"Available Buffer Len (bytes)", "scsi_mmc.rbc.alob_bytes", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_rti_address_type,
          {"Address Type", "scsi_mmc.rti.address_type", FT_UINT8, BASE_HEX,
           VALS(scsi_rti_address_type_val), 0x03, NULL, HFILL}},
        { &hf_scsi_mmc_rti_damage,
          {"Damage", "scsi_mmc.rti.damage", FT_BOOLEAN, 8,
           NULL, 0x20, NULL, HFILL}},
        { &hf_scsi_mmc_rti_copy,
          {"Copy", "scsi_mmc.rti.copy", FT_BOOLEAN, 8,
           NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_rti_track_mode,
          {"Track Mode", "scsi_mmc.rti.track_mode", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
           &scsi_track_mode_vals_ext, 0x0f, NULL, HFILL}},
        { &hf_scsi_mmc_rti_rt,
          {"RT", "scsi_mmc.rti.rt", FT_BOOLEAN, 8,
           NULL, 0x80, NULL, HFILL}},
        { &hf_scsi_mmc_rti_blank,
          {"Blank", "scsi_mmc.rti.blank", FT_BOOLEAN, 8,
           NULL, 0x40, NULL, HFILL}},
        { &hf_scsi_mmc_rti_packet,
          {"Packet/Inc", "scsi_mmc.rti.packet", FT_BOOLEAN, 8,
           NULL, 0x20, NULL, HFILL}},
        { &hf_scsi_mmc_rti_fp,
          {"FP", "scsi_mmc.rti.fp", FT_BOOLEAN, 8,
           NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_rti_data_mode,
          {"Data Mode", "scsi_mmc.rti.data_mode", FT_UINT8, BASE_HEX,
           VALS(scsi_data_mode_vals), 0x0f, NULL, HFILL}},
        { &hf_scsi_mmc_rti_lra_v,
          {"LRA_V", "scsi_mmc.rti.lra_v", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_rti_nwa_v,
          {"NWA_V", "scsi_mmc.rti.nwa_v", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_report_key_type_code,
          {"Type Code", "scsi_mmc.report_key.type_code", FT_UINT8, BASE_HEX,
           VALS(scsi_report_key_type_code_val), 0xc0, NULL, HFILL}},
        { &hf_scsi_mmc_report_key_vendor_resets,
          {"Vendor Resets", "scsi_mmc.report_key.vendor_resets", FT_UINT8, BASE_HEX,
           NULL, 0x38, NULL, HFILL}},
        { &hf_scsi_mmc_report_key_user_changes,
          {"User Changes", "scsi_mmc.report_key.user_changes", FT_UINT8, BASE_HEX,
           NULL, 0x07, NULL, HFILL}},
        { &hf_scsi_mmc_report_key_region_mask,
          {"Region Mask", "scsi_mmc.report_key.region_mask", FT_UINT8, BASE_HEX,
           NULL, 0xff, NULL, HFILL}},
        { &hf_scsi_mmc_report_key_rpc_scheme,
          {"RPC Scheme", "scsi_mmc.report_key.rpc_scheme", FT_UINT8, BASE_HEX,
           VALS(scsi_report_key_rpc_scheme_val), 0, NULL, HFILL}},
        { &hf_scsi_mmc_key_class,
          {"Key Class", "scsi_mmc.key_class", FT_UINT8, BASE_HEX,
           VALS (scsi_key_class_val), 0x00, NULL, HFILL}},
        { &hf_scsi_mmc_key_format,
          {"Key Format", "scsi_mmc.key_format", FT_UINT8, BASE_HEX,
           VALS (scsi_key_format_val), 0x3f, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_erasable,
          {"Erasable", "scsi_mmc.disc_info.erasable", FT_BOOLEAN, 8,
           NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_state_of_last_session,
          {"State Of Last Session", "scsi_mmc.disc_info.state_of_last_session", FT_UINT8, BASE_HEX,
           VALS(scsi_disc_info_sols_val), 0x0c, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_disk_status,
          {"Disk Status", "scsi_mmc.disc_info.disk_status", FT_UINT8, BASE_HEX,
           VALS(scsi_disc_info_disc_status_val), 0x03, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_number_of_sessions,
          {"Number Of Sessions", "scsi_mmc.disc_info.number_of_sessions", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_first_track_in_last_session,
          {"First Track In Last Session", "scsi_mmc.disc_info.first_track_in_last_session", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_last_track_in_last_session,
          {"Last Track In Last Session", "scsi_mmc.disc_info.last_track_in_last_session", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_did_v,
          {"DID_V", "scsi_mmc.disc_info.did_v", FT_BOOLEAN, 8,
           NULL, 0x80, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_dbc_v,
          {"DBC_V", "scsi_mmc.disc_info.dbc_v", FT_BOOLEAN, 8,
           NULL, 0x40, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_uru,
          {"URU", "scsi_mmc.disc_info.uru", FT_BOOLEAN, 8,
           NULL, 0x20, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_dac_v,
          {"DAC_V", "scsi_mmc.disc_info.dac_v", FT_BOOLEAN, 8,
           NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_dbit,
          {"Dbit", "scsi_mmc.disc_info.dbit", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_bgfs,
          {"BG Format Status", "scsi_mmc.disc_info.bgfs", FT_UINT8, BASE_HEX,
           VALS(scsi_disc_info_bgfs_val), 0x03, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_disc_type,
          {"Disc Type", "scsi_mmc.disc_info.disc_type", FT_UINT8, BASE_HEX,
           VALS(scsi_disc_info_disc_type_val), 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_disc_identification,
          {"Disc Identification", "scsi_mmc.disc_info.disc_identification", FT_UINT32, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_last_session_lead_in_start_address,
          {"Last Session Lead-In Start Address", "scsi_mmc.disc_info.last_session_lead_in_start_address", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_last_possible_lead_out_start_address,
          {"Last Possible Lead-Out Start Address", "scsi_mmc.disc_info.last_possible_lead_out_start_address", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_info_disc_bar_code,
          {"Disc Bar Code", "scsi_mmc.disc_info.disc_bar_code", FT_UINT64, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_readtoc_time,
          {"Time", "scsi_mmc.readtoc.time", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_readtoc_format,
          {"Format", "scsi_mmc.readtoc.format", FT_UINT8, BASE_HEX,
           NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_mmc_readtoc_first_session,
          {"First Session", "scsi_mmc.readtoc.first_session", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_readtoc_last_track,
          {"Last Track", "scsi_mmc.readtoc.last_track", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_readtoc_last_session,
          {"Last Session", "scsi_mmc.readtoc.last_session", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_q_subchannel_adr,
          {"Q Subchannel ADR", "scsi_mmc.q.subchannel.adr", FT_UINT8, BASE_HEX,
           VALS(scsi_q_subchannel_adr_val), 0xf0, NULL, HFILL}},
        { &hf_scsi_mmc_q_subchannel_control,
          {"Q Subchannel Control", "scsi_mmc.q.subchannel.control", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
           &scsi_q_subchannel_control_val_ext, 0x0f, NULL, HFILL}},
        { &hf_scsi_mmc_agid,
          {"AGID", "scsi_mmc.agid", FT_UINT8, BASE_HEX,
           NULL, 0xc0, NULL, HFILL}},
        { &hf_scsi_mmc_track,
          {"Track", "scsi_mmc.track", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_track_size,
          {"Track Size", "scsi_mmc.track_size", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_track_start_address,
          {"Track Start Address", "scsi_mmc.track_start_address", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_track_start_time,
          {"Track Start Time", "scsi_mmc.track_start_time", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_lba,
          {"Logical Block Address", "scsi_mmc.lba", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_session,
          {"Session", "scsi_mmc.session", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_data_length,
          {"Data Length", "scsi_mmc.data_length", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_getconf_rt,
          {"RT", "scsi_mmc.getconf.rt", FT_UINT8, BASE_HEX,
           VALS(scsi_getconf_rt_val), 0x03, NULL, HFILL}},
        { &hf_scsi_mmc_getconf_current_profile,
          {"Current Profile", "scsi_mmc.getconf.current_profile", FT_UINT16, BASE_HEX | BASE_EXT_STRING,
           &scsi_getconf_current_profile_val_ext, 0, NULL, HFILL}},
        { &hf_scsi_mmc_getconf_starting_feature,
          {"Starting Feature", "scsi_mmc.getconf.starting_feature", FT_UINT16, BASE_HEX | BASE_EXT_STRING,
           &scsi_feature_val_ext, 0, NULL, HFILL}},
        { &hf_scsi_mmc_feature,
          {"Feature", "scsi_mmc.feature", FT_UINT16, BASE_HEX | BASE_EXT_STRING,
           &scsi_feature_val_ext, 0, NULL, HFILL}},
        { &hf_scsi_mmc_feature_version,
          {"Version", "scsi_mmc.feature.version", FT_UINT8, BASE_DEC,
           NULL, 0x3c, NULL, HFILL}},
        { &hf_scsi_mmc_feature_persistent,
          {"Persistent", "scsi_mmc.feature.persistent", FT_UINT8, BASE_HEX,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_feature_current,
          {"Current", "scsi_mmc.feature.current", FT_UINT8, BASE_HEX,
           NULL, 001, NULL, HFILL}},
        { &hf_scsi_mmc_feature_additional_length,
          {"Additional Length", "scsi_mmc.feature.additional_length", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_feature_lun_sn,
          {"LUN Serial Number", "scsi_mmc.feature.lun_sn", FT_STRING, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_feature_cdread_dap,
          {"DAP", "scsi_mmc.feature.cdread.dap", FT_BOOLEAN, 8,
           NULL, 0x80, NULL, HFILL}},
        { &hf_scsi_mmc_feature_cdread_c2flag,
          {"C2 Flag", "scsi_mmc.feature.cdread.c2flag", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_feature_cdread_cdtext,
          {"CD-Text", "scsi_mmc.feature.cdread.cdtext", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_feature_dvdrw_write,
          {"Write", "scsi_mmc.feature.dvdrw.write", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_feature_dvdrw_quickstart,
          {"Quick Start", "scsi_mmc.feature.dvdrw.quickstart", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_feature_dvdrw_closeonly,
          {"Close Only", "scsi_mmc.feature.dvdrw.closeonly", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_feature_dvdr_write,
          {"Write", "scsi_mmc.feature.dvdr.write", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_feature_tao_buf,
          {"BUF", "scsi_mmc.feature.tao.buf", FT_BOOLEAN, 8,
           NULL, 0x40, NULL, HFILL}},
        { &hf_scsi_mmc_feature_tao_rwraw,
          {"R-W Raw", "scsi_mmc.feature.tao.rwraw", FT_BOOLEAN, 8,
           NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_feature_tao_rwpack,
          {"R-W Pack", "scsi_mmc.feature.tao.rwpack", FT_BOOLEAN, 8,
           NULL, 0x08, NULL, HFILL}},
        { &hf_scsi_mmc_feature_tao_testwrite,
          {"Test Write", "scsi_mmc.feature.tao.testwrite", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_mmc_feature_tao_cdrw,
          {"CD-RW", "scsi_mmc.feature.tao.cdrw", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_feature_tao_rwsubcode,
          {"R-W Subcode", "scsi_mmc.feature.tao.rwsubcode", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_feature_dts,
          {"Data Type Supported", "scsi_mmc.feature.dts", FT_UINT16, BASE_HEX,
           NULL, 0xffff, NULL, HFILL}},
        { &hf_scsi_mmc_feature_sao_buf,
          {"BUF", "scsi_mmc.feature.sao.buf", FT_BOOLEAN, 8,
           NULL, 0x40, NULL, HFILL}},
        { &hf_scsi_mmc_feature_sao_sao,
          {"SAO", "scsi_mmc.feature.sao.sao", FT_BOOLEAN, 8,
           NULL, 0x20, NULL, HFILL}},
        { &hf_scsi_mmc_feature_sao_rawms,
          {"Raw MS", "scsi_mmc.feature.sao.rawms", FT_BOOLEAN, 8,
           NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_feature_sao_raw,
          {"Raw", "scsi_mmc.feature.sao.raw", FT_BOOLEAN, 8,
           NULL, 0x08, NULL, HFILL}},
        { &hf_scsi_mmc_feature_sao_testwrite,
          {"Test Write", "scsi_mmc.feature.sao.testwrite", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_mmc_feature_sao_cdrw,
          {"CD-RW", "scsi_mmc.feature.sao.cdrw", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_feature_sao_rw,
          {"R-W", "scsi_mmc.feature.sao.rw", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_feature_sao_mcsl,
          {"Maximum Cue Sheet Length", "scsi_mmc.feature.sao.mcsl", FT_UINT24, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_feature_dvdr_buf,
          {"BUF", "scsi_mmc.feature.dvdr.buf", FT_BOOLEAN, 8,
           NULL, 0x40, NULL, HFILL}},
        { &hf_scsi_mmc_feature_dvdr_testwrite,
          {"Test Write", "scsi_mmc.feature.dvdr.testwrite", FT_BOOLEAN, 8,
           NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_mmc_feature_dvdr_dvdrw,
          {"DVD-RW", "scsi_mmc.feature.dvdr.dvdrw", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_feature_profile,
          {"Profile", "scsi_mmc.feature.profile", FT_UINT16, BASE_HEX | BASE_EXT_STRING,
           &scsi_getconf_current_profile_val_ext, 0, NULL, HFILL}},
        { &hf_scsi_mmc_feature_profile_current,
          {"Current", "scsi_mmc.feature.profile.current", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_feature_isw_buf,
          {"BUF", "scsi_mmc.feature.isw.buf", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_feature_isw_num_linksize,
          {"Number of Link Sizes", "scsi_mmc.feature.isw.num_linksize", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_feature_isw_linksize,
          {"Link Size", "scsi_mmc.feature.isw.linksize", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_read_compatibility_lba,
          {"Read Compatibility LBA", "scsi_mmc.read_compatibility_lba", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_reservation_size,
          {"Reservation Size", "scsi_mmc.reservation_size", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_last_recorded_address,
          {"Last Recorded Address", "scsi_mmc.last_recorded_address", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_first_track,
          {"First Track", "scsi_mmc.first_track", FT_UINT8, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_fixed_packet_size,
          {"Fixed Packet Size", "scsi_mmc.fixed_packet_size", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_closetrack_immed,
          {"IMMED", "scsi_mmc.closetrack.immed", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_closetrack_func,
          {"Close Function", "scsi_mmc.closetrack.func", FT_UINT8, BASE_HEX,
           VALS(scsi_closetrack_func_val), 0x07, NULL, HFILL}},
        { &hf_scsi_mmc_synccache_immed,
          {"IMMED", "scsi_mmc.synccache.immed", FT_BOOLEAN, 8,
           NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_synccache_reladr,
          {"RelAdr", "scsi_mmc.synccache.reladr", FT_BOOLEAN, 8,
           NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_num_blocks,
          {"Number of Blocks", "scsi_mmc.num_blocks", FT_UINT32, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_next_writable_address,
          {"Next Writable Address", "scsi_mmc.next_writable_address", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_free_blocks,
          {"Free Blocks", "scsi_mmc.free_blocks", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_read_dvd_format,
          { "Format Code", "scsi_mmc.read_dvd.format", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
            &scsi_read_dvd_formats_ext, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_book_type,
          { "Type", "scsi_mmc.book.type", FT_UINT8, BASE_HEX,
            VALS(scsi_disc_category_type), 0xf0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_book_version,
          { "Version", "scsi_mmc.book.version", FT_UINT8, BASE_HEX,
            NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_mmc_disc_size_size,
          { "Size", "scsi_mmc.disc.size", FT_UINT8, BASE_HEX,
            VALS(scsi_disc_size), 0xf0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_size_rate,
          { "Rate", "scsi_mmc.disc.rate", FT_UINT8, BASE_HEX,
            VALS(scsi_disc_rate), 0x0f, NULL, HFILL}},
        { &hf_scsi_mmc_disc_structure_layer,
          { "Structure", "scsi_mmc.disc.structure", FT_UINT8, BASE_HEX,
            VALS(scsi_disc_structure), 0x0f, NULL, HFILL}},
        { &hf_scsi_mmc_disc_density_length,
          { "Channel bith length", "scsi_mmc.density.channel_bit_length", FT_UINT8, BASE_HEX,
            VALS(scsi_density_length), 0xf0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_density_pitch,
          { "Average Track Pitch", "scsi_mmc.density.average_track_pitch", FT_UINT8, BASE_HEX,
            VALS(scsi_density_pitch), 0x0f, NULL, HFILL}},
        { &hf_scsi_mmc_disc_first_physical,
          { "First physical sector of data zone", "scsi_mmc.first_physical", FT_UINT24, BASE_HEX,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_last_physical,
          { "Last physical sector of data zone", "scsi_mmc.last_physical", FT_UINT24, BASE_HEX,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_last_physical_layer0,
          { "Last physical sector of layer 0", "scsi_mmc.last_physical_layer0", FT_UINT24, BASE_HEX,
            NULL, 0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_extended_format_info,
          { "Extended Format Info", "scsi_mmc.adip.extended_format_info", FT_BOOLEAN, 8,
            TFS(&scsi_adip_extended_format_info), 0x40, NULL, HFILL}},
        { &hf_scsi_mmc_disc_application_code,
          { "Disk Application Code", "scsi_mmc.disk_application_code", FT_UINT8, BASE_HEX,
            VALS(scsi_disk_application_code), 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_adip_eib0,
          { "Extended Format Block 0", "scsi_mmc.adip.extended_format_block.0", FT_BOOLEAN, 8,
            NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_adip_eib1,
          { "Extended Format Block 1", "scsi_mmc.adip.extended_format_block.1", FT_BOOLEAN, 8,
            NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_adip_eib2,
          { "Extended Format Block 2", "scsi_mmc.adip.extended_format_block.2", FT_BOOLEAN, 8,
            NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_mmc_adip_eib3,
          { "Extended Format Block 3", "scsi_mmc.adip.extended_format_block.3", FT_BOOLEAN, 8,
            NULL, 0x08, NULL, HFILL}},
        { &hf_scsi_mmc_adip_eib4,
          { "Extended Format Block 4", "scsi_mmc.adip.extended_format_block.4", FT_BOOLEAN, 8,
            NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_adip_eib5,
          { "Extended Format Block 5", "scsi_mmc.adip.extended_format_block.5", FT_BOOLEAN, 8,
            NULL, 0x20, NULL, HFILL}},
        { &hf_scsi_mmc_adip_device_manuf_id,
          { "Device Manufacturer Id", "scsi_mmc.adip.device_manufacturer_id", FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_adip_media_type_id,
          { "Media Type Id", "scsi_mmc.adip.media_type_id", FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_adip_product_revision_number,
          { "Product Revision Number", "scsi_mmc.adip.product_revision_number", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_adip_number_of_physical_info,
          { "Number of bytes of physical info", "scsi_mmc.adip.number_of_physical_info", FT_UINT8, BASE_HEX,
            NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_mmc_disc_num_layers,
          { "Number of Layers", "scsi_mmc.disk.num_layers", FT_UINT8, BASE_DEC,
            VALS(scsi_num_layers), 0x60, NULL, HFILL}},
        { &hf_scsi_mmc_disc_track_path,
          { "Track Path", "scsi_mmc.disk.track_path", FT_BOOLEAN, 8,
            TFS(&scsi_track_path), 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_gesn_polled,
          { "Polled", "scsi_mmc.gesn.polled", FT_BOOLEAN, 8,
            TFS(&scsi_gesn_path), 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_notification_flags,
          {"Notification Class Request", "scsi_mmc.notification.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_mmc_gesn_device_busy,
          { "DEVICE BUSY", "scsi_mmc.gesn.device_busy", FT_BOOLEAN, 8,
            NULL, 0x40, NULL, HFILL}},
        { &hf_scsi_mmc_gesn_multi_initiator,
          { "MULTI_INITIATOR", "scsi_mmc.gesn.multi_initiator", FT_BOOLEAN, 8,
            NULL, 0x20, NULL, HFILL}},
        { &hf_scsi_mmc_gesn_media,
          { "MEDIA", "scsi_mmc.gesn.media", FT_BOOLEAN, 8,
            NULL, 0x10, NULL, HFILL}},
        { &hf_scsi_mmc_gesn_external_request,
          { "EXTERNAL_REQUEST", "scsi_mmc.gesn.external_request", FT_BOOLEAN, 8,
            NULL, 0x08, NULL, HFILL}},
        { &hf_scsi_mmc_gesn_power_mgmt,
          { "POWER_MANAGEMENT", "scsi_mmc.gesn.power_management", FT_BOOLEAN, 8,
            NULL, 0x04, NULL, HFILL}},
        { &hf_scsi_mmc_gesn_operational_change,
          { "OPERATIONAL_CHANGE", "scsi_mmc.gesn.operational_change", FT_BOOLEAN, 8,
            NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_prevent_allow_flags,
          {"Prevent Allow Flags", "scsi_mmc.prevent_allow.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_mmc_prevent_allow_persistent,
          { "PERSISTENT", "scsi_mmc.prevent_allow.persistent", FT_BOOLEAN, 8,
            NULL, 0x02, NULL, HFILL}},
        { &hf_scsi_mmc_prevent_allow_prevent,
          { "PREVENT", "scsi_mmc.prevent_allow.prevent", FT_BOOLEAN, 8,
            NULL, 0x01, NULL, HFILL}},
        { &hf_scsi_mmc_disk_flags,
          {"Disk Flags", "scsi_mmc.disk.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_mmc_format_flags,
          {"Format Flags", "scsi_mmc.format.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_mmc_track_flags,
          {"Track Flags", "scsi_mmc.track.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
        { &hf_scsi_mmc_data_flags,
          {"Data Flags", "scsi_mmc.data.flags", FT_UINT8, BASE_HEX, NULL, 0,
           NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_scsi_mmc_profile,
        &ett_scsi_notifications,
        &ett_scsi_prevent_allow,
        &ett_scsi_disk_flags,
        &ett_scsi_format_flags,
        &ett_scsi_track_flags,
        &ett_scsi_data_flags,
    };

    /* Register the protocol name and description */
    proto_scsi_mmc = proto_register_protocol("SCSI_MMC", "SCSI_MMC", "scsi_mmc");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_scsi_mmc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
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
