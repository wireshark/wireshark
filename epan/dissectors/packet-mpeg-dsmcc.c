/* packet-mpeg-dsmcc.c
 *
 * Routines for ISO/IEC 13818-6 DSM-CC
 * Copyright 2012, Weston Schmidt <weston_schmidt@alumni.purdue.edu>
 * Copyright 2019, Anthony Crawford <anthony.r.crawford@charter.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>
#include "packet-mpeg-sect.h"

void proto_register_dsmcc(void);
void proto_reg_handoff_dsmcc(void);

/* NOTE: Please try to keep this status comment up to date until the spec is
 * completely implemented - there are a large number of tables in the spec.
 *
 * 13818-6 Table status:
 *
 * Missing tables:
 * 3-1 3-2 3-3 3-4 3-6 3-7 3-8 3-9
 * 4-61, 4-81, 4-82, 4-87, 4-88
 * 5-*
 * 6-4
 * 7-5 7-8 7-10 7-12
 * 8-2 8-3 8-4 8-6
 * 9-5 9-6
 * 10-*
 * 11-*
 * 12-*
 *
 * Dissected tables:
 * 2-1 2-4 2-6 2-7
 * 4-x
 * 6-1
 * 7-6 7-7
 * 9-2
 * J.3
 *
 * Validated (all parameters are checked) U-N Messages:
 * 0x4010, 0x4011, 0x4020, 0x4021, 0x4022, 0x4023, 0x40b0
 * 0x8012, 0x8013, 0x8022, 0x8023, 0x8030, 0x8031, 0x8060, 0x8061, 0x80b0
 * Unvalidated U-N messages:
 * 4032, 4033, 4042, 4043, 4060, 4061, 4062, 4063,
 * 4070, 4071, 4072, 4073, 4082, 4090, 40a2, 40a3
 * 8041, 8042, 8050, 8051, 8062, 8063, 8070, 8071,
 * 8072, 8073, 8082, 8092, 80a0, 80a1, 80a2, 80a3
 *
 */


static int proto_dsmcc = -1;
static gboolean dsmcc_sect_check_crc = FALSE;

/* NOTE: Please add values numerically according to 13818-6 so it is easier to
 * keep track of what parameters/tables are associated with each other.
 */

/* table 2-1 dsmccMessageHeader - start */
static int hf_dsmcc_protocol_discriminator = -1;
static int hf_dsmcc_type = -1;
static int hf_dsmcc_message_id = -1;
static int hf_dsmcc_transaction_id = -1;
static int hf_dsmcc_header_reserved = -1;
static int hf_dsmcc_adaptation_length = -1;
static int hf_dsmcc_message_length = -1;
/* table 2-1 dsmccMessageHeader - end */

/* table 2-3 transactionId - start */
static int hf_dsmcc_un_sess_flag_transaction_id_originator = -1;
static int hf_dsmcc_un_sess_flag_transaction_id_number = -1;
/* table 2-3 transactionId - end */

/* table 2-4 dsmccAdaptationHeader - start */
static int hf_dsmcc_adaptation_type = -1;
/* table 2-4 dsmccAdaptationHeader - end */

/* table 2-6 dsmccConditionalAccess - start */
static int hf_dsmcc_adaptation_ca_reserved = -1;
static int hf_dsmcc_adaptation_ca_system_id = -1;
static int hf_dsmcc_adaptation_ca_length = -1;
/* table 2-6 dsmccConditionalAccess - end */

/* table 2-7 dsmccUserId - start */
static int hf_dsmcc_adaptation_user_id_reserved = -1;
/* table 2-7 dsmccUserId - end */

/* table 4-2, 4-3, 4-4 U-N messageDiscriminator - start */
/*static int hf_dsmcc_un_sess_message_discriminator = -1;*/
static int hf_dsmcc_un_sess_flag_message_discriminator = -1;
static int hf_dsmcc_un_sess_flag_message_scenario = -1;
static int hf_dsmcc_un_sess_flag_message_type = -1;
/* table 4-2, 4-3, 4-4 U-N messageDiscriminator - end */

/* other tables in section 4.2 - start */
static int hf_dsmcc_un_sess_response = -1;
static int hf_dsmcc_un_sess_reason = -1;
static int hf_dsmcc_un_sess_reserved = -1;
/* other tables in section 4.2 - end */

/* table 4-6 U-N user data format - start */
static int hf_dsmcc_un_sess_uu_data_len = -1;
static int hf_dsmcc_un_sess_uu_data = -1;
static int hf_dsmcc_un_sess_priv_data_len = -1;
static int hf_dsmcc_un_sess_priv_data = -1;
/* table 4-6 U-N user data format - end */

/* table 4-7 U-N Resources - start */
static int hf_dsmcc_un_sess_rsrc_desc_count = -1;
/* table 4-7 U-N Resources - end */

/* table 4-10 U-N Server Session Setup Indication - start */
static int hf_dsmcc_un_sess_forward_count = -1;
/* table 4-10 U-N Server Session Setup Indication - end */

/* 4-26 Server Delete Resource Request - start */
static int hf_dsmcc_un_sess_resource_count = -1;
static int hf_dsmcc_un_sess_resource_num = -1;
/* 4-26 Server Delete Resource Request - end */

/* table 4-30, 4-31, 4-32, 4-33, 4-34, 4-35, 4-36 - start */
static int hf_dsmcc_un_sess_status_type = -1;
static int hf_dsmcc_un_sess_status_count = -1;
static int hf_dsmcc_un_sess_status_byte = -1;
/* table 4-30, 4-31, 4-32, 4-33, 4-34, 4-35, 4-36 - end */

/* table 4-56 Client Session In Progress - start */
static int hf_dsmcc_un_sess_session_count = -1;
/* table 4-56 Client Session In Progress - end */

/* table 4-58 Message Fields data types - start */
static int hf_dsmcc_un_sess_session_id_device_id = -1;
static int hf_dsmcc_un_sess_session_id_session_number = -1;
/* table 4-58 Message Fields data types - end */

/* table 4-63 U-N common descriptor header - start */
static int hf_dsmcc_un_sess_rsrc_request_id = -1;
static int hf_dsmcc_un_sess_rsrc_descriptor_type = -1;
static int hf_dsmcc_un_sess_rsrc_number = -1;
static int hf_dsmcc_un_sess_rsrc_association_tag = -1;
static int hf_dsmcc_un_sess_rsrc_flags = -1;
static int hf_dsmcc_un_sess_rsrc_status = -1;
static int hf_dsmcc_un_sess_rsrc_desc_data_fields_length = -1;
static int hf_dsmcc_un_sess_rsrc_data_field_count = -1;
static int hf_dsmcc_un_sess_rsrc_type_owner_id = -1;
static int hf_dsmcc_un_sess_rsrc_type_owner_value = -1;
/* table 4-63 U-N common descriptor header - end */

/* table 4-64 U-N resource number assignor - start */
static int hf_dsmcc_un_sess_rsrc_flag_num_assignor = -1;
static int hf_dsmcc_un_sess_rsrc_flag_num_value = -1;
/* table 4-64 U-N resource number assignor - end */

/* table 4-65 U-N resource association tag assignor - start */
static int hf_dsmcc_un_sess_rsrc_flag_association_tag_assignor = -1;
static int hf_dsmcc_un_sess_rsrc_flag_association_tag_value = -1;
/* table 4-65 U-N resource association tag assignor - end */

/* table 4-66 U-N resource allocator - start */
static int hf_dsmcc_un_sess_rsrc_flag_allocator = -1;
/* table 4-66 U-N resource allocator - end */

/* table 4-67 U-N resource attribute - start */
static int hf_dsmcc_un_sess_rsrc_flag_attribute = -1;
/* table 4-67 U-N resource attribute - end */

/* table 4-68 U-N resource view - start */
static int hf_dsmcc_un_sess_rsrc_flag_view = -1;
/* table 4-68 U-N resource view - end */

/* table 4-71 U-N dsmccResourceDescriptorValue() format - start */
static int hf_dsmcc_un_sess_rsrc_value_type = -1;
static int hf_dsmcc_un_sess_rsrc_value_count = -1;
static int hf_dsmcc_un_sess_rsrc_value_data = -1;
static int hf_dsmcc_un_sess_rsrc_most_desired = -1;
static int hf_dsmcc_un_sess_rsrc_least_desired = -1;
/* table 4-71 U-N dsmccResourceDescriptorValue() format - end */

/* table 4-74 U-N Continuous Feed Session resource descriptor - start */
static int hf_dsmcc_un_sess_rsrc_cfs_num_count = -1;
static int hf_dsmcc_un_sess_rsrc_cfs_num = -1;
/* table 4-74 U-N Continuous Feed Session resource descriptor - end  */

/* table 4-75 U-N ATM Connection resource descriptor - start */
static int hf_dsmcc_un_sess_rsrc_atm_vpi = -1;
static int hf_dsmcc_un_sess_rsrc_atm_vci = -1;
/* table 4-75 U-N ATM Connection resource descriptor - end  */

/* table 4-76 MPEG Program - start */
static int hf_dsmcc_un_sess_rsrc_mpeg_ca_pid = -1;
static int hf_dsmcc_un_sess_rsrc_mpeg_elem_stream_count = -1;
/* table 4-76 MPEG Program - end */

/* table 4-77 Physical Channel - start */
static int hf_dsmcc_un_sess_rsrc_phys_chan_direction = -1;
/* table 4-77 Physical Channel - end */

/* table 4-84 IP - start */
static int hf_dsmcc_un_sess_rsrc_src_ip_addr = -1;
static int hf_dsmcc_un_sess_rsrc_src_ip_port = -1;
static int hf_dsmcc_un_sess_rsrc_dst_ip_addr = -1;
static int hf_dsmcc_un_sess_rsrc_dst_ip_port = -1;
static int hf_dsmcc_un_sess_rsrc_ip_protocol = -1;
/* table 4-84 IP - end */

/* table 4-86 PSTN Setup - start */
static int hf_dsmcc_un_sess_rsrc_pstn_calling_id = -1;
static int hf_dsmcc_un_sess_rsrc_pstn_called_id = -1;
/* table 4-86 PSTN Setup - end */

/* Table 4-89 Q.922 Connection - start */
static int hf_dsmcc_un_sess_rsrc_dlci_count = -1;
static int hf_dsmcc_un_sess_rsrc_dlci = -1;
static int hf_dsmcc_un_sess_rsrc_dl_association_tag = -1;
/* Table 4-89 Q.922 Connection - end */

/* table 4-90 Shared Resource - start */
static int hf_dsmcc_un_sess_rsrc_shared_resource_num = -1;
/* table 4-90 Shared Resource - end */

/* table 4-91 Shared Request ID - start */
static int hf_dsmcc_un_sess_rsrc_shared_resource_request_id = -1;
/* table 4-91 Shared Request ID - end */

/* table 4-92 Headend List - start */
static int hf_dsmcc_un_sess_rsrc_headend_count = -1;
static int hf_dsmcc_un_sess_rsrc_headend_code = -1;
/* table 4-92 Headend List - end */

/* table 4-94 SDB Continuous Feed - start */
static int hf_dsmcc_un_sess_rsrc_sdb_id = -1;
static int hf_dsmcc_un_sess_rsrc_sdb_program_count = -1;
static int hf_dsmcc_un_sess_rsrc_sdb_association_tag = -1;
static int hf_dsmcc_un_sess_rsrc_sdb_broadcast_program_id = -1;
/* table 4-94 SDB Continuous Feed - end */

/* table 4-95 SDB Associations - start */
static int hf_dsmcc_un_sess_rsrc_sdb_control_association_tag = -1;
static int hf_dsmcc_un_sess_rsrc_sdb_program_association_tag = -1;
/* table 4-95 SDB Associations - end */

/* table 4-96 SDB Entitlement - start */
static int hf_dsmcc_un_sess_rsrc_sdb_exclude_count = -1;
static int hf_dsmcc_un_sess_rsrc_sdb_include_count = -1;
/* table 4-96 SDB Entitlement - end */

/* user defined 0xf001-0xf007 - start */
/* Time Warner Cable Pegasus Session Setup Protocol
* Version 2.3, May 19 2003
* These user defined resource descriptors have been implemented in
* VOD BackOffice products by Time Warner, Arris and Ericsson. */
static int hf_dsmcc_un_sess_rsrc_trans_system = -1;
static int hf_dsmcc_un_sess_rsrc_inner_coding = -1;
static int hf_dsmcc_un_sess_rsrc_split_bitstream = -1;
static int hf_dsmcc_un_sess_rsrc_mod_format = -1;
static int hf_dsmcc_un_sess_rsrc_symbol_rate = -1;
static int hf_dsmcc_un_sess_rsrc_reserved = -1;
static int hf_dsmcc_un_sess_rsrc_interleave_depth = -1;
static int hf_dsmcc_un_sess_rsrc_modulation_mode = -1;
static int hf_dsmcc_un_sess_rsrc_fec = -1;
static int hf_dsmcc_un_sess_rsrc_headend_flag = -1;
static int hf_dsmcc_un_sess_rsrc_headend_tsid = -1;
static int hf_dsmcc_un_sess_rsrc_server_ca_copyprotect = -1;
static int hf_dsmcc_un_sess_rsrc_server_ca_usercount = -1;
static int hf_dsmcc_un_sess_rsrc_client_ca_info_length = -1;
static int hf_dsmcc_un_sess_rsrc_client_ca_info_data = -1;
static int hf_dsmcc_un_sess_rsrc_service_group = -1;
/* user defined 0xf001-0xf007 - end */

/* table 6-1 compatabilityDescriptor - start */
static int hf_compat_desc_length = -1;
static int hf_compat_desc_count = -1;
static int hf_desc_type = -1;
static int hf_desc_length = -1;
static int hf_desc_spec_type = -1;
static int hf_desc_spec_data = -1;
static int hf_desc_model = -1;
static int hf_desc_version = -1;
static int hf_desc_sub_desc_count = -1;
static int hf_desc_sub_desc_type = -1;
static int hf_desc_sub_desc_len = -1;
/* table 6-1 compatabilityDescriptor - end */

/* table 7-3 dsmccDownloadDataHeader - start */
static int hf_dsmcc_dd_download_id = -1;
static int hf_dsmcc_dd_message_id = -1;
/* table 7-3 dsmccDownloadDataHeader - end */

/* table 7-6 dsmccDownloadInfoIndication/InfoResponse - start */
static int hf_dsmcc_dii_download_id = -1;
static int hf_dsmcc_dii_block_size = -1;
static int hf_dsmcc_dii_window_size = -1;
static int hf_dsmcc_dii_ack_period = -1;
static int hf_dsmcc_dii_t_c_download_window = -1;
static int hf_dsmcc_dii_t_c_download_scenario = -1;
static int hf_dsmcc_dii_number_of_modules = -1;
static int hf_dsmcc_dii_module_id = -1;
static int hf_dsmcc_dii_module_size = -1;
static int hf_dsmcc_dii_module_version = -1;
static int hf_dsmcc_dii_module_info_length = -1;
static int hf_dsmcc_dii_private_data_length = -1;
/* table 7-6 dsmccDownloadInfoIndication/InfoResponse - end */

/* table 7-7 dsmccDownloadDataBlock - start */
static int hf_dsmcc_ddb_module_id = -1;
static int hf_dsmcc_ddb_version = -1;
static int hf_dsmcc_ddb_reserved = -1;
static int hf_dsmcc_ddb_block_number = -1;
/* table 7-7 dsmccDownloadDataBlock - end */

/* table 9-2 dsmccSection - start */
static int hf_dsmcc_table_id = -1;
static int hf_dsmcc_section_syntax_indicator = -1;
static int hf_dsmcc_private_indicator = -1;
static int hf_dsmcc_reserved = -1;
static int hf_dsmcc_section_length = -1;
static int hf_dsmcc_table_id_extension = -1;
static int hf_dsmcc_reserved2 = -1;
static int hf_dsmcc_version_number = -1;
static int hf_dsmcc_current_next_indicator = -1;
static int hf_dsmcc_section_number = -1;
static int hf_dsmcc_last_section_number = -1;
static int hf_dsmcc_crc = -1;
static int hf_dsmcc_checksum = -1;
/* table 9-2 dsmccSection - end */

/* table J.3 E-164 NSAP - start */
static int hf_dsmcc_un_sess_nsap_afi = -1;
static int hf_dsmcc_un_sess_nsap_idi = -1;
static int hf_dsmcc_un_sess_nsap_ho_dsp = -1;
static int hf_dsmcc_un_sess_nsap_esi = -1;
static int hf_dsmcc_un_sess_nsap_sel = -1;
/* table J.3 E-164 NSAP - end */

/* TODO: this should really live in the ETV dissector, but I'm not sure how
 * to make the functionality work exactly right yet.  Will work on a patch
 * for this next.
 */
static int hf_etv_module_abs_path = -1;
static int hf_etv_dii_authority = -1;

static gint ett_dsmcc = -1;
static gint ett_dsmcc_payload = -1;
static gint ett_dsmcc_header = -1;
static gint ett_dsmcc_adaptation_header = -1;
static gint ett_dsmcc_message_id = -1;
static gint ett_dsmcc_transaction_id = -1;
static gint ett_dsmcc_heading = -1;
static gint ett_dsmcc_rsrc_number = -1;
static gint ett_dsmcc_rsrc_association_tag = -1;
static gint ett_dsmcc_rsrc_flags = -1;
static gint ett_dsmcc_compat = -1;
static gint ett_dsmcc_compat_sub_desc = -1;
static gint ett_dsmcc_dii_module = -1;

static expert_field ei_dsmcc_invalid_value = EI_INIT;
static expert_field ei_dsmcc_crc_invalid = EI_INIT;

#define DSMCC_TCP_PORT          13819
#define DSMCC_UDP_PORT          13819

/* DSM-CC protocol discriminator, (table 2-1) */
#define DSMCC_PROT_DISC         0x11

#define DSMCC_SSI_MASK          0x8000
#define DSMCC_PRIVATE_MASK      0x4000
#define DSMCC_RESERVED_MASK              0x3000
#define DSMCC_LENGTH_MASK                0x0fff
#define DSMCC_RESERVED2_MASK               0xc0
#define DSMCC_VERSION_NUMBER_MASK          0x3e
#define DSMCC_CURRENT_NEXT_INDICATOR_MASK  0x01

/* DSM-CC U-N Session Flags */
#define DMSCC_FLAG_MESS_DISCRIMINATOR        0xc000
#define DMSCC_FLAG_MESS_SCENARIO             0x3ff0
#define DMSCC_FLAG_MESS_TYPE                 0x000f
#define DMSCC_FLAG_TRAN_ORIG             0xc0000000
#define DMSCC_FLAG_TRAN_NUM              0x3fffffff
#define DMSCC_FLAG_RSRC_NUM_ASSIGNOR         0xc000
#define DMSCC_FLAG_RSRC_NUM_VALUE            0x3fff
#define DMSCC_FLAG_RSRC_ASSOC_TAG_ASSIGNOR   0xc000
#define DMSCC_FLAG_RSRC_ASSOC_TAG_VALUE      0x3fff
#define DMSCC_FLAG_RSRC_VIEW                   0xc0
#define DMSCC_FLAG_RSRC_ATTRIBUTE              0x3c
#define DMSCC_FLAG_RSRC_ALLOCATOR              0x03

/* DSM-CC protocol U-N messages, (table 4-5) */
/* 4-5 U-N Session Client Messages */
#define DSMCC_UN_SESS_CLN_SESS_SET_REQ       0x4010
#define DSMCC_UN_SESS_CLN_SESS_SET_CNF       0x4011
#define DSMCC_UN_SESS_CLN_SESS_REL_REQ       0x4020
#define DSMCC_UN_SESS_CLN_SESS_REL_CNF       0x4021
#define DSMCC_UN_SESS_CLN_SESS_REL_IND       0x4022
#define DSMCC_UN_SESS_CLN_SESS_REL_RES       0x4023
#define DSMCC_UN_SESS_CLN_ADD_RSRC_IND       0x4032
#define DSMCC_UN_SESS_CLN_ADD_RSRC_RES       0x4033
#define DSMCC_UN_SESS_CLN_DEL_RSRC_IND       0x4042
#define DSMCC_UN_SESS_CLN_DEL_RSRC_RES       0x4043
#define DSMCC_UN_SESS_CLN_STATUS_REQ         0x4060
#define DSMCC_UN_SESS_CLN_STATUS_CNF         0x4061
#define DSMCC_UN_SESS_CLN_STATUS_IND         0x4062
#define DSMCC_UN_SESS_CLN_STATUS_RES         0x4063
#define DSMCC_UN_SESS_CLN_RESET_REQ          0x4070
#define DSMCC_UN_SESS_CLN_RESET_CNF          0x4071
#define DSMCC_UN_SESS_CLN_RESET_IND          0x4072
#define DSMCC_UN_SESS_CLN_RESET_RES          0x4073
#define DSMCC_UN_SESS_CLN_SESS_PROC_IND      0x4082
#define DSMCC_UN_SESS_CLN_CONN_REQ           0x4090
#define DSMCC_UN_SESS_CLN_SESS_TRN_IND       0x40a2
#define DSMCC_UN_SESS_CLN_SESS_TRN_RES       0x40a3
#define DSMCC_UN_SESS_CLN_SESS_INP_REQ       0x40b0
/* 4-5 U-N Session Server Messages */
#define DSMCC_UN_SESS_SRV_SESS_SET_IND       0x8012
#define DSMCC_UN_SESS_SRV_SESS_SET_RES       0x8013
#define DSMCC_UN_SESS_SRV_SESS_REL_REQ       0x8020
#define DSMCC_UN_SESS_SRV_SESS_REL_CNF       0x8021
#define DSMCC_UN_SESS_SRV_SESS_REL_IND       0x8022
#define DSMCC_UN_SESS_SRV_SESS_REL_RES       0x8023
#define DSMCC_UN_SESS_SRV_ADD_RSRC_REQ       0x8030
#define DSMCC_UN_SESS_SRV_ADD_RSRC_CNF       0x8031
#define DSMCC_UN_SESS_SRV_DEL_RSRC_REQ       0x8040
#define DSMCC_UN_SESS_SRV_DEL_RSRC_CNF       0x8041
#define DSMCC_UN_SESS_SRV_CONT_FEED_SESS_REQ 0x8050
#define DSMCC_UN_SESS_SRV_CONT_FEED_SESS_CNF 0x8051
#define DSMCC_UN_SESS_SRV_STATUS_REQ         0x8060
#define DSMCC_UN_SESS_SRV_STATUS_CNF         0x8061
#define DSMCC_UN_SESS_SRV_STATUS_IND         0x8062
#define DSMCC_UN_SESS_SRV_STATUS_RES         0x8063
#define DSMCC_UN_SESS_SRV_RESET_REQ          0x8070
#define DSMCC_UN_SESS_SRV_RESET_CNF          0x8071
#define DSMCC_UN_SESS_SRV_RESET_IND          0x8072
#define DSMCC_UN_SESS_SRV_RESET_RES          0x8073
#define DSMCC_UN_SESS_SRV_SESS_PROC_IND      0x8082
#define DSMCC_UN_SESS_SRV_CONN_IND           0x8092
#define DSMCC_UN_SESS_SRV_SESS_TRN_REQ       0x80a0
#define DSMCC_UN_SESS_SRV_SESS_TRN_CNF       0x80a1
#define DSMCC_UN_SESS_SRV_SESS_TRN_IND       0x80a2
#define DSMCC_UN_SESS_SRV_SESS_TRN_RES       0x80a3
#define DSMCC_UN_SESS_SRV_SESS_INP_REQ       0x80b0
/* 4-73 U-N Session Resource Descriptors */
#define RSRC_CONT_FEED_SESS     0x0001
#define RSRC_ATM_CONN           0x0002
#define RSRC_MPEG_PROG          0x0003
#define RSRC_PHYS_CHAN          0x0004
#define RSRC_TS_US_BW           0x0005
#define RSRC_TS_DS_BW           0x0006
#define RSRC_ATM_SVC_CONN       0x0007
#define RSRC_CONN_NTFY          0x0008
#define RSRC_IP                 0x0009
#define RSRC_CLN_TDMA_ASSIGN    0x000a
#define RSRC_PSTN_SETUP         0x000b
#define RSRC_NISDN_SETUP        0x000c
#define RSRC_NISDN_CONN         0x000d
#define RSRC_Q922_CONN          0x000e
#define RSRC_HEADEND_LIST       0x000f
#define RSRC_ATM_VC_CONN        0x0010
#define RSRC_SDB_CONT_FEED      0x0011
#define RSRC_SDB_ASSOC          0x0012
#define RSRC_SDB_ENT            0x0013
#define RSRC_SHARED_RSRC        0x7ffe
#define RSRC_SHARED_REQ_ID      0x7fff
#define RSRC_TYPE_OWNER         0xffff
/* U-N Session User Defined Resource Descriptors */
#define RSRC_MODULATION_MODE    0xf001
#define RSRC_HEADEND_ID         0xf003
#define RSRC_SERVER_CA          0xf004
#define RSRC_CLIENT_CA          0xf005
#define RSRC_ETHERNET           0xf006
#define RSRC_SERVICE_GROUP      0xf007


/* 2-2 */
static const range_string dsmcc_header_type_vals[] = {
    {    0,    0, "ISO/IEC 13818-6 Reserved" },
    { 0x01, 0x01, "ISO/IEC 13818-6 User-to-Network Configuration Message" },
    { 0x02, 0x02, "ISO/IEC 13818-6 User-to-Network Session Message" },
    { 0x03, 0x03, "ISO/IEC 13818-6 Download Message" },
    { 0x04, 0x04, "ISO/IEC 13818-6 SDB Channel Change Protocol Message" },
    { 0x05, 0x05, "ISO/IEC 13818-6 User-to-Network Pass-Thru Message" },
    { 0x06, 0x7f, "ISO/IEC 13818-6 Reserved" },
    { 0x80, 0xff, "User Defined Message Type" },
    {    0,    0, NULL }
};

/* 2-3 */
static const range_string dsmcc_un_sess_transaction_id_originator_vals[] = {
    {    0,    0, "Assigned by Client" },
    { 0x01, 0x01, "Assigned by Server" },
    { 0x02, 0x02, "Assigned by Network" },
    { 0x03, 0x03, "ISO/IEC 13818-6 Reserved" },
    { 0x04, 0xff, "Invalid"},
    {    0,    0, NULL }
};

/* 2-5 */
static const range_string dsmcc_adaptation_header_vals[] = {
    {    0,    0, "ISO/IEC 13818-6 Reserved" },
    { 0x01, 0x01, "DSM-CC Conditional Access Adaptation Format" },
    { 0x02, 0x02, "DSM-CC User ID Adaptation Format" },
    { 0x03, 0x7f, "ISO/IEC 13818-6 Reserved" },
    { 0x80, 0xff, "User Defined Adaptation Type" },
    {    0,    0, NULL }
};

/* 4-2 */
static const range_string dsmcc_un_sess_message_discriminator_vals[] = {
    {    0,    0, "ISO/IEC 13818-6 Reserved" },
    { 0x01, 0x01, "Client and Network" },
    { 0x02, 0x02, "Server and Network" },
    { 0x03, 0x0f, "ISO/IEC 13818-6 Reserved" },
    { 0x10, 0xff, "Invalid"},
    {    0,    0, NULL }
};

/* 4-3 */
static const range_string dsmcc_un_sess_message_scenario_vals[] = {
    {      0,      0, "ISO/IEC 13818-6 Reserved" },
    { 0x0001, 0x0001, "Session Setup" },
    { 0x0002, 0x0002, "Session Release" },
    { 0x0003, 0x0003, "Add Resource" },
    { 0x0004, 0x0004, "Delete Resource" },
    { 0x0005, 0x0005, "Continuous Feed Session Setup" },
    { 0x0006, 0x0006, "Status" },
    { 0x0007, 0x0007, "Reset" },
    { 0x0008, 0x0008, "Session Proceeding" },
    { 0x0009, 0x0009, "Session Connect" },
    { 0x000a, 0x000a, "Session Transfer" },
    { 0x000b, 0x000b, "Session In Progress" },
    { 0x000c, 0x01ff, "ISO/IEC 13818-6 Reserved" },
    { 0x0200, 0x03ff, "User Defined Message Scenario" },
    { 0x0400, 0xffff, "Invalid"},
    {      0,      0, NULL }
};

/* 4-4 */
static const range_string dsmcc_un_sess_message_type_vals[] = {
    {    0,    0, "Request Message" },
    { 0x01, 0x01, "Confirm Message" },
    { 0x02, 0x02, "Indication Message" },
    { 0x03, 0x03, "Response Message" },
    { 0x04, 0x0f, "ISO/IEC 13818-6 Reserved" },
    { 0x10, 0xff, "Invalid"},
    {    0,    0, NULL }
};

/* 4-5 */
static const value_string dsmcc_un_sess_message_id_vals[] = {
    { DSMCC_UN_SESS_CLN_SESS_SET_REQ,       "Client Session Setup Request" },
    { DSMCC_UN_SESS_CLN_SESS_SET_CNF,       "Client Session Setup Confirm" },
    { DSMCC_UN_SESS_CLN_SESS_REL_REQ,       "Client Session Release Request" },
    { DSMCC_UN_SESS_CLN_SESS_REL_CNF,       "Client Session Release Confirm" },
    { DSMCC_UN_SESS_CLN_SESS_REL_IND,       "Client Session Release Indication" },
    { DSMCC_UN_SESS_CLN_SESS_REL_RES,       "Client Session Release Response" },
    { DSMCC_UN_SESS_CLN_ADD_RSRC_IND,       "Client Add Resource Indication" },
    { DSMCC_UN_SESS_CLN_ADD_RSRC_RES,       "Client Add Resource Response" },
    { DSMCC_UN_SESS_CLN_DEL_RSRC_IND,       "Client Delete Resource Indication" },
    { DSMCC_UN_SESS_CLN_DEL_RSRC_RES,       "Client Delete Resource Response" },
    { DSMCC_UN_SESS_CLN_STATUS_REQ,         "Client Status Request" },
    { DSMCC_UN_SESS_CLN_STATUS_CNF,         "Client Status Confirm" },
    { DSMCC_UN_SESS_CLN_STATUS_IND,         "Client Status Indication" },
    { DSMCC_UN_SESS_CLN_STATUS_RES,         "Client Status Response" },
    { DSMCC_UN_SESS_CLN_RESET_REQ,          "Client Reset Request" },
    { DSMCC_UN_SESS_CLN_RESET_CNF,          "Client Reset Confirm" },
    { DSMCC_UN_SESS_CLN_RESET_IND,          "Client Reset Indication" },
    { DSMCC_UN_SESS_CLN_RESET_RES,          "Client Reset Response" },
    { DSMCC_UN_SESS_CLN_SESS_PROC_IND,      "Client Session Proceeding Indication" },
    { DSMCC_UN_SESS_CLN_CONN_REQ,           "Client Connect Request" },
    { DSMCC_UN_SESS_CLN_SESS_TRN_IND,       "Client Session Transfer Indication" },
    { DSMCC_UN_SESS_CLN_SESS_TRN_RES,       "Client Session Transfer Response" },
    { DSMCC_UN_SESS_CLN_SESS_INP_REQ,       "Client Session In Progress Request" },
    { DSMCC_UN_SESS_SRV_SESS_SET_IND,       "Server Session Setup Indication" },
    { DSMCC_UN_SESS_SRV_SESS_SET_RES,       "Server Session Setup Response" },
    { DSMCC_UN_SESS_SRV_SESS_REL_REQ,       "Server Session Release Request" },
    { DSMCC_UN_SESS_SRV_SESS_REL_CNF,       "Server Session Release Confirm" },
    { DSMCC_UN_SESS_SRV_SESS_REL_IND,       "Server Session Release Indication" },
    { DSMCC_UN_SESS_SRV_SESS_REL_RES,       "Server Session Release Response" },
    { DSMCC_UN_SESS_SRV_ADD_RSRC_REQ,       "Server Add Resource Request" },
    { DSMCC_UN_SESS_SRV_ADD_RSRC_CNF,       "Server Add Resource Confirm" },
    { DSMCC_UN_SESS_SRV_DEL_RSRC_REQ,       "Server Delete Resource Request" },
    { DSMCC_UN_SESS_SRV_DEL_RSRC_CNF,       "Server Delete Resource Confirm" },
    { DSMCC_UN_SESS_SRV_CONT_FEED_SESS_REQ, "Server Continuous Feed Session Request" },
    { DSMCC_UN_SESS_SRV_CONT_FEED_SESS_CNF, "Server Continuous Feed Session Confirm" },
    { DSMCC_UN_SESS_SRV_STATUS_REQ,         "Server Status Request" },
    { DSMCC_UN_SESS_SRV_STATUS_CNF,         "Server Status Confirm" },
    { DSMCC_UN_SESS_SRV_STATUS_IND,         "Server Status Indication" },
    { DSMCC_UN_SESS_SRV_STATUS_RES,         "Server Status Response" },
    { DSMCC_UN_SESS_SRV_RESET_REQ,          "Server Reset Request" },
    { DSMCC_UN_SESS_SRV_RESET_CNF,          "Server Reset Confirm" },
    { DSMCC_UN_SESS_SRV_RESET_IND,          "Server Reset Indication" },
    { DSMCC_UN_SESS_SRV_RESET_RES,          "Server Reset Response" },
    { DSMCC_UN_SESS_SRV_SESS_PROC_IND,      "Server Session Proceeding Indication" },
    { DSMCC_UN_SESS_SRV_CONN_IND,           "Server Connect Indication" },
    { DSMCC_UN_SESS_SRV_SESS_TRN_REQ,       "Server Session Transfer Request" },
    { DSMCC_UN_SESS_SRV_SESS_TRN_CNF,       "Server Session Transfer Confirm" },
    { DSMCC_UN_SESS_SRV_SESS_TRN_IND,       "Server Session Transfer Indication" },
    { DSMCC_UN_SESS_SRV_SESS_TRN_RES,       "Server Session Transfer Response" },
    { DSMCC_UN_SESS_SRV_SESS_INP_REQ,       "Server Session In Progress Request" },
    { 0, NULL }
};

/* 4-59 */
static const range_string dsmcc_un_sess_message_reason_codes_vals[] = {
    {      0,      0, "RsnOK. The command sequence is proceeding normally." },
    { 0x0001, 0x0001, "RsnNormal. Normal conditions for releasing the session." },
    { 0x0002, 0x0002, "RsnClProcError. Procedure error detected at the Client." },
    { 0x0003, 0x0003, "RsnNeProcError. Procedure error detected at the Network." },
    { 0x0004, 0x0004, "RsnSeProcError. Procedure error detected at the Server." },
    { 0x0005, 0x0005, "RsnClFormatError. Invalid format (e.g., missing parameter) detected at the Client." },
    { 0x0006, 0x0006, "RsnNeFormatError. Invalid format (e.g., missing parameter) detected at the Network." },
    { 0x0007, 0x0007, "RsnSeFormatError. Invalid format (e.g., missing parameter) detected at the Server." },
    { 0x0008, 0x0008, "RsnNeConfigCnf. Confirmed configuration sequence (i.e., Client must respond)" },
    { 0x0009, 0x0009, "RsnSeTranRefuse. Session transfer was refused by the destination Server." },
    { 0x000a, 0x000a, "RsnSeForwardOvl. Session forwarding is due to overload conditions." },
    { 0x000b, 0x000b, "RsnSeForwardMnt. Session forwarding is due to overload maintenance conditions." },
    { 0x000c, 0x000c, "RsnSeForwardUncond. Session forwarding is sent as an unconditional request." },
    { 0x000d, 0x000d, "RsnSeRejResource. Server rejected the assigned resources." },
    { 0x000e, 0x000e, "RsnNeBroadcast. Message is being broadcast and does not require a response." },
    { 0x000f, 0x000f, "RsnSeServiceTransfer. Server indicates that the Client shall establish a session to another serverId based on the context provided in the PrivateData()." },
    { 0x0010, 0x0010, "RsnClNoSession. Client indicates the Session ID is not active." },
    { 0x0011, 0x0011, "RsnSeNoSession. Server indicates the Session ID is not active." },
    { 0x0012, 0x0012, "RsnNeNoSession. Network indicates the Session ID is not active." },
    { 0x0013, 0x0013, "RsnRetrans. Message is a retransmission." },
    { 0x0014, 0x0014, "RsnNoTransaction. Message was received without a Transaction ID." },
    { 0x0015, 0x0015, "RsnClNoResource. Requested resource is not supported." },
    { 0x0016, 0x0016, "RsnClRejResource. Client rejected the assigned resources." },
    { 0x0017, 0x0017, "RsnNeRejResource. Network rejected the assigned resources assigned by the Server." },
    { 0x0018, 0x0018, "RsnNeTimerExpired. The message is being sent as the result of an expired timer." },
    { 0x0019, 0x0019, "RsnClSessionRelease. Client initiated session release." },
    { 0x001a, 0x001a, "RsnSeSessionRelease. Server initiated session release." },
    { 0x001b, 0x001b, "RsnNeSessionRelease. Network initiated session release." },
    { 0x001c, 0x7fff, "Reserved" },
    { 0x7fff, 0xffff, "User Defined Reason Code" },
    {      0,      0, NULL }
};

/* 4-60 */
static const range_string dsmcc_un_sess_message_response_codes_vals[] = {
    {      0,      0, "RspOK. Request completed with no errors." },
    { 0x0001, 0x0001, "RspClNoSession. Client rejected the request because the requested Session ID is invalid." },
    { 0x0002, 0x0002, "RspNeNoCalls. Network is unable to accept new sessions." },
    { 0x0003, 0x0003, "RspNeInvalidClient. Network rejected the request due to an invalid Client ID." },
    { 0x0004, 0x0004, "RspNeInvalidServer. Network rejected the request due to an invalid Server ID." },
    { 0x0005, 0x0005, "RspNeNoSession. Network rejected the request because the requested Session ID is invalid." },
    { 0x0006, 0x0006, "RspSeNoCalls. Server is unable to accept new sessions." },
    { 0x0007, 0x0007, "RspSeInvalidClient. Server rejected the request due to an invalid Client ID." },
    { 0x0008, 0x0008, "RspSeNoService. Server rejected the request because the requested service could not be provided." },
    { 0x0009, 0x0009, "RspSeNoCFS. Server rejected the request because the requested Continuous Feed Session could not be found." },
    { 0x000a, 0x000a, "RspClNoResponse. Network timed out before the Client responded to an Indication message." },
    { 0x000b, 0x000b, "RspSeNoResponse. Network timed out before the Server responded to an Indication message." },
    { 0x000c, 0x000f, "ISO/IEC 13818-6 reserved." },
    { 0x0010, 0x0010, "RspSeNoSession. Server rejected the request because the requested Session ID is invalid." },
    { 0x0011, 0x0011, "RspNeResourceContinue. Resource request completed with no errors but, an indicated resource was assigned an alternate value by the Network." },
    { 0x0012, 0x0012, "RspNeResourceFailed. Resource request failed because the Network was unable to assign the requested resources." },
    { 0x0013, 0x0013, "RspNeResourceOK. Requested command completed with no errors." },
    { 0x0014, 0x0014, "RspResourceNegotiate. Network was able to complete a request but has assigned alternate values to a negotiable field." },
    { 0x0015, 0x0015, "RspClSessProceed. Network is waiting on a response from the server." },
    { 0x0016, 0x0016, "RspClUnkRequestID. Client received a message which contained an unknown Resource Request ID." },
    { 0x0017, 0x0017, "RspClNoResource. Client rejected a session set-up because it was unable to use the assigned resources." },
    { 0x0018, 0x0018, "RspClNoCalls. Client rejected a session set-up because it was not accepting calls at that time." },
    { 0x0019, 0x0019, "RspNeNoResource. Network is unable to assign one or more resources to a session." },
    { 0x001a, 0x001f, "ISO/IEC 13818-6 reserved." },
    { 0x0020, 0x0020, "RspSeNoResource. Server is unable to complete a session set-up because the required resources are not available." },
    { 0x0021, 0x0021, "RspSeRejResource. Server rejected the assigned resources." },
    { 0x0022, 0x0022, "RspClProcError. Procedure error detected at the Client." },
    { 0x0023, 0x0023, "RspNeProcError. Procedure error detected at the Network." },
    { 0x0024, 0x0024, "RspSeProcError. Procedure error detected at the Server." },
    { 0x0025, 0x0025, "RspClFormatError. Invalid format (e.g., missing parameter) detected at Client." },
    { 0x0026, 0x0026, "RspNeFormatError. Invalid format (e.g., missing parameter) detected at Network." },
    { 0x0027, 0x0027, "RspSeFormatError. Invalid format (e.g., missing parameter) detected at Server." },
    { 0x0028, 0x0028, "RspSeForwardOvl. Session forwarding is due to overload conditions." },
    { 0x0029, 0x0029, "RspSeForwardMnt. Session forwarding is due to overload maintenance conditions." },
    { 0x002a, 0x002a, "RspClRejResource. Client rejected a resource assigned to a session." },
    { 0x002b, 0x002f, "ISO/IEC 13818-6 reserved." },
    { 0x0030, 0x0030, "RspSeForwardUncond. Session forwarding is sent as an unconditional request." },
    { 0x0031, 0x0031, "RspNeTransferFailed. Session transfer failed at the Network." },
    { 0x0032, 0x0032, "RspClTransferReject. Session transfer was rejected by the Client." },
    { 0x0033, 0x0033, "RspSeTransferReject. Session transfer was rejected by the Server." },
    { 0x0034, 0x0034, "RspSeTransferResource. Server rejected the session transfer due to insufficient resource." },
    { 0x0035, 0x0035, "RspResourceCompleted. Server has accepted the resources assigned by the Network." },
    { 0x0036, 0x0036, "RspForward. Server is requesting a Session Forward." },
    { 0x0037, 0x0037, "RspNeForwardFailed. Network is unable to process a Session Forward." },
    { 0x0038, 0x0038, "RspClForwarded. Session was forwarded to the indicated Client ID." },
    { 0x0039, 0x0040, "ISO/IEC 13818-6 reserved." },
    { 0x0041, 0x0041, "RspSeTransferNoRes. The transfer to Server could not get enough resources, so it rejected the transfer." },
    { 0x0042, 0x0042, "RspNeNotOwner. An action was requested on a session by a User which was not the owner of that session." },
    { 0x0043, 0x7fff, "ISO/IEC 13818-6 reserved." },
    { 0x8000, 0xffff, "User Defined Response Code" },
    {      0,      0, NULL }
};

/* 4-61 */
static const range_string dsmcc_un_sess_status_type_vals[] = {
    {      0,      0, "Reserved" },
    { 0x0001, 0x0001, "Identify Session List" },
    { 0x0002, 0x0002, "Identify Session Status" },
    { 0x0003, 0x0003, "Identify Configuration" },
    { 0x0004, 0x0004, "Query Resource Descriptor" },
    { 0x0005, 0x0005, "Query Resource Status" },
    { 0x0006, 0x7fff, "Reserved" },
    { 0x8000, 0xffff, "User Defined Status Type" },
    {      0,      0,  NULL }
};

/* 4-64 */
static const range_string dsmcc_un_sess_rsrc_number_assignor_vals[] = {
    {    0,    0, "Reserved" },
    { 0x01, 0x01, "Client" },
    { 0x02, 0x02, "Server" },
    { 0x03, 0x03, "Network" },
    { 0x04, 0xff, "Reserved" },
    {    0,    0, NULL }
};

/* 4-65 */
static const range_string dsmcc_un_sess_rsrc_association_tag_vals[] = {
    {    0,    0, "Reserved" },
    { 0x01, 0x01, "Client" },
    { 0x02, 0x02, "Server" },
    { 0x03, 0x03, "Network" },
    { 0x04, 0xff, "Reserved" },
    {    0,    0, NULL }
};

/* 4-66 */
static const range_string dsmcc_un_sess_rsrc_allocator_vals[] = {
    {    0,    0, "Unspecified" },
    { 0x01, 0x01, "Client" },
    { 0x02, 0x02, "Server" },
    { 0x03, 0x03, "Network" },
    { 0x04, 0xff, "Reserved" },
    {    0,    0, NULL }
};

/* 4-67 */
static const range_string dsmcc_un_sess_rsrc_attribute_vals[] = {
    {    0,    0, "Mandatory Non-Negotiable" },
    { 0x01, 0x01, "Mandatory Negotiable" },
    { 0x02, 0x02, "Non-Mandatory Non-Negotiable" },
    { 0x03, 0x03, "Non-Mandatory Negotiable" },
    { 0x04, 0x0f, "Reserved"},
    { 0x10, 0xff, "Invalid"},
    {    0,    0,  NULL }
};

/* 4-68 */
static const range_string dsmcc_un_sess_rsrc_view_vals[] = {
    {    0,    0, "Reserved" },
    { 0x01, 0x01, "Client View" },
    { 0x02, 0x02, "Server View" },
    { 0x03, 0x03, "Reserved" },
    { 0x04, 0xff, "Invalid" },
    {    0, 0, NULL }
};

/* 4-69 */
static const range_string dsmcc_un_sess_rsrc_status_vals[] = {
    {    0,    0, "Reserved" },
    { 0x01, 0x01, "Requested" },
    { 0x02, 0x02, "In Progress" },
    { 0x03, 0x03, "Alternate Assigned" },
    { 0x04, 0x04, "Assigned"},
    { 0x05, 0x05, "Failed"},
    { 0x06, 0x06, "Unprocessed"},
    { 0x07, 0x07, "Invalid"},
    { 0x08, 0x08, "Released"},
    { 0x09, 0x7f, "Reserved"},
    { 0x80, 0xff, "User Defined"},
    {    0,    0,  NULL }
};

/* 4-72 */
static const range_string dsmcc_un_sess_rsrc_value_types_vals[] = {
    {      0,      0, "Reserved" },
    { 0x0001, 0x0001, "Single" },
    { 0x0002, 0x0002, "List" },
    { 0x0003, 0x0003, "Range" },
    { 0x0004, 0x7fff, "Reserved"},
    { 0x8000, 0xffff, "User Defined"},
    {      0,      0,  NULL }
};

/* 4-73 */
static const range_string dsmcc_un_sess_rsrc_descriptor_type_vals[] = {
    {      0,      0, "Reserved" },
    { 0x0001, 0x0001, "Continuous Feed Session" },
    { 0x0002, 0x0002, "ATM Connection" },
    { 0x0003, 0x0003, "MPEG Program" },
    { 0x0004, 0x0004, "Physical Channel" },
    { 0x0005, 0x0005, "TS Upstream Bandwidth" },
    { 0x0006, 0x0006, "TS Downstream Bandwidth" },
    { 0x0007, 0x0007, "ATM SVC Connection" },
    { 0x0008, 0x0008, "Connection Notify" },
    { 0x0009, 0x0009, "IP" },
    { 0x000a, 0x000a, "Client TDMA Assignment" },
    { 0x000b, 0x000b, "PSTN Setup" },
    { 0x000c, 0x000c, "NISDN Setup" },
    { 0x000d, 0x000d, "NISDN Connection" },
    { 0x000e, 0x000e, "Q.922 Connections" },
    { 0x000f, 0x000f, "Headend List" },
    { 0x0010, 0x0010, "ATM VC Connection" },
    { 0x0011, 0x0011, "SDB Continuous Feed" },
    { 0x0012, 0x0012, "SDB Associations" },
    { 0x0013, 0x0013, "SDB Entitlement" },
    { 0x0014, 0x7ffd, "Reserved" },
    { 0x7ffe, 0x7ffe, "Shared Resource" },
    { 0x7fff, 0x7fff, "Shared Request ID" },
    { 0x8000, 0xf000, "User Defined" },
    { 0xf001, 0xf001, "Modulation Mode" },
    { 0xf002, 0xf002, "User Defined" },
    { 0xf003, 0xf003, "Headend ID" },
    { 0xf004, 0xf004, "Server Conditional Access" },
    { 0xf005, 0xf005, "Client Conditional Access" },
    { 0xf006, 0xf006, "Ethernet Interface" },
    { 0xf007, 0xf007, "Service Group" },
    { 0xf008, 0xfffe, "User Defined" },
    { 0xffff, 0xffff, "User Defined Type Owner" },
    {      0,      0,  NULL }
};

/* table 4-78 direction values */
static const range_string dsmcc_un_sess_rsrc_phys_chan_direction_vals[] = {
    {      0,      0, "Downstream (Server to Client)" },
    { 0x0001, 0x0001, "Upstream (Client to Server)" },
    { 0x0002, 0xffff, "ISO/IEC 13818-6 Reserved" },
    {      0,      0, NULL }
};

/* 4-84 IP protocol types */
static const range_string dsmcc_un_sess_rsrc_ip_protocol_types_vals[] = {
    {      0,      0, "Reserved" },
    { 0x0001, 0x0001, "TCP" },
    { 0x0002, 0x0002, "UDP" },
    { 0x0003, 0x7fff, "Reserved" },
    { 0x8000, 0xffff, "User Defined" },
    {      0,      0,  NULL }
};

/* user defined 0xf001-0xf007 - start */
static const range_string dsmcc_un_sess_rsrc_modulation_format_vals[] = {
    { 0x00, 0x00, "Unknown" },
    { 0x01, 0x05, "Reserved" },
    { 0x06, 0x06, "QAM16" },
    { 0x07, 0x07, "QAM32" },
    { 0x08, 0x08, "QAM64" },
    { 0x09, 0x0b, "Reserved" },
    { 0x0c, 0x0c, "QAM128" },
    { 0x0d, 0x0f, "Reserved" },
    { 0x10, 0x10, "QAM256" },
    { 0x11, 0xff, "Reserved" },
    {    0,    0, NULL }
};

static const range_string dsmcc_un_sess_rsrc_transmission_system_vals[] = {
    {    0,    0, "Unknown Transmission System" },
    { 0x01, 0x01, "SADVB Transmission System" },
    { 0x02, 0x02, "GI Transmission System" },
    { 0x03, 0xff, "Reserved" },
    {    0,    0, NULL }
};

static const range_string dsmcc_un_sess_rsrc_mod_mode_vals[] = {
    {    0,    0, "No Modulation Mode" },
    { 0x01, 0x18, "Reserved" },
    { 0x19, 0x19, "QAM 4 Modulation Mode"},
    { 0x1a, 0xff, "Reserved" },
    {    0,    0, NULL }
};

static const range_string dsmcc_un_sess_rsrc_fec_vals[] = {
    {    0,    0, "FEC Transmission System" },
    { 0x01, 0x01, "FEC DAVIC" },
    { 0x02, 0xff, "Reserved"},
    {    0,    0, NULL }
};

static const range_string dsmcc_un_sess_rsrc_headend_flag_vals[] = {
    {    0,    0, "Invalid" },
    { 0x01, 0x01, "The session is intended for the Head End named by the HeadEndId" },
    { 0x02, 0x02, "The session is intended for the Head End where the content is introduced to the network" },
    { 0x03, 0x03, "The session is intended for all Head Ends that have QAMs"},
    { 0x04, 0x04, "The session is intended for the QAM with an output Transport Stream ID named by the TransportStreamId"},
    { 0x05, 0xff, "Invalid" },
    {    0,    0, NULL }
};
/* user defined 0xf001-0xf007 - end */

/* 7-4 */
static const value_string dsmcc_dd_message_id_vals[] = {
    { 0x1001, "Download Info Request" },
    { 0x1002, "Download Info Indication" },
    { 0x1003, "Download Data Block" },
    { 0x1004, "Download Data Request" },
    { 0x1005, "Download Data Cancel" },
    { 0x1006, "Download Server Initiate" },
    {      0, NULL }
};

/* 9-2 */
static const value_string dsmcc_payload_name_vals[] = {
    { DSMCC_TID_LLCSNAP,   "LLCSNAP" },
    { DSMCC_TID_UN_MSG,    "User Network Message" },
    { DSMCC_TID_DD_MSG,    "Download Data Message" },
    { DSMCC_TID_DESC_LIST, "Descriptor List" },
    { DSMCC_TID_PRIVATE,   "Private" },
    { 0, NULL }
};

/* U-N Session Message Flags */
static int * const bf_message_id[] = {
    &hf_dsmcc_un_sess_flag_message_discriminator,
    &hf_dsmcc_un_sess_flag_message_scenario,
    &hf_dsmcc_un_sess_flag_message_type,
    NULL
};
static int * const bf_transaction_id[] = {
    &hf_dsmcc_un_sess_flag_transaction_id_originator,
    &hf_dsmcc_un_sess_flag_transaction_id_number,
    NULL
};
static int * const bf_rsrc_number[] = {
    &hf_dsmcc_un_sess_rsrc_flag_num_assignor,
    &hf_dsmcc_un_sess_rsrc_flag_num_value,
    NULL
};
static int * const bf_rsrc_association_tag[] = {
    &hf_dsmcc_un_sess_rsrc_flag_association_tag_assignor,
    &hf_dsmcc_un_sess_rsrc_flag_association_tag_value,
    NULL
};
static int * const bf_rsrc_flags[] = {
    &hf_dsmcc_un_sess_rsrc_flag_view,
    &hf_dsmcc_un_sess_rsrc_flag_attribute,
    &hf_dsmcc_un_sess_rsrc_flag_allocator,
    NULL
};

/* Table J.3 E.164 NSAP */
static guint
dissect_dsmcc_un_session_nsap(
        tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *sub_tree)
{
    guint offset_start;

    offset_start = offset;
    proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_nsap_afi, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_nsap_idi, tvb, offset, 8, ENC_NA);
    offset += 8;
    proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_nsap_ho_dsp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_nsap_esi, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_nsap_sel, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset-offset_start;
}

/* 4-58 SessionId */
static guint
dissect_dsmcc_un_session_id(
        tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *sub_tree)
{
    proto_tree *sub_sub_tree;
    guint       offset_start;

    offset_start = offset;

    sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 10, ett_dsmcc_heading, NULL, "Session ID");
    proto_item_set_text(sub_sub_tree, "Session ID: 0x%s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, 10));
    proto_tree_add_item(sub_sub_tree, hf_dsmcc_un_sess_session_id_device_id, tvb, offset, 6, ENC_NA);
    offset += 6;
    proto_tree_add_item(sub_sub_tree, hf_dsmcc_un_sess_session_id_session_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset-offset_start;
}


/* Table 2-4 Adaptation Header Format */
static void
dissect_dsmcc_adaptation_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t   *sub_tvb;
    guint       offset = 0;
    proto_item *pi;
    proto_tree *sub_tree;
    proto_tree *sub_sub_tree;
    guint8      type, tmp;
    guint16     ca_len;

    type = tvb_get_guint8(tvb, offset);

    if (1 == type) {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dsmcc_adaptation_header, NULL, "Adaptation Header");
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        tmp = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (0xff != tmp) {
            expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value, "Invalid value - should be 0xff");
        }
        offset += 1;
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_system_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        ca_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        sub_tvb = tvb_new_subset_length(tvb, offset, ca_len);
        call_data_dissector(sub_tvb, pinfo, tree);
    } else if (2 == type) {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dsmcc_adaptation_header, NULL, "Adaptation Header");
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        tmp = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_user_id_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (0xff != tmp) {
            expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value, "Invalid value - should be 0xff");
        }
        offset += 1;
        sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "User ID");
        dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
    } else {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dsmcc_adaptation_header, NULL, "Unknown Adaptation Header");
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
}

/* Table 2-1 DSM-CC Message Header Format */
static guint
dissect_dsmcc_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, gboolean download_header)
{
    tvbuff_t   *sub_tvb;
    proto_item *pi;
    proto_tree *sub_tree;
    guint8      prot_disc, adaptation_len;
    guint       reserved, offset_start;
    int         msg_id, tx_id;

    offset_start = offset;

    prot_disc = tvb_get_guint8(tvb, offset);
    reserved = tvb_get_guint8(tvb, 8+offset);
    adaptation_len = tvb_get_guint8(tvb, 9+offset);

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, 12+adaptation_len, ett_dsmcc_header, NULL, "DSM-CC Header");
    pi = proto_tree_add_item(sub_tree, hf_dsmcc_protocol_discriminator, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (DSMCC_PROT_DISC != prot_disc) {
        expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value, "Invalid value - should be 0x11");
    }
    offset += 1;
    proto_tree_add_item(sub_tree, hf_dsmcc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    if (TRUE == download_header) {
        msg_id = hf_dsmcc_dd_message_id;
        tx_id = hf_dsmcc_dd_download_id;
        proto_tree_add_item(sub_tree, msg_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(sub_tree, tx_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        msg_id = hf_dsmcc_message_id;
        tx_id = hf_dsmcc_transaction_id;
        proto_tree_add_bitmask_with_flags(sub_tree, tvb, offset, msg_id, ett_dsmcc_message_id, bf_message_id, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 2;
        proto_tree_add_bitmask_with_flags(sub_tree, tvb, offset, tx_id, ett_dsmcc_transaction_id, bf_transaction_id, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 4;
    }

    pi = proto_tree_add_item(sub_tree, hf_dsmcc_header_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (0xff != reserved) {
        expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value, "Invalid value - should be 0xff");
    }
    offset += 1;

    proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(sub_tree, hf_dsmcc_message_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (0 < adaptation_len) {
        sub_tvb = tvb_new_subset_length(tvb, offset, adaptation_len);
        dissect_dsmcc_adaptation_header(sub_tvb, pinfo, sub_tree);
        offset += adaptation_len;
    }

    return offset-offset_start;
}

static guint
dissect_dsmcc_dii_compat_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset)
{
    gint        i, j;
    guint8      sub_count, sub_len;
    guint16     len, count;
    proto_tree *compat_tree;
    proto_tree *desc_sub_tree;

    len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_compat_desc_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (0 < len) {
        count = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_compat_desc_count, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        for (i = 0; i < count; i++) {
            compat_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_dsmcc_compat, NULL, "Compatibility Descriptor");
            proto_tree_add_item(compat_tree, hf_desc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(compat_tree, hf_desc_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(compat_tree, hf_desc_spec_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(compat_tree, hf_desc_spec_data, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
            proto_tree_add_item(compat_tree, hf_desc_model, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(compat_tree, hf_desc_version, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            sub_count = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(compat_tree, hf_desc_sub_desc_count, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            for (j = 0; j < sub_count; j++) {
                sub_len = tvb_get_guint8(tvb, offset+1);

                desc_sub_tree = proto_tree_add_subtree(compat_tree, tvb, offset, sub_len+2,
                                            ett_dsmcc_compat_sub_desc, NULL, "Sub Descriptor");
                proto_tree_add_item(desc_sub_tree, hf_desc_sub_desc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(desc_sub_tree, hf_desc_sub_desc_len, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                offset += sub_len;
            }
        }

        if( 1000 == offset ) {
            expert_add_info( pinfo, NULL, &ei_dsmcc_crc_invalid);
        }
    }

    return 2 + len;
}

static void
dissect_dsmcc_dii(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset)
{
    guint16     modules, module_id, private_data_len;
    guint8      module_info_len, module_version;
    guint       i, module_size;
    proto_tree *mod_tree;

    proto_tree_add_item(tree, hf_dsmcc_dii_download_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_dsmcc_dii_block_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dsmcc_dii_window_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_dii_ack_period, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_dii_t_c_download_window, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_dsmcc_dii_t_c_download_scenario, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    offset += dissect_dsmcc_dii_compat_desc(tvb, pinfo, tree, offset);
    proto_tree_add_item(tree, hf_dsmcc_dii_number_of_modules, tvb, offset, 2, ENC_BIG_ENDIAN);
    modules = tvb_get_ntohs(tvb, offset);
    offset += 2;

    for (i = 0; i < modules; i++ ) {
        module_id = tvb_get_ntohs(tvb, offset);
        module_size = tvb_get_ntohl(tvb, 2+offset);
        module_version = tvb_get_guint8(tvb, 6+offset);

        mod_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
                ett_dsmcc_dii_module, NULL, "Module Id: 0x%x, Version: %u, Size: %u",
                module_id, module_version, module_size);
        proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset +=1;

        module_info_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_info_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset +=1;
        if (0 < module_info_len) {
            proto_tree_add_item(mod_tree, hf_etv_module_abs_path, tvb, offset, 1,
                ENC_ASCII|ENC_BIG_ENDIAN);
            offset += module_info_len;
        }
    }

    private_data_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_dsmcc_dii_private_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (0 < private_data_len) {
        proto_tree_add_item(tree, hf_etv_dii_authority, tvb, offset, 1,
            ENC_ASCII|ENC_BIG_ENDIAN);
        /*offset += private_data_len;*/
    }
}


static void
dissect_dsmcc_ddb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
            proto_tree *top_tree, guint offset)
{
    tvbuff_t   *sub_tvb;
    proto_item *pi;
    guint8      reserved;

    proto_tree_add_item(tree, hf_dsmcc_ddb_module_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dsmcc_ddb_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    reserved = tvb_get_guint8(tvb, offset);
    pi = proto_tree_add_item(tree, hf_dsmcc_ddb_reserved, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    if (0xff != reserved) {
        expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value,
                    "Invalid value - should be 0xff");
    }
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_ddb_block_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    sub_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(sub_tvb, pinfo, top_tree);
}


static void
dissect_dsmcc_un_download(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *top_tree)
{
    proto_tree *sub_tree;
    guint16    msg_id;
    guint      offset = 0;

    msg_id = tvb_get_ntohs(tvb, offset+2);

    sub_tree = proto_tree_add_subtree_format(tree, tvb, 0, -1, ett_dsmcc_payload, NULL,
            "User Network Message - %s", val_to_str(msg_id, dsmcc_dd_message_id_vals, "%u"));

    switch (msg_id) {
        case 0x1001:
        case 0x1002:
            offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, FALSE);
            dissect_dsmcc_dii(tvb, pinfo, sub_tree, offset);
            break;
        case 0x1003:
            offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, TRUE);
            dissect_dsmcc_ddb(tvb, pinfo, sub_tree, top_tree, offset);
            break;
        case 0x1004:
            /* TODO: Add support */
            break;
        case 0x1005:
            /* TODO: Add support */
            break;
        case 0x1006:
            /* TODO: Add support */
            break;
        default:
            break;
    }
}

/* table 4-71 dsmccResourceDescriptorValue format*/
static guint
dissect_dsmcc_un_session_resource_value(
        tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *sub_tree, guint value_len)
{
    guint32  i, counter, resource_value_type;
    guint    offset_start;

    offset_start = offset;

    proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_rsrc_value_type, tvb, offset, 2, ENC_BIG_ENDIAN, &resource_value_type);
    offset += 2;
    if (resource_value_type == 1)  /* single value */
    {
        proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_rsrc_value_data, tvb, offset, value_len, ENC_NA);
        offset += value_len;
    }
    else if (resource_value_type == 2)  /* list value */
    {
        proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_rsrc_value_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
        offset += 2;
        for (i=0; i<counter; i++)
        {
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_rsrc_value_data, tvb, offset, value_len, ENC_NA);
            offset += value_len;
        }
    }
    else if (resource_value_type == 3)  /* range value */
    {
        proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_rsrc_most_desired, tvb, offset, value_len, ENC_NA);
        offset += value_len;
        proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_rsrc_least_desired, tvb, offset, value_len, ENC_NA);
        offset += value_len;
    }

    return offset-offset_start;
}


static guint
dissect_dsmcc_un_session_resources(
        tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *sub_tree)
{
    proto_tree  *pi;
    proto_tree  *sub_sub_tree;
    proto_tree  *sub_sub_sub_tree;
    proto_tree  *sub_sub_sub_sub_tree;
    proto_tree  *rsrc_tree;
    guint32      i, j, counter, resource_count;
    guint16      tmp, resource_type, data_fields_length, counter_ca;
    guint        offset_start;

    offset_start = offset;

    /* Table 4-62 General format of the DSM-CC Resource Descriptor - dsmccResourceDescriptor() */
    proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_rsrc_desc_count, tvb, offset, 2, ENC_BIG_ENDIAN, &resource_count);
    offset += 2;
    for (j=0; j<resource_count; j++)
    {
        sub_sub_tree = proto_tree_add_subtree_format(sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Resource %u", 1+j);

        /* Table 4-63 - commonDescriptorHeader() */
        sub_sub_sub_tree = proto_tree_add_subtree(sub_sub_tree, tvb, offset, 14, ett_dsmcc_heading, NULL, "Header");
        proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_request_id, tvb, offset, 2, ENC_NA);
        offset += 2;
        proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_descriptor_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        resource_type = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_bitmask_with_flags(sub_sub_sub_tree, tvb, offset, hf_dsmcc_un_sess_rsrc_number, ett_dsmcc_rsrc_number, bf_rsrc_number, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 2;
        proto_tree_add_bitmask_with_flags(sub_sub_sub_tree, tvb, offset, hf_dsmcc_un_sess_rsrc_association_tag, ett_dsmcc_rsrc_association_tag, bf_rsrc_association_tag, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 2;
        proto_tree_add_bitmask_with_flags(sub_sub_sub_tree, tvb, offset, hf_dsmcc_un_sess_rsrc_flags, ett_dsmcc_rsrc_flags, bf_rsrc_flags, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset += 1;
        proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_status, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_desc_data_fields_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        data_fields_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_data_field_count, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Resource data - resourceDescriptorDataFields() */
        sub_sub_sub_tree = proto_tree_add_subtree(sub_sub_tree, tvb, offset, data_fields_length, ett_dsmcc_heading, NULL, "Data");
        switch (resource_type)
        {
            /* Table 4-74 Continuous Feed Session */
            case RSRC_CONT_FEED_SESS:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 10, ett_dsmcc_heading, NULL, "Session ID");
                proto_tree_add_item(rsrc_tree, hf_dsmcc_un_sess_session_id_device_id, tvb, offset, 6, ENC_NA);
                offset += 6;
                proto_tree_add_item(rsrc_tree, hf_dsmcc_un_sess_session_id_session_number, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item_ret_uint(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_cfs_num_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
                offset += 2;
                for (i=0; i<counter; i++)
                {
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_cfs_num, tvb, offset, 2, ENC_NA);
                }
                break;
            /* Table 4-75 ATM Connection */
            case RSRC_ATM_CONN:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "ATM Address:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 20);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "ATM VCI:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "ATM VPI:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                break;
            /* Table 4-76 MPEG Program */
            case RSRC_MPEG_PROG:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "MPEG Program Number:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "MPEG PMT PID:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_mpeg_ca_pid, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item_ret_uint(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_mpeg_elem_stream_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
                offset += 2;
                for (i=0; i<counter; i++)
                {
                    rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "MPEG PID:");
                    offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                    rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "MPEG Stream Type:");
                    offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 1);
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_reserved, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "MPEG Association Tag:");
                    offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                }
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "MPEG PCR:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                break;
            /* Table 4-77 Physical Channel */
            case RSRC_PHYS_CHAN:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Channel ID (Hz):");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_phys_chan_direction, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            /* Table 4-79 TS Upstream Bandwidth */
            case RSRC_TS_US_BW:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "TS Upstream Bandwidth:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "TS Upstream TSID:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                break;
            /* Table 4-80 TS Downstream Bandwidth */
            case RSRC_TS_DS_BW:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "TS Downstream Bandwidth:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "TS Downstream TSID:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                break;
            /* Table 4-81 ATM SVC Connection */
            case RSRC_ATM_SVC_CONN:
                /* TODO - Unsure how to implement ITU-T Q.2931 */
                break;
            /* Table 4-82 Connection Notify */
            case RSRC_CONN_NTFY:
                /* no data fields */
                break;
            /* Table 4-84 IP */
            case RSRC_IP:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_src_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_src_ip_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_dst_ip_addr, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_dst_ip_port, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_ip_protocol, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                break;
            /* Table 4-85 Client TDMA Assignment */
            case RSRC_CLN_TDMA_ASSIGN:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Start Slot Number:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Number of Slots:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Slot Spacing:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Upstream Transport ID:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                break;
            /* Table 4-86 PSTN Setup */
            case RSRC_PSTN_SETUP:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_pstn_calling_id, tvb, offset, 12, ENC_NA);
                offset += 12;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_pstn_called_id, tvb, offset, 12, ENC_NA);
                offset += 12;
                break;
            /* Table 4-87 NISDN Setup */
            case RSRC_NISDN_SETUP:
            /*  TODO - Unsure how to implement ITU-T Q.931 */
                break;
            /* Table 4-88 NISDN Connection */
            case RSRC_NISDN_CONN:
            /*  TODO - Unsure how to implement ITU-T Q.931 */
                break;
            /* Table 4-89 Q.922 Connection */
            case RSRC_Q922_CONN:
                proto_tree_add_item_ret_uint(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_dlci_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
                offset += 2;
                for (i=0; i<counter; i++)
                {
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_dlci, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_dl_association_tag, tvb, offset, 2, ENC_NA);
                    offset += 2;
                }
                break;
            /* Table 4-92 Headend List */
            case RSRC_HEADEND_LIST:
                proto_tree_add_item_ret_uint(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_headend_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
                offset += 2;
                for (i=0; i<counter; i++)
                {
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_headend_code, tvb, offset, 20, ENC_NA);
                    offset += 20;
                }
                break;
            /* Table 4-93 ATM VC Connection */
            case RSRC_ATM_VC_CONN:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_atm_vpi, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_atm_vci, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;
            /* Table 4-94 SDB Continuous Feed */
            case RSRC_SDB_CONT_FEED:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_id, tvb, offset, 6, ENC_NA);
                offset += 6;
                proto_tree_add_item_ret_uint(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_program_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
                offset += 2;
                for (i=0; i<counter; i++)
                {
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_association_tag, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_broadcast_program_id, tvb, offset, 2, ENC_NA);
                    offset += 2;
                }
                break;
            /* Table 4-95 SDB Associations */
            case RSRC_SDB_ASSOC:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_control_association_tag, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_program_association_tag, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;
            /* Table 4-96 SDB Entitlement */
            case RSRC_SDB_ENT:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_id, tvb, offset, 6, ENC_NA);
                offset += 6;
                proto_tree_add_item_ret_uint(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_exclude_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
                offset += 2;
                for (i=0; i<counter; i++)
                {
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_broadcast_program_id, tvb, offset, 2, ENC_NA);
                    offset += 2;
                }
                proto_tree_add_item_ret_uint(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_include_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
                offset += 2;
                for (i=0; i<counter; i++)
                {
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_sdb_broadcast_program_id, tvb, offset, 2, ENC_NA);
                    offset += 2;
                }
                break;
            /* User Defined - Modulation Mode */
            case RSRC_MODULATION_MODE:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_trans_system, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_inner_coding, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_split_bitstream, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_mod_format, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_symbol_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_interleave_depth, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_modulation_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_fec, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                break;
            /* User Defined - Headend ID */
            case RSRC_HEADEND_ID:
                tmp = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                pi = proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_headend_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
                if ((tmp == 0) || (tmp > 4)) {
                    expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value, "Invalid value - should be values 1 to 4");
                }
                offset += 2;
                sub_sub_sub_sub_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Headend ID:");
                offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_sub_sub_tree);
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_headend_tsid, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            /* User Defined - Server Conditional Access */
            case RSRC_SERVER_CA:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Server CA System ID:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_server_ca_copyprotect, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item_ret_uint(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_server_ca_usercount, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
                offset += 2;
                for (i=0; i<counter; i++)
                {
                    sub_sub_sub_sub_tree = proto_tree_add_subtree_format(sub_sub_sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "User ID %u", 1+i);
                    offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_sub_sub_tree);
                }
                break;
            /* User Defined - Client Conditional Access */
            case RSRC_CLIENT_CA:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Client CA System ID:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_client_ca_info_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                counter_ca = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                offset += 2;
                if (counter_ca > 0)
                {
                    proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_client_ca_info_data, tvb, offset, counter_ca, ENC_NA);
                    offset = offset + counter_ca;
                }
                break;
            /* User Defined - Ethernet Interface */
            case RSRC_ETHERNET:
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Ethernet Source UDP:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Ethernet Source IP:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Ethernet Source MAC:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 6);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Ethernet Destination UDP:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 2);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Ethernet Destination IP:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 4);
                rsrc_tree = proto_tree_add_subtree(sub_sub_sub_tree, tvb, offset, 0, ett_dsmcc_heading, NULL, "Ethernet Destination MAC:");
                offset += dissect_dsmcc_un_session_resource_value(tvb, offset, pinfo, rsrc_tree, 6);
                break;
            /* User Defined - Service Group */
            case RSRC_SERVICE_GROUP:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_value_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_service_group, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            /* Table 4-90 Shared Resource */
            case RSRC_SHARED_RSRC:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_shared_resource_num, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;
            /* Table 4-91 Shared Resource Request ID */
            case RSRC_SHARED_REQ_ID:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_shared_resource_request_id, tvb, offset, 2, ENC_NA);
                offset += 2;
                break;
            /* Table 4-63 Type Owner */
            case RSRC_TYPE_OWNER:
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_type_owner_id, tvb, offset, 3, ENC_NA);
                offset += 3;
                proto_tree_add_item(sub_sub_sub_tree, hf_dsmcc_un_sess_rsrc_type_owner_value, tvb, offset, 3, ENC_NA);
                offset += 3;
                break;
            default:
                break;
        }
    }

    return offset-offset_start;
}

/* UserData() is vendor proprietary, therefore not dissected. */
static guint
dissect_dsmcc_un_session_user_data(
        tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint   offset_start;
    guint16 uu_len, priv_len;

    offset_start = offset;

    uu_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_dsmcc_un_sess_uu_data_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (uu_len>0) {
        proto_tree_add_item(tree, hf_dsmcc_un_sess_uu_data, tvb, offset, uu_len, ENC_NA);
        offset += uu_len;
    }

    priv_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_dsmcc_un_sess_priv_data_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (priv_len>0) {
        proto_tree_add_item(tree, hf_dsmcc_un_sess_priv_data, tvb, offset, priv_len, ENC_NA);
        offset += priv_len;
    }

    return offset-offset_start;
}


static void
dissect_dsmcc_un_session(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, proto_tree *top_tree _U_)
{
    proto_item  *pi;
    proto_tree  *sub_tree;
    proto_tree  *sub_sub_tree;
    guint32     i, counter;
    guint16     msg_id;
    guint       offset = 0;

    msg_id = tvb_get_ntohs(tvb, offset+2);

    sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
            ett_dsmcc_payload, &pi, "User Network Message (Session) - %s",
            val_to_str(msg_id, dsmcc_un_sess_message_id_vals, "0x%x"));
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
            val_to_str(msg_id, dsmcc_un_sess_message_id_vals, "0x%x"));

    offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, FALSE);

    switch (msg_id) {

        /* CLIENT Messages */
        case DSMCC_UN_SESS_CLN_SESS_SET_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* client nsap */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* server nsap */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* user data */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_SESS_SET_CNF:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_SESS_REL_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_SESS_REL_CNF:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_SESS_REL_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_SESS_REL_RES:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_ADD_RSRC_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_ADD_RSRC_RES:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_DEL_RSRC_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_resource_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_resource_num, tvb, offset, 2, ENC_NA);
                offset += 2;
            }
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_DEL_RSRC_RES:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_STATUS_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_status_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_byte, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case DSMCC_UN_SESS_CLN_STATUS_CNF:
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_status_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_byte, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case DSMCC_UN_SESS_CLN_STATUS_IND:
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_status_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_byte, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case DSMCC_UN_SESS_CLN_STATUS_RES:
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_status_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_byte, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case DSMCC_UN_SESS_CLN_RESET_REQ:
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_CLN_RESET_CNF:
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_CLN_RESET_IND:
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_CLN_RESET_RES:
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_CLN_SESS_PROC_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_CLN_CONN_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_SESS_TRN_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            /* client */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* old server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Old Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* new server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "New Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_SESS_TRN_RES:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_CLN_SESS_INP_REQ:
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_session_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            }
            break;

        /* SERVER Messages */
        case DSMCC_UN_SESS_SRV_SESS_SET_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* client */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_forward_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Forward Server ID");
                offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            }
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_SET_RES:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* next server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Next Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_REL_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_REL_CNF:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_REL_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_REL_RES:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_ADD_RSRC_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_ADD_RSRC_CNF:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_DEL_RSRC_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_resource_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_resource_num, tvb, offset, 2, ENC_NA);
                offset += 2;
            }
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_DEL_RSRC_CNF:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_CONT_FEED_SESS_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_CONT_FEED_SESS_CNF:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_STATUS_REQ:
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_status_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_byte, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case DSMCC_UN_SESS_SRV_STATUS_CNF:
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_status_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_byte, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case DSMCC_UN_SESS_SRV_STATUS_IND:
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_status_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_byte, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case DSMCC_UN_SESS_SRV_STATUS_RES:
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_status_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_status_byte, tvb, offset, 1, ENC_NA);
                offset += 1;
            }
            break;
        case DSMCC_UN_SESS_SRV_RESET_REQ:
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_SRV_RESET_CNF:
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_SRV_RESET_IND:
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_SRV_RESET_RES:
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_SRV_SESS_PROC_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DSMCC_UN_SESS_SRV_CONN_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_TRN_REQ:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            /* destination server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Destination Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* base server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Base Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_TRN_CNF:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_TRN_IND:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            /* client */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Client ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* source server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Source Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            /* base server */
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, 20, ett_dsmcc_heading, NULL, "Base Server ID");
            offset += dissect_dsmcc_un_session_nsap(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_TRN_RES:
            offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "Resources");
            offset += dissect_dsmcc_un_session_resources(tvb, offset, pinfo, sub_sub_tree);
            sub_sub_tree = proto_tree_add_subtree(sub_tree, tvb, offset, -1, ett_dsmcc_heading, NULL, "User Data");
            offset += dissect_dsmcc_un_session_user_data(tvb, offset, pinfo, sub_sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_INP_REQ:
            proto_tree_add_item_ret_uint(sub_tree, hf_dsmcc_un_sess_session_count, tvb, offset, 2, ENC_BIG_ENDIAN, &counter);
            offset += 2;
            for (i=0; i<counter; i++)
            {
                offset += dissect_dsmcc_un_session_id(tvb, offset, pinfo, sub_tree);
            }
            break;
        default:
            break;
    }
    proto_item_set_len(pi, offset);
}


static void
dissect_dsmcc_un(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
            proto_tree *top_tree)
{
    guint8 type;

    /* dsmccMessageHeader.dsmccType */
    type = tvb_get_guint8(tvb, 1);

    switch (type) {
        case 1: /* user-to-network configuration */
            /* TODO: Add support */
            break;
        case 2: /* user-to-network session */
            dissect_dsmcc_un_session(tvb, pinfo, tree, top_tree);
            break;
        case 3: /* user-to-network download */
            dissect_dsmcc_un_download(tvb, pinfo, tree, top_tree);
            break;
        case 4: /* sdb channel change protocol */
            /* TODO: Add support */
            break;
        case 5: /* user-to-network pass-thru */
            /* TODO: Add support */
            break;
        default:
            break;
    }
}


static int
dissect_dsmcc_ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_in, void *data _U_)
{
    proto_item *pi;
    proto_tree *tree;
    guint       crc_len;
    guint8      tid;
    guint16     sect_len;
    guint32     crc, calculated_crc;
    const char *label;
    tvbuff_t   *sub_tvb;
    guint16     ssi;
    guint       offset = 0;

    pi = proto_tree_add_item(tree_in, proto_dsmcc, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(pi, ett_dsmcc);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSM-CC");

    tid = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_dsmcc_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    ssi = tvb_get_ntohs(tvb, offset);
    ssi &= DSMCC_SSI_MASK;
    proto_tree_add_item(tree, hf_dsmcc_section_syntax_indicator, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_private_indicator, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_section_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    sect_len = tvb_get_ntohs(tvb, offset);
    sect_len &= DSMCC_LENGTH_MASK;
    offset += 2;

    proto_tree_add_item(tree, hf_dsmcc_table_id_extension, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dsmcc_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_version_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_current_next_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_last_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;

    sub_tvb = tvb_new_subset_length(tvb, offset, sect_len-9);
    switch (tid) {
        case DSMCC_TID_LLCSNAP:
            /* TODO: Add support */
            break;
        case DSMCC_TID_UN_MSG:
        case DSMCC_TID_DD_MSG:
            dissect_dsmcc_un(sub_tvb, pinfo, tree, tree_in);
            break;
        case DSMCC_TID_DESC_LIST:
            /* TODO: Add support */
            break;
        case DSMCC_TID_PRIVATE:
            /* TODO: Add support */
            break;
        default:
            break;
    }

    crc_len = 3 + sect_len - 4; /* Add the header, remove the crc */
    if (ssi) {
        crc = tvb_get_ntohl(tvb, crc_len);

        calculated_crc = crc;
        label = "Unverified";
        if (dsmcc_sect_check_crc) {
            label = "Verified";
            calculated_crc = crc32_mpeg2_tvb_offset(tvb, 0, crc_len);
        }

        if (calculated_crc == crc) {
            proto_tree_add_uint_format( tree, hf_dsmcc_crc, tvb,
                crc_len, 4, crc, "CRC: 0x%08x [%s]", crc, label);
        } else {
            proto_item *msg_error;

            msg_error = proto_tree_add_uint_format( tree, hf_dsmcc_crc, tvb,
                        crc_len, 4, crc,
                        "CRC: 0x%08x [Failed Verification (Calculated: 0x%08x)]",
                        crc, calculated_crc );
            PROTO_ITEM_SET_GENERATED(msg_error);
            expert_add_info( pinfo, msg_error, &ei_dsmcc_crc_invalid);
        }
    } else {
        /* TODO: actually check the checksum */
        proto_tree_add_checksum(tree, tvb, crc_len, hf_dsmcc_checksum,
            -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }

    return tvb_reported_length(tvb);
}


static int dissect_dsmcc_tcp(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data _U_)
{
    proto_item *pi;
    proto_tree *sub_tree;

    if (tvb_get_guint8(tvb, 0) != DSMCC_PROT_DISC)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSM-CC");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_item(tree, proto_dsmcc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(pi, ett_dsmcc);

    dissect_dsmcc_un(tvb, pinfo, sub_tree, tree);

    return tvb_reported_length(tvb);
}


static int dissect_dsmcc_udp(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data _U_)
{
    proto_item *pi;
    proto_tree *sub_tree;

    if (tvb_get_guint8(tvb, 0) != DSMCC_PROT_DISC)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSM-CC");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_item(tree, proto_dsmcc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(pi, ett_dsmcc);

    dissect_dsmcc_un(tvb, pinfo, sub_tree, tree);

    return tvb_reported_length(tvb);
}


void
proto_register_dsmcc(void)
{
    /* NOTE: Please add tables numerically according to 13818-6 so it is
     * easier to keep track of what parameters/tables are associated with
     * each other.
     */
    static hf_register_info hf[] = {

        /* table 2-1 dsmccMessageHeader - start */
        { &hf_dsmcc_protocol_discriminator, {
            "Protocol Discriminator", "mpeg_dsmcc.protocol",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_type, {
            "Type", "mpeg_dsmcc.type",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_header_type_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_message_id, {
            "Message ID", "mpeg_dsmcc.message_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_transaction_id, {
            "Transaction ID", "mpeg_dsmcc.transaction_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_header_reserved, {
            "Reserved", "mpeg_dsmcc.header_reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_adaptation_length, {
            "Adaptation Length", "mpeg_dsmcc.adaptation_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_message_length, {
            "Message Length", "mpeg_dsmcc.message_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 2-1 dsmccMessageHeader - end */

        /* table 2-3 Transaction ID originator - start */
        { &hf_dsmcc_un_sess_flag_transaction_id_originator, {
            "Transaction ID Originator", "mpeg_dsmcc.transaction_id_originator",
            FT_UINT32, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_transaction_id_originator_vals),
            DMSCC_FLAG_TRAN_ORIG, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_flag_transaction_id_number, {
            "Transaction Number", "mpeg_dsmcc.transaction_id_number",
            FT_UINT32, BASE_DEC, NULL, DMSCC_FLAG_TRAN_NUM, NULL, HFILL
        } },
        /* table 2-3 Transaction ID originator - end */

        /* table 2-4 dsmccAdaptationHeader - start */
        { &hf_dsmcc_adaptation_type, {
            "Adaptation Type", "mpeg_dsmcc.adaptation_header.type",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_adaptation_header_vals), 0, NULL, HFILL
        } },
        /* table 2-4 dsmccAdaptationHeader - end */

        /* table 2-6 dsmccConditionalAccess - start */
        { &hf_dsmcc_adaptation_ca_reserved, {
            "Reserved", "mpeg_dsmcc.adaptation_header.ca.reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_adaptation_ca_system_id, {
            "CA System ID", "mpeg_dsmcc.adaptation_header.ca.system_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_adaptation_ca_length, {
            "CA Length", "mpeg_dsmcc.adaptation_header.ca.length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 2-6 dsmccConditionalAccess - end */

        /* table 2-7 dsmccUserId - start */
        { &hf_dsmcc_adaptation_user_id_reserved, {
            "Reserved", "mpeg_dsmcc.adaptation_header.uid.reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        /* table 2-7 dsmccUserId - end */

        /* other tables in section 4.2 - start */
        { &hf_dsmcc_un_sess_response, {
            "Response", "mpeg_dsmcc.un_sess.response",
            FT_UINT16, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_message_response_codes_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_reason, {
            "Reason", "mpeg_dsmcc.un_sess.reason",
            FT_UINT16, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_message_reason_codes_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_reserved, {
            "Reserved", "mpeg_dsmcc.un_sess.reserved",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        /* other tables in section 4.2 - end */

        /* table 4-2 message discriminator - start */
        { &hf_dsmcc_un_sess_flag_message_discriminator, {
            "Message Discriminator", "mpeg_dsmcc.message_discriminator",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_message_discriminator_vals),
            DMSCC_FLAG_MESS_DISCRIMINATOR, NULL, HFILL
        } },
        /* table 4-2 message discriminator - end */

        /* table 4-3 message scenario - start */
        { &hf_dsmcc_un_sess_flag_message_scenario, {
            "Message Scenario", "mpeg_dsmcc.message_scenario",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_message_scenario_vals),
            DMSCC_FLAG_MESS_SCENARIO, NULL, HFILL
        } },
        /* table 4-3 message scenario - end */

        /* table 4-4 message type - start */
        { &hf_dsmcc_un_sess_flag_message_type, {
            "Message Type", "mpeg_dsmcc.message_type",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_message_type_vals),
            DMSCC_FLAG_MESS_TYPE, NULL, HFILL
        } },
        /* table 4-4 message type - end */

        /* table 4-5 U-N Resources - start */
        { &hf_dsmcc_un_sess_rsrc_desc_count, {
            "Resource Descriptor Count", "mpeg_dsmcc.un_sess.rsrc_desc_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 4-5 U-N Resources - end */

        /* table 4-6 U-N user data format - start */
        { &hf_dsmcc_un_sess_uu_data_len, {
            "User data length", "mpeg_dsmcc.un_sess.uu_data_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_uu_data, {
            "User data", "mpeg_dsmcc.un_sess.uu_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_priv_data_len, {
            "Private data length", "mpeg_dsmcc.un_sess.priv_data_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_priv_data, {
            "Private data", "mpeg_dsmcc.un_sess.priv_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-6 U-N user data format - end */

        /* 4-10 - Server Session Setup Indication message - start */
        { &hf_dsmcc_un_sess_forward_count, {
            "Forward Count", "mpeg_dsmcc.un_sess.forward_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* 4-10 - Server Session Setup Indication message - start */

        /* 4-26 - start */
        { &hf_dsmcc_un_sess_resource_count, {
            "Resource Count", "mpeg_dsmcc.un_sess.resource_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_resource_num, {
            "Resource Number", "mpeg_dsmcc.un_sess.resource_num",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* 4-26 - end */

        /* table 4-35 ServerStatusRequest message, 4-36 ServerStatusConfirm message - start */
        { &hf_dsmcc_un_sess_status_type, {
            "Status Type", "mpeg_dsmcc.un_sess.status_type",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_status_type_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_status_count, {
            "Status Count (Bytes)", "mpeg_dsmcc.un_sess.status_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_status_byte, {
            "Status Byte", "mpeg_dsmcc.un_sess.status_byte",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-35 ServerStatusRequest message, 4-36 ServerStatusConfirm message - end */

        /* table 4-56 - start */
        { &hf_dsmcc_un_sess_session_count, {
            "Session Count", "mpeg_dsmcc.un_sess.session_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 4-56 - end */

        /* table 4-58 Message Fields data types - start */
        { &hf_dsmcc_un_sess_session_id_device_id, {
            "Device ID", "mpeg_dsmcc.un_sess.session_id_device_id",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_session_id_session_number, {
            "Session Number", "mpeg_dsmcc.un_sess.session_id_session_number",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 4-58 Message Fields data types - start */

        /* table 4-63 U-N common descriptor header - start */
        { &hf_dsmcc_un_sess_rsrc_request_id, {
            "Request ID", "mpeg_dsmcc.un_sess.rsrc_request_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_descriptor_type, {
            "Descriptor Type", "mpeg_dsmcc.un_sess.rsrc_descriptor_type",
            FT_UINT16, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_descriptor_type_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_number, {
            "Resource Num", "mpeg_dsmcc.un_sess.rsrc_number",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_association_tag, {
            "Association Tag", "mpeg_dsmcc.un_sess.rsrc_association_tag",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_flags, {
            "Resource Flags", "mpeg_dsmcc.un_sess.rsrc_flags",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_status, {
            "Resource Status", "mpeg_dsmcc.un_sess.rsrc_status",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_status_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_desc_data_fields_length, {
            "Data Fields Length", "mpeg_dsmcc.un_sess.rsrc_desc_data_fields_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_data_field_count, {
            "Data Field Count", "mpeg_dsmcc.un_sess.rsrc_data_field_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_type_owner_id, {
            "Type Owner ID", "mpeg_dsmcc.un_sess.rsrc_type_owner_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_type_owner_value, {
            "Type Owner Value", "mpeg_dsmcc.un_sess.rsrc_type_owner_value",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-63 U-N common descriptor header - end */

        /* table 4-64 U-N resource number assignor - start */
        { &hf_dsmcc_un_sess_rsrc_flag_num_assignor, {
            "Resource Num Assignor", "mpeg_dsmcc.un_sess.rsrc_flag_num_assignor",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_number_assignor_vals),
            DMSCC_FLAG_RSRC_NUM_ASSIGNOR, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_flag_num_value, {
            "Resource Num Value", "mpeg_dsmcc.un_sess.rsrc_flag_num_value",
            FT_UINT16, BASE_DEC, NULL, DMSCC_FLAG_RSRC_NUM_VALUE, NULL, HFILL
        } },
        /* table 4-64 U-N resource number assignor - end */

        /* table 4-65 U-N resource association tag assignor - start */
        { &hf_dsmcc_un_sess_rsrc_flag_association_tag_assignor, {
            "Association Tag Assignor", "mpeg_dsmcc.un_sess.rsrc_flag_association_tag_assignor",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_association_tag_vals),
            DMSCC_FLAG_RSRC_ASSOC_TAG_ASSIGNOR, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_flag_association_tag_value, {
            "Association Tag Value", "mpeg_dsmcc.un_sess.rsrc_flag_association_tag_value",
            FT_UINT16, BASE_DEC, NULL, DMSCC_FLAG_RSRC_ASSOC_TAG_VALUE, NULL, HFILL
        } },
        /* table 4-65 U-N resource association tag assignor - end */

        /* table 4-66 U-N resource allocator - start */
       { &hf_dsmcc_un_sess_rsrc_flag_allocator, {
            "Resource Allocator", "mpeg_dsmcc.un_sess.rsrc_flag_allocator",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_allocator_vals),
            DMSCC_FLAG_RSRC_ALLOCATOR, NULL, HFILL
        } },
        /* table 4-66 U-N resource allocator - end */

        /* table 4-67 U-N resource attribute - start */
       { &hf_dsmcc_un_sess_rsrc_flag_attribute, {
            "Resource Attribute", "mpeg_dsmcc.un_sess.rsrc_flag_attribute",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_attribute_vals),
            DMSCC_FLAG_RSRC_ATTRIBUTE, NULL, HFILL
        } },
        /* table 4-67 U-N resource attribute - end */

        /* table 4-68 U-N resource view - start */
       { &hf_dsmcc_un_sess_rsrc_flag_view, {
            "Resource View", "mpeg_dsmcc.un_sess.rsrc_flag_view",
            FT_UINT8, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_view_vals),
            DMSCC_FLAG_RSRC_VIEW, NULL, HFILL
        } },
        /* table 4-68 U-N resource view - end */

        /* table 4-71 U-N dsmccResourceDescriptorValue() field format - start */
        { &hf_dsmcc_un_sess_rsrc_value_type, {
            "Value Type", "mpeg_dsmcc.un_sess.rsrc_value_type",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_value_types_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_value_count, {
            "Value Count", "mpeg_dsmcc.un_sess.rsrc_value_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_value_data, {
            "Value Data", "mpeg_dsmcc.un_sess.rsrc_value_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_most_desired, {
            "Most Desired", "mpeg_dsmcc.un_sess.rsrc_most_desired",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_least_desired, {
            "Least Desired", "mpeg_dsmcc.un_sess.rsrc_least_desired",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-71 U-N dsmccResourceDescriptorValue() field format - end */

        /* table 4-74 U-N Continuous Feed Session resource descriptor - start */
        { &hf_dsmcc_un_sess_rsrc_cfs_num_count, {
            "Resource Num Count", "mpeg_dsmcc.un_sess.rsrc_cfs_num_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_cfs_num, {
            "Resource Number", "mpeg_dsmcc.un_sess.rsrc_cfs_num",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-74 U-N Continuous Feed Session resource descriptor - end  */

        /* table 4-75 U-N ATM Connection resource descriptor - start */
        { &hf_dsmcc_un_sess_rsrc_atm_vpi, {
            "ATM VPI", "mpeg_dsmcc.un_sess.rsrc_atm_vpi",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_atm_vci, {
            "ATM VCI", "mpeg_dsmcc.un_sess.rsrc_atm_vci",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-75 U-N ATM Connection resource descriptor - end  */

        /* table 4-76 MPEG Program - start */
        { &hf_dsmcc_un_sess_rsrc_mpeg_ca_pid, {
            "MPEG CA PID", "mpeg_dsmcc.un_sess.rsrc_mpeg_ca_pid",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_mpeg_elem_stream_count, {
            "Elementary Stream Count", "mpeg_dsmcc.un_sess.rsrc_mpeg_elem_stream_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_reserved, {
            "Reserved", "mpeg_dsmcc.un_sess.rsrc_reserved",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-76 MPEG Program - end */

         /* table 4-77 Physical Channel - start */
        { &hf_dsmcc_un_sess_rsrc_phys_chan_direction, {
            "Channel Direction", "mpeg_dsmcc.un_sess.rsrc_phys_chan_direction",
            FT_UINT16, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_phys_chan_direction_vals), 0, NULL, HFILL
        } },
        /* table 4-77 Physical Channel - end */

        /* table 4-84 IP  - start */
        { &hf_dsmcc_un_sess_rsrc_src_ip_addr, {
            "Source IP Address", "mpeg_dsmcc.un_sess.rsrc_src_ip_addr",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_src_ip_port, {
            "Source IP Port", "mpeg_dsmcc.un_sess.rsrc_src_ip_port",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_dst_ip_addr, {
            "Destination IP Address", "mpeg_dsmcc.un_sess.rsrc_dst_ip_addr",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_dst_ip_port, {
            "Destination IP Port", "mpeg_dsmcc.un_sess.rsrc_dst_ip_port",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_ip_protocol, {
            "IP Protocol", "mpeg_dsmcc.un_sess.rsrc_ip_protocol",
            FT_UINT16, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_ip_protocol_types_vals), 0, NULL, HFILL
        } },
        /* table 4-84 IP  - end */

        /* table 4-86 PSTN Setup - start */
        { &hf_dsmcc_un_sess_rsrc_pstn_calling_id, {
            "Calling ID", "mpeg_dsmcc.un_sess.rsrc_pstn_calling_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_pstn_called_id, {
            "Called ID", "mpeg_dsmcc.un_sess.rsrc_pstn_called_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-86 PSTN Setup - end */

        /* table 4-89 Q.922 Connection - start */
        { &hf_dsmcc_un_sess_rsrc_dlci_count, {
            "DL CI Count", "mpeg_dsmcc.un_sess.rsrc_dlci_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_dlci, {
            "DL CI", "mpeg_dsmcc.un_sess.rsrc_dlci",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_dl_association_tag, {
            "Association Tag", "mpeg_dsmcc.un_sess.rsrc_dl_association_tag",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-89 Q.922 Connection - end */

        /* table 4-90 Shared Resource - start */
        { &hf_dsmcc_un_sess_rsrc_shared_resource_num, {
            "Shared Resource Num", "mpeg_dsmcc.un_sess.rsrc_shared_resource_num",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-90 Shared Resource - end */

        /* table 4-91 Shared Request ID - start */
        { &hf_dsmcc_un_sess_rsrc_shared_resource_request_id, {
            "Shared Request ID", "mpeg_dsmcc.un_sess.rsrc_shared_resource_request_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-91 Shared Request ID - end */

        /* table 4-92 Headend List - start */
        { &hf_dsmcc_un_sess_rsrc_headend_count, {
            "Headend Count", "mpeg_dsmcc.un_sess.rsrc_headend_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_headend_code, {
            "Headend Code", "mpeg_dsmcc.un_sess.rsrc_headend_code",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-92 Headend List - end */

        /* table 4-94 Continuous Feed - start */
        { &hf_dsmcc_un_sess_rsrc_sdb_id, {
            "SDB ID", "mpeg_dsmcc.un_sess.rsrc_sdb_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_sdb_program_count, {
            "Program Count", "mpeg_dsmcc.un_sess.rsrc_sdb_program_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_sdb_association_tag, {
            "Association Tag", "mpeg_dsmcc.un_sess.rsrc_sdb_association_tag",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_sdb_broadcast_program_id, {
            "Broadcast Program ID", "mpeg_dsmcc.un_sess.rsrc_sdb_broadcast_program_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-94 Continuous Feed - end */

        /* table 4-95 SDB Associations - start */
        { &hf_dsmcc_un_sess_rsrc_sdb_control_association_tag, {
            "Control Association Tag", "mpeg_dsmcc.un_sess.rsrc_sdb_control_association_tag",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_sdb_program_association_tag, {
            "Program Association Tag", "mpeg_dsmcc.un_sess.rsrc_sdb_program_association_tag",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-95 SDB Associations - end */

        /* table 4-96 SDB Entitlement - start */
        { &hf_dsmcc_un_sess_rsrc_sdb_exclude_count, {
            "Exclude Count", "mpeg_dsmcc.un_sess.rsrc_sdb_exclude_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_sdb_include_count, {
            "Include Count", "mpeg_dsmcc.un_sess.rsrc_sdb_include_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 4-96 SDB Entitlement - end */

        /* User defined 0xf001-0xf007 - start */
        { &hf_dsmcc_un_sess_rsrc_trans_system, {
            "Transmission System", "mpeg_dsmcc.un_sess.rsrc_trans_system",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_transmission_system_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_inner_coding, {
            "Inner Coding", "mpeg_dsmcc.un_sess.rsrc_inner_coding",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_split_bitstream, {
            "Split Bitstream", "mpeg_dsmcc.un_sess.rsrc_split_bitstream",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_mod_format, {
            "Modulation Format", "mpeg_dsmcc.un_sess.rsrc_mod_format",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_modulation_format_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_symbol_rate, {
            "Symbol Rate", "mpeg_dsmcc.un_sess.rsrc_symbol_rate",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_interleave_depth, {
            "Interleave Depth", "mpeg_dsmcc.un_sess.rsrc_interleave_depth",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_modulation_mode, {
            "Modulation Mode", "mpeg_dsmcc.un_sess.rsrc_modulation_mode",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_mod_mode_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_fec, {
            "Forward Error Correction", "mpeg_dsmcc.un_sess.rsrc_fec",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_fec_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_headend_flag, {
            "Headend Flag", "mpeg_dsmcc.un_sess.rsrc_headend_flag",
            FT_UINT16, BASE_DEC|BASE_RANGE_STRING,
            RVALS(dsmcc_un_sess_rsrc_headend_flag_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_headend_tsid, {
            "Headend TSID", "mpeg_dsmcc.un_sess.rsrc_headend_tsid",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_server_ca_copyprotect, {
            "Copy Protect", "mpeg_dsmcc.un_sess.rsrc_server_ca_copyprotect",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_server_ca_usercount, {
            "User Count", "mpeg_dsmcc.un_sess.rsrc_server_ca_usercount",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_client_ca_info_length, {
            "CA Info Length", "mpeg_dsmcc.un_sess.rsrc_client_ca_info_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_client_ca_info_data, {
            "CA Info Data", "mpeg_dsmcc.un_sess.rsrc_client_ca_info_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_rsrc_service_group, {
            "Service Group", "mpeg_dsmcc.un_sess.rsrc_service_group",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* User defined 0xf001-0xf007 - end */

        /* table 6-1 compatabilityDescriptor - start */
        { &hf_compat_desc_length, {
            "Compatibility Descriptor Length", "mpeg_dsmcc.dii.compat_desc_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_compat_desc_count, {
            "Descriptor Length", "mpeg_dsmcc.dii.compat_desc_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_type, {
            "Descriptor Type", "mpeg_dsmcc.dii.compat.type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_length, {
            "Descriptor Length", "mpeg_dsmcc.dii.compat.length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_spec_type, {
            "Specifier Type", "mpeg_dsmcc.dii.compat.spec_type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_spec_data, {
            "Specifier Data", "mpeg_dsmcc.dii.compat.spec_data",
            FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_model, {
            "Model", "mpeg_dsmcc.dii.compat.model",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_version, {
            "Version", "mpeg_dsmcc.dii.compat.version",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_sub_desc_count, {
            "Version", "mpeg_dsmcc.dii.compat.sub_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_sub_desc_type, {
            "Type", "mpeg_dsmcc.dii.compat.sub_type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_sub_desc_len, {
            "Length", "mpeg_dsmcc.dii.compat.sub_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 6-1 compatabilityDescriptor - end */

        /* table 7-3 dsmccDownloadDataHeader - start */
        { &hf_dsmcc_dd_download_id, {
            "Download ID", "mpeg_dsmcc.download_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dd_message_id, {
            "Message ID", "mpeg_dsmcc.message_id",
            FT_UINT16, BASE_HEX,
            VALS(dsmcc_dd_message_id_vals), 0, NULL, HFILL
        } },
        /* table 7-3 dsmccDownloadDataHeader - end */

        /* table 7-6 downloadInfoIndication - start */
        { &hf_dsmcc_dii_download_id, {
            "Download ID", "mpeg_dsmcc.dii.download_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_block_size, {
            "Block Size", "mpeg_dsmcc.dii.block_size",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_window_size, {
            "Window Size", "mpeg_dsmcc.dii.window_size",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_ack_period, {
            "ACK Period", "mpeg_dsmcc.dii.ack_period",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_t_c_download_window, {
            "Carousel Download Window", "mpeg_dsmcc.dii.carousel_download_window",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_t_c_download_scenario, {
            "Carousel Download Scenario", "mpeg_dsmcc.dii.carousel_download_scenario",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_number_of_modules, {
            "Number of Modules", "mpeg_dsmcc.dii.module_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_module_id, {
            "Module ID", "mpeg_dsmcc.dii.module_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_module_size, {
            "Module Size", "mpeg_dsmcc.dii.module_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_module_version, {
            "Module Version", "mpeg_dsmcc.dii.module_version",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_module_info_length, {
            "Module Info Length", "mpeg_dsmcc.dii.module_info_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_private_data_length, {
            "Private Data Length", "mpeg_dsmcc.dii.private_data_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 7-6 downloadInfoIndication - end */

        /* table 7-7 dsmccDownloadDataBlock - start */
        { &hf_dsmcc_ddb_module_id, {
            "Module ID", "mpeg_dsmcc.ddb.module_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_ddb_version, {
            "Version", "mpeg_dsmcc.ddb.version",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_ddb_reserved, {
            "Reserved", "mpeg_dsmcc.ddb.reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_ddb_block_number, {
            "Block Number", "mpeg_dsmcc.ddb.block_num",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        /* table 7-7 dsmccDownloadDataBlock - end */

        /* table 9-2 - start */
        { &hf_dsmcc_table_id, {
            "Table ID", "mpeg_sect.table_id",
            FT_UINT8, BASE_HEX, VALS(dsmcc_payload_name_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_section_syntax_indicator, {
            "Session Syntax Indicator", "mpeg_sect.ssi",
            FT_UINT16, BASE_DEC, NULL, DSMCC_SSI_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_private_indicator, {
            "Private Indicator", "mpeg_dsmcc.private_indicator",
            FT_UINT16, BASE_DEC, NULL, DSMCC_PRIVATE_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_reserved, {
            "Reserved", "mpeg_sect.reserved",
            FT_UINT16, BASE_HEX, NULL, DSMCC_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_section_length, {
            "Length", "mpeg_sect.section_length",
            FT_UINT16, BASE_DEC, NULL, DSMCC_LENGTH_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_table_id_extension, {
            "Table ID Extension", "mpeg_dsmcc.table_id_extension",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_reserved2, {
            "Reserved", "mpeg_dsmcc.reserved2",
            FT_UINT8, BASE_HEX, NULL, DSMCC_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_version_number, {
            "Version Number", "mpeg_dsmcc.version_number",
            FT_UINT8, BASE_DEC, NULL, DSMCC_VERSION_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_current_next_indicator, {
            "Current Next Indicator", "mpeg_dsmcc.current_next_indicator",
            FT_UINT8, BASE_DEC, NULL, DSMCC_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_section_number, {
            "Section Number", "mpeg_dsmcc.section_number",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_last_section_number, {
            "Last Section Number", "mpeg_dsmcc.last_section_number",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_crc, {
            "CRC 32", "mpeg_sect.crc",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_checksum, {
            "Checksum", "mpeg_dsmcc.checksum",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        /* table 9-2 - end */

        /* table J.3 NSAP - start */
        { &hf_dsmcc_un_sess_nsap_afi, {
            "Authority and Format Identifier (AFI)", "mpeg_dsmcc.un_sess.dsmcc_nsap_afi",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_nsap_idi, {
            "Initial Domain Identifier (IDI)", "mpeg_dsmcc.un_sess.dsmcc_nsap_idi",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_nsap_ho_dsp, {
            "High Order DSP (HO-DSP)", "mpeg_dsmcc.un_sess.dsmcc_nsap_ho_dsp",
            FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_nsap_esi, {
            "End System Identifier (ESI)", "mpeg_dsmcc.un_sess.dsmcc_nsap_esi",
            FT_ETHER, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_nsap_sel, {
            "Selector (SEL)", "mpeg_dsmcc.un_sess.dsmcc_nsap_esi",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table J.3 NSAP - end */

        { &hf_etv_module_abs_path, {
            "Module Absolute Path", "etv.dsmcc.dii.module_abs_path",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_etv_dii_authority, {
            "Authority", "etv.dsmcc.dii.authority",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } }
        /* table J.3 NSAP - end */
    };

    static gint *ett[] = {
        &ett_dsmcc,
        &ett_dsmcc_payload,
        &ett_dsmcc_adaptation_header,
        &ett_dsmcc_header,
        &ett_dsmcc_message_id,
        &ett_dsmcc_transaction_id,
        &ett_dsmcc_heading,
        &ett_dsmcc_rsrc_number,
        &ett_dsmcc_rsrc_association_tag,
        &ett_dsmcc_rsrc_flags,
        &ett_dsmcc_compat,
        &ett_dsmcc_compat_sub_desc,
        &ett_dsmcc_dii_module
    };
    static ei_register_info ei[] = {
        { &ei_dsmcc_invalid_value, { "mpeg_dsmcc.invalid_value", PI_PROTOCOL, PI_WARN,
                    "Invalid value", EXPFILL }},
        { &ei_dsmcc_crc_invalid, { "mpeg_sect.crc.invalid", PI_CHECKSUM, PI_WARN,
                    "Invalid CRC", EXPFILL }},
    };

    module_t *dsmcc_module;
    expert_module_t* expert_dsmcc;

    proto_dsmcc = proto_register_protocol("MPEG DSM-CC", "MPEG DSM-CC", "mpeg_dsmcc");

    proto_register_field_array(proto_dsmcc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_dsmcc = expert_register_protocol(proto_dsmcc);
    expert_register_field_array(expert_dsmcc, ei, array_length(ei));
    register_dissector("mp2t-dsmcc", dissect_dsmcc_ts, proto_dsmcc);

    dsmcc_module = prefs_register_protocol(proto_dsmcc, NULL);

    prefs_register_bool_preference(dsmcc_module, "verify_crc",
        "Verify the section CRC or checksum",
        "Whether the section dissector should verify the CRC or checksum",
        &dsmcc_sect_check_crc);
}


void
proto_reg_handoff_dsmcc(void)
{
    dissector_handle_t dsmcc_ts_handle, dsmcc_tcp_handle, dsmcc_udp_handle;

    dsmcc_ts_handle = create_dissector_handle(dissect_dsmcc_ts, proto_dsmcc);
    dsmcc_tcp_handle = create_dissector_handle(dissect_dsmcc_tcp, proto_dsmcc);
    dsmcc_udp_handle = create_dissector_handle(dissect_dsmcc_udp, proto_dsmcc);

    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_LLCSNAP, dsmcc_ts_handle);
    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_UN_MSG, dsmcc_ts_handle);
    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_DD_MSG, dsmcc_ts_handle);
    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_DESC_LIST, dsmcc_ts_handle);
    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_PRIVATE, dsmcc_ts_handle);

    dissector_add_uint_with_preference("tcp.port", DSMCC_TCP_PORT, dsmcc_tcp_handle);
    dissector_add_uint_with_preference("udp.port", DSMCC_UDP_PORT, dsmcc_udp_handle);
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
