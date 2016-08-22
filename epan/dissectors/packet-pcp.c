/* packet-pcp.c
 * Routines for Performace Co-Pilot protocol dissection
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

#include <epan/packet.h>
#include <epan/expert.h>
#include <glib.h>
#include "packet-tcp.h"
#include "packet-ssl-utils.h"

void proto_register_pcp(void);
void proto_reg_handoff_pcp(void);

#define PCP_PORT 44321
#define PMPROXY_PORT 44322
#define PCP_HEADER_LEN 12

#define PM_ERR_NAME -12357

static dissector_handle_t pcp_handle;

static int proto_pcp = -1;
static int hf_pcp_pdu_length = -1;
static int hf_pcp_pdu_type = -1;
static int hf_pcp_pdu_pid = -1;
static int hf_pcp_pdu_error = -1;
static int hf_pcp_pdu_padding = -1;
static int hf_pcp_creds_number_of = -1;
static int hf_pcp_creds_type = -1;
static int hf_pcp_creds_version = -1;
static int hf_pcp_start = -1;
static int hf_pcp_start_status = -1;
static int hf_pcp_start_zero = -1;
static int hf_pcp_start_version = -1;
static int hf_pcp_start_licensed = -1;
static int hf_pcp_features_flags = -1;
static int hf_pcp_features_flags_secure = -1;
static int hf_pcp_features_flags_compress = -1;
static int hf_pcp_features_flags_auth = -1;
static int hf_pcp_features_flags_creds_reqd = -1;
static int hf_pcp_features_flags_secure_ack = -1;
static int hf_pcp_features_flags_no_nss_init = -1;
static int hf_pcp_features_flags_container = -1;
static int hf_pcp_pmns_traverse = -1;
static int hf_pcp_pmns_subtype = -1;
static int hf_pcp_pmns_namelen = -1;
static int hf_pcp_pmns_name = -1;
static int hf_pcp_pmns_names = -1;
static int hf_pcp_pmns_names_nstrbytes = -1;
static int hf_pcp_pmns_names_numstatus = -1;
static int hf_pcp_pmns_names_numnames = -1;
static int hf_pcp_pmns_names_nametree = -1;
static int hf_pcp_pmns_names_nametree_status = -1;
static int hf_pcp_pmns_names_nametree_namelen = -1;
static int hf_pcp_pmns_names_nametree_name = -1;
static int hf_pcp_pmns_ids = -1;
static int hf_pcp_pmns_ids_status = -1;
static int hf_pcp_pmns_ids_numids = -1;
static int hf_pcp_pmns_child = -1;
static int hf_pcp_pmid = -1;
static int hf_pcp_pmid_flag = -1;
static int hf_pcp_pmid_domain = -1;
static int hf_pcp_pmid_cluster = -1;
static int hf_pcp_pmid_item = -1;
static int hf_pcp_pmid_type = -1;
static int hf_pcp_pmid_sem = -1;
static int hf_pcp_pmid_inst = -1;
static int hf_pcp_profile = -1;
static int hf_pcp_ctxnum = -1;
static int hf_pcp_profile_g_state = -1;
static int hf_pcp_profile_numprof = -1;
static int hf_pcp_profile_profile = -1;
static int hf_pcp_profile_profile_state = -1;
static int hf_pcp_profile_profile_numinst = -1;
static int hf_pcp_fetch = -1;
static int hf_pcp_fetch_numpmid = -1;
static int hf_pcp_when = -1;
static int hf_pcp_when_sec = -1;
static int hf_pcp_when_usec = -1;
static int hf_pcp_desc = -1;
static int hf_pcp_desc_req = -1;
static int hf_pcp_units = -1;
static int hf_pcp_units_dimspace = -1;
static int hf_pcp_units_dimtime = -1;
static int hf_pcp_units_dimcount = -1;
static int hf_pcp_units_scalespace = -1;
static int hf_pcp_units_scaletime = -1;
static int hf_pcp_units_scalecount = -1;
static int hf_pcp_instance = -1;
static int hf_pcp_instance_req = -1;
static int hf_pcp_instance_namelen = -1;
static int hf_pcp_instance_name = -1;
static int hf_pcp_instance_indom = -1;
static int hf_pcp_instance_valoffset = -1;
static int hf_pcp_instance_vallength = -1;
static int hf_pcp_instance_value_insitu = -1;
static int hf_pcp_instance_value_ptr = -1;
static int hf_pcp_instance_value_int = -1;
static int hf_pcp_instance_value_uint = -1;
static int hf_pcp_instance_value_int64 = -1;
static int hf_pcp_instance_value_uint64 = -1;
static int hf_pcp_instance_value_float = -1;
static int hf_pcp_instance_value_double = -1;
static int hf_pcp_instance_value_aggr = -1;
static int hf_pcp_instances = -1;
static int hf_pcp_instances_numinst = -1;
static int hf_pcp_results = -1;
static int hf_pcp_results_numpmid = -1;
static int hf_pcp_result = -1;
static int hf_pcp_result_numval = -1;
static int hf_pcp_result_valfmt = -1;
static int hf_pcp_text_req = -1;
static int hf_pcp_text_type = -1;
static int hf_pcp_text_type_format = -1;
static int hf_pcp_text_type_ident = -1;
static int hf_pcp_text = -1;
static int hf_pcp_text_ident = -1;
static int hf_pcp_text_buflen = -1;
static int hf_pcp_text_buffer = -1;
static int hf_pcp_user_auth_payload = -1;

static gint ett_pcp = -1;
static gint ett_pcp_pdu_length = -1;
static gint ett_pcp_pdu_type = -1;
static gint ett_pcp_pdu_pid = -1;
static gint ett_pcp_pdu_error = -1;
static gint ett_pcp_pdu_padding = -1;
static gint ett_pcp_creds_number_of = -1;
static gint ett_pcp_creds_type = -1;
static gint ett_pcp_creds_vala = -1;
static gint ett_pcp_creds_valb = -1;
static gint ett_pcp_creds_valc = -1;
static gint ett_pcp_start = -1;
static gint ett_pcp_start_status = -1;
static gint ett_pcp_start_zero = -1;
static gint ett_pcp_start_version = -1;
static gint ett_pcp_start_licensed = -1;
static gint ett_pcp_start_features = -1;
static gint ett_pcp_pmns_traverse = -1;
static gint ett_pcp_pmns_subtype = -1;
static gint ett_pcp_pmns_namelen = -1;
static gint ett_pcp_pmns_name = -1;
static gint ett_pcp_pmns_names = -1;
static gint ett_pcp_pmns_names_nstrbytes = -1;
static gint ett_pcp_pmns_names_numstatus = -1;
static gint ett_pcp_pmns_names_numnames = -1;
static gint ett_pcp_pmns_names_nametree = -1;
static gint ett_pcp_pmns_names_nametree_status = -1;
static gint ett_pcp_pmns_names_nametree_namelen = -1;
static gint ett_pcp_pmns_names_nametree_name = -1;
static gint ett_pcp_pmns_ids = -1;
static gint ett_pcp_pmns_ids_status = -1;
static gint ett_pcp_pmns_ids_numids = -1;
static gint ett_pcp_pmns_child = -1;
static gint ett_pcp_pmid = -1;
static gint ett_pcp_pmid_flag = -1;
static gint ett_pcp_pmid_domain = -1;
static gint ett_pcp_pmid_cluster = -1;
static gint ett_pcp_pmid_item = -1;
static gint ett_pcp_pmid_type = -1;
static gint ett_pcp_pmid_sem = -1;
static gint ett_pcp_profile = -1;
static gint ett_pcp_ctxnum = -1;
static gint ett_pcp_profile_g_state = -1;
static gint ett_pcp_profile_numprof = -1;
static gint ett_pcp_profile_profile = -1;
static gint ett_pcp_profile_profile_state = -1;
static gint ett_pcp_profile_profile_numinst = -1;
static gint ett_pcp_fetch = -1;
static gint ett_pcp_fetch_numpmid = -1;
static gint ett_pcp_when = -1;
static gint ett_pcp_when_sec = -1;
static gint ett_pcp_when_usec = -1;
static gint ett_pcp_desc_req = -1;
static gint ett_pcp_units = -1;
static gint ett_pcp_units_dimspace = -1;
static gint ett_pcp_units_dimtime = -1;
static gint ett_pcp_units_dimcount = -1;
static gint ett_pcp_units_scalespace = -1;
static gint ett_pcp_units_scaletime = -1;
static gint ett_pcp_units_scalecount = -1;
static gint ett_pcp_instance = -1;
static gint ett_pcp_instance_req = -1;
static gint ett_pcp_instance_namelen = -1;
static gint ett_pcp_instance_name = -1;
static gint ett_pcp_instance_inst = -1;
static gint ett_pcp_instance_indom = -1;
static gint ett_pcp_instance_valoffset = -1;
static gint ett_pcp_instance_vallength = -1;
static gint ett_pcp_instance_value_insitu = -1;
static gint ett_pcp_instance_value_ptr = -1;
static gint ett_pcp_instance_value_int = -1;
static gint ett_pcp_instance_value_uint = -1;
static gint ett_pcp_instance_value_int64 = -1;
static gint ett_pcp_instance_value_uint64 = -1;
static gint ett_pcp_instance_value_float = -1;
static gint ett_pcp_instance_value_double = -1;
static gint ett_pcp_instance_value_aggr = -1;
static gint ett_pcp_instances = -1;
static gint ett_pcp_instances_numinst = -1;
static gint ett_pcp_results = -1;
static gint ett_pcp_results_numpmid = -1;
static gint ett_pcp_result = -1;
static gint ett_pcp_result_numval = -1;
static gint ett_pcp_result_valfmt = -1;
static gint ett_pcp_text_req = -1;
static gint ett_pcp_text_type = -1;
static gint ett_pcp_text_type_format = -1;
static gint ett_pcp_text_type_ident = -1;
static gint ett_pcp_text = -1;
static gint ett_pcp_text_ident = -1;
static gint ett_pcp_text_buflen = -1;
static gint ett_pcp_text_buffer = -1;

static expert_field ei_pcp_type_event_unimplemented = EI_INIT;
static expert_field ei_pcp_type_nosupport_unsupported = EI_INIT;
static expert_field ei_pcp_type_unknown_unknown_value = EI_INIT;
static expert_field ei_pcp_unimplemented_value = EI_INIT;
static expert_field ei_pcp_unimplemented_packet_type = EI_INIT;
static expert_field ei_pcp_ssl_upgrade = EI_INIT;
static expert_field ei_pcp_ssl_upgrade_failed = EI_INIT;

/* Magic numbers */
#define PCP_SECURE_ACK_SUCCESSFUL 0

static const value_string pcp_feature_flags[] = {
#define PCP_PDU_FLAG_SECURE         0x1
      { PCP_PDU_FLAG_SECURE,        "SECURE" },
#define PCP_PDU_FLAG_COMPRESS       0x2
      { PCP_PDU_FLAG_COMPRESS,      "COMPRESS" },
#define PCP_PDU_FLAG_AUTH           0x4
      { PCP_PDU_FLAG_AUTH,          "AUTH"},
#define PCP_PDU_FLAG_CREDS_REQD     0x8
      { PCP_PDU_FLAG_CREDS_REQD,    "CREDS_REQD" },
#define PCP_PDU_FLAG_SECURE_ACK     0x10
      { PCP_PDU_FLAG_SECURE_ACK,    "SECURE_ACK" },
#define PCP_PDU_FLAG_NO_NSS_INIT    0x20
      { PCP_PDU_FLAG_NO_NSS_INIT,   "NO_NSS_INIT" },
#define PCP_PDU_FLAG_CONTAINER      0x40
      { PCP_PDU_FLAG_CONTAINER,     "CONTAINER" },
      { 0, NULL }
};

/* packet types */
static const value_string packettypenames[] = {
#define PCP_PDU_START_OR_ERROR  0x7000
       {PCP_PDU_START_OR_ERROR, "START/ERROR" },
#define PCP_PDU_RESULT          0x7001
       {PCP_PDU_RESULT,         "RESULT" },
#define PCP_PDU_PROFILE         0x7002
       {PCP_PDU_PROFILE,        "PROFILE"},
#define PCP_PDU_FETCH           0x7003
       {PCP_PDU_FETCH,          "FETCH"},
#define PCP_PDU_DESC_REQ        0x7004
       {PCP_PDU_DESC_REQ,       "DESC_REQ"},
#define PCP_PDU_DESC            0x7005
       {PCP_PDU_DESC,           "DESC"},
#define PCP_PDU_INSTANCE_REQ    0x7006
       {PCP_PDU_INSTANCE_REQ,   "INSTANCE_REQ" },
#define PCP_PDU_INSTANCE        0x7007
       {PCP_PDU_INSTANCE,       "INSTANCE" },
#define PCP_PDU_TEXT_REQ        0x7008
       {PCP_PDU_TEXT_REQ,       "TEXT_REQ" },
#define PCP_PDU_TEXT            0x7009
       {PCP_PDU_TEXT,           "TEXT" },
#define PCP_PDU_CONTROL_REQ     0x700a
       {PCP_PDU_CONTROL_REQ,    "CONTROL_REQ" },  /* unimplemented (pmlc/pmlogger only) */
#define PCP_PDU_DATA_X          0x700b
       {PCP_PDU_DATA_X,         "DATA_X" },       /* unimplemented (pmlc/pmlogger only) */
#define PCP_PDU_CREDS           0x700c
       {PCP_PDU_CREDS,          "CREDS" },
#define PCP_PDU_PMNS_IDS        0x700d
       {PCP_PDU_PMNS_IDS,       "PMNS_IDS" },
#define PCP_PDU_PMNS_NAMES      0x700e
       {PCP_PDU_PMNS_NAMES,     "PMNS_NAMES" },
#define PCP_PDU_PMNS_CHILD      0x700f
       {PCP_PDU_PMNS_CHILD,     "PMNS_CHILD" },
#define PCP_PDU_PMNS_TRAVERSE   0x7010 /*also type FINISH as per pcp headers, but I can not see it used */
       {PCP_PDU_PMNS_TRAVERSE,  "PMNS_TRAVERSE" },
#define PCP_PDU_USER_AUTH       0x7011
       {PCP_PDU_USER_AUTH,      "USER_AUTH" },
       { 0, NULL }
};

static const value_string packettypenames_pm_units_space[] = {
    { 0, "PM_SPACE_BYTE" },
    { 1, "PM_SPACE_KBYTE" },
    { 2, "PM_SPACE_MBYTE" },
    { 3, "PM_SPACE_GBYTE" },
    { 4, "PM_SPACE_TBYTE" },
    { 5, "PM_SPACE_PBYTE" },
    { 6, "PM_SPACE_EBYTE" },
    { 0, NULL }
};

static const value_string packettypenames_pm_units_time[] = {
    { 0, "PM_TIME_NSEC" },
    { 1, "PM_TIME_USEC" },
    { 2, "PM_TIME_MSEC" },
    { 3, "PM_TIME_SEC" },
    { 4, "PM_TIME_MIN" },
    { 5, "PM_TIME_HOUR" },
    { 0, NULL }
};

static const value_string packettypenames_pm_types[] = {
    #define PM_TYPE_NOSUPPORT    -1
    {  -1, "PM_TYPE_NOSUPPORT" },
    #define PM_TYPE_32       0
    {   0, "PM_TYPE_32" },
    #define PM_TYPE_U32      1
    {   1, "PM_TYPE_U32" },
    #define PM_TYPE_64       2
    {   2, "PM_TYPE_64" },
    #define PM_TYPE_U64      3
    {   3, "PM_TYPE_U64" },
    #define PM_TYPE_FLOAT    4
    {   4, "PM_TYPE_FLOAT" },
    #define PM_TYPE_DOUBLE   5
    {   5, "PM_TYPE_DOUBLE" },
    #define PM_TYPE_STRING   6
    {   6, "PM_TYPE_STRING" },
    #define PM_TYPE_AGGREGATE 7
    {   7, "PM_TYPE_AGGREGATE" },
    #define PM_TYPE_AGGREGATE_STATIC 8
    {   8, "PM_TYPE_AGGREGATE_STATIC" },
    #define PM_TYPE_EVENT    9
    {   9, "PM_TYPE_EVENT" },
    #define PM_TYPE_UNKNOWN  255
    { 255, "PM_TYPE_UNKNOWN" },
    {   0, NULL }
};

static const value_string packettypenames_pm_types_sem[] = {
    {  1, "PM_SEM_COUNTER" },
    {  3, "PM_SEM_INSTANT" },
    {  4, "PM_SEM_DISCRETE" },
    {  0, NULL }
};

static const value_string packettypenames_text_type_format[] = {
    #define PM_TEXT_ONELINE 1
    { 1, "PM_TEXT_ONELINE" },
    #define PM_TEXT_HELP    2
    { 2, "PM_TEXT_HELP" },
    { 0, NULL }
};

static const value_string packettypenames_text_type_ident[] = {
    #define PM_TEXT_PMID    4
    { 1, "PM_TEXT_PMID" },
    #define PM_TEXT_INDOM   8
    { 2, "PM_TEXT_INDOM" },
    { 0, NULL }
};

static const value_string packettypenames_valfmt[] = {
    #define PM_VAL_INSITU   0
    { 0, "PM_VAL_INSITU" },
    #define PM_VAL_DPTR 1
    { 1, "PM_VAL_DPTR" },
    #define PM_VAL_SPTR 2
    { 2, "PM_VAL_SPTR" },
    { 0, NULL }
};

static const value_string packettypenames_errors[] = {
    { -12345, "PM_ERR_GENERIC" },
    { -12346, "PM_ERR_PMNS" },
    { -12347, "PM_ERR_NOPMNS" },
    { -12348, "PM_ERR_DUPPMNS" },
    { -12349, "PM_ERR_TEXT" },
    { -12350, "PM_ERR_APPVERSION" },
    { -12351, "PM_ERR_VALUE" },
    { -12352, "PM_ERR_LICENSE" },
    { -12353, "PM_ERR_TIMEOUT" },
    { -12354, "PM_ERR_NODATA" },
    { -12355, "PM_ERR_RESET" },
    { -12356, "PM_ERR_FILE" },
    { PM_ERR_NAME, "PM_ERR_NAME" },
    { -12358, "PM_ERR_PMID" },
    { -12359, "PM_ERR_INDOM" },
    { -12360, "PM_ERR_INST" },
    { -12361, "PM_ERR_UNIT" },
    { -12362, "PM_ERR_CONV" },
    { -12363, "PM_ERR_TRUNC" },
    { -12364, "PM_ERR_SIGN" },
    { -12365, "PM_ERR_PROFILE" },
    { -12366, "PM_ERR_IPC" },
    { -12367, "PM_ERR_NOASCII" },
    { -12368, "PM_ERR_EOF" },
    { -12369, "PM_ERR_NOTHOST" },
    { -12370, "PM_ERR_EOL" },
    { -12371, "PM_ERR_MODE" },
    { -12372, "PM_ERR_LABEL" },
    { -12373, "PM_ERR_LOGREC" },
    { -12374, "PM_ERR_NOTARCHIVE" },
    { -12375, "PM_ERR_LOGFILE" },
    { -12376, "PM_ERR_NOCONTEXT" },
    { -12377, "PM_ERR_PROFILESPEC" },
    { -12378, "PM_ERR_PMID_LOG" },
    { -12379, "PM_ERR_INDOM_LOG" },
    { -12380, "PM_ERR_INST_LOG" },
    { -12381, "PM_ERR_NOPROFILE" },
    { -12386, "PM_ERR_NOAGENT" },
    { -12387, "PM_ERR_PERMISSION" },
    { -12388, "PM_ERR_CONNLIMIT" },
    { -12389, "PM_ERR_AGAIN" },
    { -12390, "PM_ERR_ISCONN" },
    { -12391, "PM_ERR_NOTCONN" },
    { -12392, "PM_ERR_NEEDPORT" },
    { -12393, "PM_ERR_WANTACK" },
    { -12394, "PM_ERR_NONLEAF" },
    { -12395, "PM_ERR_OBJSTYLE" },
    { -12396, "PM_ERR_PMCDLICENSE" },
    { -12397, "PM_ERR_TYPE" },
    { -12442, "PM_ERR_CTXBUSY" },
    { -12443, "PM_ERR_TOOSMALL" },
    { -12444, "PM_ERR_TOOBIG" },
    { -13393, "PM_ERR_PMDAREADY" },
    { -13394, "PM_ERR_PMDANOTREADY" },
    { -21344, "PM_ERR_NYI" },
    {      0, NULL }
};

static const value_string packettypenames_creds[]= {
    { 1, "CVERSION" },
    { 2, "CAUTH" },
    { 0, NULL }
};

typedef struct pcp_conv_info_t {
    wmem_array_t *pmid_name_candidates;
    wmem_map_t *pmid_to_name;
    guint32 last_pmns_names_frame;
    guint32 last_processed_pmns_names_frame;
} pcp_conv_info_t;

/* function prototypes */
static pcp_conv_info_t* get_pcp_conversation_info(packet_info *pinfo);
static int is_unvisited_pmns_names_frame(packet_info *pinfo);
static void add_candidate_name_for_pmid_resolution(packet_info *pinfo, tvbuff_t *tvb, int offset, int name_len);
static void mark_this_frame_as_last_pmns_names_frame(packet_info *pinfo);
static inline int has_unprocessed_pmns_names_frame(pcp_conv_info_t *pcp_conv_info);
static void create_pmid_to_name_map_from_candidates(pcp_conv_info_t *pcp_conv_info, tvbuff_t *tvb, int offset, guint32 num_ids);
static void populate_pmids_to_names(packet_info *pinfo, tvbuff_t *tvb, int offset, guint32 num_ids);
static inline int client_to_server(packet_info *pinfo);
static guint8* get_name_from_pmid(guint32 pmid, packet_info *pinfo);
static guint get_pcp_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data);
static const gchar *get_pcp_features_to_string(guint16 feature_flags);
static int dissect_pcp_message_creds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_pmns_traverse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_pmns_names(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_pmns_child(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_pmns_ids(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_profile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_fetch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_desc_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_instance_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_instance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_text_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_message_user_auth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_partial_pmid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_partial_when(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_partial_features(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

/* message length for dissect_tcp */
static guint get_pcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                 int offset, void *data _U_)
{
    /* length is at the very start of the packet, after tcp header */
    return (guint)tvb_get_ntohl(tvb, offset);
}

static void mark_this_frame_as_last_pmns_names_frame(packet_info *pinfo) {
    pcp_conv_info_t *pcp_conv_info;
    pcp_conv_info = get_pcp_conversation_info(pinfo);

    if(pinfo->num > pcp_conv_info->last_pmns_names_frame) {
        pcp_conv_info->last_pmns_names_frame = pinfo->num;
    }
}

static inline int has_unprocessed_pmns_names_frame(pcp_conv_info_t *pcp_conv_info) {
    return pcp_conv_info->last_pmns_names_frame > pcp_conv_info->last_processed_pmns_names_frame;
}

static inline int client_to_server(packet_info *pinfo) {
    return pinfo->destport == PCP_PORT || pinfo->destport == PMPROXY_PORT;
}

static guint8* get_name_from_pmid(guint32 pmid, packet_info *pinfo) {
    guint8 *name;
    wmem_map_t *pmid_to_name;

    pmid_to_name = get_pcp_conversation_info(pinfo)->pmid_to_name;

    name = (guint8*)wmem_map_lookup(pmid_to_name, GINT_TO_POINTER(pmid));
    if(!name) {
        name = (guint8*)wmem_strdup(wmem_packet_scope(), "Metric name unknown");
    }

    return name;
}

static const gchar *get_pcp_features_to_string(guint16 feature_flags)
{
    const value_string *flag_under_test;
    wmem_strbuf_t *string_buffer;
    gsize string_length;

    string_buffer = wmem_strbuf_new(wmem_packet_scope(), "");

    /* Build the comma-separated list of feature flags as a string. EG 'SECURE, COMPRESS, AUTH, ' */
    flag_under_test = &pcp_feature_flags[0];
    while (flag_under_test->value) {
        if (feature_flags & flag_under_test->value) {
            wmem_strbuf_append_printf(string_buffer, "%s, ", flag_under_test->strptr);
        }
        flag_under_test++;
    }

    /* Cleanup the last remaining ', ' from the string */
    string_length = wmem_strbuf_get_len(string_buffer);
    if (string_length > 2) {
        wmem_strbuf_truncate(string_buffer, string_length - 2);
    }

    return wmem_strbuf_get_str(string_buffer);
}

static pcp_conv_info_t* get_pcp_conversation_info(packet_info *pinfo) {
    conversation_t  *conversation;
    pcp_conv_info_t *pcp_conv_info;

    conversation = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                     pinfo->ptype, pinfo->srcport,
                                     pinfo->destport, 0);

    /* Conversation setup is done in the main dissecting routine so it should never be null */
    DISSECTOR_ASSERT(conversation);

    pcp_conv_info = (pcp_conv_info_t *)conversation_get_proto_data(conversation, proto_pcp);

    /* Conversation data is initialized when creating the conversation so should never be null */
    DISSECTOR_ASSERT(pcp_conv_info);

    return pcp_conv_info;
}

static void add_candidate_name_for_pmid_resolution(packet_info *pinfo, tvbuff_t *tvb, int offset, int name_len) {
    pcp_conv_info_t *pcp_conv_info;
    guint8 *name;

    pcp_conv_info = get_pcp_conversation_info(pinfo);

    if(is_unvisited_pmns_names_frame(pinfo)) {
        name = tvb_get_string_enc(wmem_file_scope(), tvb, offset, name_len, ENC_ASCII);
        wmem_array_append_one(pcp_conv_info->pmid_name_candidates, name);
    }
}

static int is_unvisited_pmns_names_frame(packet_info *pinfo) {
    pcp_conv_info_t *pcp_conv_info;

    pcp_conv_info = get_pcp_conversation_info(pinfo);

    return pinfo->num > pcp_conv_info->last_processed_pmns_names_frame && pinfo->num > pcp_conv_info->last_pmns_names_frame;
}

static void populate_pmids_to_names(packet_info *pinfo, tvbuff_t *tvb, int offset, guint32 num_ids) {
    pcp_conv_info_t *pcp_conv_info;
    guint number_of_name_candidates;

    pcp_conv_info = get_pcp_conversation_info(pinfo);
    number_of_name_candidates = wmem_array_get_count(pcp_conv_info->pmid_name_candidates);

    if(number_of_name_candidates == num_ids && has_unprocessed_pmns_names_frame(pcp_conv_info)) {
        create_pmid_to_name_map_from_candidates(pcp_conv_info, tvb, offset, num_ids);
        /* Set this frame to the one that we processed */
        pcp_conv_info->last_processed_pmns_names_frame = pcp_conv_info->last_pmns_names_frame;
    }

    pcp_conv_info->pmid_name_candidates = wmem_array_new(wmem_file_scope(), sizeof(guint8 *));
}

static void create_pmid_to_name_map_from_candidates(pcp_conv_info_t *pcp_conv_info, tvbuff_t *tvb, int offset, guint32 num_ids) {
    guint32 i;

    for(i=0; i<num_ids; i++) {
        guint32 pmid;
        guint8 *pmid_name;

        pmid = tvb_get_ntohl(tvb, offset);
        pmid_name = *(guint8 **)wmem_array_index(pcp_conv_info->pmid_name_candidates, i);

        if(wmem_map_lookup(pcp_conv_info->pmid_to_name, GINT_TO_POINTER(pmid)) == NULL) {
            wmem_map_insert(pcp_conv_info->pmid_to_name, GINT_TO_POINTER(pmid), pmid_name);
        }
        offset += 4;
    }
}

static int dissect_pcp_message_creds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    guint32 creds_length;
    guint32 i;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]",
                    val_to_str(PCP_PDU_CREDS, packettypenames, "Unknown Type:0x%02x"));

    /* first is the number of creds */
    proto_tree_add_item(tree, hf_pcp_creds_number_of, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* store the number of creds so we know how long to interate for */
    creds_length = tvb_get_ntohl(tvb, offset);
    offset += 4;
    /* go through each __pmVersionCred struct */
    for (i = 0; i < creds_length; i++) {
        /* __pmVersionCred.c_type */
        proto_tree_add_item(tree, hf_pcp_creds_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* __pmVersionCred.c_version */
        proto_tree_add_item(tree, hf_pcp_creds_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* __pmVersionCred.c_flags */
        offset = dissect_pcp_partial_features(tvb, pinfo, tree, offset);
    }
    return offset;
}

/* ERROR packet format:
    signed int error
 */
static int dissect_pcp_message_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    gint32  error_num;
    pcp_conv_info_t *pcp_conv_info;

    /* append the type of packet, we can't look this up as it clashes with START */
    col_append_str(pinfo->cinfo, COL_INFO, "[ERROR] ");

    /* add the error item to the tree and column */
    proto_tree_add_item(tree, hf_pcp_pdu_error, tvb, offset, 4, ENC_BIG_ENDIAN);
    error_num = tvb_get_ntohl(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, "error=%s ",
                    val_to_str(error_num, packettypenames_errors, "Unknown Error:%i"));
    offset += 4;

    /* Clean out candidate names if we got an error from a PMNS_NAMES lookup. This will allow subsequent PMNS_NAMES
       lookups to work in the same conversation
     */
    if(error_num == PM_ERR_NAME) {
        pcp_conv_info = get_pcp_conversation_info(pinfo);
        pcp_conv_info->pmid_name_candidates = wmem_array_new(wmem_file_scope(), sizeof(guint8 *));
    }

    return offset;
}

/* START packet format:
    unsigned int    sts,
    struct          __pmPDUInfo
     |
     |> unsigned int    zero : 1 bit
        unsigned int    version : 7 bits
        unsigned int    licensed : 8 bits
        unsigned int    features : 16 bits
*/
static int dissect_pcp_message_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    /* create a start tree tree to hold the information*/
    proto_item *pcp_start_item;
    proto_tree *pcp_start_tree;
    guint32     status;

    pcp_start_item = proto_tree_add_item(tree, hf_pcp_start, tvb, 0, -1, ENC_NA);
    pcp_start_tree = proto_item_add_subtree(pcp_start_item, ett_pcp);

    /* append the type of packet, we can't look this up as it clashes with ERROR */
    col_append_str(pinfo->cinfo, COL_INFO, "[START]");

    /* status */
    status = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(pcp_start_tree, hf_pcp_start_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if(tvb_reported_length_remaining(tvb, offset) == 0){
        /* Most likely we're in a SSL upgrade if this is the end of the start packet */
        if(status == PCP_SECURE_ACK_SUCCESSFUL) {
            expert_add_info(pinfo, tree, &ei_pcp_ssl_upgrade);
            ssl_starttls_ack(find_dissector("ssl"), pinfo, pcp_handle);
        }
        else {
            expert_add_info(pinfo, tree, &ei_pcp_ssl_upgrade_failed);
        }
    }
    else {
        /* zero bit and version bits */
        proto_tree_add_item(pcp_start_tree, hf_pcp_start_zero, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pcp_start_tree, hf_pcp_start_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* licensed */
        proto_tree_add_item(pcp_start_tree, hf_pcp_start_licensed, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* features */
        offset = dissect_pcp_partial_features(tvb, pinfo, pcp_start_tree, offset);
    }
    return offset;
}

/* PMNS_TRAVERSE packet format:
    guint32 subtype
    guint32 namelen
    char name[sizeof(namelen)] + padding
*/
static int dissect_pcp_message_pmns_traverse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_pmns_traverse_item;
    proto_tree *pcp_pmns_traverse_tree;
    guint32     name_len;
    guint32     padding;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]",
                    val_to_str(PCP_PDU_PMNS_TRAVERSE, packettypenames, "Unknown Type:0x%02x"));

    pcp_pmns_traverse_item = proto_tree_add_item(tree, hf_pcp_pmns_traverse, tvb, offset, -1, ENC_NA);
    pcp_pmns_traverse_tree = proto_item_add_subtree(pcp_pmns_traverse_item, ett_pcp);

    /* subtype */
    proto_tree_add_item(pcp_pmns_traverse_tree, hf_pcp_pmns_subtype, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* namelen */
    proto_tree_add_item(pcp_pmns_traverse_tree, hf_pcp_pmns_namelen, tvb, offset, 4, ENC_BIG_ENDIAN);
    name_len = tvb_get_ntohl(tvb, offset); /* get the actual length out so we can use it in the next item */
    offset += 4;
    /* name */
    proto_tree_add_item(pcp_pmns_traverse_tree, hf_pcp_pmns_name, tvb, offset, name_len, ENC_ASCII|ENC_NA);
    offset += name_len; /* increment by whatever the length of the name string was */

    /* "padding" (not really padding, just what is left over in the old buffer) */
    padding = name_len % 4; /* names are padded to the nearest 4 byte boundary */
    if (padding != 0) { /* if there is padding, keep going till the remainder of mod 4 */
        padding = 4 - padding; /* we want the inverse of the remainder */

        proto_tree_add_item(pcp_pmns_traverse_tree, hf_pcp_pdu_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }
    return offset;
}

/* PMNS_NAMES packet format:
    guint32     nstrbytes (number of str bytes)
    guint32     numstatus (0 if no status. Also, if 0, use name_t, otherwise use name_status_t )
    guint32     numnames
    __pmPDU     names (if numstatus = 0, filled with name_t, otherwise name_status_t)
    | |
    | |> -- name_t --
    |    int namelen
    |    char name[sizeof(namelen)]
    |
    |>  -- name_status_t --
        int status
        int namelen
        char name[sizeof(namelen)]
*/
static int dissect_pcp_message_pmns_names(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_pmns_names_item;
    proto_tree *pcp_pmns_names_tree;
    proto_item *pcp_pmns_names_name_item;
    proto_tree *pcp_pmns_names_name_tree;
    guint32     is_pmns_names_status;
    guint32     num_names;
    guint32     name_len;
    guint32     full_name_len;
    guint32     padding;
    guint32     i;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_PMNS_NAMES, packettypenames, "Unknown Type:0x%02x"));

    pcp_pmns_names_item = proto_tree_add_item(tree, hf_pcp_pmns_names, tvb, offset, -1, ENC_NA);
    pcp_pmns_names_tree = proto_item_add_subtree(pcp_pmns_names_item, ett_pcp);

    /* nstrbytes */
    proto_tree_add_item(pcp_pmns_names_tree, hf_pcp_pmns_names_nstrbytes, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* numstatus */
    proto_tree_add_item(pcp_pmns_names_tree, hf_pcp_pmns_names_numstatus, tvb, offset, 4, ENC_BIG_ENDIAN);
    is_pmns_names_status = tvb_get_ntohl(tvb, offset); /* is the status also present in this PDU? */
    offset += 4;

    /* numnames */
    proto_tree_add_item(pcp_pmns_names_tree, hf_pcp_pmns_names_numnames, tvb, offset, 4, ENC_BIG_ENDIAN);
    num_names = tvb_get_ntohl(tvb, offset); /* get the number of names to iterate through */
    offset += 4;

    /* nametrees */
    for (i=0; i < num_names; i++) {
        /* find out the size of the name_t/name_status_t before we create the tree */
        if (is_pmns_names_status) {
            name_len = tvb_get_ntohl(tvb, offset+4);
            full_name_len = name_len + 8;
        } else {
            name_len = tvb_get_ntohl(tvb, offset);
            full_name_len = name_len + 4;
        }
        /* add a new subtree for each name */
        pcp_pmns_names_name_item = proto_tree_add_item(pcp_pmns_names_tree, hf_pcp_pmns_names_nametree,
                                                       tvb, offset, full_name_len, ENC_NA);
        pcp_pmns_names_name_tree = proto_item_add_subtree(pcp_pmns_names_name_item, ett_pcp);

        if (is_pmns_names_status) {
            /* print out the name status and increment if we're supposed to have it */
            proto_tree_add_item(pcp_pmns_names_name_tree, hf_pcp_pmns_names_nametree_status,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        /* namelen */
        proto_tree_add_item(pcp_pmns_names_name_tree, hf_pcp_pmns_names_nametree_namelen,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        /* name */
        if(client_to_server(pinfo)) {
            add_candidate_name_for_pmid_resolution(pinfo, tvb, offset, name_len);
        }
        proto_tree_add_item(pcp_pmns_names_name_tree, hf_pcp_pmns_names_nametree_name,
                            tvb, offset, name_len, ENC_ASCII|ENC_NA);
        offset += name_len;
        /* padding */
        padding = name_len % 4; /* names are padded to the nearest 4 byte boundary */
        if (padding != 0) {
            padding = 4 - padding; /* we want the inverse of the remainder */
            /* if there is padding, keep going till the remainder of mod 8 */
            proto_tree_add_item(pcp_pmns_names_name_tree, hf_pcp_pdu_padding, tvb, offset, padding, ENC_NA);
            offset += padding;
        }
    }
    if(client_to_server(pinfo)) {
        mark_this_frame_as_last_pmns_names_frame(pinfo);
    }
    return offset;
}

/* PMNS_CHILD packet format:
    guint32  subtype
    guint32  namelen
    char name[namelen]
*/
static int dissect_pcp_message_pmns_child(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_pmns_child_item;
    proto_tree *pcp_pmns_child_tree;
    guint32     name_len;

    pcp_pmns_child_item = proto_tree_add_item(tree, hf_pcp_pmns_child, tvb, offset, -1, ENC_NA);
    pcp_pmns_child_tree = proto_item_add_subtree(pcp_pmns_child_item, ett_pcp);

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_PMNS_CHILD, packettypenames, "Unknown Type:0x%02x"));

    /* subtype */
    proto_tree_add_item(pcp_pmns_child_tree, hf_pcp_pmns_subtype, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* namelen */
    proto_tree_add_item(pcp_pmns_child_tree, hf_pcp_pmns_namelen, tvb, offset, 4, ENC_BIG_ENDIAN);
    name_len = tvb_get_ntohl(tvb, offset); /* length of the next value */
    offset += 4;

    /* name */
    proto_tree_add_item(pcp_pmns_child_tree, hf_pcp_pmns_name, tvb, offset, name_len, ENC_ASCII|ENC_NA);
    offset += 4;
    return offset;
}

/* PMNS_IDS packet format
    guint32 status
    guint32 numids
    pmID    idlist[numids] (where pmID = uint32)

*/
static int dissect_pcp_message_pmns_ids(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_pmns_ids_item;
    proto_tree *pcp_pmns_ids_tree;
    guint32     num_ids;
    guint32     i;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]",
                    val_to_str(PCP_PDU_PMNS_IDS, packettypenames, "Unknown Type:0x%02x"));

    pcp_pmns_ids_item = proto_tree_add_item(tree, hf_pcp_pmns_ids, tvb, offset, -1, ENC_NA);
    pcp_pmns_ids_tree = proto_item_add_subtree(pcp_pmns_ids_item, ett_pcp);

    /* status */
    proto_tree_add_item(pcp_pmns_ids_tree, hf_pcp_pmns_ids_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* numids */
    proto_tree_add_item(pcp_pmns_ids_tree, hf_pcp_pmns_ids_numids, tvb, offset, 4, ENC_BIG_ENDIAN);
    num_ids = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* Populate the PMID to name mapping */
    populate_pmids_to_names(pinfo, tvb, offset, num_ids);

    /* pmIDs */
    for (i=0; i<num_ids; i++) {
        /* pmID */
        offset = dissect_pcp_partial_pmid(tvb, pinfo, pcp_pmns_ids_tree, offset);
    }
    return offset;
}

/*  PROFILE packet format
    guint32     ctxnum;
    guint32     g_state;
    guint32     numprof;
    guint32     pad;
    pmProfile   profiles[numprof]
      |
      |> pmInDom indom;
         int     state;
         int     numinst;
         int     pad;
*/
static int dissect_pcp_message_profile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_profile_item;
    proto_tree *pcp_profile_tree;
    proto_item *pcp_profile_profile_item;
    proto_tree *pcp_profile_profile_tree;
    guint32     num_prof;
    guint32     i;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_PROFILE, packettypenames, "Unknown Type:0x%02x"));

    pcp_profile_item = proto_tree_add_item(tree, hf_pcp_profile, tvb, offset, -1, ENC_NA);
    pcp_profile_tree = proto_item_add_subtree(pcp_profile_item, ett_pcp);

    /* ctxnum */
    proto_tree_add_item(pcp_profile_tree, hf_pcp_ctxnum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* g_state */
    proto_tree_add_item(pcp_profile_tree, hf_pcp_profile_g_state, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* numprof */
    proto_tree_add_item(pcp_profile_tree, hf_pcp_profile_numprof, tvb, offset, 4, ENC_BIG_ENDIAN);
    num_prof = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* pad */
    proto_tree_add_item(pcp_profile_tree, hf_pcp_pdu_padding, tvb, offset, 4, ENC_NA);
    offset += 4;

    /* iterate through each profile */
    for (i=0; i<num_prof; i++) {
        /* subtree for each profile */
        pcp_profile_profile_item = proto_tree_add_item(pcp_profile_tree, hf_pcp_profile_profile, tvb, offset, 32, ENC_NA);
        pcp_profile_profile_tree = proto_item_add_subtree(pcp_profile_profile_item, ett_pcp);

        /* indom */
        proto_tree_add_item(pcp_profile_profile_tree, hf_pcp_instance_indom, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* state - include/exclude */
        proto_tree_add_item(pcp_profile_profile_tree, hf_pcp_profile_profile_state, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* numinst - number of instances to follow */
        proto_tree_add_item(pcp_profile_profile_tree, hf_pcp_profile_profile_numinst, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* padding */
        proto_tree_add_item(pcp_profile_tree, hf_pcp_pdu_padding, tvb, offset, 4, ENC_NA);
        offset += 4;
    }
    return offset;
}

/*  FETCH packet format
    guint32         cxtnum
    __pmTimeval     when (unsigned int tv_sec, unsigned int tv_usec)
    guint32         numpmid
    pmID            pmidlist[1-x] (unsigned int)
 */
static int dissect_pcp_message_fetch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_fetch_item;
    proto_tree *pcp_fetch_tree;
    guint32     num_pmid;
    guint32     i;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]",
                    val_to_str(PCP_PDU_FETCH, packettypenames, "Unknown Type:0x%02x"));

    pcp_fetch_item = proto_tree_add_item(tree, hf_pcp_fetch, tvb, offset, -1, ENC_NA);
    pcp_fetch_tree = proto_item_add_subtree(pcp_fetch_item, ett_pcp);

    /* ctxnum */
    proto_tree_add_item(pcp_fetch_tree, hf_pcp_ctxnum, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* when */
    offset = dissect_pcp_partial_when(tvb, pinfo, pcp_fetch_tree, offset);

    /* numpmid */
    proto_tree_add_item(pcp_fetch_tree, hf_pcp_fetch_numpmid, tvb, offset, 4, ENC_BIG_ENDIAN);
    num_pmid = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* pmIDs*/
    for (i=0; i<num_pmid; i++) {
        /* decode partial PMID message */
        offset = dissect_pcp_partial_pmid(tvb, pinfo, pcp_fetch_tree, offset);
    }
    return offset;
}

/* RESULT packet format

    __pmTimeval when (unsigned int tv_sec, unsigned int tv_usec)
    int         numpmid
    _pmPDU      data[1-n] (contains v_list types)
      |
      |> pmID           pmid
         int            numval
         int            valfmt
        __pmValue_PDU   vlist[1-n] (contains pmValue PDUs)
          |
          |> int    inst
             int    offset/value
             (if valfmt == PTR type)
             int8   type
             int24  length
             char   value[length]
*/
static int dissect_pcp_message_result(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_results_item;
    proto_tree *pcp_results_tree;
    proto_item *pcp_result_item;
    proto_tree *pcp_result_tree;
    proto_item *pcp_result_instance_item;
    proto_tree *pcp_result_instance_tree;
    guint32     num_pmid;
    guint32     num_val;
    guint32     offset_start;
    guint32     valfmt_type;
    guint32     value_type;
    guint32     pmvalueblock_offset;
    guint32     pmvalueblock_value_length;
    guint32     i;
    guint32     j;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_RESULT, packettypenames, "Unknown Type:0x%02x"));

    pcp_results_item = proto_tree_add_item(tree, hf_pcp_results, tvb, offset, -1, ENC_NA);
    pcp_results_tree = proto_item_add_subtree(pcp_results_item, ett_pcp);

    /* when */
    offset = dissect_pcp_partial_when(tvb, pinfo, pcp_results_tree, offset);

    /* numpmid */
    proto_tree_add_item(pcp_results_tree, hf_pcp_results_numpmid, tvb, offset, 4, ENC_BIG_ENDIAN);
    num_pmid = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* result */
    for (i=0; i<num_pmid; i++) {
        /* work out how long each result should be - set starting offset */
        offset_start = offset;

        pcp_result_item = proto_tree_add_item(pcp_results_tree, hf_pcp_result, tvb, offset, -1, ENC_NA);
        pcp_result_tree = proto_item_add_subtree(pcp_result_item, ett_pcp);

        /* pmID */
        offset = dissect_pcp_partial_pmid(tvb, pinfo, pcp_result_tree, offset);

        /* numval */
        proto_tree_add_item(pcp_result_tree, hf_pcp_result_numval, tvb, offset, 4, ENC_BIG_ENDIAN);
        num_val = tvb_get_ntohl(tvb, offset);
        offset += 4;

        /* if there are no numvals, then the valfmt isn't sent */
        if (num_val > 0) {

            /* valfmt */
            proto_tree_add_item(pcp_result_tree, hf_pcp_result_valfmt, tvb, offset, 4, ENC_BIG_ENDIAN);
            valfmt_type = tvb_get_ntohl(tvb, offset);
            offset += 4;

            /* instance */
            for (j=0; j<num_val; j++) {
                /* give the subtree name length of inst (int) + offset/va (int) */
                pcp_result_instance_item = proto_tree_add_item(pcp_result_tree, hf_pcp_instance,
                                                               tvb, offset, 8, ENC_NA);
                pcp_result_instance_tree = proto_item_add_subtree(pcp_result_instance_item, ett_pcp);

                /* inst */
                proto_tree_add_item(pcp_result_instance_tree, hf_pcp_pmid_inst, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;

                /* valoffset/value: depending on the format, the next 32 bits is the value _OR_ the offset to where
                   the value is */
                if (valfmt_type == PM_VAL_INSITU) {
                    proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_insitu,
                                        tvb, offset, 4, ENC_BIG_ENDIAN);
                } else {
                    /* offset in the packet to find pmValueBlock */
                    proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_valoffset,
                                        tvb, offset, 4, ENC_BIG_ENDIAN);
                    /* get the offset (not the offset of the count we are at) but where we should look  */
                    pmvalueblock_offset = tvb_get_ntohl(tvb, offset);
                    pmvalueblock_offset = pmvalueblock_offset * 4; /* offset values are in 32bit units */

                    /* type */
                    value_type = tvb_get_guint8(tvb, pmvalueblock_offset);
                    proto_tree_add_item(pcp_result_instance_tree, hf_pcp_pmid_type,
                                        tvb, pmvalueblock_offset, 1, ENC_BIG_ENDIAN);
                    pmvalueblock_offset += 1;

                    /* length */
                    pmvalueblock_value_length = tvb_get_ntoh24(tvb, pmvalueblock_offset);
                    /* can't add a tree item the ususal way as it is outside of the tree */
                    proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_vallength,
                                        tvb, pmvalueblock_offset, 3, ENC_BIG_ENDIAN);
                    pmvalueblock_offset += 3;

                    /* value - note we go up to the pmvalueblock_value_length - 4,
                       as this value includes the previous 4 bytes */
                    switch (value_type) {
                        case PM_TYPE_32:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_int, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_BIG_ENDIAN);
                            break;
                        case PM_TYPE_U32:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_uint, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_BIG_ENDIAN);
                            break;
                        case PM_TYPE_64:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_int64, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_BIG_ENDIAN);
                            break;
                        case PM_TYPE_U64:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_uint64, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_BIG_ENDIAN);
                            break;
                        case PM_TYPE_FLOAT:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_float, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_BIG_ENDIAN);
                            break;
                        case PM_TYPE_DOUBLE:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_double, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_BIG_ENDIAN);
                            break;
                        case PM_TYPE_STRING:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_ptr, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_ASCII|ENC_NA);
                            break;
                        case PM_TYPE_AGGREGATE:
                        case PM_TYPE_AGGREGATE_STATIC:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_aggr, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_NA);
                            break;
                        case PM_TYPE_EVENT:
                            expert_add_info(pinfo, pcp_result_instance_tree, &ei_pcp_type_event_unimplemented);
                            break;
                        case PM_TYPE_NOSUPPORT:
                            expert_add_info(pinfo, pcp_result_instance_tree, &ei_pcp_type_nosupport_unsupported);
                            break;
                        case PM_TYPE_UNKNOWN:
                            expert_add_info(pinfo, pcp_result_instance_tree, &ei_pcp_type_unknown_unknown_value);
                            break;
                        default:
                            expert_add_info(pinfo, pcp_result_instance_tree, &ei_pcp_unimplemented_value);
                            break;
                }
            }
        /* bump the offset after the instance value _or_ the offset into
           the packet (pcp.instance.valoffset) , each being 4 bytes */
        offset += 4;
        }

        }
        /* we now know how long the field is */
        proto_item_set_len(pcp_result_tree, offset-offset_start);

    }
    return offset;
}

/*  DESC_REQ pcaket format
    pmID    pmid (32bit int)
*/
static int dissect_pcp_message_desc_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_desc_req_item;
    proto_tree *pcp_desc_req_tree;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_DESC_REQ, packettypenames, "Unknown Type:0x%02x"));

    /* subtree for packet type */
    pcp_desc_req_item = proto_tree_add_item(tree, hf_pcp_desc_req, tvb, offset, -1, ENC_NA);
    pcp_desc_req_tree = proto_item_add_subtree(pcp_desc_req_item, ett_pcp);

    offset = dissect_pcp_partial_pmid(tvb, pinfo, pcp_desc_req_tree, offset);

    return offset;
}

/* DESC packet format
    pmID        pmid
    int         type (base data type)
    pmInDom     indom
    int         sem (semantics of the value: instant? counter? etc..)
    pmUnits     units
        |
        v
        signed  int     dimSpace : 4
        signed  int     dimTime : 4
        signed  int     dimCount : 4
        unsigned int    scaleSpace : 4
        unsigned int    scaleTime : 4
        signed  int     scaleCount : 4
        unsigned int    pad : 8
*/
static int dissect_pcp_message_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_desc_item;
    proto_tree *pcp_desc_tree;
    proto_item *pcp_desc_units_item;
    proto_tree *pcp_desc_units_tree;
    guint32     bits_offset;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_DESC, packettypenames, "Unknown Type:0x%02x"));

    /* root desc tree */
    pcp_desc_item = proto_tree_add_item(tree, hf_pcp_desc, tvb, offset, 4, ENC_NA);
    pcp_desc_tree = proto_item_add_subtree(pcp_desc_item, ett_pcp);

    /* pmID */
    offset = dissect_pcp_partial_pmid(tvb, pinfo, pcp_desc_tree, offset);

    /* type */
    proto_tree_add_item(pcp_desc_tree, hf_pcp_pmid_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* indom */
    proto_tree_add_item(pcp_desc_tree, hf_pcp_instance_indom, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* sem */
    proto_tree_add_item(pcp_desc_tree, hf_pcp_pmid_sem, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* pmUnits */
    bits_offset = offset*8; /* create the bits offset */
    pcp_desc_units_item = proto_tree_add_item(pcp_desc_tree, hf_pcp_units, tvb, offset, -1, ENC_NA);
    pcp_desc_units_tree = proto_item_add_subtree(pcp_desc_units_item, ett_pcp);

    /* dimspace */
    proto_tree_add_bits_item(pcp_desc_units_tree, hf_pcp_units_dimspace, tvb, bits_offset, 4, ENC_BIG_ENDIAN);
    bits_offset += 4;
    /* dimtime  */
    proto_tree_add_bits_item(pcp_desc_units_tree, hf_pcp_units_dimtime, tvb, bits_offset, 4, ENC_BIG_ENDIAN);
    bits_offset += 4;
    /* dimcount */
    proto_tree_add_bits_item(pcp_desc_units_tree, hf_pcp_units_dimcount, tvb, bits_offset, 4, ENC_BIG_ENDIAN);
    bits_offset += 4;
    /* scalespace */
    proto_tree_add_bits_item(pcp_desc_units_tree, hf_pcp_units_scalespace, tvb, bits_offset, 4, ENC_BIG_ENDIAN);
    bits_offset += 4;
    /* scaletime */
    proto_tree_add_bits_item(pcp_desc_units_tree, hf_pcp_units_scaletime, tvb, bits_offset, 4, ENC_BIG_ENDIAN);
    bits_offset += 4;
    /* scalecount */
    proto_tree_add_bits_item(pcp_desc_units_tree, hf_pcp_units_scalecount, tvb, bits_offset, 4, ENC_BIG_ENDIAN);
    /*bits_offset += 4;*/
    /* padding */
    offset  += 3; /* total offset of pmunits before */
    proto_tree_add_item(pcp_desc_units_tree, hf_pcp_pdu_padding, tvb, offset, 1, ENC_NA);
    offset  += 1;
    /*bits_offset += 8;*/
    return offset;

}

/* INSTANCE_REQ packet format
     pmInDom        indom
     __pmTimeval    when
     int            inst
     int            namelen
     char           name
*/
static int dissect_pcp_message_instance_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_instance_req_item;
    proto_tree *pcp_instance_req_tree;
    guint32     name_len;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_INSTANCE_REQ, packettypenames, "Unknown Type:0x%02x"));

    pcp_instance_req_item = proto_tree_add_item(tree, hf_pcp_instance_req, tvb, offset, -1, ENC_NA);
    pcp_instance_req_tree = proto_item_add_subtree(pcp_instance_req_item, ett_pcp);

    /* indom */
    proto_tree_add_item(pcp_instance_req_tree, hf_pcp_instance_indom, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* when */
    offset = dissect_pcp_partial_when(tvb, pinfo, pcp_instance_req_tree, offset);

    /* inst */
    proto_tree_add_item(pcp_instance_req_tree, hf_pcp_pmid_inst, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* namelen */
    proto_tree_add_item(pcp_instance_req_tree, hf_pcp_instance_namelen, tvb, offset, 4, ENC_BIG_ENDIAN);
    name_len = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* name */
    if (name_len > 0) {
        proto_tree_add_item(pcp_instance_req_tree, hf_pcp_instance_name, tvb, offset, name_len, ENC_ASCII|ENC_NA);
        offset += name_len;
    }
    return offset;
}

/* TEXT_REQ packet format
     int            ident
     int            type
*/
static int dissect_pcp_message_text_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_text_req_item;
    proto_tree *pcp_text_req_tree;
    proto_item *pcp_text_req_type_item;
    proto_tree *pcp_text_req_type_tree;
    guint32     bits_offset;
    guint32     type;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_TEXT_REQ, packettypenames, "Unknown Type:0x%02x"));

    pcp_text_req_item = proto_tree_add_item(tree, hf_pcp_text_req, tvb, offset, -1, ENC_NA);
    pcp_text_req_tree = proto_item_add_subtree(pcp_text_req_item, ett_pcp);

    /* peek at type to decode ident correctly */
    type = tvb_get_ntohl(tvb, offset + 4);

    /* ident */
    if (type & PM_TEXT_PMID) {
        offset = dissect_pcp_partial_pmid(tvb, pinfo, pcp_text_req_tree, offset);
    } else if (type & PM_TEXT_INDOM) {
        proto_tree_add_item(pcp_text_req_tree, hf_pcp_instance_indom, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* type */
    pcp_text_req_type_item = proto_tree_add_item(pcp_text_req_tree, hf_pcp_text_type, tvb, offset, 4, ENC_NA);
    pcp_text_req_type_tree = proto_item_add_subtree(pcp_text_req_type_item, ett_pcp);
    bits_offset = offset * 8 + 28;
    proto_tree_add_bits_item(pcp_text_req_type_tree, hf_pcp_text_type_ident, tvb, bits_offset, 2, ENC_BIG_ENDIAN);
    bits_offset += 2;
    proto_tree_add_bits_item(pcp_text_req_type_tree, hf_pcp_text_type_format, tvb, bits_offset, 2, ENC_BIG_ENDIAN);

    offset += 4;
    return offset;
}

/* TEXT packet format
     int            ident
     int            buflen
     char           buffer
*/
static int dissect_pcp_message_text(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_text_item;
    proto_tree *pcp_text_tree;
    guint32     buflen;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_TEXT, packettypenames, "Unknown Type:0x%02x"));

    pcp_text_item = proto_tree_add_item(tree, hf_pcp_text, tvb, offset, -1, ENC_NA);
    pcp_text_tree = proto_item_add_subtree(pcp_text_item, ett_pcp);

    /* ident */
    proto_tree_add_item(pcp_text_tree, hf_pcp_text_ident, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* buflen */
    buflen = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(pcp_text_tree, hf_pcp_text_buflen, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* buffer */
    proto_tree_add_item(pcp_text_tree, hf_pcp_text_buffer, tvb, offset, buflen, ENC_ASCII|ENC_NA);
    offset += buflen;

    return offset;
}

/* USER_AUTH packet format
     int            ident
     int            buflen
     char           buffer
*/
static int dissect_pcp_message_user_auth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_USER_AUTH, packettypenames, "Unknown Type:0x%02x"));

    proto_tree_add_item(tree, hf_pcp_user_auth_payload, tvb, offset, -1, ENC_NA);

    return tvb_reported_length(tvb);
}

/* INSTANCE packet type
 pmInDom    indom
 int        numinst
 instlist_t instlist[numinst]
    |
    |>  int         inst
        int         namelen
        char        name
 */
static int dissect_pcp_message_instance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    proto_item *pcp_instances_item;
    proto_tree *pcp_instances_tree;
    proto_item *pcp_instance_item;
    proto_tree *pcp_instance_tree;
    guint32     num_inst;
    guint32     i;
    guint32     name_len;
    guint32     padding;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PCP_PDU_INSTANCE, packettypenames, "Unknown Type:0x%02x"));

    pcp_instances_item = proto_tree_add_item(tree, hf_pcp_instances, tvb, offset, -1, ENC_NA);
    pcp_instances_tree = proto_item_add_subtree(pcp_instances_item, ett_pcp);

    /* indom */
    proto_tree_add_item(pcp_instances_tree, hf_pcp_instance_indom, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* numinst */
    proto_tree_add_item(pcp_instances_tree, hf_pcp_instances_numinst, tvb, offset, 4, ENC_BIG_ENDIAN);
    num_inst = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /* instlist */
    for (i=0; i<num_inst; i++) {
        /* get the size of the name first, so we know how much offset to give */
        name_len = tvb_get_ntohl(tvb, offset+4);

        /* give the subtree name length + 2 ints */
        pcp_instance_item = proto_tree_add_item(pcp_instances_tree, hf_pcp_instance, tvb, offset, name_len+8, ENC_NA);
        pcp_instance_tree = proto_item_add_subtree(pcp_instance_item, ett_pcp);

        /* inst */
        proto_tree_add_item(pcp_instance_tree, hf_pcp_pmid_inst, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* namelen */
        proto_tree_add_item(pcp_instance_tree, hf_pcp_instance_namelen, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* name */
        if (name_len > 0) {
            proto_tree_add_item(pcp_instance_tree, hf_pcp_instance_name, tvb, offset, name_len, ENC_ASCII|ENC_NA);
            offset += name_len;
        }

        /* padding */
        padding = name_len % 4; /* names are padded to the nearest 4 byte boundary */
        if (padding != 0) { /* if there is padding, keep going till the remainder of mod 4 */
            padding = 4 - padding; /* we want the inverse of the remainder */

            proto_tree_add_item(pcp_instance_tree, hf_pcp_pdu_padding, tvb, offset, padding, ENC_NA);
            offset += padding;
        }
    }
    return offset;
}

/* PARTIAL DISSECTOR ROUTINES
   these routines are called by dissect_pcp_message_* as needed
*/

static int dissect_pcp_partial_pmid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_item *pcp_pmid_item;
    proto_tree *pcp_pmid_tree;
    guint32     bits_offset;
    guint32     pmid;
    guint8     *name;

    bits_offset = offset * 8;

    pmid = tvb_get_ntohl(tvb, offset);
    name = get_name_from_pmid(pmid, pinfo);

    /* subtree for pmid */
    pcp_pmid_item = proto_tree_add_item(tree, hf_pcp_pmid, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_item_append_text(pcp_pmid_item, " (%s)", name);
    pcp_pmid_tree = proto_item_add_subtree(pcp_pmid_item, ett_pcp);

    /* flag - 1 bit */
    proto_tree_add_bits_item(pcp_pmid_tree, hf_pcp_pmid_flag, tvb, bits_offset, 1, ENC_BIG_ENDIAN);
    bits_offset += 1;
    /* domain - 9 bits */
    proto_tree_add_bits_item(pcp_pmid_tree, hf_pcp_pmid_domain, tvb, bits_offset, 9, ENC_BIG_ENDIAN);
    bits_offset += 9;
    /* cluster - 12 bits */
    proto_tree_add_bits_item(pcp_pmid_tree, hf_pcp_pmid_cluster, tvb, bits_offset, 12, ENC_BIG_ENDIAN);
    bits_offset += 12;
    /* item - 10 bits */
    proto_tree_add_bits_item(pcp_pmid_tree, hf_pcp_pmid_item, tvb, bits_offset, 10, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int dissect_pcp_partial_when(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    proto_item *pcp_when_item;
    proto_tree *pcp_when_tree;

    /* when - create a new subtree for each val */
    pcp_when_item = proto_tree_add_item(tree, hf_pcp_when, tvb, offset, 8, ENC_NA);
    pcp_when_tree = proto_item_add_subtree(pcp_when_item, ett_pcp);

    /* when tv_sec */
    proto_tree_add_item(pcp_when_tree, hf_pcp_when_sec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* when tv_usec */
    proto_tree_add_item(pcp_when_tree, hf_pcp_when_usec, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static int dissect_pcp_partial_features(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
    guint16     feature_flags;
    const gchar *feature_flags_string;

    static const int * pcp_feature_flags_header_fields[] = {
            &hf_pcp_features_flags_container,
            &hf_pcp_features_flags_no_nss_init,
            &hf_pcp_features_flags_secure_ack,
            &hf_pcp_features_flags_creds_reqd,
            &hf_pcp_features_flags_auth,
            &hf_pcp_features_flags_compress,
            &hf_pcp_features_flags_secure,
            NULL
    };

    feature_flags = tvb_get_ntohs(tvb, offset);
    feature_flags_string = get_pcp_features_to_string(feature_flags);

    col_append_fstr(pinfo->cinfo, COL_INFO, " Features=[%s]", feature_flags_string);

    proto_tree_add_bitmask(tree, tvb, offset, hf_pcp_features_flags, ett_pcp_start_features, pcp_feature_flags_header_fields, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/* MAIN DISSECTING ROUTINE (after passed from dissect_tcp, all non-ssl packets hit function) */
static int dissect_pcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *root_pcp_item;
    proto_tree *pcp_tree;
    conversation_t  *conversation;
    pcp_conv_info_t *pcp_conv_info;
    guint32     packet_type;
    gint32      err_bytes;
    int         offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCP");
    col_clear(pinfo->cinfo, COL_INFO);


    conversation = find_or_create_conversation(pinfo);

    pcp_conv_info = (pcp_conv_info_t*)conversation_get_proto_data(conversation, proto_pcp);

    if(pcp_conv_info == NULL) {
        pcp_conv_info = (pcp_conv_info_t*)g_malloc(sizeof(pcp_conv_info_t));
        conversation_add_proto_data(conversation, proto_pcp, pcp_conv_info);

        pcp_conv_info->pmid_name_candidates = wmem_array_new(wmem_file_scope(), sizeof(guint8 *));
        pcp_conv_info->pmid_to_name = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        pcp_conv_info->last_pmns_names_frame = 0;
        pcp_conv_info->last_processed_pmns_names_frame = 0;
    }

    root_pcp_item = proto_tree_add_item(tree, proto_pcp, tvb, 0, -1, ENC_NA);
    pcp_tree      = proto_item_add_subtree(root_pcp_item, ett_pcp);

    packet_type   = tvb_get_ntohl(tvb, 4);

    /* check if we are the client requesting or the server */
    if (pinfo->srcport == PCP_PORT || pinfo->srcport == PMPROXY_PORT) {
        col_set_str(pinfo->cinfo, COL_INFO, "Server > Client ");
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Client > Server ");
    }

    /* PCP packet length */
    proto_tree_add_item(pcp_tree, hf_pcp_pdu_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* PCP Packet type */
    proto_tree_add_item(pcp_tree, hf_pcp_pdu_type,   tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    /* PCP Remote PID */
    proto_tree_add_item(pcp_tree, hf_pcp_pdu_pid,    tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* dissect the rest of the packet depending on the type */
    switch (packet_type) {
        case PCP_PDU_CREDS:
            dissect_pcp_message_creds(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_START_OR_ERROR:
            err_bytes = tvb_get_ntohl(tvb, offset); /* get the first 4 bytes, determine if this is an error or not */
            /* errors are signed and are all negative so check for a negative number.
               It's the only way we can differentiate between start/error packets */
            if (err_bytes < 0) {
                dissect_pcp_message_error(tvb, pinfo, pcp_tree, offset);
            } else {
                dissect_pcp_message_start(tvb, pinfo, pcp_tree, offset);
            }
            break;

        case PCP_PDU_PMNS_TRAVERSE:
            dissect_pcp_message_pmns_traverse(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_PMNS_NAMES:
            dissect_pcp_message_pmns_names(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_PMNS_CHILD:
            dissect_pcp_message_pmns_child(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_PMNS_IDS:
            dissect_pcp_message_pmns_ids(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_PROFILE:
            dissect_pcp_message_profile(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_FETCH:
            dissect_pcp_message_fetch(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_RESULT:
            dissect_pcp_message_result(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_DESC_REQ:
            dissect_pcp_message_desc_req(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_DESC:
            dissect_pcp_message_desc(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_INSTANCE_REQ:
            dissect_pcp_message_instance_req(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_INSTANCE:
            dissect_pcp_message_instance(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_TEXT_REQ:
            dissect_pcp_message_text_req(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_TEXT:
            dissect_pcp_message_text(tvb, pinfo, pcp_tree, offset);
            break;

        case PCP_PDU_USER_AUTH:
            dissect_pcp_message_user_auth(tvb, pinfo, pcp_tree, offset);
            break;

        default:
            /* append the type of packet */
            col_append_str(pinfo->cinfo, COL_INFO, "[UNIMPLEMENTED TYPE]");
            /* if we got here, then we didn't get a packet type that we know of */
            expert_add_info(pinfo, pcp_tree, &ei_pcp_unimplemented_packet_type);
            break;
    }
    return tvb_captured_length(tvb);
}

static int dissect_pcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    /* pass all packets through TCP-reassembly */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, PCP_HEADER_LEN, get_pcp_message_len, dissect_pcp_message, data);
    return tvb_captured_length(tvb);
}

/* setup the dissecting */
void proto_register_pcp(void)
{
    static hf_register_info hf[] = {
        { &hf_pcp_pdu_length,
          { "PDU Length", "pcp.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pdu_type,
          { "Type", "pcp.type",
            FT_UINT32, BASE_HEX,
            VALS(packettypenames), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pdu_pid,
          { "From", "pcp.from",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pdu_error,
          { "Error", "pcp.error",
            FT_INT32, BASE_DEC,
            VALS(packettypenames_errors), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pdu_padding,
          { "Padding", "pcp.padding",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_creds_number_of,
          { "Number of Credentials", "pcp.creds.number",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_creds_type,
          { "Credentials Type", "pcp.creds.type",
            FT_UINT8, BASE_DEC,
            VALS(packettypenames_creds), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_creds_version,
          { "Credentials Version", "pcp.creds.version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_start,
          { "Start", "pcp.start",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_start_zero,
          { "Start Bit", "pcp.start.zero",
            FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x80,
            NULL, HFILL
          }
        },
        { &hf_pcp_start_version,
          { "Version", "pcp.start.version",
            FT_UINT8, BASE_DEC, /* not a real 8 bit int, only uses 7 bits */
            NULL, 0x7F,
            NULL, HFILL
          }
        },
        { &hf_pcp_start_status,
          { "Start Status", "pcp.start.status",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_start_licensed,
          { "Licensed", "pcp.start.licensed",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_features_flags,
          { "Features", "pcp.features.flags",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_features_flags_secure,
          { "Secure", "pcp.features.flags.secure",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), PCP_PDU_FLAG_SECURE,
            NULL, HFILL
          }
        },
        { &hf_pcp_features_flags_compress,
          { "Compression", "pcp.features.flags.compression",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), PCP_PDU_FLAG_COMPRESS,
            NULL, HFILL
          }
        },
        { &hf_pcp_features_flags_auth,
          { "Authentication", "pcp.features.flags.auth",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), PCP_PDU_FLAG_AUTH,
            NULL, HFILL
          }
        },
        { &hf_pcp_features_flags_creds_reqd,
          { "Credentials Required", "pcp.features.flags.creds_reqd",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), PCP_PDU_FLAG_CREDS_REQD,
            NULL, HFILL
          }
        },
        { &hf_pcp_features_flags_secure_ack,
          { "Secure Acknowledgement", "pcp.features.flags.secure_ack",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), PCP_PDU_FLAG_SECURE_ACK,
            NULL, HFILL
          }
        },
        { &hf_pcp_features_flags_no_nss_init,
          { "No NSS Init", "pcp.features.flags.no_nss_init",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), PCP_PDU_FLAG_NO_NSS_INIT,
            NULL, HFILL
          }
        },
        { &hf_pcp_features_flags_container,
          { "Container", "pcp.features.flags.container",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), PCP_PDU_FLAG_CONTAINER,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_traverse,
          { "PMNS Traverse", "pcp.pmns_traverse",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_subtype,
          { "Subtype", "pcp.pmns.subtype",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_namelen,
          { "Name Length", "pcp.pmns.namelen",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_name,
          { "Name", "pcp.pmns.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_names,
          { "PMNS Names", "pcp.pmns_names",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_names_nstrbytes,
          { "String Bytes", "pcp.pmns_names.nstrbytes",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_names_numstatus,
          { "Status", "pcp.pmns_names.numstatus",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_names_numnames,
          { "Number of Names", "pcp.pmns_names.numnames",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_names_nametree,
          { "Names", "pcp.pmns_names.nametree",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_names_nametree_status,
          { "Status", "pcp.pmns_names.nametree.status",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_names_nametree_namelen,
          { "Length", "pcp.pmns_names.nametree.namelen",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_names_nametree_name,
          { "Name", "pcp.pmns_names.nametree.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_ids,
          { "PMNS IDs", "pcp.pmns_ids",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_ids_status,
          { "Status", "pcp.pmns_ids.status",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_ids_numids,
          { "Number of IDs", "pcp.pmns_ids.numids",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmns_child,
          { "PMID Child", "pcp.pmns.child",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmid,
          { "PMID", "pcp.pmid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmid_flag,
          { "Flag", "pcp.pmid.flag",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmid_domain,
          { "Domain", "pcp.pmid.domain",
            FT_UINT16, BASE_DEC, /* uses 9 bits */
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmid_cluster,
          { "Cluster", "pcp.pmid.cluster",
            FT_UINT16, BASE_DEC, /* uses 12 bits */
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmid_item,
          { "Item", "pcp.pmid.item",
            FT_UINT16, BASE_DEC, /* uses 10 bits */
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmid_type,
          { "Type", "pcp.pmid.type",
            FT_INT8, BASE_DEC,
            VALS(packettypenames_pm_types), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmid_sem,
          { "Type Semantics", "pcp.pmid.sem",
            FT_UINT32, BASE_DEC,
            VALS(packettypenames_pm_types_sem), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_pmid_inst,
          { "Instance", "pcp.pmid.inst",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_profile,
          { "Profile", "pcp.profile",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_ctxnum,
          { "Context Number", "pcp.ctxnum",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_profile_g_state,
          { "Global Include/Exclude State", "pcp.profile.g_state",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_profile_numprof,
          { "Number of Profiles", "pcp.profile.numprof",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_profile_profile,
          { "Each Profile", "pcp.profile.profile",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_profile_profile_state,
          { "Include/Exclude State", "pcp.profile.profile.state",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_profile_profile_numinst,
          { "Number Instances to Follow", "pcp.profile.profile.numinst",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_fetch,
          { "Fetch", "pcp.fetch",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_fetch_numpmid,
          { "Number PMIDs", "pcp.fetch.numpmid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_when,
          { "Time Value", "pcp.when",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_when_sec,
          { "Seconds", "pcp.when.sec",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_when_usec,
          { "Microseconds", "pcp.when.usec",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_desc_req,
          { "Description Request", "pcp.desc_req",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_desc,
          { "Description Response", "pcp.desc",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_units,
          { "PMID Units", "pcp.units",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_units_dimspace,
          { "Dimension Space", "pcp.units.dimspace",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_units_dimtime,
          { "Dimension Time", "pcp.units.dimtime",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_units_dimcount,
          { "Dimension Count", "pcp.units.dimcount",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_units_scalespace,
          { "Scale Space", "pcp.units.scalespace",
            FT_UINT8, BASE_DEC,
            VALS(packettypenames_pm_units_space), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_units_scaletime,
          { "Scale Time", "pcp.units.scalespace",
            FT_UINT8, BASE_DEC,
            VALS(packettypenames_pm_units_time), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_units_scalecount,
          { "Scale Count", "pcp.units.scalecount",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_req,
          { "Instance Request", "pcp.instance_req",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instances,
          { "Instance Response", "pcp.instances",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instances_numinst,
          { "Number of Instances", "pcp.instance_resp.numinst",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance,
          { "Instance", "pcp.instance",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_namelen,
          { "Name Length", "pcp.instance.namelen",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_name,
          { "Name", "pcp.instance.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_indom,
          { "Instance Domain", "pcp.instance.indom",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_valoffset,
          { "Instance Offset", "pcp.instance.valoffset",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_vallength,
          { "Instance Value Length", "pcp.instance.vallength",
            FT_INT24, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_insitu,
          { "Instance Value", "pcp.instance.value.uint",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_ptr,
          { "Instance Value", "pcp.instance.value.string",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_int,
          { "Instance Value", "pcp.instance.value.int",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_uint,
          { "Instance Value", "pcp.instance.value.uint",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_int64,
          { "Instance Value", "pcp.instance.value.int64",
            FT_INT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_uint64,
          { "Instance Value", "pcp.instance.value.uint64",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_float,
          { "Instance Value", "pcp.instance.value.float",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_double,
          { "Instance Value", "pcp.instance.value.float",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_aggr,
          { "Instance Value", "pcp.instance.value.bytes",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_results,
          { "Fetch Results", "pcp.results",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_results_numpmid,
          { "Number of PMIDs", "pcp.results.numpmid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_result,
          { "Result", "pcp.result",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_result_numval,
          { "Number of Values", "pcp.result.numval",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_result_valfmt,
          { "Value Encoding Format", "pcp.result.valfmt",
            FT_UINT32, BASE_DEC,
            VALS(packettypenames_valfmt), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_text_req,
          { "Text Request", "pcp.text_req",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_text_type,
          { "Help Text Type", "pcp.text.type",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_text_type_format,
          { "Text Type Format", "pcp.text.type.format",
            FT_UINT8, BASE_DEC,
            VALS(packettypenames_text_type_format), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_text_type_ident,
          { "Text Type Ident", "pcp.text.type.ident",
            FT_UINT8, BASE_DEC,
            VALS(packettypenames_text_type_ident), 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_text,
          { "Text Response", "pcp.text",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_text_ident,
          { "Text Ident (raw)", "pcp.text.ident",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_text_buflen,
          { "Text Buffer Length", "pcp.text.buflen",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_text_buffer,
          { "Text Buffer", "pcp.text.buffer",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_user_auth_payload,
          { "User Authentication Payload", "pcp.user_auth_payload",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
    };

    static gint *ett[] = {
        &ett_pcp,
        &ett_pcp_pdu_length,
        &ett_pcp_pdu_type,
        &ett_pcp_pdu_pid,
        &ett_pcp_pdu_error,
        &ett_pcp_pdu_padding,
        &ett_pcp_creds_number_of,
        &ett_pcp_creds_type,
        &ett_pcp_creds_vala,
        &ett_pcp_creds_valb,
        &ett_pcp_creds_valc,
        &ett_pcp_start,
        &ett_pcp_start_status,
        &ett_pcp_start_zero,
        &ett_pcp_start_version,
        &ett_pcp_start_licensed,
        &ett_pcp_start_features,
        &ett_pcp_pmns_traverse,
        &ett_pcp_pmns_subtype,
        &ett_pcp_pmns_namelen,
        &ett_pcp_pmns_name,
        &ett_pcp_pmns_names,
        &ett_pcp_pmns_names_nstrbytes,
        &ett_pcp_pmns_names_numstatus,
        &ett_pcp_pmns_names_numnames,
        &ett_pcp_pmns_names_nametree,
        &ett_pcp_pmns_names_nametree_status,
        &ett_pcp_pmns_names_nametree_namelen,
        &ett_pcp_pmns_names_nametree_name,
        &ett_pcp_pmns_ids,
        &ett_pcp_pmns_ids_status,
        &ett_pcp_pmns_ids_numids,
        &ett_pcp_pmns_child,
        &ett_pcp_pmid,
        &ett_pcp_pmid_flag,
        &ett_pcp_pmid_domain,
        &ett_pcp_pmid_cluster,
        &ett_pcp_pmid_item,
        &ett_pcp_pmid_type,
        &ett_pcp_pmid_sem,
        &ett_pcp_profile,
        &ett_pcp_ctxnum,
        &ett_pcp_profile_g_state,
        &ett_pcp_profile_numprof,
        &ett_pcp_profile_profile,
        &ett_pcp_profile_profile_state,
        &ett_pcp_profile_profile_numinst,
        &ett_pcp_fetch,
        &ett_pcp_fetch_numpmid,
        &ett_pcp_when,
        &ett_pcp_when_sec,
        &ett_pcp_when_usec,
        &ett_pcp_desc_req,
        &ett_pcp_units,
        &ett_pcp_units_dimspace,
        &ett_pcp_units_dimtime,
        &ett_pcp_units_dimcount,
        &ett_pcp_units_scalespace,
        &ett_pcp_units_scaletime,
        &ett_pcp_units_scalecount,
        &ett_pcp_instance,
        &ett_pcp_instance_req,
        &ett_pcp_instance_namelen,
        &ett_pcp_instance_name,
        &ett_pcp_instance_indom,
        &ett_pcp_instance_inst,
        &ett_pcp_instance_valoffset,
        &ett_pcp_instance_vallength,
        &ett_pcp_instance_value_insitu,
        &ett_pcp_instance_value_ptr,
        &ett_pcp_instance_value_int,
        &ett_pcp_instance_value_uint,
        &ett_pcp_instance_value_int64,
        &ett_pcp_instance_value_uint64,
        &ett_pcp_instance_value_float,
        &ett_pcp_instance_value_double,
        &ett_pcp_instance_value_aggr,
        &ett_pcp_instances,
        &ett_pcp_instances_numinst,
        &ett_pcp_results,
        &ett_pcp_results_numpmid,
        &ett_pcp_result,
        &ett_pcp_result_numval,
        &ett_pcp_result_valfmt,
        &ett_pcp_text_req,
        &ett_pcp_text_type,
        &ett_pcp_text_type_format,
        &ett_pcp_text_type_ident,
        &ett_pcp_text,
        &ett_pcp_text_ident,
        &ett_pcp_text_buflen,
        &ett_pcp_text_buffer,
    };

    static ei_register_info ei[] = {
        { &ei_pcp_type_event_unimplemented, { "pcp.pmid.type.event.unimplemented", PI_UNDECODED, PI_WARN, "PM_TYPE_EVENT: Unimplemented Value Type", EXPFILL }},
        { &ei_pcp_type_nosupport_unsupported, { "pcp.pmid.type.nosupport.unsupported", PI_UNDECODED, PI_WARN, "PM_TYPE_NOSUPPORT: Unsupported Value Type", EXPFILL }},
        { &ei_pcp_type_unknown_unknown_value, { "pcp.pmid.type.unknown.unknown_value", PI_UNDECODED, PI_WARN, "PM_TYPE_UNKNOWN: Unknown Value Type", EXPFILL }},
        { &ei_pcp_unimplemented_value, { "pcp.pmid.type.unimplemented", PI_UNDECODED, PI_WARN, "Unimplemented Value Type", EXPFILL }},
        { &ei_pcp_unimplemented_packet_type, { "pcp.type.unimplemented", PI_UNDECODED, PI_WARN, "Unimplemented Packet Type", EXPFILL }},
        { &ei_pcp_ssl_upgrade, { "pcp.ssl_upgrade", PI_COMMENTS_GROUP, PI_COMMENT, "SSL upgrade via SECURE_ACK", EXPFILL }},
        { &ei_pcp_ssl_upgrade_failed, { "pcp.ssl_upgrade_failed", PI_RESPONSE_CODE, PI_WARN, "SSL upgrade via SECURE_ACK failed", EXPFILL }},
    };

    expert_module_t* expert_pcp;

    expert_pcp = expert_register_protocol(proto_pcp);
    expert_register_field_array(expert_pcp, ei, array_length(ei));

    proto_pcp = proto_register_protocol("Performance Co-Pilot", "PCP", "pcp");

    proto_register_field_array(proto_pcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pcp_handle = register_dissector("pcp", dissect_pcp, proto_pcp);
}

void proto_reg_handoff_pcp(void)
{
    dissector_add_uint("tcp.port", PCP_PORT, pcp_handle);
}

/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
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
