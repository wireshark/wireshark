/* packet-pcp.c
 * Routines for Performace Co-Pilot protocol dissection
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
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-tcp.h"

#define PCP_PORT 44321
#define PCP_HEADER_LEN 12


static int proto_pcp = -1;
static int hf_pcp_pdu_length = -1;
static int hf_pcp_pdu_type = -1;
static int hf_pcp_pdu_pid = -1;
static int hf_pcp_pdu_error = -1;
static int hf_pcp_pdu_padding = -1;
static int hf_pcp_creds_number_of = -1;
static int hf_pcp_creds_type = -1;
static int hf_pcp_creds_vala = -1;
static int hf_pcp_creds_valb = -1;
static int hf_pcp_creds_valc = -1;
static int hf_pcp_start = -1;
static int hf_pcp_start_status = -1;
static int hf_pcp_start_zero = -1;
static int hf_pcp_start_version = -1;
static int hf_pcp_start_licensed = -1;
static int hf_pcp_start_authorize = -1;
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
static gint ett_pcp_start_authorize = -1;
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

/* packet types */
static const value_string packettypenames[] = {
    #define    START_OR_ERROR 0x7000
    { 0x7000, "START/ERROR" },
    #define    RESULT 0x7001
    { 0x7001, "RESULT" },
    #define    PROFILE 0x7002
    { 0x7002, "PROFILE"},
    #define    FETCH 0x7003
    { 0x7003, "FETCH"},
    #define    DESC_REQ 0x7004
    { 0x7004, "DESC_REQ"},
    #define    DESC 0x7005
    { 0x7005, "DESC"},
    #define    INSTANCE_REQ 0x7006
    { 0x7006, "INSTANCE_REQ" },
    #define    INSTANCE 0x7007
    { 0x7007, "INSTANCE" },
    #define    TEXT_REQ 0x7008
    { 0x7008, "TEXT_REQ" },
    #define    TEXT 0x7009
    { 0x7009, "TEXT" },
    #define    CONTROL_REQ 0x700a
    { 0x700a, "CONTROL_REQ" },  /* unimplemented (pmlc/pmlogger only) */
    #define    DATA_X 0x700b
    { 0x700b, "DATA_X" },       /* unimplemented (pmlc/pmlogger only) */
    #define    CREDS 0x700c
    { 0x700c, "CREDS" },
    #define    PMNS_IDS 0x700d
    { 0x700d, "PMNS_IDS" },
    #define    PMNS_NAMES 0x700e
    { 0x700e, "PMNS_NAMES" },
    #define    PMNS_CHILD 0x700f
    { 0x700f, "PMNS_CHILD" },
    #define    PMNS_TRAVERSE 0x7010 /*also type FINISH as per pcp headers, but I can not see it used */
    { 0x7010, "PMNS_TRAVERSE" },
    {      0, NULL }
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
    { -12357, "PM_ERR_NAME" },
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

/* function prototypes */
static guint get_pcp_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset);
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
static int dissect_pcp_partial_pmid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static int dissect_pcp_partial_when(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);
static void dissect_pcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_pcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* message length for dissect_tcp */
static guint get_pcp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    /* length is at the very start of the packet, after tcp header */
    return (guint)tvb_get_ntohl(tvb, offset);
}

static int dissect_pcp_message_creds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    guint32 creds_length;
    guint32 i;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]",
                    val_to_str(CREDS, packettypenames, "Unknown Type:0x%02x"));

    /* first is the number of creds */
    proto_tree_add_item(tree, hf_pcp_creds_number_of, tvb, offset, 4, ENC_BIG_ENDIAN);
    /* store the number of creds so we know how long to interate for */
    creds_length = tvb_get_ntohl(tvb, offset);
    offset += 4;
    /* go through each __pmCreds struct */
    for (i = 0; i < creds_length; i++) {
        /* __pmCred.c_type */
        proto_tree_add_item(tree, hf_pcp_creds_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* __pmCred.c_vala - Usually the PDU version */
        proto_tree_add_item(tree, hf_pcp_creds_vala, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* __pmCred.c_valb - Unused */
        proto_tree_add_item(tree, hf_pcp_creds_valb, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* __pmCred.c_valc - Unused */
        proto_tree_add_item(tree, hf_pcp_creds_valc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    return offset;
}

/* ERROR packet format:
    signed int error
 */
static int dissect_pcp_message_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    gint32  error_num;

    /* append the type of packet, we can't look this up as it clashes with START */
    col_append_str(pinfo->cinfo, COL_INFO, "[ERROR] ");

    /* add the error item to the tree and column */
    proto_tree_add_item(tree, hf_pcp_pdu_error, tvb, offset, 4, ENC_BIG_ENDIAN);
    error_num = tvb_get_ntohl(tvb, 4);
    col_append_fstr(pinfo->cinfo, COL_INFO, "error=%s ",
                    val_to_str(error_num, packettypenames_errors, "Unknown Error:%i"));
    offset += 4;
    return offset;
}

/* START packet format:
    unsigned int    sts,
    struct          __pmPDUInfo
     |
     |> unsigned int    zero : 1 bit
        unsigned int    version : 7 bits
        unsigned int    licensed : 8 bits
        unsigned int    authorize : 16 bits
*/
static int dissect_pcp_message_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
    /* create a start tree tree to hold the information*/
    proto_item *pcp_start_item;
    proto_tree *pcp_start_tree;
    guint32     bits_offset;

    pcp_start_item = proto_tree_add_item(tree, hf_pcp_start, tvb, 0, -1, ENC_NA);
    pcp_start_tree = proto_item_add_subtree(pcp_start_item, ett_pcp);

    bits_offset = offset*8;

    /* append the type of packet, we can't look this up as it clashes with ERROR */
    col_append_str(pinfo->cinfo, COL_INFO, "[START]");

    /* status */
    proto_tree_add_item(pcp_start_tree, hf_pcp_start_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    bits_offset += 32; /* 4 bytes */
    /* zero bit and version bits */
    proto_tree_add_bits_item(pcp_start_tree, hf_pcp_start_zero, tvb, bits_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(pcp_start_tree, hf_pcp_start_version, tvb, bits_offset+1, 7, ENC_BIG_ENDIAN);
    offset += 1;
    /*bits_offset += 8;*/
    /* licensed */
    proto_tree_add_item(pcp_start_tree, hf_pcp_start_licensed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* authorize */
    proto_tree_add_item(pcp_start_tree, hf_pcp_start_authorize, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
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
                    val_to_str(PMNS_TRAVERSE, packettypenames, "Unknown Type:0x%02x"));

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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PMNS_NAMES, packettypenames, "Unknown Type:0x%02x"));

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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PMNS_CHILD, packettypenames, "Unknown Type:0x%02x"));

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
                    val_to_str(PMNS_IDS, packettypenames, "Unknown Type:0x%02x"));

    pcp_pmns_ids_item = proto_tree_add_item(tree, hf_pcp_pmns_ids, tvb, offset, -1, ENC_NA);
    pcp_pmns_ids_tree = proto_item_add_subtree(pcp_pmns_ids_item, ett_pcp);

    /* status */
    proto_tree_add_item(pcp_pmns_ids_tree, hf_pcp_pmns_ids_status, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* numids */
    proto_tree_add_item(pcp_pmns_ids_tree, hf_pcp_pmns_ids_numids, tvb, offset, 4, ENC_BIG_ENDIAN);
    num_ids = tvb_get_ntohl(tvb, offset);
    offset += 4;

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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(PROFILE, packettypenames, "Unknown Type:0x%02x"));

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
                    val_to_str(FETCH, packettypenames, "Unknown Type:0x%02x"));

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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(RESULT, packettypenames, "Unknown Type:0x%02x"));

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
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_aggr, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_NA);
                        case PM_TYPE_AGGREGATE_STATIC:
                            proto_tree_add_item(pcp_result_instance_tree, hf_pcp_instance_value_aggr, tvb,
                                pmvalueblock_offset, pmvalueblock_value_length-4, ENC_NA);
                            break;
                        case PM_TYPE_EVENT:
                            expert_add_info_format(pinfo, pcp_result_instance_tree, PI_UNDECODED, PI_WARN,
                                                   "PM_TYPE_EVENT: Unimplemented Value Type");
                            break;
                        case PM_TYPE_NOSUPPORT:
                            expert_add_info_format(pinfo, pcp_result_instance_tree, PI_UNDECODED, PI_WARN,
                                                   "PM_TYPE_NOSUPPORT: Unsupported Value Type");
                            break;
                        case PM_TYPE_UNKNOWN:
                            expert_add_info_format(pinfo, pcp_result_instance_tree, PI_UNDECODED,
                                                   PI_WARN, "PM_TYPE_UNKNOWN: Unknown Value Type");
                            break;
                        default:
                            expert_add_info_format(pinfo, pcp_result_instance_tree, PI_UNDECODED, PI_WARN,
                                                   "Unimplemented Value Type");
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
    proto_item *pcp_desc_req_pmid_item;
    proto_tree *pcp_desc_req_pmid_tree;
    guint32     bits_offset;

    /* append the type of packet */
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(DESC_REQ, packettypenames, "Unknown Type:0x%02x"));

    bits_offset = offset*8;
    /* subtree for packet type */
    pcp_desc_req_item = proto_tree_add_item(tree, hf_pcp_desc_req, tvb, offset, -1, ENC_NA);
    pcp_desc_req_tree = proto_item_add_subtree(pcp_desc_req_item, ett_pcp);

    /* subtree for pmid */
    pcp_desc_req_pmid_item = proto_tree_add_item(pcp_desc_req_tree, hf_pcp_pmid, tvb, offset, 4, ENC_BIG_ENDIAN);
    pcp_desc_req_pmid_tree = proto_item_add_subtree(pcp_desc_req_pmid_item, ett_pcp);

    /* flag - 1 bit */
    proto_tree_add_bits_item(pcp_desc_req_pmid_tree, hf_pcp_pmid_flag, tvb, bits_offset, 1, ENC_BIG_ENDIAN);
    bits_offset += 1;
    /* domain - 9 bits */
    proto_tree_add_bits_item(pcp_desc_req_pmid_tree, hf_pcp_pmid_domain, tvb, bits_offset, 9, ENC_BIG_ENDIAN);
    bits_offset += 9;
    /* cluster - 12 bits */
    proto_tree_add_bits_item(pcp_desc_req_pmid_tree, hf_pcp_pmid_cluster, tvb, bits_offset, 12, ENC_BIG_ENDIAN);
    bits_offset += 12;
    /* item - 10 bits */
    proto_tree_add_bits_item(pcp_desc_req_pmid_tree, hf_pcp_pmid_item, tvb, bits_offset, 10, ENC_BIG_ENDIAN);
    /*bits_offset += 10;*/
    offset += 4; /* the bytes offset should now be the same as the bits offset, not that we need this anymore */
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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(DESC, packettypenames, "Unknown Type:0x%02x"));

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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(INSTANCE_REQ, packettypenames, "Unknown Type:0x%02x"));

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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(TEXT_REQ, packettypenames, "Unknown Type:0x%02x"));

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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(TEXT, packettypenames, "Unknown Type:0x%02x"));

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
    col_append_fstr(pinfo->cinfo, COL_INFO, "[%s]", val_to_str(INSTANCE, packettypenames, "Unknown Type:0x%02x"));

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

    bits_offset = offset * 8;

    /* subtree for pmid */
    pcp_pmid_item = proto_tree_add_item(tree, hf_pcp_pmid, tvb, offset, 4, ENC_BIG_ENDIAN);
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

/* MAIN DISSECTING ROUTINE (after passed from dissect_tcp, all packets hit function) */
static void dissect_pcp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *root_pcp_item;
    proto_tree *pcp_tree;
    guint32     packet_type;
    gint32      err_bytes;
    int         offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCP");
    col_clear(pinfo->cinfo, COL_INFO);


    root_pcp_item = proto_tree_add_item(tree, proto_pcp, tvb, 0, -1, ENC_NA);
    pcp_tree      = proto_item_add_subtree(root_pcp_item, ett_pcp);

    packet_type   = tvb_get_ntohl(tvb, 4);

    /* check if we are the client requesting or the server */
    if (pinfo->srcport == PCP_PORT) {
        col_add_str(pinfo->cinfo, COL_INFO, "Server > Client ");
    } else {
        col_add_str(pinfo->cinfo, COL_INFO, "Client > Server ");
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
        case CREDS:
            dissect_pcp_message_creds(tvb, pinfo, pcp_tree, offset);
            break;

        case START_OR_ERROR:
            err_bytes = tvb_get_ntohl(tvb, offset); /* get the first 4 bytes, determine if this is an error or not */
            /* errors are signed and are all negative so check for a negative number.
               It's the only way we can differentiate between start/error packets */
            if (err_bytes < 0) {
                dissect_pcp_message_error(tvb, pinfo, pcp_tree, offset);
            } else {
                dissect_pcp_message_start(tvb, pinfo, pcp_tree, offset);
            }
            break;

        case PMNS_TRAVERSE:
            dissect_pcp_message_pmns_traverse(tvb, pinfo, pcp_tree, offset);
            break;

        case PMNS_NAMES:
            dissect_pcp_message_pmns_names(tvb, pinfo, pcp_tree, offset);
            break;

        case PMNS_CHILD:
            dissect_pcp_message_pmns_child(tvb, pinfo, pcp_tree, offset);
            break;

        case PMNS_IDS:
            dissect_pcp_message_pmns_ids(tvb, pinfo, pcp_tree, offset);
            break;

        case PROFILE:
            dissect_pcp_message_profile(tvb, pinfo, pcp_tree, offset);
            break;

        case FETCH:
            dissect_pcp_message_fetch(tvb, pinfo, pcp_tree, offset);
            break;

        case RESULT:
            dissect_pcp_message_result(tvb, pinfo, pcp_tree, offset);
            break;

        case DESC_REQ:
            dissect_pcp_message_desc_req(tvb, pinfo, pcp_tree, offset);
            break;

        case DESC:
            dissect_pcp_message_desc(tvb, pinfo, pcp_tree, offset);
            break;

        case INSTANCE_REQ:
            dissect_pcp_message_instance_req(tvb, pinfo, pcp_tree, offset);
            break;

        case INSTANCE:
            dissect_pcp_message_instance(tvb, pinfo, pcp_tree, offset);
            break;

        case TEXT_REQ:
            dissect_pcp_message_text_req(tvb, pinfo, pcp_tree, offset);
            break;

        case TEXT:
            dissect_pcp_message_text(tvb, pinfo, pcp_tree, offset);
            break;

        default:
            /* append the type of packet */
            col_append_str(pinfo->cinfo, COL_INFO, "[UNIMPLEMENTED TYPE]");
            /* if we got here, then we didn't get a packet type that we know of */
            expert_add_info_format(pinfo, pcp_tree, PI_UNDECODED, PI_WARN, "Unimplemented Packet Type");
            break;
    }
}

static void dissect_pcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* pass all packets through TCP-reassembally */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, PCP_HEADER_LEN, get_pcp_message_len, dissect_pcp_message);
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
        { &hf_pcp_creds_vala,
          { "Credentials Value A", "pcp.creds.vala",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_creds_valb,
          { "Credentials Value B", "pcp.creds.valb",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_creds_valc,
          { "Credentials Value C", "pcp.creds.valc",
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
          { "Start Compatibility Bit", "pcp.start.zero",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_start_version,
          { "Version", "pcp.start.version",
            FT_UINT8, BASE_DEC, /* not a real 8 bit int, only uses 7 bits */
            NULL, 0x0,
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
        { &hf_pcp_start_authorize,
          { "Authorize", "pcp.start.authorize",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
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
          { "Instance Value", "pcp.instance.value",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_ptr,
          { "Instance Value", "pcp.instance.value",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_int,
          { "Instance Value", "pcp.instance.value",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_uint,
          { "Instance Value", "pcp.instance.value",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_int64,
          { "Instance Value", "pcp.instance.value",
            FT_INT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_uint64,
          { "Instance Value", "pcp.instance.value",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_float,
          { "Instance Value", "pcp.instance.value",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_double,
          { "Instance Value", "pcp.instance.value",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_pcp_instance_value_aggr,
          { "Instance Value", "pcp.instance.value",
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
        &ett_pcp_start_authorize,
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

    proto_pcp = proto_register_protocol("Performance Co-Pilot", "PCP", "pcp");

    proto_register_field_array(proto_pcp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_pcp(void)
{
    dissector_handle_t pcp_handle;

    pcp_handle = create_dissector_handle(dissect_pcp, proto_pcp);
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
* vi: set shiftwidth=4 tabstop=4 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
