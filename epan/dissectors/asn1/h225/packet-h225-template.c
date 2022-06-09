/* packet-h225.c
 * Routines for h225 packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * To quote the author of the previous H323/H225/H245 dissector:
 *   "This is a complete replacement of the previous limitied dissector
 * that Ronnie was crazy enough to write by hand. It was a lot of time
 * to hack it by hand, but it is incomplete and buggy and it is good when
 * it will go away."
 * Ronnie did a great job and all the VoIP users had made good use of it!
 * Credit to Tomas Kukosa for developing the asn2wrs compiler.
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>

#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/next_tvb.h>
#include <epan/asn1.h>
#include <epan/t35.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/rtd_table.h>
#include "packet-frame.h"
#include "packet-tpkt.h"
#include "packet-per.h"
#include "packet-h225.h"
#include "packet-h235.h"
#include "packet-h245.h"
#include "packet-h323.h"
#include "packet-q931.h"
#include "packet-tls.h"

#define PNAME  "H323-MESSAGES"
#define PSNAME "H.225.0"
#define PFNAME "h225"

#define UDP_PORT_RAS_RANGE "1718-1719"
#define TCP_PORT_CS   1720
#define TLS_PORT_CS   1300

void proto_register_h225(void);
static h225_packet_info* create_h225_packet_info(packet_info *pinfo);
static void ras_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, h225_packet_info *pi);

/* Item of ras request list*/
typedef struct _h225ras_call_t {
  guint32 requestSeqNum;
  e_guid_t guid;
  guint32 req_num;  /* frame number request seen */
  guint32 rsp_num;  /* frame number response seen */
  nstime_t req_time;  /* arrival time of request */
  gboolean responded; /* true, if request has been responded */
  struct _h225ras_call_t *next_call; /* pointer to next ras request with same SequenceNumber and conversation handle */
} h225ras_call_t;


/* Item of ras-request key list*/
typedef struct _h225ras_call_info_key {
  guint reqSeqNum;
  conversation_t *conversation;
} h225ras_call_info_key;

/* Global Memory Chunks for lists and Global hash tables*/

static wmem_map_t *ras_calls[7] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};

/* functions, needed using ras-request and halfcall matching*/
static h225ras_call_t * find_h225ras_call(h225ras_call_info_key *h225ras_call_key ,int category);
static h225ras_call_t * new_h225ras_call(h225ras_call_info_key *h225ras_call_key, packet_info *pinfo, e_guid_t *guid, int category);
static h225ras_call_t * append_h225ras_call(h225ras_call_t *prev_call, packet_info *pinfo, e_guid_t *guid, int category);


static dissector_handle_t h225ras_handle;
static dissector_handle_t data_handle;
/* Subdissector tables */
static dissector_table_t nsp_object_dissector_table;
static dissector_table_t nsp_h221_dissector_table;
static dissector_table_t tp_dissector_table;
static dissector_table_t gef_name_dissector_table;
static dissector_table_t gef_content_dissector_table;


static dissector_handle_t h245_handle=NULL;
static dissector_handle_t h245dg_handle=NULL;
static dissector_handle_t h4501_handle=NULL;

static dissector_handle_t nsp_handle;
static dissector_handle_t tp_handle;

static next_tvb_list_t *h245_list;
static next_tvb_list_t *tp_list;

/* Initialize the protocol and registered fields */
static int h225_tap = -1;
static int proto_h225 = -1;

static int hf_h221Manufacturer = -1;
static int hf_h225_ras_req_frame = -1;
static int hf_h225_ras_rsp_frame = -1;
static int hf_h225_ras_dup = -1;
static int hf_h225_ras_deltatime = -1;
static int hf_h225_debug_dissector_try_string = -1;

#include "packet-h225-hf.c"

/* Initialize the subtree pointers */
static gint ett_h225 = -1;
#include "packet-h225-ett.c"

/* Preferences */
static guint h225_tls_port = TLS_PORT_CS;
static gboolean h225_reassembly = TRUE;
static gboolean h225_h245_in_tree = TRUE;
static gboolean h225_tp_in_tree = TRUE;

/* Global variables */
static guint32 ipv4_address;
static ws_in6_addr ipv6_address;
static ws_in6_addr ipv6_address_zeros = {{0}};
static guint32 ip_port;
static gboolean contains_faststart = FALSE;
static e_guid_t *call_id_guid;

/* NonStandardParameter */
static const char *nsiOID;
static guint32 h221NonStandard;
static guint32 t35CountryCode;
static guint32 t35Extension;
static guint32 manufacturerCode;

/* TunnelledProtocol */
static const char *tpOID;

static const value_string ras_message_category[] = {
  {  0, "Gatekeeper    "},
  {  1, "Registration  "},
  {  2, "UnRegistration"},
  {  3, "Admission     "},
  {  4, "Bandwidth     "},
  {  5, "Disengage     "},
  {  6, "Location      "},
  {  0, NULL }
};

typedef enum _ras_type {
  RAS_REQUEST,
  RAS_CONFIRM,
  RAS_REJECT,
  RAS_OTHER
}ras_type;

typedef enum _ras_category {
  RAS_GATEKEEPER,
  RAS_REGISTRATION,
  RAS_UNREGISTRATION,
  RAS_ADMISSION,
  RAS_BANDWIDTH,
  RAS_DISENGAGE,
  RAS_LOCATION,
  RAS_OTHERS
}ras_category;

#define NUM_RAS_STATS 7

static tap_packet_status
h225rassrt_packet(void *phs, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *phi, tap_flags_t flags _U_)
{
  rtd_data_t* rtd_data = (rtd_data_t*)phs;
  rtd_stat_table* rs = &rtd_data->stat_table;
  const h225_packet_info *pi=(const h225_packet_info *)phi;

  ras_type rasmsg_type = RAS_OTHER;
  ras_category rascategory = RAS_OTHERS;

  if (pi->msg_type != H225_RAS || pi->msg_tag == -1) {
    /* No RAS Message or uninitialized msg_tag -> return */
    return TAP_PACKET_DONT_REDRAW;
  }

  if (pi->msg_tag < 21) {
    /* */
    rascategory = (ras_category)(pi->msg_tag / 3);
    rasmsg_type = (ras_type)(pi->msg_tag % 3);
  }
  else {
    /* No SRT yet (ToDo) */
    return TAP_PACKET_DONT_REDRAW;
  }

  switch(rasmsg_type) {

  case RAS_REQUEST:
    if(pi->is_duplicate){
      rs->time_stats[rascategory].req_dup_num++;
    }
    else {
      rs->time_stats[rascategory].open_req_num++;
    }
    break;

  case RAS_CONFIRM:
    /* no break - delay stats are identical for Confirm and Reject */
  case RAS_REJECT:
    if(pi->is_duplicate){
      /* Duplicate is ignored */
      rs->time_stats[rascategory].rsp_dup_num++;
    }
    else if (!pi->request_available) {
      /* no request was seen, ignore response */
      rs->time_stats[rascategory].disc_rsp_num++;
    }
    else {
      rs->time_stats[rascategory].open_req_num--;
      time_stat_update(&(rs->time_stats[rascategory].rtd[0]),&(pi->delta_time), pinfo);
    }
    break;

  default:
    return TAP_PACKET_DONT_REDRAW;
  }
  return TAP_PACKET_REDRAW;
}

#include "packet-h225-fn.c"

/* Forward declaration we need below */
void proto_reg_handoff_h225(void);

/*
 * Functions needed for Ras-Hash-Table
 */

/* compare 2 keys */
static gint h225ras_call_equal(gconstpointer k1, gconstpointer k2)
{
  const h225ras_call_info_key* key1 = (const h225ras_call_info_key*) k1;
  const h225ras_call_info_key* key2 = (const h225ras_call_info_key*) k2;

  return (key1->reqSeqNum == key2->reqSeqNum &&
          key1->conversation == key2->conversation);
}

/* calculate a hash key */
static guint h225ras_call_hash(gconstpointer k)
{
  const h225ras_call_info_key* key = (const h225ras_call_info_key*) k;

  return key->reqSeqNum + GPOINTER_TO_UINT(key->conversation);
}


h225ras_call_t * find_h225ras_call(h225ras_call_info_key *h225ras_call_key ,int category)
{
  h225ras_call_t *h225ras_call = (h225ras_call_t *)wmem_map_lookup(ras_calls[category], h225ras_call_key);

  return h225ras_call;
}

h225ras_call_t * new_h225ras_call(h225ras_call_info_key *h225ras_call_key, packet_info *pinfo, e_guid_t *guid, int category)
{
  h225ras_call_info_key *new_h225ras_call_key;
  h225ras_call_t *h225ras_call = NULL;


  /* Prepare the value data.
     "req_num" and "rsp_num" are frame numbers;
     frame numbers are 1-origin, so we use 0
     to mean "we don't yet know in which frame
     the reply for this call appears". */
  new_h225ras_call_key = wmem_new(wmem_file_scope(), h225ras_call_info_key);
  new_h225ras_call_key->reqSeqNum = h225ras_call_key->reqSeqNum;
  new_h225ras_call_key->conversation = h225ras_call_key->conversation;
  h225ras_call = wmem_new(wmem_file_scope(), h225ras_call_t);
  h225ras_call->req_num = pinfo->num;
  h225ras_call->rsp_num = 0;
  h225ras_call->requestSeqNum = h225ras_call_key->reqSeqNum;
  h225ras_call->responded = FALSE;
  h225ras_call->next_call = NULL;
  h225ras_call->req_time=pinfo->abs_ts;
  h225ras_call->guid=*guid;
  /* store it */
  wmem_map_insert(ras_calls[category], new_h225ras_call_key, h225ras_call);

  return h225ras_call;
}

h225ras_call_t * append_h225ras_call(h225ras_call_t *prev_call, packet_info *pinfo, e_guid_t *guid, int category _U_)
{
  h225ras_call_t *h225ras_call = NULL;

  /* Prepare the value data.
     "req_num" and "rsp_num" are frame numbers;
     frame numbers are 1-origin, so we use 0
     to mean "we don't yet know in which frame
     the reply for this call appears". */
  h225ras_call = wmem_new(wmem_file_scope(), h225ras_call_t);
  h225ras_call->req_num = pinfo->num;
  h225ras_call->rsp_num = 0;
  h225ras_call->requestSeqNum = prev_call->requestSeqNum;
  h225ras_call->responded = FALSE;
  h225ras_call->next_call = NULL;
  h225ras_call->req_time=pinfo->abs_ts;
  h225ras_call->guid=*guid;

  prev_call->next_call = h225ras_call;
  return h225ras_call;
}

static void
h225_frame_end(void)
{
  /* next_tvb pointers are allocated in packet scope, clear it. */
  h245_list = NULL;
  tp_list = NULL;
}

static int
dissect_h225_H323UserInformation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *it;
  proto_tree *tr;
  int offset = 0;
  h225_packet_info* h225_pi;

  /* Init struct for collecting h225_packet_info */
  h225_pi = create_h225_packet_info(pinfo);
  h225_pi->msg_type = H225_CS;
  p_add_proto_data(pinfo->pool, pinfo, proto_h225, 0, h225_pi);

  register_frame_end_routine(pinfo, h225_frame_end);
  h245_list = next_tvb_list_new(pinfo->pool);
  tp_list = next_tvb_list_new(pinfo->pool);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear(pinfo->cinfo, COL_INFO);

  it=proto_tree_add_protocol_format(tree, proto_h225, tvb, 0, -1, PSNAME" CS");
  tr=proto_item_add_subtree(it, ett_h225);

  offset = dissect_H323_UserInformation_PDU(tvb, pinfo, tr, NULL);

  if (h245_list->count){
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
  }

  next_tvb_call(h245_list, pinfo, tree, h245dg_handle, data_handle);
  next_tvb_call(tp_list, pinfo, tree, NULL, data_handle);

  tap_queue_packet(h225_tap, pinfo, h225_pi);

  return offset;
}
static int
dissect_h225_h225_RasMessage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_){
  proto_item *it;
  proto_tree *tr;
  guint32 offset=0;
  h225_packet_info* h225_pi;

  /* Init struct for collecting h225_packet_info */
  h225_pi = create_h225_packet_info(pinfo);
  h225_pi->msg_type = H225_RAS;
  p_add_proto_data(pinfo->pool, pinfo, proto_h225, 0, h225_pi);

  register_frame_end_routine(pinfo, h225_frame_end);
  h245_list = next_tvb_list_new(pinfo->pool);
  tp_list = next_tvb_list_new(pinfo->pool);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  it=proto_tree_add_protocol_format(tree, proto_h225, tvb, offset, -1, PSNAME" RAS");
  tr=proto_item_add_subtree(it, ett_h225);

  offset = dissect_RasMessage_PDU(tvb, pinfo, tr, NULL);

  ras_call_matching(tvb, pinfo, tr, h225_pi);

  next_tvb_call(h245_list, pinfo, tree, h245dg_handle, data_handle);
  next_tvb_call(tp_list, pinfo, tree, NULL, data_handle);

  tap_queue_packet(h225_tap, pinfo, h225_pi);

  return offset;
}


/* The following values represent the size of their valuestring arrays */

#define RAS_MSG_TYPES (sizeof(h225_RasMessage_vals) / sizeof(value_string))
#define CS_MSG_TYPES (sizeof(T_h323_message_body_vals) / sizeof(value_string))

#define GRJ_REASONS (sizeof(GatekeeperRejectReason_vals) / sizeof(value_string))
#define RRJ_REASONS (sizeof(RegistrationRejectReason_vals) / sizeof(value_string))
#define URQ_REASONS (sizeof(UnregRequestReason_vals) / sizeof(value_string))
#define URJ_REASONS (sizeof(UnregRejectReason_vals) / sizeof(value_string))
#define ARJ_REASONS (sizeof(AdmissionRejectReason_vals) / sizeof(value_string))
#define BRJ_REASONS (sizeof(BandRejectReason_vals) / sizeof(value_string))
#define DRQ_REASONS (sizeof(DisengageReason_vals) / sizeof(value_string))
#define DRJ_REASONS (sizeof(DisengageRejectReason_vals) / sizeof(value_string))
#define LRJ_REASONS (sizeof(LocationRejectReason_vals) / sizeof(value_string))
#define IRQNAK_REASONS (sizeof(InfoRequestNakReason_vals) / sizeof(value_string))
#define REL_CMP_REASONS (sizeof(h225_ReleaseCompleteReason_vals) / sizeof(value_string))
#define FACILITY_REASONS (sizeof(FacilityReason_vals) / sizeof(value_string))

/* TAP STAT INFO */
typedef enum
{
  MESSAGE_TYPE_COLUMN = 0,
  COUNT_COLUMN
} h225_stat_columns;

typedef struct _h225_table_item {
  guint count;     /* Message count */
  guint table_idx; /* stat_table index */
} h225_table_item_t;

static stat_tap_table_item h225_stat_fields[] = {{TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "Message Type or Reason", "%-25s"}, {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Count", "%d"}};

static guint ras_msg_idx[RAS_MSG_TYPES];
static guint cs_msg_idx[CS_MSG_TYPES];

static guint grj_reason_idx[GRJ_REASONS];
static guint rrj_reason_idx[RRJ_REASONS];
static guint urq_reason_idx[URQ_REASONS];
static guint urj_reason_idx[URJ_REASONS];
static guint arj_reason_idx[ARJ_REASONS];
static guint brj_reason_idx[BRJ_REASONS];
static guint drq_reason_idx[DRQ_REASONS];
static guint drj_reason_idx[DRJ_REASONS];
static guint lrj_reason_idx[LRJ_REASONS];
static guint irqnak_reason_idx[IRQNAK_REASONS];
static guint rel_cmp_reason_idx[REL_CMP_REASONS];
static guint facility_reason_idx[FACILITY_REASONS];

static guint other_idx;

static void h225_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "H.225 Messages and Message Reasons";
  int num_fields = sizeof(h225_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table *table;
  int row_idx = 0, msg_idx;
  stat_tap_table_item_type items[sizeof(h225_stat_fields)/sizeof(stat_tap_table_item)];

  table = stat_tap_find_table(new_stat, table_name);
  if (table) {
    if (new_stat->stat_tap_reset_table_cb) {
      new_stat->stat_tap_reset_table_cb(table);
    }
    return;
  }

  memset(items, 0x0, sizeof(items));
  table = stat_tap_init_table(table_name, num_fields, 0, NULL);
  stat_tap_add_table(new_stat, table);

  items[MESSAGE_TYPE_COLUMN].type = TABLE_ITEM_STRING;
  items[COUNT_COLUMN].type = TABLE_ITEM_UINT;
  items[COUNT_COLUMN].value.uint_value = 0;

  /* Add a row for each value type */

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      h225_RasMessage_vals[msg_idx].strptr
      ? h225_RasMessage_vals[msg_idx].strptr
      : "Unknown RAS message";
    ras_msg_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (h225_RasMessage_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      T_h323_message_body_vals[msg_idx].strptr
      ? T_h323_message_body_vals[msg_idx].strptr
      : "Unknown CS message";
    cs_msg_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (T_h323_message_body_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      GatekeeperRejectReason_vals[msg_idx].strptr
      ? GatekeeperRejectReason_vals[msg_idx].strptr
      : "Unknown gatekeeper reject reason";
    grj_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (GatekeeperRejectReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      RegistrationRejectReason_vals[msg_idx].strptr
      ? RegistrationRejectReason_vals[msg_idx].strptr
      : "Unknown registration reject reason";
    rrj_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (RegistrationRejectReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      UnregRequestReason_vals[msg_idx].strptr
      ? UnregRequestReason_vals[msg_idx].strptr
      : "Unknown unregistration request reason";
    urq_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (UnregRequestReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      UnregRejectReason_vals[msg_idx].strptr
      ? UnregRejectReason_vals[msg_idx].strptr
      : "Unknown unregistration reject reason";
    urj_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (UnregRejectReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      AdmissionRejectReason_vals[msg_idx].strptr
      ? AdmissionRejectReason_vals[msg_idx].strptr
      : "Unknown admission reject reason";
    arj_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (AdmissionRejectReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      BandRejectReason_vals[msg_idx].strptr
      ? BandRejectReason_vals[msg_idx].strptr
      : "Unknown band reject reason";
    brj_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (BandRejectReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      DisengageReason_vals[msg_idx].strptr
      ? DisengageReason_vals[msg_idx].strptr
      : "Unknown disengage reason";
    drq_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (DisengageReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      DisengageRejectReason_vals[msg_idx].strptr
      ? DisengageRejectReason_vals[msg_idx].strptr
      : "Unknown disengage reject reason";
    drj_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (DisengageRejectReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      LocationRejectReason_vals[msg_idx].strptr
      ? LocationRejectReason_vals[msg_idx].strptr
      : "Unknown location reject reason";
    lrj_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (LocationRejectReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      InfoRequestNakReason_vals[msg_idx].strptr
      ? InfoRequestNakReason_vals[msg_idx].strptr
      : "Unknown info request nak reason";
    irqnak_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (InfoRequestNakReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      h225_ReleaseCompleteReason_vals[msg_idx].strptr
      ? h225_ReleaseCompleteReason_vals[msg_idx].strptr
      : "Unknown release complete reason";
    rel_cmp_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (h225_ReleaseCompleteReason_vals[msg_idx].strptr);

  msg_idx = 0;
  do
  {
    items[MESSAGE_TYPE_COLUMN].value.string_value =
      FacilityReason_vals[msg_idx].strptr
      ? FacilityReason_vals[msg_idx].strptr
      : "Unknown facility reason";
    facility_reason_idx[msg_idx] = row_idx;

    stat_tap_init_table_row(table, row_idx, num_fields, items);
    row_idx++;
    msg_idx++;
  } while (FacilityReason_vals[msg_idx].strptr);


  items[MESSAGE_TYPE_COLUMN].value.string_value = "Unknown H.225 message";
  stat_tap_init_table_row(table, row_idx, num_fields, items);
  other_idx = row_idx;
}

static tap_packet_status
h225_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *hpi_ptr, tap_flags_t flags _U_)
{
  stat_data_t* stat_data = (stat_data_t*)tapdata;
  const h225_packet_info *hpi = (const h225_packet_info *)hpi_ptr;
  int tag_idx = -1;
  int reason_idx = -1;

  if(hpi->msg_tag < 0) { /* uninitialized */
    return TAP_PACKET_DONT_REDRAW;
  }

  switch (hpi->msg_type) {

  case H225_RAS:
    tag_idx = ras_msg_idx[MIN(hpi->msg_tag, (int)RAS_MSG_TYPES-1)];

    /* Look for reason tag */
    if(hpi->reason < 0) { /* uninitialized */
      break;
    }

    switch(hpi->msg_tag) {

    case 2: /* GRJ */
      reason_idx = grj_reason_idx[MIN(hpi->reason, (int)GRJ_REASONS-1)];
      break;
    case 5: /* RRJ */
      reason_idx = rrj_reason_idx[MIN(hpi->reason, (int)RRJ_REASONS-1)];
      break;
    case 6: /* URQ */
      reason_idx = urq_reason_idx[MIN(hpi->reason, (int)URQ_REASONS-1)];
      break;
    case 8: /* URJ */
      reason_idx = urj_reason_idx[MIN(hpi->reason, (int)URJ_REASONS-1)];
      break;
    case 11: /* ARJ */
      reason_idx = arj_reason_idx[MIN(hpi->reason, (int)ARJ_REASONS-1)];
      break;
    case 14: /* BRJ */
      reason_idx = brj_reason_idx[MIN(hpi->reason, (int)BRJ_REASONS-1)];
      break;
    case 15: /* DRQ */
      reason_idx = drq_reason_idx[MIN(hpi->reason, (int)DRQ_REASONS-1)];
      break;
    case 17: /* DRJ */
      reason_idx = drj_reason_idx[MIN(hpi->reason, (int)DRJ_REASONS-1)];
      break;
    case 20: /* LRJ */
      reason_idx = lrj_reason_idx[MIN(hpi->reason, (int)LRJ_REASONS-1)];
      break;
    case 29: /* IRQ Nak */
      reason_idx = irqnak_reason_idx[MIN(hpi->reason, (int)IRQNAK_REASONS-1)];
      break;
    default:
      /* do nothing */
      break;
    }

    break;

  case H225_CS:
    tag_idx = cs_msg_idx[MIN(hpi->msg_tag, (int)CS_MSG_TYPES-1)];

    /* Look for reason tag */
    if(hpi->reason < 0) { /* uninitialized */
      break;
    }

    switch(hpi->msg_tag) {

    case 5: /* ReleaseComplete */
      reason_idx = rel_cmp_reason_idx[MIN(hpi->reason, (int)REL_CMP_REASONS-1)];
      break;
    case 6: /* Facility */
      reason_idx = facility_reason_idx[MIN(hpi->reason, (int)FACILITY_REASONS-1)];
      break;
    default:
      /* do nothing */
      break;
    }

    break;

  case H225_OTHERS:
  default:
    tag_idx = other_idx;
  }

  if (tag_idx >= 0) {
    stat_tap_table*table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);
    stat_tap_table_item_type* msg_data = stat_tap_get_field_data(table, tag_idx, COUNT_COLUMN);;
    msg_data->value.uint_value++;
    stat_tap_set_field_data(table, tag_idx, COUNT_COLUMN, msg_data);

    if (reason_idx >= 0) {
      msg_data = stat_tap_get_field_data(table, reason_idx, COUNT_COLUMN);;
      msg_data->value.uint_value++;
      stat_tap_set_field_data(table, reason_idx, COUNT_COLUMN, msg_data);
    }

    return TAP_PACKET_REDRAW;
  }
  return TAP_PACKET_DONT_REDRAW;
}

static void
h225_stat_reset(stat_tap_table* table)
{
  guint element;
  stat_tap_table_item_type* item_data;

  for (element = 0; element < table->num_elements; element++)
  {
    item_data = stat_tap_get_field_data(table, element, COUNT_COLUMN);
    item_data->value.uint_value = 0;
    stat_tap_set_field_data(table, element, COUNT_COLUMN, item_data);
  }
}

/*--- proto_register_h225 -------------------------------------------*/
void proto_register_h225(void) {

  /* List of fields */
  static hf_register_info hf[] = {
  { &hf_h221Manufacturer,
    { "H.225 Manufacturer", "h225.Manufacturer", FT_UINT32, BASE_HEX,
    VALS(H221ManufacturerCode_vals), 0, "h225.H.221 Manufacturer", HFILL }},

  { &hf_h225_ras_req_frame,
    { "RAS Request Frame", "h225.ras.reqframe", FT_FRAMENUM, BASE_NONE,
    NULL, 0, NULL, HFILL }},

  { &hf_h225_ras_rsp_frame,
    { "RAS Response Frame", "h225.ras.rspframe", FT_FRAMENUM, BASE_NONE,
    NULL, 0, NULL, HFILL }},

  { &hf_h225_ras_dup,
    { "Duplicate RAS Message", "h225.ras.dup", FT_UINT32, BASE_DEC,
    NULL, 0, NULL, HFILL }},

  { &hf_h225_ras_deltatime,
    { "RAS Service Response Time", "h225.ras.timedelta", FT_RELATIVE_TIME, BASE_NONE,
    NULL, 0, "Timedelta between RAS-Request and RAS-Response", HFILL }},

  { &hf_h225_debug_dissector_try_string,
    { "*** DEBUG dissector_try_string", "h225.debug.dissector_try_string", FT_STRING, BASE_NONE,
    NULL, 0, NULL, HFILL }},

#include "packet-h225-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h225,
#include "packet-h225-ettarr.c"
  };

  static tap_param h225_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui h225_stat_table = {
    REGISTER_STAT_GROUP_TELEPHONY,
    "H.225",
    PFNAME,
    "h225,counter",
    h225_stat_init,
    h225_stat_packet,
    h225_stat_reset,
    NULL,
    NULL,
    sizeof(h225_stat_fields)/sizeof(stat_tap_table_item), h225_stat_fields,
    sizeof(h225_stat_params)/sizeof(tap_param), h225_stat_params,
    NULL,
    0
  };

  module_t *h225_module;
  int i, proto_h225_ras;

  /* Register protocol */
  proto_h225 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Create a "fake" protocol to get proper display strings for SRT dialogs */
  proto_h225_ras = proto_register_protocol("H.225 RAS", "H.225 RAS", "h225_ras");

  /* Register fields and subtrees */
  proto_register_field_array(proto_h225, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  h225_module = prefs_register_protocol(proto_h225, proto_reg_handoff_h225);
  prefs_register_uint_preference(h225_module, "tls.port",
    "H.225 TLS Port",
    "H.225 Server TLS Port",
    10, &h225_tls_port);
  prefs_register_bool_preference(h225_module, "reassembly",
    "Reassemble H.225 messages spanning multiple TCP segments",
    "Whether the H.225 dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &h225_reassembly);
  prefs_register_bool_preference(h225_module, "h245_in_tree",
    "Display tunnelled H.245 inside H.225.0 tree",
    "ON - display tunnelled H.245 inside H.225.0 tree, OFF - display tunnelled H.245 in root tree after H.225.0",
    &h225_h245_in_tree);
  prefs_register_bool_preference(h225_module, "tp_in_tree",
    "Display tunnelled protocols inside H.225.0 tree",
    "ON - display tunnelled protocols inside H.225.0 tree, OFF - display tunnelled protocols in root tree after H.225.0",
    &h225_tp_in_tree);

  register_dissector(PFNAME, dissect_h225_H323UserInformation, proto_h225);
  register_dissector("h323ui",dissect_h225_H323UserInformation, proto_h225);
  h225ras_handle = register_dissector("h225.ras", dissect_h225_h225_RasMessage, proto_h225);

  nsp_object_dissector_table = register_dissector_table("h225.nsp.object", "H.225 NonStandardParameter Object", proto_h225, FT_STRING, BASE_NONE);
  nsp_h221_dissector_table = register_dissector_table("h225.nsp.h221", "H.225 NonStandardParameter h221", proto_h225, FT_UINT32, BASE_HEX);
  tp_dissector_table = register_dissector_table("h225.tp", "H.225 Tunnelled Protocol", proto_h225, FT_STRING, BASE_NONE);
  gef_name_dissector_table = register_dissector_table("h225.gef.name", "H.225 Generic Extensible Framework Name", proto_h225, FT_STRING, BASE_NONE);
  gef_content_dissector_table = register_dissector_table("h225.gef.content", "H.225 Generic Extensible Framework Content", proto_h225, FT_STRING, BASE_NONE);

  for(i=0;i<7;i++) {
    ras_calls[i] = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), h225ras_call_hash, h225ras_call_equal);
  }

  h225_tap = register_tap(PFNAME);

  register_rtd_table(proto_h225_ras, PFNAME, NUM_RAS_STATS, 1, ras_message_category, h225rassrt_packet, NULL);

  register_stat_tap_table_ui(&h225_stat_table);

  oid_add_from_string("Version 1","0.0.8.2250.0.1");
  oid_add_from_string("Version 2","0.0.8.2250.0.2");
  oid_add_from_string("Version 3","0.0.8.2250.0.3");
  oid_add_from_string("Version 4","0.0.8.2250.0.4");
  oid_add_from_string("Version 5","0.0.8.2250.0.5");
  oid_add_from_string("Version 6","0.0.8.2250.0.6");
}


/*--- proto_reg_handoff_h225 ---------------------------------------*/
void
proto_reg_handoff_h225(void)
{
  static gboolean h225_prefs_initialized = FALSE;
  static dissector_handle_t q931_tpkt_handle;
  static guint saved_h225_tls_port;

  if (!h225_prefs_initialized) {
    dissector_add_uint_range_with_preference("udp.port", UDP_PORT_RAS_RANGE, h225ras_handle);

    h245_handle = find_dissector("h245");
    h245dg_handle = find_dissector("h245dg");
    h4501_handle = find_dissector_add_dependency("h4501", proto_h225);
    data_handle = find_dissector("data");
    h225_prefs_initialized = TRUE;
    q931_tpkt_handle = find_dissector("q931.tpkt");
  } else {
    ssl_dissector_delete(saved_h225_tls_port, q931_tpkt_handle);
  }

  saved_h225_tls_port = h225_tls_port;
  ssl_dissector_add(saved_h225_tls_port, q931_tpkt_handle);
}

static h225_packet_info* create_h225_packet_info(packet_info *pinfo)
{
  h225_packet_info* pi = wmem_new0(pinfo->pool, h225_packet_info);

  pi->msg_type = H225_OTHERS;
  pi->cs_type = H225_OTHER;
  pi->msg_tag = -1;
  pi->reason = -1;

  return pi;
}

/*
  The following function contains the routines for RAS request/response matching.
  A RAS response matches with a request, if both messages have the same
  RequestSequenceNumber, belong to the same IP conversation and belong to the same
  RAS "category" (e.g. Admission, Registration).

  We use hashtables to access the lists of RAS calls (request/response pairs).
  We have one hashtable for each RAS category. The hashkeys consist of the
  non-unique 16-bit RequestSequenceNumber and values representing the conversation.

  In big capture files, we might get different requests with identical keys.
  These requests aren't necessarily duplicates. They might be valid new requests.
  At the moment we just use the timedelta between the last valid and the new request
  to decide if the new request is a duplicate or not. There might be better ways.
  Two thresholds are defined below.

  However the decision is made, another problem arises. We can't just add those
  requests to our hashtables. Instead we create lists of RAS calls with identical keys.
  The hashtables for RAS calls contain now pointers to the first RAS call in a list of
  RAS calls with identical keys.
  These lists aren't expected to contain more than 3 items and are usually single item
  lists. So we don't need an expensive but intelligent way to access these lists
  (e.g. hashtables). Just walk through such a list.
*/

#define THRESHOLD_REPEATED_RESPONDED_CALL 300
#define THRESHOLD_REPEATED_NOT_RESPONDED_CALL 1800

static void ras_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, h225_packet_info *pi)
{
  proto_item *hidden_item;
  conversation_t* conversation = NULL;
  h225ras_call_info_key h225ras_call_key;
  h225ras_call_t *h225ras_call = NULL;
  nstime_t delta;
  guint msg_category;

  if(pi->msg_type == H225_RAS && pi->msg_tag < 21) {
    /* make RAS request/response matching only for tags from 0 to 20 for now */

    msg_category = pi->msg_tag / 3;
    if(pi->msg_tag % 3 == 0) {    /* Request Message */
      conversation = find_or_create_conversation(pinfo);

      /* prepare the key data */
      h225ras_call_key.reqSeqNum = pi->requestSeqNum;
      h225ras_call_key.conversation = conversation;

      /* look up the request */
      h225ras_call = find_h225ras_call(&h225ras_call_key ,msg_category);

      if (h225ras_call != NULL) {
        /* We've seen requests with this reqSeqNum, with the same
           source and destination, before - do we have
           *this* request already? */
        /* Walk through list of ras requests with identical keys */
        do {
          if (pinfo->num == h225ras_call->req_num) {
            /* We have seen this request before -> do nothing */
            break;
          }

          /* if end of list is reached, exit loop and decide if request is duplicate or not. */
          if (h225ras_call->next_call == NULL) {
            if ( (pinfo->num > h225ras_call->rsp_num && h225ras_call->rsp_num != 0
               && pinfo->abs_ts.secs > (h225ras_call->req_time.secs + THRESHOLD_REPEATED_RESPONDED_CALL) )
               ||(pinfo->num > h225ras_call->req_num && h225ras_call->rsp_num == 0
               && pinfo->abs_ts.secs > (h225ras_call->req_time.secs + THRESHOLD_REPEATED_NOT_RESPONDED_CALL) ) )
            {
              /* if last request has been responded
                 and this request appears after last response (has bigger frame number)
                 and last request occurred more than 300 seconds ago,
                 or if last request hasn't been responded
                 and this request appears after last request (has bigger frame number)
                 and last request occurred more than 1800 seconds ago,
                 we decide that we have a new request */
              /* Append new ras call to list */
              h225ras_call = append_h225ras_call(h225ras_call, pinfo, &pi->guid, msg_category);
            } else {
              /* No, so it's a duplicate request.
                 Mark it as such. */
              pi->is_duplicate = TRUE;
              hidden_item = proto_tree_add_uint(tree, hf_h225_ras_dup, tvb, 0,0, pi->requestSeqNum);
              proto_item_set_hidden(hidden_item);
            }
            break;
          }
          h225ras_call = h225ras_call->next_call;
        } while (h225ras_call != NULL );
      }
      else {
        h225ras_call = new_h225ras_call(&h225ras_call_key, pinfo, &pi->guid, msg_category);
      }

      /* add link to response frame, if available */
      if(h225ras_call && h225ras_call->rsp_num != 0){
        proto_item *ti =
        proto_tree_add_uint_format(tree, hf_h225_ras_rsp_frame, tvb, 0, 0, h225ras_call->rsp_num,
                                     "The response to this request is in frame %u",
                                     h225ras_call->rsp_num);
        proto_item_set_generated(ti);
      }

    /* end of request message handling*/
    }
    else {          /* Confirm or Reject Message */
      conversation = find_conversation_pinfo(pinfo, 0);
      if (conversation != NULL) {
        /* look only for matching request, if
           matching conversation is available. */
        h225ras_call_key.reqSeqNum = pi->requestSeqNum;
        h225ras_call_key.conversation = conversation;
        h225ras_call = find_h225ras_call(&h225ras_call_key ,msg_category);
        if(h225ras_call) {
          /* find matching ras_call in list of ras calls with identical keys */
          do {
            if (pinfo->num == h225ras_call->rsp_num) {
              /* We have seen this response before -> stop now with matching ras call */
              break;
            }

            /* Break when list end is reached */
            if(h225ras_call->next_call == NULL) {
              break;
            }
            h225ras_call = h225ras_call->next_call;
          } while (h225ras_call != NULL) ;

          if (!h225ras_call) {
            return;
          }

          /* if this is an ACF, ARJ or DCF, DRJ, give guid to tap and make it filterable */
          if (msg_category == 3 || msg_category == 5) {
            pi->guid = h225ras_call->guid;
            hidden_item = proto_tree_add_guid(tree, hf_h225_guid, tvb, 0, GUID_LEN, &pi->guid);
            proto_item_set_hidden(hidden_item);
          }

          if (h225ras_call->rsp_num == 0) {
            /* We have not yet seen a response to that call, so
               this must be the first response; remember its
               frame number. */
            h225ras_call->rsp_num = pinfo->num;
          }
          else {
            /* We have seen a response to this call - but was it
               *this* response? */
            if (h225ras_call->rsp_num != pinfo->num) {
              /* No, so it's a duplicate response.
                 Mark it as such. */
              pi->is_duplicate = TRUE;
              hidden_item = proto_tree_add_uint(tree, hf_h225_ras_dup, tvb, 0,0, pi->requestSeqNum);
              proto_item_set_hidden(hidden_item);
            }
          }

          if(h225ras_call->req_num != 0){
            proto_item *ti;
            h225ras_call->responded = TRUE;
            pi->request_available = TRUE;

            /* Indicate the frame to which this is a reply. */
            ti = proto_tree_add_uint_format(tree, hf_h225_ras_req_frame, tvb, 0, 0, h225ras_call->req_num,
              "This is a response to a request in frame %u", h225ras_call->req_num);
            proto_item_set_generated(ti);

            /* Calculate RAS Service Response Time */
            nstime_delta(&delta, &pinfo->abs_ts, &h225ras_call->req_time);
            pi->delta_time = delta; /* give it to tap */

            /* display Ras Service Response Time and make it filterable */
            ti = proto_tree_add_time(tree, hf_h225_ras_deltatime, tvb, 0, 0, &(pi->delta_time));
            proto_item_set_generated(ti);
          }
        }
      }
    }
  }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
