/* packet-gearman.c
 * Routines for Gearman protocol packet disassembly
 * By Flier Lu <flier.lu@gmail.com>
 * Copyright 2010 Flier Lu
 *
 * Gearman Protocol
 * ----------------
 * http://gearman.org/protocol/
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
#include "packet-tcp.h"

void proto_register_gearman(void);
void proto_reg_handoff_gearman(void);

static dissector_handle_t gearman_handle;

static int proto_gearman;

static int hf_gearman_mgr_cmd;
static int hf_gearman_magic_code;
static int hf_gearman_pkt_type;
static int hf_gearman_data_size;
static int hf_gearman_data_content;
static int hf_gearman_option_name;
static int hf_gearman_func_name;
static int hf_gearman_func_namez;
static int hf_gearman_client_id;
static int hf_gearman_client_count;
static int hf_gearman_uniq_id;
static int hf_gearman_uniq_idz;
static int hf_gearman_argument;
static int hf_gearman_job_handle;
static int hf_gearman_job_handlez;
static int hf_gearman_complete_numerator;
static int hf_gearman_complete_denominator;
static int hf_gearman_submit_job_sched_minute;
static int hf_gearman_submit_job_sched_hour;
static int hf_gearman_submit_job_sched_day_of_month;
static int hf_gearman_submit_job_sched_month;
static int hf_gearman_submit_job_sched_day_of_week;
static int hf_gearman_submit_job_epoch_time;
static int hf_gearman_reducer;
static int hf_gearman_result;
static int hf_gearman_known_status;
static int hf_gearman_running_status;
static int hf_gearman_timeout_value;
static int hf_gearman_echo_text;
static int hf_gearman_err_code;
static int hf_gearman_err_text;

static int ett_gearman;
static int ett_gearman_command;
static int ett_gearman_content;

static expert_field ei_gearman_pkt_type_unknown;

static bool gearman_desegment  = true;

static const int GEARMAN_COMMAND_HEADER_SIZE = 12;
static const int GEARMAN_PORT = 4730;
static const unsigned char *GEARMAN_MAGIC_CODE_REQUEST = "\0REQ";
static const unsigned char *GEARMAN_MAGIC_CODE_RESPONSE = "\0RES";

static const char *GEARMAN_MGR_CMDS[] = {
  "workers",
  "status",
  "maxqueue",
  "shutdown",
  "version"
};

static const int GEARMAN_MGR_CMDS_COUNT = array_length(GEARMAN_MGR_CMDS);

typedef enum
{
  GEARMAN_COMMAND_TEXT,
  GEARMAN_COMMAND_CAN_DO,              /* W->J: FUNC */
  GEARMAN_COMMAND_CANT_DO,             /* W->J: FUNC */
  GEARMAN_COMMAND_RESET_ABILITIES,     /* W->J: -- */
  GEARMAN_COMMAND_PRE_SLEEP,           /* W->J: -- */
  GEARMAN_COMMAND_UNUSED,
  GEARMAN_COMMAND_NOOP,                /* J->W: -- */
  GEARMAN_COMMAND_SUBMIT_JOB,          /* C->J: FUNC[0]UNIQ[0]ARGS */
  GEARMAN_COMMAND_JOB_CREATED,         /* J->C: HANDLE  */
  GEARMAN_COMMAND_GRAB_JOB,            /* W->J: --  */
  GEARMAN_COMMAND_NO_JOB,              /* J->W: -- */
  GEARMAN_COMMAND_JOB_ASSIGN,          /* J->W: HANDLE[0]FUNC[0]ARG  */
  GEARMAN_COMMAND_WORK_STATUS,         /* W->J/C: HANDLE[0]NUMERATOR[0]DENOMINATOR */
  GEARMAN_COMMAND_WORK_COMPLETE,       /* W->J/C: HANDLE[0]RES */
  GEARMAN_COMMAND_WORK_FAIL,           /* W->J/C: HANDLE */
  GEARMAN_COMMAND_GET_STATUS,          /* C->J: HANDLE */
  GEARMAN_COMMAND_ECHO_REQ,            /* ?->J: TEXT */
  GEARMAN_COMMAND_ECHO_RES,            /* J->?: TEXT */
  GEARMAN_COMMAND_SUBMIT_JOB_BG,       /* C->J: FUNC[0]UNIQ[0]ARGS  */
  GEARMAN_COMMAND_ERROR,               /* J->?: ERRCODE[0]ERR_TEXT */
  GEARMAN_COMMAND_STATUS_RES,          /* C->J: HANDLE[0]KNOWN[0]RUNNING[0]NUM[0]DENOM */
  GEARMAN_COMMAND_SUBMIT_JOB_HIGH,     /* C->J: FUNC[0]UNIQ[0]ARGS  */
  GEARMAN_COMMAND_SET_CLIENT_ID,       /* W->J: [RANDOM_STRING_NO_WHITESPACE] */
  GEARMAN_COMMAND_CAN_DO_TIMEOUT,      /* W->J: FUNC[0]TIMEOUT */
  GEARMAN_COMMAND_ALL_YOURS,
  GEARMAN_COMMAND_WORK_EXCEPTION,
  GEARMAN_COMMAND_OPTION_REQ,
  GEARMAN_COMMAND_OPTION_RES,
  GEARMAN_COMMAND_WORK_DATA,
  GEARMAN_COMMAND_WORK_WARNING,
  GEARMAN_COMMAND_GRAB_JOB_UNIQ,
  GEARMAN_COMMAND_JOB_ASSIGN_UNIQ,
  GEARMAN_COMMAND_SUBMIT_JOB_HIGH_BG,
  GEARMAN_COMMAND_SUBMIT_JOB_LOW,
  GEARMAN_COMMAND_SUBMIT_JOB_LOW_BG,
  GEARMAN_COMMAND_SUBMIT_JOB_SCHED,
  GEARMAN_COMMAND_SUBMIT_JOB_EPOCH,
  GEARMAN_COMMAND_SUBMIT_REDUCE_JOB,      /* C->J: FUNC[0]UNIQ[0]REDUCER[0]UNUSED[0]ARGS */
  GEARMAN_COMMAND_SUBMIT_REDUCE_JOB_BG,   /* C->J: FUNC[0]UNIQ[0]REDUCER[0]UNUSED[0]ARGS */
  GEARMAN_COMMAND_GRAB_JOB_ALL,           /* W->J -- */
  GEARMAN_COMMAND_JOB_ASSIGN_ALL,         /* J->W: HANDLE[0]FUNC[0]UNIQ[0]REDUCER[0]ARGS */
  GEARMAN_COMMAND_GET_STATUS_UNIQUE,      /* C->J: UNIQUE */
  GEARMAN_COMMAND_STATUS_RES_UNIQUE,      /* J->C: UNIQUE[0]KNOWN[0]RUNNING[0]NUM[0]DENOM[0]CLIENT_COUNT */
  GEARMAN_COMMAND_MAX /* Always add new commands before this. */
} gearman_command_t;

static const value_string gearman_command_names[] = {
  { GEARMAN_COMMAND_TEXT,                 "TEXT" },
  { GEARMAN_COMMAND_CAN_DO,               "CAN_DO" },             /* W->J: FUNC */
  { GEARMAN_COMMAND_CANT_DO,              "CANT_DO" },            /* W->J: FUNC */
  { GEARMAN_COMMAND_RESET_ABILITIES,      "RESET_ABILITIES" },    /* W->J: -- */
  { GEARMAN_COMMAND_PRE_SLEEP,            "PRE_SLEEP" },          /* W->J: -- */
  { GEARMAN_COMMAND_UNUSED,               "UNUSED" },
  { GEARMAN_COMMAND_NOOP,                 "NOOP" },               /* J->W: -- */
  { GEARMAN_COMMAND_SUBMIT_JOB,           "SUBMIT_JOB" },         /* C->J: FUNC[0]UNIQ[0]ARGS */
  { GEARMAN_COMMAND_JOB_CREATED,          "JOB_CREATED" },        /* J->C: HANDLE  */
  { GEARMAN_COMMAND_GRAB_JOB,             "GRAB_JOB" },           /* W->J: --  */
  { GEARMAN_COMMAND_NO_JOB,               "NO_JOB" },             /* J->W: -- */
  { GEARMAN_COMMAND_JOB_ASSIGN,           "JOB_ASSIGN" },         /* J->W: HANDLE[0]FUNC[0]ARG  */
  { GEARMAN_COMMAND_WORK_STATUS,          "WORK_STATUS" },        /* W->J/C: HANDLE[0]NUMERATOR[0]DENOMINATOR */
  { GEARMAN_COMMAND_WORK_COMPLETE,        "WORK_COMPLETE" },      /* W->J/C: HANDLE[0]RES */
  { GEARMAN_COMMAND_WORK_FAIL,            "WORK_FAIL" },          /* W->J/C: HANDLE */
  { GEARMAN_COMMAND_GET_STATUS,           "GET_STATUS" },         /* C->J: HANDLE */
  { GEARMAN_COMMAND_ECHO_REQ,             "ECHO_REQ" },           /* ?->J: TEXT */
  { GEARMAN_COMMAND_ECHO_RES,             "ECHO_RES" },           /* J->?: TEXT */
  { GEARMAN_COMMAND_SUBMIT_JOB_BG,        "SUBMIT_JOB_BG" },      /* C->J: FUNC[0]UNIQ[0]ARGS  */
  { GEARMAN_COMMAND_ERROR,                "ERROR" },              /* J->?: ERRCODE[0]ERR_TEXT */
  { GEARMAN_COMMAND_STATUS_RES,           "STATUS_RES" },         /* C->J: HANDLE[0]KNOWN[0]RUNNING[0]NUM[0]DENOM */
  { GEARMAN_COMMAND_SUBMIT_JOB_HIGH,      "SUBMIT_JOB_HIGH" },    /* C->J: FUNC[0]UNIQ[0]ARGS  */
  { GEARMAN_COMMAND_SET_CLIENT_ID,        "SET_CLIENT_ID" },      /* W->J: [RANDOM_STRING_NO_WHITESPACE] */
  { GEARMAN_COMMAND_CAN_DO_TIMEOUT,       "CAN_DO_TIMEOUT" },     /* W->J: FUNC[0]TIMEOUT */
  { GEARMAN_COMMAND_ALL_YOURS,            "ALL_YOURS" },
  { GEARMAN_COMMAND_WORK_EXCEPTION,       "WORK_EXCEPTION" },
  { GEARMAN_COMMAND_OPTION_REQ,           "OPTION_REQ" },
  { GEARMAN_COMMAND_OPTION_RES,           "OPTION_RES" },
  { GEARMAN_COMMAND_WORK_DATA,            "WORK_DATA" },
  { GEARMAN_COMMAND_WORK_WARNING,         "WORK_WARNING" },
  { GEARMAN_COMMAND_GRAB_JOB_UNIQ,        "GRAB_JOB_UNIQ" },
  { GEARMAN_COMMAND_JOB_ASSIGN_UNIQ,      "JOB_ASSIGN_UNIQ" },
  { GEARMAN_COMMAND_SUBMIT_JOB_HIGH_BG,   "SUBMIT_JOB_HIGH_BG" },
  { GEARMAN_COMMAND_SUBMIT_JOB_LOW,       "SUBMIT_JOB_LOW" },
  { GEARMAN_COMMAND_SUBMIT_JOB_LOW_BG,    "SUBMIT_JOB_LOW_BG" },
  { GEARMAN_COMMAND_SUBMIT_JOB_SCHED,     "SUBMIT_JOB_SCHED" },
  { GEARMAN_COMMAND_SUBMIT_JOB_EPOCH,     "SUBMIT_JOB_EPOCH" },
  { GEARMAN_COMMAND_SUBMIT_REDUCE_JOB,    "SUBMIT_REDUCE_JOB" },
  { GEARMAN_COMMAND_SUBMIT_REDUCE_JOB_BG, "SUBMIT_REDUCE_JOB_BG" },
  { GEARMAN_COMMAND_GRAB_JOB_ALL,         "GRAB_JOB_ALL" },
  { GEARMAN_COMMAND_JOB_ASSIGN_ALL,       "JOB_ASSIGN_ALL" },
  { GEARMAN_COMMAND_GET_STATUS_UNIQUE,    "GET_STATUS_UNIQUE" },
  { GEARMAN_COMMAND_STATUS_RES_UNIQUE,    "STATUS_RES_UNIQUE" },
  { 0, NULL}
};

static unsigned
get_gearman_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return tvb_get_ntohl(tvb, offset+8)+GEARMAN_COMMAND_HEADER_SIZE;
}

static int
dissect_binary_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int curr_offset;
  char *magic_code;
  uint32_t type, size;
  unsigned len;
  proto_item *content_item = NULL;
  proto_tree *content_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Gearman");
  col_clear(pinfo->cinfo,COL_INFO);

  magic_code = tvb_get_string_enc(pinfo->pool, tvb, 1, 3, ENC_ASCII);
  type = tvb_get_ntohl(tvb, 4);
  size = tvb_get_ntohl(tvb, 8);

  col_append_sep_fstr(pinfo->cinfo, COL_INFO, " , ", "[%s] ", magic_code);

  col_append_fstr(pinfo->cinfo, COL_INFO, "%s(%d) LEN=%d",
      val_to_str(type, gearman_command_names, "Unknown (0x%08x)"), type, size);

  if (tree) {
    proto_item *ti;
    proto_tree *command_tree, *gearman_tree;
    ti = proto_tree_add_item(tree, proto_gearman, tvb, 0, -1, ENC_NA);
    gearman_tree = proto_item_add_subtree(ti, ett_gearman);

    command_tree = proto_tree_add_subtree_format(gearman_tree, tvb, 0, GEARMAN_COMMAND_HEADER_SIZE+size, ett_gearman_command, NULL,
                             "[%s] %s(%d) LEN=%d", magic_code, val_to_str(type, gearman_command_names, "Unknown (0x%08x)"), type, size);

    proto_tree_add_string(command_tree, hf_gearman_magic_code, tvb, 0, 4, magic_code);
    proto_tree_add_item(command_tree, hf_gearman_pkt_type, tvb, 4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(command_tree, hf_gearman_data_size, tvb, 8, 4, ENC_BIG_ENDIAN);

    // explicitly set len to 0 if there are no arguments,
    // else use tvb_strnlen() to find the remaining length of tvb
    len = ( size > 0 ) ? tvb_strnlen( tvb, GEARMAN_COMMAND_HEADER_SIZE, -1 ) : 0 ;
    content_item = proto_tree_add_item(command_tree, hf_gearman_data_content, tvb, GEARMAN_COMMAND_HEADER_SIZE, len, ENC_ASCII);
    content_tree = proto_item_add_subtree(content_item, ett_gearman_content);
  }

  curr_offset = GEARMAN_COMMAND_HEADER_SIZE;

  switch(type)
  {

  //
  // when determining len for proto_tree_add_item()
  //
  // if the command has one argument:
  //   - use tvb_strnlen()
  //
  // if the command has multiple arguments:
  //   - use tvb_strsize() for the all but the last argument
  //   - use tvb_strnlen() for the last argument
  //
  // These are *not* null-terminated strings, they're null-separated
  // strings.  For example, some arguments might be the last argument
  // in some commands and not be the last argument in other commands,
  // so they're not always followed by a null.

  //
  // commands with a single argument
  //

  case GEARMAN_COMMAND_ECHO_REQ:
  case GEARMAN_COMMAND_ECHO_RES:
    if (!tree) break;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_echo_text, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_JOB_CREATED:
  case GEARMAN_COMMAND_WORK_FAIL:
    if (!tree) break;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_job_handle, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_OPTION_REQ:
  case GEARMAN_COMMAND_OPTION_RES:
    if (!tree) break;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_option_name, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_SET_CLIENT_ID:
    if (!tree) break;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_client_id, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_GET_STATUS_UNIQUE:
    if (!tree) break;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_uniq_id, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_CAN_DO:
  case GEARMAN_COMMAND_CANT_DO:
    if (!tree) break;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_func_name, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  //
  // commands with multiple arguments
  //

  case GEARMAN_COMMAND_ERROR:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_err_code, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_err_text, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_WORK_DATA:
  case GEARMAN_COMMAND_WORK_WARNING:
  case GEARMAN_COMMAND_WORK_COMPLETE:
  case GEARMAN_COMMAND_WORK_EXCEPTION:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_job_handlez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_result, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_STATUS_RES:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_job_handlez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_known_status, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_running_status, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_complete_numerator, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_complete_denominator, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_SUBMIT_JOB:
  case GEARMAN_COMMAND_SUBMIT_JOB_BG:
  case GEARMAN_COMMAND_SUBMIT_JOB_HIGH:
  case GEARMAN_COMMAND_SUBMIT_JOB_HIGH_BG:
  case GEARMAN_COMMAND_SUBMIT_JOB_LOW:
  case GEARMAN_COMMAND_SUBMIT_JOB_LOW_BG:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_func_namez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_uniq_idz, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_argument, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_SUBMIT_REDUCE_JOB:
  case GEARMAN_COMMAND_SUBMIT_REDUCE_JOB_BG:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_func_namez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_uniq_idz, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_reducer, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_argument, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_SUBMIT_JOB_SCHED:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_func_namez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_uniq_idz, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_submit_job_sched_minute, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_submit_job_sched_hour, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_submit_job_sched_day_of_month, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_submit_job_sched_month, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_submit_job_sched_day_of_week, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_argument, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_SUBMIT_JOB_EPOCH:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_func_namez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_uniq_idz, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_submit_job_epoch_time, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_argument, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_JOB_ASSIGN:
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_job_handlez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_func_namez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_argument, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_JOB_ASSIGN_UNIQ:
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_job_handlez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_func_namez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_uniq_idz, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_argument, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_JOB_ASSIGN_ALL:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_job_handlez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_func_namez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_uniq_idz, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_reducer, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_argument, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_WORK_STATUS:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_job_handlez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_complete_numerator, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_complete_denominator, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_CAN_DO_TIMEOUT:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_func_namez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_timeout_value, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  case GEARMAN_COMMAND_STATUS_RES_UNIQUE:
    if (!tree) break;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_job_handlez, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_known_status, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_running_status, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_complete_numerator, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strsize(tvb, curr_offset);
    proto_tree_add_item(content_tree, hf_gearman_complete_denominator, tvb, curr_offset, len, ENC_NA|ENC_ASCII);

    curr_offset += len;
    len = tvb_strnlen( tvb, curr_offset, -1 );
    proto_tree_add_item(content_tree, hf_gearman_client_count, tvb, curr_offset, len, ENC_NA|ENC_ASCII);
    break;

  default:
    if (size > 0)
      expert_add_info(pinfo, content_item, &ei_gearman_pkt_type_unknown);
  }

  col_set_fence(pinfo->cinfo, COL_INFO);
  return tvb_captured_length(tvb);
}

static void
dissect_management_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int i, type = 0, cmdlen, linelen, offset = 0, next_offset = 0;
  proto_item *ti;
  proto_tree *gearman_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Gearman");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_gearman, tvb, 0, -1, ENC_NA);
  gearman_tree = proto_item_add_subtree(ti, ett_gearman);

  while ((linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false)) > 0)
  {
    for (i=0; i<GEARMAN_MGR_CMDS_COUNT; i++)
    {
      /* the array is a const and clearly none of the elements are longer than
       * MAX_SIGNED_INT so this is a safe cast */
      cmdlen = (int)strlen(GEARMAN_MGR_CMDS[i]);

      if (cmdlen == linelen && 0 == tvb_strneql(tvb, offset, GEARMAN_MGR_CMDS[i], cmdlen))
      {
        const uint8_t* cmdstr;
        proto_tree_add_item_ret_string(gearman_tree, hf_gearman_mgr_cmd, tvb, offset, cmdlen, ENC_ASCII|ENC_NA, pinfo->pool, &cmdstr);
        col_add_fstr(pinfo->cinfo, COL_INFO, "[MGR] %s", cmdstr);
        type = 1;
        break;
      }
    }

    if (GEARMAN_MGR_CMDS_COUNT == i)
    {
      proto_tree_add_format_text(gearman_tree, tvb, offset, next_offset - offset);

      if (type == 0)
      {
        col_add_fstr(pinfo->cinfo, COL_INFO, "[MGR] %s", tvb_get_string_enc(pinfo->pool, tvb, offset, linelen, ENC_ASCII));
        type = -1;
      }
      else
      {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ",", tvb_get_string_enc(pinfo->pool, tvb, offset, linelen, ENC_ASCII));
      }
    }

    offset = next_offset;
  }
}

static int
dissect_gearman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  if ((0 == tvb_memeql(tvb, 0, GEARMAN_MAGIC_CODE_REQUEST, 4)) ||
      (0 == tvb_memeql(tvb, 0, GEARMAN_MAGIC_CODE_RESPONSE, 4)))
  {
    tcp_dissect_pdus(tvb, pinfo, tree, gearman_desegment, GEARMAN_COMMAND_HEADER_SIZE, get_gearman_pdu_len, dissect_binary_packet, data);
  }
  else
  {
    dissect_management_packet(tvb, pinfo, tree);
  }

  return tvb_captured_length(tvb);
}

void
proto_register_gearman(void)
{
  static hf_register_info hf[] = {
    { &hf_gearman_mgr_cmd, { "Management Command", "gearman.mgr_cmd", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_gearman_magic_code, { "Magic Code", "gearman.magic_code", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_gearman_pkt_type, { "Packet Type", "gearman.pkt_type", FT_UINT32, BASE_DEC_HEX, VALS(gearman_command_names), 0x0, NULL, HFILL} },
    { &hf_gearman_data_size, { "Data Length", "gearman.data_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_data_content, { "Data Content", "gearman.data_content", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_option_name, { "Option Name", "gearman.opt.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_func_name, { "Function Name", "gearman.func.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_func_namez, { "Function Name", "gearman.func.name", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_client_id, { "Client ID", "gearman.client_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_client_count, { "Client Count", "gearman.client_count", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_uniq_id, { "Unique ID", "gearman.uniq_id", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_uniq_idz, { "Unique ID", "gearman.uniq_id", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_argument, { "Function Argument", "gearman.func.arg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_job_handle, { "Job Handle", "gearman.job.handle", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_job_handlez, { "Job Handle", "gearman.job.handle", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_complete_numerator, { "Complete Numerator", "gearman.numerator", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_complete_denominator, { "Complete Denominator", "gearman.denominator", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_submit_job_sched_minute, { "Minute", "gearman.submit_job_sched.minute", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_submit_job_sched_hour, { "Hour", "gearman.submit_job_sched.hour", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_submit_job_sched_day_of_month, { "Day of Month", "gearman.submit_job_sched.day_of_month", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_submit_job_sched_month, { "Month", "gearman.submit_job_sched.month", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_submit_job_sched_day_of_week, { "Day of Week", "gearman.submit_job_sched.day_of_week", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_submit_job_epoch_time, { "Epoch Time", "gearman.submit_job.epoch_time", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_reducer, { "Reducer", "gearman.reducer", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_result, { "Function Result", "gearman.func.result", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_known_status, { "Known job", "gearman.job.known", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_running_status, { "Running Job", "gearman.job.running", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_timeout_value, { "Timeout Value", "gearman.timeout.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_echo_text, { "Echo Text", "gearman.echo_text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_err_code, { "Error Code", "gearman.err.code", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} },
    { &hf_gearman_err_text, { "Error Text", "gearman.err.text", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL} }
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_gearman,
    &ett_gearman_command,
    &ett_gearman_content
  };

  static ei_register_info ei[] = {
     { &ei_gearman_pkt_type_unknown, { "gearman.pkt_type.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
  };

  module_t *gearman_module;
  expert_module_t* expert_gearman;

  proto_gearman = proto_register_protocol("Gearman Protocol", "Gearman", "gearman");

  proto_register_field_array(proto_gearman, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_gearman = expert_register_protocol(proto_gearman);
  expert_register_field_array(expert_gearman, ei, array_length(ei));

  gearman_module = prefs_register_protocol(proto_gearman, NULL);
  prefs_register_bool_preference(gearman_module, "desegment",
                                  "Desegment all Gearman messages spanning multiple TCP segments",
                                  "Whether the Gearman dissector should desegment all messages spanning multiple TCP segments",
                                  &gearman_desegment);

  gearman_handle = register_dissector("gearman", dissect_gearman, proto_gearman);
}

void
proto_reg_handoff_gearman(void)
{
  dissector_add_uint_with_preference("tcp.port", GEARMAN_PORT, gearman_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
