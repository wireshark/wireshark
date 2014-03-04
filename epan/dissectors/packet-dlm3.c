/* packet-dlm3.c
 * Routines for dlm3 dissection
 * Copyright 2007, Masatake YAMATO <jet@gyve.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/* This dissector supports version 3.0 of the dlm(Distributed Lock Manager)
   protocol

   Actual implementation for the protocol is in linux kernel.
   See files under linux/fs/dlm/ */

/*
 * #defines are mostly copied from
 * *.[ch] files in linux/fs/dlm/ and linux/include/linux/dlm.h
 *
 * dlm_internal.h:
 * -----------------------------------------------------------------------
 **  Copyright (C) Sistina Software, Inc.  1997-2003  All rights reserved.
 **  Copyright (C) 2004-2005 Red Hat, Inc.  All rights reserved.
 **
 **  This copyrighted material is made available to anyone wishing to use,
 **  modify, copy, or redistribute it subject to the terms and conditions
 **  of the GNU General Public License v.2.
 * -----------------------------------------------------------------------
 */


#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>



#define TCP_PORT_DLM3           21064
#define SCTP_PORT_DLM3          TCP_PORT_DLM3

#define DLM3_MAJOR_VERSION      0x00030000
#define DLM3_MINOR_VERSION      0x00000000

#define DLM3_MSG                1
#define DLM3_RCOM               2

#define DLM3_MSG_REQUEST        1
#define DLM3_MSG_CONVERT        2
#define DLM3_MSG_UNLOCK         3
#define DLM3_MSG_CANCEL         4
#define DLM3_MSG_REQUEST_REPLY  5
#define DLM3_MSG_CONVERT_REPLY  6
#define DLM3_MSG_UNLOCK_REPLY   7
#define DLM3_MSG_CANCEL_REPLY   8
#define DLM3_MSG_GRANT          9
#define DLM3_MSG_BAST           10
#define DLM3_MSG_LOOKUP         11
#define DLM3_MSG_REMOVE         12
#define DLM3_MSG_LOOKUP_REPLY   13
#define DLM3_MSG_PURGE          14

#define DLM3_LKF_NOQUEUE        0x00000001
#define DLM3_LKF_CANCEL         0x00000002
#define DLM3_LKF_CONVERT        0x00000004
#define DLM3_LKF_VALBLK         0x00000008
#define DLM3_LKF_QUECVT         0x00000010
#define DLM3_LKF_IVVALBLK       0x00000020
#define DLM3_LKF_CONVDEADLK     0x00000040
#define DLM3_LKF_PERSISTENT     0x00000080
#define DLM3_LKF_NODLCKWT       0x00000100
#define DLM3_LKF_NODLCKBLK      0x00000200
#define DLM3_LKF_EXPEDITE       0x00000400
#define DLM3_LKF_NOQUEUEBAST    0x00000800
#define DLM3_LKF_HEADQUE        0x00001000
#define DLM3_LKF_NOORDER        0x00002000
#define DLM3_LKF_ORPHAN         0x00004000
#define DLM3_LKF_ALTPR          0x00008000
#define DLM3_LKF_ALTCW          0x00010000
#define DLM3_LKF_FORCEUNLOCK    0x00020000
#define DLM3_LKF_TIMEOUT        0x00040000

#define DLM3_SBF_DEMOTED        0x01
#define DLM3_SBF_VALNOTVALID    0x02
#define DLM3_SBF_ALTMODE        0x04

#define DLM3_IFL_USER           0x00000001
#define DLM3_IFL_ORPHAN         0x00000002
/* They may not be used in receiver side.
   --------------------------------------
   #define DLM3_IFL_MSTCPY          0x00010000
   #define DLM3_IFL_RESEND          0x00020000
   #define DLM3_IFL_DEAD            0x00040000
   #define DLM3_IFL_OVERLAP_UNLOCK  0x00080000
   #define DLM3_IFL_OVERLAP_CANCEL  0x00100000
   #define DLM3_IFL_ENDOFLIFE       0x00200000
   #define DLM3_IFL_WATCH_TIMEWARN  0x00400000
   #define DLM3_IFL_TIMEOUT_CANCEL  0x00800000
   #define DLM3_IFL_DEADLOCK_CANCEL 0x01000000 */

#define DLM3_LKSTS_WAITING      1
#define DLM3_LKSTS_GRANTED      2
#define DLM3_LKSTS_CONVERT      3

#define DLM3_LOCK_IV            -1
#define DLM3_LOCK_NL            0
#define DLM3_LOCK_CR            1
#define DLM3_LOCK_CW            2
#define DLM3_LOCK_PR            3
#define DLM3_LOCK_PW            4
#define DLM3_LOCK_EX            5

#define DLM3_AST_COMP           1
#define DLM3_AST_BAST           2


/* see asm-generic/errno-base.h about LINUX_*  */
#define LINUX_EAGAIN            11
#define LINUX_ENOMEM            12
#define LINUX_INVAL             22

#define DLM3_ERRNO_EDEADLK       35
#define DLM3_ERRNO_EBADR         53
#define DLM3_ERRNO_EBADSLT       57
#define DLM3_ERRNO_EPROTO        71
#define DLM3_ERRNO_EOPNOTSUPP    95
#define DLM3_ERRNO_ETIMEDOUT    110
#define DLM3_ERRNO_EINPROGRESS  115

#define DLM3_ECANCEL            0x10001
#define DLM3_EUNLOCK            0x10002


#define DLM3_RCOM_STATUS        1
#define DLM3_RCOM_NAMES         2
#define DLM3_RCOM_LOOKUP        3
#define DLM3_RCOM_LOCK          4
#define DLM3_RCOM_STATUS_REPLY  5
#define DLM3_RCOM_NAMES_REPLY   6
#define DLM3_RCOM_LOOKUP_REPLY  7
#define DLM3_RCOM_LOCK_REPLY    8

#define DLM3_RS_NODES           0x00000001
#define DLM3_RS_NODES_ALL       0x00000002
#define DLM3_RS_DIR             0x00000004
#define DLM3_RS_DIR_ALL         0x00000008
#define DLM3_RS_LOCKS           0x00000010
#define DLM3_RS_LOCKS_ALL       0x00000020
#define DLM3_RS_DONE            0x00000040
#define DLM3_RS_DONE_ALL        0x00000080

#define DLM3_RESNAME_MAXLEN     64

/* Forward declaration we need below */
void proto_register_dlm3(void);
void proto_reg_handoff_dlm3(void);


/* Initialize the protocol and registered fields */
static int proto_dlm3 = -1;

/* fields for struct dlm_header(h) */
static int hf_dlm3_h_version   = -1;
static int hf_dlm3_h_major_version = -1;
static int hf_dlm3_h_minor_version = -1;
static int hf_dlm3_h_lockspace = -1;
static int hf_dlm3_h_nodeid    = -1;
static int hf_dlm3_h_length    = -1;
static int hf_dlm3_h_cmd       = -1;
static int hf_dlm3_h_pad       = -1;

/* fields for struct dlm_message(m) */
static int hf_dlm3_m_type         = -1;
static int hf_dlm3_m_nodeid       = -1;
static int hf_dlm3_m_pid          = -1;
static int hf_dlm3_m_lkid         = -1;
static int hf_dlm3_m_remid        = -1;
static int hf_dlm3_m_parent_lkid  = -1;
static int hf_dlm3_m_parent_remid = -1;

/* bit fields for dlm_message::exflags */
#define DLM3_DEFINE_HF_EXFLAGS(NAME)            \
  static int hf_dlm3_##NAME      = -1;          \
  static int hf_dlm3_##NAME##_noqueue     = -1; \
  static int hf_dlm3_##NAME##_cancel      = -1; \
  static int hf_dlm3_##NAME##_convert     = -1; \
  static int hf_dlm3_##NAME##_valblk      = -1; \
  static int hf_dlm3_##NAME##_quecvt      = -1; \
  static int hf_dlm3_##NAME##_ivvalblk    = -1; \
  static int hf_dlm3_##NAME##_convdeadlk  = -1; \
  static int hf_dlm3_##NAME##_persistent  = -1; \
  static int hf_dlm3_##NAME##_nodlckwt    = -1; \
  static int hf_dlm3_##NAME##_nodlckblk   = -1; \
  static int hf_dlm3_##NAME##_expedite    = -1; \
  static int hf_dlm3_##NAME##_noqueuebast = -1; \
  static int hf_dlm3_##NAME##_headque     = -1; \
  static int hf_dlm3_##NAME##_noorder     = -1; \
  static int hf_dlm3_##NAME##_orphan      = -1; \
  static int hf_dlm3_##NAME##_altpr       = -1; \
  static int hf_dlm3_##NAME##_altcw       = -1; \
  static int hf_dlm3_##NAME##_forceunlock = -1; \
  static int hf_dlm3_##NAME##_timeout     = -1
DLM3_DEFINE_HF_EXFLAGS(m_exflags);

/* bit fields for dlm_message::sbflags */
static int hf_dlm3_m_sbflags             = -1;
static int hf_dlm3_m_sbflags_demoted     = -1;
static int hf_dlm3_m_sbflags_valnotvalid = -1;
static int hf_dlm3_m_sbflags_altmode     = -1;

/* bit fields for dlm_message::flags */
#define DLM3_DEFINE_HF_FLAGS(NAME)              \
  static int hf_dlm3_##NAME          = -1;      \
  static int hf_dlm3_##NAME##_user   = -1;      \
  static int hf_dlm3_##NAME##_orphan = -1
DLM3_DEFINE_HF_FLAGS(m_flags);

static int hf_dlm3_m_lvbseq       = -1;
static int hf_dlm3_m_hash         = -1;
static int hf_dlm3_m_status       = -1;
static int hf_dlm3_m_grmode       = -1;
static int hf_dlm3_m_rqmode       = -1;
static int hf_dlm3_m_bastmode     = -1;

/* bit fields for dlm_message::asts */
#define DLM3_DEFINE_HF_ASTS(NAME)                       \
  static int hf_dlm3_##NAME##_asts         = -1;        \
  static int hf_dlm3_##NAME##_asts_comp    = -1;        \
  static int hf_dlm3_##NAME##_asts_bast    = -1
DLM3_DEFINE_HF_ASTS(m);

static int hf_dlm3_m_result       = -1;
static int hf_dlm3_m_extra        = -1;

/* fields for struct dlm_rcom(rc) */
static int hf_dlm3_rc_type      = -1;
static int hf_dlm3_rc_result    = -1;
static int hf_dlm3_rc_id        = -1;
static int hf_dlm3_rc_seq       = -1;
static int hf_dlm3_rc_seq_reply = -1;
static int hf_dlm3_rc_buf       = -1;

/* fields for struct rcom_config(rf) */
static int hf_dlm3_rf_lvblen    = -1;
DLM3_DEFINE_HF_EXFLAGS(rf_lsflags);
static int hf_dlm3_rf_unused    = -1;

/* fields for struct rcom_lock(rl) */
static int hf_dlm3_rl_ownpid        = -1;
static int hf_dlm3_rl_lkid          = -1;
static int hf_dlm3_rl_remid         = -1;
static int hf_dlm3_rl_parent_lkid   = -1;
static int hf_dlm3_rl_parent_remid  = -1;
DLM3_DEFINE_HF_EXFLAGS(rl_exflags);
DLM3_DEFINE_HF_FLAGS(rl_flags);
static int hf_dlm3_rl_lvbseq        = -1;
static int hf_dlm3_rl_result        = -1;
static int hf_dlm3_rl_rqmode        = -1;
static int hf_dlm3_rl_grmode        = -1;
static int hf_dlm3_rl_status        = -1;
DLM3_DEFINE_HF_ASTS(rl);
static int hf_dlm3_rl_wait_type     = -1;
static int hf_dlm3_rl_namelen       = -1;
static int hf_dlm3_rl_name          = -1;
static int hf_dlm3_rl_name_contents = -1;
static int hf_dlm3_rl_name_padding  = -1;
static int hf_dlm3_rl_lvb           = -1;

/* Initialize the subtree pointers */
static gint ett_dlm3         = -1;
static gint ett_dlm3_version = -1;

static gint ett_dlm3_msg       = -1;
static gint ett_dlm3_m_exflags = -1;
static gint ett_dlm3_sbflags   = -1;
static gint ett_dlm3_m_flags   = -1;
static gint ett_dlm3_m_asts    = -1;

static gint ett_dlm3_rcom        = -1;
static gint ett_dlm3_rcom_lock   = -1;
static gint ett_dlm3_rcom_config = -1;

static gint ett_dlm3_rf_lsflags  = -1;
static gint ett_dlm3_rl_exflags  = -1;
static gint ett_dlm3_rl_flags    = -1;
static gint ett_dlm3_rl_asts     = -1;
static gint ett_dlm3_rl_name     = -1;


/* configurable parameters */
static guint dlm3_tcp_port  = TCP_PORT_DLM3;
static guint dlm3_sctp_port = SCTP_PORT_DLM3;

/*
 * Value strings
 */
static const value_string dlm3_cmd[] = {
  { DLM3_MSG,  "message"          },
  { DLM3_RCOM, "recovery command" },
  { 0,         NULL               }
};

static const value_string dlm3_msg[] = {
  { DLM3_MSG_REQUEST,       "request message"    },
  { DLM3_MSG_CONVERT,       "conversion message" },
  { DLM3_MSG_UNLOCK,        "unlock message"     },
  { DLM3_MSG_CANCEL,        "cancel message"     },
  { DLM3_MSG_REQUEST_REPLY, "request reply"      },
  { DLM3_MSG_CONVERT_REPLY, "conversion reply"   },
  { DLM3_MSG_UNLOCK_REPLY,  "unlock reply"       },
  { DLM3_MSG_CANCEL_REPLY,  "cancel reply"       },
  { DLM3_MSG_GRANT,         "grant message"      },
  { DLM3_MSG_BAST,          "bast message"       },
  { DLM3_MSG_LOOKUP,        "lookup message"     },
  { DLM3_MSG_REMOVE,        "remove message"     },
  { DLM3_MSG_LOOKUP_REPLY,  "lookup reply"       },
  { DLM3_MSG_PURGE,         "purge orphans"      },
  { 0,                      NULL                 }
};

static const value_string dlm3_status[] = {
  { DLM3_LKSTS_WAITING, "waiting"  },
  { DLM3_LKSTS_GRANTED, "granted"  },
  { DLM3_LKSTS_CONVERT, "convert"  },
  { 0,                  NULL       }
};

static const value_string dlm3_mode[] = {
  { DLM3_LOCK_IV, "invalid"          },
  { DLM3_LOCK_NL, "null"             },
  { DLM3_LOCK_CR, "concurrent read"  },
  { DLM3_LOCK_CW, "concurrent write" },
  { DLM3_LOCK_PR, "protected read"   },
  { DLM3_LOCK_PW, "protected write"  },
  { DLM3_LOCK_EX, "exclusive"        },
  { 0,            NULL               }
};

static const value_string dlm3_result[] = {
  { -LINUX_EAGAIN, "blocked"                       },
  { -LINUX_ENOMEM, "no memory"                     },
  { -LINUX_INVAL,  "invalid parameters"            },
  { -DLM3_ERRNO_EDEADLK,     "Resource deadlock avoided"  },
  { -DLM3_ERRNO_EBADR,       "Invalid request descriptor" },
  { -DLM3_ERRNO_EBADSLT,     "Invalid slot"               },
  { -DLM3_ERRNO_EPROTO,      "Protocol error"             },
  { -DLM3_ERRNO_EOPNOTSUPP,  "Operation not supported"    },
  { -DLM3_ERRNO_ETIMEDOUT,   "Connection timed out"       },
  { -DLM3_ERRNO_EINPROGRESS, "Operation now in progress"  },
  { -DLM3_ECANCEL, "cancel completed successfully" },
  { -DLM3_EUNLOCK, "unlock request was successful" },
  { 0,             "successful"                    },
  { 0,             NULL                            }
};

static const value_string dlm3_rcom[] = {
  { DLM3_RCOM_STATUS,       "status command" },
  { DLM3_RCOM_NAMES,        "names command"  },
  { DLM3_RCOM_LOOKUP,       "lookup command" },
  { DLM3_RCOM_LOCK,         "lock command"   },
  { DLM3_RCOM_STATUS_REPLY, "status reply"   },
  { DLM3_RCOM_NAMES_REPLY,  "names reply"    },
  { DLM3_RCOM_LOOKUP_REPLY, "lookup reply"   },
  { DLM3_RCOM_LOCK_REPLY,   "lock reply"     },
  { 0,                      NULL             }
};

static const value_string dlm3_rs[] = {
  { DLM3_RS_NODES,     "recovering nodes"                    },
  { DLM3_RS_NODES_ALL, "recovering all nodes"                },
  { DLM3_RS_DIR,       "recovering resource directory"       },
  { DLM3_RS_DIR_ALL,   "recovering all resource directories" },
  { DLM3_RS_LOCKS,     "recovering lock"                     },
  { DLM3_RS_LOCKS_ALL, "recovering all locks"                },
  { DLM3_RS_DONE,      "recovering is done"                  },
  { DLM3_RS_DONE_ALL,  "all recovering is done"              },
  { 0,                 NULL                                  }
};

/*
 * Fields
 */
#define DLM3_DEFINE_EXFLAGS_FIELDS(NAME)        \
  static const int* NAME##_fields[] = {         \
    &hf_dlm3_##NAME##_timeout ,                 \
    &hf_dlm3_##NAME##_forceunlock ,             \
    &hf_dlm3_##NAME##_altcw       ,             \
    &hf_dlm3_##NAME##_altpr       ,             \
    &hf_dlm3_##NAME##_orphan      ,             \
    &hf_dlm3_##NAME##_noorder     ,             \
    &hf_dlm3_##NAME##_headque     ,             \
    &hf_dlm3_##NAME##_noqueuebast ,             \
    &hf_dlm3_##NAME##_expedite    ,             \
    &hf_dlm3_##NAME##_nodlckblk   ,             \
    &hf_dlm3_##NAME##_nodlckwt    ,             \
    &hf_dlm3_##NAME##_persistent  ,             \
    &hf_dlm3_##NAME##_convdeadlk  ,             \
    &hf_dlm3_##NAME##_ivvalblk    ,             \
    &hf_dlm3_##NAME##_quecvt      ,             \
    &hf_dlm3_##NAME##_valblk      ,             \
    &hf_dlm3_##NAME##_convert     ,             \
    &hf_dlm3_##NAME##_cancel      ,             \
    &hf_dlm3_##NAME##_noqueue     ,             \
    NULL                                        \
  }
DLM3_DEFINE_EXFLAGS_FIELDS(m_exflags);

static const int *m_sbflags_fields[] = {
  &hf_dlm3_m_sbflags_altmode     ,
  &hf_dlm3_m_sbflags_valnotvalid ,
  &hf_dlm3_m_sbflags_demoted     ,
  NULL
};

#define DLM3_DEFINE_FLAGS_FIELDS(NAME)          \
  static const int* NAME##_fields[] = {         \
    &hf_dlm3_##NAME##_orphan        ,           \
    &hf_dlm3_##NAME##_user          ,           \
    NULL                                        \
  }
DLM3_DEFINE_FLAGS_FIELDS(m_flags);

#define DLM3_DEFINE_ASTS_FIELDS(NAME)           \
  static const int* NAME##_asts_fields[] = {    \
    &hf_dlm3_##NAME##_asts_bast           ,     \
    &hf_dlm3_##NAME##_asts_comp           ,     \
    NULL                                        \
  }
DLM3_DEFINE_ASTS_FIELDS(m);

DLM3_DEFINE_EXFLAGS_FIELDS(rf_lsflags);

DLM3_DEFINE_EXFLAGS_FIELDS(rl_exflags);
DLM3_DEFINE_FLAGS_FIELDS(rl_flags);
DLM3_DEFINE_ASTS_FIELDS(rl);

/* Code to actually dissect the packets */
static void
dissect_dlm3_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 guint length, int offset)
{
  guint32     m_type;

  m_type   = tvb_get_letohl(tvb, offset);
  proto_tree_add_uint(tree,
                      hf_dlm3_m_type, tvb, offset, 4, m_type);
  col_append_fstr(pinfo->cinfo, COL_INFO,
                ": %s",
                val_to_str_const(m_type,
                                 dlm3_msg,
                                 "Unknown"));

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_nodeid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_lkid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  /* TODO: See `create_lkb'
     lkid has some structure. We dissect more. */

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_remid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_parent_lkid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_parent_remid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_dlm3_m_exflags, ett_dlm3_m_exflags,
                         m_exflags_fields, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_dlm3_m_sbflags, ett_dlm3_sbflags,
                         m_sbflags_fields, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_dlm3_m_flags, ett_dlm3_m_flags,
                         m_flags_fields, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_lvbseq, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_hash, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_status, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_grmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_rqmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_bastmode, tvb, offset, 4, ENC_LITTLE_ENDIAN);


  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_dlm3_m_asts, ett_dlm3_m_asts,
                         m_asts_fields, ENC_LITTLE_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_m_result, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  if ((length - offset) > 0) {
    proto_tree_add_item(tree,
                        hf_dlm3_m_extra,
                        tvb,
                        offset,
                        -1,
                        ENC_NA);
  }
}



static void
dissect_dlm3_rcom_lock(tvbuff_t *tvb, proto_tree *tree,
                       guint length, int offset)
{
  proto_item *sub_item;
  proto_tree *sub_tree;
  int         sub_offset;
  guint16     namelen;
  guint32     exflags;


  if ((length - offset) < ( 4 * 8 + 4 + 1 * 4 + 2 * 2
                            + DLM3_RESNAME_MAXLEN ))
    return;


  proto_tree_add_item(tree,
                      hf_dlm3_rl_ownpid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_lkid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_remid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_parent_lkid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_parent_remid, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_dlm3_rl_exflags, ett_dlm3_rl_exflags,
                         rl_exflags_fields, ENC_LITTLE_ENDIAN);
  exflags = tvb_get_letohl(tvb, offset);


  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_dlm3_rl_flags, ett_dlm3_rl_flags,
                         rl_flags_fields, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_lvbseq, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_result, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_rqmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);

  offset += 1;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_grmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);

  offset += 1;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);

  offset += 1;
  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_dlm3_rl_asts, ett_dlm3_rl_asts,
                         rl_asts_fields, ENC_LITTLE_ENDIAN);

  offset += 1;
  proto_tree_add_item(tree,
                      hf_dlm3_rl_wait_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);

  offset += 2;
  namelen = tvb_get_letohs(tvb, offset);
  proto_tree_add_uint(tree,
                      hf_dlm3_rl_namelen, tvb, offset, 2,
                      namelen);

  offset += 2;
  sub_item = proto_tree_add_item(tree,
                                 hf_dlm3_rl_name, tvb, offset,
                                 DLM3_RESNAME_MAXLEN, ENC_NA);

  sub_tree = proto_item_add_subtree(sub_item,
                                    ett_dlm3_rl_name);
  sub_offset = offset;
  proto_tree_add_item(sub_tree,
                      hf_dlm3_rl_name_contents, tvb, sub_offset,
                      namelen, ENC_ASCII|ENC_NA);

  sub_offset += namelen;
  proto_tree_add_item(sub_tree,
                      hf_dlm3_rl_name_padding, tvb, sub_offset,
                      DLM3_RESNAME_MAXLEN - namelen, ENC_NA);

  offset += DLM3_RESNAME_MAXLEN;
  if (((length - offset) > 0) && (exflags & DLM3_LKF_VALBLK))
    proto_tree_add_item(tree,
                        hf_dlm3_rl_lvb, tvb, offset,
                        -1,
                        ENC_NA);
}


static void
dissect_dlm3_rcom_config(tvbuff_t *tvb, proto_tree *tree,
                         guint length, int offset)
{
  if ((length - offset) < ( 4 + 4 + 8 ))
    return;

  proto_tree_add_item(tree,
                      hf_dlm3_rf_lvblen, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_bitmask(tree, tvb, offset,
                         hf_dlm3_rf_lsflags, ett_dlm3_rf_lsflags,
                         rf_lsflags_fields, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rf_unused, tvb, offset, 8, ENC_LITTLE_ENDIAN);


  /*offset += 8;*/
  /* END */
}

static void
dissect_dlm3_rcom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  guint length, int offset)
{
  guint32     rc_type;

  proto_item *sub_item;
  proto_tree *sub_tree;


  rc_type  = tvb_get_letohl(tvb, offset);
  proto_tree_add_uint(tree,
                      hf_dlm3_rc_type, tvb, offset, 4, rc_type);
  col_append_fstr(pinfo->cinfo, COL_INFO,
                  ": %s",
                  val_to_str_const(rc_type,
                                   dlm3_rcom,
                                   "Unknown"));

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rc_result, tvb, offset, 4, ENC_LITTLE_ENDIAN);

  offset += 4;
  proto_tree_add_item(tree,
                      hf_dlm3_rc_id, tvb, offset, 8, ENC_LITTLE_ENDIAN);

  offset += 8;
  proto_tree_add_item(tree,
                      hf_dlm3_rc_seq, tvb, offset, 8, ENC_LITTLE_ENDIAN);

  offset += 8;
  proto_tree_add_item(tree,
                      hf_dlm3_rc_seq_reply, tvb, offset, 8, ENC_LITTLE_ENDIAN);

  offset += 8;
  if ((length - offset) == 0) {
    /* No rc_buf: Just return */
    return;
  }

  /* Decode rc_buf */
  sub_item = proto_tree_add_item(tree,
                                 hf_dlm3_rc_buf,
                                 tvb,
                                 offset,
                                 -1,
                                 ENC_NA);

  offset += 0;
  if (rc_type == DLM3_RCOM_LOCK) {
    sub_tree = proto_item_add_subtree(sub_item,
                                      ett_dlm3_rcom_lock);
    dissect_dlm3_rcom_lock(tvb, sub_tree, length, offset);
  } else if (rc_type == DLM3_RCOM_STATUS_REPLY) {
    sub_tree = proto_item_add_subtree(sub_item,
                                      ett_dlm3_rcom_config);
    dissect_dlm3_rcom_config(tvb, sub_tree, length, offset);
  }

}

static int
dissect_dlm3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  proto_item *item, *sub_item;
  proto_tree *tree, *sub_tree;

  int        offset;
  guint      length;
  guint32    h_version;
  guint8     h_cmd;


  /* Check that there's enough data */
  length = tvb_length(tvb);
  if (length < 4 + 4 + 4 + 2 + 1 + 1)
    return 0;

  /* Check the protocol version  */
  h_version = tvb_get_letohl(tvb, 0);
  if (h_version != (DLM3_MAJOR_VERSION|DLM3_MINOR_VERSION))
    return 0;

  /* Check the command */
  h_cmd = tvb_get_guint8(tvb, 4 + 4 + 4 + 2) ;
  if ((h_cmd != DLM3_MSG) && (h_cmd != DLM3_RCOM))
    return 0;

  if ((h_cmd == DLM3_MSG) && (length < ((4 + 4 + 4 + 2 + 1 + 1)
                                        + (4 * 12 + 4 * 6))))
    return 0;
  else if ((h_cmd == DLM3_RCOM) && (length < 4 + 4 + 8 + 8 + 8))
    return 0;


  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLM3");


  col_set_str(pinfo->cinfo, COL_INFO, "DLM3");

  col_set_str(pinfo->cinfo, COL_INFO,
                val_to_str_const(h_cmd,
                           dlm3_cmd,
                           "packet-dlm3.c internal bug"));

  if (parent_tree) {
    offset = 0;

    item = proto_tree_add_item(parent_tree, proto_dlm3, tvb, offset,
                               -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_dlm3);

    sub_item = proto_tree_add_uint(tree,
                                   hf_dlm3_h_version, tvb, offset, 4,
                                   h_version);
    sub_tree = proto_item_add_subtree(sub_item, ett_dlm3_version);
    proto_tree_add_uint(sub_tree,
                        hf_dlm3_h_major_version, tvb, offset + 0, 2,
                        (h_version & 0xFFFF0000) >> 16);
    proto_tree_add_uint(sub_tree,
                        hf_dlm3_h_minor_version, tvb, offset + 2, 2,
                        (h_version & 0x0000FFFF));


    offset += 4;
    proto_tree_add_item(tree,
                        hf_dlm3_h_lockspace, tvb, offset, 4, ENC_LITTLE_ENDIAN);

    offset += 4;
    proto_tree_add_item(tree,
                        hf_dlm3_h_nodeid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree,
                        hf_dlm3_h_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    offset += 2;
    sub_item = proto_tree_add_uint(tree,
                                   hf_dlm3_h_cmd, tvb, offset, 1, h_cmd);

    offset += 1;
    proto_tree_add_item(tree,
                        hf_dlm3_h_pad, tvb, offset, 1, ENC_LITTLE_ENDIAN);


    offset += 1;
    if (h_cmd == DLM3_MSG) {
      sub_tree = proto_item_add_subtree(sub_item, ett_dlm3_msg);
      dissect_dlm3_msg(tvb, pinfo, sub_tree, length, offset);
    } else if (h_cmd== DLM3_RCOM) {
      sub_tree = proto_item_add_subtree(sub_item, ett_dlm3_rcom);
      dissect_dlm3_rcom(tvb, pinfo, sub_tree, length, offset);
    }
  }
  return tvb_length(tvb);
}


/* Register the protocol with Wireshark */

#define DLM3_REGISTER_HF_LOCKID(NAME)                                   \
  { &hf_dlm3_##NAME##_lkid,                                             \
      { "Lock ID on Sender", "dlm3." #NAME ".lkid",                     \
          FT_UINT32, BASE_DEC_HEX, NULL, 0x0,                           \
          NULL, HFILL}},                                                \
{ &hf_dlm3_##NAME##_remid,                                              \
    { "Lock ID on Receiver", "dlm3." #NAME ".remid",                    \
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,                             \
        NULL, HFILL}},                                                  \
{ &hf_dlm3_##NAME##_parent_lkid,                                        \
    { "Parent Lock ID on Sender", "dlm3." #NAME ".parent_lkid",         \
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,                             \
        NULL, HFILL}},                                                  \
{ &hf_dlm3_##NAME##_parent_remid,                                       \
    { "Parent Lock ID on Receiver", "dlm3." #NAME ".parent_remid",      \
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,                             \
        NULL, HFILL}}

#define DLM3_REGISTER_HF_EXFLAGS(SYMNAME,STRNAME)                       \
{ &hf_dlm3_##SYMNAME,                                                   \
  { "External Flags", "dlm3." STRNAME "",                               \
    FT_UINT32, BASE_HEX, NULL, 0x0,                                     \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_noqueue,                                         \
  { "Don't queue", "dlm3." STRNAME ".noqueue",                          \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_NOQUEUE,                             \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_cancel,                                          \
  { "Cancel", "dlm3." STRNAME ".cancel",                                \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_CANCEL,                              \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_convert,                                         \
  { "Convert", "dlm3." STRNAME ".convert",                              \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_CONVERT,                             \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_valblk,                                          \
  { "Return the contents of the lock value block", "dlm3." STRNAME ".valblk", \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_VALBLK,                              \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_quecvt,                                          \
  { "Force a conversion request to be queued", "dlm3." STRNAME ".quecvt", \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_QUECVT,                              \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_ivvalblk,                                        \
  { "Invalidate the lock value block", "dlm3." STRNAME ".ivvalblk",     \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_IVVALBLK,                            \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_convdeadlk,                                      \
  { "Forced down to NL to resolve a conversion deadlock", "dlm3." STRNAME ".convdeadlk", \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_CONVDEADLK,                          \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_persistent,                                      \
  { "Persistent", "dlm3." STRNAME ".persistent",                        \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_PERSISTENT,                          \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_nodlckwt,                                        \
  { "Don't cancel the lock if it gets into conversion deadlock", "dlm3." STRNAME ".nodlckwt", \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_NODLCKWT,                            \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_nodlckblk,                                       \
  { "Nodlckblk", "dlm3." STRNAME ".nodlckblk",                          \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_NODLCKBLK,                           \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_expedite,                                        \
  { "Grant a NL lock immediately", "dlm3." STRNAME ".expedite",         \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_EXPEDITE,                            \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_noqueuebast,                                     \
  { "Send blocking ASTs even for NOQUEUE operations", "dlm3." STRNAME ".noqueuebast", \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_NOQUEUEBAST,                         \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_headque,                                         \
  { "Add a lock to the head of the queue", "dlm3." STRNAME ".headque",  \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_HEADQUE,                             \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_noorder,                                         \
  { "Disregard the standard grant order rules", "dlm3." STRNAME ".noorder", \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_NOORDER,                             \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_orphan,                                          \
  { "Orphan", "dlm3." STRNAME ".orphan",                                \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_ORPHAN,                              \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_altpr,                                           \
  { "Try to grant the lock in `protected read' mode", "dlm3." STRNAME ".altpr", \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_ALTPR,                               \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_altcw,                                           \
  { "Try to grant the lock in `concurrent read' mode", "dlm3." STRNAME ".altcw", \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_ALTCW,                               \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_forceunlock,                                     \
  { "Force unlock", "dlm3." STRNAME ".forceunlock",                     \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_FORCEUNLOCK,                         \
    NULL, HFILL}},                                                      \
{ &hf_dlm3_##SYMNAME##_timeout,                                         \
  { "Timeout", "dlm3." STRNAME ".timeout",                              \
    FT_BOOLEAN, 32, NULL, DLM3_LKF_TIMEOUT,                             \
    NULL, HFILL}}


#define DLM3_REGISTER_HF_FLAGS(SYMNAME,STRNAME)         \
{ &hf_dlm3_##SYMNAME,                                   \
  { "Internal Flags", "dlm3." STRNAME,                  \
    FT_UINT32, BASE_HEX, NULL, 0x0,                     \
    NULL, HFILL}},                                      \
{ &hf_dlm3_##SYMNAME##_user,                            \
  { "User space lock realted", "dlm3." STRNAME ".user", \
    FT_BOOLEAN, 32, NULL, DLM3_IFL_USER,                \
    NULL, HFILL}},                                      \
{ &hf_dlm3_##SYMNAME##_orphan,                          \
  { "Orphaned lock", "dlm3." STRNAME ".orphan",         \
    FT_BOOLEAN, 32, NULL, DLM3_IFL_ORPHAN,              \
    NULL, HFILL}}

#define DLM3_REGISTER_HF_ASTS(NAME,SIZE)         \
{ &hf_dlm3_##NAME##_asts,                        \
  { "Asynchronous Traps", "dlm3." #NAME ".asts", \
    FT_UINT##SIZE, BASE_HEX, NULL, 0x0,           \
    NULL, HFILL}},                               \
{ &hf_dlm3_##NAME##_asts_comp,                   \
  { "Completion", "dlm3." #NAME ".asts.comp",    \
    FT_BOOLEAN, SIZE, NULL, DLM3_AST_COMP,       \
    NULL, HFILL }},                              \
{ &hf_dlm3_##NAME##_asts_bast,                   \
  { "Blocking", "dlm3." #NAME ".asts.bast",      \
    FT_BOOLEAN, SIZE, NULL, DLM3_AST_BAST,       \
    NULL, HFILL }}

void
proto_register_dlm3(void)
{
  module_t *dlm3_module;


  static hf_register_info hf[] = {
    /* dlm_header */
    { &hf_dlm3_h_version,
      { "Version", "dlm3.h.version",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_h_major_version,
      { "Major Version", "dlm3.h.major_version",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_h_minor_version,
      { "Minor Version", "dlm3.h.minor_version",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_h_lockspace,
      { "Lockspace Global ID", "dlm3.h.lockspac",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_h_nodeid,
      { "Sender Node ID", "dlm3.h.nodeid",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_h_length,
      { "Length", "dlm3.h.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_h_cmd,
      { "Command", "dlm3.h.cmd",
        FT_UINT8, BASE_DEC, VALS(dlm3_cmd), 0x0,
        NULL, HFILL }},
    { &hf_dlm3_h_pad,
      { "Padding", "dlm3.h.pad",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    /* dlm_message */
    { &hf_dlm3_m_type,
      { "Message Type", "dlm3.m.type",
        FT_UINT32, BASE_DEC, VALS(dlm3_msg), 0x0,
        NULL, HFILL }},
    { &hf_dlm3_m_nodeid,
      { "Receiver Node ID", "dlm3.m.nodeid",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_m_pid,
      { "Process ID of Lock Owner", "dlm3.m.pid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    DLM3_REGISTER_HF_LOCKID(m),

    /* dlm_message::exflags */
    DLM3_REGISTER_HF_EXFLAGS(m_exflags, "m.exflags"),

    /* dlm_message::sbflags */
    { &hf_dlm3_m_sbflags,
      { "Status Block Flags", "dlm3.m.sbflags",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},
    { &hf_dlm3_m_sbflags_demoted,
      { "Demoted for deadlock resolution", "dlm3.m.sbflags.demoted",
        FT_BOOLEAN, 32, NULL, DLM3_SBF_DEMOTED,
        NULL, HFILL}},
    { &hf_dlm3_m_sbflags_valnotvalid,
      { "Lock Value Block Is Invalid", "dlm3.m.sbflags.valnotvalid",
        FT_BOOLEAN, 32, NULL, DLM3_SBF_VALNOTVALID,
        NULL, HFILL}},
    { &hf_dlm3_m_sbflags_altmode,
      { "Try to Grant in Alternative Mode", "dlm3.m.sbflags.altmode",
        FT_BOOLEAN, 32, NULL, DLM3_SBF_ALTMODE,
        NULL, HFILL}},

    /* dlm_message::flags */
    DLM3_REGISTER_HF_FLAGS(m_flags, "m.flags"),

    { &hf_dlm3_m_lvbseq,
      { "Lock Value Block Sequence Number", "dlm3.m.lvbseq",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL}},

    { &hf_dlm3_m_hash,
      { "Hash value", "dlm3.m.hash",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL}},

    { &hf_dlm3_m_status,
      { "Status", "dlm3.m.status",
        FT_INT32, BASE_DEC, VALS(dlm3_status), 0x0,
        NULL, HFILL}},

    { &hf_dlm3_m_grmode,
      { "Granted Mode", "dlm3.m.grmode",
        FT_INT32, BASE_DEC, VALS(dlm3_mode), 0x0,
        NULL, HFILL}},
    { &hf_dlm3_m_rqmode,
      { "Request Mode", "dlm3.m.rqmode",
        FT_INT32, BASE_DEC, VALS(dlm3_mode), 0x0,
        NULL, HFILL}},
    { &hf_dlm3_m_bastmode,
      { "Mode requested by another node", "dlm3.m.bastmode",
        FT_INT32, BASE_DEC, VALS(dlm3_mode), 0x0,
        NULL, HFILL}},

    /* dlm_message::asts */
    DLM3_REGISTER_HF_ASTS(m, 32),

    { &hf_dlm3_m_result,
      { "Message Result(errno)", "dlm3.m.result",
        FT_INT32, BASE_DEC, VALS(dlm3_result), 0x0,
        NULL, HFILL}},
    { &hf_dlm3_m_extra,
      { "Extra Message", "dlm3.m.extra",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},

    /* dlm_rcom */
    { &hf_dlm3_rc_type,
      { "Recovery Command Type", "dlm3.rc.type",
        FT_UINT32, BASE_DEC, VALS(dlm3_rcom), 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rc_result,
      { "Recovery Command Result", "dlm3.rc.result",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rc_id,
      { "Recovery Command ID", "dlm3.rc.id",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rc_seq,
      { "Recovery Command Sequence Number of Sender", "dlm3.rc.seq",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rc_seq_reply,
      { "Recovery Command Sequence Number of Receiver", "dlm3.rc.seq_reply",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rc_buf,
      { "Recovery Buffer", "dlm3.rc.buf",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},

    /* rcom_config */
    { &hf_dlm3_rf_lvblen,
      { "Lock Value Block Length", "dlm3.rf.lvblen",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

    /* rcom_config::rf_lsflags */
    DLM3_REGISTER_HF_EXFLAGS(rf_lsflags, "rf.lsflags"),

    { &hf_dlm3_rf_unused,
      { "Unused area", "dlm3.rf.lsflags.unused",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},

    /* rcom_lock */
    { &hf_dlm3_rl_ownpid,
      { "Process ID of Lock Owner", "dlm3.rl.ownpid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

    DLM3_REGISTER_HF_LOCKID(rl),
    DLM3_REGISTER_HF_EXFLAGS(rl_exflags, "rl.exflags"),
    DLM3_REGISTER_HF_FLAGS(rl_flags, "rl.flags"),

    { &hf_dlm3_rl_lvbseq,
      { "Lock Value Block Sequence Number", "dlm3.rl.lvbseq",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rl_result,
      { "Result of Recovering master copy", "dlm3.rl.result",
        FT_INT32, BASE_DEC, VALS(dlm3_result), 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rl_rqmode,
      { "Request Mode", "dlm3.rl.rqmode",
        FT_INT8, BASE_DEC, VALS(dlm3_mode), 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rl_grmode,
      { "Granted Mode", "dlm3.rl.grmode",
        FT_INT8, BASE_DEC, VALS(dlm3_mode), 0x0,
        NULL, HFILL}},
    { &hf_dlm3_rl_status,
      { "Status", "dlm3.rl.status",
        FT_INT8, BASE_DEC, VALS(dlm3_rs), 0x0,
        NULL, HFILL}},
    DLM3_REGISTER_HF_ASTS(rl, 8),

    { &hf_dlm3_rl_wait_type,
      { "Message Type the waiter is waiting for", "dlm3.rl.wait_type",
        FT_UINT16, BASE_DEC, VALS(dlm3_msg), 0x0,
        NULL, HFILL }},

    { &hf_dlm3_rl_namelen,
      { "Length of `name' field", "dlm3.rl.namelen",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_rl_name,
      { "Name of Resource", "dlm3.rl.name",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_rl_name_contents,
      { "Contents actually occupying `name' field", "dlm3.rl.name_contents",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_rl_name_padding,
      { "Padding", "dlm3.rl.name_padding",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlm3_rl_lvb,
      { "Lock Value Block", "dlm3.rl.lvb",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }}
  };

  static gint *ett[] = {
    &ett_dlm3,
    &ett_dlm3_version,

    &ett_dlm3_msg,
    &ett_dlm3_m_exflags,
    &ett_dlm3_sbflags,
    &ett_dlm3_m_flags,
    &ett_dlm3_m_asts,

    &ett_dlm3_rcom,
    &ett_dlm3_rcom_lock,
    &ett_dlm3_rcom_config,

    &ett_dlm3_rf_lsflags,
    &ett_dlm3_rl_exflags,
    &ett_dlm3_rl_flags,
    &ett_dlm3_rl_asts,
    &ett_dlm3_rl_name
  };

  proto_dlm3 = proto_register_protocol("Distributed Lock Manager",
                                       "DLM3", "dlm3");
  proto_register_field_array(proto_dlm3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  dlm3_module = prefs_register_protocol(proto_dlm3,
                                        proto_reg_handoff_dlm3);

  prefs_register_uint_preference(dlm3_module, "tcp.port",
                                 "DLM3 TCP Port",
                                 "Set the TCP port for Distributed Lock Manager",
                                 10,
                                 &dlm3_tcp_port);
  prefs_register_uint_preference(dlm3_module, "sctp.port",
                                 "DLM3 SCTP Port",
                                 "Set the SCTP port for Distributed Lock Manager",
                                 10,
                                 &dlm3_sctp_port);
}


void
proto_reg_handoff_dlm3(void)
{
  static gboolean dissector_registered = FALSE;

  static guint tcp_port;
  static guint sctp_port;

  static dissector_handle_t dlm3_tcp_handle;
  static dissector_handle_t dlm3_sctp_handle;

  if (!dissector_registered) {
    dlm3_sctp_handle = new_create_dissector_handle(dissect_dlm3, proto_dlm3);
    dlm3_tcp_handle = new_create_dissector_handle(dissect_dlm3, proto_dlm3);
    dissector_registered = TRUE;
  } else {
    dissector_delete_uint("tcp.port",  tcp_port,  dlm3_tcp_handle);
    dissector_delete_uint("sctp.port", sctp_port, dlm3_sctp_handle);
  }

  tcp_port  = dlm3_tcp_port;
  sctp_port = dlm3_sctp_port;
  dissector_add_uint("tcp.port",  tcp_port,  dlm3_tcp_handle);
  dissector_add_uint("sctp.port", sctp_port, dlm3_sctp_handle);
}

/* packet-dlm3.c ends here. */
