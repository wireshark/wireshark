/* packet-tcpcl.c
 * References:
 *     RFC 7242: https://tools.ietf.org/html/rfc7242
 *     RFC 9174: https://www.rfc-editor.org/rfc/rfc9174.html
 *
 * TCPCLv4 portions copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
 * Copyright 2006-2007 The MITRE Corporation.
 * All Rights Reserved.
 * Approved for Public Release; Distribution Unlimited.
 * Tracking Number 07-0090.
 *
 * The US Government will not be charged any license fee and/or royalties
 * related to this software. Neither name of The MITRE Corporation; nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification reference:
 * RFC 5050
 * https://tools.ietf.org/html/rfc5050
 */

/*
 *    Modifications were made to this file under designation MFS-33289-1 and
 *    are Copyright 2015 United States Government as represented by NASA
 *       Marshall Space Flight Center. All Rights Reserved.
 *
 *    Released under the GNU GPL with NASA legal approval granted 2016-06-10.
 *
 *    The subject software is provided "AS IS" WITHOUT ANY WARRANTY of any kind,
 *    either expressed, implied or statutory and this agreement does not,
 *    in any manner, constitute an endorsement by government agency of any
 *    results, designs or products resulting from use of the subject software.
 *    See the Agreement for the specific language governing permissions and
 *    limitations.
 */

#include "config.h"

#include <inttypes.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/tvbuff-int.h>
#include <epan/dissectors/packet-tls-utils.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-bpv6.h>
#include "packet-tcpcl.h"

void proto_register_tcpclv3(void);
void proto_reg_handoff_tcpclv3(void);

static const char magic[] = {'d', 't', 'n', '!'};

static int proto_tcpcl = -1;
static int proto_tcpcl_exts = -1;
/// Protocol column name
static const char *const proto_name_tcpcl = "TCPCL";

static gboolean tcpcl_desegment_transfer = TRUE;
static gboolean tcpcl_analyze_sequence = TRUE;
static gboolean tcpcl_decode_bundle = TRUE;

/* For Reassembling TCP Convergence Layer segments */
static reassembly_table xfer_reassembly_table;

/// Dissector handles
static dissector_handle_t tcpcl_handle = NULL;
static dissector_handle_t tls_handle = NULL;
static dissector_handle_t bundle_handle = NULL;

/// Extension sub-dissectors
static dissector_table_t sess_ext_dissectors = NULL;
static dissector_table_t xfer_ext_dissectors = NULL;

static const value_string v3_message_type_vals[] = {
    {((TCPCLV3_DATA_SEGMENT>>4)  & 0x0F), "DATA_SEGMENT"},
    {((TCPCLV3_ACK_SEGMENT>>4)   & 0x0F), "ACK_SEGMENT"},
    {((TCPCLV3_REFUSE_BUNDLE>>4) & 0x0F), "REFUSE_BUNDLE"},
    {((TCPCLV3_KEEP_ALIVE>>4)    & 0x0F), "KEEPALIVE"},
    {((TCPCLV3_SHUTDOWN>>4)      & 0x0F), "SHUTDOWN"},
    {((TCPCLV3_LENGTH>>4)      & 0x0F), "LENGTH"},
    {0, NULL}
};

/* Refuse-Bundle Reason-Code Flags as per RFC-7242: Section-5.4 */
static const value_string v3_refuse_reason_code[] = {
    {TCPCLV3_REFUSE_REASON_UNKNOWN,       "Reason for refusal is unknown"},
    {TCPCLV3_REFUSE_REASON_RX_COMPLETE,   "Complete Bundle Received"},
    {TCPCLV3_REFUSE_REASON_RX_EXHAUSTED,  "Receiver's resources exhausted"},
    {TCPCLV3_REFUSE_REASON_RX_RETRANSMIT, "Receiver expects re-transmission of bundle"},
    {0, NULL}
};

static const value_string v4_message_type_vals[]={
    {TCPCLV4_MSGTYPE_SESS_INIT, "SESS_INIT"},
    {TCPCLV4_MSGTYPE_SESS_TERM, "SESS_TERM"},
    {TCPCLV4_MSGTYPE_MSG_REJECT, "MSG_REJECT"},
    {TCPCLV4_MSGTYPE_KEEPALIVE, "KEEPALIVE"},
    {TCPCLV4_MSGTYPE_XFER_SEGMENT, "XFER_SEGMENT"},
    {TCPCLV4_MSGTYPE_XFER_ACK, "XFER_ACK"},
    {TCPCLV4_MSGTYPE_XFER_REFUSE, "XFER_REFUSE"},
    {0, NULL},
};

static const value_string v4_sess_term_reason_vals[]={
    {0x00, "Unknown"},
    {0x01, "Idle timeout"},
    {0x02, "Version mismatch"},
    {0x03, "Busy"},
    {0x04, "Contact Failure"},
    {0x05, "Resource Exhaustion"},
    {0, NULL},
};

static const value_string v4_xfer_refuse_reason_vals[]={
    {0x00, "Unknown"},
    {0x01, "Completed"},
    {0x02, "No Resources"},
    {0x03, "Retransmit"},
    {0x04, "Not Acceptable"},
    {0x05, "Extension Failure"},
    {0, NULL},
};

static const value_string v4_msg_reject_reason_vals[]={
    {0x00, "reserved"},
    {0x01, "Message Type Unknown"},
    {0x02, "Message Unsupported"},
    {0x03, "Message Unexpected"},
    {0, NULL},
};

static int hf_chdr_tree = -1;
static int hf_chdr_magic = -1;
static int hf_chdr_version = -1;
static int hf_chdr_related = -1;

/* TCP Convergence Header Variables */
static int hf_tcpclv3_mhdr = -1;
static int hf_tcpclv3_pkt_type = -1;

/* Refuse-Bundle reason code */
static int hf_tcpclv3_refuse_reason_code = -1;

static int hf_tcpclv3_chdr_flags = -1;
static int hf_tcpclv3_chdr_keep_alive = -1;
static int hf_tcpclv3_chdr_flags_ack_req = -1;
static int hf_tcpclv3_chdr_flags_frag_enable = -1;
static int hf_tcpclv3_chdr_flags_nak = -1;
static int hf_tcpclv3_chdr_local_eid_length = -1;
static int hf_tcpclv3_chdr_local_eid = -1;

/* TCP Convergence Data Header Variables */
static int hf_tcpclv3_data_procflags = -1;
static int hf_tcpclv3_data_procflags_start = -1;
static int hf_tcpclv3_data_procflags_end = -1;
static int hf_tcpclv3_xfer_id = -1;
static int hf_tcpclv3_data_segment_length = -1;
static int hf_tcpclv3_data_segment_data = -1;

/* TCP Convergence Ack Variables */
static int hf_tcpclv3_ack_length = -1;

/* TCP Convergence Shutdown Header Variables */
static int hf_tcpclv3_shutdown_flags = -1;
static int hf_tcpclv3_shutdown_flags_reason = -1;
static int hf_tcpclv3_shutdown_flags_delay = -1;
static int hf_tcpclv3_shutdown_reason = -1;
static int hf_tcpclv3_shutdown_delay = -1;

static int hf_tcpclv4_chdr_flags = -1;
static int hf_tcpclv4_chdr_flags_cantls = -1;
static int hf_tcpclv4_negotiate_use_tls = -1;

static int hf_tcpclv4_mhdr_tree = -1;
static int hf_tcpclv4_mhdr_type = -1;
static int hf_tcpclv4_sess_init_keepalive = -1;
static int hf_tcpclv4_sess_init_seg_mru = -1;
static int hf_tcpclv4_sess_init_xfer_mru = -1;
static int hf_tcpclv4_sess_init_nodeid_len = -1;
static int hf_tcpclv4_sess_init_nodeid_data = -1;
static int hf_tcpclv4_sess_init_extlist_len = -1;
static int hf_tcpclv4_sess_init_related = -1;
static int hf_tcpclv4_negotiate_keepalive = -1;

static int hf_tcpclv4_sess_term_flags = -1;
static int hf_tcpclv4_sess_term_flags_reply = -1;
static int hf_tcpclv4_sess_term_reason = -1;
static int hf_tcpclv4_sess_term_related = -1;

static int hf_tcpclv4_sessext_tree = -1;
static int hf_tcpclv4_sessext_flags = -1;
static int hf_tcpclv4_sessext_flags_crit = -1;
static int hf_tcpclv4_sessext_type = -1;
static int hf_tcpclv4_sessext_len = -1;
static int hf_tcpclv4_sessext_data = -1;

static int hf_tcpclv4_xferext_tree = -1;
static int hf_tcpclv4_xferext_flags = -1;
static int hf_tcpclv4_xferext_flags_crit = -1;
static int hf_tcpclv4_xferext_type = -1;
static int hf_tcpclv4_xferext_len = -1;
static int hf_tcpclv4_xferext_data = -1;

static int hf_tcpclv4_xfer_flags = -1;
static int hf_tcpclv4_xfer_flags_start = -1;
static int hf_tcpclv4_xfer_flags_end = -1;
static int hf_tcpclv4_xfer_id = -1;
static int hf_tcpclv4_xfer_total_len = -1;
static int hf_tcpclv4_xfer_segment_extlist_len = -1;
static int hf_tcpclv4_xfer_segment_data_len = -1;
static int hf_tcpclv4_xfer_segment_data = -1;
static int hf_tcpclv4_xfer_segment_seen_len = -1;
static int hf_tcpclv4_xfer_segment_related_start = -1;
static int hf_tcpclv4_xfer_segment_time_start = -1;
static int hf_tcpclv4_xfer_segment_related_ack = -1;
static int hf_tcpclv4_xfer_segment_time_diff = -1;
static int hf_tcpclv4_xfer_ack_ack_len = -1;
static int hf_tcpclv4_xfer_ack_related_start = -1;
static int hf_tcpclv4_xfer_ack_time_start = -1;
static int hf_tcpclv4_xfer_ack_related_seg = -1;
static int hf_tcpclv4_xfer_ack_time_diff = -1;
static int hf_tcpclv4_xfer_refuse_reason = -1;
static int hf_tcpclv4_xfer_refuse_related_seg = -1;
static int hf_tcpclv4_msg_reject_reason = -1;
static int hf_tcpclv4_msg_reject_head = -1;

static int hf_tcpclv4_xferext_transferlen_total_len = -1;

static int hf_othername_bundleeid = -1;

/*TCP Convergence Layer Reassembly boilerplate*/
static int hf_xfer_fragments = -1;
static int hf_xfer_fragment = -1;
static int hf_xfer_fragment_overlap = -1;
static int hf_xfer_fragment_overlap_conflicts = -1;
static int hf_xfer_fragment_multiple_tails = -1;
static int hf_xfer_fragment_too_long_fragment = -1;
static int hf_xfer_fragment_error = -1;
static int hf_xfer_fragment_count = -1;
static int hf_xfer_reassembled_in = -1;
static int hf_xfer_reassembled_length = -1;
static int hf_xfer_reassembled_data = -1;

static hf_register_info hf_tcpcl[] = {
    {&hf_chdr_tree, {"Contact Header", "tcpcl.contact_hdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_magic, {"Protocol Magic", "tcpcl.contact_hdr.magic", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_version, {"Version", "tcpcl.contact_hdr.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_chdr_related, {"Related Header", "tcpcl.contact_hdr.related", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_tcpclv3_mhdr,
     {"TCPCLv3 Header", "tcpcl.mhdr",
      FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_pkt_type,
     {"Message Type", "tcpcl.pkt_type",
      FT_UINT8, BASE_DEC, VALS(v3_message_type_vals), 0xF0, NULL, HFILL}
    },
    {&hf_tcpclv3_refuse_reason_code,
     {"Reason-Code", "tcpcl.refuse.reason_code",
      FT_UINT8, BASE_DEC, VALS(v3_refuse_reason_code), 0x0F, NULL, HFILL}
    },
    {&hf_tcpclv3_data_procflags,
     {"Data Flags", "tcpcl.data.proc.flag",
      FT_UINT8, BASE_HEX, NULL, TCPCLV3_DATA_FLAGS, NULL, HFILL}
    },
    {&hf_tcpclv3_data_procflags_start,
     {"Segment contains start of bundle", "tcpcl.data.proc.start",
      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV3_DATA_START_FLAG, NULL, HFILL}
    },
    {&hf_tcpclv3_data_procflags_end,
     {"Segment contains end of Bundle", "tcpcl.data.proc.end",
      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV3_DATA_END_FLAG, NULL, HFILL}
    },
    {&hf_tcpclv3_xfer_id, {"Implied Transfer ID", "tcpcl.xfer_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv3_data_segment_length,
     {"Segment Length", "tcpcl.data.length",
      FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_data_segment_data,
     {"Segment Data", "tcpcl.data",
      FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_shutdown_flags,
     {"TCP Convergence Shutdown Flags", "tcpcl.shutdown.flags",
      FT_UINT8, BASE_HEX, NULL, TCPCLV3_SHUTDOWN_FLAGS, NULL, HFILL}
    },
    {&hf_tcpclv3_shutdown_flags_reason,
     {"Shutdown includes Reason Code", "tcpcl.shutdown.reason.flag",
      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV3_SHUTDOWN_REASON, NULL, HFILL}
    },
    {&hf_tcpclv3_shutdown_flags_delay,
     {"Shutdown includes Reconnection Delay", "tcpcl.shutdown.delay.flag",
      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV3_SHUTDOWN_DELAY, NULL, HFILL}
    },
    {&hf_tcpclv3_shutdown_reason,
     {"Shutdown Reason Code", "tcpcl.shutdown.reason",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_shutdown_delay,
     {"Shutdown Reconnection Delay", "tcpcl.shutdown.delay",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_ack_length,
     {"Ack Length", "tcpcl.ack.length",
      FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_chdr_flags,
     {"Flags", "tcpcl.contact_hdr.flags",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_chdr_flags_ack_req,
     {"Bundle Acks Requested", "tcpcl.contact_hdr.flags.ackreq",
      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV3_BUNDLE_ACK_FLAG, NULL, HFILL}
    },
    {&hf_tcpclv3_chdr_flags_frag_enable,
     {"Reactive Fragmentation Enabled", "tcpcl.contact_hdr.flags.fragen",
      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV3_REACTIVE_FRAG_FLAG, NULL, HFILL}
    },
    {&hf_tcpclv3_chdr_flags_nak,
     {"Support Negative Acknowledgements", "tcpcl.contact_hdr.flags.nak",
      FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV3_CONNECTOR_RCVR_FLAG, NULL, HFILL}
    },
    {&hf_tcpclv3_chdr_keep_alive,
     {"Keep Alive", "tcpcl.contact_hdr.keep_alive",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_chdr_local_eid,
     {"Local EID", "tcpcl.contact_hdr.local_eid",
      FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_tcpclv3_chdr_local_eid_length,
     {"Local EID Length", "tcpcl.contact_hdr.local_eid_length",
      FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },

    {&hf_tcpclv4_chdr_flags, {"Contact Flags", "tcpcl.v4.chdr.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_chdr_flags_cantls, {"CAN_TLS", "tcpcl.v4.chdr.flags.can_tls", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV4_CONTACT_FLAG_CANTLS, NULL, HFILL}},
    // Contact negotiation results
    {&hf_tcpclv4_negotiate_use_tls, {"Negotiated Use TLS", "tcpcl.v4.negotiated.use_tls", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_tcpclv4_mhdr_tree, {"TCPCLv4 Message", "tcpcl.v4.mhdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_mhdr_type, {"Message Type", "tcpcl.v4.mhdr.type", FT_UINT8, BASE_HEX, VALS(v4_message_type_vals), 0x0, NULL, HFILL}},

    // Session extension fields
    {&hf_tcpclv4_sessext_tree, {"Session Extension Item", "tcpcl.v4.sessext", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sessext_flags, {"Item Flags", "tcpcl.v4.sessext.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sessext_flags_crit, {"CRITICAL", "tcpcl.v4.sessext.flags.critical", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV4_EXTENSION_FLAG_CRITICAL, NULL, HFILL}},
    {&hf_tcpclv4_sessext_type, {"Item Type", "tcpcl.v4.sessext.type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sessext_len, {"Item Length", "tcpcl.v4.sessext.len", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sessext_data, {"Type-Specific Data", "tcpcl.v4.sessext.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    // Transfer extension fields
    {&hf_tcpclv4_xferext_tree, {"Transfer Extension Item", "tcpcl.v4.xferext", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xferext_flags, {"Item Flags", "tcpcl.v4.xferext.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xferext_flags_crit, {"CRITICAL", "tcpcl.v4.xferext.flags.critical", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV4_EXTENSION_FLAG_CRITICAL, NULL, HFILL}},
    {&hf_tcpclv4_xferext_type, {"Item Type", "tcpcl.v4.xferext.type", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xferext_len, {"Item Length", "tcpcl.v4.xferext.len", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xferext_data, {"Type-Specific Data", "tcpcl.v4.xferext.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    // SESS_INIT fields
    {&hf_tcpclv4_sess_init_keepalive, {"Keepalive Interval", "tcpcl.v4.sess_init.keepalive", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sess_init_seg_mru, {"Segment MRU", "tcpcl.v4.sess_init.seg_mru", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sess_init_xfer_mru, {"Transfer MRU", "tcpcl.v4.sess_init.xfer_mru", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sess_init_nodeid_len, {"Node ID Length", "tcpcl.v4.sess_init.nodeid_len", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sess_init_nodeid_data, {"Node ID Data (UTF8)", "tcpcl.v4.sess_init.nodeid_data", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sess_init_extlist_len, {"Extension Items Length", "tcpcl.v4.sess_init.extlist_len", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sess_init_related, {"Related SESS_INIT", "tcpcl.v4.sess_init.related", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    // Session negotiation results
    {&hf_tcpclv4_negotiate_keepalive, {"Negotiated Keepalive Interval", "tcpcl.v4.negotiated.keepalive", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0x0, NULL, HFILL}},
    // SESS_TERM fields
    {&hf_tcpclv4_sess_term_flags, {"Flags", "tcpcl.v4.sess_term.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sess_term_flags_reply, {"REPLY", "tcpcl.v4.sess_term.flags.reply", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV4_SESS_TERM_FLAG_REPLY, NULL, HFILL}},
    {&hf_tcpclv4_sess_term_reason, {"Reason", "tcpcl.v4.ses_term.reason", FT_UINT8, BASE_DEC, VALS(v4_sess_term_reason_vals), 0x0, NULL, HFILL}},
    {&hf_tcpclv4_sess_term_related, {"Related SESS_TERM", "tcpcl.v4.ses_term.related", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    // Common transfer fields
    {&hf_tcpclv4_xfer_flags, {"Transfer Flags", "tcpcl.v4.xfer_flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_flags_start, {"START", "tcpcl.v4.xfer_flags.start", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV4_TRANSFER_FLAG_START, NULL, HFILL}},
    {&hf_tcpclv4_xfer_flags_end, {"END", "tcpcl.v4.xfer_flags.end", FT_BOOLEAN, 8, TFS(&tfs_set_notset), TCPCLV4_TRANSFER_FLAG_END, NULL, HFILL}},
    {&hf_tcpclv4_xfer_id, {"Transfer ID", "tcpcl.v4.xfer_id", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_total_len, {"Expected Total Length", "tcpcl.v4.xfer.total_len", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    // XFER_SEGMENT fields
    {&hf_tcpclv4_xfer_segment_extlist_len, {"Extension Items Length", "tcpcl.v4.xfer_segment.extlist_len", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_segment_data_len, {"Segment Length", "tcpcl.v4.xfer_segment.data_len", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_segment_data, {"Segment Data", "tcpcl.v4.xfer_segment.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_segment_seen_len, {"Seen Length", "tcpcl.v4.xfer_segment.seen_len", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_segment_related_start, {"Related XFER_SEGMENT start", "tcpcl.v4.xfer_segment.related_start", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_segment_time_start, {"Time since transfer Start", "tcpcl.v4.xfer_segment.time_since_start", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_segment_related_ack, {"Related XFER_ACK", "tcpcl.v4.xfer_segment.related_ack", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_segment_time_diff, {"Acknowledgment Time", "tcpcl.v4.xfer_segment.time_diff", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    // XFER_ACK fields
    {&hf_tcpclv4_xfer_ack_ack_len, {"Acknowledged Length", "tcpcl.v4.xfer_ack.ack_len", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_ack_related_start, {"Related XFER_SEGMENT start", "tcpcl.v4.xfer_ack.related_start", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_ack_time_start, {"Time since transfer Start", "tcpcl.v4.xfer_ack.time_since_start", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_ack_related_seg, {"Related XFER_SEGMENT", "tcpcl.v4.xfer_ack.related_seg", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_ack_time_diff, {"Acknowledgment Time", "tcpcl.v4.xfer_ack.time_diff", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    // XFER_REFUSE fields
    {&hf_tcpclv4_xfer_refuse_reason, {"Reason", "tcpcl.v4.xfer_refuse.reason", FT_UINT8, BASE_DEC, VALS(v4_xfer_refuse_reason_vals), 0x0, NULL, HFILL}},
    {&hf_tcpclv4_xfer_refuse_related_seg, {"Related XFER_SEGMENT", "tcpcl.v4.xfer_refuse.related_seg", FT_FRAMENUM, BASE_NONE, VALS(v4_xfer_refuse_reason_vals), 0x0, NULL, HFILL}},
    // MSG_REJECT fields
    {&hf_tcpclv4_msg_reject_reason, {"Reason", "tcpcl.v4.msg_reject.reason", FT_UINT8, BASE_DEC, VALS(v4_msg_reject_reason_vals), 0x0, NULL, HFILL}},
    {&hf_tcpclv4_msg_reject_head, {"Rejected Type", "tcpcl.v4.msg_reject.head", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},

    // Specific extensions
    {&hf_tcpclv4_xferext_transferlen_total_len, {"Total Length", "tcpcl.v4.xferext.transfer_length.total_len", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, &units_octet_octets, 0x0, NULL, HFILL}},
    // PKIX other name form
    {&hf_othername_bundleeid, {"BundleEID", "tcpcl.v4.BundleEID", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},

    {&hf_xfer_fragments,
        {"Transfer fragments", "tcpcl.xfer.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_fragment,
        {"Transfer fragment", "tcpcl.xfer.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_fragment_overlap,
        {"Transfer fragment overlap", "tcpcl.xfer.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_fragment_overlap_conflicts,
        {"Transfer fragment overlapping with conflicting data",
        "tcpcl.xfer.fragment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_fragment_multiple_tails,
        {"Message has multiple tail fragments",
        "tcpcl.xfer.fragment.multiple_tails",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_fragment_too_long_fragment,
        {"Transfer fragment too long", "tcpcl.xfer.fragment.too_long_fragment",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_fragment_error,
        {"Transfer defragmentation error", "tcpcl.xfer.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_fragment_count,
        {"Transfer fragment count", "tcpcl.xfer.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_reassembled_in,
        {"Reassembled in", "tcpcl.xfer.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_reassembled_length,
        {"Reassembled length", "tcpcl.xfer.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    {&hf_xfer_reassembled_data,
        {"Reassembled data", "tcpcl.xfer.reassembled.data",
        FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

};

static int *const v3_chdr_flags[] = {
    &hf_tcpclv3_chdr_flags_ack_req,
    &hf_tcpclv3_chdr_flags_frag_enable,
    &hf_tcpclv3_chdr_flags_nak,
    NULL
};

static int *const v3_data_procflags[] = {
    &hf_tcpclv3_data_procflags_start,
    &hf_tcpclv3_data_procflags_end,
    NULL
};
static int *const v4_chdr_flags[] = {
    &hf_tcpclv4_chdr_flags_cantls,
    NULL
};
static int *const v4_sess_term_flags[] = {
    &hf_tcpclv4_sess_term_flags_reply,
    NULL
};
static int *const v4_xfer_flags[] = {
    &hf_tcpclv4_xfer_flags_start,
    &hf_tcpclv4_xfer_flags_end,
    NULL
};
static int *const v4_sessext_flags[] = {
    &hf_tcpclv4_sessext_flags_crit,
    NULL
};
static int *const v4_xferext_flags[] = {
    &hf_tcpclv4_xferext_flags_crit,
    NULL
};

/* Tree Node Variables */
static gint ett_proto_tcpcl = -1;
static gint ett_chdr = -1;
static gint ett_tcpclv3_chdr_flags = -1;
static gint ett_tcpclv3_mhdr = -1;
static gint ett_tcpclv3_data_procflags = -1;
static gint ett_tcpclv3_shutdown_flags = -1;
static gint ett_xfer_fragment = -1;
static gint ett_xfer_fragments = -1;
static gint ett_tcpclv4_chdr_flags = -1;
static gint ett_tcpclv4_mhdr = -1;
static gint ett_tcpclv4_sess_term_flags = -1;
static gint ett_tcpclv4_xfer_flags = -1;
static gint ett_tcpclv4_sessext = -1;
static gint ett_tcpclv4_sessext_flags = -1;
static gint ett_tcpclv4_sessext_data = -1;
static gint ett_tcpclv4_xferext = -1;
static gint ett_tcpclv4_xferext_flags = -1;
static gint ett_tcpclv4_xferext_data = -1;

static gint *ett[] = {
    &ett_proto_tcpcl,
    &ett_chdr,
    &ett_tcpclv3_chdr_flags,
    &ett_tcpclv3_mhdr,
    &ett_tcpclv3_data_procflags,
    &ett_tcpclv3_shutdown_flags,
    &ett_tcpclv4_chdr_flags,
    &ett_tcpclv4_mhdr,
    &ett_tcpclv4_sess_term_flags,
    &ett_tcpclv4_xfer_flags,
    &ett_tcpclv4_sessext,
    &ett_tcpclv4_sessext_flags,
    &ett_tcpclv4_sessext_data,
    &ett_tcpclv4_xferext,
    &ett_tcpclv4_xferext_flags,
    &ett_tcpclv4_xferext_data,
    &ett_xfer_fragment,
    &ett_xfer_fragments,
};

static expert_field ei_invalid_magic = EI_INIT;
static expert_field ei_invalid_version = EI_INIT;
static expert_field ei_mismatch_version = EI_INIT;
static expert_field ei_chdr_duplicate = EI_INIT;

static expert_field ei_tcpclv3_invalid_msg_type = EI_INIT;
static expert_field ei_tcpclv3_data_flags = EI_INIT;
static expert_field ei_tcpclv3_segment_length = EI_INIT;
static expert_field ei_tcpclv3_ack_length = EI_INIT;

static expert_field ei_tcpclv4_invalid_msg_type = EI_INIT;
static expert_field ei_tcpclv4_invalid_sessext_type = EI_INIT;
static expert_field ei_tcpclv4_invalid_xferext_type = EI_INIT;
static expert_field ei_tcpclv4_extitem_critical = EI_INIT;
static expert_field ei_tcpclv4_sess_init_missing = EI_INIT;
static expert_field ei_tcpclv4_sess_init_duplicate = EI_INIT;
static expert_field ei_tcpclv4_sess_term_duplicate = EI_INIT;
static expert_field ei_tcpclv4_sess_term_reply_flag = EI_INIT;
static expert_field ei_tcpclv4_xfer_seg_over_seg_mru = EI_INIT;
static expert_field ei_tcpclv4_xfer_seg_missing_start = EI_INIT;
static expert_field ei_tcpclv4_xfer_seg_duplicate_start = EI_INIT;
static expert_field ei_tcpclv4_xfer_seg_missing_end = EI_INIT;
static expert_field ei_tcpclv4_xfer_seg_duplicate_end = EI_INIT;
static expert_field ei_tcpclv4_xfer_seg_no_relation = EI_INIT;
static expert_field ei_xfer_seg_over_total_len = EI_INIT;
static expert_field ei_xfer_mismatch_total_len = EI_INIT;
static expert_field ei_xfer_ack_mismatch_flags = EI_INIT;
static expert_field ei_xfer_ack_no_relation = EI_INIT;
static expert_field ei_tcpclv4_xfer_refuse_no_transfer = EI_INIT;
static expert_field ei_tcpclv4_xferload_over_xfer_mru = EI_INIT;

static ei_register_info ei_tcpcl[] = {
    {&ei_invalid_magic, { "tcpcl.invalid_contact_magic", PI_PROTOCOL, PI_ERROR, "Magic string is invalid", EXPFILL}},
    {&ei_invalid_version, { "tcpcl.invalid_contact_version", PI_PROTOCOL, PI_ERROR, "Protocol version not handled", EXPFILL}},
    {&ei_mismatch_version, { "tcpcl.mismatch_contact_version", PI_PROTOCOL, PI_ERROR, "Protocol version mismatch", EXPFILL}},
    {&ei_chdr_duplicate, { "tcpcl.contact_duplicate", PI_SEQUENCE, PI_ERROR, "Duplicate Contact Header", EXPFILL}},

    {&ei_tcpclv3_invalid_msg_type, { "tcpcl.unknown_message_type", PI_UNDECODED, PI_ERROR, "Message type is unknown", EXPFILL}},
    {&ei_tcpclv3_data_flags, { "tcpcl.data.flags.invalid", PI_PROTOCOL, PI_WARN, "Invalid TCP CL Data Segment Flags", EXPFILL }},
    {&ei_tcpclv3_segment_length, { "tcpcl.data.length.invalid", PI_PROTOCOL, PI_ERROR, "Invalid Data Length", EXPFILL }},
    {&ei_tcpclv3_ack_length, { "tcpcl.ack.length.error", PI_PROTOCOL, PI_WARN, "Ack Length: Error", EXPFILL }},

    {&ei_tcpclv4_invalid_msg_type, { "tcpcl.v4.unknown_message_type", PI_UNDECODED, PI_ERROR, "Message type is unknown", EXPFILL}},
    {&ei_tcpclv4_invalid_sessext_type, { "tcpcl.v4.unknown_sessext_type", PI_UNDECODED, PI_WARN, "Session Extension type is unknown", EXPFILL}},
    {&ei_tcpclv4_invalid_xferext_type, { "tcpcl.v4.unknown_xferext_type", PI_UNDECODED, PI_WARN, "Transfer Extension type is unknown", EXPFILL}},
    {&ei_tcpclv4_extitem_critical, { "tcpcl.v4.extitem_critical", PI_REQUEST_CODE, PI_CHAT, "Extension Item is critical", EXPFILL}},
    {&ei_tcpclv4_sess_init_missing, { "tcpcl.v4.sess_init_missing", PI_SEQUENCE, PI_ERROR, "Expected SESS_INIT message first", EXPFILL}},
    {&ei_tcpclv4_sess_init_duplicate, { "tcpcl.v4.sess_init_duplicate", PI_SEQUENCE, PI_ERROR, "Duplicate SESS_INIT message", EXPFILL}},
    {&ei_tcpclv4_sess_term_duplicate, { "tcpcl.v4.sess_term_duplicate", PI_SEQUENCE, PI_ERROR, "Duplicate SESS_TERM message", EXPFILL}},
    {&ei_tcpclv4_sess_term_reply_flag, { "tcpcl.v4.sess_term_reply_flag", PI_SEQUENCE, PI_ERROR, "Reply SESS_TERM missing flag", EXPFILL}},
    {&ei_tcpclv4_xfer_seg_over_seg_mru, { "tcpcl.v4.xfer_seg_over_seg_mru", PI_PROTOCOL, PI_WARN, "Segment data size larger than peer MRU", EXPFILL}},
    {&ei_tcpclv4_xfer_seg_missing_start, { "tcpcl.v4.xfer_seg_missing_start", PI_SEQUENCE, PI_ERROR, "First XFER_SEGMENT is missing START flag", EXPFILL}},
    {&ei_tcpclv4_xfer_seg_duplicate_start, { "tcpcl.v4.xfer_seg_duplicate_start", PI_SEQUENCE, PI_ERROR, "Non-first XFER_SEGMENT has START flag", EXPFILL}},
    {&ei_tcpclv4_xfer_seg_missing_end, { "tcpcl.v4.xfer_seg_missing_end", PI_SEQUENCE, PI_ERROR, "Last XFER_SEGMENT is missing END flag", EXPFILL}},
    {&ei_tcpclv4_xfer_seg_duplicate_end, { "tcpcl.v4.xfer_seg_duplicate_end", PI_SEQUENCE, PI_ERROR, "Non-last XFER_SEGMENT has END flag", EXPFILL}},
    {&ei_tcpclv4_xfer_seg_no_relation, { "tcpcl.v4.xfer_seg_no_relation", PI_SEQUENCE, PI_NOTE, "XFER_SEGMENT has no related XFER_ACK", EXPFILL}},
    {&ei_tcpclv4_xfer_refuse_no_transfer, { "tcpcl.v4.xfer_refuse_no_transfer", PI_SEQUENCE, PI_NOTE, "XFER_REFUSE has no related XFER_SEGMENT(s)", EXPFILL}},
    {&ei_tcpclv4_xferload_over_xfer_mru, { "tcpcl.v4.xferload_over_xfer_mru", PI_SEQUENCE, PI_NOTE, "Transfer larger than peer MRU", EXPFILL}},
    {&ei_xfer_seg_over_total_len, { "tcpcl.xfer_seg_over_total_len", PI_SEQUENCE, PI_ERROR, "XFER_SEGMENT has accumulated length beyond the Transfer Length extension", EXPFILL}},
    {&ei_xfer_mismatch_total_len, { "tcpcl.xfer_mismatch_total_len", PI_SEQUENCE, PI_ERROR, "Transfer has total length different than the Transfer Length extension", EXPFILL}},
    {&ei_xfer_ack_mismatch_flags, { "tcpcl.xfer_ack_mismatch_flags", PI_SEQUENCE, PI_ERROR, "XFER_ACK does not have flags matching XFER_SEGMENT", EXPFILL}},
    {&ei_xfer_ack_no_relation, { "tcpcl.xfer_ack_no_relation", PI_SEQUENCE, PI_NOTE, "XFER_ACK has no related XFER_SEGMENT", EXPFILL}},
};

static const fragment_items xfer_frag_items = {
    /*Fragment subtrees*/
    &ett_xfer_fragment,
    &ett_xfer_fragments,
    /*Fragment Fields*/
    &hf_xfer_fragments,
    &hf_xfer_fragment,
    &hf_xfer_fragment_overlap,
    &hf_xfer_fragment_overlap_conflicts,
    &hf_xfer_fragment_multiple_tails,
    &hf_xfer_fragment_too_long_fragment,
    &hf_xfer_fragment_error,
    &hf_xfer_fragment_count,
    /*Reassembled in field*/
    &hf_xfer_reassembled_in,
    /*Reassembled length field*/
    &hf_xfer_reassembled_length,
    /* Reassembled data field */
    &hf_xfer_reassembled_data,
    /*Tag*/
    "Transfer fragments"
};

static void tcpcl_frame_loc_init(tcpcl_frame_loc_t *loc, const packet_info *pinfo, tvbuff_t *tvb, const gint offset) {
    loc->frame_num = pinfo->num;
    // This is a messy way to determine the index,
    // but no other public functions allow determining how two TVB are related
    loc->src_ix = -1;
    for(GSList *srcit = pinfo->data_src; srcit != NULL; srcit = g_slist_next(srcit)) {
        ++(loc->src_ix);
        struct data_source *src = srcit->data;
        if (get_data_source_tvb(src)->real_data == tvb->real_data) {
            break;
        }
    }
    loc->raw_offset = tvb_raw_offset(tvb) + offset;
}

/** Construct a new object on the file allocator.
 */
static tcpcl_frame_loc_t * tcpcl_frame_loc_new(wmem_allocator_t *alloc, const packet_info *pinfo, tvbuff_t *tvb, const gint offset) {
    tcpcl_frame_loc_t *obj = wmem_new(alloc, tcpcl_frame_loc_t);
    tcpcl_frame_loc_init(obj, pinfo, tvb, offset);
    return obj;
}

/** Construct a new object on the file allocator.
 */
static tcpcl_frame_loc_t * tcpcl_frame_loc_clone(wmem_allocator_t *alloc, const tcpcl_frame_loc_t *loc) {
    tcpcl_frame_loc_t *obj = wmem_new(alloc, tcpcl_frame_loc_t);
    *obj = *loc;
    return obj;
}

#define tcpcl_frame_loc_free wmem_free

/** Function to match the GCompareDataFunc signature.
 */
static gint tcpcl_frame_loc_compare(gconstpointer a, gconstpointer b, gpointer user_data _U_) {
    const tcpcl_frame_loc_t *aloc = a;
    const tcpcl_frame_loc_t *bloc = b;

    if (aloc->frame_num < bloc->frame_num) {
        return -1;
    }
    else if (aloc->frame_num > bloc->frame_num) {
        return 1;
    }

    if (aloc->raw_offset < bloc->raw_offset) {
        return -1;
    }
    else if (aloc->raw_offset > bloc->raw_offset) {
        return 1;
    }
    return 0;
}

/** Function to match the GCompareFunc signature.
 */
static gboolean tcpcl_frame_loc_equal(gconstpointer a, gconstpointer b) {
    const tcpcl_frame_loc_t *aobj = a;
    const tcpcl_frame_loc_t *bobj = b;
    return (
        (aobj->frame_num == bobj->frame_num)
        && (aobj->raw_offset == bobj->raw_offset)
    );
}

/** Function to match the GHashFunc signature.
 */
static guint tcpcl_frame_loc_hash(gconstpointer key) {
    const tcpcl_frame_loc_t *obj = key;
    return (
        g_int_hash(&(obj->frame_num))
        ^ g_int64_hash(&(obj->raw_offset))
    );
}

struct tcpcl_ack_meta;
typedef struct tcpcl_ack_meta tcpcl_ack_meta_t;
struct tcpcl_seg_meta;
typedef struct tcpcl_seg_meta tcpcl_seg_meta_t;

struct tcpcl_seg_meta {
    /// Location associated with this metadata
    tcpcl_frame_loc_t frame_loc;
    /// Timestamp on the frame (end time if reassembled)
    nstime_t frame_time;
    /// Copy of message flags
    guint8 flags;
    /// Total transfer length including this segment
    guint64 seen_len;

    /// Potential related start segment
    tcpcl_seg_meta_t *related_start;
    /// Potential related XFER_ACK
    tcpcl_ack_meta_t *related_ack;
};

static tcpcl_seg_meta_t * tcpcl_seg_meta_new(const packet_info *pinfo, const tcpcl_frame_loc_t *loc) {
    tcpcl_seg_meta_t *obj = wmem_new(wmem_file_scope(), tcpcl_seg_meta_t);
    obj->frame_loc = *loc;
    obj->frame_time = pinfo->abs_ts;
    obj->flags = 0;
    obj->seen_len = 0;
    obj->related_start = NULL;
    obj->related_ack = NULL;
    return obj;
}

static void tcpcl_seg_meta_free(tcpcl_seg_meta_t *obj) {
    wmem_free(wmem_file_scope(), obj);
}

/** Function to match the GCompareFunc signature.
 */
static gint tcpcl_seg_meta_compare_loc(gconstpointer a, gconstpointer b) {
    return tcpcl_frame_loc_compare(
        &(((tcpcl_seg_meta_t *)a)->frame_loc),
        &(((tcpcl_seg_meta_t *)b)->frame_loc),
        NULL
    );
}

struct tcpcl_ack_meta {
    /// Location associated with this metadata
    tcpcl_frame_loc_t frame_loc;
    /// Timestamp on the frame (end time if reassembled)
    nstime_t frame_time;
    /// Copy of message flags
    guint8 flags;
    /// Total acknowledged length including this ack
    guint64 seen_len;

    /// Potential related start segment
    tcpcl_seg_meta_t *related_start;
    /// Potential related XFER_SEGMENT
    tcpcl_seg_meta_t *related_seg;
};

static tcpcl_ack_meta_t * tcpcl_ack_meta_new(const packet_info *pinfo, const tcpcl_frame_loc_t *loc) {
    tcpcl_ack_meta_t *obj = wmem_new(wmem_file_scope(), tcpcl_ack_meta_t);
    obj->frame_loc = *loc;
    obj->frame_time = pinfo->abs_ts;
    obj->flags = 0;
    obj->seen_len = 0;
    obj->related_start = NULL;
    obj->related_seg = NULL;
    return obj;
}

static void tcpcl_ack_meta_free(tcpcl_ack_meta_t *obj) {
    wmem_free(wmem_file_scope(), obj);
}

/** Function to match the GCompareFunc signature.
 */
static gint tcpcl_ack_meta_compare_loc(gconstpointer a, gconstpointer b) {
    return tcpcl_frame_loc_compare(
        &(((tcpcl_seg_meta_t *)a)->frame_loc),
        &(((tcpcl_seg_meta_t *)b)->frame_loc),
        NULL
    );
}

static tcpcl_transfer_t * tcpcl_transfer_new(void) {
    tcpcl_transfer_t *obj = wmem_new(wmem_file_scope(), tcpcl_transfer_t);
    obj->seg_list = wmem_list_new(wmem_file_scope());
    obj->ack_list = wmem_list_new(wmem_file_scope());
    obj->total_length = NULL;
    return obj;
}

static tcpcl_transfer_t * get_or_create_transfer_t(wmem_map_t *table, const guint64 xfer_id) {
    tcpcl_transfer_t *xfer = wmem_map_lookup(table, &xfer_id);
    if (!xfer) {
        guint64 *key = wmem_new(wmem_file_scope(), guint64);
        *key = xfer_id;
        xfer = tcpcl_transfer_new();
        wmem_map_insert(table, key, xfer);
    }
    return xfer;
}

static tcpcl_peer_t * tcpcl_peer_new(void) {
    tcpcl_peer_t *obj = wmem_new0(wmem_file_scope(), tcpcl_peer_t);
    clear_address(&(obj->addr));
    obj->frame_loc_to_transfer = wmem_map_new(wmem_file_scope(), tcpcl_frame_loc_hash, tcpcl_frame_loc_equal);
    obj->transfers = wmem_map_new(wmem_file_scope(), g_int64_hash, g_int64_equal);
    return obj;
}

static void tcpcl_peer_associate_transfer(tcpcl_peer_t *peer, const tcpcl_frame_loc_t *loc, const guint64 xfer_id) {
    gpointer *xfer = wmem_map_lookup(peer->frame_loc_to_transfer, loc);
    if (!xfer) {
        tcpcl_frame_loc_t *key = tcpcl_frame_loc_clone(wmem_file_scope(), loc);
        guint64 *val = wmem_new(wmem_file_scope(), guint64);
        *val = xfer_id;
        wmem_map_insert(peer->frame_loc_to_transfer, key, val);
    }
}

static tcpcl_conversation_t * tcpcl_conversation_new(void) {
    tcpcl_conversation_t *obj = wmem_new0(wmem_file_scope(), tcpcl_conversation_t);
    obj->active = tcpcl_peer_new();
    obj->passive = tcpcl_peer_new();
    return obj;
}

tcpcl_dissect_ctx_t * tcpcl_dissect_ctx_get(tvbuff_t *tvb, packet_info *pinfo, const gint offset) {
    conversation_t *convo = find_or_create_conversation(pinfo);
    tcpcl_conversation_t *tcpcl_convo = (tcpcl_conversation_t *)conversation_get_proto_data(convo, proto_tcpcl);
    if (!tcpcl_convo) {
        return NULL;
    }
    tcpcl_dissect_ctx_t *ctx = wmem_new0(wmem_packet_scope(), tcpcl_dissect_ctx_t);
    ctx->convo = tcpcl_convo;
    ctx->cur_loc = tcpcl_frame_loc_new(wmem_packet_scope(), pinfo, tvb, offset);

    const gboolean src_is_active = (
        addresses_equal(&(ctx->convo->active->addr), &(pinfo->src))
        && (ctx->convo->active->port == pinfo->srcport)
    );
    if (src_is_active) {
        ctx->tx_peer = ctx->convo->active;
        ctx->rx_peer = ctx->convo->passive;
    }
    else {
        ctx->tx_peer = ctx->convo->passive;
        ctx->rx_peer = ctx->convo->active;
    }

    ctx->is_contact = (
        !(ctx->tx_peer->chdr_seen)
        || tcpcl_frame_loc_equal(ctx->tx_peer->chdr_seen, ctx->cur_loc)
    );

    return ctx;
}

static void try_negotiate(tcpcl_dissect_ctx_t *ctx, packet_info *pinfo) {
    if (!(ctx->convo->contact_negotiated)
        && (ctx->convo->active->chdr_seen)
        && (ctx->convo->passive->chdr_seen)) {
        ctx->convo->session_use_tls = (
            ctx->convo->active->can_tls & ctx->convo->passive->can_tls
        );
        ctx->convo->contact_negotiated = TRUE;

        if (ctx->convo->session_use_tls
            && (!(ctx->convo->session_tls_start))) {
            col_append_str(pinfo->cinfo, COL_INFO, " [STARTTLS]");
            ctx->convo->session_tls_start = tcpcl_frame_loc_clone(wmem_file_scope(), ctx->cur_loc);
            ssl_starttls_ack(tls_handle, pinfo, tcpcl_handle);
        }
    }

    if (!(ctx->convo->sess_negotiated)
        && (ctx->convo->active->sess_init_seen)
        && (ctx->convo->passive->sess_init_seen)) {
        ctx->convo->sess_keepalive = MIN(
            ctx->convo->active->keepalive,
            ctx->convo->passive->keepalive
        );
        ctx->convo->sess_negotiated = TRUE;

    }
}

typedef struct {
    // key type for addresses_ports_reassembly_table_functions
    void *addr_port;
    // TCPCL ID
    guint64 xfer_id;
} tcpcl_fragment_key_t;

static guint fragment_key_hash(gconstpointer ptr) {
    const tcpcl_fragment_key_t *obj = (const tcpcl_fragment_key_t *)ptr;
    return (
        addresses_ports_reassembly_table_functions.hash_func(obj->addr_port)
        ^ g_int64_hash(&(obj->xfer_id))
    );
}

static gboolean fragment_key_equal(gconstpointer ptrA, gconstpointer ptrB) {
    const tcpcl_fragment_key_t *objA = (const tcpcl_fragment_key_t *)ptrA;
    const tcpcl_fragment_key_t *objB = (const tcpcl_fragment_key_t *)ptrB;
    return (
        addresses_ports_reassembly_table_functions.equal_func(objA->addr_port, objB->addr_port)
        && (objA->xfer_id == objB->xfer_id)
    );
}

static gpointer fragment_key_temporary(const packet_info *pinfo, const guint32 id, const void *data) {
    tcpcl_fragment_key_t *obj = g_slice_new(tcpcl_fragment_key_t);
    obj->addr_port = addresses_ports_reassembly_table_functions.temporary_key_func(pinfo, id, NULL);
    obj->xfer_id = *((const guint64 *)data);
    return (gpointer)obj;
}

static gpointer fragment_key_persistent(const packet_info *pinfo, const guint32 id, const void *data) {
    tcpcl_fragment_key_t *obj = g_slice_new(tcpcl_fragment_key_t);
    obj->addr_port = addresses_ports_reassembly_table_functions.persistent_key_func(pinfo, id, NULL);
    obj->xfer_id = *((const guint64 *)data);
    return (gpointer)obj;
}

static void fragment_key_free_temporary(gpointer ptr) {
    tcpcl_fragment_key_t *obj = (tcpcl_fragment_key_t *)ptr;
    if (obj) {
        addresses_ports_reassembly_table_functions.free_temporary_key_func(obj->addr_port);
        g_slice_free(tcpcl_fragment_key_t, obj);
    }
}

static void fragment_key_free_persistent(gpointer ptr) {
    tcpcl_fragment_key_t *obj = (tcpcl_fragment_key_t *)ptr;
    if (obj) {
        addresses_ports_reassembly_table_functions.free_persistent_key_func(obj->addr_port);
        g_slice_free(tcpcl_fragment_key_t, obj);
    }
}

static reassembly_table_functions xfer_reassembly_table_functions = {
    fragment_key_hash,
    fragment_key_equal,
    fragment_key_temporary,
    fragment_key_persistent,
    fragment_key_free_temporary,
    fragment_key_free_persistent
};

/** Record metadata about one segment in a transfer.
 */
static void transfer_add_segment(tcpcl_dissect_ctx_t *ctx, guint64 xfer_id, guint8 flags,
                                 guint64 data_len,
                                 packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree_msg,
                                 proto_item *item_msg, proto_item *item_flags) {
    tcpcl_transfer_t *xfer = get_or_create_transfer_t(ctx->tx_peer->transfers, xfer_id);

    guint8 flag_start, flag_end;
    if (ctx->tx_peer->version == 3) {
        flag_start = TCPCLV3_DATA_START_FLAG;
        flag_end = TCPCLV3_DATA_END_FLAG;
    }
    else {
        flag_start = TCPCLV4_TRANSFER_FLAG_START;
        flag_end = TCPCLV4_TRANSFER_FLAG_END;
    }

    // Add or get the segment metadata
    tcpcl_seg_meta_t *seg_meta = tcpcl_seg_meta_new(pinfo, ctx->cur_loc);
    wmem_list_frame_t *frm = wmem_list_find_custom(xfer->seg_list, seg_meta, tcpcl_seg_meta_compare_loc);
    if (frm) {
        tcpcl_seg_meta_free(seg_meta);
        seg_meta = wmem_list_frame_data(frm);
    }
    else {
        wmem_list_insert_sorted(xfer->seg_list, seg_meta, tcpcl_seg_meta_compare_loc);
        frm = wmem_list_find_custom(xfer->seg_list, seg_meta, tcpcl_seg_meta_compare_loc);
        // Set for new item
        seg_meta->flags = flags;
    }

    // mark start-of-transfer
    if (!(seg_meta->related_start)) {
        wmem_list_frame_t *frm_front = wmem_list_head(xfer->seg_list);
        tcpcl_seg_meta_t *seg_front = frm_front ? wmem_list_frame_data(frm_front) : NULL;
        if (seg_front && (seg_front->flags & flag_start)) {
            seg_meta->related_start = seg_front;
        }
    }

    // accumulate segment sizes
    guint64 prev_seen_len;
    wmem_list_frame_t *frm_prev = wmem_list_frame_prev(frm);
    if (!frm_prev) {
        if (!(flags & flag_start)) {
            expert_add_info(pinfo, item_flags, &ei_tcpclv4_xfer_seg_missing_start);
        }
        prev_seen_len = 0;
    }
    else {
        const tcpcl_seg_meta_t *seg_prev = wmem_list_frame_data(frm_prev);
        if (flags & flag_start) {
            expert_add_info(pinfo, item_flags, &ei_tcpclv4_xfer_seg_duplicate_start);
        }
        prev_seen_len = seg_prev->seen_len;
    }
    wmem_list_frame_t *frm_next = wmem_list_frame_next(frm);
    if (!frm_next) {
        if (!(flags & flag_end)) {
            expert_add_info(pinfo, item_flags, &ei_tcpclv4_xfer_seg_missing_end);
        }
    }
    else {
        if (flags & flag_end) {
            expert_add_info(pinfo, item_flags, &ei_tcpclv4_xfer_seg_duplicate_end);
        }
    }
    seg_meta->seen_len = prev_seen_len + data_len;

    proto_item *item_seen = proto_tree_add_uint64(tree_msg, hf_tcpclv4_xfer_segment_seen_len, tvb, 0, 0, seg_meta->seen_len);
    PROTO_ITEM_SET_GENERATED(item_seen);
    if (seg_meta->seen_len > ctx->rx_peer->transfer_mru) {
        expert_add_info(pinfo, item_seen, &ei_tcpclv4_xferload_over_xfer_mru);
    }
    if (xfer->total_length) {
        if (seg_meta->seen_len > *(xfer->total_length)) {
            expert_add_info(pinfo, item_seen, &ei_xfer_seg_over_total_len);
        }
        else if ((flags & flag_end)
            && (seg_meta->seen_len != *(xfer->total_length))) {
            expert_add_info(pinfo, item_seen, &ei_xfer_mismatch_total_len);
        }
        proto_item *item_total = proto_tree_add_uint64(tree_msg, hf_tcpclv4_xfer_total_len, tvb, 0, 0, *(xfer->total_length));
        PROTO_ITEM_SET_GENERATED(item_total);
    }

    if (seg_meta->related_ack) {
        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_tcpclv4_xfer_segment_related_ack, tvb, 0, 0, seg_meta->related_ack->frame_loc.frame_num);
        PROTO_ITEM_SET_GENERATED(item_rel);

        nstime_t td;
        nstime_delta(&td, &(seg_meta->related_ack->frame_time), &(seg_meta->frame_time));
        proto_item *item_td = proto_tree_add_time(tree_msg, hf_tcpclv4_xfer_segment_time_diff, tvb, 0, 0, &td);
        PROTO_ITEM_SET_GENERATED(item_td);

    }
    else {
        expert_add_info(pinfo, item_msg, &ei_tcpclv4_xfer_seg_no_relation);
    }
    if (seg_meta->related_start && (seg_meta->related_start != seg_meta)) {
        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_tcpclv4_xfer_segment_related_start, tvb, 0, 0, seg_meta->related_start->frame_loc.frame_num);
        PROTO_ITEM_SET_GENERATED(item_rel);

        nstime_t td;
        nstime_delta(&td, &(seg_meta->frame_time), &(seg_meta->related_start->frame_time));
        proto_item *item_td = proto_tree_add_time(tree_msg, hf_tcpclv4_xfer_segment_time_start, tvb, 0, 0, &td);
        PROTO_ITEM_SET_GENERATED(item_td);
    }
}

static void transfer_add_ack(tcpcl_dissect_ctx_t *ctx, guint64 xfer_id, guint8 flags,
                             guint64 ack_len,
                             packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree_msg,
                             proto_item *item_msg, proto_item *item_flags) {
    tcpcl_transfer_t *xfer = get_or_create_transfer_t(ctx->rx_peer->transfers, xfer_id);

    // Add or get the ack metadata
    tcpcl_ack_meta_t *ack_meta = tcpcl_ack_meta_new(pinfo, ctx->cur_loc);
    wmem_list_frame_t *frm = wmem_list_find_custom(xfer->ack_list, ack_meta, tcpcl_ack_meta_compare_loc);
    if (frm) {
        tcpcl_ack_meta_free(ack_meta);
        ack_meta = wmem_list_frame_data(frm);
    }
    else {
        wmem_list_insert_sorted(xfer->ack_list, ack_meta, tcpcl_ack_meta_compare_loc);
        wmem_list_find_custom(xfer->ack_list, ack_meta, tcpcl_ack_meta_compare_loc);
        // Set for new item
        ack_meta->flags = flags;
        ack_meta->seen_len = ack_len;
    }

    // mark start-of-transfer
    if (!(ack_meta->related_start)) {
        wmem_list_frame_t *frm_front = wmem_list_head(xfer->seg_list);
        tcpcl_seg_meta_t *seg_front = frm_front ? wmem_list_frame_data(frm_front) : NULL;
        if (seg_front && (seg_front->flags & TCPCLV4_TRANSFER_FLAG_START)) {
            ack_meta->related_start = seg_front;
        }
    }

    // Assemble both of the links here, as ACK will always follow segment
    if (!(ack_meta->related_seg)) {
        wmem_list_frame_t *seg_iter = wmem_list_head(xfer->seg_list);
        for (; seg_iter; seg_iter = wmem_list_frame_next(seg_iter)) {
            tcpcl_seg_meta_t *seg_meta = wmem_list_frame_data(seg_iter);
            if (seg_meta->seen_len == ack_meta->seen_len) {
                seg_meta->related_ack = ack_meta;
                ack_meta->related_seg = seg_meta;
            }
        }
    }

    if (xfer->total_length) {
        proto_item *item_total = proto_tree_add_uint64(tree_msg, hf_tcpclv4_xfer_total_len, tvb, 0, 0, *(xfer->total_length));
        PROTO_ITEM_SET_GENERATED(item_total);
    }
    if (ack_meta->related_seg) {
        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_tcpclv4_xfer_ack_related_seg, tvb, 0, 0, ack_meta->related_seg->frame_loc.frame_num);
        PROTO_ITEM_SET_GENERATED(item_rel);

        nstime_t td;
        nstime_delta(&td, &(ack_meta->frame_time), &(ack_meta->related_seg->frame_time));
        proto_item *item_td = proto_tree_add_time(tree_msg, hf_tcpclv4_xfer_ack_time_diff, tvb, 0, 0, &td);
        PROTO_ITEM_SET_GENERATED(item_td);

        if (item_flags && (ack_meta->flags != ack_meta->related_seg->flags)) {
            expert_add_info(pinfo, item_flags, &ei_xfer_ack_mismatch_flags);
        }
    }
    else {
        expert_add_info(pinfo, item_msg, &ei_xfer_ack_no_relation);
    }
    if (ack_meta->related_start) {
        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_tcpclv4_xfer_ack_related_start, tvb, 0, 0, ack_meta->related_start->frame_loc.frame_num);
        PROTO_ITEM_SET_GENERATED(item_rel);

        nstime_t td;
        nstime_delta(&td, &(ack_meta->frame_time), &(ack_meta->related_start->frame_time));
        proto_item *item_td = proto_tree_add_time(tree_msg, hf_tcpclv4_xfer_ack_time_start, tvb, 0, 0, &td);
        PROTO_ITEM_SET_GENERATED(item_td);
    }
}

static void transfer_add_refuse(tcpcl_dissect_ctx_t *ctx, guint64 xfer_id,
                                packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree_msg,
                                proto_item *item_msg) {
    const tcpcl_transfer_t *xfer = wmem_map_lookup(ctx->rx_peer->transfers, &xfer_id);
    const tcpcl_seg_meta_t *seg_last = NULL;
    if (xfer) {
        wmem_list_frame_t *seg_iter = wmem_list_tail(xfer->seg_list);
        seg_iter = seg_iter ? wmem_list_frame_prev(seg_iter) : NULL;
        seg_last = seg_iter ? wmem_list_frame_data(seg_iter) : NULL;
    }

    if (seg_last) {
        proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_tcpclv4_xfer_refuse_related_seg, tvb, 0, 0, seg_last->frame_loc.frame_num);
        PROTO_ITEM_SET_GENERATED(item_rel);
    }
    else {
        expert_add_info(pinfo, item_msg, &ei_tcpclv4_xfer_refuse_no_transfer);
    }
}

static gint get_clamped_length(guint64 orig) {
    gint clamped;
    if (orig > G_MAXINT) {
        clamped = G_MAXINT;
    }
    else {
        clamped = (gint) orig;
    }
    return clamped;
}

static guint
get_v3_msg_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
               tcpcl_dissect_ctx_t *ctx _U_)
{
    const int orig_offset = offset;
    int    len, bytecount;
    guint8 conv_hdr = tvb_get_guint8(tvb, offset);
    offset += 1;

    switch (conv_hdr & TCPCLV3_TYPE_MASK)
    {
    case TCPCLV3_DATA_SEGMENT:
        /* get length from sdnv */
        len = evaluate_sdnv(tvb, offset, &bytecount);
        if (len < 0)
            return 0;

        offset += bytecount+len;
        break;

    case TCPCLV3_ACK_SEGMENT:
        /* get length from sdnv */
        len = evaluate_sdnv(tvb, offset, &bytecount);
        if (len < 0)
            return 0;

        offset += bytecount;
        break;

    case TCPCLV3_KEEP_ALIVE:
    case TCPCLV3_REFUSE_BUNDLE:
        /* always 1 byte */
        break;
    case TCPCLV3_SHUTDOWN:
        if (conv_hdr & TCPCLV3_SHUTDOWN_REASON) {
            offset += 1;
        }
        if (conv_hdr & TCPCLV3_SHUTDOWN_DELAY) {
            offset += 2;
        }
        break;

    case TCPCLV3_LENGTH:
        /* get length from sdnv */
        len = evaluate_sdnv(tvb, offset, &bytecount);
        if (len < 0)
            return 0;
        offset += bytecount;
        break;
    }

    /* This probably isn't a TCPCL/Bundle packet, so just stop dissection */
    return offset - orig_offset;
}

static int
dissect_v3_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               tcpcl_dissect_ctx_t *ctx)
{
    guint8         conv_hdr;
    const char *msgtype_name;
    guint8         refuse_bundle_hdr;
    int            offset = 0;
    int            sdnv_length, segment_length;
    proto_item    *conv_item, *sub_item;
    proto_tree    *conv_tree, *sub_tree;
    guint64 *xfer_id = NULL;
    proto_item *item_xfer_id = NULL;

    conv_item = proto_tree_add_item(tree, hf_tcpclv3_mhdr, tvb, 0, -1, ENC_NA);
    conv_tree = proto_item_add_subtree(conv_item, ett_tcpclv3_mhdr);

    conv_hdr = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(conv_tree, hf_tcpclv3_pkt_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    msgtype_name = val_to_str_const((conv_hdr>>4)&0xF, v3_message_type_vals, "Unknown");
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msgtype_name);
    proto_item_append_text(proto_tree_get_parent(conv_tree), ": %s", msgtype_name);

    switch (conv_hdr & TCPCLV3_TYPE_MASK) {
    case TCPCLV3_DATA_SEGMENT: {
        proto_item *item_flags;

        item_flags = proto_tree_add_bitmask(
            conv_tree, tvb,
            offset, hf_tcpclv3_data_procflags,
            ett_tcpclv3_data_procflags, v3_data_procflags,
            ENC_BIG_ENDIAN
        );

        /* Only Start and End flags (bits 0 & 1) are valid in Data Segment */
        if ((conv_hdr & ~(TCPCLV3_TYPE_MASK | TCPCLV3_DATA_FLAGS)) != 0) {
            expert_add_info(pinfo, item_flags, &ei_tcpclv3_data_flags);
        }

        segment_length = evaluate_sdnv(tvb, 1, &sdnv_length);
        sub_item = proto_tree_add_int(conv_tree, hf_tcpclv3_data_segment_length, tvb, 1, sdnv_length, segment_length);
        if (segment_length < 0) {
            expert_add_info(pinfo, sub_item, &ei_tcpclv3_segment_length);
            return 1;
        }
        offset += 1 + sdnv_length;

        // implied transfer ID
        xfer_id = wmem_map_lookup(ctx->tx_peer->frame_loc_to_transfer, ctx->cur_loc);
        if (!xfer_id) {
            xfer_id = wmem_new(wmem_packet_scope(), guint64);
            *xfer_id = wmem_map_size(ctx->tx_peer->transfers);

            if (conv_hdr & TCPCLV3_DATA_START_FLAG) {
                *xfer_id += 1;
                get_or_create_transfer_t(ctx->tx_peer->transfers, *xfer_id);
            }
            tcpcl_peer_associate_transfer(ctx->tx_peer, ctx->cur_loc, *xfer_id);
        }
        item_xfer_id = proto_tree_add_uint64(conv_tree, hf_tcpclv3_xfer_id, tvb, 0, 0, *xfer_id);
        PROTO_ITEM_SET_GENERATED(item_xfer_id);

        proto_tree_add_item(conv_tree, hf_tcpclv3_data_segment_data, tvb, offset, segment_length, ENC_NA);

        if (tcpcl_analyze_sequence) {
            transfer_add_segment(ctx, *xfer_id, (conv_hdr & TCPCLV3_DATA_FLAGS), segment_length, pinfo, tvb, conv_tree, conv_item, item_flags);
        }

        if (tcpcl_desegment_transfer) {
            // Reassemble the segments
            fragment_head *frag_msg;
            frag_msg = fragment_add_seq_next(
                &xfer_reassembly_table,
                tvb, offset,
                pinfo, 0, xfer_id,
                segment_length,
                !(conv_hdr & TCPCLV3_DATA_END_FLAG)
            );
            ctx->xferload = process_reassembled_data(
                tvb, offset, pinfo,
                "Reassembled Transfer",
                frag_msg,
                &xfer_frag_items,
                NULL,
                proto_tree_get_parent_tree(tree)
            );
        }
        offset += segment_length;

        break;
    }
    case TCPCLV3_ACK_SEGMENT: {
        /*No valid flags*/
        offset += 1;

        segment_length = evaluate_sdnv(tvb, offset, &sdnv_length);
        sub_item = proto_tree_add_int(conv_tree, hf_tcpclv3_ack_length, tvb, offset, sdnv_length, segment_length);
        if (segment_length < 0) {
            expert_add_info(pinfo, sub_item, &ei_tcpclv3_ack_length);
        } else {
            offset += sdnv_length;
        }

        // implied transfer ID
        xfer_id = wmem_map_lookup(ctx->rx_peer->frame_loc_to_transfer, ctx->cur_loc);
        if (!xfer_id) {
            xfer_id = wmem_new(wmem_packet_scope(), guint64);
            *xfer_id = wmem_map_size(ctx->rx_peer->transfers);

            tcpcl_peer_associate_transfer(ctx->rx_peer, ctx->cur_loc, *xfer_id);
        }
        item_xfer_id = proto_tree_add_uint64(conv_tree, hf_tcpclv3_xfer_id, tvb, 0, 0, *xfer_id);
        PROTO_ITEM_SET_GENERATED(item_xfer_id);

        if (tcpcl_analyze_sequence) {
            transfer_add_ack(ctx, *xfer_id, 0, segment_length, pinfo, tvb, conv_tree, conv_item, NULL);
        }

        break;
    }
    case TCPCLV3_KEEP_ALIVE:
        /*No valid flags in Keep Alive*/
        offset += 1;
        break;

    case TCPCLV3_SHUTDOWN:
        /* Add tree for Shutdown Flags */
        sub_item = proto_tree_add_item(conv_tree, hf_tcpclv3_shutdown_flags, tvb,
                                        offset, 1, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(sub_item, ett_tcpclv3_shutdown_flags);

        proto_tree_add_item(sub_tree, hf_tcpclv3_shutdown_flags_reason,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_tcpclv3_shutdown_flags_delay,
                            tvb, offset, 1, ENC_BIG_ENDIAN);

        offset += 1;
        if (conv_hdr & TCPCLV3_SHUTDOWN_REASON) {
            proto_tree_add_item(conv_tree,
                                hf_tcpclv3_shutdown_reason, tvb,
                                offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
        }
        if (conv_hdr & TCPCLV3_SHUTDOWN_DELAY) {
            proto_tree_add_item(conv_tree,
                                hf_tcpclv3_shutdown_delay, tvb,
                                offset, 2, ENC_BIG_ENDIAN);
            offset += 1;
        }
        break;
    case TCPCLV3_REFUSE_BUNDLE:
        /*No valid flags*/
        offset += 1;

        refuse_bundle_hdr = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(conv_tree, hf_tcpclv3_refuse_reason_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const((refuse_bundle_hdr>>4)&0xF, v3_refuse_reason_code, "Unknown"));

        // implied transfer ID
        xfer_id = wmem_map_lookup(ctx->rx_peer->frame_loc_to_transfer, ctx->cur_loc);
        if (!xfer_id) {
            xfer_id = wmem_new(wmem_packet_scope(), guint64);
            *xfer_id = wmem_map_size(ctx->rx_peer->transfers);

            tcpcl_peer_associate_transfer(ctx->rx_peer, ctx->cur_loc, *xfer_id);
        }
        item_xfer_id = proto_tree_add_uint64(conv_tree, hf_tcpclv3_xfer_id, tvb, 0, 0, *xfer_id);
        PROTO_ITEM_SET_GENERATED(item_xfer_id);

        if (tcpcl_analyze_sequence) {
            transfer_add_refuse(ctx, *xfer_id, pinfo, tvb, conv_tree, conv_item);
        }

        break;

    default:
        expert_add_info(pinfo, proto_tree_get_parent(conv_tree), &ei_tcpclv3_invalid_msg_type);
        break;
    }

    return offset;
}

static guint get_v4_msg_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
                            tcpcl_dissect_ctx_t *ctx _U_) {
    const int init_offset = offset;
    guint8 msgtype = tvb_get_guint8(tvb, offset);
    offset += 1;
    switch(msgtype) {
        case TCPCLV4_MSGTYPE_SESS_INIT: {
            const gint buflen = tvb_reported_length(tvb);
            offset += 2 + 8 + 8;
            if (buflen < offset + 2) {
                return 0;
            }
            guint16 nodeid_len = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
            offset += 2;
            offset += nodeid_len;
            if (buflen < offset + 4) {
                return 0;
            }
            guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
            offset += 4;
            offset += extlist_len;
            break;
        }
        case TCPCLV4_MSGTYPE_SESS_TERM: {
            offset += 1 + 1;
            break;
        }
        case TCPCLV4_MSGTYPE_XFER_SEGMENT: {
            const gint buflen = tvb_reported_length(tvb);
            if (buflen < offset + 1) {
                return 0;
            }
            guint8 flags = tvb_get_guint8(tvb, offset);
            offset += 1;
            offset += 8;
            if (flags & TCPCLV4_TRANSFER_FLAG_START) {
                if (buflen < offset + 4) {
                    return 0;
                }
                guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                offset += 4;
                offset += extlist_len;
            }
            if (buflen < offset + 8) {
                return 0;
            }
            guint64 data_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            offset += 8;
            const gint data_len_clamp = get_clamped_length(data_len);
            offset += data_len_clamp;
            break;
        }
        case TCPCLV4_MSGTYPE_XFER_ACK: {
            offset += 1 + 8 + 8;
            break;
        }
        case TCPCLV4_MSGTYPE_XFER_REFUSE: {
            offset += 1 + 8;
            break;
        }
        case TCPCLV4_MSGTYPE_KEEPALIVE: {
            break;
        }
        case TCPCLV4_MSGTYPE_MSG_REJECT: {
            offset += 1 + 1;
            break;
        }
        default:
            break;
    }
    return offset - init_offset;
}

static int
dissect_v4_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               tcpcl_dissect_ctx_t *ctx _U_) {
    int offset  = 0;
    // Length of non-protocol 'payload' data in this message
    gint payload_len = 0;

    guint8 msgtype = 0;
    const char *msgtype_name = NULL;

    proto_item *item_msg = proto_tree_add_item(tree, hf_tcpclv4_mhdr_tree, tvb, offset, 0, ENC_NA);
    proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_tcpclv4_mhdr);

    msgtype = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree_msg, hf_tcpclv4_mhdr_type, tvb, offset, 1, msgtype);
    offset += 1;
    msgtype_name = val_to_str(msgtype, v4_message_type_vals, "type 0x%02" PRIx32);
    wmem_strbuf_t *suffix_text = wmem_strbuf_new(wmem_packet_scope(), NULL);

    switch(msgtype) {
        case TCPCLV4_MSGTYPE_SESS_INIT: {
            guint16 keepalive = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(tree_msg, hf_tcpclv4_sess_init_keepalive, tvb, offset, 2, keepalive);
            offset += 2;

            guint64 seg_mru = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint64(tree_msg, hf_tcpclv4_sess_init_seg_mru, tvb, offset, 8, seg_mru);
            offset += 8;

            guint64 xfer_mru = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint64(tree_msg, hf_tcpclv4_sess_init_xfer_mru, tvb, offset, 8, xfer_mru);
            offset += 8;

            guint16 nodeid_len = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(tree_msg, hf_tcpclv4_sess_init_nodeid_len, tvb, offset, 2, nodeid_len);
            offset += 2;

            {
                guint8 *nodeid_data = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, nodeid_len, ENC_UTF_8);
                proto_tree_add_string(tree_msg, hf_tcpclv4_sess_init_nodeid_data, tvb, offset, nodeid_len, (const char *)nodeid_data);
                wmem_free(wmem_packet_scope(), nodeid_data);
            }
            offset += nodeid_len;

            guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint(tree_msg, hf_tcpclv4_sess_init_extlist_len, tvb, offset, 4, extlist_len);
            offset += 4;

            gint extlist_offset = 0;
            while (extlist_offset < (int)extlist_len) {
                gint extitem_offset = 0;
                proto_item *item_ext = proto_tree_add_item(tree_msg, hf_tcpclv4_sessext_tree, tvb, offset + extlist_offset, 0, ENC_NA);
                proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_tcpclv4_sessext);

                guint8 extitem_flags = tvb_get_guint8(tvb, offset + extlist_offset + extitem_offset);
                proto_tree_add_bitmask(tree_ext, tvb, offset + extlist_offset + extitem_offset, hf_tcpclv4_sessext_flags, ett_tcpclv4_sessext_flags, v4_sessext_flags, ENC_BIG_ENDIAN);
                extitem_offset += 1;
                const gboolean is_critical = (extitem_flags & TCPCLV4_EXTENSION_FLAG_CRITICAL);
                if (is_critical) {
                    expert_add_info(pinfo, item_ext, &ei_tcpclv4_extitem_critical);
                }

                guint16 extitem_type = tvb_get_guint16(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                proto_item *item_type = proto_tree_add_uint(tree_ext, hf_tcpclv4_sessext_type, tvb, offset + extlist_offset + extitem_offset, 2, extitem_type);
                extitem_offset += 2;

                dissector_handle_t subdis = dissector_get_uint_handle(xfer_ext_dissectors, extitem_type);
                const char *subname = dissector_handle_get_dissector_name(subdis);
                if (subdis) {
                    proto_item_set_text(item_type, "Item Type: %s (0x%04" PRIx16 ")", subname, extitem_type);
                }

                guint16 extitem_len = tvb_get_guint16(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint(tree_ext, hf_tcpclv4_sessext_len, tvb, offset + extlist_offset + extitem_offset, 2, extitem_len);
                extitem_offset += 2;

                tvbuff_t *extitem_tvb = tvb_new_subset_length(tvb, offset + extlist_offset + extitem_offset, extitem_len);
                proto_item *item_extdata = proto_tree_add_item(tree_ext, hf_tcpclv4_sessext_data, extitem_tvb, 0, tvb_captured_length(extitem_tvb), ENC_NA);
                proto_tree *tree_extdata = proto_item_add_subtree(item_extdata, ett_tcpclv4_sessext_data);

                int sublen = 0;
                if (subdis) {
                    sublen = call_dissector_only(subdis, extitem_tvb, pinfo, tree_extdata, NULL);
                }
                if (sublen == 0) {
                    expert_add_info(pinfo, item_type, &ei_tcpclv4_invalid_sessext_type);
                }
                extitem_offset += extitem_len;

                proto_item_set_len(item_ext, extitem_offset);
                extlist_offset += extitem_offset;

                if (subname) {
                    proto_item_append_text(item_ext, ": %s", subname);
                }
                else {
                    proto_item_append_text(item_ext, ": Type 0x%04" PRIx16, extitem_type);
                }
                if (is_critical) {
                    proto_item_append_text(item_ext, ", CRITICAL");
                }
            }
            // advance regardless of any internal offset processing
            offset += extlist_len;

            if (ctx->tx_peer->sess_init_seen) {
                if (tcpcl_analyze_sequence) {
                    if (!tcpcl_frame_loc_equal(ctx->tx_peer->sess_init_seen, ctx->cur_loc)) {
                        expert_add_info(pinfo, item_msg, &ei_tcpclv4_sess_init_duplicate);
                    }
                }
            }
            else {
                ctx->tx_peer->sess_init_seen = tcpcl_frame_loc_clone(wmem_file_scope(), ctx->cur_loc);
                ctx->tx_peer->keepalive = keepalive;
                ctx->tx_peer->segment_mru = seg_mru;
                ctx->tx_peer->transfer_mru = xfer_mru;
            }

            break;
        }
        case TCPCLV4_MSGTYPE_SESS_TERM: {
            guint8 flags = tvb_get_guint8(tvb, offset);
            proto_tree_add_bitmask(tree_msg, tvb, offset, hf_tcpclv4_sess_term_flags, ett_tcpclv4_sess_term_flags, v4_sess_term_flags, ENC_BIG_ENDIAN);
            offset += 1;

            guint8 reason = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(tree_msg, hf_tcpclv4_sess_term_reason, tvb, offset, 1, reason);
            offset += 1;

            if (ctx->tx_peer->sess_term_seen) {
                if (tcpcl_analyze_sequence) {
                    if (!tcpcl_frame_loc_equal(ctx->tx_peer->sess_term_seen, ctx->cur_loc)) {
                        expert_add_info(pinfo, item_msg, &ei_tcpclv4_sess_term_duplicate);
                    }
                }
            }
            else {
                ctx->tx_peer->sess_term_seen = tcpcl_frame_loc_clone(wmem_file_scope(), ctx->cur_loc);
                ctx->tx_peer->sess_term_reason = reason;
            }

            if (tcpcl_analyze_sequence) {
                if (ctx->rx_peer->sess_term_seen) {
                    proto_item *item_rel = proto_tree_add_uint(tree_msg, hf_tcpclv4_sess_term_related, tvb, 0, 0, ctx->rx_peer->sess_term_seen->frame_num);
                    PROTO_ITEM_SET_GENERATED(item_rel);

                    // Is this message after the other SESS_TERM?
                    if (tcpcl_frame_loc_compare(ctx->tx_peer->sess_term_seen, ctx->rx_peer->sess_term_seen, NULL) > 0) {
                        if (!(flags & TCPCLV4_SESS_TERM_FLAG_REPLY)) {
                            expert_add_info(pinfo, item_msg, &ei_tcpclv4_sess_term_reply_flag);
                        }
                    }
                }
            }

            break;
        }
        case TCPCLV4_MSGTYPE_XFER_SEGMENT:{
            guint8 flags = tvb_get_guint8(tvb, offset);
            proto_item *item_flags = proto_tree_add_bitmask(tree_msg, tvb, offset, hf_tcpclv4_xfer_flags, ett_tcpclv4_xfer_flags, v4_xfer_flags, ENC_BIG_ENDIAN);
            offset += 1;

            guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint64(tree_msg, hf_tcpclv4_xfer_id, tvb, offset, 8, xfer_id);
            offset += 8;

            if (flags & TCPCLV4_TRANSFER_FLAG_START) {
                guint32 extlist_len = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                proto_tree_add_uint(tree_msg, hf_tcpclv4_xfer_segment_extlist_len, tvb, offset, 4, extlist_len);
                offset += 4;

                gint extlist_offset = 0;
                while (extlist_offset < (int)extlist_len) {
                    gint extitem_offset = 0;
                    proto_item *item_ext = proto_tree_add_item(tree_msg, hf_tcpclv4_xferext_tree, tvb, offset + extlist_offset, 0, ENC_NA);
                    proto_tree *tree_ext = proto_item_add_subtree(item_ext, ett_tcpclv4_xferext);

                    guint8 extitem_flags = tvb_get_guint8(tvb, offset + extlist_offset + extitem_offset);
                    proto_tree_add_bitmask(tree_ext, tvb, offset + extlist_offset + extitem_offset, hf_tcpclv4_xferext_flags, ett_tcpclv4_xferext_flags, v4_xferext_flags, ENC_BIG_ENDIAN);
                    extitem_offset += 1;
                    const gboolean is_critical = (extitem_flags & TCPCLV4_EXTENSION_FLAG_CRITICAL);
                    if (is_critical) {
                        expert_add_info(pinfo, item_ext, &ei_tcpclv4_extitem_critical);
                    }

                    guint16 extitem_type = tvb_get_guint16(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                    proto_item *item_type = proto_tree_add_uint(tree_ext, hf_tcpclv4_xferext_type, tvb, offset + extlist_offset + extitem_offset, 2, extitem_type);
                    extitem_offset += 2;

                    dissector_handle_t subdis = dissector_get_uint_handle(xfer_ext_dissectors, extitem_type);
                    const char *subname = dissector_handle_get_dissector_name(subdis);
                    if (subdis) {
                        proto_item_set_text(item_type, "Item Type: %s (0x%04" PRIx16 ")", subname, extitem_type);
                    }

                    guint16 extitem_len = tvb_get_guint16(tvb, offset + extlist_offset + extitem_offset, ENC_BIG_ENDIAN);
                    proto_tree_add_uint(tree_ext, hf_tcpclv4_xferext_len, tvb, offset + extlist_offset + extitem_offset, 2, extitem_len);
                    extitem_offset += 2;

                    tvbuff_t *extitem_tvb = tvb_new_subset_length(tvb, offset + extlist_offset + extitem_offset, extitem_len);
                    proto_item *item_extdata = proto_tree_add_item(tree_ext, hf_tcpclv4_xferext_data, extitem_tvb, 0, tvb_captured_length(extitem_tvb), ENC_NA);
                    proto_tree *tree_extdata = proto_item_add_subtree(item_extdata, ett_tcpclv4_xferext_data);

                    tcpcl_frame_loc_t *extitem_loc = tcpcl_frame_loc_new(wmem_packet_scope(), pinfo, extitem_tvb, 0);
                    tcpcl_peer_associate_transfer(ctx->tx_peer, extitem_loc, xfer_id);

                    int sublen = 0;
                    if (subdis) {
                        sublen = call_dissector_only(subdis, extitem_tvb, pinfo, tree_extdata, NULL);
                    }
                    if (sublen == 0) {
                        expert_add_info(pinfo, item_type, &ei_tcpclv4_invalid_xferext_type);
                    }
                    extitem_offset += extitem_len;

                    proto_item_set_len(item_ext, extitem_offset);
                    extlist_offset += extitem_offset;

                    if (subname) {
                        proto_item_append_text(item_ext, ": %s", subname);
                    }
                    else {
                        proto_item_append_text(item_ext, ": Type 0x%04" PRIx16, extitem_type);
                    }
                    if (is_critical) {
                        proto_item_append_text(item_ext, ", CRITICAL");
                    }
                }
                // advance regardless of any internal offset processing
                offset += extlist_len;
            }

            guint64 data_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_item *item_len = proto_tree_add_uint64(tree_msg, hf_tcpclv4_xfer_segment_data_len, tvb, offset, 8, data_len);
            offset += 8;

            if (data_len > ctx->rx_peer->segment_mru) {
                expert_add_info(pinfo, item_len, &ei_tcpclv4_xfer_seg_over_seg_mru);
            }
            const gint data_len_clamp = get_clamped_length(data_len);

            // Treat data as payload layer
            const gint data_offset = offset;
            proto_tree_add_item(tree_msg, hf_tcpclv4_xfer_segment_data, tvb, offset, data_len_clamp, ENC_NA);
            offset += data_len_clamp;
            payload_len = data_len_clamp;

            wmem_strbuf_append_printf(suffix_text, ", Xfer ID: %" PRIi64, xfer_id);

            if (flags) {
                wmem_strbuf_append(suffix_text, ", Flags: ");
                gboolean sep = FALSE;
                if (flags & TCPCLV4_TRANSFER_FLAG_START) {
                    wmem_strbuf_append(suffix_text, "START");
                    sep = TRUE;
                }
                if (flags & TCPCLV4_TRANSFER_FLAG_END) {
                    if (sep) {
                        wmem_strbuf_append(suffix_text, "|");
                    }
                    wmem_strbuf_append(suffix_text, "END");
                }
            }

            if (tcpcl_analyze_sequence) {
                transfer_add_segment(ctx, xfer_id, flags, data_len, pinfo, tvb, tree_msg, item_msg, item_flags);
            }

            if (tcpcl_desegment_transfer) {
                // Reassemble the segments
                fragment_head *xferload_frag_msg = fragment_add_seq_next(
                    &xfer_reassembly_table,
                    tvb, data_offset,
                    pinfo, 0, &xfer_id,
                    data_len_clamp,
                    !(flags & TCPCLV4_TRANSFER_FLAG_END)
                );
                ctx->xferload = process_reassembled_data(
                    tvb, data_offset, pinfo,
                    "Reassembled Transfer",
                    xferload_frag_msg,
                    &xfer_frag_items,
                    NULL,
                    proto_tree_get_parent_tree(tree)
                );
            }

            break;
        }
        case TCPCLV4_MSGTYPE_XFER_ACK:{
            guint8 flags = tvb_get_guint8(tvb, offset);
            proto_item *item_flags = proto_tree_add_bitmask(tree_msg, tvb, offset, hf_tcpclv4_xfer_flags, ett_tcpclv4_xfer_flags, v4_xfer_flags, ENC_BIG_ENDIAN);
            offset += 1;

            guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint64(tree_msg, hf_tcpclv4_xfer_id, tvb, offset, 8, xfer_id);
            offset += 8;

            guint64 ack_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint64(tree_msg, hf_tcpclv4_xfer_ack_ack_len, tvb, offset, 8, ack_len);
            offset += 8;

            wmem_strbuf_append_printf(suffix_text, ", Xfer ID: %" PRIi64, xfer_id);

            if (flags) {
                wmem_strbuf_append(suffix_text, ", Flags: ");
                gboolean sep = FALSE;
                if (flags & TCPCLV4_TRANSFER_FLAG_START) {
                    wmem_strbuf_append(suffix_text, "START");
                    sep = TRUE;
                }
                if (flags & TCPCLV4_TRANSFER_FLAG_END) {
                    if (sep) {
                        wmem_strbuf_append(suffix_text, "|");
                    }
                    wmem_strbuf_append(suffix_text, "END");
                }
            }

            if (tcpcl_analyze_sequence) {
                transfer_add_ack(ctx, xfer_id, flags, ack_len, pinfo, tvb, tree_msg, item_msg, item_flags);
            }

            break;
        }
        case TCPCLV4_MSGTYPE_XFER_REFUSE: {
            guint8 reason = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(tree_msg, hf_tcpclv4_xfer_refuse_reason, tvb, offset, 1, reason);
            offset += 1;

            guint64 xfer_id = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_uint64(tree_msg, hf_tcpclv4_xfer_id, tvb, offset, 8, xfer_id);
            offset += 8;

            wmem_strbuf_append_printf(suffix_text, ", Xfer ID: %" PRIi64, xfer_id);

            if (tcpcl_analyze_sequence) {
                transfer_add_refuse(ctx, xfer_id, pinfo, tvb, tree_msg, item_msg);
            }

            break;
        }
        case TCPCLV4_MSGTYPE_KEEPALIVE: {
            break;
        }
        case TCPCLV4_MSGTYPE_MSG_REJECT: {
            guint8 reason = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(tree_msg, hf_tcpclv4_msg_reject_reason, tvb, offset, 1, reason);
            offset += 1;

            guint8 rej_head = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(tree_msg, hf_tcpclv4_msg_reject_head, tvb, offset, 1, rej_head);
            offset += 1;

            break;
        }
        default:
            expert_add_info(pinfo, item_msg, &ei_tcpclv4_invalid_msg_type);
            break;
    }

    proto_item_set_len(item_msg, offset - payload_len);
    proto_item_append_text(item_msg, ": %s%s", msgtype_name, wmem_strbuf_get_str(suffix_text));
    wmem_strbuf_finalize(suffix_text);

    if (tcpcl_analyze_sequence) {
        if (!(ctx->tx_peer->sess_init_seen)) {
            expert_add_info(pinfo, item_msg, &ei_tcpclv4_sess_init_missing);
        }
        else {
            // This message is before SESS_INIT (but is not the SESS_INIT)
            const gint cmp_sess_init = tcpcl_frame_loc_compare(ctx->cur_loc, ctx->tx_peer->sess_init_seen, NULL);
            if (((msgtype == TCPCLV4_MSGTYPE_SESS_INIT) && (cmp_sess_init < 0))
                || ((msgtype != TCPCLV4_MSGTYPE_SESS_INIT) && (cmp_sess_init <= 0))) {
                expert_add_info(pinfo, item_msg, &ei_tcpclv4_sess_init_missing);
            }
        }
    }

    if (msgtype_name) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, msgtype_name);
    }

    try_negotiate(ctx, pinfo);
    // Show negotiation results
    if (msgtype == TCPCLV4_MSGTYPE_SESS_INIT) {
        if (ctx->convo->sess_negotiated) {
            if (ctx->rx_peer->sess_init_seen){
                proto_item *item_nego = proto_tree_add_uint(tree_msg, hf_tcpclv4_sess_init_related, tvb, 0, 0, ctx->rx_peer->sess_init_seen->frame_num);
                PROTO_ITEM_SET_GENERATED(item_nego);
            }
            {
                proto_item *item_nego = proto_tree_add_uint(tree_msg, hf_tcpclv4_negotiate_keepalive, tvb, 0, 0, ctx->convo->sess_keepalive);
                PROTO_ITEM_SET_GENERATED(item_nego);
            }
        }
    }

    return offset;
}

static guint get_message_len(packet_info *pinfo, tvbuff_t *tvb, int ext_offset, void *data _U_) {
    tcpcl_dissect_ctx_t *ctx = tcpcl_dissect_ctx_get(tvb, pinfo, ext_offset);
    if (!ctx) {
        return 0;
    }
    const guint init_offset = ext_offset;
    guint offset = ext_offset;

    if (ctx->is_contact) {
        offset += 4;
        guint8 version = tvb_get_guint8(tvb, offset);
        offset += 1;
        if (version == 3) {
            offset += 3;
            int bytecount;
            int len = evaluate_sdnv(tvb, offset, &bytecount);
            offset += len + 1;
        }
        else if (version == 4) {
            offset += 1;
        }
        else {
            return 0;
        }
    }
    else {
        if (ctx->tx_peer->version == 3) {
            guint sublen = get_v3_msg_len(pinfo, tvb, offset, ctx);
            if (sublen == 0) {
                return 0;
            }
            offset += sublen;
        }
        else if (ctx->tx_peer->version == 4) {
            guint sublen = get_v4_msg_len(pinfo, tvb, offset, ctx);
            if (sublen == 0) {
                return 0;
            }
            offset += sublen;
        }
        else {
            return 0;
        }
    }
    const int needlen = offset - init_offset;
    return needlen;
}

static gint dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    tcpcl_dissect_ctx_t *ctx = tcpcl_dissect_ctx_get(tvb, pinfo, offset);
    if (!ctx) {
        return 0;
    }

    {
        const gchar *proto_name = col_get_text(pinfo->cinfo, COL_PROTOCOL);
        if (g_strcmp0(proto_name, proto_name_tcpcl) != 0) {
            col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_tcpcl);
            col_clear(pinfo->cinfo, COL_INFO);
        }
    }

    // Don't add more than one TCPCL tree item
    proto_item *item_tcpcl;
    proto_tree *tree_tcpcl;
    if (tree && (tree->last_child)
            && (tree->last_child->finfo->hfinfo->id == proto_tcpcl)) {
        item_tcpcl = tree->last_child;
        tree_tcpcl = proto_item_get_subtree(item_tcpcl);
    }
    else {
        item_tcpcl = proto_tree_add_item(tree, proto_tcpcl, tvb, 0, 0, ENC_NA);
        tree_tcpcl = proto_item_add_subtree(item_tcpcl, ett_proto_tcpcl);
    }

    if (ctx->is_contact) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Contact Header");

        proto_item *item_chdr = proto_tree_add_item(tree_tcpcl, hf_chdr_tree, tvb, offset, -1, ENC_NA);
        proto_tree *tree_chdr = proto_item_add_subtree(item_chdr, ett_chdr);

        const void *magic_data = tvb_memdup(wmem_packet_scope(), tvb, offset, sizeof(magic));
        proto_item *item_magic = proto_tree_add_bytes(tree_chdr, hf_chdr_magic, tvb, offset, 4, magic_data);
        offset += sizeof(magic);
        if (memcmp(magic_data, magic, sizeof(magic)) != 0) {
            expert_add_info(pinfo, item_magic, &ei_invalid_magic);
            return offset;
        }

        ctx->tx_peer->version = tvb_get_guint8(tvb, offset);
        proto_item *item_version = proto_tree_add_uint(tree_chdr, hf_chdr_version, tvb, offset, 1, ctx->tx_peer->version);
        offset += 1;

        // Mark or check version match
        if (!ctx->convo->version) {
            ctx->convo->version = wmem_new(wmem_file_scope(), guint8);
            *(ctx->convo->version) = ctx->tx_peer->version;
        }
        else if (*(ctx->convo->version) != ctx->tx_peer->version) {
            expert_add_info(pinfo, item_version, &ei_mismatch_version);
        }

        if ((ctx->tx_peer->version < 3) || (ctx->tx_peer->version > 4)) {
            expert_add_info(pinfo, item_version, &ei_invalid_version);
            return offset;
        }

        if (ctx->tx_peer->version == 3) {
            /* Subtree to expand the bits in the Contact Header Flags */
            proto_tree_add_bitmask(tree_chdr, tvb, offset, hf_tcpclv3_chdr_flags, ett_tcpclv3_chdr_flags, v3_chdr_flags, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(tree_chdr, hf_tcpclv3_chdr_keep_alive, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /*
             * New format Contact header has length field followed by Bundle Header.
             */
            int sdnv_length;
            expert_field *ei_bundle_sdnv_length;
            int eid_length = evaluate_sdnv_ei(tvb, offset, &sdnv_length, &ei_bundle_sdnv_length);
            proto_item *item_len = proto_tree_add_int(tree_chdr, hf_tcpclv3_chdr_local_eid_length, tvb, offset, sdnv_length, eid_length);
            offset += sdnv_length;
            if (ei_bundle_sdnv_length) {
                expert_add_info(pinfo, item_len, ei_bundle_sdnv_length);
                return offset;
            }

            proto_tree_add_item(tree_chdr, hf_tcpclv3_chdr_local_eid, tvb, offset, eid_length, ENC_NA|ENC_ASCII);
            offset += eid_length;

            // assumed parameters
            ctx->tx_peer->segment_mru = G_MAXUINT64;
            ctx->tx_peer->transfer_mru = G_MAXUINT64;
        }
        else if (ctx->tx_peer->version == 4) {
            guint8 flags = tvb_get_guint8(tvb, offset);
            proto_tree_add_bitmask(tree_chdr, tvb, offset, hf_tcpclv4_chdr_flags, ett_tcpclv4_chdr_flags, v4_chdr_flags, ENC_BIG_ENDIAN);
            offset += 1;

            ctx->tx_peer->can_tls = (flags & TCPCLV4_CONTACT_FLAG_CANTLS);
        }

        proto_item_set_len(item_chdr, offset);

        if (ctx->tx_peer->chdr_seen) {
            if (tcpcl_analyze_sequence) {
                if (!tcpcl_frame_loc_equal(ctx->tx_peer->chdr_seen, ctx->cur_loc)) {
                    expert_add_info(pinfo, item_chdr, &ei_chdr_duplicate);
                }
            }
        }
        else {
            ctx->tx_peer->chdr_seen = tcpcl_frame_loc_clone(wmem_file_scope(), ctx->cur_loc);
        }

        try_negotiate(ctx, pinfo);
        // Show negotiation results
        if (ctx->convo->contact_negotiated) {
            if (ctx->rx_peer->chdr_seen) {
                proto_item *item_nego = proto_tree_add_uint(tree_chdr, hf_chdr_related, tvb, 0, 0, ctx->rx_peer->chdr_seen->frame_num);
                PROTO_ITEM_SET_GENERATED(item_nego);
            }
            if (ctx->tx_peer->version == 4) {
                proto_item *item_nego = proto_tree_add_boolean(tree_chdr, hf_tcpclv4_negotiate_use_tls, tvb, 0, 0, ctx->convo->session_use_tls);
                PROTO_ITEM_SET_GENERATED(item_nego);
            }
        }
    }
    else {
        if (ctx->tx_peer->version == 3) {
            offset += dissect_v3_msg(tvb, pinfo, tree_tcpcl, ctx);
        }
        else if (ctx->tx_peer->version == 4) {
            offset += dissect_v4_msg(tvb, pinfo, tree_tcpcl, ctx);
        }
    }

    const int item_len = proto_item_get_len(item_tcpcl);
    gboolean is_new_item_tcpcl = (item_len <= 0);
    if (is_new_item_tcpcl) {
        proto_item_set_len(item_tcpcl, offset);
        proto_item_append_text(item_tcpcl, " Version %d", ctx->tx_peer->version);
    }
    else {
        proto_item_set_len(item_tcpcl, item_len + offset);
    }

    if (ctx->xferload) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Bundle]");

        if (tcpcl_decode_bundle) {
            if (bundle_handle) {
                call_dissector(
                    bundle_handle,
                    ctx->xferload,
                    pinfo,
                    tree
                );
            }
        }
    }

    return offset;
}

static int
dissect_tcpcl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Retrieve information from conversation, or add it if it isn't
     * there yet */
    conversation_t *convo = find_or_create_conversation(pinfo);
    tcpcl_conversation_t *tcpcl_convo = (tcpcl_conversation_t *)conversation_get_proto_data(convo, proto_tcpcl);
    if (!tcpcl_convo) {
        tcpcl_convo = tcpcl_conversation_new();
        conversation_add_proto_data(convo, proto_tcpcl, tcpcl_convo);
        // Assume the first source (i.e. TCP initiator) is the active node
        copy_address_wmem(wmem_file_scope(), &(tcpcl_convo->active->addr), &(pinfo->src));
        tcpcl_convo->active->port = pinfo->srcport;
        copy_address_wmem(wmem_file_scope(), &(tcpcl_convo->passive->addr), &(pinfo->dst));
        tcpcl_convo->passive->port = pinfo->destport;
    }

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 1, get_message_len, dissect_message, NULL);

    const guint buflen = tvb_captured_length(tvb);
    return buflen;
}

static int dissect_xferext_transferlen(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    int offset = 0;
    tcpcl_dissect_ctx_t *ctx = tcpcl_dissect_ctx_get(tvb, pinfo, offset);
    if (!ctx) {
        return 0;
    }

    guint64 total_len = tvb_get_guint64(tvb, offset, ENC_BIG_ENDIAN);
    proto_item *item_len = proto_tree_add_uint64(tree, hf_tcpclv4_xferext_transferlen_total_len, tvb, offset, 8, total_len);
    offset += 8;
    if (total_len > ctx->rx_peer->transfer_mru) {
        expert_add_info(pinfo, item_len, &ei_tcpclv4_xferload_over_xfer_mru);
    }

    if (tcpcl_analyze_sequence) {
        guint64 *xfer_id = wmem_map_lookup(ctx->tx_peer->frame_loc_to_transfer, ctx->cur_loc);
        if (xfer_id) {
            tcpcl_transfer_t *xfer = get_or_create_transfer_t(ctx->tx_peer->transfers, *xfer_id);
            xfer->total_length = wmem_new(wmem_file_scope(), guint64);
            *(xfer->total_length) = total_len;
        }
    }

    return offset;
}

static int dissect_othername_bundleeid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    asn1_ctx_t actx;
    asn1_ctx_init(&actx, ASN1_ENC_BER, TRUE, pinfo);
    offset += dissect_ber_restricted_string(
        FALSE, BER_UNI_TAG_IA5String,
        &actx, tree, tvb, offset, hf_othername_bundleeid, NULL
    );
    return offset;
}

/// Re-initialize after a configuration change
static void reinit_tcpcl(void) {
}

void
proto_register_tcpclv3(void)
{
    expert_module_t *expert_tcpcl;

    proto_tcpcl = proto_register_protocol(
        "DTN TCP Convergence Layer Protocol",
        "TCPCL",
        "tcpcl"
    );

    proto_tcpcl_exts = proto_register_protocol_in_name_only(
        "TCPCL Extension Subdissectors",
        "TCPCL Extension Subdissectors",
        "tcpcl_exts",
        proto_tcpcl,
        FT_PROTOCOL
    );

    proto_register_field_array(proto_tcpcl, hf_tcpcl, array_length(hf_tcpcl));
    proto_register_subtree_array(ett, array_length(ett));
    expert_tcpcl = expert_register_protocol(proto_tcpcl);
    expert_register_field_array(expert_tcpcl, ei_tcpcl, array_length(ei_tcpcl));

    tcpcl_handle = create_dissector_handle(dissect_tcpcl, proto_tcpcl);
    sess_ext_dissectors = register_dissector_table("tcpcl.v4.sess_ext", "TCPCLv4 Session Extension", proto_tcpcl, FT_UINT16, BASE_HEX);
    xfer_ext_dissectors = register_dissector_table("tcpcl.v4.xfer_ext", "TCPCLv4 Transfer Extension", proto_tcpcl, FT_UINT16, BASE_HEX);

    module_t *module_tcpcl = prefs_register_protocol(proto_tcpcl, reinit_tcpcl);
    prefs_register_bool_preference(
        module_tcpcl,
        "analyze_sequence",
        "Analyze message sequences",
        "Whether the TCPCLv4 dissector should analyze the sequencing of "
        "the messages within each session.",
        &tcpcl_analyze_sequence
    );
    prefs_register_bool_preference(
        module_tcpcl,
        "desegment_transfer",
        "Reassemble the segments of each transfer",
        "Whether the TCPCLv4 dissector should combine the sequential segments "
        "of a transfer into the full bundle being transfered."
        "To use this option, you must also enable "
        "\"Allow subdissectors to reassemble TCP streams\" "
        "in the TCP protocol settings.",
        &tcpcl_desegment_transfer
    );
    prefs_register_bool_preference(
        module_tcpcl,
        "decode_bundle",
        "Decode bundle data",
        "If enabled, the bundle will be decoded as BPv7 content. "
        "Otherwise, it is assumed to be plain CBOR.",
        &tcpcl_decode_bundle
    );

    reassembly_table_register(
        &xfer_reassembly_table,
        &xfer_reassembly_table_functions
    );

}

void
proto_reg_handoff_tcpclv3(void)
{
    tls_handle = find_dissector_add_dependency("tls", proto_tcpcl);
    bundle_handle = find_dissector("bundle");

    dissector_add_uint_with_preference("tcp.port", BUNDLE_PORT, tcpcl_handle);

    /* Packaged extensions */
    {
        dissector_handle_t dis_h = create_dissector_handle_with_name(dissect_xferext_transferlen, proto_tcpcl_exts, "Transfer Length");
        dissector_add_uint("tcpcl.v4.xfer_ext", TCPCLV4_XFEREXT_TRANSFER_LEN, dis_h);
    }

    register_ber_oid_dissector("1.3.6.1.5.5.7.3.35", NULL, proto_tcpcl_exts, "id-kp-bundleSecurity");
    register_ber_oid_dissector("1.3.6.1.5.5.7.8.11", dissect_othername_bundleeid, proto_tcpcl_exts, "id-on-bundleEID");

    reinit_tcpcl();
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
