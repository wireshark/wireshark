/* packet-wlccp.c
 * Routines for Cisco Wireless LAN Context Control Protocol dissection
 *
 * Copyright 2005, Joerg Mayer (see AUTHORS file)
 * Copyright 2006, Stephen Fisher (see AUTHORS file)
 * Copyright 2007, Kevin A. Noll <maillistnoll@earthlink.net>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * The CISCOWL dissector was merged into this one.
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

/* Version 0x00 was reverse engineered */
/* Version 0xC1 Protocol reference: US Patent Application 0050220054 */
/* and considerable reverse engineering due to the patent application*/
/* being incomplete                                                  */

/* More clues to version 0x00 of the protocol:
 *
 * Header (Eth V2 or SNAP)
 * Length (2 bytes)
 * Type (2 bytes)
 *	0202: Unknown, Length 36 (14 + 20 + 2)
 *	4001: Unknown, Length 48 (14 + 32 + 2)
 *	4601: Unknown, Length 34 (14 + 18 + 2)
 *	4081 on Eth V2: Name, Version Length 84 (14 + 48 + 20 + 2)
 *	4081 on 802.3: Name Length 72 (14 + 56 + 2)
 * Dst MAC (6 bytes)
 * Src MAC (6 bytes)
 * Unknown1 (2 bytes)  Unknown19 + Unknown2 may be a MAC address on type 0202
 * Unknown2 (4 bytes)	see Unknown19
 * 0 (17 bytes)
 * Device IP (4 bytes)
 * 0 (2 bytes)
 * Device name (8 bytes)
 * 0 (20 bytes)
 * Unknown3 (2 bytes)
 * Unknown4 (4 bytes)
 * Version string (10 bytes)
 * 0 (4 bytes)
 * 0 (2 bytes)
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/oui.h>
#include "packet-llc.h"


/* The UDP port that WLCCP is expected to ride on */
/* WLCCP also uses an LLC OUI type and an ethertype */
#define WLCCP_UDP_PORT 2887


/* SAP is 2-bit version and 6-bit Type */
#define SAP_VERSION_MASK (0xC0)
#define SAP_VALUE_MASK (0x3f)

static const value_string wlccp_sap_vs[] = {
	{ 0x0, "Context Management"        },
	{ 0x1, "Security"		   },
	{ 0x2, "Radio Resource Management" },
	{ 0x3, "QOS"			   },
	{ 0x4, "Network Management"	   },
	{ 0x5, "MIP"			   },
	{ 0, NULL                          }
};

#define WLCCP_SAP_CCM (0x00)
#define WLCCP_SAP_SEC (0x01)
#define WLCCP_SAP_RRM (0x02)
#define WLCCP_SAP_QOS (0x03)
#define WLCCP_SAP_NM  (0x04)
#define WLCCP_SAP_MIP (0x05)

static const value_string wlccp_node_type_vs[] = {
	{ 0x00, "None"				},
	{ 0x01, "Access Point (AP)"		},
	{ 0x02, "Subnet Context Manager (SCM)"	},
	{ 0x04, "Local Context Manager (LCM)" 	},
	{ 0x08, "Campus Context Manager (CCM)"	},
	{ 0x10, "Infrastructure (ICN)"      	},
	{ 0x40, "Client"			},
/*	{ 0x8000, "Multi Mask?"		    }, */
	{ 0, NULL				}
};

/* The Message Type field contains a 2-bit Sub-Type and a 6-bit Base Message Type */
#define MT_SUBTYPE         (0xC0)
#define MT_BASE_MSG_TYPE   (0x3F)

static const value_string wlccp_subtype_vs[] = {
	{ 0x0, "Request" },
	{ 0x1, "Reply"   },
	{ 0x2, "Confirm" },
	{ 0x3, "Ack"     },
	{ 0, NULL      }
};

/* The Message Type definitions are a combination of the SAP and the Type_ID 	*/
/* fields. These mappings are not well documented and have been gathered from a */
/* combination of the WLCCP patent application, experimentation, and WLCCP 	*/
/* device logs.									*/

/* For SAP=0 */
static const value_string wlccp_msg_type_vs_0[] = {
	{ 0x1, "SCM Advertise"			},
	{ 0x2, "CCM Advertise"			},
	{ 0x3, "Registration"			},
	{ 0x4, "DeRegistration"			},
	{ 0x5, "Detach"				},
	{ 0x6, "Context"			},
	{ 0x7, "Path Update"			},
	{ 0x8, "Path Check"			},
	{ 0x9, "PreRegistration"		},
	{ 0x0a, "Trace"				},
	{ 0x0b, "cmAAA EAP Authent"		},
	{ 0x0c, "cmPathInit Path Authent"	},
	{ 0x0f, "cmWIDS"			},
	{ 0, NULL				}

};

/* For SAP=1 */
static const value_string wlccp_msg_type_vs_1[] = {
/*	{ 0x1, "Unknown" 			}, */
	{ 0, NULL				}

};

/* For SAP=2 */
static const value_string wlccp_msg_type_vs_2[] = {
	{ 0x1, "rmReq" 				},
	{ 0x2, "rmReqRoutingResp"		},
	{ 0x3, "rmReport"			},
	{ 0, NULL				}

};

/* For SAP=3 */
static const value_string wlccp_msg_type_vs_3[] = {
/*	{ 0x1, "Unknown" 			}, */
	{ 0, NULL				}

};

/* For SAP=4 */
static const value_string wlccp_msg_type_vs_4[] = {
	{ 0x01, "nmAck" 			},
	{ 0x10, "nmConfigRequest"		},
	{ 0x11, "nmConfigReply"			},
	{ 0x20, "nmApRegistration"		},
	{ 0x21, "nmScmStateChange"		},
	{ 0x22, "nmScmKeepActive"		},
	{ 0x30, "nmClientEventReport"		},
	{ 0x31, "nmAllClientRefreshRequest"	},
	{ 0, NULL				}

};

/* For SAP=5 */
static const value_string wlccp_msg_type_vs_5[] = {
/*	{ 0x1, "Unknown" 			}, */
	{ 0, NULL				}

};


/* Mask definitions for the CM Flags field */
#define F_RETRY            (1<<15)
#define F_RESPONSE_REQUEST (1<<14)
#define F_TLV              (1<<13)
#define F_INBOUND          (1<<12)
#define F_OUTBOUND         (1<<11)
#define F_HOPWISE_ROUTING  (1<<10)
#define F_ROOT_CM          (1<<9)
#define F_RELAY            (1<<8)
#define F_MIC              (1<<7)

/* Mask definitions for the RM Flags field */
#define RM_F_REQUEST_REPLY    (1<<0)
#define RM_F_MIC              (1<<1)

/* Mask definitions for the NM Flags field */
/* the NM flags are the same as the CM flags except there is no
INBOUND, OUTBOUND, HOPWISE_ROUTING, ROOT_CM, or RELAY flag, and
the RESPONSE_REQUEST flag is renamed ACK_REQD
*/
#define F_ACK_REQD         (1<<14)


/* Mask definitions for the SCM Flags field */
#define F_SCM_LAYER2UPDATE	(1<<3)
#define F_SCM_UNATTACHED	(1<<2)
#define F_SCM_UNSCHEDULED 	(1<<1)
#define F_SCM_ACTIVE 		(1<<0)

/* Mask definitions for the SCM Priority Flags field */
#define F_SCM_PRIORITY 	0xfe
#define F_SCM_PREFERRED 	0x01

/* Mask definitions for the SCM Bridge Priority Flags field */
#define F_SCM_BRIDGE_PRIORITY	0xfe
#define F_SCM_BRIDGE_DISABLE	0x01

/* The TLV Type definitions are a combination of the TLV Group and the       */
/* TLV Type ID fields. These mappings are not well documented and have been  */
/* gathered from a combination of the WLCCP patent application,              */
/* experimentation, and WLCCP device logs                                    */

/* The TLV Group/Type Field contains some flags and the Group ID and Type ID */
#define TLV_F_CONTAINER		(0x8000)
#define TLV_F_ENCRYPTED		(0x4000)
#define TLV_F_RESVD		(0x3000)
#define TLV_F_RESVD2		(0x2000)
#define TLV_F_RESVD3		(0x1000)
#define TLV_F_REQUEST		(0x0080)
#define TLV_GROUP_ID		(0x0F00)
#define TLV_TYPE_ID		(0x007F)

static const value_string wlccp_tlv_group_vs[] = {
	{ 0x0, "WLCCP Group"			},
	{ 0x1, "Security Group"			},
	{ 0x2, "RRM Group"			},
	{ 0x3, "QOS Group"			},
	{ 0x4, "NM Group"			},
	{ 0x5, "MIP Group"			},
	{ 0, NULL				}
};


#define WLCCP_TLV_GROUP_WLCCP (0x00)
#define WLCCP_TLV_GROUP_SEC (0x01)
#define WLCCP_TLV_GROUP_RRM (0x02)
#define WLCCP_TLV_GROUP_QOS (0x03)
#define WLCCP_TLV_GROUP_NM  (0x04)
#define WLCCP_TLV_GROUP_MIP (0x05)

/* Group 0 */
static const value_string wlccp_tlv_typeID_0[] = {
	{ 0x00, "NULL TLV"				},
	{ 0x09, "ipv4Address"				},
	{ 0x01, "Container"				},
	{ 0x02, "AP Port Info"				},
	{ 0x03, "ipv4 Subnet ID"			},
	{ 0x04, "Secondary LAN Address List"		},
	{ 0x05, "Multicast Ethernet Address List"	},
	{ 0x06, "ipv4 Multicast Address List"		},
	{ 0x07, "AP Port List"				},
	{ 0x08, "Requestor SSID"			},
	{ 0, NULL					}
};

/* Group 1 */
static const value_string wlccp_tlv_typeID_1[] = {
	{ 0x01, "initSession"				},
	{ 0x02, "inSecureContextReq"			},
	{ 0x06, "authenticator"				},
	{ 0x08, "mic"					},
	{ 0x0a, "inSecureContextReply"			},
	{ 0, NULL					}
};

/* Group 2 */
static const value_string wlccp_tlv_typeID_2[] = {
	{ 0x03, "rmReport"				},
	{ 0x04, "aggrRmReport"				},
	{ 0x15, "frameReport"				},
	{ 0x17, "ccaReport"				},
	{ 0x19, "rpiHistReport"				},
	{ 0x1e, "commonBeaconReport"			},
	{ 0x1f, "aggrBeaconReport"			},
	{ 0x5b, "mfpRouting"				},
	{ 0x5c, "mfpConfig"				},
	{ 0, NULL					}
};

/* Group 3 */
static const value_string wlccp_tlv_typeID_3[] = {
/*	{ 0x01, "Unknown"				} */
	{ 0, NULL					},
};

/* Group 4 */
static const value_string wlccp_tlv_typeID_4[] = {
/*	{ 0x01, "Unknown"				} */
	{ 0, NULL					},
};

/* Group 5 */
static const value_string wlccp_tlv_typeID_5[] = {
/*	{ 0x01, "Unknown"				} */
	{ 0, NULL					},
};





static const value_string wlccp_aaa_msg_type_vs[] = {
	{ 0x0, "Start"				},
	{ 0x1, "Finish"				},
	{ 0x2, "EAPOL"				},
	{ 0x3, "Cisco Accounting"		},
	{ 0, NULL				}
};

static const value_string wlccp_eapol_auth_type_vs[] = {
	{ 0x0, "EAP Only"			},
	{ 0x1, "MAC Only"			},
	{ 0x2, "MAC then EAP"			},
	{ 0x3, "MAC and EAP"			},
	{ 0x4, "LEAP only"			},
	{ 0x5, "MAC then LEAP"			},
	{ 0x6, "MAC and LEAP"			},
	{ 0, NULL				}
};

static const value_string wlccp_key_mgmt_type_vs[] = {
	{ 0x0, "None"				},
	{ 0x1, "CCKM"				},
	{ 0x2, "Legacy 802.1x"			},
	{ 0x3, "SSN/TGi"			},
	{ 0, NULL				}
};

static const value_string eapol_type_vs[] = {
	{ 0x0, "EAP Packet"			},
	{ 0x1, "EAP Start"			},
	{ 0x2, "Unknown"			},
	{ 0x3, "Key"				},
	{ 0, NULL				}

};

static const value_string wlccp_status_vs[] = {
	{0, "Success"				},
	{ 0, NULL				}
};

static const value_string cisco_pid_vals[] = {
        { 0x0000, "WLCCP" },
        { 0, NULL         }
};

static const value_string wlccp_mode_vs[] = {
	{ 0x0,		"apSelected"	},
	{0x01,		"series"	},
	{0x3,		"parallel"	},
	{0, NULL			}
};


static const value_string phy_type_80211_vs[] = {
	{ 0x01,		"FHSS 2.4 GHz"		},
	{ 0x02,		"DSSS 2.4 GHz"		},
	{ 0x03,		"IR Baseband"		},
	{ 0x04,		"OFDM 5GHz"		},
	{ 0x05,		"HRDSSS"		},
	{ 0x06,		"ERP"			},
	{ 0, NULL				}
};


/* 802.11 capabilities flags */
#define F_80211_ESS		0x0001
#define F_80211_IBSS		0x0002
#define F_80211_CFPOLL		0x0004
#define F_80211_CFPOLL_REQ	0x0008
#define F_80211_PRIVACY		0x0010
#define F_80211_SHORT_PREAMBLE	0x0020
#define F_80211_PBCC		0x0040
#define F_80211_CH_AGILITY	0x0080
#define F_80211_SPEC_MGMT	0x0100
#define F_80211_QOS		0x0200
#define F_80211_SHORT_TIME_SLOT	0x0400
#define F_80211_APSD		0x0800
#define F_80211_RESVD		0x1000
#define F_80211_DSSS_OFDM	0x2000
#define F_80211_DLYD_BLK_ACK	0x4000
#define F_80211_IMM_BLK_ACK	0x8000




/*
struct subdissector_returns_t
{
	static int consumed
	static gboolean mic_flag;
	static gboolean tlv_flag;
}; * struct flags_t declaration *
*/



/* Forward declarations we need below */
static guint dissect_wlccp_ccm_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type);
static guint dissect_wlccp_sec_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type);
static guint dissect_wlccp_rrm_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type);
static guint dissect_wlccp_qos_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type);
static guint dissect_wlccp_nm_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type);
static guint dissect_wlccp_mip_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type);

static guint dissect_wlccp_tlvs(proto_tree *_tree, tvbuff_t *tvb, guint tlv_offset, guint _depth);

static guint dissect_wlccp_ccm_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti);
static guint dissect_wlccp_sec_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti);
static guint dissect_wlccp_rrm_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti);
static guint dissect_wlccp_qos_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti);
static guint dissect_wlccp_nm_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti);
static guint dissect_wlccp_mip_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti);

static void set_mic_flag(gboolean flag);
static void set_tlv_flag(gboolean flag);
static gboolean get_tlv_flag(void);
static gboolean get_mic_flag(void);

/* Initialize some utlity variables */
static gboolean mic_flag=0, tlv_flag=0;

/* Initialize the protocol and registered fields */
static int proto_wlccp = -1;

static int hf_llc_wlccp_pid = -1;



static int hf_wlccp_dstmac = -1;
static int hf_wlccp_srcmac = -1;
static int hf_wlccp_hostname = -1;

/* WLCCP Fixed header fields */
static int hf_wlccp_version = -1;

static int hf_wlccp_sap = -1; /* SAP Tree */
static int hf_wlccp_sap_version = -1;
static int hf_wlccp_sap_id = -1;

static int hf_wlccp_destination_node_type = -1;
static int hf_wlccp_length = -1;

static int hf_wlccp_type = -1; /* Message Type Tree */
static int hf_wlccp_subtype = -1;
static int hf_wlccp_base_message_type_0 = -1;
static int hf_wlccp_base_message_type_1 = -1;
static int hf_wlccp_base_message_type_2 = -1;
static int hf_wlccp_base_message_type_3 = -1;
static int hf_wlccp_base_message_type_4 = -1;
static int hf_wlccp_base_message_type_5 = -1;
static int hf_wlccp_base_message_type_unknown = -1;

static int hf_wlccp_hops = -1;
static int hf_wlccp_nm_version = -1;

static int hf_wlccp_msg_id = -1;

static int hf_wlccp_flags = -1; /* Flags Tree */
static int hf_wlccp_rm_flags = -1;
static int hf_wlccp_retry_flag = -1;
static int hf_wlccp_response_request_flag = -1;
static int hf_wlccp_ack_required_flag = -1;
static int hf_wlccp_tlv_flag = -1;
static int hf_wlccp_inbound_flag = -1;
static int hf_wlccp_outbound_flag = -1;
static int hf_wlccp_hopwise_routing_flag = -1;
static int hf_wlccp_root_cm_flag = -1;
static int hf_wlccp_relay_flag = -1;
static int hf_wlccp_mic_flag = -1;
static int hf_wlccp_rm_request_reply_flag = -1;
static int hf_wlccp_rm_mic_flag = -1;

static int hf_wlccp_originator = -1; /* Originator Tree */
static int hf_wlccp_originator_node_type = -1;
/* static int hf_wlccp_originator_id = -1; */

static int hf_wlccp_responder = -1; /* Responder Tree */
static int hf_wlccp_responder_node_type = -1;
/*static int hf_wlccp_responder_id = -1; */


/* static int hf_wlccp_relay_node = -1;*/ /* Relay Node Tree */
static int hf_wlccp_relay_node_type = -1;
static int hf_wlccp_relay_node_id = -1;

static int hf_wlccp_priority = -1;
static int hf_wlccp_age = -1;
static int hf_wlccp_period = -1;
static int hf_wlccp_ipv4_address = -1;

/* SCM Advertisement */
static int hf_wlccp_scm_hop_address = -1;

static int hf_wlccp_scm_flags = -1; /* SCM Flags Tree */
static int hf_wlccp_scm_active_flag = -1;
static int hf_wlccp_scm_unscheduled_flag = -1;
static int hf_wlccp_scm_unattached_flag = -1;
static int hf_wlccp_scm_layer2update_flag = -1;

static int hf_wlccp_scm_election_group = -1;
static int hf_wlccp_scm_attach_count = -1;

static int hf_wlccp_scm_priority_flags = -1; /* SCM Priority Flags */
static int hf_wlccp_scm_priority = -1;
static int hf_wlccp_scm_preferred_flag = -1;

static int hf_wlccp_scm_bridge_priority_flags = -1; /* SCM Bridge Priority Flags */
static int hf_wlccp_scm_bridge_priority = -1;
static int hf_wlccp_scm_bridge_disable_flag = -1;

static int hf_wlccp_scm_node_id = -1;
static int hf_wlccp_scm_unknown_short = -1;
static int hf_wlccp_scm_instance_age = -1;
static int hf_wlccp_scm_path_cost = -1;
static int hf_wlccp_scm_hop_count = -1;
static int hf_wlccp_scm_advperiod = -1;

/*kan for apRegistration messages*/
static int hf_wlccp_timestamp = -1;
static int hf_wlccp_apregstatus = -1;
static int hf_wlccp_ap_node_id = -1;
static int hf_wlccp_ap_node_type = -1;
static int hf_wlccp_ap_node_id_address = -1;
/*kan for nmPathInit messages */
static int hf_wlccp_requ_node_type = -1;
static int hf_wlccp_requ_node_id = -1;
static int hf_wlccp_status = -1;
static int hf_wlccp_path_init_rsvd = -1;
/*kan - for cmAAA messages */
static int hf_wlccp_aaa_msg_type = -1;
static int hf_wlccp_aaa_auth_type = -1;
static int hf_wlccp_keymgmt_type = -1;
/*kan - for cmAAA EAPOL messages */
static int hf_wlccp_eapol_msg = -1;
static int hf_wlccp_eapol_version = -1;
static int hf_wlccp_eapol_type = -1;
static int hf_wlccp_eap_msg_length = -1;
static int hf_wlccp_eap_msg = -1;
/*kan - for cmAAA Proprietary message */
static int hf_wlccp_cisco_acctg_msg = -1;
/*kan - for cmWIDS */
static int hf_wlccp_wids_msg_type = -1;
/*kan - for nmConfigRequest and nmConfigReply */
static int hf_wlccp_nmconfig = -1;

static int hf_wlccp_scmstate_change = -1;
static int hf_wlccp_scmstate_change_reason = -1;

static int hf_wlccp_scmattach_state = -1;
static int hf_wlccp_nmcapability = -1;
static int hf_wlccp_refresh_req_id = -1;

static int hf_wlccp_tlv = -1;
static int hf_tlv_flags = -1;

static int hf_wlccp_null_tlv = -1;

static int hf_wlccp_tlv_type = -1;
static int hf_wlccp_tlv_type0 = -1;
static int hf_wlccp_tlv_type1 = -1;
static int hf_wlccp_tlv_type2 = -1;
static int hf_wlccp_tlv_type3 = -1;
static int hf_wlccp_tlv_type4 = -1;
static int hf_wlccp_tlv_type5 = -1;
static int hf_wlccp_tlv_group = -1;
static int hf_wlccp_tlv_container_flag = -1;
static int hf_wlccp_tlv_encrypted_flag = -1;
static int hf_wlccp_tlv_request_flag = -1;
static int hf_wlccp_tlv_reserved_bit = -1;
static int hf_wlccp_tlv_length = -1;

/* static int hf_wlccp_tlv_value = -1; */

static int hf_wlccp_path_length = -1;
static int hf_wlccp_mic_msg_seq_count = -1;
static int hf_wlccp_mic_length = -1;
static int hf_wlccp_mic_value = -1;

static int hf_wlccp_key_seq_count = -1;
static int hf_wlccp_dest_node_type = -1;
static int hf_wlccp_dest_node_id = -1;
static int hf_wlccp_supp_node_type = -1;
static int hf_wlccp_supp_node_id = -1;
static int hf_wlccp_key_mgmt_type = -1;
static int hf_wlccp_nonce = -1;
static int hf_wlccp_session_timeout = -1;
static int hf_wlccp_src_node_type = -1;
static int hf_wlccp_src_node_id = -1;
static int hf_wlccp_token = -1;
static int hf_wlccp_mode = -1;
static int hf_wlccp_scan_mode = -1;
static int hf_wlccp_rss = -1;
static int hf_wlccp_srcidx = -1;
static int hf_wlccp_parent_tsf = -1;
static int hf_wlccp_target_tsf = -1;

static int hf_wlccp_channel = -1;
static int hf_wlccp_phy_type = -1;
static int hf_wlccp_bssid = -1;
static int hf_wlccp_beacon_interval = -1;
/* static int hf_wlccp_capabilities = -1; */
static int hf_wlccp_tlv80211 = -1;
static int hf_wlccp_duration = -1;
static int hf_wlccp_rpidensity = -1;
static int hf_wlccp_ccabusy = -1;
static int hf_wlccp_sta_type = -1;
static int hf_wlccp_stamac = -1;
static int hf_wlccp_token2 = -1;
static int hf_wlccp_interval = -1;
static int hf_wlccp_count = -1;
static int hf_framereport_elements = -1;
static int hf_wlccp_numframes = -1;
static int hf_wlccp_mfpcapability = -1;
static int hf_wlccp_mfpflags = -1;
static int hf_wlccp_mfpconfig = -1;
static int hf_wlccp_clientmac = -1;
static int hf_time_elapsed = -1;
static int hf_wlccp_parent_ap_mac = -1;
static int hf_wlccp_auth_type =-1;
static int hf_reg_lifetime = -1;
static int hf_wlccp_radius_user_name = -1;
static int hf_wds_reason = -1;


static int hf_wlccp_80211_capabilities = -1;
static int hf_80211_cap_ess = -1;
static int hf_80211_cap_ibss = -1;
static int hf_80211_cap_cf_pollable = -1;
static int hf_80211_cap_cf_poll_req = -1;
static int hf_80211_cap_privacy = -1;
static int hf_80211_short_preamble = -1;
static int hf_80211_pbcc = -1;
static int hf_80211_chan_agility = -1;
static int hf_80211_spectrum_mgmt = -1;
static int hf_80211_qos = -1;
static int hf_80211_short_time_slot = -1;
static int hf_80211_apsd = -1;
static int hf_80211_reserved = -1;
static int hf_80211_dsss_ofdm = -1;
static int hf_80211_dlyd_block_ack = -1;
static int hf_80211_imm_block_ack = -1;


static int hf_wlccp_tlv_unknown_value = -1;

/* Initialize the subtree pointers */
static gint ett_wlccp = -1;
static gint ett_wlccp_sap_tree = -1;
static gint ett_wlccp_type = -1;
static gint ett_wlccp_cm_flags = -1;
static gint ett_wlccp_scm_flags = -1;
static gint ett_wlccp_scm_priority_flags = -1;
static gint ett_wlccp_scm_bridge_priority_flags = -1;
static gint ett_wlccp_rm_flags = -1;
static gint ett_wlccp_nm_flags = -1;


static gint ett_wlccp_flags = -1;
static gint ett_wlccp_ap_node_id = -1;
static gint ett_wlccp_eapol_msg_tree = -1;
static gint ett_wlccp_eap_tree = -1;
static gint ett_wlccp_tlv_tree = -1;
static gint ett_tlv_flags_tree = -1;
static gint ett_tlv_sub_tree = -1;
static gint ett_80211_capability_flags_tree = -1;
static gint ett_framereport_elements_tree = -1;



/* Code to actually dissect the packets */
static void
dissect_wlccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wlccp_tree, *wlccp_sap_tree, *wlccp_type_tree;

	guint offset = 0, old_offset;

	guint8 version=0, sap_id=0;

	guint16 type;
	guint8 base_message_type=0, message_sub_type=0;

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WLCCP");

	if (check_col(pinfo->cinfo, COL_INFO))
	{
		if(tvb_get_guint8(tvb, 0) == 0xC1)  /* Get the version number */
		{

			sap_id = tvb_get_guint8(tvb,1) & SAP_VALUE_MASK;
			base_message_type=(tvb_get_guint8(tvb,6)) & MT_BASE_MSG_TYPE;
			message_sub_type=(tvb_get_guint8(tvb, 6) &  MT_SUBTYPE ) >> 6;


			switch (sap_id)
			{

				case WLCCP_SAP_CCM:
				{

					col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %-27s  SubType: %s",
						val_to_str_const(base_message_type, wlccp_msg_type_vs_0, "Unknown"),
						val_to_str_const(message_sub_type, wlccp_subtype_vs, "Unknown")
					);
					break;

				} /* case WLCCP_SAP_CCM */

				case WLCCP_SAP_SEC:
				{

					col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %-27s  SubType: %s",
						val_to_str_const(base_message_type, wlccp_msg_type_vs_1, "Unknown"),
						val_to_str_const(message_sub_type, wlccp_subtype_vs, "Unknown")
					);
					break;
				} /* case WLCCP_SAP_SEC */

				case WLCCP_SAP_RRM:
				{
					col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %-27s  SubType: %s",
						val_to_str_const(base_message_type, wlccp_msg_type_vs_2, "Unknown"),
						val_to_str_const(message_sub_type, wlccp_subtype_vs, "Unknown")
					);
					break;

				} /* case WLCCP_SAP_RRM */

				case WLCCP_SAP_QOS:
				{
					col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %-27s  SubType: %s",
						val_to_str_const(base_message_type, wlccp_msg_type_vs_3, "Unknown"),
						val_to_str_const(message_sub_type, wlccp_subtype_vs, "Unknown")
					);
					break;
				} /* case WLCCP_SAP_QOS */

				case WLCCP_SAP_NM:
				{
					col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %-27s  SubType: %s",
						val_to_str_const(base_message_type, wlccp_msg_type_vs_4, "Unknown"),
						val_to_str_const(message_sub_type, wlccp_subtype_vs, "Unknown")
					);
					break;

				} /* case WLCCP_SAP_NM */

				case WLCCP_SAP_MIP:
				{
					col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %-27s  SubType: %s",
						val_to_str_const(base_message_type, wlccp_msg_type_vs_5, "Unknown"),
						val_to_str_const(message_sub_type, wlccp_subtype_vs, "Unknown")
					);
					break;
				} /* case WLCCP_SAP_MIP */

				default:
				{
					col_add_fstr(pinfo->cinfo, COL_INFO, "Message Type: %-27s  SubType: %s",
						"Unknown",
						val_to_str_const(message_sub_type, wlccp_subtype_vs, "Unknown")
					);
					break;
				} /* default for switch sap */


			} /* switch sap */

		} /* if version=0xC1 (tvb_get_guint8(tvb, 0) == 0xC1)*/

	} /* if check_col */

	if (tree) {
		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_wlccp, tvb, 0, -1, ENC_NA);
		wlccp_tree = proto_item_add_subtree(ti, ett_wlccp);

		proto_tree_add_item(wlccp_tree, hf_wlccp_version,
				    tvb, offset, 1, ENC_BIG_ENDIAN);

		/* interpretation of the packet is determined by WLCCP version */
		version = tvb_get_guint8(tvb, 0);
		offset += 1;

		if(version == 0x0) {
			proto_tree_add_item(wlccp_tree, hf_wlccp_length,
					    tvb, 1, 1, ENC_BIG_ENDIAN);

			proto_tree_add_item(wlccp_tree, hf_wlccp_type,
					    tvb, 2, 2, ENC_BIG_ENDIAN);
			type = tvb_get_ntohs(tvb, 2);

			proto_tree_add_item(wlccp_tree, hf_wlccp_dstmac,
					    tvb, 4, 6, ENC_NA);

			proto_tree_add_item(wlccp_tree, hf_wlccp_srcmac,
					    tvb, 10, 6, ENC_NA);

			if(type == 0x4081) {
				proto_tree_add_item(wlccp_tree, hf_wlccp_ipv4_address,
						    tvb, 38, 4, ENC_BIG_ENDIAN);

				proto_tree_add_item(wlccp_tree, hf_wlccp_hostname,
						    tvb, 44, 28, ENC_ASCII|ENC_NA);
			} /* if type = 0x4081 */
		} /* if version == 0x00 */

		if(version == 0xC1)
		{

			{ /* SAP Field */
			ti = proto_tree_add_item(wlccp_tree, hf_wlccp_sap,
						tvb, offset, 1, ENC_BIG_ENDIAN);
			wlccp_sap_tree = proto_item_add_subtree(ti, ett_wlccp_sap_tree);

			proto_tree_add_item(wlccp_sap_tree, hf_wlccp_sap_version,
					    tvb, offset, 1, ENC_BIG_ENDIAN);

			proto_tree_add_item(wlccp_sap_tree, hf_wlccp_sap_id,
					    tvb, offset, 1, ENC_BIG_ENDIAN);

 			sap_id = tvb_get_guint8(tvb,offset) & SAP_VALUE_MASK;

			offset += 1;

			} /* SAP Field */

			proto_tree_add_item(wlccp_tree, hf_wlccp_destination_node_type,
					    tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(wlccp_tree, hf_wlccp_length,
					    tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;


			{ /* Message Type Field */
			ti = proto_tree_add_item(wlccp_tree, hf_wlccp_type,
						 tvb, offset, 1, ENC_BIG_ENDIAN);

			wlccp_type_tree = proto_item_add_subtree(ti, ett_wlccp_type);

			proto_tree_add_item(wlccp_type_tree, hf_wlccp_subtype,
					    tvb, offset, 1, ENC_BIG_ENDIAN);

			switch (sap_id)
			{

				case WLCCP_SAP_CCM:
				{

					proto_tree_add_item(wlccp_type_tree, hf_wlccp_base_message_type_0,
							tvb, offset, 1, ENC_BIG_ENDIAN);

					break;

				} /* case WLCCP_SAP_CCM */

				case WLCCP_SAP_SEC:
				{
					proto_tree_add_item(wlccp_type_tree, hf_wlccp_base_message_type_1,
							tvb, offset, 1, ENC_BIG_ENDIAN);

					break;

				} /* case WLCCP_SAP_SEC */

				case WLCCP_SAP_RRM:
				{
					proto_tree_add_item(wlccp_type_tree, hf_wlccp_base_message_type_2,
							tvb, offset, 1, ENC_BIG_ENDIAN);

					break;

				} /* case WLCCP_SAP_RRM */

				case WLCCP_SAP_QOS:
				{
					proto_tree_add_item(wlccp_type_tree, hf_wlccp_base_message_type_3,
							tvb, offset, 1, ENC_BIG_ENDIAN);

					break;

				} /* case WLCCP_SAP_QOS */

				case WLCCP_SAP_NM:
				{
					proto_tree_add_item(wlccp_type_tree, hf_wlccp_base_message_type_4,
							tvb, offset, 1, ENC_BIG_ENDIAN);

					break;

				} /* case WLCCP_SAP_NM */

				case WLCCP_SAP_MIP:
				{
					proto_tree_add_item(wlccp_type_tree, hf_wlccp_base_message_type_5,
							tvb, offset, 1, ENC_BIG_ENDIAN);

					break;

				} /* case WLCCP_SAP_MIP */

				default:
				{

					proto_tree_add_item(wlccp_type_tree, hf_wlccp_base_message_type_unknown,
							tvb, offset, 1, ENC_BIG_ENDIAN);

					break;

				} /* default for switch sap */

			} /* switch sap */

 			base_message_type=(tvb_get_guint8(tvb,offset) & MT_BASE_MSG_TYPE );

			offset += 1;
			} /* Message Type Field */

			/* after the Message Type Field things change based on SAP and Message Type */

			set_mic_flag(FALSE);
			set_tlv_flag(FALSE);

			switch (sap_id)
			{

				case WLCCP_SAP_CCM:
				{

					offset = dissect_wlccp_ccm_msg(wlccp_tree, tvb, offset, base_message_type);

					break;

				} /* case WLCCP_SAP_CCM */

				case WLCCP_SAP_SEC:
				{

					offset = dissect_wlccp_sec_msg(wlccp_tree, tvb, offset, base_message_type);

					break;

				} /* case WLCCP_SAP_SEC */

				case WLCCP_SAP_RRM:
				{

					offset = dissect_wlccp_rrm_msg(wlccp_tree, tvb, offset, base_message_type);

					break;

				} /* case WLCCP_SAP_RRM */

				case WLCCP_SAP_QOS:
				{

					offset = dissect_wlccp_qos_msg(wlccp_tree, tvb, offset, base_message_type);

					break;

				} /* case WLCCP_SAP_QOS */

				case WLCCP_SAP_NM:
				{

					offset = dissect_wlccp_nm_msg(wlccp_tree, tvb, offset, base_message_type);

					break;

				} /* case WLCCP_SAP_NM */

				case WLCCP_SAP_MIP:
				{

					offset = dissect_wlccp_mip_msg(wlccp_tree, tvb, offset, base_message_type);

					break;

				} /* case WLCCP_SAP_MIP */

				default:
				{
					/* what should we do if we get an undefined SAP? */

					break;

				} /* default for switch sap */

			} /* switch sap */



			if(get_tlv_flag() || get_mic_flag())
			{

				if (tvb_length_remaining(tvb,offset) < 4)
				{
				/* something is wrong if the TLV flag is set and there's not enough left in the buffer */

				/* proto_tree_add_string(wlccp_tree, NULL, tvb, offset, -1, "MIC Flag=%d and TLV Flag=%d, but no data left to decode."); */

				} /* if bytes_left <=0 */
				else
				{

					while (tvb_length_remaining(tvb,offset) >= 4)
					{
						old_offset = offset;
						offset = dissect_wlccp_tlvs(wlccp_tree, tvb, offset, 0);
						DISSECTOR_ASSERT(offset > old_offset);
					} /* while bytes_left */

;
				} /*else bytes_left < 4 */

			} /* if tlv_flag || mic_flag */

		} /* if version == 0xC1 */

	} /* if tree */

} /* dissect_wlccp */


/*******************************************************************************************/

/* some utility functions */

/* these could be implemented with a struct */

static void set_mic_flag(gboolean flag)
{
	mic_flag=flag;
} /*set_mic_flag */

static void set_tlv_flag(gboolean flag)
{
	tlv_flag=flag;
} /* set_tlv_flag */

static gboolean get_tlv_flag(void)
{
	return(tlv_flag);
} /* get_tlv_flag */

static gboolean get_mic_flag(void)
{
	return(mic_flag);
} /* get_mic_flag */

/*******************************************************************************************/

static guint dissect_wlccp_ccm_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type)
{
	proto_item *_ti;
	proto_tree *_wlccp_eapol_msg_tree, *_wlccp_cm_flags_tree, *_wlccp_scm_flags_tree, *_wlccp_scm_priority_flags_tree, *_wlccp_scm_bridge_priority_flags_tree;

	gboolean _relay_flag=0, _mic_flag=0, _tlv_flag=0;
	guint8 _aaa_msg_type=0, _eapol_type=0;
	guint16 _eap_msg_length=0;

	proto_tree_add_item(_tree, hf_wlccp_hops,
			    _tvb, _offset, 1, ENC_BIG_ENDIAN);
	_offset += 1;

	proto_tree_add_item(_tree, hf_wlccp_msg_id,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;


/* Decode the CM Flags Field */

	_ti = proto_tree_add_item(_tree, hf_wlccp_flags,
				_tvb, _offset, 2, ENC_BIG_ENDIAN);
	_wlccp_cm_flags_tree = proto_item_add_subtree(_ti, ett_wlccp_cm_flags);


	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_retry_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_response_request_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_tlv_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_tlv_flag = (tvb_get_ntohs(_tvb, _offset)>>13) & 1;
	set_tlv_flag(_tlv_flag);

	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_inbound_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_outbound_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_hopwise_routing_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_root_cm_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_relay_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_relay_flag = (tvb_get_ntohs(_tvb, _offset)>>8) & 1;

	proto_tree_add_item(_wlccp_cm_flags_tree, hf_wlccp_mic_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_mic_flag = (tvb_get_ntohs(_tvb, _offset)>>7) & 1;
	set_mic_flag(_mic_flag);

	_offset += 2;

/* End Decode the CM Flags Field */


	proto_tree_add_item(_tree, hf_wlccp_originator_node_type,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;

	proto_tree_add_item(_tree, hf_wlccp_originator,
			    _tvb, _offset, 6, ENC_NA);
	_offset += 6;

	proto_tree_add_item(_tree, hf_wlccp_responder_node_type,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;

	proto_tree_add_item(_tree, hf_wlccp_responder,
			    _tvb, _offset, 6, ENC_NA);
	_offset += 6;

	if(_relay_flag)
	{
		proto_tree_add_item(_tree, hf_wlccp_relay_node_type,
				    _tvb, _offset, 2, ENC_BIG_ENDIAN);
		_offset += 2;

		proto_tree_add_item(_tree, hf_wlccp_relay_node_id,
				    _tvb, _offset, 6, ENC_NA);
		_offset += 6;

	} /* if _relay_flag */


	switch (_base_message_type)
	{

		case 0x01:
		{
			proto_tree_add_item(_tree, hf_wlccp_scm_hop_address,
					    _tvb, _offset, 6, ENC_NA);
			_offset += 6;

/* Decode the SCM Flags Field */

			_ti = proto_tree_add_item(_tree, hf_wlccp_scm_flags,
						_tvb, _offset, 2, ENC_BIG_ENDIAN);
			_wlccp_scm_flags_tree = proto_item_add_subtree(_ti, ett_wlccp_scm_flags);

			proto_tree_add_item(_wlccp_scm_flags_tree, hf_wlccp_scm_layer2update_flag,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);

			proto_tree_add_item(_wlccp_scm_flags_tree, hf_wlccp_scm_unattached_flag,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);

			proto_tree_add_item(_wlccp_scm_flags_tree, hf_wlccp_scm_unscheduled_flag,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);

			proto_tree_add_item(_wlccp_scm_flags_tree, hf_wlccp_scm_active_flag,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

/* End Decode the SCM Flags Field */


			proto_tree_add_item(_tree, hf_wlccp_scm_election_group,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_scm_attach_count,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

/* Decode the SCM Priority Flags Field */

			_ti = proto_tree_add_item(_tree, hf_wlccp_scm_priority_flags,
						_tvb, _offset, 1, ENC_BIG_ENDIAN);
			_wlccp_scm_priority_flags_tree = proto_item_add_subtree(_ti, ett_wlccp_scm_priority_flags);

			proto_tree_add_item(_wlccp_scm_priority_flags_tree, hf_wlccp_scm_priority,
					_tvb, _offset, 1, ENC_BIG_ENDIAN);

			proto_tree_add_item(_wlccp_scm_priority_flags_tree, hf_wlccp_scm_preferred_flag,
					_tvb, _offset, 1, ENC_BIG_ENDIAN);

			_offset += 1;

/* End Decode the SCM Priority Flags Field */

/* Decode the SCM Bridge Priority Flags Field */

			_ti = proto_tree_add_item(_tree, hf_wlccp_scm_bridge_priority_flags,
						_tvb, _offset, 1, ENC_BIG_ENDIAN);
			_wlccp_scm_bridge_priority_flags_tree = proto_item_add_subtree(_ti, ett_wlccp_scm_bridge_priority_flags);

			proto_tree_add_item(_wlccp_scm_bridge_priority_flags_tree, hf_wlccp_scm_bridge_priority,
					_tvb, _offset, 1, ENC_BIG_ENDIAN);

			proto_tree_add_item(_wlccp_scm_bridge_priority_flags_tree, hf_wlccp_scm_bridge_disable_flag,
					_tvb, _offset, 1, ENC_BIG_ENDIAN);

			_offset += 1;

/* End Decode the SCM Bridge Priority Flags Field */

			proto_tree_add_item(_tree, hf_wlccp_scm_node_id,
					    _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_scm_unknown_short,
					    _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_scm_instance_age,
					    _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			proto_tree_add_item(_tree, hf_wlccp_scm_path_cost,
					    _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_scm_hop_count,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_scm_advperiod,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			break;
		} /* case 0x01 */

		case 0x02:
		{

			break;
		} /* case 0x02 */

		case 0x03:
		{

			break;
		} /* case 0x03 */

		case 0x04:
		{

			break;
		} /* case 0x04 */

		case 0x05:
		{

			break;
		} /* case 0x05 */

		case 0x06:
		{

			break;
		} /* case 0x06 */

		case 0x07:
		{

			break;
		} /* case 0x07 */

		case 0x08:
		{

			break;
		} /* case 0x08 */

		case 0x09:
		{

			break;
		} /* case 0x09 */

		case 0x0a:
		{

			break;
		} /* case 0x0a */

		case 0x0b: /* cmAAA */
		{
			proto_tree_add_item(_tree, hf_wlccp_requ_node_type,
					    _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_requ_node_id,
					    _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			/*kan - according to the patent applicatoin these fields vary based
			on one another.
			For now we decode what we know about and then we'll come back and add
			the rest */

			proto_tree_add_item(_tree, hf_wlccp_aaa_msg_type,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_aaa_msg_type=tvb_get_guint8(_tvb,_offset);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_aaa_auth_type,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_keymgmt_type,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_status,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

/* kan - I'm pretty sure this EAPOL tree only applies sometimes, but it's the only complete example that I have
to test against for now.
For that matter, it may be possible to just hand this piece of the packet over to the EAPOL dissector and let it
handle things. To be investigated further */

			if (_aaa_msg_type == 0x2)  /*EAPOL*/
			{
				_ti = proto_tree_add_item(_tree, hf_wlccp_eapol_msg,
						         _tvb, _offset, 6, ENC_NA);

				_wlccp_eapol_msg_tree = proto_item_add_subtree(
						_ti, ett_wlccp_eapol_msg_tree);


/* THIS NEEDS TO BE CHECKED */
 				/*kan - skip some unknown bytes */
				_offset += 2;

				proto_tree_add_item(_wlccp_eapol_msg_tree, hf_wlccp_eapol_version,
			                    _tvb, _offset, 1, ENC_BIG_ENDIAN);

				_offset += 1;

				proto_tree_add_item(_wlccp_eapol_msg_tree, hf_wlccp_eapol_type,
			        	            _tvb, _offset, 1, ENC_BIG_ENDIAN);
				_eapol_type=tvb_get_guint8(_tvb, _offset);
				_offset += 1;

				if (_eapol_type == 0)
				{
					proto_tree_add_item(_wlccp_eapol_msg_tree, hf_wlccp_eap_msg_length,
			        		            _tvb, _offset, 2, ENC_BIG_ENDIAN);
					_eap_msg_length=tvb_get_ntohs(_tvb, _offset);
					_offset += 2;

					proto_tree_add_item(_wlccp_eapol_msg_tree, hf_wlccp_eap_msg,
			        		            _tvb, _offset, _eap_msg_length, ENC_NA);
					_offset += _eap_msg_length;

				} /* if _eapol_type == 0 */

			} /* if _aaa_msg_type ==0x2 */

			if (_aaa_msg_type == 0x3)  /*Cisco proprietary message*/
			{
				proto_tree_add_item(_tree, hf_wlccp_cisco_acctg_msg,
						    _tvb, _offset, -1, ENC_NA);
			} /* if aaa_msg_type == 0x3 */

			break;
		} /* case 0x0b */

		case 0x0c:  /* cmPathInit */
		{
			proto_tree_add_item(_tree, hf_wlccp_requ_node_type,
					    _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_requ_node_id,
					    _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			/*kan - there's a reserved alignment byte right here*/
			proto_tree_add_item(_tree, hf_wlccp_path_init_rsvd,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_status,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset +=1;

			break;
		} /* case 0x0c */

		case 0x0f:  /* cmWIDS */
		{
			proto_tree_add_item(_tree, hf_wlccp_wids_msg_type,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_status,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset +=1;

			break;
		} /* case 0x0f */

		default:
		{

			break;
		} /* default for switch _base_message_type */

	} /* switch _base_message_type */


	return(_offset);
} /* dissect_wlccp_ccm_msg */

static guint dissect_wlccp_sec_msg(proto_tree *_tree _U_, tvbuff_t *_tvb _U_, guint _offset, guint8 _base_message_type)
{

/* at the momemt we have no more data to use to write this dissector code */
/* it's just a place holder for now                                       */

	switch (_base_message_type)
	{

		case 0x01:
		{

			break;
		} /* case 0x01 */

		default:
		{

			break;
		} /* default for switch _base_message_type */

	} /* switch _base_message_type */



	return(_offset);

} /* dissect_wlccp_sec_msg */

static guint dissect_wlccp_rrm_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type)
{

	proto_tree *_wlccp_rm_flags_tree;
	proto_item *_ti;

	gboolean _mic_flag=0;



/* Decode the RM Flags Field */

	_ti = proto_tree_add_item(_tree, hf_wlccp_rm_flags,
			 _tvb, _offset, 1, ENC_BIG_ENDIAN);

	_wlccp_rm_flags_tree = proto_item_add_subtree(_ti, ett_wlccp_rm_flags);

	proto_tree_add_item(_wlccp_rm_flags_tree, hf_wlccp_rm_mic_flag,
			    _tvb, _offset, 1, ENC_BIG_ENDIAN);

	_mic_flag = (tvb_get_guint8(_tvb, _offset) & RM_F_MIC) >> 1;

	set_mic_flag(_mic_flag);

	set_tlv_flag(TRUE);

	proto_tree_add_item(_wlccp_rm_flags_tree, hf_wlccp_rm_request_reply_flag,
			    _tvb, _offset, 1, ENC_BIG_ENDIAN);

	_offset += 1;

/* End Decode the RM Flags Field */

	proto_tree_add_item(_tree, hf_wlccp_msg_id,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;

	proto_tree_add_item(_tree, hf_wlccp_originator_node_type,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;

	proto_tree_add_item(_tree, hf_wlccp_originator,
			    _tvb, _offset, 6, ENC_NA);
	_offset += 6;

	proto_tree_add_item(_tree, hf_wlccp_responder_node_type,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;

	proto_tree_add_item(_tree, hf_wlccp_responder,
			    _tvb, _offset, 6, ENC_NA);
	_offset += 6;


	switch (_base_message_type)
	{

		case 0x01: /* rmReq */
		{
			break;
		} /* case 0x01 */

		case 0x02: /* rmReqRoutingResp */
		{
			break;
		} /* case 0x01 */

		case 0x03: /* rmReport */
		{
			break;
		} /* case 0x01 */

		default:
		{

			break;
		} /* default for switch _base_message_type */

	} /* switch _base_message_type */


	return(_offset);

} /* dissect_wlccp_rrm_msg */



static guint dissect_wlccp_qos_msg(proto_tree *_tree _U_, tvbuff_t *_tvb _U_, guint _offset, guint8 _base_message_type)
{
/* at the momemt we have no more data to use to write this dissector code */
/* it's just a place holder for now                                       */


	switch (_base_message_type)
	{

		case 0x01:
		{

			break;
		} /* case 0x01 */

		default:
		{

			break;
		} /* default for switch _base_message_type */

	} /* switch _base_message_type */


	return(_offset);

} /* dissect_wlccp_qos_msg */


static guint dissect_wlccp_nm_msg(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint8 _base_message_type)
{
	proto_item *_ti;
	proto_tree *_wlccp_ap_node_id_tree, *_wlccp_nm_flags_tree;

	gboolean _mic_flag=0, _tlv_flag=0;


	proto_tree_add_item(_tree, hf_wlccp_nm_version,
			    _tvb, _offset, 1, ENC_BIG_ENDIAN);
	_offset += 1;

	proto_tree_add_item(_tree, hf_wlccp_msg_id,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;


/* Decode the NM Flags Field */

	_ti = proto_tree_add_item(_tree, hf_wlccp_flags,
			 _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_wlccp_nm_flags_tree = proto_item_add_subtree(_ti, ett_wlccp_nm_flags);


	proto_tree_add_item(_wlccp_nm_flags_tree, hf_wlccp_retry_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(_wlccp_nm_flags_tree, hf_wlccp_ack_required_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(_wlccp_nm_flags_tree, hf_wlccp_tlv_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_tlv_flag = (tvb_get_ntohs(_tvb, _offset)>>13) & 1;
	set_tlv_flag(_tlv_flag);

	proto_tree_add_item(_wlccp_nm_flags_tree, hf_wlccp_mic_flag,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_mic_flag = (tvb_get_ntohs(_tvb, _offset)>>7) & 1;
	set_mic_flag(_mic_flag);

	_offset += 2;

/* End Decode the NM Flags Field */


	proto_tree_add_item(_tree, hf_wlccp_originator_node_type,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;

	proto_tree_add_item(_tree, hf_wlccp_originator,
			    _tvb, _offset, 6, ENC_NA);
	_offset += 6;

	proto_tree_add_item(_tree, hf_wlccp_responder_node_type,
			    _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_offset += 2;

	proto_tree_add_item(_tree, hf_wlccp_responder,
			    _tvb, _offset, 6, ENC_NA);
	_offset += 6;


	switch (_base_message_type)
	{

		case 0x01:  /* nmAck */
		{
			break;
		} /* case 0x01 */

		case 0x10:  /* nmConfigRequest */
		{
			proto_tree_add_item(_tree, hf_wlccp_nmconfig,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* kan - there appears to be some padding or other unknowns here */
			_offset += 3;

			break;
		} /* case 0x10 */

		case 0x11:  /* nmConfigReply */
		{
			proto_tree_add_item(_tree, hf_wlccp_nmconfig,
					    _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* kan - there appears to be some padding or other unknowns here */
			_offset += 3;

			break;
		} /* case 0x11 */

		case 0x20:  /* nmApRegistration */
		{
			proto_tree_add_item(_tree, hf_wlccp_timestamp,
					_tvb, _offset, 8, ENC_BIG_ENDIAN);
			_offset += 8;

			proto_tree_add_item(_tree, hf_wlccp_apregstatus,
					_tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			_offset += 3; /*kan - skip some apparently unused bytes */

			_ti = proto_tree_add_item(_tree, hf_wlccp_ap_node_id,
						_tvb, _offset, 8, ENC_NA);

			_wlccp_ap_node_id_tree = proto_item_add_subtree(
					_ti, ett_wlccp_ap_node_id);

			proto_tree_add_item(_wlccp_ap_node_id_tree, hf_wlccp_ap_node_type,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_wlccp_ap_node_id_tree, hf_wlccp_ap_node_id_address,
					_tvb, _offset, 6, ENC_NA);
			_offset += 6;

			break;
		} /* case 0x20 */

		case 0x21: /* nmScmStateChange */
		{
			proto_tree_add_item(_tree, hf_wlccp_timestamp,
		                            _tvb, _offset, 8, ENC_BIG_ENDIAN);
			_offset += 8;

			proto_tree_add_item(_tree, hf_wlccp_scmstate_change,
		                            _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_scmstate_change_reason,
		                            _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/*kan - skip some apparently unused bytes */
			_offset += 2;

			break;
		} /* case 0x21 */

		case 0x22: /* nmScmKeepActive */
		{
			proto_tree_add_item(_tree, hf_wlccp_scmattach_state,
		                            _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_nmconfig,
		                            _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_nmcapability,
		                            _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			 /*kan - skip some apparently unused bytes */
			_offset += 1;

			break;
		} /* case 0x22 */

		case 0x30: /* nmClientEventReport */
		{
			proto_tree_add_item(_tree, hf_wlccp_timestamp,
					    _tvb, _offset, 8, ENC_BIG_ENDIAN);
			_offset += 8;

			break;
		} /* case 0x30 */

		case 0x31: /* nmAllClientRefreshRequest */
		{
			proto_tree_add_item(_tree, hf_wlccp_refresh_req_id,
		                            _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			break;
		} /* case 0x31 */

		default:
		{

			break;
		} /* default for switch _base_message_type */

	} /* switch _base_message_type */



	return(_offset);

} /* dissect_wlccp_nm_msg */

static guint dissect_wlccp_mip_msg(proto_tree *_tree _U_, tvbuff_t *_tvb _U_, guint _offset, guint8 _base_message_type)
{
/* at the momemt we have no more data to use to write this dissector code */
/* it's just a place holder for now                                       */

	switch (_base_message_type)
	{

		case 0x01:
		{

			break;
		} /* case 0x01 */

		default:
		{

			break;
		} /* default for switch _base_message_type */

	} /* switch _base_message_type */

	return(_offset);

} /* dissect_wlccp_mip_msg */


/***************************************************************************************************/

static guint dissect_wlccp_tlvs( proto_tree *_tree, tvbuff_t *_tvb, guint _offset, guint _depth)
{

	proto_item *_ti, *_temp_ti;
	proto_tree *_tlv_tree;
	proto_tree *_tlv_flags_tree;

	gboolean _container_flag=0;
	gint  _group_id=0, _type_id=0;
	guint _length=0;
	guint _tlv_end=0;
	guint _old_offset;



	/* the TLV length is 2 bytes into the TLV, and we need it now */
	_length = tvb_get_ntohs(_tvb,_offset+2);

	/* figure out where the end of this TLV is so we know when to stop dissecting it */
	_tlv_end = _offset + _length;

	/* this TLV is _length bytes long */
	_ti = proto_tree_add_item(_tree, hf_wlccp_tlv, _tvb, _offset, _length, ENC_NA);
	/* create the TLV sub tree */
	_tlv_tree = proto_item_add_subtree(_ti, ett_wlccp_tlv_tree);

	/* save the pointer because we'll add some text to it later */
	_temp_ti = _ti;



	/* add an arbitrary safety factor in case we foul up the dissector recursion */
	DISSECTOR_ASSERT(_depth < 100);

	/* add the flags field to the tlv_tree */
	_ti = proto_tree_add_item(_tlv_tree, hf_tlv_flags, _tvb, _offset, 2, ENC_BIG_ENDIAN);
	_tlv_flags_tree = proto_item_add_subtree(_ti, ett_tlv_flags_tree);

	/*
	first 2 bytes are the flags, Group and Type
	bit 0 = container,
	bit 1 = encrypted,
	bits 2-3 = reserved,
	bits 4-7 = group ID,
	bit 5 = request,
	bits 9-15 = type ID
	*/


	/* the TLV group and type IDs are contained in the flags field, extract them */
	_group_id = (tvb_get_ntohs(_tvb,_offset) & TLV_GROUP_ID) >> 8;
	_type_id = (tvb_get_ntohs(_tvb,_offset) & TLV_TYPE_ID);

	/* add the flags to the tree */
	proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_container_flag, _tvb, _offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_encrypted_flag, _tvb, _offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_reserved_bit, _tvb, _offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_group, _tvb, _offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_request_flag, _tvb, _offset, 2, ENC_BIG_ENDIAN);

	/* a hack to show the right string representation of the type_id in the tree */
	switch (_group_id)
	{
		case WLCCP_TLV_GROUP_WLCCP:
		{
			proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_type0, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			break;
		} /* case WLCCP_TLV_GROUP_WLCCP */

		case WLCCP_TLV_GROUP_SEC:
		{
			proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_type1, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			break;
		} /* case WLCCP_TLV_GROUP_SEC */

		case WLCCP_TLV_GROUP_RRM:
		{
			proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_type2, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			break;
		} /* case WLCCP_TLV_GROUP_RRM */

		case WLCCP_TLV_GROUP_QOS:
		{
			proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_type3, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			break;
		} /* case WLCCP_TLV_GROUP_QOS */

		case WLCCP_TLV_GROUP_NM:
		{
			proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_type4, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			break;
		} /* case WLCCP_TLV_GROUP_NM */

		case WLCCP_TLV_GROUP_MIP:
		{
			proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_type5, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			break;
		} /* case WLCCP_TLV_GROUP_MIP */

		default:
		{
			proto_tree_add_item(_tlv_flags_tree, hf_wlccp_tlv_type, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			break;
		} /* case default for switch _group_id */


	} /* switch _group_id */

	_container_flag = (tvb_get_ntohs(_tvb, _offset) & TLV_F_CONTAINER) >> 15;

	/* according to the patent, some behavior changes if the request flag is set */
	/* it would be nice if it said how, but I don't think it matters for decoding purposes */

	_offset += 2;

	/* finished with the flags field */

	/* add the length field to the tlv_tree */
	proto_tree_add_item(_tlv_tree, hf_wlccp_tlv_length, _tvb, _offset, 2, ENC_BIG_ENDIAN);

	_offset += 2;
	/* finished with the length field */

	/* now decode the fixed fields in each TLV */

	switch (_group_id)
	{
		case WLCCP_TLV_GROUP_WLCCP:
		{
			_offset = dissect_wlccp_ccm_tlv(_tlv_tree, _tvb, _offset, _type_id, _length - 4, _temp_ti);
			break;

		} /* case WLCCP_TLV_GROUP_WLCCP */

		case WLCCP_TLV_GROUP_SEC:
		{
			_offset = dissect_wlccp_sec_tlv(_tlv_tree, _tvb, _offset, _type_id, _length - 4, _temp_ti);
			break;

		} /* case WLCCP_TLV_GROUP_SEC */

		case WLCCP_TLV_GROUP_RRM:
		{
			_offset = dissect_wlccp_rrm_tlv(_tlv_tree, _tvb, _offset, _type_id, _length - 4, _temp_ti);
			break;

		} /* case WLCCP_TLV_GROUP_RRM */

		case WLCCP_TLV_GROUP_QOS:
		{
			_offset = dissect_wlccp_qos_tlv(_tlv_tree, _tvb, _offset, _type_id, _length - 4, _temp_ti);
			break;

		} /* case WLCCP_TLV_GROUP_QOS */

		case WLCCP_TLV_GROUP_NM:
		{
			_offset = dissect_wlccp_nm_tlv(_tlv_tree, _tvb, _offset, _type_id, _length - 4, _temp_ti);
			break;

		} /* case WLCCP_TLV_GROUP_NM */

		case WLCCP_TLV_GROUP_MIP:
		{
			_offset = dissect_wlccp_mip_tlv(_tlv_tree, _tvb, _offset, _type_id, _length - 4, _temp_ti);
			break;

		} /* case WLCCP_TLV_GROUP_MIP */

		default:
		{
			_offset = _tlv_end;
			break;
		} /* case default for switch _group_id */

	} /* switch _group_id */

	/* done with decoding the fixed TLV fields */



	/* If this TLV is a container, then build a sub tree and decode the contained TLVs */

	if (_container_flag && (_offset >= _tlv_end) )
	{
	/* something is wrong if there's not enough left in the buffer */

	} /* if container_flag and _offset >= _tlv_end */
	else /* _container_flag && _offset >= tlv_end */
	{

		if (_container_flag &&  (_offset < _tlv_end) )
		{

			while (_offset < _tlv_end)
			{
				_old_offset = _offset;
				_offset = dissect_wlccp_tlvs(_tlv_tree, _tvb, _offset, _depth++);
				DISSECTOR_ASSERT(_offset > _old_offset);
			} /* while bytes_left >= 4*/

		} /* _container_flag && (tvb_length_remaining(_tvb,_offset) >= 4) */

	} /*_container_flag && (tvb_length_remaining(_tvb,_offset) < 4) */


	/* done with decoding the contained TLVs */

	return(_tlv_end);

} /* dissect_wlccp_tlvs */


/* ************************************************************************************************************* */

/* ALL THE TLV SUB-DISSECTORS NEED A DEFAULT CASE, OTHERWISE WE'LL GET INTO AN INFINITE RECURSION LOOP INSIDE    */
/* THE CALLING FUNCTION dissect_wlccp_tlvs.  BESIDES, IT'S JUST GOOD FORM :-)                                    */


static guint dissect_wlccp_ccm_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti)
{

	switch (_type_id)
	{

		case 0x00:  /* NULL TLV */
		{
			proto_item_append_text(_ti, "     NULL TLV");
			proto_tree_add_item(_tree, hf_wlccp_null_tlv	, _tvb, _offset, _length, ENC_NA);
			_offset += _length;

			break;

		} /* case tlv_type_id = 0x09 */


		case 0x09:  /* ipv4Address */
		{
			proto_item_append_text(_ti, "     IPv4Address");
			proto_tree_add_item(_tree, hf_wlccp_ipv4_address, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			break;

		} /* case tlv_type_id = 0x09 */


		default:
		{
		/* for unknown types, just add them to the tree as a blob */
			proto_item_append_text(_ti, "     Unknown");

			proto_tree_add_item(_tree, hf_wlccp_tlv_unknown_value, _tvb, _offset, _length, ENC_NA);
			_offset += _length;

			break;
		} /* case default for tlv_group_id=0x00  */

	} /* switch _type_id */

	return(_offset);

} /* dissect_wlccp_ccm_tlv */



static guint dissect_wlccp_sec_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti)
{

	switch (_type_id)
	{

		case 0x01: /* initSession */
		{

			proto_item_append_text(_ti, "     initSession");

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_path_length, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 2;


			break;
		} /* case 0x01 */

		case 0x02: /* inSecureContextReq */
		{

			proto_item_append_text(_ti, "     inSecureContextReq");

			proto_tree_add_item(_tree, hf_wlccp_key_seq_count, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			proto_tree_add_item(_tree, hf_wlccp_dest_node_type, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_dest_node_id, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_supp_node_type, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_supp_node_id, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			/* skip unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_key_mgmt_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_nonce, _tvb, _offset, 32, ENC_NA);
			_offset += 32;

			break;
		} /* case 0x02 */


		case 0x06: /*  authenticator */
		{

			proto_item_append_text(_ti, "     authenticator");

			proto_tree_add_item(_tree, hf_wlccp_dest_node_type, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_dest_node_id, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_src_node_type, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_src_node_id, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_key_seq_count, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			/* skip unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_status, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_nonce, _tvb, _offset, 32, ENC_NA);
			_offset += 32;

			break;
		} /* case 0x06 */

		case 0x08: /* MIC */
		{

			guint16 _mic_length=0;

			proto_item_append_text(_ti, "     mic");

			proto_tree_add_item(_tree, hf_wlccp_mic_msg_seq_count, _tvb, _offset, 8, ENC_BIG_ENDIAN);
			_offset += 8;

			proto_tree_add_item(_tree, hf_wlccp_mic_length, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_mic_length = tvb_get_ntohs(_tvb,_offset);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_mic_value, _tvb, _offset, _mic_length, ENC_NA);
			_offset += _mic_length;

			break;
		}

		case 0x0a: /* inSecureContextReply */
		{

			proto_item_append_text(_ti, "     inSecureContextReply");


			proto_tree_add_item(_tree, hf_wlccp_key_seq_count, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			proto_tree_add_item(_tree, hf_wlccp_dest_node_type, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_dest_node_id, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_supp_node_type, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_supp_node_id, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_nonce, _tvb, _offset, 32, ENC_NA);
			_offset += 32;

			proto_tree_add_item(_tree, hf_wlccp_session_timeout, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			break;
		} /* case 0x0a */



		default:
		{
		/* for unknown types, just add them to the tree as a blob */
			proto_item_append_text(_ti, "     Unknown");
			proto_tree_add_item(_tree, hf_wlccp_tlv_unknown_value, _tvb, _offset, _length, ENC_NA);
			_offset += _length;

			break;
		} /* default case for switch (_type_id) */

	} /* switch _type_id */

	return(_offset);
} /* dissect_wlccp_sec_tlv */



static guint dissect_wlccp_rrm_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti)
{

	switch (_type_id)
	{

		case 0x02: /* aggrRmReq */
		{
			proto_item_append_text(_ti, "     aggrRmReq");
			proto_tree_add_item(_tree, hf_wlccp_token2, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_interval, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			break;

		} /* case tlv_type_id = 0x02 */

		case 0x03 : /* rmReport */
		{
			proto_item_append_text(_ti, "     rmReport");

			proto_tree_add_item(_tree, hf_wlccp_sta_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_bssid, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_stamac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			break;
		} /* case tlv_type_id = 0x03 */

		case 0x04: /* aggrRmReport */
		{
			proto_item_append_text(_ti, "     aggrRmReport");

			/* no fields */

			break;
		} /* case tlv_type_id = 0x04 */

		case 0x12: /* beaconRequest */
		{
			proto_item_append_text(_ti, "     beaconRequest");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_scan_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_duration, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;


			break;
		} /* case 0x12 */

		case 0x14: /* frameRequest */
		{

			guint _count=0, _counter=0;

			proto_item_append_text(_ti, "     frameRequest");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_count, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_count = tvb_get_guint8(_tvb,_offset);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_duration, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			for (_counter=0; _counter < _count; _counter++)
			{

				proto_tree_add_item(_tree, hf_wlccp_bssid, _tvb, _offset, 6, ENC_NA);
				_offset += 6;

			} /* for _counter=0 */



			break;
		} /* case 0x14 */

		case 0x15: /* frameReport */
		{

			proto_item *_fr_ti;
			proto_tree *_fr_elems_tree;

			guint _counter=0, _arraylen=0;

			proto_item_append_text(_ti, "     frameReport");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_duration, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			_arraylen=(_length-10)/14;

			if (_arraylen > 0)
			{

				_fr_ti = proto_tree_add_item(_tree, hf_framereport_elements, _tvb, _offset, (_length-10), ENC_NA);
				_fr_elems_tree = proto_item_add_subtree(_fr_ti, ett_framereport_elements_tree);

				for(_counter=0; _counter < _arraylen; _counter++)
				{

					proto_tree_add_item(_fr_elems_tree, hf_wlccp_numframes, _tvb, _offset, 1, ENC_BIG_ENDIAN);
					_offset += 1;

					proto_tree_add_item(_fr_elems_tree, hf_wlccp_rss, _tvb, _offset, 1, ENC_BIG_ENDIAN);
					_offset += 1;

					proto_tree_add_item(_fr_elems_tree, hf_wlccp_bssid, _tvb, _offset, 6, ENC_NA);
					_offset += 6;

					proto_tree_add_item(_fr_elems_tree, hf_wlccp_stamac, _tvb, _offset, 6, ENC_NA);
					_offset += 6;

				} /* for _counter=0 */

			} /* if _arraylen > 0 */


			break;
		} /* case 0x15 */


		case 0x16: /* ccaRequest */
		{
			proto_item_append_text(_ti, "     ccaRequest");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_duration, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			break;
		} /* case 0x16 */


		case 0x17:  /* ccaReport */
		{
			proto_item_append_text(_ti, "     ccaReport");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_duration, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_ccabusy, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			break;

		} /* case tlv_type_id = 0x17 */

		case 0x18: /* rpiHistRequest */
		{
			proto_item_append_text(_ti, "     rpiHistRequest");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_duration, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			break;
		} /* case 0x18 */

		case 0x19: /* rpiHistReport */
		{

			guint _rpi_density_length=0;

			proto_item_append_text(_ti, "     rpiHistReport");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_duration, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			_rpi_density_length = _length - 6 - 4;

			proto_tree_add_item(_tree, hf_wlccp_rpidensity, _tvb, _offset, _rpi_density_length, ENC_NA);
			_offset += _rpi_density_length;

			break;

		} /* case tlv_type_id = 0x19 */

		case 0x1c: /* nullRequest */
		{
			proto_item_append_text(_ti, "     nullRequest");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_duration, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			break;
		} /* case 0x1c */


		case 0x1e: /* commonBeaconReport */
		{

			proto_tree *_80211_capabilities_tree;
			proto_item *_new_ti;

			guint _tlv80211length=0;

			proto_item_append_text(_ti, "     commonBeaconReport");

			proto_tree_add_item(_tree, hf_wlccp_srcidx, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_channel, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_phy_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_bssid, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_beacon_interval, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;


			/*
			if we assume the next field is the capabilities field from the 802.11 beacon,
			then we have a 16-bit field thhf_wlccp_statusat contains the following (802.11-2007):
			bit 0 = ESS
			bit 1 = IBSS
			bit 2 = CF pollable
			bit 3 = CF Poll Request
			bit 4 = privacy
			bit 5 = Short Preamble
			bit 6 = PBCC
			bit 7 = Channel Agility
			bit 8 = Spectrum Management
			bit 9 = QoS
			bit 10 = Short Slot Time
			bit 11 = APSD
			bit 12 = Reserved
			bit 13 = DSSS-OFDM
			bit 14 = Delayed Block Ack
			bit 15 = Immediate Block Ack
			*/

			_new_ti = proto_tree_add_item(_tree, hf_wlccp_80211_capabilities,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			_80211_capabilities_tree = proto_item_add_subtree(_new_ti, ett_80211_capability_flags_tree);

			proto_tree_add_item(_80211_capabilities_tree, hf_80211_imm_block_ack,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_dlyd_block_ack,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_dsss_ofdm,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_reserved,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_apsd,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_short_time_slot,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_qos,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_spectrum_mgmt,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_chan_agility,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_pbcc,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_short_preamble,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_cap_privacy,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_cap_cf_poll_req,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_cap_cf_pollable,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_cap_ibss,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(_80211_capabilities_tree, hf_80211_cap_ess,
					_tvb, _offset, 2, ENC_BIG_ENDIAN);

			/* proto_tree_add_item(_tree, hf_wlccp_capabilities, _tvb, _offset, 2, ENC_BIG_ENDIAN); */
			_offset += 2;


			_tlv80211length = _length - 13 - 4;

			/* This TLV could be decoded per the 802.11 information element spec's */
			proto_tree_add_item(_tree, hf_wlccp_tlv80211, _tvb, _offset, _tlv80211length, ENC_NA);
			_offset += _tlv80211length;

			break;

		} /* case tlv_type_id = 0x1e */


		case 0x1f: /* aggrBeaconReport */
		{
			proto_item_append_text(_ti, "     aggrBeaconReport");

			proto_tree_add_item(_tree, hf_wlccp_token, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_mode, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_rss, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_srcidx, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_parent_tsf, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			proto_tree_add_item(_tree, hf_wlccp_target_tsf, _tvb, _offset, 8, ENC_BIG_ENDIAN);
			_offset += 8;

			break;
		} /* case tlv_type_id = 0x1f */


		case 0x20: /* rmReqRoutingList */
		{

			guint _counter=0, _arraylen=0;

			proto_item_append_text(_ti, "     rmReqRoutingList");

			_arraylen=(_length)/16;

			if (_arraylen > 0)
			{

				for(_counter=0; _counter < _arraylen; _counter++)
				{

					proto_tree_add_item(_tree, hf_wlccp_ipv4_address, _tvb, _offset, 4, ENC_BIG_ENDIAN);
					_offset += 4;

					proto_tree_add_item(_tree, hf_wlccp_bssid, _tvb, _offset, 6, ENC_NA);
					_offset += 6;

					proto_tree_add_item(_tree, hf_wlccp_stamac, _tvb, _offset, 6, ENC_NA);
					_offset += 6;

				} /* for _counter=0 */

			} /* if _arraylen > 0 */
			break;
		} /* case 0x20 */

		case 0x21: /* rmReqRoutingResp */
		{

			guint _counter=0, _arraylen=0;

			proto_item_append_text(_ti, "     rmReqRoutingResp");

			proto_tree_add_item(_tree, hf_wlccp_token2, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			_arraylen=(_length)/11;

			if (_arraylen > 0)
			{

				for(_counter=0; _counter < _arraylen; _counter++)
				{

					proto_tree_add_item(_tree, hf_wlccp_ipv4_address, _tvb, _offset, 4, ENC_BIG_ENDIAN);
					_offset += 4;

					proto_tree_add_item(_tree, hf_wlccp_bssid, _tvb, _offset, 6, ENC_NA);
					_offset += 6;

					proto_tree_add_item(_tree, hf_wlccp_status, _tvb, _offset, 1, ENC_BIG_ENDIAN);
					_offset += 1;

				} /* for _counter=0 */

			} /* if _arraylen > 0 */

			break;
		} /* case 0x21 */

		case 0x22: /* rmReqAck */
		{
			proto_item_append_text(_ti, "     rmReqAck");

			proto_tree_add_item(_tree, hf_wlccp_status, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			break;
		} /* case 0x22 */


		case 0x58: /* mfpCapability */
		{
			proto_item_append_text(_ti, "     mfpCapability");

			proto_tree_add_item(_tree, hf_wlccp_mfpcapability, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			break;
		} /* case 0x58 */

		case 0x5b: /* mfpRouting */
		{
			proto_item_append_text(_ti, "     mfpRouting");

			proto_tree_add_item(_tree, hf_wlccp_ipv4_address, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			proto_tree_add_item(_tree, hf_wlccp_bssid, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wlccp_mfpflags, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			break;
		} /* case 0x5b */

		case 0x5c: /* mfpConfig */
		{
			proto_item_append_text(_ti, "     mfpConfig");

			proto_tree_add_item(_tree, hf_wlccp_mfpconfig, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			break;
		} /* case 0x5c */


		default:
		{
		/* for unknown types, just add them to the tree as a blob */
			proto_item_append_text(_ti, "     Unknown");

			proto_tree_add_item(_tree, hf_wlccp_tlv_unknown_value, _tvb, _offset, _length, ENC_NA);
			_offset += _length;

		break;
		} /* case default  */

	} /* switch type_id */

	return(_offset);

} /* dissect_wlccp_rrm_tlv */

static guint dissect_wlccp_qos_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti)
{

	switch (_type_id)
	{

		default:
		{
		/* for unknown types, just add them to the tree as a blob */
			proto_item_append_text(_ti, "     Unknown");

			proto_tree_add_item(_tree, hf_wlccp_tlv_unknown_value, _tvb, _offset, _length, ENC_NA);
			_offset += _length;

			break;
		} /* default case for switch (_type_id) */

	} /* switch _type_id */


	return(_offset);

} /* dissect_wlccp_qos_tlv */

static guint dissect_wlccp_nm_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti)
{

	switch (_type_id)
	{

		case 0x20: /* nmClientEventIntoWDS */
		{

			guint _radius_user_name_length = 0;

			proto_item_append_text(_ti, "     nmClientEventIntoWDS");

			proto_tree_add_item(_tree, hf_wlccp_clientmac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_time_elapsed, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_parent_ap_mac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_reg_lifetime, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_ipv4_address, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			proto_tree_add_item(_tree, hf_wlccp_auth_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_key_mgmt_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			_radius_user_name_length = _length - 23 - 4;

			proto_tree_add_item(_tree, hf_wlccp_radius_user_name, _tvb, _offset, _radius_user_name_length, ENC_ASCII|ENC_NA);
			_offset += _radius_user_name_length;


			break;
		} /* case 0x20 */

		case 0x21: /* nmClientEventOutOfWDS */
		{
			proto_item_append_text(_ti, "     nmClientEventOutOfWDS");

			proto_tree_add_item(_tree, hf_wlccp_clientmac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_time_elapsed, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_parent_ap_mac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_wds_reason, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			break;
		} /* case 0x21 */

		case 0x22: /* nmClientEventIntraWDS */
		{
			proto_item_append_text(_ti, "     nmClientEventIntraWDS");

			proto_tree_add_item(_tree, hf_wlccp_clientmac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_time_elapsed, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_parent_ap_mac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_reg_lifetime, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_auth_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_key_mgmt_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 3;


			break;
		} /* case 0x22 */

		case 0x24: /* nmClientEventIPAddressUpdate */
		{
			proto_item_append_text(_ti, "     nmClientEventIPAddressUpdate");

			proto_tree_add_item(_tree, hf_wlccp_clientmac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_time_elapsed, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_parent_ap_mac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			/* skip some unused bytes */
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_ipv4_address, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;


			break;
		} /* case 0x24 */

		case 0x26: /* nmClientEventRefresh */
		{

			guint _radius_user_name_length = 0;

			proto_item_append_text(_ti, "     nmClientEventRefresh");

			proto_tree_add_item(_tree, hf_wlccp_clientmac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_time_elapsed, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_parent_ap_mac, _tvb, _offset, 6, ENC_NA);
			_offset += 6;

			proto_tree_add_item(_tree, hf_reg_lifetime, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_ipv4_address, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;

			proto_tree_add_item(_tree, hf_wlccp_auth_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			proto_tree_add_item(_tree, hf_wlccp_key_mgmt_type, _tvb, _offset, 1, ENC_BIG_ENDIAN);
			_offset += 1;

			/* skip some unused bytes */
			_offset += 1;

			_radius_user_name_length = _length - 23 - 4;

			proto_tree_add_item(_tree, hf_wlccp_radius_user_name, _tvb, _offset, _radius_user_name_length, ENC_ASCII|ENC_NA);
			_offset += _radius_user_name_length;

			break;
		} /* case 0x26 */

		case 0x27: /* nmClientEventRefreshDone */
		{
			proto_item_append_text(_ti, "     nmClientEventRefreshDone");

			/* skip some unused bytes */
			_offset += 6;

			proto_tree_add_item(_tree, hf_time_elapsed, _tvb, _offset, 2, ENC_BIG_ENDIAN);
			_offset += 2;

			proto_tree_add_item(_tree, hf_wlccp_refresh_req_id, _tvb, _offset, 4, ENC_BIG_ENDIAN);
			_offset += 4;


			break;
		} /* case 0x27 */


		default:
		{
		/* for unknown types, just add them to the tree as a blob */
			proto_item_append_text(_ti, "     Unknown");

			proto_tree_add_item(_tree, hf_wlccp_tlv_unknown_value, _tvb, _offset, _length, ENC_NA);
			_offset += _length;

			break;
		} /* default case for switch (_type_id) */

	} /* switch _type_id */


	return(_offset);

} /* dissect_wlccp_nm_tlv */

static guint dissect_wlccp_mip_tlv(proto_tree *_tree, tvbuff_t *_tvb, guint _offset, gint _type_id, guint _length, proto_item *_ti)
{

	switch (_type_id)
	{


		default:
		{
		/* for unknown types, just add them to the tree as a blob */
			proto_item_append_text(_ti, "     Unknown");

			proto_tree_add_item(_tree, hf_wlccp_tlv_unknown_value, _tvb, _offset, _length, ENC_NA);
			_offset += _length;

			break;
		} /* default case for switch (_type_id) */

	} /* switch _type_id */


	return(_offset);

} /* dissect_wlccp_mip_tlv */


/* Register the protocol with Wireshark */
void
proto_register_wlccp(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_wlccp_version,
		  { "Version", "wlccp.version",
		    FT_UINT8, BASE_HEX, NULL,
		    0x0, "Protocol ID/Version", HFILL }
		},

		{ &hf_wlccp_srcmac,
		  { "Src MAC", "wlccp.srcmac",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Source MAC address", HFILL }
		},

		{ &hf_wlccp_dstmac,
		  { "Dst MAC", "wlccp.dstmac",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Destination MAC address", HFILL }
		},

		{ &hf_wlccp_hostname,
		  { "Hostname", "wlccp.hostname",
		    FT_STRING, BASE_NONE, NULL,
		    0x0, "Hostname of device", HFILL }
		},

		{ &hf_wlccp_sap,
		  { "SAP", "wlccp.sap",
		    FT_UINT8, BASE_HEX, NULL,
		    0x0, "Service Access Point", HFILL }
		},

		{ &hf_wlccp_sap_version,
		  { "SAP Version", "wlccp.sap_version",
		    FT_UINT8, BASE_DEC, NULL,
		    SAP_VERSION_MASK, "Service Access Point Version", HFILL }
		},

		{ &hf_wlccp_sap_id,
		  { "SAP ID", "wlccp.sap_id",
		    FT_UINT8, BASE_DEC, VALS(wlccp_sap_vs),
		    SAP_VALUE_MASK, "Service Access Point ID", HFILL }
		},

		{ &hf_wlccp_destination_node_type,
		  { "Destination node type", "wlccp.destination_node_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Node type of the hop destination", HFILL }
		},

		{ &hf_wlccp_length,
		  { "Length", "wlccp.length",
		    FT_UINT16, BASE_DEC, NULL,
		    0x0, "Length of WLCCP payload (bytes)", HFILL }
		},


		{ &hf_wlccp_type,
		  { "Message Type", "wlccp.type",
		    FT_UINT8, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_subtype,
		  { "Subtype", "wlccp.subtype",
		    FT_UINT8, BASE_DEC, VALS(wlccp_subtype_vs),
		    MT_SUBTYPE, "Message Subtype", HFILL }
		},

		{ &hf_wlccp_base_message_type_0,
		  { "Base message type", "wlccp.base_message_type",
		    FT_UINT8, BASE_HEX_DEC, VALS(wlccp_msg_type_vs_0),
		    MT_BASE_MSG_TYPE, NULL, HFILL }
		},

		{ &hf_wlccp_base_message_type_1,
		  { "Base message type", "wlccp.base_message_type",
		    FT_UINT8, BASE_HEX_DEC, VALS(wlccp_msg_type_vs_1),
		    MT_BASE_MSG_TYPE, NULL, HFILL }
		},

		{ &hf_wlccp_base_message_type_2,
		  { "Base message type", "wlccp.base_message_type",
		    FT_UINT8, BASE_HEX_DEC, VALS(wlccp_msg_type_vs_2),
		    MT_BASE_MSG_TYPE, NULL, HFILL }
		},

		{ &hf_wlccp_base_message_type_3,
		  { "Base message type", "wlccp.base_message_type",
		    FT_UINT8, BASE_HEX_DEC, VALS(wlccp_msg_type_vs_3),
		    MT_BASE_MSG_TYPE, NULL, HFILL }
		},

		{ &hf_wlccp_base_message_type_4,
		  { "Base message type", "wlccp.base_message_type",
		    FT_UINT8, BASE_HEX_DEC, VALS(wlccp_msg_type_vs_4),
		    MT_BASE_MSG_TYPE, NULL, HFILL }
		},

		{ &hf_wlccp_base_message_type_5,
		  { "Base message type", "wlccp.base_message_type",
		    FT_UINT8, BASE_HEX_DEC, VALS(wlccp_msg_type_vs_5),
		    MT_BASE_MSG_TYPE, NULL, HFILL }
		},

		{ &hf_wlccp_base_message_type_unknown,
		  { "Base message type", "wlccp.base_message_type",
		    FT_UINT8, BASE_HEX_DEC, NULL,
		    MT_BASE_MSG_TYPE, NULL, HFILL }
		},

		{ &hf_wlccp_hops,
		  { "Hops", "wlccp.hops",
		    FT_UINT8, BASE_DEC, NULL,
		    0x0, "Number of WLCCP hops", HFILL }
		},

		{ &hf_wlccp_nm_version,
		  { "NM Version", "wlccp.nm_version",
		    FT_UINT8, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_msg_id,
		  { "Message ID", "wlccp.msg_id",
		    FT_UINT16, BASE_DEC, NULL,
		    0x0, "Sequence number used to match request/reply pairs",
		    HFILL }
		},


		{ &hf_wlccp_flags,
		  { "Flags", "wlccp.flags",
		    FT_UINT16, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_rm_flags,
		  { "RM Flags", "wlccp.rm_flags",
		    FT_UINT8, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_retry_flag,
		  { "Retry flag", "wlccp.retry_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_RETRY, "Set on for retransmissions", HFILL }
		},

		{ &hf_wlccp_response_request_flag,
		  { "Response request flag", "wlccp.response_request_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_RESPONSE_REQUEST, "Set on to request a reply", HFILL }
		},

		{ &hf_wlccp_rm_request_reply_flag,
		  { "Request Reply flag", "wlccp.request_reply_flag",
		    FT_UINT8, BASE_DEC, NULL,
		    RM_F_REQUEST_REPLY, "Set on to request a reply", HFILL }
		},

		{ &hf_wlccp_ack_required_flag,
		  { "Ack Required flag", "wlccp.ack_required_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_ACK_REQD, "Set on to require an acknowledgement", HFILL }
		},

		{ &hf_wlccp_tlv_flag,
		  { "TLV flag", "wlccp.tlv_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_TLV, "Set to indicate that optional TLVs follow the fixed fields", HFILL }
		},

		{ &hf_wlccp_inbound_flag,
		  { "Inbound flag", "wlccp.inbound_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_INBOUND, "Message is inbound to the top of the topology tree", HFILL }
		},

		{ &hf_wlccp_outbound_flag,
		  { "Outbound flag", "wlccp.outbound_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_OUTBOUND, "Message is outbound from the top of the topology tree", HFILL }
		},

		{ &hf_wlccp_hopwise_routing_flag,
		  { "Hopwise-routing flag", "wlccp.hopwise_routing_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_HOPWISE_ROUTING, "On to force intermediate access points to process the message also", HFILL }
		},

		{ &hf_wlccp_root_cm_flag,
		  { "Root context manager flag", "wlccp.root_cm_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_ROOT_CM, "Set to on to send message to the root context manager of the topology tree", HFILL }
		},

		{ &hf_wlccp_relay_flag,
		  { "Relay flag", "wlccp.relay_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_RELAY, "Signifies that this header is immediately followed by a relay node field", HFILL }
		},

		{ &hf_wlccp_mic_flag,
		  { "MIC flag", "wlccp.mic_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_MIC, "On in a message that must be authenticated and has an authentication TLV", HFILL }
		},

		{ &hf_wlccp_rm_mic_flag,
		  { "MIC flag", "wlccp.mic_flag",
		    FT_UINT8, BASE_DEC, NULL,
		    RM_F_MIC, "On in a message that must be authenticated and has an authentication TLV", HFILL }
		},

		{ &hf_wlccp_originator_node_type,
		  { "Originator node type", "wlccp.originator_node_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Originating device's node type", HFILL }
		},

		{ &hf_wlccp_originator,
		  { "Originator", "wlccp.originator",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Originating device's MAC address", HFILL }
		},

		{ &hf_wlccp_responder_node_type,
		  { "Responder node type", "wlccp.responder_node_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Responding device's node type", HFILL }
		},

		{ &hf_wlccp_responder,
		  { "Responder", "wlccp.responder",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Responding device's MAC address", HFILL }
		},

		{ &hf_wlccp_requ_node_type,
		  { "Requestor node type", "wlccp.requ_node_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Requesting device's node type", HFILL }
		},

		{ &hf_wlccp_requ_node_id,
		  { "Requestor", "wlccp.requestor",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Requestor device's MAC address", HFILL }
		},

		{ &hf_wlccp_status,
		  { "Status", "wlccp.status",
		    FT_UINT8, BASE_DEC, VALS(wlccp_status_vs),
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_path_init_rsvd,
		  { "Reserved", "wlccp.path_init_reserved",
		    FT_UINT8, BASE_DEC, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_relay_node_type,
		  { "Relay node type", "wlccp.relay_node_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, "Type of node which relayed this message", HFILL }
		},

		{ &hf_wlccp_relay_node_id,
		  { "Relay node ID", "wlccp.relay_node_id",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Node which relayed this message", HFILL }
		},

		{ &hf_wlccp_priority,
		  { "WDS priority", "wlccp.priority",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "WDS priority of this access point", HFILL }
		},

		{ &hf_wlccp_age,
		  { "Age", "wlccp.age",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Time since AP became a WDS master", HFILL }
		},

		{ &hf_wlccp_period,
		  { "Period", "wlccp.period",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Interval between announcements (seconds)", HFILL }
		},

		{ &hf_wlccp_ipv4_address,
		  { "IPv4 Address", "wlccp.ipv4_address",
		    FT_IPv4, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_scm_hop_address,
		  { "Hop Address", "wlccp.scm_hop_address",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Source 802 Port Address", HFILL }
		},

		{ &hf_wlccp_scm_flags,
		  { "SCM flags", "wlccp.scm_flags",
		    FT_UINT16, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_scm_active_flag,
		  { "Active flag", "wlccp.scm_active_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_SCM_ACTIVE, "Set to on in advertisements from the active SCM", HFILL }
		},

		{ &hf_wlccp_scm_unscheduled_flag,
		  { "Unscheduled flag", "wlccp.scm_unscheduled_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_SCM_UNSCHEDULED, "Set to on in unscheduled advertisement messages", HFILL }
		},

		{ &hf_wlccp_scm_unattached_flag,
		  { "Unattached flag", "wlccp.scm_unattached_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_SCM_UNATTACHED, "Set to on in advertisements from an unattached node", HFILL }
		},

		{ &hf_wlccp_scm_layer2update_flag,
		  { "Layer2 Update flag", "wlccp.scm_layer2update_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_SCM_LAYER2UPDATE, "Set to on if WLCCP Layer 2 path updates are enabled", HFILL }
		},

		{ &hf_wlccp_scm_election_group,
		  { "SCM Election Group", "wlccp.scm_election_group",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_scm_attach_count,
		  { "Attach Count", "wlccp.scm_attach_count",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Attach count of the hop source", HFILL }
		},

		{ &hf_wlccp_scm_priority_flags,
		  { "SCM Priority flags", "wlccp.scm_priority_flags",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_scm_priority,
		  { "SCM Priority", "wlccp.scm_priority",
		    FT_UINT8, BASE_DEC, NULL,
		    F_SCM_PRIORITY, NULL, HFILL }
		},

		{ &hf_wlccp_scm_preferred_flag,
		  { "Preferred flag", "wlccp.scm_preferred_flag",
		    FT_UINT8, BASE_DEC, NULL,
		    F_SCM_PREFERRED, "Set to off if the SCM is the preferred SCM", HFILL }
		},

		{ &hf_wlccp_scm_bridge_priority_flags,
		  { "Bridge Priority flags", "wlccp.scm_bridge_priority_flags",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_scm_bridge_priority,
		  { "Bridge priority", "wlccp.scm_bridge_priority",
		    FT_UINT8, BASE_DEC, NULL,
		    F_SCM_BRIDGE_PRIORITY, "Used to negotiate the designated bridge on a non-STP secondary Ethernet LAN", HFILL }
		},

		{ &hf_wlccp_scm_bridge_disable_flag,
		  { "Bridge disable flag", "wlccp.scm_bridge_disable_flag",
		    FT_UINT8, BASE_DEC, NULL,
		    F_SCM_BRIDGE_DISABLE, "Set to on to indicate that secondary briding is disabled", HFILL }
		},

		{ &hf_wlccp_scm_node_id,
		  { "SCM Node ID", "wlccp.scm_node_id",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, "Node ID of the SCM", HFILL }
		},

		{ &hf_wlccp_scm_unknown_short,
		  { "Unknown Short", "wlccp.scm_unknown_short",
		    FT_UINT16, BASE_HEX, NULL,
		    0x0, "SCM Unknown Short Value", HFILL }
		},

		{ &hf_wlccp_scm_instance_age,
		  { "Instance Age", "wlccp.scm_instance_age",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    "Instance age of the SCM in seconds", HFILL }
		},

		{ &hf_wlccp_scm_path_cost,
		  { "Path cost", "wlccp.scm_path_cost",
		    FT_UINT16, BASE_DEC, NULL,
		    0x0, "Sum of port costs on the path to the SCM", HFILL }
		},

		{ &hf_wlccp_scm_hop_count,
		  { "Hop Count", "wlccp.scm_hop_count",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Number of wireless hops on the path to SCM", HFILL }
		},

		{ &hf_wlccp_scm_advperiod,
		  { "Advertisement Period", "wlccp.scm_advperiod",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    "Average number of seconds between SCM advertisements", HFILL }
		},

		{ &hf_wlccp_timestamp,
		  { "Timestamp", "wlccp.timestamp",
		    FT_UINT64, BASE_DEC, NULL, 0,
		    "Registration Timestamp", HFILL }
		},

		{ &hf_wlccp_apregstatus,
		  { "Registration Status", "wlccp.apregstatus",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    "AP Registration Status", HFILL }
		},

		{ &hf_wlccp_ap_node_id,
		  { "AP Node ID", "wlccp.apnodeid",
		    FT_NONE, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_ap_node_type,
		  { "AP Node Type", "wlccp.apnodetype",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_ap_node_id_address,
		  { "AP Node Address", "wlccp.apnodeidaddress",
		    FT_ETHER, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_aaa_msg_type,
		  { "AAA Message Type", "wlccp.aaa_msg_type",
		    FT_UINT8, BASE_HEX, VALS(wlccp_aaa_msg_type_vs), 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_aaa_auth_type,
		  { "AAA Authentication Type", "wlccp.aaa_auth_type",
		    FT_UINT8, BASE_HEX, VALS(wlccp_eapol_auth_type_vs), 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_keymgmt_type,
		  { "AAA Key Management Type", "wlccp.aaa_keymgmt_type",
		    FT_UINT8, BASE_HEX, VALS(wlccp_key_mgmt_type_vs), 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_eapol_msg,
		  { "EAPOL Message", "wlccp.eapol_msg",
		    FT_NONE, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_eapol_version,
		  { "EAPOL Version", "wlccp.eapol_version",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_eapol_type,
		  { "EAPOL Type", "wlccp.eapol_type",
		    FT_UINT8, BASE_HEX, VALS(eapol_type_vs), 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_eap_msg_length,
		  { "EAP Packet Length", "wlccp.eap_pkt_length",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "EAPOL Type", HFILL }
		},

		{ &hf_wlccp_eap_msg,
		  { "EAP Message", "wlccp.eap_msg",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_cisco_acctg_msg,
		  { "Cisco Accounting Message", "wlccp.cisco_acctg_msg",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_wids_msg_type,
		  { "WIDS Message Type", "wlccp.wids_msg_type",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_nmconfig,
		  { "NM Config", "wlccp.nmconfig",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_scmstate_change,
		  { "SCM State Change", "wlccp.scmstate_change",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_scmstate_change_reason,
		  { "SCM State Change Reason", "wlccp.scmstate_change_reason",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_scmattach_state,
		  { "SCM Attach State", "wlccp.scmattach_state",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_nmcapability,
		  { "NM Capability", "wlccp.nm_capability",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_refresh_req_id,
		  { "Refresh Request ID", "wlccp.refresh_request_id",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_tlv,
		  { "WLCCP TLV", "wlccp.tlv",
		    FT_NONE, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_tlv_flags,
		  { "TLV Flags", "wlccp.tlv_flags",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    "TLV Flags, Group and Type", HFILL }
		},

		{ &hf_wlccp_null_tlv,
		  { "NULL TLV", "wlccp.null_tlv",
		    FT_BYTES, BASE_NONE, NULL ,
		    0, NULL, HFILL }
		},


		{ &hf_wlccp_tlv_type,
		  { "TLV Type", "wlccp.tlv_type",
		    FT_UINT16, BASE_DEC, NULL ,
		    TLV_TYPE_ID, "TLV Type ID", HFILL }
		},

		{ &hf_wlccp_tlv_type0,
		  { "TLV Type", "wlccp.tlv_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_tlv_typeID_0),
		    TLV_TYPE_ID, "TLV Type ID", HFILL }
		},

		{ &hf_wlccp_tlv_type1,
		  { "TLV Type", "wlccp.tlv_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_tlv_typeID_1),
		    TLV_TYPE_ID, "TLV Type ID", HFILL }
		},

		{ &hf_wlccp_tlv_type2,
		  { "TLV Type", "wlccp.tlv_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_tlv_typeID_2),
		    TLV_TYPE_ID, "TLV Type ID", HFILL }
		},

		{ &hf_wlccp_tlv_type3,
		  { "TLV Type", "wlccp.tlv_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_tlv_typeID_3),
		    TLV_TYPE_ID, "TLV Type ID", HFILL }
		},

		{ &hf_wlccp_tlv_type4,
		  { "TLV Type", "wlccp.tlv_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_tlv_typeID_4),
		    TLV_TYPE_ID, "TLV Type ID", HFILL }
		},

		{ &hf_wlccp_tlv_type5,
		  { "TLV Type", "wlccp.tlv_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_tlv_typeID_5),
		    TLV_TYPE_ID, "TLV Type ID", HFILL }
		},

		{ &hf_wlccp_tlv_group,
		  { "TLV Group", "wlccp.tlv_group",
		    FT_UINT16, BASE_DEC, VALS(wlccp_tlv_group_vs) ,
		    TLV_GROUP_ID, "TLV Group ID", HFILL }
		},

		{ &hf_wlccp_tlv_container_flag,
		  { "TLV Container Flag", "wlccp.tlv_container_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    TLV_F_CONTAINER, "Set on if the TLV is a container", HFILL }
		},

		{ &hf_wlccp_tlv_encrypted_flag,
		  { "TLV Encrypted Flag", "wlccp.tlv_encrypted_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    TLV_F_ENCRYPTED, "Set on if the TLV is encrypted", HFILL }
		},

		{ &hf_wlccp_tlv_reserved_bit,
		  { "Reserved bits", "wlccp.tlv_reserved_bit",
		    FT_UINT16, BASE_DEC, NULL,
		    TLV_F_RESVD, "Reserved", HFILL }
		},

		{ &hf_wlccp_tlv_request_flag,
		  { "TLV Request Flag", "wlccp.tlv_request_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    TLV_F_REQUEST, "Set on if the TLV is a request", HFILL }
		},

		{ &hf_wlccp_tlv_length,
		  { "TLV Length", "wlccp.tlv_length",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_path_length,
		  { "Path Length", "wlccp.path_length",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_mic_msg_seq_count,
		  { "MIC Message Sequence Count", "wlccp.mic_msg_seq_count",
		    FT_UINT64, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_mic_length,
		  { "MIC Length", "wlccp.mic_length",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_mic_value,
		  { "MIC Value", "wlccp.mic_value",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_dest_node_type,
		  { "Destination node type", "wlccp.dest_node_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_dest_node_id,
		  { "Destination node ID", "wlccp.dest_node_id",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_supp_node_type,
		  { "Destination node type", "wlccp.supp_node_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_supp_node_id,
		  { "Supporting node ID", "wlccp.supp_node_id",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_src_node_type,
		  { "Source node type", "wlccp.source_node_type",
		    FT_UINT16, BASE_DEC, VALS(wlccp_node_type_vs),
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_src_node_id,
		  { "Source node ID", "wlccp.source_node_id",
		    FT_ETHER, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_key_mgmt_type,
		  { "Key Management type", "wlccp.key_mgmt_type",
		    FT_UINT8, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wlccp_key_seq_count,
		  { "Key Sequence Count", "wlccp.key_seq_count",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_session_timeout,
		  { "Session Timeout", "wlccp.session_timeout",
		    FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_nonce,
		  { "Nonce Value", "wlccp.nonce_value",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_token,
		  { "Token", "wlccp.token",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_scan_mode,
		  { "Scan Mode", "wlccp.scan_mode",
		    FT_UINT8, BASE_HEX, NULL,
		    0, NULL, HFILL }
		},

		{ &hf_wlccp_mode,
		  { "Mode", "wlccp.mode",
		    FT_UINT8, BASE_HEX, VALS(wlccp_mode_vs),
		    0, NULL, HFILL }
		},

		{ &hf_wlccp_rss,
		  { "RSS", "wlccp.rss",
		    FT_INT8, BASE_DEC, NULL, 0,
		    "Received Signal Strength", HFILL }
		},

		{ &hf_wlccp_srcidx,
		  { "Source Index", "wlccp.srcidx",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_parent_tsf,
		  { "Parent TSF", "wlccp.parenttsf",
		    FT_UINT32, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_target_tsf,
		  { "Target TSF", "wlccp.targettsf",
		    FT_UINT64, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_channel,
		  { "Channel", "wlccp.channel",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_phy_type,
		  { "PHY Type", "wlccp.phy_type",
		    FT_UINT8, BASE_DEC, VALS(phy_type_80211_vs), 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_bssid,
		  { "BSS ID", "wlccp.bssid",
		    FT_ETHER, BASE_NONE, NULL, 0,
		    "Basic Service Set ID", HFILL }
		},

		{ &hf_wlccp_beacon_interval,
		  { "Beacon Interval", "wlccp.beacon_interval",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		/*
 		{ &hf_wlccp_capabilities,
 		  { "Capabilities", "wlccp.capabilities",
 		    FT_UINT16, BASE_HEX, NULL, 0,
 		    NULL, HFILL }
 		},
		*/

		{ &hf_wlccp_80211_capabilities,
		  { "802.11 Capabilities Flags", "wlccp.80211_capabilities",
		    FT_UINT16, BASE_HEX, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_80211_cap_ess,
		  { "ESS flag", "wlccp.80211_ess_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_ESS, "Set on by APs in Beacon or Probe Response", HFILL }
		},


		{ &hf_80211_cap_ibss,
		  { "IBSS flag", "wlccp.80211_ibss_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_IBSS, "Set on by STAs in Beacon or Probe Response", HFILL }
		},

		{ &hf_80211_cap_cf_pollable,
		  { "CF Pollable flag", "wlccp.80211_cf_pollable_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_CFPOLL, NULL, HFILL }
		},

		{ &hf_80211_cap_cf_poll_req,
		  { "CF Poll Request flag", "wlccp.80211_cf_poll_req_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_CFPOLL_REQ, NULL, HFILL }
		},

		{ &hf_80211_cap_privacy,
		  { "Privacy flag", "wlccp.80211_cf_poll_req_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_PRIVACY, "Set on indicate confidentiality is required in the BSS", HFILL }
		},

		{ &hf_80211_short_preamble,
		  { "Short Preamble flag", "wlccp.80211_short_preamble_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_SHORT_PREAMBLE, NULL, HFILL }
		},

		{ &hf_80211_pbcc,
		  { "PBCC flag", "wlccp.80211_pbcc_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_PBCC, NULL, HFILL }
		},

		{ &hf_80211_chan_agility,
		  { "Channel Agility flag", "wlccp.80211_chan_agility_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_CH_AGILITY, NULL, HFILL }
		},

		{ &hf_80211_spectrum_mgmt,
		  { "Spectrum Management flag", "wlccp.80211_spectrum_mgmt_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_SPEC_MGMT, NULL, HFILL }
		},

		{ &hf_80211_qos,
		  { "QOS flag", "wlccp.80211_qos_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_QOS, NULL, HFILL }
		},

		{ &hf_80211_short_time_slot,
		  { "Short Time Slot flag", "wlccp.80211_short_time_slot_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_SHORT_TIME_SLOT, NULL, HFILL }
		},

		{ &hf_80211_apsd,
		  { "APSD flag", "wlccp.80211_apsd_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_APSD, NULL, HFILL }
		},

		{ &hf_80211_reserved,
		  { "Reserved", "wlccp.80211_reserved",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_RESVD, NULL, HFILL }
		},

		{ &hf_80211_dsss_ofdm,
		  { "DSSS-OFDM Flag", "wlccp.dsss_ofdm_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_DSSS_OFDM, NULL, HFILL }
		},

		{ &hf_80211_dlyd_block_ack,
		  { "Delayed Block Ack Flag", "wlccp.dsss_dlyd_block_ack_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_DLYD_BLK_ACK, NULL, HFILL }
		},

		{ &hf_80211_imm_block_ack,
		  { "Immediate Block Ack Flag", "wlccp.dsss_imm_block_ack_flag",
		    FT_UINT16, BASE_DEC, NULL,
		    F_80211_IMM_BLK_ACK, NULL, HFILL }
		},


		{ &hf_wlccp_tlv80211,
		  { "802.11 TLV Value", "wlccp.tlv80211",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_duration,
		  { "Duration", "wlccp.duration",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_rpidensity,
		  { "RPI Density", "wlccp.rpi_denisty",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_ccabusy,
		  { "CCA Busy", "wlccp.cca_busy",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_stamac,
		  { "Station MAC", "wlccp.station_mac",
		    FT_ETHER, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_sta_type,
		  { "Station Type", "wlccp.station_type",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_token2,
		  { "2 Byte Token", "wlccp.token2",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_interval,
		  { "Interval", "wlccp.interval",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_framereport_elements,
		  { "Frame Report Elements", "wlccp.framereport_elements",
		    FT_NONE, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_count,
		  { "Element Count", "wlccp.element_count",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_numframes,
		  { "Number of frames", "wlccp.numframes",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_mfpcapability,
		  { "MFP Capability", "wlccp.mfp_capability",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_mfpflags,
		  { "MFP Flags", "wlccp.mfp_flags",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_mfpconfig,
		  { "MFP Config", "wlccp.mfp_config",
		    FT_UINT16, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_clientmac,
		  { "Client MAC", "wlccp.client_mac",
		    FT_ETHER, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_reg_lifetime,
		  { "Reg. LifeTime", "wlccp.reg_lifetime",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_time_elapsed,
		  { "Elapsed Time", "wlccp.time_elapsed",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_parent_ap_mac,
		  { "Parent AP MAC", "wlccp.parent_ap_mac",
		    FT_ETHER, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_auth_type,
		  { "Authentication Type", "wlccp.auth_type",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},

		{ &hf_wlccp_radius_user_name,
		  { "RADIUS Username", "wlccp.radius_username",
		    FT_STRING, BASE_NONE, NULL,
		    0x0, NULL, HFILL }
		},

		{ &hf_wds_reason,
		  { "Reason Code", "wlccp.wds_reason",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},


		{ &hf_wlccp_tlv_unknown_value,
		  { "Unknown TLV Contents", "wlccp.tlv_unknown_value",
		    FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }
		}

	}; /* hf_register_info hf */

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wlccp,
		&ett_wlccp_sap_tree,
		&ett_wlccp_type,
		&ett_wlccp_flags,
		&ett_wlccp_cm_flags,
		&ett_wlccp_scm_flags,
		&ett_wlccp_scm_priority_flags,
		&ett_wlccp_scm_bridge_priority_flags,
		&ett_wlccp_rm_flags,
		&ett_wlccp_nm_flags,
		&ett_wlccp_ap_node_id,
		&ett_wlccp_eapol_msg_tree,
		&ett_wlccp_eap_tree,
		&ett_wlccp_tlv_tree,
		&ett_tlv_flags_tree,
		&ett_tlv_sub_tree,
		&ett_80211_capability_flags_tree,
		&ett_framereport_elements_tree
	}; /* static gint *ett[] */

	/* Register the protocol name and description */
	proto_wlccp = proto_register_protocol("Cisco Wireless LAN Context Control Protocol", "WLCCP", "wlccp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_wlccp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_wlccp(void)
{
	dissector_handle_t wlccp_handle;

	wlccp_handle = create_dissector_handle(dissect_wlccp, proto_wlccp);

	dissector_add_uint("ethertype", ETHERTYPE_WLCCP, wlccp_handle);
	dissector_add_uint("udp.port", WLCCP_UDP_PORT, wlccp_handle);
	dissector_add_uint("llc.wlccp_pid", 0x0000, wlccp_handle);

}


void
proto_register_wlccp_oui(void)
{
	static hf_register_info hf[] = {
		{ &hf_llc_wlccp_pid,
		  { "PID", "llc.wlccp_pid",
		    FT_UINT16, BASE_HEX, VALS(cisco_pid_vals),
		    0x0, NULL, HFILL }
		}
	};

	llc_add_oui(OUI_CISCOWL, "llc.wlccp_pid", "Cisco WLCCP OUI PID", hf);

}
