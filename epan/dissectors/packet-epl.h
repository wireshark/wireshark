/* packet-epl.h
 * Routines for "Ethernet Powerlink 2.0" dissection 
 * (ETHERNET Powerlink V2.0 Communication Profile Specification Draft Standard Version 1.0.0)
 *
 * Copyright (c) 2006: Zurich University of Applied Sciences Winterthur (ZHW)
 *                     Institute of Embedded Systems (InES)
 *                     http://ines.zhwin.ch
 *
 *                     - Dominic BÇchaz <bdo@zhwin.ch>
 *                     - Damir Bursic <bum@zhwin.ch>
 *                     - David BÅchi <bhd@zhwin.ch>
 *
 *
 * $Id$
 *
 * A plugin for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#ifndef __PACKET_EPL_H__
#define __PACKET_EPL_H__

/* function prototypes */
static gboolean dissect_epl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void proto_register_epl(void);
void proto_reg_handoff_epl(void);

gint dissect_epl_soc(proto_tree *epl_tree, tvbuff_t *tvb, gint offset);
gint dissect_epl_preq(proto_tree *epl_tree, tvbuff_t *tvb, gint offset);
gint dissect_epl_pres(proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset);
gint dissect_epl_soa(proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset);

gint dissect_epl_asnd(proto_tree *tree, proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset);
gint dissect_epl_asnd_ires(proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset);
gint dissect_epl_asnd_sres(proto_tree *tree, proto_tree *epl_tree, tvbuff_t *tvb, guint8 epl_src, gint offset);
gint dissect_epl_asnd_nmtcmd(proto_tree *epl_tree, tvbuff_t *tvb, gint offset);
gint dissect_epl_asnd_nmtreq(proto_tree *epl_tree, tvbuff_t *tvb, gint offset);

gint dissect_epl_asnd_sdo(proto_tree *epl_tree, tvbuff_t *tvb, gint offset);
gint dissect_epl_sdo_sequence(proto_tree *epl_tree, tvbuff_t *tvb, gint offset);
gint dissect_epl_sdo_command(proto_tree *epl_tree, tvbuff_t *tvb, gint offset);
gint dissect_epl_sdo_command_write_by_index(proto_tree *epl_tree, tvbuff_t *tvb, gint offset, gboolean segmented, gboolean response);
gint dissect_epl_sdo_command_read_by_index(proto_tree *epl_tree, tvbuff_t *tvb, gint offset, gboolean response);

const gchar* decode_epl_address(guchar adr);
const gchar* decode_epl_address_abbrev(guchar adr);



/* Container for tapping relevant data */
typedef struct _epl_info_t {
    unsigned char epl_mtyp;
} epl_info_t;


/*EPL Addressing*/
#define EPL_INVALID_NODEID                        0
#define EPL_MN_NODEID                           240
#define EPL_DIAGNOSTIC_DEVICE_NODEID            253
#define EPL_TO_LEGACY_ETHERNET_ROUTER_NODEID    254
#define EPL_BROADCAST_NODEID                    255

static const value_string addr_str_vals[] = {
    {EPL_INVALID_NODEID,                    " (invalid)"                        },
    {EPL_MN_NODEID,                         " (Managing Node)"                  },
    {EPL_DIAGNOSTIC_DEVICE_NODEID,          " (Diagnostic Device)"              },
    {EPL_TO_LEGACY_ETHERNET_ROUTER_NODEID,  " (EPL to legacy Ethernet Router)"  },
    {EPL_BROADCAST_NODEID,                  " (broadcast)"                      },
    {0,NULL}
};
static const gchar* addr_str_cn  = " (Controlled Node)";
static const gchar* addr_str_res = " (reserved)";

static const value_string addr_str_abbr_vals[] = {
    {EPL_INVALID_NODEID,                    " (inv.)"   },
    {EPL_MN_NODEID,                         " (MN)"     },
    {EPL_DIAGNOSTIC_DEVICE_NODEID,          " (diag.)"  },
    {EPL_TO_LEGACY_ETHERNET_ROUTER_NODEID,  " (router)" },
    {EPL_BROADCAST_NODEID,                  " (bc)"     },
    {0,NULL}
};
static const gchar* addr_str_abbr_cn  = " (CN)";
static const gchar* addr_str_abbr_res = " (res.)";


/* Offsets of fields within an EPL packet. */
#define EPL_MTYP_OFFSET             0   /* same offset for all message types*/
#define EPL_DEST_OFFSET             1   /* same offset for all message types*/
#define EPL_SRC_OFFSET              2   /* same offset for all message types*/

#define EPL_SOA_SVID_OFFSET         6
#define EPL_SOA_SVTG_OFFSET         7
#define EPL_SOA_EPLV_OFFSET         8

#define EPL_ASND_SVID_OFFSET        3
#define EPL_ASND_DATA_OFFSET        4


/* EPL message types */
#define EPL_SOC     0x01
#define EPL_PREQ    0x03
#define EPL_PRES    0x04
#define EPL_SOA     0x05
#define EPL_ASND    0x06

static const value_string mtyp_vals[] = {
    {EPL_SOC,  "Start of Cycle (SoC)"       },
    {EPL_PREQ, "PollRequest (PReq)"         },
    {EPL_PRES, "PollResponse (PRes)"        },
    {EPL_SOA,  "Start of Asynchronous (SoA)"},
    {EPL_ASND, "Asynchronous Send (ASnd)"   },
    {0,NULL}
};

/* RequestedServiceID s for EPL message type "SoA" */
#define EPL_SOA_NOSERVICE               0
#define EPL_SOA_IDENTREQUEST            1
#define EPL_SOA_STATUSREQUEST           2
#define EPL_SOA_NMTREQUESTINVITE        3
#define EPL_SOA_UNSPECIFIEDINVITE     255

static const value_string soa_svid_vals[] = {
    {EPL_SOA_NOSERVICE,           "NoService"        },
    {EPL_SOA_IDENTREQUEST,        "IdentRequest"     },
    {EPL_SOA_STATUSREQUEST,       "StatusRequest"    },
    {EPL_SOA_NMTREQUESTINVITE,    "NMTRequestInvite" },
    {EPL_SOA_UNSPECIFIEDINVITE,   "UnspecifiedInvite"},
    {0,NULL}
};

/* ServiceID values for EPL message type "ASnd" */
#define EPL_ASND_IDENTRESPONSE          1
#define EPL_ASND_STATUSRESPONSE         2
#define EPL_ASND_NMTREQUEST             3
#define EPL_ASND_NMTCOMMAND             4
#define EPL_ASND_SDO                    5

static const value_string asnd_svid_vals[] = {
    {EPL_ASND_IDENTRESPONSE,  "IdentResponse" },
    {EPL_ASND_STATUSRESPONSE, "StatusResponse"},
    {EPL_ASND_NMTREQUEST,     "NMTRequest"    },
    {EPL_ASND_NMTCOMMAND,     "NMTCommand"    },
    {EPL_ASND_SDO,            "SDO"           },
    {0,NULL}
};

/* NMTCommand values for EPL message type "ASnd" */
#define EPL_ASND_NMTCOMMAND_NMTSTARTNODE                0x21
#define EPL_ASND_NMTCOMMAND_NMTSTOPNODE                 0x22
#define EPL_ASND_NMTCOMMAND_NMTENTERPREOPERATIONAL2     0x23
#define EPL_ASND_NMTCOMMAND_NMTENABLEREADYTOOPERATE     0x24
#define EPL_ASND_NMTCOMMAND_NMTRESETNODE                0x28
#define EPL_ASND_NMTCOMMAND_NMTRESETCOMMUNICATION       0x29
#define EPL_ASND_NMTCOMMAND_NMTRESETCONFIGURATION       0x2A
#define EPL_ASND_NMTCOMMAND_NMTSWRESET                  0x2B

#define EPL_ASND_NMTCOMMAND_NMTSTARTNODEEX              0x41
#define EPL_ASND_NMTCOMMAND_NMTSTOPNODEEX               0x42
#define EPL_ASND_NMTCOMMAND_NMTENTERPREOPERATIONAL2EX   0x43
#define EPL_ASND_NMTCOMMAND_NMTENABLEREADYTOOPERATEEX   0x44
#define EPL_ASND_NMTCOMMAND_NMTRESETNODEEX              0x48
#define EPL_ASND_NMTCOMMAND_NMTRESETCOMMUNICATIONEX     0x49
#define EPL_ASND_NMTCOMMAND_NMTRESETCONFIGURATIONEX     0x4A
#define EPL_ASND_NMTCOMMAND_NMTSWRESETEX                0x4B

#define EPL_ASND_NMTCOMMAND_NMTNETHOSTNAMESET           0x62
#define EPL_ASND_NMTCOMMAND_NMTFLUSHARPENTRY            0x63
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHCONFIGUREDNODES   0x80
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHACTIVENODES       0x90
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHPREOPERATIONAL1   0x91
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHPREOPERATIONAL2   0x92
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHREADYTOOPERATE    0x93
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHOPERATIONAL       0x94
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHSTOPPED           0x95
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHEMERGENCYNEW      0xA0
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHTIME              0XB0
#define EPL_ASND_NMTCOMMAND_NMTINVALIDSERVICE           0xFF

static const value_string asnd_cid_vals[] = {
    {EPL_ASND_NMTCOMMAND_NMTSTARTNODE,                "NMTStartNode"              },
    {EPL_ASND_NMTCOMMAND_NMTSTOPNODE,                 "NMTStopNode"               },
    {EPL_ASND_NMTCOMMAND_NMTENTERPREOPERATIONAL2,     "NMTEnterPreOperational2"   },
    {EPL_ASND_NMTCOMMAND_NMTENABLEREADYTOOPERATE,     "NMTEnableReadyToOperate"   },
    {EPL_ASND_NMTCOMMAND_NMTRESETNODE,                "NMTResetNode"              },
    {EPL_ASND_NMTCOMMAND_NMTRESETCOMMUNICATION,       "NMTResetCommunication"     },
    {EPL_ASND_NMTCOMMAND_NMTRESETCONFIGURATION,       "NMTResetConfiguration"     },
    {EPL_ASND_NMTCOMMAND_NMTSWRESET,                  "NMTSwReset"                },
    {EPL_ASND_NMTCOMMAND_NMTSTARTNODEEX,              "NMTStartNodeEx"            },
    {EPL_ASND_NMTCOMMAND_NMTSTOPNODEEX,               "NMTStopNodeEx"             },
    {EPL_ASND_NMTCOMMAND_NMTENTERPREOPERATIONAL2EX,   "NMTEnterPreOperational2Ex" },
    {EPL_ASND_NMTCOMMAND_NMTENABLEREADYTOOPERATEEX,   "NMTEnableReadyToOperateEx" },
    {EPL_ASND_NMTCOMMAND_NMTRESETNODEEX,              "NMTResetNodeEx"            },
    {EPL_ASND_NMTCOMMAND_NMTRESETCOMMUNICATIONEX,     "NMTCommunicationEx"        },
    {EPL_ASND_NMTCOMMAND_NMTRESETCONFIGURATIONEX,     "NMTResetConfigurationEx"   },
    {EPL_ASND_NMTCOMMAND_NMTSWRESETEX,                "NMTSwResetEx"              },
    {EPL_ASND_NMTCOMMAND_NMTNETHOSTNAMESET,           "NMTNetHostNameSet"         },
    {EPL_ASND_NMTCOMMAND_NMTFLUSHARPENTRY,            "NMTFlushArpEntry"          },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHCONFIGUREDNODES,   "NMTPublishConfiguredNodes" },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHACTIVENODES,       "NMTPublishActiveNodes"     },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHPREOPERATIONAL1,   "NMTPublishPreOperational1" },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHPREOPERATIONAL2,   "NMTPublishPreOperational2" },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHREADYTOOPERATE,    "NMTPublishReadyToOperate"  },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHOPERATIONAL,       "NMTPublishOperational"     },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHSTOPPED,           "NMTPublishStopped"         },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHEMERGENCYNEW,      "NMTPublishEmergencyNew"    },
    {EPL_ASND_NMTCOMMAND_NMTPUBLISHTIME,              "NMTPublishTime"            },
    {EPL_ASND_NMTCOMMAND_NMTINVALIDSERVICE,           "NMTInvalidService"         },
    {0,NULL}
};

/* Priority values for EPL message type "ASnd", "", "", field PR */
#define EPL_PR_GENERICREQUEST   0x00
#define EPL_PR_NMTREQUEST       0x07

static const value_string epl_pr_vals[] = {
    {EPL_PR_GENERICREQUEST,   "GenericRequest"},
    {EPL_PR_NMTREQUEST,       "NMTRequest"    },
    {0,NULL}
};

/* NMT State values (for CN)*/
#define EPL_NMT_GS_OFF                  0x00
#define EPL_NMT_GS_INITIALIZING         0x19
#define EPL_NMT_GS_RESET_APPLICATION    0x29
#define EPL_NMT_GS_RESET_COMMUNICATION  0x39
#define EPL_NMT_CS_NOT_ACTIVE           0x1C
#define EPL_NMT_CS_PRE_OPERATIONAL_1    0x1D
#define EPL_NMT_CS_PRE_OPERATIONAL_2    0x5D
#define EPL_NMT_CS_READY_TO_OPERATE     0x6D
#define EPL_NMT_CS_OPERATIONAL          0xFD
#define EPL_NMT_CS_STOPPED              0x4D
#define EPL_NMT_CS_BASIC_ETHERNET       0x1E

static const value_string epl_nmt_cs_vals[] = {
    {EPL_NMT_GS_OFF,                  "NMT_GS_OFF"                },
    {EPL_NMT_GS_INITIALIZING,         "NMT_GS_INITIALIZING"       },
    {EPL_NMT_GS_RESET_APPLICATION,    "NMT_GS_RESET_APPLICATION"  },
    {EPL_NMT_GS_RESET_COMMUNICATION,  "NMT_GS_RESET_COMMUNICATION"},
    {EPL_NMT_CS_NOT_ACTIVE,           "NMT_CS_NOT_ACTIVE"         },
    {EPL_NMT_CS_PRE_OPERATIONAL_1,    "NMT_CS_PRE_OPERATIONAL_1"  },
    {EPL_NMT_CS_PRE_OPERATIONAL_2,    "NMT_CS_PRE_OPERATIONAL_2"  },
    {EPL_NMT_CS_READY_TO_OPERATE,     "NMT_CS_READY_TO_OPERATE"   },
    {EPL_NMT_CS_OPERATIONAL,          "NMT_CS_OPERATIONAL"        },
    {EPL_NMT_CS_STOPPED,              "NMT_CS_STOPPED"            },
    {EPL_NMT_CS_BASIC_ETHERNET,       "NMT_CS_BASIC_ETHERNET"     },
    {0,NULL}
};

/* NMT State values (for MN)*/
#define EPL_NMT_GS_OFF                  0x00
#define EPL_NMT_GS_INITIALIZING         0x19
#define EPL_NMT_GS_RESET_APPLICATION    0x29
#define EPL_NMT_GS_RESET_COMMUNICATION  0x39
#define EPL_NMT_MS_NOT_ACTIVE           0x1C
#define EPL_NMT_MS_PRE_OPERATIONAL_1    0x1D
#define EPL_NMT_MS_PRE_OPERATIONAL_2    0x5D
#define EPL_NMT_MS_READY_TO_OPERATE     0x6D
#define EPL_NMT_MS_OPERATIONAL          0xFD
#define EPL_NMT_MS_BASIC_ETHERNET       0x1E

static const value_string epl_nmt_ms_vals[] = {
    {EPL_NMT_GS_OFF,                  "NMT_GS_OFF"                },
    {EPL_NMT_GS_INITIALIZING,         "NMT_GS_INITIALIZING"       },
    {EPL_NMT_GS_RESET_APPLICATION,    "NMT_GS_RESET_APPLICATION"  },
    {EPL_NMT_GS_RESET_COMMUNICATION,  "NMT_GS_RESET_COMMUNICATION"},
    {EPL_NMT_MS_NOT_ACTIVE,           "NMT_MS_NOT_ACTIVE"         },
    {EPL_NMT_MS_PRE_OPERATIONAL_1,    "NMT_MS_PRE_OPERATIONAL_1"  },
    {EPL_NMT_MS_PRE_OPERATIONAL_2,    "NMT_MS_PRE_OPERATIONAL_2"  },
    {EPL_NMT_MS_READY_TO_OPERATE,     "NMT_MS_READY_TO_OPERATE"   },
    {EPL_NMT_MS_OPERATIONAL,          "NMT_MS_OPERATIONAL"        },
    {EPL_NMT_MS_BASIC_ETHERNET,       "NMT_MS_BASIC_ETHERNET"     },
    {0,NULL}
};

/* SDO SequenceLayer */
#define EPL_ASND_SDO_SEQ_RECEIVE_SEQUENCE_NUMBER_OFFSET        4
#define EPL_ASND_SDO_SEQ_RECEIVE_CON_OFFSET                    4

#define EPL_ASND_SDO_SEQ_SEND_SEQUENCE_NUMBER_OFFSET           5
#define EPL_ASND_SDO_SEQ_SEND_CON_OFFSET                       5

#define EPL_ASND_SDO_SEQ_RECEIVE_CON_NO_CONNECTION          0x00
#define EPL_ASND_SDO_SEQ_RECEIVE_CON_INITIALIZATION         0x01
#define EPL_ASND_SDO_SEQ_RECEIVE_CON_CONNECTION_VALID       0x02
#define EPL_ASND_SDO_SEQ_RECEIVE_CON_ERROR_RESPONSE         0x03

static const value_string epl_sdo_receive_con_vals[] = {
    {EPL_ASND_SDO_SEQ_RECEIVE_CON_NO_CONNECTION,      "No connection"                          },
    {EPL_ASND_SDO_SEQ_RECEIVE_CON_INITIALIZATION,     "Initialization"                         },
    {EPL_ASND_SDO_SEQ_RECEIVE_CON_CONNECTION_VALID,   "Connection valid"                       },
    {EPL_ASND_SDO_SEQ_RECEIVE_CON_ERROR_RESPONSE,     "Error Response (retransmission request)"},
    {0,NULL}
};

#define EPL_ASND_SDO_SEQ_SEND_CON_NO_CONNECTION             0x00
#define EPL_ASND_SDO_SEQ_SEND_CON_INITIALIZATION            0x01
#define EPL_ASND_SDO_SEQ_SEND_CON_CONNECTION_VALID          0x02
#define EPL_ASND_SDO_SEQ_SEND_CON_ERROR_VALID_ACK_REQ       0x03  

static const value_string epl_sdo_send_con_vals[] = {
    {EPL_ASND_SDO_SEQ_SEND_CON_NO_CONNECTION,         "No connection"                             },
    {EPL_ASND_SDO_SEQ_SEND_CON_INITIALIZATION,        "Initialization"                            },
    {EPL_ASND_SDO_SEQ_SEND_CON_CONNECTION_VALID,      "Connection valid"                          },
    {EPL_ASND_SDO_SEQ_SEND_CON_ERROR_VALID_ACK_REQ,   "Connection valid with acknowledge request" },
    {0,NULL}
};

/* SDO EPL Command Layer Protocol */
#define EPL_ASND_SDO_CMD_ABORT_FILTER                    0x40
#define EPL_ASND_SDO_CMD_SEGMENTATION_FILTER             0x10
#define EPL_ASND_SDO_CMD_RESPONSE_FILTER                 0x80


/* SDO - Abort Transfer */
static const value_string sdo_cmd_abort_code[] = { 
    {0x05030000, "reserved" },
    {0x05040000, "SDO protocol timed out." },
    {0x05040001, "Client/server Command ID not valid or unknown." },
    {0x05040002, "Invalid block size." },
    {0x05040003, "Invalid sequence number." },
    {0x05040004, "reserved" },
    {0x05040005, "Out of memory." },
    {0x06010000, "Unsupported access to an object." },
    {0x06010001, "Attempt to read a write-only object." },
    {0x06010002, "Attempt to write a read-only object." },
    {0x06020000, "Object does not exist in the object dictionary." },
    {0x06040041, "Object can not be mapped to the PDO." },
    {0x06040042, "The number and length of the objects to be mapped would exceed PDO length." },  
    {0x06040043, "General parameter incompatibility." },  
    {0x06040047, "General internal incompatibility in the device." },
    {0x06060000, "Access failed due to an hardware error." }, 
    {0x06070010, "Data type does not match, length of service parameter does not match." },
    {0x06070012, "Data type does not match, length of service parameter too high." },
    {0x06070013, "Data type does not match, length of service parameter too low." },
    {0x06090011, "Sub-index does not exist." },
    {0x06090030, "Value range of parameter exceeded (only for write access)." },
    {0x06090031, "Value of parameter writen to high." },
    {0x06090032, "Value of parameter writen to low." },  
    {0x06090036, "maximum value is less then minimum value." },  
    {0x08000000, "General error" },  
    {0x08000020, "Data cannot be transferred or stored to the application." },
    {0x08000021, "Data cannot be transferred or stored to the application because of local control." }, 
    {0x08000022, "Data cannot be transferred or stored to the application because of the present device state." },
    {0x08000023, "Object dictionary dynamic generation fails or no object dictionary is present." },   
    {0x08000024, "EDS, DCF or Concise DCF Data set empty." },   
    {0,NULL}
}; 


#define EPL_ASND_SDO_CMD_RESPONSE_RESPONSE      0
#define EPL_ASND_SDO_CMD_RESPONSE_REQUEST       1

static const value_string epl_sdo_asnd_cmd_response[] = {
    {EPL_ASND_SDO_CMD_RESPONSE_RESPONSE,  "Request"   },
    {EPL_ASND_SDO_CMD_RESPONSE_REQUEST,   "Response"  },
    {0,NULL}
};

#define EPL_ASND_SDO_CMD_ABORT_TRANSFER_OK      0
#define EPL_ASND_SDO_CMD_ABORT_ABORT_TRANSFER   1

static const value_string epl_sdo_asnd_cmd_abort[] = {
    {EPL_ASND_SDO_CMD_ABORT_TRANSFER_OK,      "Transfer OK"    },
    {EPL_ASND_SDO_CMD_ABORT_ABORT_TRANSFER,   "Abort Transfer" },
    {0,NULL}
}; 

#define EPL_ASND_SDO_CMD_SEGMENTATION_EPEDITED_TRANSFER 0
#define EPL_ASND_SDO_CMD_SEGMENTATION_INITIALE_TRANSFER 1
#define EPL_ASND_SDO_CMD_SEGMENTATION_SEGMENT           2
#define EPL_ASND_SDO_CMD_SEGMENTATION_TRANSFER_COMPLETE 3

static const value_string epl_sdo_asnd_cmd_segmentation[] = {
    {EPL_ASND_SDO_CMD_SEGMENTATION_EPEDITED_TRANSFER, "Expedited Transfer" },
    {EPL_ASND_SDO_CMD_SEGMENTATION_INITIALE_TRANSFER, "Initiate Transfer"  },
    {EPL_ASND_SDO_CMD_SEGMENTATION_SEGMENT,           "Segment"            },
    {EPL_ASND_SDO_CMD_SEGMENTATION_TRANSFER_COMPLETE, "Transfer Complete"  },
    {0,NULL}
};

#define EPL_ASND_SDO_COMMAND_NOT_IN_LIST                        0x00
#define EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX                     0x01
#define EPL_ASND_SDO_COMMAND_READ_BY_INDEX                      0x02
#define EPL_ASND_SDO_COMMAND_WRITE_ALL_BY_INDEX                 0x03
#define EPL_ASND_SDO_COMMAND_READ_ALL_BY_INDEX                  0x04
#define EPL_ASND_SDO_COMMAND_WRITE_BY_NAME                      0x05
#define EPL_ASND_SDO_COMMAND_READ_BY_NAME                       0x06
#define EPL_ASND_SDO_COMMAND_FILE_WRITE                         0x20
#define EPL_ASND_SDO_COMMAND_FILE_READ                          0x21
#define EPL_ASND_SDO_COMMAND_WRITE_MULTIPLE_PARAMETER_BY_INDEX  0x31
#define EPL_ASND_SDO_COMMAND_READ_MULTIPLE_PARAMETER_BY_INDEX   0x32
#define EPL_ASND_SDO_COMMAND_MAXIMUM_SEGMENT_SIZE               0x70
#define EPL_ASND_SDO_COMMAND_LINK_NAME_TO_INDEX                 0x71

static const value_string epl_sdo_asnd_commands[] = {
    {EPL_ASND_SDO_COMMAND_NOT_IN_LIST                      , "Not in List"                       },
    {EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX                   , "Write by Index"                    },
    {EPL_ASND_SDO_COMMAND_READ_BY_INDEX                    , "Read by Index"                     },
    {EPL_ASND_SDO_COMMAND_WRITE_ALL_BY_INDEX               , "Write All by Index"                },
    {EPL_ASND_SDO_COMMAND_READ_ALL_BY_INDEX                , "Read All by Index"                 },
    {EPL_ASND_SDO_COMMAND_WRITE_BY_NAME                    , "Write by Name"                     },
    {EPL_ASND_SDO_COMMAND_READ_BY_NAME                     , "Read by Name"                      },
    {EPL_ASND_SDO_COMMAND_FILE_WRITE                       , "File Write"                        },
    {EPL_ASND_SDO_COMMAND_FILE_READ                        , "File Read"                         },
    {EPL_ASND_SDO_COMMAND_WRITE_MULTIPLE_PARAMETER_BY_INDEX, "Write Multiple Parameter by Index" },
    {EPL_ASND_SDO_COMMAND_READ_MULTIPLE_PARAMETER_BY_INDEX , "Read Multiple Parameter by Index"  },
    {EPL_ASND_SDO_COMMAND_MAXIMUM_SEGMENT_SIZE             , "Maximum Segment Size"              },
    {EPL_ASND_SDO_COMMAND_LINK_NAME_TO_INDEX               , "Link objects only accessible via name to an index/sub-index"},
    {0,NULL}
};

#endif /* __PACKET_EPL_H__ */
