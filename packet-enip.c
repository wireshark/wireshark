/* packet-enip.c
 * Routines for EtherNet/IP (Industrial Protocol) dissection
 * EtherNet/IP Home: www.odva.org
 *
 * Copyright 2003
 * Magnus Hansson <mah@hms.se>
 * Joakim Wiberg <jow@hms.se>
 *
 * $Id: packet-enip.c,v 1.7 2003/10/06 08:10:32 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

/* Defines */
#define ENIP_ENCAP_PORT		44818	/* EtherNet/IP located on port 44818 */
#define ENIP_IO_PORT		   2222	/* EtherNet/IP IO located on port 2222  */

/* return codes of function classifying packets as query/response */
#define REQUEST_PACKET	   0
#define RESPONSE_PACKET		1
#define CANNOT_CLASSIFY		2

/* CIP Encapsulation function codes */
#define NOP                0x0000
#define LIST_SERVICES      0x0004
#define LIST_IDENTITY      0x0063
#define LIST_INTERFACES    0x0064
#define REGISTER_SESSION   0x0065
#define UNREGISTER_SESSION 0x0066
#define SEND_RR_DATA       0x006F
#define SEND_UNIT_DATA     0x0070
#define INDICATE_STATUS    0x0072
#define CANCEL             0x0073

/* CIP Encapsulation status codes */
#define SUCCESS               0x0000
#define INVALID_CMD           0x0001
#define NO_RESOURCES          0x0002
#define INCORRECT_DATA        0x0003
#define INVALID_SESSION       0x0064
#define INVALID_LENGTH        0x0065
#define UNSUPPORTED_PROT_REV  0x0069

/* CIP Common Data Format Type IDs */
#define CDF_NULL              0x0000
#define LIST_IDENTITY_RESP    0x000C
#define CONNECTION_BASED      0x00A1
#define CONNECTION_TRANSPORT  0x00B1
#define UNCONNECTED_MSG       0x00B2
#define LIST_SERVICES_RESP    0x0100
#define SOCK_ADR_INFO_OT      0x8000
#define SOCK_ADR_INFO_TO      0x8001
#define SEQ_ADDRESS           0x8002

/* CIP Service Codes */
#define SC_GET_ATT_ALL           0x01
#define SC_SET_ATT_ALL           0x02
#define SC_GET_ATT_LIST          0x03
#define SC_SET_ATT_LIST          0x04
#define SC_RESET                 0x05
#define SC_START                 0x06
#define SC_STOP                  0x07
#define SC_CREATE                0x08
#define SC_DELETE                0x09
#define SC_MULT_SERV_PACK        0x0A
#define SC_APPLY_ATTRIBUTES      0x0D
#define SC_GET_ATT_SINGLE        0x0E
#define SC_SET_ATT_SINGLE        0x10
#define SC_FIND_NEXT_OBJ_INST    0x11
#define SC_RESTOR                0x15
#define SC_SAVE                  0x16
#define SC_NO_OP                 0x17
#define SC_GET_MEMBER            0x18
#define SC_SET_MEMBER            0x19

#define SC_FWD_CLOSE             0x4E
#define SC_UNCON_SEND            0x52
#define SC_FWD_OPEN              0x54



/* CIP Genral status codes */
#define CI_GRC_SUCCESS              0x00
#define CI_GRC_FAILURE              0x01
#define CI_GRC_NO_RESOURCE          0x02
#define CI_GRC_BAD_DATA             0x03
#define CI_GRC_BAD_PATH             0x04
#define CI_GRC_BAD_CLASS_INSTANCE   0x05
#define CI_GRC_PARTIAL_DATA         0x06
#define CI_GRC_CONN_LOST            0x07
#define CI_GRC_BAD_SERVICE          0x08
#define CI_GRC_BAD_ATTR_DATA        0x09
#define CI_GRC_ATTR_LIST_ERROR      0x0A
#define CI_GRC_ALREADY_IN_MODE      0x0B
#define CI_GRC_BAD_OBJ_MODE         0x0C
#define CI_GRC_OBJ_ALREADY_EXISTS   0x0D
#define CI_GRC_ATTR_NOT_SETTABLE    0x0E
#define CI_GRC_PERMISSION_DENIED    0x0F
#define CI_GRC_DEV_IN_WRONG_STATE   0x10
#define CI_GRC_REPLY_DATA_TOO_LARGE 0x11
#define CI_GRC_FRAGMENT_PRIMITIVE   0x12
#define CI_GRC_CONFIG_TOO_SMALL     0x13
#define CI_GRC_UNDEFINED_ATTR       0x14
#define CI_GRC_CONFIG_TOO_BIG       0x15
#define CI_GRC_OBJ_DOES_NOT_EXIST   0x16
#define CI_GRC_NO_FRAGMENTATION     0x17
#define CI_GRC_DATA_NOT_SAVED       0x18
#define CI_GRC_DATA_WRITE_FAILURE   0x19
#define CI_GRC_REQUEST_TOO_LARGE    0x1A
#define CI_GRC_RESPONSE_TOO_LARGE   0x1B
#define CI_GRC_MISSING_LIST_DATA    0x1C
#define CI_GRC_INVALID_LIST_STATUS  0x1D
#define CI_GRC_SERVICE_ERROR        0x1E
#define CI_GRC_CONN_RELATED_FAILURE 0x1F
#define CI_GRC_INVALID_PARAMETER    0x20
#define CI_GRC_WRITE_ONCE_FAILURE   0x21
#define CI_GRC_INVALID_REPLY        0x22
#define CI_GRC_BAD_KEY_IN_PATH      0x25
#define CI_GRC_BAD_PATH_SIZE        0x26
#define CI_GRC_UNEXPECTED_ATTR      0x27
#define CI_GRC_INVALID_MEMBER       0x28
#define CI_GRC_MEMBER_NOT_SETTABLE  0x29

#define CI_GRC_STILL_PROCESSING     0xFF


/* IOI Path types */
#define CI_SEGMENT_TYPE_MASK        0xE0

#define CI_PATH_SEGMENT             0x00
#define CI_LOGICAL_SEGMENT          0x20
#define CI_NETWORK_SEGMENT          0x40
#define CI_SYMBOLIC_SEGMENT         0x60
#define CI_DATA_SEGMENT             0x80

#define CI_LOGICAL_SEG_TYPE_MASK    0x1C
#define CI_LOGICAL_SEG_CLASS_ID     0x00
#define CI_LOGICAL_SEG_INST_ID      0x04
#define CI_LOGICAL_SEG_MBR_ID       0x08
#define CI_LOGICAL_SEG_CON_POINT    0x0C
#define CI_LOGICAL_SEG_ATTR_ID      0x10
#define CI_LOGICAL_SEG_SPECIAL      0x14
#define CI_LOGICAL_SEG_SERV_ID      0x18
#define CI_LOGICAL_SEG_RES_1        0x1C

#define CI_LOGICAL_SEG_FORMAT_MASK  0x03
#define CI_LOGICAL_SEG_8_BIT        0x00
#define CI_LOGICAL_SEG_16_BIT       0x01
#define CI_LOGICAL_SEG_32_BIT       0x02
#define CI_LOGICAL_SEG_RES_2        0x03
#define CI_LOGICAL_SEG_E_KEY        0x00

#define CI_E_KEY_FORMAT_VAL         0x04

#define CI_DATA_SEG_SIMPLE          0x80
#define CI_DATA_SEG_SYMBOL          0x91


/* Device Profile:s */
#define DP_GEN_DEV                           0x00
#define DP_AC_DRIVE	                        0x02
#define DP_MOTOR_OVERLOAD                    0x03
#define DP_LIMIT_SWITCH                      0x04
#define DP_IND_PROX_SWITCH                   0x05
#define DP_PHOTO_SENSOR                      0x06
#define DP_GENP_DISC_IO                      0x07
#define DP_RESOLVER                          0x09
#define DP_COM_ADAPTER                       0x0C
#define DP_POS_CNT                           0x10
#define DP_DC_DRIVE                          0x13
#define DP_CONTACTOR                         0x15
#define DP_MOTOR_STARTER                     0x16
#define DP_SOFT_START                        0x17
#define DP_HMI                               0x18
#define DP_MASS_FLOW_CNT                     0x1A
#define DP_PNEUM_VALVE                       0x1B
#define DP_VACUUM_PRES_GAUGE                 0x1C



/* Initialize the protocol and registered fields */
static int proto_cipencap              = -1;
static int hf_enip_command             = -1;
static int hf_enip_ifacehnd            = -1;

static int hf_enip_cpf_typeid          = -1;

static int hf_enip_ucm_sc              = -1;
static int hf_enip_ucm_rr              = -1;
static int hf_enip_ucm_path            = -1;
static int hf_enip_ucm_genstat         = -1;
static int hf_enip_cpf_lir_sinfamily   = -1;
static int hf_enip_cpf_lir_sinport     = -1;
static int hf_enip_cpf_lir_sinaddr     = -1;
static int hf_enip_cpf_lir_sinzero     = -1;
static int hf_enip_cpf_lir_devtype     = -1;
static int hf_enip_cpf_lir_prodcode    = -1;
static int hf_enip_cpf_lir_status      = -1;
static int hf_enip_cpf_lir_sernbr      = -1;
static int hf_enip_cpf_lir_namelength  = -1;
static int hf_enip_cpf_lir_name        = -1;
static int hf_enip_cpf_lir_state       = -1;

static int hf_enip_cpf_sat_connid      = -1;
static int hf_enip_cpf_sat_seqnum      = -1;

static int hf_enip_vendors             = -1;

static int hf_enip_ucm_fwo_comp        = -1;
static int hf_enip_ucm_fwo_mrev        = -1;

static int hf_enip_ucm_fwo_con_size    = -1;
static int hf_enip_ucm_fwo_fixed_var   = -1;
static int hf_enip_ucm_fwo_prio        = -1;
static int hf_enip_ucm_fwo_typ         = -1;
static int hf_enip_ucm_fwo_own         = -1;

static int hf_enip_cpf_lsr_tcp         = -1;
static int hf_enip_cpf_lsr_udp         = -1;


/* Initialize the subtree pointers */
static gint ett_cipencap   = -1;
static gint ett_cip        = -1;
static gint ett_cpf        = -1;
static gint ett_path       = -1;
static gint ett_ekey_path  = -1;
static gint ett_cia_path   = -1;
static gint ett_data_seg   = -1;

static gint ett_cipencaph  = -1;
static gint ett_csf        = -1;
static gint ett_rrsc       = -1;
static gint ett_sockadd    = -1;
static gint ett_mcsc       = -1;
static gint ett_ncp        = -1;
static gint ett_lsrcf      = -1;
static gint ett_mes_req    = -1;
static gint ett_cmd_data   = -1;
static gint ett_port_path  = -1;
static gint ett_mult_ser   = -1;



/* Translate function to string - Encapsulation commands */
static const value_string encap_cmd_vals[] = {
	{ NOP,			      "NOP"                },
	{ LIST_SERVICES,	   "List Services"      },
	{ LIST_IDENTITY,		"List Identity"      },
	{ LIST_INTERFACES,	"List Interfaces"    },
	{ REGISTER_SESSION,	"Register Session"   },
	{ UNREGISTER_SESSION,"Unregister Session" },
	{ SEND_RR_DATA,		"Send RR Data"       },
	{ SEND_UNIT_DATA,		"Send Unit Data"     },
	{ INDICATE_STATUS,	"Indicate Status"    },
	{ CANCEL,		      "Cancel"             },

	{ 0,				      NULL                 }
};


/* Translate function to string - Encapsulation status */
static const value_string encap_status_vals[] = {
	{ SUCCESS,			      "Success" },
	{ INVALID_CMD,	         "Invalid Command" },
	{ NO_RESOURCES,		   "No Memory Resources" },
	{ INCORRECT_DATA,	      "Incorrect Data" },
	{ INVALID_SESSION,	   "Invalid Session Handle" },
	{ INVALID_LENGTH,       "Invalid Length" },
	{ UNSUPPORTED_PROT_REV,	"Unsupported Protocol Revision" },

	{ 0,				         NULL }
};

/* Translate function to Common data format values */
static const value_string cdf_type_vals[] = {
	{ CDF_NULL,			      "Null Address Item" },
	{ LIST_IDENTITY_RESP,	"List Identity Response" },
	{ CONNECTION_BASED,		"Connected Address Item" },
	{ CONNECTION_TRANSPORT,	"Connected Data Item" },
	{ UNCONNECTED_MSG,	   "Unconnected Data Item" },
	{ LIST_SERVICES_RESP,   "List Services Response" },
	{ SOCK_ADR_INFO_OT,	   "Socket Address Info O->T" },
	{ SOCK_ADR_INFO_TO,	   "Socket Address Info T->O" },
	{ SEQ_ADDRESS,	         "Sequenced Address Item" },

	{ 0,				         NULL }
};

/* Translate function to string - CIP Service codes */
static const value_string encap_sc_vals[] = {
	{ SC_GET_ATT_ALL,	         "Get Attribute All" },
	{ SC_SET_ATT_ALL,	         "Set Attribute All" },
	{ SC_GET_ATT_LIST,	      "Get Attribute List" },
	{ SC_SET_ATT_LIST,	      "Set Attribute List" },
	{ SC_RESET,	               "Reset" },
   { SC_START,	               "Start" },
   { SC_STOP,	               "Stop" },
   { SC_CREATE,	            "Create" },
   { SC_DELETE,	            "Delete" },
   { SC_APPLY_ATTRIBUTES,	   "Apply Attributes" },
	{ SC_GET_ATT_SINGLE,	      "Get Attribute Single" },
	{ SC_SET_ATT_SINGLE,	      "Set Attribute Single" },
   { SC_FIND_NEXT_OBJ_INST,	"Find Next Object Instance" },
   { SC_RESTOR,	            "Restore" },
	{ SC_SAVE,	               "Save" },
	{ SC_NO_OP,	               "Nop" },
	{ SC_GET_MEMBER,	         "Get Member" },
	{ SC_SET_MEMBER,	         "Set Member" },
	{ SC_MULT_SERV_PACK,       "Multiple Service Packet" },

	/* Some class specific services */
	{ SC_FWD_CLOSE,	         "Forward Close" },
	{ SC_FWD_OPEN,	            "Forward Open" },
	{ SC_UNCON_SEND,           "Unconnected Send" },

	{ 0,				            NULL }
};

/* Translate function to string - CIP Request/Response */
static const value_string encap_sc_rr[] = {
	{ 0,	      "Request"  },
	{ 1,	      "Response" },

	{ 0,			NULL }
};


/* Translate function to string - Compatibility */
static const value_string enip_com_bit_vals[] = {
	{ 0,	      "Bit Cleared" },
	{ 1,	      "Bit Set"     },

	{ 0,        NULL          }
};

/* Translate function to string - True/False */
static const value_string enip_true_false_vals[] = {
	{ 0,	      "False"       },
	{ 1,	      "True"        },

	{ 0,        NULL          }
};


/* Translate function to string - Connection priority */
static const value_string enip_con_prio_vals[] = {
	{ 0,	      "Low Priority"  },
	{ 1,	      "High Priority" },
	{ 2,	      "Scheduled"     },
	{ 3,	      "Urgent"        },

	{ 0,        NULL            }
};


/* Translate function to string - Connection size fixed or variable */
static const value_string enip_con_fw_vals[] = {
	{ 0,	      "Fixed"    },
	{ 1,	      "Variable" },

	{ 0,        NULL       }
};


/* Translate function to string - Connection owner */
static const value_string enip_con_owner_vals[] = {
	{ 0,	      "Exclusive" },
	{ 1,	      "Redundant" },

	{ 0,        NULL        }
};


/* Translate function to string - Connection type */
static const value_string enip_con_type_vals[] = {
	{ 0,	      "Null"           },
	{ 1,	      "Multicast"      },
	{ 2,	      "Point to Point" },
	{ 3,	      "Reserved"       },

	{ 0,        NULL             }
};

/* Translate function to string - Timeout Multiplier */
static const value_string enip_con_time_mult_vals[] = {
	{ 0,        "*4"   },
	{ 1,        "*8"   },
	{ 2,        "*16"  },
	{ 3,        "*32"  },
	{ 4,        "*64"  },
	{ 5,        "*128" },
	{ 6,        "*256" },
	{ 7,        "*512" },

   { 0,        NULL    }
};


/* Translate function to string - CIP General Status codes */
static const value_string encap_cip_gs_vals[] = {
	{ CI_GRC_SUCCESS,             "Success" },
   { CI_GRC_FAILURE,             "Connection failure" },
   { CI_GRC_NO_RESOURCE,         "Resource(s) unavailable" },
   { CI_GRC_BAD_DATA,            "Obj specific data bad" },
   { CI_GRC_BAD_PATH,            "Bad path segment" },
   { CI_GRC_BAD_CLASS_INSTANCE,  "Class/Instance unknown" },
   { CI_GRC_PARTIAL_DATA,        "Not all expected data sent" },
   { CI_GRC_CONN_LOST,           "Messaging connection lost" },
   { CI_GRC_BAD_SERVICE,         "Unimplemented service code" },
   { CI_GRC_BAD_ATTR_DATA,       "Bad attribute data value" },
   { CI_GRC_ATTR_LIST_ERROR,     "Get/Set attr list failed" },
   { CI_GRC_ALREADY_IN_MODE,     "Obj already in requested mode" },
   { CI_GRC_BAD_OBJ_MODE,        "Obj not in proper mode" },
   { CI_GRC_OBJ_ALREADY_EXISTS,  "Object already created" },
   { CI_GRC_ATTR_NOT_SETTABLE,   "Set of get only attr tried" },
   { CI_GRC_PERMISSION_DENIED,   "Insufficient access permission" },
   { CI_GRC_DEV_IN_WRONG_STATE,  "Device not in proper mode" },
   { CI_GRC_REPLY_DATA_TOO_LARGE,"Response packet too large" },
   { CI_GRC_FRAGMENT_PRIMITIVE,  "Primitive value will fragment" },
   { CI_GRC_CONFIG_TOO_SMALL,    "Configuration too small" },
   { CI_GRC_UNDEFINED_ATTR,      "Attribute is undefined" },
   { CI_GRC_CONFIG_TOO_BIG,      "Configuration too big" },
   { CI_GRC_OBJ_DOES_NOT_EXIST,  "Non-existant object specified" },
   { CI_GRC_NO_FRAGMENTATION,    "Fragmentation not active" },
   { CI_GRC_DATA_NOT_SAVED,      "Attr data not previously saved" },
   { CI_GRC_DATA_WRITE_FAILURE,  "Attr data not saved this time" },
   { CI_GRC_REQUEST_TOO_LARGE,   "Routing failure on request" },
   { CI_GRC_RESPONSE_TOO_LARGE,  "Routing failure on response" },
   { CI_GRC_MISSING_LIST_DATA,   "Attr data not found in list" },
   { CI_GRC_INVALID_LIST_STATUS, "Returned list of attr w/status" },
   { CI_GRC_SERVICE_ERROR,       "Embedded service failed" },
   { CI_GRC_CONN_RELATED_FAILURE,"Error in conn processing" },
   { CI_GRC_INVALID_PARAMETER,   "Param associated with req inv" },
   { CI_GRC_WRITE_ONCE_FAILURE,  "Write once previously done" },
   { CI_GRC_INVALID_REPLY,       "Invalid reply received" },
   { CI_GRC_BAD_KEY_IN_PATH,     "Electronic key in path failed" },
   { CI_GRC_BAD_PATH_SIZE,       "Invalid path size" },
   { CI_GRC_UNEXPECTED_ATTR,     "Cannot set attr at this time" },
   { CI_GRC_INVALID_MEMBER,      "Member ID in list nonexistant" },
   { CI_GRC_MEMBER_NOT_SETTABLE, "Cannot set value of member" },

  	{ 0,				               NULL }
};


/* Translate Vendor ID:s */
static const value_string encap_cip_vendor_vals[] = {
   { 1,     "Rockwell Automation/Allen-Bradley"                   },
   { 5,     "Rockwell Automation/Reliance Electric"               },
   { 40,    "WAGO Corporation"                                    },
   { 49,    "Grayhill Inc."                                       },
   { 50,    "Real Time Automation (C&ID)"                         },
   { 52,    "Numatics, Inc."                                      },
   { 57,    "Pepperl + Fuchs"                                     },
   { 81,    "IXXAT Automation GmbH"                               },
   { 90,    "HMS Industrial Networks AB"                          },
   { 96,    "Digital Electronics Corp"                            },
   { 133,   "Balogh T.A.G., Corporation"                          },
   { 170,   "Pyramid Solutions, Inc."                             },
   { 256,   "InterlinkBT LLC"                                     },
   { 258,   "Hardy Instruments, Inc."                             },
   { 283,   "Hilscher GmbH"                                       },
   { 287,   "Bosch Rexroth Corporation, Indramat"                 },
   { 356,   "Fanuc Robotics America"                              },
   { 579,   "Applicom international"                              },
   { 588,   "West Instruments Limited"                            },
   { 590,   "Delta Computer Systems Inc."                         },
   { 596,   "Wire-Pro, Inc."                                      },
   { 635,   "The Siemon Company"                                  },
   { 638,   "Woodhead Connectivity"                               },
   { 651,   "Fife Corporation"                                    },
   { 668,   "Rockwell Automation/Entek IRD Intl."                 },
   { 678,   "Cognex Corporation"                                  },
   { 734,   "Hakko Electronics Co., Ltd"                          },
   { 735,   "Tang & Associates"                                   },
   { 743,   "Linux Network Services"                              },
   { 748,   "DVT Corporation"                                     },
   { 759,   "FLS Automation A/S"                                  },
   { 768,   "CSIRO Mining Automation"                             },
   { 778,   "Harting, Inc. NA"                                    },
   { 784,   "Ci Technologies Pty Ltd (for Pelamos Industries)"    },
   { 796,   "Siemens Energy & Automation, Inc."                   },
   { 798,   "Tyco Electronics"                                    },
   { 803,   "ICP DAS Co., LTD"                                    },
   { 805,   "Digi International, Inc."                            },
   { 812,   "Process Control Corporation"                         },
   { 832,   "Quest Technical Solutions, Inc."                     },
   { 841,   "Panduit Corporation"                                 },
   { 850,   "Datalogic, Inc."                                     },
   { 851,   "SoftPLC Corporation"                                 },
   { 857,   "RVSI"                                                },
   { 859,   "Tennessee Rand Automation"                           },

	{ 0,		NULL                                                  }
};

/* Translate Device Profile:s */
static const value_string encap_cip_devtype_vals[] = {
   { DP_GEN_DEV,              "Generic Device"              },
   { DP_AC_DRIVE,             "AC Drive"                    },
   { DP_MOTOR_OVERLOAD,       "Motor Overload"              },
   { DP_LIMIT_SWITCH,         "Limit Switch"                },
   { DP_IND_PROX_SWITCH,      "Inductive Proximity Switch"  },
   { DP_PHOTO_SENSOR,         "Photoelectric Sensor"        },
   { DP_GENP_DISC_IO,         "General Purpose Dicrete I/O" },
   { DP_RESOLVER,             "Resolver"                    },
   { DP_COM_ADAPTER,          "Communications Adapter"      },
   { DP_POS_CNT,              "Position Controller",        },
   { DP_DC_DRIVE,             "DC Drive"                    },
   { DP_CONTACTOR,            "Contactor",                  },
   { DP_MOTOR_STARTER,        "Motor Starter",              },
   { DP_SOFT_START,           "Soft Start",                 },
   { DP_HMI,                  "Human-Machine Interface"     },
   { DP_MASS_FLOW_CNT,        "Mass Flow Controller"        },
   { DP_PNEUM_VALVE,          "Pneumatic Valve"             },
   { DP_VACUUM_PRES_GAUGE,    "Vaccuum Pressure Gauge"      },

   { 0,				            NULL                          }
};


/* Translate class names */
static const value_string enip_class_names_vals[] = {
	{ 0x01,     "Identity Object"                       },
	{ 0x02,     "Message Router"                        },
	{ 0x03,     "DeviceNet Object"                      },
	{ 0x04,     "Assembly Object"                       },
	{ 0x05,     "Connection Object"                     },
	{ 0x06,     "Connection Manager"                    },
	{ 0x07,     "Register Object"                       },
	{ 0x08,     "Discrete Input Point Object"           },
	{ 0x09,     "Discrete Output Point Object"          },
	{ 0x0A,     "Analog Input Point Object"             },
	{ 0x0B,     "Analog Output Point Object"            },
	{ 0x0E,     "Presence Sensing Object"               },
	{ 0x0F,     "Parameter Object"                      },
	{ 0x10,     "Parameter Group Object"                },
	{ 0x12,     "Group Object"                          },
	{ 0x1D,     "Discrete Input Group Object"           },
	{ 0x1E,     "Discrete Output Group Object"          },
	{ 0x1F,     "Discrete Group Object"                 },
	{ 0x20,     "Analog Input Group Object"             },
	{ 0x21,     "Analog Output Group Object"            },
	{ 0x22,     "Analog Group Object"                   },
	{ 0x23,     "Position Sensor Object"                },
	{ 0x24,     "Position Controller Supervisor Object" },
	{ 0x25,     "Position Controller Object"            },
	{ 0x26,     "Block Sequencer Object"                },
	{ 0x27,     "Command Block Object"                  },
	{ 0x28,     "Motor Data Object"                     },
	{ 0x29,     "Control Supervisor Object"             },
	{ 0x2A,     "AC/DC Drive Object"                    },
	{ 0x2B,     "Acknowledge Handler Object"            },
	{ 0x2C,     "Overload Object"                       },
	{ 0x2D,     "Softstart Object"                      },
	{ 0x2E,     "Selection Object"                      },
	{ 0x30,     "S-Device Supervisor Object"            },
	{ 0x31,     "S-Analog Sensor Object"                },
	{ 0x32,     "S-Analog Actuator Object"              },
	{ 0x33,     "S-Single Stage Controller Object"      },
	{ 0x34,     "S-Gas Calibration Object"              },
	{ 0x35,     "Trip Point Object"                     },
	{ 0xF0,     "ControlNet Object"                     },
	{ 0xF1,     "ControlNet Keeper Object"              },
	{ 0xF2,     "ControlNet Scheduling Object"          },
	{ 0xF3,     "Connection Configuration Object"       },
	{ 0xF4,     "Port Object"                           },
	{ 0xF5,     "TCP/IP Interface Object"               },
	{ 0xF6,     "EtherNet Link Object"                  },

	{ 0,			NULL                                    }
};



static proto_item*
add_byte_array_text_to_proto_tree( proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char* str )
{
  char   *tmp, *tmp2, *tmp2start;
  proto_item* pi;
  int          i,tmp_length;
  guint32      octet;
  /* At least one version of Apple's C compiler/linker is buggy, causing
     a complaint from the linker about the "literal C string section"
     not ending with '\0' if we initialize a 16-element "char" array with
     a 16-character string, the fact that initializing such an array with
     such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
     '\0' byte in the string nonwithstanding. */
  static const char my_hex_digits[16] =
      { '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };



   if( ( length * 2 ) > 32 )
   {
      tmp2 = (char*)g_malloc( 36 );
      tmp_length = 16;
   }
   else
   {
      tmp2 = (char*)g_malloc( ( length * 2 ) + 1 );
      tmp_length = length;
   }

   tmp2start = tmp2;

   tmp = (char*)g_malloc( tmp_length );
   tvb_memcpy( tvb, tmp, start, tmp_length );

   for( i = 0; i < tmp_length; i++ )
   {
      octet = tmp[i];
      octet >>= 4;
      *tmp2++ = my_hex_digits[octet&0xF];
      octet = tmp[i];
      *tmp2++ = my_hex_digits[octet&0xF];
   }

   if( tmp_length != length )
   {
      *tmp2++ = '.';
      *tmp2++ = '.';
      *tmp2++ = '.';
   }

   *tmp2 = 0;

   pi = proto_tree_add_text( tree, tvb, start, length, "%s%s", str, tmp2start );

   g_free( tmp );
   g_free( tmp2start );

   return( pi );

} /* end of add_byte_array_text_to_proto_tree() */



/* Decode and add epath to tree */
static void
show_epath( tvbuff_t *tvb, proto_item *pi, int offset, int path_length )
{
   int pathpos;
   int temp_data;
   int temp_data2;
   unsigned char segment_type, temp_byte, opt_link_size;
   proto_tree *path_tree, *port_tree;
   proto_item *qi, *cia_item, *ds_item;
   proto_tree *e_key_tree, *cia_tree, *ds_tree;
   proto_item *mcpi, *temp_item, *port_item, *ext_link_item;
   proto_tree *mc_tree;
   int seg_size, i, temp_word;
   char *temp_string;

   /* Create a sub tree for the epath */
   path_tree = proto_item_add_subtree( pi, ett_path );

   proto_tree_add_item_hidden(path_tree, hf_enip_ucm_path,
							   tvb, offset, path_length, TRUE );

   pathpos = 0;

   while( pathpos < path_length )
   {
      /* Get segement type */
      segment_type = tvb_get_guint8( tvb, offset + pathpos );

      /* Determine the segment type */

      switch( segment_type & CI_SEGMENT_TYPE_MASK )
      {
      case CI_PATH_SEGMENT:

         port_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 0, "Port Segment (0x00)" );
         port_tree = proto_item_add_subtree( port_item, ett_port_path );

         /* Add Extended Link Address Size */
         temp_item = proto_tree_add_text( port_tree, tvb, offset+pathpos, 1, "Extended Link Address: " );

         if( segment_type & 0x10 )
         {
            proto_item_append_text(temp_item, "TRUE");
            opt_link_size = tvb_get_guint8( tvb, offset + pathpos + 1 );

            proto_tree_add_text( port_tree, tvb, offset+pathpos+1, 1, "Link Address Size: %d", opt_link_size  );
            ext_link_item = proto_tree_add_text( port_tree, tvb, offset+pathpos+2, opt_link_size, "Link Address: " );

            /* Add extended link address */
            for( i=0; i < opt_link_size; i++ )
            {
               temp_byte = tvb_get_guint8( tvb, offset + pathpos+2+i );
               proto_item_append_text(ext_link_item, "%c", temp_byte );
            }

            /* Pad byte */
            if( opt_link_size % 2 )
            {
              pathpos = pathpos + 3 + opt_link_size;
              proto_item_set_len(port_item, 3+opt_link_size);
            }
            else
            {
              pathpos = pathpos + 2 + opt_link_size;
              proto_item_set_len(port_item, 2+opt_link_size);
            }

         }
         else
         {
            proto_item_append_text(temp_item, "FALSE");
            proto_tree_add_text( port_tree, tvb, offset+pathpos, 1, "Port Identifier: %d", (segment_type & 0x0F)  );
            proto_tree_add_text( port_tree, tvb, offset+pathpos+1, 1, "Link Address: %d", tvb_get_guint8( tvb, offset + pathpos + 1 )  );
            proto_item_set_len(port_item, 2);
            pathpos += 2;
         }

         break;

      case CI_LOGICAL_SEGMENT:

         /* Logical segment, determin the logical type */

         switch( segment_type & CI_LOGICAL_SEG_TYPE_MASK )
         {
         case CI_LOGICAL_SEG_CLASS_ID:

            /* Logical Class ID, do a format check */

   		   if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
   		   {
   		      temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Class Segment (0x%02X)", segment_type );

               /* Create a sub tree for the class */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 8-bit class number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 1, 1, "Class: %s (0x%02X)", val_to_str( temp_data, enip_class_names_vals , "Unknown class" ), temp_data );

               temp_string = match_strval( temp_data, enip_class_names_vals );

               if( temp_string )
               {
                  proto_item_append_text(pi, "%s", temp_string );
               }
               else
               {
                  proto_item_append_text(pi, "Class: 0x%02X", temp_data );
               }

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 3, "16-Bit Logical Class Segment (0x%02X)", segment_type );

               /* Create a sub tree for the class */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit class number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 2, 2, "Class: %s (0x%04X)", val_to_str( temp_data, enip_class_names_vals , "Unknown class" ), temp_data );
               temp_string = match_strval( temp_data, enip_class_names_vals );

               if( temp_string )
               {
                  proto_item_append_text(pi, "%s", temp_string );
               }
               else
               {
                  proto_item_append_text(pi, "Class: 0x%04X", temp_data );
               }

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 5, "32-Bit Logical Instance Segment (0x%02X)", segment_type );

               /* Create a sub tree for the class */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 32-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 2, 4, "Class: %s (0x%08X)", val_to_str( temp_data, enip_class_names_vals , "Unknown class" ), temp_data );
               temp_string = match_strval( temp_data, enip_class_names_vals );

               if( temp_string )
               {
                  proto_item_append_text(pi, "%s", temp_string );
               }
               else
               {
                  proto_item_append_text(pi, "Class: 0x%08X", temp_data );
               }

               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Logical Segment Format" );
               return;
            }
            break;


         case CI_LOGICAL_SEG_INST_ID:

            /* Logical Instance ID, do a format check */

   		   if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
   		   {
   		      temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Instance Segment (0x%02X)", segment_type );

               /* Create a sub tree for the instance */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 8-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 1, 1, "Instance: 0x%02X", temp_data );
               proto_item_append_text(pi, ", Inst: 0x%02X", temp_data );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 3, "16-Bit Logical Instance Segment (0x%02X)", segment_type );

               /* Create a sub tree for the instance */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 2, 2, "Instance: 0x%04X", temp_data );
               proto_item_append_text(pi, ", Inst: 0x%04X", temp_data );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 5, "32-Bit Logical Instance Segment (0x%02X)", segment_type );

               /* Create a sub tree for the instance */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 2, 4, "Instance: 0x%08X", temp_data );
               proto_item_append_text(pi, ", Inst: 0x%08X", temp_data );

               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Logical Segment Format" );
               return;
            }
            break;


         case CI_LOGICAL_SEG_ATTR_ID:

            /* Logical Attribute ID, do a format check */

   		   if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
   		   {
   		      temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Attribute Segment (0x%02X)", segment_type );

               /* Create a sub tree for the attribute */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 8-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 1, 1, "Attribute: 0x%02X", temp_data );
               proto_item_append_text(pi, ", Att: 0x%02X", temp_data );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 3, "16-Bit Logical Attribute Segment (0x%02X)", segment_type );

               /* Create a sub tree for the attribute */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 2, 2, "Attribute: 0x%04X", temp_data );
               proto_item_append_text(pi, ", Att: 0x%04X", temp_data );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 5, "32-Bit Logical Attribute Segment (0x%02X)", segment_type );

               /* Create a sub tree for the attribute */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 2, 4, "Attribute: 0x%08X", temp_data );
               proto_item_append_text(pi, ", Att: 0x%08X", temp_data );

               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Logical Segment Format" );
               return;
            }
            break;


         case CI_LOGICAL_SEG_CON_POINT:

            /* Logical Connection point , do a format check */

   		   if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
   		   {
   		      temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Connection Point Segment (0x%02X)", segment_type );

               /* Create a sub tree for the connection point */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 8-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 1, 1, "Connection Point: 0x%02X", temp_data );
               proto_item_append_text(pi, ", ConPnt: 0x%02X", temp_data );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 3, "16-Bit Logical Connection Point Segment (0x%02X)", segment_type );

               /* Create a sub tree for the connection point */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 2, 2, "Connection Point: 0x%04X", temp_data );
               proto_item_append_text(pi, ", ConPnt: 0x%04X", temp_data );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 5, "32-Bit Logical Connection Point Segment (0x%02X)", segment_type );

               /* Create a sub tree for the connection point */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit instance number */
               proto_tree_add_text( cia_tree, tvb, offset + pathpos + 2, 4, "Connection Point (0x%08X)", temp_data );
               proto_item_append_text(pi, ", ConPnt: 0x%08X", temp_data );

               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Logical Segment Format" );
               return;
            }
            break;


         case CI_LOGICAL_SEG_SPECIAL:

            /* Logical Special ID, the only logical format sepcifyed is electronic key */

            if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_E_KEY )
            {

               /* Get the Key Format */

               temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );

               if( temp_data == CI_E_KEY_FORMAT_VAL )
               {
                  qi = proto_tree_add_text( path_tree, tvb, offset + pathpos, 10, "Electronic Key Segment (0x%02X): ",segment_type );

                  /* Create a sub tree for the IOI */
                  e_key_tree = proto_item_add_subtree( qi, ett_ekey_path );

                  /* Print the key type */
                  proto_tree_add_text( e_key_tree, tvb, offset + pathpos + 1, 1, "Key Format: 0x%02X", temp_data );

                  /* Get the Vendor ID */
      		      temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
                  proto_tree_add_item( e_key_tree, hf_enip_vendors, tvb, offset + pathpos + 2, 2, TRUE);
                  proto_item_append_text( qi, "VendorID: 0x%04X", temp_data );

                  /* Get Device Type */
   		         temp_data = tvb_get_letohs( tvb, offset + pathpos + 4 );
   		         proto_tree_add_item( e_key_tree, hf_enip_cpf_lir_devtype, tvb, offset + pathpos + 4, 2, TRUE);
                  proto_item_append_text( qi, ", DevTyp: 0x%04X", temp_data );

                  /* Product Code */
   		         temp_data = tvb_get_letohs( tvb, offset + pathpos + 6 );
                  proto_tree_add_text( e_key_tree, tvb, offset + pathpos + 6, 2, "Product Code: 0x%04X", temp_data );

                  /* Major revision/Compatibility */
   		         temp_data = tvb_get_guint8( tvb, offset + pathpos + 8 );

   					/* Add Major revision/Compatibility tree */
   					mcpi = proto_tree_add_text(e_key_tree, tvb, offset + pathpos + 8, 1, "Compatibility ");
   					mc_tree = proto_item_add_subtree(mcpi, ett_mcsc);

   					/* Add Compatibility bit info */
                  proto_tree_add_item(mc_tree, hf_enip_ucm_fwo_comp,
   							tvb, offset + pathpos + 8, 1, TRUE );

                  proto_item_append_text( mcpi, "%s, Major Revision: %d",
                              val_to_str( ( temp_data & 0x80 )>>7, enip_com_bit_vals , "" ),
                              temp_data & 0x7F );

   					/* Major revision */
   					proto_tree_add_item(mc_tree, hf_enip_ucm_fwo_mrev,
   							tvb, offset + pathpos + 8, 1, TRUE );

                  /* Minor revision */
                  temp_data2 = tvb_get_guint8( tvb, offset + pathpos + 9 );
                  proto_tree_add_text( e_key_tree, tvb, offset + pathpos + 9, 1, "Minor Revision: %d", temp_data2 );

                  proto_item_append_text( qi, ", V.%d.%d", ( temp_data & 0x7F ), temp_data2 );

                  /* Increment the path pointer */
                  pathpos += 10;

               }
               else
               {
                  /* Unsupported electronic key format */
                  proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Electronic Key Format" );
                  return;
               }

            }
            else
            {
               /* Unsupported special segment format */
               proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Special Segment Format" );
               return;
            }
            break;


         default:

            /* Unsupported logical segment type */
            proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Logical Segment Type" );
            return;

         } /* end of switch( segment_type & CI_LOGICAL_SEG_TYPE_MASK ) */
         break;


      case CI_DATA_SEGMENT:

         /* Data segment, determin the logical type */

         switch( segment_type )
         {

            case CI_DATA_SEG_SIMPLE:

               /* Simple data segment */
               ds_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 1, "Simple Data Segment (0x%02X)", segment_type );

               /* Create a sub tree */
               ds_tree = proto_item_add_subtree( ds_item, ett_data_seg );

               /* Segment size */
               seg_size = tvb_get_guint8( tvb, offset + pathpos+1 )*2;
               proto_tree_add_text( ds_tree, tvb, offset + pathpos+1, 1, "Data Size: %d (words)", seg_size/2 );

               /* Segment data  */
               if( seg_size != 0 )
               {
                  qi = proto_tree_add_text( ds_tree, tvb, offset + pathpos+2, 0, "Data: " );

                  for( i=0; i < seg_size/2; i ++ )
                  {
                    temp_word = tvb_get_letohs( tvb, offset + pathpos+2+(i*2) );
                    proto_item_append_text(qi, " 0x%04X", temp_word );
                  }

                  proto_item_set_len(qi, seg_size);
               }

               proto_item_set_len( ds_item, 2 + seg_size );
               pathpos = pathpos + 2 + seg_size;

               break;

            case CI_DATA_SEG_SYMBOL:

               /* ANSI extended symbol segment */
               ds_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 1, "Extended Symbol Segment (0x%02X)", segment_type );

               /* Create a sub tree */
               ds_tree = proto_item_add_subtree( ds_item, ett_data_seg );

               /* Segment size */
               seg_size = tvb_get_guint8( tvb, offset + pathpos+1 );
               proto_tree_add_text( ds_tree, tvb, offset + pathpos+1, 1, "Data Size: %d", seg_size );

               /* Segment data  */
               if( seg_size != 0 )
               {
                  qi = proto_tree_add_text( ds_tree, tvb, offset + pathpos+2, 0, "Data: " );

                  for( i=0; i < seg_size; i++ )
                  {
                    temp_byte = tvb_get_guint8( tvb, offset + pathpos+2+i );
                    proto_item_append_text(qi, "%c", temp_byte );
                  }

                  proto_item_set_len(qi, seg_size);

                  if( seg_size %2 )
                  {
                     /* We have a PAD BYTE */
                     proto_tree_add_text( ds_tree, tvb, offset + pathpos+2+i, 1, "Pad Byte (0x%02X)",
                         tvb_get_guint8( tvb, offset + pathpos+2+i ) );
                     pathpos++;
                     seg_size++;
                  }
               }

               proto_item_set_len( ds_item, 2 + seg_size );
               pathpos = pathpos + 2 + seg_size;

               break;

            default:
               proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Sub-Segment Type" );
               return;

            } /* End of switch sub-type */

            break;

      default:

         /* Unsupported segment type */
         proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Segment Type" );
         return;

      } /* end of switch( segment_type & CI_SEGMENT_TYPE_MASK ) */

   } /* end of while( pathpos < path_length ) */

} /* end of show_epath() */



static void
add_cip_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length )
{
   proto_item *pi, *rrsci, *ncppi, *ar_item, *temp_item, *temp_item2;
	proto_tree *temp_tree;
   proto_tree *rrsci_tree;
   proto_tree *ncp_tree;
   proto_tree *cmd_data_tree;
	int req_path_size, conn_path_size, mr_req_path_size;
	int temp_data;
	unsigned char gen_stat;
   unsigned char add_stat_size;
   unsigned char temp_byte, route_path_size;
   unsigned char app_rep_size, i;
   int msg_req_siz, num_services, serv_offset;


   /* Add Service code & Request/Response tree */
	rrsci = proto_tree_add_text(item_tree, tvb, offset, 1, "Service: ");
	rrsci_tree = proto_item_add_subtree(rrsci, ett_rrsc);

	/* Add Request/Response */
   proto_tree_add_item(rrsci_tree, hf_enip_ucm_rr,
			tvb, offset, 1, TRUE );

   proto_item_append_text( rrsci, "%s (%s)",
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                  encap_sc_vals , "Unknown Service Code (%x)"),
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x80 )>>7,
                  encap_sc_rr, "") );

	/* Add Service code */
	proto_tree_add_item(rrsci_tree, hf_enip_ucm_sc,
			tvb, offset, 1, TRUE );


	if( tvb_get_guint8( tvb, offset ) & 0x80 )
	{
	   /* Response message */

		/* Add general status */
		gen_stat = tvb_get_guint8( tvb, offset+2 );

		proto_tree_add_item(item_tree, hf_enip_ucm_genstat,
			tvb, offset+2, 1, TRUE );

      /* Add additional status size */
      temp_data = tvb_get_guint8( tvb, offset+3 );
      proto_tree_add_text( item_tree, tvb, offset+3, 1, "Additional Status Size: %d (word)", temp_data );

		add_stat_size = tvb_get_guint8( tvb, offset+3 )*2;

		if( add_stat_size )
		{
         /* Add additional status */
         pi = proto_tree_add_text( item_tree, tvb, offset+4, add_stat_size, "Additional Status:" );

         for( i=0; i < add_stat_size/2; i ++ )
         {
           proto_item_append_text( pi, " 0x%04X", tvb_get_letohs( tvb, offset+4+(i*2) ) );
         }
		}

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cmd_data );

		   if( gen_stat == CI_GRC_SUCCESS )
   		{
   			/* Success responses */

   			if( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_FWD_OPEN )
            {
               /* Forward open Response (Success) */

               /* Display originator to target connection ID */
               temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 4, "O->T Network Connection ID: 0x%08X", temp_data );

               /* Display target to originator connection ID */
               temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size+4 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+4, 4, "T->O Network Connection ID: 0x%08X", temp_data );

               /* Display connection serial number */
               temp_data = tvb_get_letohs( tvb, offset+4+add_stat_size+8 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+8, 2, "Connection Serial Number: 0x%04X", temp_data );

               /* Display the originator vendor id */
               proto_tree_add_item( cmd_data_tree, hf_enip_vendors, tvb, offset+4+add_stat_size+10, 2, TRUE);

               /* Display the originator serial number */
               temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size+12 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+12, 4, "Originator Serial Number: 0x%08X", temp_data );

               /* Display originator to target actual packet interval */
               temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size+16 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+16, 4, "O->T API: %dms (0x%08X)", temp_data / 1000, temp_data );

               /* Display originator to target actual packet interval */
               temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size+20 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+20, 4, "T->O API: %dms (0x%08X)", temp_data / 1000, temp_data );

               /* Display the application reply size */
               app_rep_size = tvb_get_guint8( tvb, offset+4+add_stat_size+24 ) * 2;
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+24, 1, "Application Reply Size: %d (words)", app_rep_size / 2 );

               /* Display the Reserved byte */
               temp_byte = tvb_get_guint8( tvb, offset+4+add_stat_size+25 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+25, 1, "Reserved: 0x%02X", temp_byte );

               if( app_rep_size != 0 )
               {
                  /* Display application Reply data */
                  ar_item = proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+26, app_rep_size, "Application Reply:" );

                  for( i=0; i < app_rep_size; i++ )
                  {
                    temp_byte = tvb_get_guint8( tvb, offset+4+add_stat_size+26+i );
                    proto_item_append_text(ar_item, " 0x%02X", temp_byte );
                  }

                } /* End of if reply data */

            } /* End of if forward open response */
   			else if( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_FWD_CLOSE )
            {
               /* Forward close response (Success) */

               /* Display connection serial number */
               temp_data = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 2, "Connection Serial Number: 0x%04X", temp_data );

               /* Display the originator vendor id */
               proto_tree_add_item( cmd_data_tree, hf_enip_vendors, tvb, offset+4+add_stat_size+2, 2, TRUE);

               /* Display the originator serial number */
               temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size+4 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+4, 4, "Originator Serial Number: 0x%08X", temp_data );

               /* Display the application reply size */
               app_rep_size = tvb_get_guint8( tvb, offset+4+add_stat_size+8 ) * 2;
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+8, 1, "Application Reply Size: %d (words)", app_rep_size / 2 );

               /* Display the Reserved byte */
               temp_byte = tvb_get_guint8( tvb, offset+4+add_stat_size+9 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+9, 1, "Reserved: 0x%02X", temp_byte );

               if( app_rep_size != 0 )
               {
                  /* Display application Reply data */
                  ar_item = proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+10, app_rep_size, "Application Reply:" );

                  for( i=0; i < app_rep_size; i ++ )
                  {
                    temp_byte = tvb_get_guint8( tvb, offset+4+add_stat_size+10+i );
                    proto_item_append_text(ar_item, " 0x%02X", temp_byte );
                  }

                } /* End of if reply data */

            } /* End of if forward close response */
            else if( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_UNCON_SEND )
            {
               /* Unconnected send response (Success) */

               /* Display service response data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
            }
            else if( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_MULT_SERV_PACK )
            {
               /* Multiple Service Reply (Success)*/

               /* Add number of replies */
               num_services = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 2, "Number of Replies: %d", num_services );

               /* Add replies */
               temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+add_stat_size+4, num_services*2, "Offsets: " );

               for( i=0; i < num_services; i++ )
               {
                  int serv_length;

                  serv_offset = tvb_get_letohs( tvb, offset+6+add_stat_size+(i*2) );

                  if( i == (num_services-1) )
                  {
                     /* Last service to add */
                     proto_item_append_text(temp_item, "%d", serv_offset );
                     serv_length = item_length-add_stat_size-serv_offset-4;
                  }
                  else
                  {
                     proto_item_append_text(temp_item, "%d, ", serv_offset );
                     serv_length = tvb_get_letohs( tvb, offset+6+add_stat_size+((i+1)*2) ) - serv_offset;
                  }

                  temp_item2 = proto_tree_add_text( cmd_data_tree, tvb, offset+serv_offset+4, serv_length, "Service Reply #%d", i+1 );
                  temp_tree = proto_item_add_subtree( temp_item2, ett_mult_ser );
                  add_cip_data( temp_tree, tvb, offset+serv_offset+4, serv_length );
               }
            } /* End if Multiple service Packet */
            else if( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_GET_ATT_LIST )
            {
               /* Get Attribute List Reply (Success)*/

               int att_count;

               /* Add Attribute Count */
               att_count = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 2, "Attribute Count: %d", att_count );

               /* Add the data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+6+add_stat_size, item_length-6-add_stat_size, "Data: " );

            } /* End if Multiple service Packet */
            else
   			{
   			   /* Add data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
   		   } /* end of check service code */

   	   }
         else
         {
            /* Error responses */

            if( ( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_FWD_OPEN ) ||
                ( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_FWD_CLOSE ) )
            {
               /* Forward open and forward close error response look the same */

               /* Display connection serial number */
               temp_data = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 2, "Connection Serial Number: 0x%04X", temp_data );

               /* Display the originator vendor id */
               proto_tree_add_item( cmd_data_tree, hf_enip_vendors, tvb, offset+4+add_stat_size+2, 2, TRUE);

               /* Display the originator serial number */
               temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size+4 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+4, 4, "Originator Serial Number: 0x%08X", temp_data );

               /* Display remaining path size */
               temp_data = tvb_get_guint8( tvb, offset+4+add_stat_size+8 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+8, 1, "Remaining Path Size: %d", temp_data );

               /* Display reserved data */
               temp_data = tvb_get_guint8( tvb, offset+4+add_stat_size+9 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+9, 1, "Reserved: 0x%02X", temp_data );
            }
            else if( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_UNCON_SEND )
            {
               /* Unconnected send response (Unsuccess) */

               /* Display remaining path size */
               temp_data = tvb_get_guint8( tvb, offset+4+add_stat_size);
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 1, "Remaining Path Size: %d", temp_data );
            }
            else
            {
               /* Add data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
            }

         } /* end of if-else( CI_CRC_SUCCESS ) */

      } /* End of if command-specific data present */

	} /* End of if reply */
	else
	{
	   /* Request */

	   /* Add path size */
	   req_path_size = tvb_get_guint8( tvb, offset+1 )*2;
	   proto_tree_add_text( item_tree, tvb, offset+1, 1, "Request Path Size: %d (words)", req_path_size/2 );

      /* Add the epath */
      pi = proto_tree_add_text(item_tree, tvb, offset+2, req_path_size, "Request Path: ");
      show_epath( tvb, pi, offset+2, req_path_size );

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {

         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cmd_data );

         /* Check what service code that recived */

         if( tvb_get_guint8( tvb, offset ) == SC_FWD_OPEN )
         {
            /* Forward open Request*/

            /* Display the priority/tick timer */
            temp_byte = tvb_get_guint8( tvb, offset+2+req_path_size );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 1, "Priority/Time_tick: 0x%02X", temp_byte );

            /* Display the time-out ticks */
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+1 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+1, 1, "Time-out_ticks: %d", temp_data );

            /* Display the actual time out */
            temp_data = ( 1 << ( temp_byte & 0x0F ) ) * temp_data;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 2, "Actual Time Out: %dms", temp_data );

            /* Display originator to taget connection ID */
            temp_data = tvb_get_letohl( tvb, offset+2+req_path_size+2 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, 4, "O->T Network Connection ID: 0x%08X", temp_data );

            /* Display target to originator connection ID */
            temp_data = tvb_get_letohl( tvb, offset+2+req_path_size+6 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+6, 4, "T->O Network Connection ID: 0x%08X", temp_data );

            /* Display connection serial number */
            temp_data = tvb_get_letohs( tvb, offset+2+req_path_size+10 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+10, 2, "Connection Serial Number: 0x%04X", temp_data );

            /* Display the originator vendor id */
            proto_tree_add_item( cmd_data_tree, hf_enip_vendors, tvb, offset+2+req_path_size+12, 2, TRUE);

            /* Display the originator serial number */
            temp_data = tvb_get_letohl( tvb, offset+2+req_path_size+14 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+14, 4, "Originator Serial Number: 0x%08X", temp_data );

            /* Display the timeout multiplier */
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+18 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+18, 1, "Connection Timeout Multiplier: %s (%d)", val_to_str( temp_data, enip_con_time_mult_vals , "Reserved" ), temp_data );

            /* Put out an indicator for the reserved bytes */
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+19, 3, "Reserved Data" );

            /* Display originator to target requested packet interval */
            temp_data = tvb_get_letohl( tvb, offset+2+req_path_size+22 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+22, 4, "O->T RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

   	      /* Display originator to target network connection patameterts, in a tree */
   	      temp_data = tvb_get_letohs( tvb, offset+2+req_path_size+26 );
   	      ncppi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+26, 2, "O->T Network Connection Parameters: 0x%04X", temp_data );
   	      ncp_tree = proto_item_add_subtree(ncppi, ett_ncp);

            /* Add the data to the tree */
            proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_own,
   					tvb, offset+2+req_path_size+26, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_typ,
   					tvb, offset+2+req_path_size+26, 2, TRUE );
            proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_prio,
   					tvb, offset+2+req_path_size+26, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_fixed_var,
   					tvb, offset+2+req_path_size+26, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_con_size,
   					tvb, offset+2+req_path_size+26, 2, TRUE );

            /* Display target to originator requested packet interval */
            temp_data = tvb_get_letohl( tvb, offset+2+req_path_size+28 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+28, 4, "T->O RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

   	      /* Display target to originator network connection patameterts, in a tree */
   	      temp_data = tvb_get_letohs( tvb, offset+2+req_path_size+32 );
   	      ncppi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+32, 2, "T->O Network Connection Parameters: 0x%04X", temp_data );
   	      ncp_tree = proto_item_add_subtree(ncppi, ett_ncp);

            /* Add the data to the tree */
            proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_own,
   					tvb, offset+2+req_path_size+32, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_typ,
   					tvb, offset+2+req_path_size+32, 2, TRUE );
            proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_prio,
   					tvb, offset+2+req_path_size+32, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_fixed_var,
   					tvb, offset+2+req_path_size+32, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_enip_ucm_fwo_con_size,
   					tvb, offset+2+req_path_size+32, 2, TRUE );

            /* Transport type/trigger */
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+34 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+6+req_path_size+34, 1, "Transport Type/Trigger: 0x%02X", temp_data );

            /* Add path size */
            conn_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+35 )*2;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+35, 1, "Connection Path Size: %d (words)", conn_path_size / 2 );

            /* Add the epath */
            pi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+36, conn_path_size, "Connection Path: ");
            show_epath( tvb, pi, offset+2+req_path_size+36, conn_path_size );
         }
         else if( tvb_get_guint8( tvb, offset ) == SC_FWD_CLOSE )
         {
            /* Forward Close Request */

            /* Display the priority/tick timer */
            temp_byte = tvb_get_guint8( tvb, offset+2+req_path_size );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 1, "Priority/Time_tick: 0x%02X", temp_byte );

            /* Display the time-out ticks */
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+1 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+1, 1, "Time-out_ticks: %d", temp_data );

            /* Display connection serial number */
            temp_data = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, 2, "Connection Serial Number: 0x%04X", temp_data );

            /* Display the originator vendor id */
            proto_tree_add_item( cmd_data_tree, hf_enip_vendors, tvb, offset+2+req_path_size+4, 2, TRUE);

            /* Display the originator serial number */
            temp_data = tvb_get_letohl( tvb, offset+2+req_path_size+6 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+6, 4, "Originator Serial Number: 0x%08X", temp_data );

            /* Add the path size */
            conn_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+10 )*2;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+10, 1, "Connection Path Size: %d (words)", conn_path_size / 2 );

            /* Add the reserved byte */
            temp_byte = tvb_get_guint8( tvb, offset+2+req_path_size+11 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+11, 1, "Reserved: 0x%02X", temp_byte );

            /* Add the EPATH */
            pi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+12, conn_path_size, "Connection Path: ");
            show_epath( tvb, pi, offset+2+req_path_size+12, conn_path_size );

         } /* End of forward close */
         else if( tvb_get_guint8( tvb, offset ) == SC_UNCON_SEND )
         {
            /* Unconnected send */

            /* Display the priority/tick timer */
            temp_byte = tvb_get_guint8( tvb, offset+2+req_path_size );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 1, "Priority/Time_tick: 0x%02X", temp_byte );

            /* Display the time-out ticks */
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+1 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+1, 1, "Time-out_ticks: %d", temp_data );

            /* Message request size */
            msg_req_siz = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, 2, "Message Request Size: 0x%04X", msg_req_siz );

            /* Message Request */
            temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+4, msg_req_siz, "Message Request" );
            temp_tree = proto_item_add_subtree(temp_item, ett_mes_req );

            /* MR - Service */
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+4 );
            proto_tree_add_text( temp_tree, tvb, offset+2+req_path_size+4, 1, "Service: %s (0x%02X)", val_to_str( temp_data, encap_sc_vals , "" ), temp_data );

            /* MR - Request path Size */
   		   mr_req_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+5 )*2;
   		   proto_tree_add_text( temp_tree, tvb, offset+2+req_path_size+5, 1, "Request Path Size: %d (words)", mr_req_path_size/2 );

            /* MR - EPATH */
            temp_item = proto_tree_add_text(temp_tree, tvb, offset+2+req_path_size+6, mr_req_path_size, "Request Path: ");
            show_epath( tvb, temp_item, offset+2+req_path_size+6, mr_req_path_size );

            /* MR - Request data */
            if( ( msg_req_siz-2-mr_req_path_size ) != 0 )
            {
               add_byte_array_text_to_proto_tree( temp_tree, tvb, offset+2+req_path_size+6+mr_req_path_size, msg_req_siz-2-mr_req_path_size, "Request Data: " );
            }

            if( msg_req_siz % 2 )
            {
               /* Pad byte */
               proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+4+msg_req_siz, 1, "Pad Byte (0x%02X)",
                  tvb_get_guint8( tvb, offset+2+req_path_size+4+msg_req_siz ) );
               msg_req_siz++;	/* include the padding */
            }

            /* Route Path Size */
            route_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+4+msg_req_siz )*2;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+4+msg_req_siz, 1, "Route Path Size: %d (words)", route_path_size/2 );

            /* Reserved */
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+5+msg_req_siz, 1, "Reserved (0x%02X)",
                tvb_get_guint8( tvb, offset+2+req_path_size+5+msg_req_siz ) );

            /* Route Path */
            temp_item = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+6+msg_req_siz, route_path_size, "Route Path");
            show_epath( tvb, temp_item, offset+2+req_path_size+6+msg_req_siz, route_path_size );

         } /* End if unconnected send */
         else if( tvb_get_guint8( tvb, offset ) == SC_MULT_SERV_PACK )
         {
            /* Multiple service packet */

            /* Add number of services */
            num_services = tvb_get_letohs( tvb, offset+2+req_path_size );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 2, "Number of Services: %d", num_services );

            /* Add services */
            temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, num_services*2, "Offsets: " );

            for( i=0; i < num_services; i++ )
            {
               int serv_length;

               serv_offset = tvb_get_letohs( tvb, offset+4+req_path_size+(i*2) );

               if( i == (num_services-1) )
               {
                  /* Last service to add */
                  serv_length = item_length-2-req_path_size-serv_offset;
                  proto_item_append_text(temp_item, "%d", serv_offset );
               }
               else
               {
                  serv_length = tvb_get_letohs( tvb, offset+4+req_path_size+((i+1)*2) ) - serv_offset;
                  proto_item_append_text(temp_item, "%d, ", serv_offset );
               }

               temp_item2 = proto_tree_add_text( cmd_data_tree, tvb, offset+serv_offset+6, serv_length, "Service Packet #%d", i+1 );
               temp_tree = proto_item_add_subtree( temp_item2, ett_mult_ser );
               add_cip_data( temp_tree, tvb, offset+serv_offset+6, serv_length );
            }
         } /* End if Multiple service Packet */
         else if( tvb_get_guint8( tvb, offset ) == SC_GET_ATT_LIST )
         {
            /* Get attribute list request */

            int att_count;

            /* Add number of services */
            att_count = tvb_get_letohs( tvb, offset+2+req_path_size );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 2, "Attribute Count: %d", att_count );

            /* Add Attribute List */
            temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, att_count*2, "Attribute List: " );

            for( i=0; i < att_count; i++ )
            {
               if( i == (att_count-1) )
                  proto_item_append_text(temp_item, "%d",tvb_get_letohs( tvb, offset+4+req_path_size+(i*2) ) );
               else
                  proto_item_append_text(temp_item, "%d, ",tvb_get_letohs( tvb, offset+4+req_path_size+(i*2) ) );
            }

         } /* End of Get attribute list request */
         else
         {
		      /* Add data */
            add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Data: " );
         } /* End of check service code */

      } /* End of if command-specific data present */

	} /* end of if-else( request ) */

} /* end of add_cip_data() */



static void
show_cdf( int encap_service, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset )
{
   proto_item *temp_item, *ri, *ci;
   proto_item *sockaddr_item;
	proto_tree *temp_tree, *cip_tree, *item_tree, *sockaddr_tree;
	int temp_data, item_count, item_length, item, i;
	char temp_char;
	unsigned char name_length;

	/* Show Common Data Format sub tree */
	item_count = tvb_get_letohs( tvb, offset );
   ri = proto_tree_add_text( tree, tvb, offset, 2, "Item Count: %d", item_count );
	cip_tree = proto_item_add_subtree(ri, ett_cip);

	while( item_count-- )
	{
		/* Add item type tree */
		ci = proto_tree_add_item(cip_tree, hf_enip_cpf_typeid, tvb, offset+2, 2, TRUE );
		item_tree = proto_item_add_subtree(ci, ett_cpf);

		/* Add length field */
      temp_data = tvb_get_letohs( tvb, offset+4 );
      proto_tree_add_text( item_tree, tvb, offset+4, 2, "Length: %d", temp_data );

		item        = tvb_get_letohs( tvb, offset+2 );
		item_length = tvb_get_letohs( tvb, offset+4 );

		if( item_length )
		{
		   /* Add item data field */

			switch( item )
			{
			   case CONNECTION_BASED:

			      /* Add Connection identifier */
			      proto_tree_add_text( item_tree, tvb, offset+6, 4, "Connection Identifier: 0x%04X", tvb_get_letohl( tvb, offset + 6 )  );
			      break;

			   case UNCONNECTED_MSG:

					/* Add CIP data tree*/
					add_cip_data( item_tree, tvb, offset+6, item_length );

					break;

            case CONNECTION_TRANSPORT:

               if( encap_service == SEND_UNIT_DATA )
               {
                  /*
                  ** If the encapsulation service is SendUnit Data, this is a
                  ** encapsulated connected message
                  */

                  /* Add sequence count ( Transport Class 1,2,3 )*/
                  proto_tree_add_text( item_tree, tvb, offset+6, 2, "Sequence Count: 0x%04X", tvb_get_letohs( tvb, offset+6 ) );

                  /* Add CIP data tree */
                  add_cip_data( item_tree, tvb, offset+8, item_length-2 );
               }
               else
               {
                  /* Display data */
                  add_byte_array_text_to_proto_tree( item_tree, tvb, offset+6, item_length, "Data: " );

               } /* End of if send unit data */

               break;


            case LIST_IDENTITY_RESP:

               /* Encapsulation version */
               temp_data = tvb_get_letohs( tvb, offset+6 );
               proto_tree_add_text( item_tree, tvb, offset+6, 2, "Encapsulation Version: %d", temp_data );

               /* Socket Address */
               sockaddr_item = proto_tree_add_text( item_tree, tvb, offset+8, 16, "Socket Address");
               sockaddr_tree = proto_item_add_subtree( sockaddr_item, ett_sockadd );

               /* Socket address struct - sin_family */
               proto_tree_add_item(sockaddr_tree, hf_enip_cpf_lir_sinfamily,
							tvb, offset+8, 2, FALSE );

               /* Socket address struct - sin_port */
               proto_tree_add_item(sockaddr_tree, hf_enip_cpf_lir_sinport,
							tvb, offset+10, 2, FALSE );

               /* Socket address struct - sin_address */
               proto_tree_add_item(sockaddr_tree, hf_enip_cpf_lir_sinaddr,
							tvb, offset+12, 4, FALSE );

               /* Socket address struct - sin_zero */
               proto_tree_add_item(sockaddr_tree, hf_enip_cpf_lir_sinzero,
							tvb, offset+16, 8, FALSE );

               /* Vendor ID */
               proto_tree_add_item(item_tree, hf_enip_vendors,
							tvb, offset+24, 2, TRUE );

               /* Device Type */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_devtype,
							tvb, offset+26, 2, TRUE );

               /* Product Code */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_prodcode,
							tvb, offset+28, 2, TRUE );

               /* Revision */
               temp_data = tvb_get_letohs( tvb, offset+30 );
               proto_tree_add_text( item_tree, tvb, offset+30, 2, "Revision: v.%d.%02d", temp_data & 0xFF, ( temp_data & 0xFF00 ) >> 8 );

               /* Status */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_status,
							tvb, offset+32, 2, TRUE );

               /* Serial Number */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_sernbr,
							tvb, offset+34, 4, TRUE );

               /* Product Name Length */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_namelength,
							tvb, offset+38, 1, TRUE );

               /* Get the lenth of the name */
               name_length = tvb_get_guint8( tvb, offset+38 );

               /* Product Name Length */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_name,
							tvb, offset+39, name_length, TRUE );

               /* Product Name Length */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_state,
							tvb, offset+name_length+39, 1, TRUE );
               break;


            case SOCK_ADR_INFO_OT:
            case SOCK_ADR_INFO_TO:

               /* Socket address struct - sin_family */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_sinfamily,
							tvb, offset+6, 2, FALSE );

               /* Socket address struct - sin_port */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_sinport,
							tvb, offset+8, 2, FALSE );

               /* Socket address struct - sin_address */
               proto_tree_add_item(item_tree, hf_enip_cpf_lir_sinaddr,
							tvb, offset+10, 4, FALSE );

               /* Socket address struct - sin_zero */
               proto_tree_add_item( item_tree, hf_enip_cpf_lir_sinzero,
							tvb, offset+14, 8, FALSE );
				   break;


            case SEQ_ADDRESS:
               proto_tree_add_item(item_tree, hf_enip_cpf_sat_connid,
							tvb, offset+6, 4, TRUE );

               proto_tree_add_item(item_tree, hf_enip_cpf_sat_seqnum,
							tvb, offset+10, 4, TRUE );

               /* Add info to column */

               if(check_col(pinfo->cinfo, COL_INFO))
	            {
	               col_clear(pinfo->cinfo, COL_INFO);

                  col_add_fstr(pinfo->cinfo, COL_INFO,
				         "Connection: ID=0x%08X, SEQ=%010d",
				         tvb_get_letohl( tvb, offset+6 ),
				         tvb_get_letohl( tvb, offset+10 ) );
				   }

				   break;

            case LIST_SERVICES_RESP:

               /* Encapsulation version */
               temp_data = tvb_get_letohs( tvb, offset+6 );
               proto_tree_add_text( item_tree, tvb, offset+6, 2, "Encapsulation Version: %d", temp_data );

               /* Capability flags */
               temp_data = tvb_get_letohs( tvb, offset+8 );
               temp_item = proto_tree_add_text(item_tree, tvb, offset+8, 2, "Capability Flags: 0x%04X", temp_data );
               temp_tree = proto_item_add_subtree(temp_item, ett_lsrcf);

               proto_tree_add_item(temp_tree, hf_enip_cpf_lsr_tcp,
                  tvb, offset+8, 2, TRUE );
      		   proto_tree_add_item(temp_tree, hf_enip_cpf_lsr_udp,
      			   tvb, offset+8, 2, TRUE );

               /* Name of service */
               temp_item = proto_tree_add_text( item_tree, tvb, offset+10, 16, "Name Of Service: " );

               for( i=0; i<16; i++ )
               {
                    temp_char = tvb_get_guint8( tvb, offset+10+i );

                    if( temp_char == 0 )
                     break;

                    proto_item_append_text(temp_item, "%c", temp_char );
               }
               break;


				default:

               add_byte_array_text_to_proto_tree( item_tree, tvb, offset+6, item_length, "Data: " );
               break;

			} /* end of switch( item type ) */

		} /* end of if( item length ) */

		offset = offset + item_length + 4;

	} /* end of while( item count ) */

} /* end of show_cdf() */



static int
classify_packet(packet_info *pinfo)
{
	/* see if nature of packets can be derived from src/dst ports */
	/* if so, return as found */
	if ( ( ENIP_ENCAP_PORT == pinfo->srcport && ENIP_ENCAP_PORT != pinfo->destport ) ||
		 ( ENIP_ENCAP_PORT != pinfo->srcport && ENIP_ENCAP_PORT == pinfo->destport ) ) {
		if ( ENIP_ENCAP_PORT == pinfo->srcport )
			return RESPONSE_PACKET;
		else if ( ENIP_ENCAP_PORT == pinfo->destport )
			return REQUEST_PACKET;
	}
	/* else, cannot classify */
	return CANNOT_CLASSIFY;
}



/* Code to actually dissect the packets */
static int
dissect_cipencap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   int	    packet_type;
   guint16  encap_cmd, encap_data_length;
   gchar    *cmd_string;
   char     pkt_type_str[9] = "";
   guint32  status;

   /* Set up structures needed to add the protocol subtree and manage it */
   proto_item *ti, *encaph, *csf;
   proto_tree *cipencap_tree, *headertree, *csftree;

   /* An ENIP packet is at least 4 bytes long - we need the command type. */
   if (!tvb_bytes_exist(tvb, 0, 4))
      return 0;

   /* Get the command type and see if it's valid. */
   encap_cmd = tvb_get_letohs( tvb, 0 );
   cmd_string = match_strval(encap_cmd, encap_cmd_vals);
   if (cmd_string == NULL)
      return 0;	/* not a known command */

   /* Make entries in Protocol column and Info column on summary display */
   if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENIP");

   if(check_col(pinfo->cinfo, COL_INFO))
   {
      packet_type = classify_packet(pinfo);

      switch ( packet_type )
      {
         case REQUEST_PACKET:
            strcpy(pkt_type_str, "Request");
            break;

         case RESPONSE_PACKET:
            strcpy(pkt_type_str, "Response");
            break;

         default:
            strcpy(pkt_type_str, "Unknown");
      }

      col_add_fstr(pinfo->cinfo, COL_INFO,
                   "%s: %s, Session=0x%08X",
		   pkt_type_str, cmd_string, tvb_get_letohl( tvb, 4 ) );
   } /* end of if( col exists ) */

   /* In the interest of speed, if "tree" is NULL, don't do any work not
      necessary to generate protocol tree items. */
   if (tree) {

      /* create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cipencap, tvb, 0, -1, FALSE);

      cipencap_tree = proto_item_add_subtree(ti, ett_cipencap);

      /* Add encapsulation header tree */
      encaph     = proto_tree_add_text( cipencap_tree, tvb, 0, 24, "Encapsulation Header");
      headertree = proto_item_add_subtree(encaph, ett_cipencaph);

      /* CIP header information */
      proto_tree_add_uint(headertree, hf_enip_command, tvb, 0, 2, encap_cmd);

      encap_data_length = tvb_get_letohs( tvb, 2 );
      proto_tree_add_text( headertree, tvb, 2, 2, "Length: %u", encap_data_length );

      proto_tree_add_text( headertree, tvb, 4, 4, "Session Handle: 0x%08X",
                          tvb_get_letohl( tvb, 4 ) );

      status = tvb_get_letohl( tvb, 8 );
      proto_tree_add_text( headertree, tvb, 8, 4, "Status: %s (0x%08X)",
                          val_to_str( status, encap_status_vals,
                                     "Unknown Status Code" ),
                          status);

      add_byte_array_text_to_proto_tree( headertree, tvb, 12, 8, "Sender context: " );

      proto_tree_add_text( headertree, tvb, 20, 4, "Options: 0x%08X",
                          tvb_get_letohl( tvb, 20 ) );

      /* Command specific data - create tree */
      if( encap_data_length )
      {
         /* The packet have some command specific data, buid a sub tree for it */

         csf = proto_tree_add_text( cipencap_tree, tvb, 24, encap_data_length,
                                   "Command Specific Data");

         csftree = proto_item_add_subtree(csf, ett_csf);

         switch( encap_cmd )
         {
            case NOP:
               show_cdf( encap_cmd, tvb, pinfo, csftree, 24 );
               break;

            case LIST_SERVICES:
               show_cdf( encap_cmd, tvb, pinfo, csftree, 24 );
               break;

            case LIST_IDENTITY:
               show_cdf( encap_cmd, tvb, pinfo, csftree, 24 );
               break;

            case LIST_INTERFACES:
               show_cdf( encap_cmd, tvb, pinfo, csftree, 24 );
               break;

            case REGISTER_SESSION:
               proto_tree_add_text( csftree, tvb, 24, 2, "Protocol Version: 0x%04X",
                                   tvb_get_letohs( tvb, 24 ) );

               proto_tree_add_text( csftree, tvb, 26, 2, "Option Flags: 0x%04X",
                                   tvb_get_letohs( tvb, 26 ) );

               break;

            case UNREGISTER_SESSION:
               break;

            case SEND_RR_DATA:
            case SEND_UNIT_DATA:
               proto_tree_add_item(csftree, hf_enip_ifacehnd, tvb, 24, 4, TRUE);

               proto_tree_add_text( csftree, tvb, 28, 2, "Timeout: %u",
                                   tvb_get_letohs( tvb, 28 ) );

               show_cdf( encap_cmd, tvb, pinfo, csftree, 30 );
               break;

            case INDICATE_STATUS:
            case CANCEL:
            default:

               /* Can not decode - Just show the data */
               add_byte_array_text_to_proto_tree( headertree, tvb, 24, encap_data_length, "Encap Data: " );
               break;

         } /* end of switch() */

      } /* end of if( encapsulated data ) */

   }

   return tvb_length(tvb);
} /* end of dissect_cipencap() */


/* Code to actually dissect the io packets*/
static void
dissect_enipio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   /* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *cipencap_tree;

   /* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENIP");

   /* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree)
	{
      /* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_cipencap, tvb, 0, -1, FALSE);

		cipencap_tree = proto_item_add_subtree(ti, ett_cipencap);

      show_cdf( 0xFFFF, tvb, pinfo, cipencap_tree, 0 );
	}

} /* end of dissect_enipio() */


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_cipencap(void)
{

/* Setup list of header fields  lengthSee Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_enip_command,
			{ "Command",           "enip.command",
			FT_UINT16, BASE_HEX, VALS(encap_cmd_vals), 0,
			"Encapsulation command", HFILL }
		},

		/* Encapsulated data headers */
		/* Common Packet Format */
		{ &hf_enip_cpf_typeid,
			{ "Type ID",          "enip.cpf.typeid",
			FT_UINT16, BASE_HEX, VALS(cdf_type_vals), 0,
			"Type of encapsulated item", HFILL }
		},

		/* Send RR Data */
		{ &hf_enip_ifacehnd,
			{ "Interface Handle",           "enip.cpf.rr.ifacehnd",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Interface handle", HFILL }
		},

		/* Unconnected message */
      { &hf_enip_ucm_rr,
			{ "Request/Response", "enip.cip.rr",
			FT_UINT8, BASE_HEX, VALS(encap_sc_rr), 0x80,
			"Request or Response message", HFILL }
		},
		{ &hf_enip_ucm_sc,
			{ "Service",           "enip.cip.sc",
			FT_UINT8, BASE_HEX, VALS(encap_sc_vals), 0x7F,
			"CIP Service code", HFILL }
		},
		{ &hf_enip_ucm_path,
			{ "Request Path",           "enip.cip.path",
			FT_BYTES, BASE_HEX, NULL, 0,
			"Request path", HFILL }
		},
		{ &hf_enip_ucm_genstat,
			{ "General Status",           "enip.cip.genstat",
			FT_UINT8, BASE_HEX, VALS(encap_cip_gs_vals), 0,
			"General Status", HFILL }
		},

		/* List identity response */
      { &hf_enip_cpf_lir_sinfamily,
			{ "sin_family", "enip.lir.sinfamily",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Socket Address Sin Family", HFILL }
		},
      { &hf_enip_cpf_lir_sinport,
			{ "sin_port", "enip.lir.sinport",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Socket Address Sin Port", HFILL }
		},
      { &hf_enip_cpf_lir_sinaddr,
			{ "sin_addr", "enip.lir.sinaddr",
			FT_IPv4, BASE_HEX, NULL, 0,
			"Socket Address Sin Addr", HFILL }
		},
      { &hf_enip_cpf_lir_sinzero,
			{ "sin_zero", "enip.lir.sinzero",
			FT_BYTES, BASE_HEX, NULL, 0,
			"Socket Address Sin Zero", HFILL }
		},
      { &hf_enip_cpf_lir_devtype,
			{ "Device Type", "enip.lir.devtype",
			FT_UINT16, BASE_DEC, VALS(encap_cip_devtype_vals), 0,
			"Device Type", HFILL }
		},
      { &hf_enip_cpf_lir_prodcode,
			{ "Product Code", "enip.lir.prodcode",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Product Code", HFILL }
		},
      { &hf_enip_cpf_lir_status,
			{ "Status", "enip.lir.status",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Status", HFILL }
		},
      { &hf_enip_cpf_lir_sernbr,
			{ "Serial Number", "enip.lir.ser",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Serial Number", HFILL }
		},
      { &hf_enip_cpf_lir_namelength,
			{ "Product Name Length", "enip.lir.namelength",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Product Name Length", HFILL }
		},
      { &hf_enip_cpf_lir_name,
			{ "Product Name", "enip.lir.name",
			FT_STRING, BASE_NONE, NULL, 0,
			"Product Name", HFILL }
		},
      { &hf_enip_cpf_lir_state,
			{ "State", "enip.lir.state",
			FT_UINT8, BASE_HEX, NULL, 0,
			"State", HFILL }
		},
      /* Vendor ID number */
		{ &hf_enip_vendors,
			{ "Vendor ID",           "enip.vnd",
			FT_UINT16, BASE_HEX, VALS(encap_cip_vendor_vals), 0,
			"Vendor ID number", HFILL }
		},
      { &hf_enip_ucm_fwo_comp,
			{ "Compatibility", "enip.cip.fwo.cmp",
			FT_UINT8, BASE_HEX, VALS(enip_com_bit_vals), 0x80,
			"Compatibility bit", HFILL }
		},
      { &hf_enip_ucm_fwo_mrev,
			{ "Major Revision", "enip.cip.fwo.mrev",
			FT_UINT8, BASE_DEC, NULL, 0x7F,
			"Major Revision", HFILL }
		},
      { &hf_enip_ucm_fwo_con_size,
			{ "Connection Size", "enip.cip.fwo.consize",
			FT_UINT16, BASE_DEC, NULL, 0x01FF,
			"Connection size", HFILL }
		},
      { &hf_enip_ucm_fwo_fixed_var,
			{ "Connection Size Type", "enip.cip.fwo.f_v",
			FT_UINT16, BASE_DEC, VALS(enip_con_fw_vals), 0x0200,
			"Fixed or variable connection size", HFILL }
		},
      { &hf_enip_ucm_fwo_prio,
			{ "Priority", "enip.cip.fwo.prio",
			FT_UINT16, BASE_DEC, VALS(enip_con_prio_vals), 0x0C00,
			"Connection priority", HFILL }
		},
      { &hf_enip_ucm_fwo_typ,
			{ "Connection Type", "enip.cip.fwo.typ",
			FT_UINT16, BASE_DEC, VALS(enip_con_type_vals), 0x6000,
			"Connection type", HFILL }
		},
      { &hf_enip_ucm_fwo_own,
			{ "Owner", "enip.cip.fwo.own",
			FT_UINT16, BASE_DEC, VALS(enip_con_owner_vals), 0x8000,
			"Redundant owner bit", HFILL }
		},
		/* Sequenced Address Type */
      { &hf_enip_cpf_sat_connid,
			{ "Connection ID", "enip.sat.connid",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Connection ID from forward open reply", HFILL }
		},
      { &hf_enip_cpf_sat_seqnum,
			{ "Sequence Number", "enip.sat.seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Sequence Number", HFILL }
		},
		{ &hf_enip_cpf_lsr_tcp,
			{ "Supports CIP Encapsultion via TCP", "enip.ls.tcp",
			FT_UINT16, BASE_DEC, VALS(enip_true_false_vals), 0x0020,
			"Supports CIP Encapsultion via TCP", HFILL }
		},
		{ &hf_enip_cpf_lsr_udp,
			{ "Supports CIP Class 0 or 1 via UDP", "enip.ls.udp",
			FT_UINT16, BASE_DEC, VALS(enip_true_false_vals), 0x0100,
			"Supports CIP Class 0 or 1 via UDP", HFILL }
		}

   };


/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_cipencap,
		&ett_cip,
		&ett_cpf,
		&ett_path,
		&ett_ekey_path,
		&ett_cipencaph,
		&ett_csf,
		&ett_rrsc,
		&ett_sockadd,
		&ett_mcsc,
		&ett_ncp,
		&ett_cia_path,
		&ett_data_seg,
		&ett_lsrcf,
		&ett_mes_req,
		&ett_cmd_data,
		&ett_port_path,
		&ett_mult_ser
	};

/* Register the protocol name and description */
	proto_cipencap = proto_register_protocol("EtherNet/IP (Industrial Protocol)",
	    "ENIP", "enip");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_cipencap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

} /* end of proto_register_cipencap() */


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_cipencap(void)
{
	dissector_handle_t cipencap_handle;
	dissector_handle_t enipio_handle;

	/* Register for encapsulated CIP data, using both TCP/UDP */
	cipencap_handle = new_create_dissector_handle(dissect_cipencap, proto_cipencap);
	dissector_add("tcp.port", ENIP_ENCAP_PORT, cipencap_handle);
	dissector_add("udp.port", ENIP_ENCAP_PORT, cipencap_handle);

	/* Register for IO data over UDP */
	enipio_handle = create_dissector_handle(dissect_enipio, proto_cipencap);
	dissector_add("udp.port", ENIP_IO_PORT, enipio_handle);

} /* end of proto_reg_handoff_cipencap() */
