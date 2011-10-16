/* packet-cip.c
 * Routines for Common Industrial Protocol (CIP) dissection
 * CIP Home: www.odva.org
 *
 * Copyright 2004
 * Magnus Hansson <mah@hms.se>
 * Joakim Wiberg <jow@hms.se>
 *
 * Added support for Connection Configuration Object
 *   ryan wamsley * Copyright 2007
 *
 * Object dependend services based on IOI
 *   Jan Bartels, Siempelkamp Maschinen- und Anlagenbau GmbH & Co. KG
 *   Copyright 2007
 *
 * Improved support for CoCo and CM objects
 *   Michael Mann * Copyright 2011
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
   &ett_cip,         dissect_cip
   &ett_path,        dissect_epath
   &ett_ekey_path,   dissect_epath
   &ett_mcsc,        dissect_epath,
   &ett_cia_path,    dissect_epath
   &ett_data_seg,    dissect_epath
   &ett_port_path,   dissect_epath
   &ett_rrsc,        dissect_cip_generic_data, dissect_cip_mr_data, dissect_cip_cm_data, dissect_cip_cco_data, dissect_cip_pccc_data
   &ett_status_item  dissect_cip_generic_data, dissect_cip_mr_data, dissect_cip_cm_data, dissect_cip_cco_data, dissect_cip_pccc_data

   &ett_cmd_data,    dissect_cip_generic_data, dissect_cip_mr_data, dissect_cip_cm_data, dissect_cip_cco_data, dissect_cip_pccc_data
   &ett_ncp,         dissect_cip_cm_data
   &ett_mes_req,     dissect_cip_cm_data
   &ett_mult_ser,    dissect_cip_mr_data
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include "packet-enip.h"
#include "packet-cip.h"

#define  ENIP_CIP_INTERFACE   0

typedef struct cip_req_info {
   dissector_handle_t dissector;
   guint8 bService;
   guint IOILen;
   void *pIOI;
   void *pData;
} cip_req_info_t;

typedef struct cip_simple_request_info {
   guint32 iClass;
   guint32 iInstance;
   guint32 iAttribute;
   guint32 iMember;
} cip_simple_request_info_t;

static dissector_handle_t cip_handle;
static dissector_handle_t cip_class_generic_handle;
static dissector_handle_t cip_class_cm_handle;
static dissector_handle_t cip_class_mr_handle;
static dissector_handle_t cip_class_cco_handle;

/* Initialize the protocol and registered fields */
static int proto_cip               = -1;
static int proto_cip_class_generic = -1;
static int proto_cip_class_cm      = -1;
static int proto_cip_class_mr      = -1;
static int proto_cip_class_cco     = -1;
static int proto_enip              = -1;

static int hf_cip_sc      = -1;
static int hf_cip_rr      = -1;
static int hf_cip_epath   = -1;
static int hf_cip_genstat = -1;

static int hf_cip_fwo_comp = -1;
static int hf_cip_fwo_mrev = -1;

static int hf_cip_cm_ot_connid   = -1;
static int hf_cip_cm_to_connid   = -1;
static int hf_cip_cm_conn_serial_num   = -1;
static int hf_cip_cm_orig_serial_num   = -1;
static int hf_cip_cm_fwo_con_size   = -1;
static int hf_cip_cm_lfwo_con_size  = -1;
static int hf_cip_cm_fwo_fixed_var  = -1;
static int hf_cip_cm_lfwo_fixed_var = -1;
static int hf_cip_cm_fwo_prio       = -1;
static int hf_cip_cm_lfwo_prio      = -1;
static int hf_cip_cm_fwo_typ        = -1;
static int hf_cip_cm_lfwo_typ       = -1;
static int hf_cip_cm_fwo_own        = -1;
static int hf_cip_cm_lfwo_own       = -1;
static int hf_cip_cm_fwo_dir        = -1;
static int hf_cip_cm_fwo_trigg      = -1;
static int hf_cip_cm_fwo_class      = -1;
static int hf_cip_cm_gco_conn       = -1;
static int hf_cip_cm_gco_coo_conn   = -1;
static int hf_cip_cm_gco_roo_conn   = -1;
static int hf_cip_cm_gco_la         = -1;
static int hf_cip_cco_con_type      = -1;
static int hf_cip_cco_ot_rtf        = -1;
static int hf_cip_cco_to_rtf        = -1;

static int hf_cip_vendor              = -1;
static int hf_cip_devtype             = -1;
static int hf_cip_port                = -1;
static int hf_cip_link_address_byte   = -1;
static int hf_cip_link_address_string = -1;
static int hf_cip_class8              = -1;
static int hf_cip_class16             = -1;
static int hf_cip_class32             = -1;
static int hf_cip_instance8           = -1;
static int hf_cip_instance16          = -1;
static int hf_cip_instance32          = -1;
static int hf_cip_member8             = -1;
static int hf_cip_member16            = -1;
static int hf_cip_member32            = -1;
static int hf_cip_attribute8          = -1;
static int hf_cip_attribute16         = -1;
static int hf_cip_attribute32         = -1;
static int hf_cip_conpoint8           = -1;
static int hf_cip_conpoint16          = -1;
static int hf_cip_conpoint32          = -1;
static int hf_cip_symbol              = -1;
static int hf_cip_class_rev           = -1;
static int hf_cip_class_max_inst32    = -1;
static int hf_cip_class_num_inst32    = -1;
static int hf_cip_reserved8           = -1;

/* Initialize the subtree pointers */
static gint ett_cip               = -1;
static gint ett_cip_class_generic = -1;
static gint ett_cip_class_mr      = -1;
static gint ett_cip_class_cm      = -1;
static gint ett_cip_class_cco     = -1;

static gint ett_path      = -1;
static gint ett_ekey_path = -1;
static gint ett_mcsc      = -1;
static gint ett_cia_path  = -1;
static gint ett_data_seg  = -1;
static gint ett_port_path = -1;

static gint ett_rrsc        = -1;
static gint ett_status_item = -1;
static gint ett_cmd_data    = -1;

static gint ett_cm_rrsc     = -1;
static gint ett_cm_ncp      = -1;
static gint ett_cm_mes_req  = -1;
static gint ett_cm_cmd_data = -1;

static gint ett_mr_rrsc     = -1;
static gint ett_mr_mult_ser = -1;
static gint ett_mr_cmd_data = -1;

static gint ett_cco_iomap    = -1;
static gint ett_cco_con_status = -1;
static gint ett_cco_con_flag = -1;
static gint ett_cco_tdi      = -1;
static gint ett_cco_ncp      = -1;
static gint ett_cco_rrsc     = -1;
static gint ett_cco_cmd_data = -1;

static dissector_table_t   subdissector_class_table;
static dissector_table_t   subdissector_symbol_table;

/* Translate function to string - CIP Service codes */
static const value_string cip_sc_vals[] = {
   GENERIC_SC_LIST

   { 0,                       NULL }
};

/* Translate function to string - CIP Service codes for CM */
static const value_string cip_sc_vals_cm[] = {
   GENERIC_SC_LIST

   /* Some class specific services */
   { SC_CM_FWD_CLOSE,            "Forward Close" },
   { SC_CM_FWD_OPEN,             "Forward Open" },
   { SC_CM_UNCON_SEND,           "Unconnected Send" },
   { SC_CM_LARGE_FWD_OPEN,       "Large Forward Open" },
   { SC_CM_GET_CONN_OWNER,       "Get Connection Owner" },

   { 0,                       NULL }
};

/* Translate function to string - CIP Service codes for CCO */
static const value_string cip_sc_vals_cco[] = {
   GENERIC_SC_LIST

   /* Some class specific services */
   { SC_CCO_KICK_TIMER,           "Kick Timer" },
   { SC_CCO_OPEN_CONN,            "Open Connection" },
   { SC_CCO_CLOSE_CONN,           "Close Connection" },
   { SC_CCO_STOP_CONN,            "Stop Connection" },
   { SC_CCO_CHANGE_START,         "Change Start" },
   { SC_CCO_GET_STATUS,           "Get Status" },
   { SC_CCO_CHANGE_COMPLETE,      "Change Complete" },
   { SC_CCO_AUDIT_CHANGE,         "Audit Changes" },

   { 0,                       NULL }
};

/* Translate function to string - CIP Request/Response */
static const value_string cip_sc_rr[] = {
   { 0,        "Request"  },
   { 1,        "Response" },

   { 0,        NULL }
};

/* Translate function to string - Compatibility */
static const value_string cip_com_bit_vals[] = {
   { 0,        "Bit Cleared" },
   { 1,        "Bit Set"     },

   { 0,        NULL          }
};

/* Translate function to string - Connection priority */
static const value_string cip_con_prio_vals[] = {
   { 0,        "Low Priority"  },
   { 1,        "High Priority" },
   { 2,        "Scheduled"     },
   { 3,        "Urgent"        },

   { 0,        NULL            }
};

/* Translate function to string - Connection size fixed or variable */
static const value_string cip_con_fw_vals[] = {
   { 0,        "Fixed"    },
   { 1,        "Variable" },

   { 0,        NULL       }
};

/* Translate function to string - Connection owner */
static const value_string cip_con_owner_vals[] = {
   { 0,        "Exclusive" },
   { 1,        "Redundant" },

   { 0,        NULL        }
};

/* Translate function to string - Connection direction */
static const value_string cip_con_dir_vals[] = {
   { 0,        "Client" },
   { 1,        "Server" },

   { 0,        NULL        }
};

/* Translate function to string - Connection type*/
static const value_string cip_con_vals[] = {
   { 0,        "Originator" },
   { 1,        "Target" },

   { 0,        NULL        }
};

/* Translate function to string - Production trigger */
static const value_string cip_con_trigg_vals[] = {
   { 0,        "Cyclic" },
   { 1,        "Change-Of-State" },
   { 2,        "Application Object" },

   { 0,        NULL        }
};

/* Translate function to string - Transport class */
static const value_string cip_con_class_vals[] = {
   { 0,        "0" },
   { 1,        "1" },
   { 2,        "2" },
   { 3,        "3" },

   { 0,        NULL        }
};

/* Translate function to string - Connection type */
static const value_string cip_con_type_vals[] = {
   { 0,        "Null"           },
   { 1,        "Multicast"      },
   { 2,        "Point to Point" },
   { 3,        "Reserved"       },

   { 0,        NULL             }
};

/* Translate function to string - Timeout Multiplier */
static const value_string cip_con_time_mult_vals[] = {
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

/* Translate function to string - Connection Last Action */
static const value_string cip_con_last_action_vals[] = {
   { 0,        "No Owner"           },
   { 1,        "Owner Is Idle Mode" },
   { 2,        "Owner Is Run Mode"  },
   { 255,      "Implementation not supported" },

   { 0,        NULL             }
};

/* Translate function to string - real time transfer format type */
static const value_string cip_con_rtf_vals[] = {
   { 0,        "32-bit Header"  },
   { 1,        "Zero data length idle mode"},
   { 2,        "Modeless"  },
   { 3,        "Heartbeat"  },
   { 5,        "Safety"  },

   { 0,        NULL             }
};

/* Translate function to string - CCO change type */
static const value_string cip_cco_change_type_vals[] = {
   { 0,        "Full"           },
   { 1,        "Incremental"    },

   { 0,        NULL             }
};

/* Translate function to string - CIP General Status codes */
const value_string cip_gs_vals[] = {
   { CI_GRC_SUCCESS,             "Success" },
   { CI_GRC_FAILURE,             "Connection failure" },
   { CI_GRC_NO_RESOURCE,         "Resource unavailable" },
   { CI_GRC_BAD_DATA,            "Invalid parameter value" },
   { CI_GRC_BAD_PATH,            "Path segment error" },
   { CI_GRC_BAD_CLASS_INSTANCE,  "Path destination unknown" },
   { CI_GRC_PARTIAL_DATA,        "Partial transfer" },
   { CI_GRC_CONN_LOST,           "Connection lost" },
   { CI_GRC_BAD_SERVICE,         "Service not supported" },
   { CI_GRC_BAD_ATTR_DATA,       "Invalid attribute value" },
   { CI_GRC_ATTR_LIST_ERROR,     "Attribute list error" },
   { CI_GRC_ALREADY_IN_MODE,     "Already in requested mode/state" },
   { CI_GRC_BAD_OBJ_MODE,        "Object state conflict" },
   { CI_GRC_OBJ_ALREADY_EXISTS,  "Object already exists" },
   { CI_GRC_ATTR_NOT_SETTABLE,   "Attribute not settable" },
   { CI_GRC_PERMISSION_DENIED,   "Privilege violation" },
   { CI_GRC_DEV_IN_WRONG_STATE,  "Device state conflict" },
   { CI_GRC_REPLY_DATA_TOO_LARGE,"Reply data too large" },
   { CI_GRC_FRAGMENT_PRIMITIVE,  "Fragmentation of a primitive value" },
   { CI_GRC_CONFIG_TOO_SMALL,    "Not enough data" },
   { CI_GRC_UNDEFINED_ATTR,      "Attribute not supported" },
   { CI_GRC_CONFIG_TOO_BIG,      "Too much data" },
   { CI_GRC_OBJ_DOES_NOT_EXIST,  "Object does not exist" },
   { CI_GRC_NO_FRAGMENTATION,    "Service fragmentation sequence not in progress" },
   { CI_GRC_DATA_NOT_SAVED,      "No stored attribute data" },
   { CI_GRC_DATA_WRITE_FAILURE,  "Store operation failure" },
   { CI_GRC_REQUEST_TOO_LARGE,   "Routing failure, request packet too large" },
   { CI_GRC_RESPONSE_TOO_LARGE,  "Routing failure, response packet too large" },
   { CI_GRC_MISSING_LIST_DATA,   "Missing attribute list entry data" },
   { CI_GRC_INVALID_LIST_STATUS, "Invalid attribute value list" },
   { CI_GRC_SERVICE_ERROR,       "Embedded service error" },
   { CI_GRC_CONN_RELATED_FAILURE,"Vendor specific error" },
   { CI_GRC_INVALID_PARAMETER,   "Invalid parameter" },
   { CI_GRC_WRITE_ONCE_FAILURE,  "Write-once value or medium already written" },
   { CI_GRC_INVALID_REPLY,       "Invalid reply received" },
   { CI_GRC_BUFFER_OVERFLOW,     "Buffer overflow" },
   { CI_GRC_MESSAGE_FORMAT,      "Invalid message format" },
   { CI_GRC_BAD_KEY_IN_PATH,     "Key failure in path" },
   { CI_GRC_BAD_PATH_SIZE,       "Path size invalid" },
   { CI_GRC_UNEXPECTED_ATTR,     "Unexpected attribute in list" },
   { CI_GRC_INVALID_MEMBER,      "Invalid Member ID" },
   { CI_GRC_MEMBER_NOT_SETTABLE, "Member not settable" },
   { CI_GRC_G2_SERVER_FAILURE,   "Group 2 only server general failure" },
   { CI_GRC_UNKNOWN_MB_ERROR,    "Unknown Modbus error" },

   { 0,                          NULL }
};

/* Translate Vendor ID:s */
const value_string cip_vendor_vals[] = {
   VENDOR_ID_LIST

   { 0, NULL }
};

/* Translate Device Profile:s */
const value_string cip_devtype_vals[] = {
   { DP_GEN_DEV,              "Generic Device"              },
   { DP_AC_DRIVE,             "AC Drive"                    },
   { DP_MOTOR_OVERLOAD,       "Motor Overload"              },
   { DP_LIMIT_SWITCH,         "Limit Switch"                },
   { DP_IND_PROX_SWITCH,      "Inductive Proximity Switch"  },
   { DP_PHOTO_SENSOR,         "Photoelectric Sensor"        },
   { DP_GENP_DISC_IO,         "General Purpose Discrete I/O"},
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
   { DP_VACUUM_PRES_GAUGE,    "Vacuum Pressure Gauge"       },

   { 0, NULL }
};

#define CI_CLS_MR   0x02    /* Message Router */
#define CI_CLS_CM   0x06    /* Connection Manager */
#define CI_CLS_CCO  0xF3    /* Connection Configuration Object */

/* Translate class names */
static const value_string cip_class_names_vals[] = {
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
   { 0x37,     "File Object"                           },
   { 0x38,     "S-Partial Pressure Object"             },
   { 0x39,     "Safety Supervisor Object"              },
   { 0x3A,     "Safety Validator Object"               },
   { 0x3B,     "Safety Discrete Output Point Object"   },
   { 0x3C,     "Safety Discrete Output Group Object"   },
   { 0x3D,     "Safety Discrete Input Point Object"    },
   { 0x3E,     "Safety Discrete Input Group Object"    },
   { 0x3F,     "Safety Dual Channel Output Object"     },
   { 0x40,     "S-Sensor Calibration Object"           },
   { 0x41,     "Event Log Object"                      },
   { 0x42,     "Motion Axis Object"                    },
   { 0x43,     "Time Sync Object"                      },
   { 0x44,     "Modbus Object"                         },
   { 0x45,     "Originator Connection List Object"     },
   { 0x46,     "Modbus Serial Link Object"             },
   { 0x47,     "Device Level Ring (DLR) Object"        },
   { 0x48,     "QoS Object"                            },
   { 0xF0,     "ControlNet Object"                     },
   { 0xF1,     "ControlNet Keeper Object"              },
   { 0xF2,     "ControlNet Scheduling Object"          },
   { 0xF3,     "Connection Configuration Object"       },
   { 0xF4,     "Port Object"                           },
   { 0xF5,     "TCP/IP Interface Object"               },
   { 0xF6,     "EtherNet Link Object"                  },
   { 0xF7,     "CompoNet Object"                       },
   { 0xF8,     "CompoNet Repeater Object"              },

   { 0,        NULL                                    }
};

static void
dissect_cip_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, packet_info *pinfo, cip_req_info_t *preq_info );

static proto_item*
add_byte_array_text_to_proto_tree( proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char* str )
{
   const guint8 *tmp;
   char         *tmp2, *tmp2start;
   proto_item   *pi;
   int           i,tmp_length,tmp2_length;
   guint32       octet;
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
      tmp_length = 16;
      tmp2_length = 36;
   }
   else
   {
      tmp_length = length;
      tmp2_length = ( length * 2 ) + 1;
   }

   tmp = tvb_get_ptr( tvb, start, tmp_length );
   tmp2 = (char*)ep_alloc( tmp2_length );

   tmp2start = tmp2;

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

   return( pi );

} /* end of add_byte_array_text_to_proto_tree() */


/* Dissect EPATH */
static void
dissect_epath( tvbuff_t *tvb, proto_item *epath_item, int offset, int path_length, gboolean generate )
{
   int pathpos, temp_data, temp_data2, seg_size, i, temp_word;
   unsigned char segment_type, opt_link_size;
   proto_tree *path_tree, *port_tree, *net_tree;
   proto_item *qi, *cia_item, *ds_item;
   proto_tree *e_key_tree, *cia_tree, *ds_tree;
   proto_item *mcpi, *port_item, *net_item;
   proto_tree *mc_tree;
   proto_item *it;
   proto_item *hidden_item;

   /* Create a sub tree for the epath */
   path_tree = proto_item_add_subtree( epath_item, ett_path );

   if ( !generate )
   {
      hidden_item = proto_tree_add_item(path_tree, hf_cip_epath,
                                        tvb, offset, path_length, ENC_NA );
      PROTO_ITEM_SET_HIDDEN(hidden_item);
   }

   pathpos = 0;

   while( pathpos < path_length )
   {
      /* Get segement type */
      segment_type = tvb_get_guint8( tvb, offset + pathpos );

      /* Determine the segment type */

      switch( segment_type & CI_SEGMENT_TYPE_MASK )
      {
         case CI_PORT_SEGMENT:

            port_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 0, "Port Segment" );
            if ( generate )
            {
               port_item = proto_tree_add_text( path_tree, NULL, 0, 0, "Port Segment" );
               PROTO_ITEM_SET_GENERATED(port_item);
            }
            else
               port_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 0, "Port Segment" );
            port_tree = proto_item_add_subtree( port_item, ett_port_path );

            /* Add port number */
            if ( generate )
            {
               it = proto_tree_add_uint(port_tree, hf_cip_port, NULL, 0, 0, ( segment_type & 0x0F ) );
               PROTO_ITEM_SET_GENERATED(it);
            }
            else
               proto_tree_add_item( port_tree, hf_cip_port, tvb, offset + pathpos, 1, ENC_LITTLE_ENDIAN );
            proto_item_append_text( epath_item, "Port: %d", ( segment_type & 0x0F ) );
            proto_item_append_text( port_item, ": Port: %d", ( segment_type & 0x0F ) );

            if( segment_type & 0x10 )
            {
               /* Add Extended Link Address flag */
               if ( generate )
               {
                  it = proto_tree_add_text( port_tree, NULL, 0, 0, "Extended Link Address: TRUE" );
                  PROTO_ITEM_SET_GENERATED(it);
               }
               else
                  it = proto_tree_add_text( port_tree, tvb, offset+pathpos, 1, "Extended Link Address: TRUE" );

               /* Add size of extended link address */
               opt_link_size = tvb_get_guint8( tvb, offset + pathpos + 1 );
               if ( generate )
               {
                  it = proto_tree_add_text( port_tree, NULL, 0, 0, "Link Address Size: %d", opt_link_size  );
                  PROTO_ITEM_SET_GENERATED(it);
               }
               else
                  it = proto_tree_add_text( port_tree, tvb, offset+pathpos+1, 1, "Link Address Size: %d", opt_link_size  );

               /* Add extended link address */
               if ( generate )
               {
                  it = proto_tree_add_string(port_tree, hf_cip_link_address_string, NULL, 0, 0, tvb_format_text(tvb, offset+pathpos+2, opt_link_size) );
                  PROTO_ITEM_SET_GENERATED(it);
               }
               else
                  proto_tree_add_item( port_tree, hf_cip_link_address_string, tvb, offset+pathpos+2, opt_link_size, ENC_ASCII|ENC_NA );
               proto_item_append_text( epath_item, ", Address: %s", tvb_format_text(tvb, offset+pathpos+2, opt_link_size) );
               proto_item_append_text( port_item,  ", Address: %s", tvb_format_text(tvb, offset+pathpos+2, opt_link_size) );

               /* Pad byte */
               if( opt_link_size % 2 )
               {
                  proto_item_set_len( port_item, 3 + opt_link_size );
                  pathpos = pathpos + 3 + opt_link_size;
               }
               else
               {
                  proto_item_set_len( port_item, 2 + opt_link_size );
                  pathpos = pathpos + 2 + opt_link_size;
               }
            }
            else
            {
               /* Add Extended Link Address flag */
               if ( generate )
               {
                  it = proto_tree_add_text( port_tree, NULL, 0, 0, "Extended Link Address: FALSE" );
                  PROTO_ITEM_SET_GENERATED(it);
               }
               else
                  it = proto_tree_add_text( port_tree, tvb, offset+pathpos, 1, "Extended Link Address: FALSE" );

               /* Add Link Address */
               if ( generate )
               {
                  it = proto_tree_add_uint(port_tree, hf_cip_link_address_byte, NULL, 0, 0, tvb_get_guint8( tvb, offset + pathpos + 1 ) );
                  PROTO_ITEM_SET_GENERATED(it);
               }
               else
                  proto_tree_add_item( port_tree, hf_cip_link_address_byte, tvb, offset+pathpos+1, 1, ENC_BIG_ENDIAN );
               proto_item_append_text( epath_item, ", Address: %d",tvb_get_guint8( tvb, offset + pathpos + 1 ) );
               proto_item_append_text( port_item,  ", Address: %d",tvb_get_guint8( tvb, offset + pathpos + 1 ) );

               proto_item_set_len( port_item, 2 );
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
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "8-Bit Logical Class Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Class Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the class */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 8-bit class number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint(cia_tree, hf_cip_class8, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_class8, tvb, offset + pathpos + 1, 1, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "%s", val_to_str( temp_data, cip_class_names_vals , "Class: 0x%02X" ) );

                     /* 2 bytes of path used */
                     pathpos += 2;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
                  {
                     temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "16-Bit Logical Class Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 4, "16-Bit Logical Class Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the class */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 16-bit class number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint(cia_tree, hf_cip_class16, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_class16, tvb, offset + pathpos + 2, 2, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "%s", val_to_str( temp_data, cip_class_names_vals , "Class: 0x%04X" ) );

                     /* 4 bytes of path used */
                     pathpos += 4;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
                  {
                     temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "32-Bit Logical Instance Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 6, "32-Bit Logical Instance Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the class */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 32-bit class number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint(cia_tree, hf_cip_class32, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_class32, tvb, offset + pathpos + 2, 4, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "%s", val_to_str( temp_data, cip_class_names_vals , "Class: 0x%08X" ) );

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
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "8-Bit Logical Instance Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Instance Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the instance */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 8-bit instance number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint(cia_tree, hf_cip_instance8, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_instance8, tvb, offset + pathpos + 1, 1, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Instance: 0x%02X", temp_data );

                     /* 2 bytes of path used */
                     pathpos += 2;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
                  {
                     temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "16-Bit Logical Instance Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 4, "16-Bit Logical Instance Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the instance */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 16-bit instance number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint(cia_tree, hf_cip_instance16, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_instance16, tvb, offset + pathpos + 2, 2, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Instance: 0x%04X", temp_data );

                     /* 4 bytes of path used */
                     pathpos += 4;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
                  {
                     temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "32-Bit Logical Instance Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 6, "32-Bit Logical Instance Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the instance */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 32-bit instance number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint(cia_tree, hf_cip_instance32, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_instance32, tvb, offset + pathpos + 2, 4, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Instance: 0x%08X", temp_data );


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


               case CI_LOGICAL_SEG_MBR_ID:

                  /* Logical Member ID, do a format check */

                  if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
                  {
                     temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "8-Bit Logical Member Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Member Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the attribute */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 8-bit attribute number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint( cia_tree, hf_cip_member8, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_member8, tvb, offset + pathpos + 1, 1, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Member: 0x%02X", temp_data );

                     /* 2 bytes of path used */
                     pathpos += 2;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
                  {
                     temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "16-Bit Logical Member Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 4, "16-Bit Logical Member Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the attribute */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 16-bit attribute number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint( cia_tree, hf_cip_member16, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_member16, tvb, offset + pathpos + 2, 2, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Member: 0x%04X", temp_data );

                     /* 4 bytes of path used */
                     pathpos += 4;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
                  {
                     temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "32-Bit Logical Member Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 6, "32-Bit Logical Member Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the attribute */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 32-bit attribute number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint( cia_tree, hf_cip_member32, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_member32, tvb, offset + pathpos + 2, 4, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Member: 0x%08X", temp_data );

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
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "8-Bit Logical Attribute Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Attribute Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the attribute */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 8-bit attribute number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint( cia_tree, hf_cip_attribute8, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_attribute8, tvb, offset + pathpos + 1, 1, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Attribute: 0x%02X", temp_data );

                     /* 2 bytes of path used */
                     pathpos += 2;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
                  {
                     temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "16-Bit Logical Attribute Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 4, "16-Bit Logical Attribute Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the attribute */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 16-bit attribute number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint( cia_tree, hf_cip_attribute16, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_attribute16, tvb, offset + pathpos + 2, 2, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Attribute: 0x%04X", temp_data );

                     /* 4 bytes of path used */
                     pathpos += 4;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
                  {
                     temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
                     if ( generate )
                     {
                        cia_item = proto_tree_add_text( path_tree, NULL, 0, 0, "32-Bit Logical Attribute Segment (0x%02X)", segment_type );
                        PROTO_ITEM_SET_GENERATED(cia_item);
                     }
                     else
                        cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 6, "32-Bit Logical Attribute Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the attribute */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 32-bit attribute number */
                     if ( generate )
                     {
                        it = proto_tree_add_uint( cia_tree, hf_cip_attribute32, NULL, 0, 0, temp_data );
                        PROTO_ITEM_SET_GENERATED(it);
                     }
                     else
                        proto_tree_add_item( cia_tree, hf_cip_attribute32, tvb, offset + pathpos + 2, 4, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Attribute: 0x%08X", temp_data );

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

                     /* Display the 8-bit connection point number */
                     proto_tree_add_item( cia_tree, hf_cip_conpoint8, tvb, offset + pathpos + 1, 1, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Connection Point: 0x%02X", temp_data );

                     /* 2 bytes of path used */
                     pathpos += 2;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
                  {
                     temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
                     cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 4, "16-Bit Logical Connection Point Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the connection point */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 16-bit connection point number */
                     proto_tree_add_item( cia_tree, hf_cip_conpoint16, tvb, offset + pathpos + 2, 2, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Connection Point: 0x%04X", temp_data );

                     /* 4 bytes of path used */
                     pathpos += 4;
                  }
                  else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
                  {
                     temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
                     cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 6, "32-Bit Logical Connection Point Segment (0x%02X)", segment_type );

                     /* Create a sub tree for the connection point */
                     cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

                     /* Display the 32-bit connection point number */
                     proto_tree_add_item( cia_tree, hf_cip_conpoint32, tvb, offset + pathpos + 2, 4, ENC_LITTLE_ENDIAN );
                     proto_item_append_text( epath_item, "Connection Point: 0x%08X", temp_data );

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
                        proto_tree_add_item( e_key_tree, hf_cip_vendor, tvb, offset + pathpos + 2, 2, ENC_LITTLE_ENDIAN);
                        proto_item_append_text( qi, "VendorID: 0x%04X", temp_data );

                        /* Get Device Type */
                        temp_data = tvb_get_letohs( tvb, offset + pathpos + 4 );
                        proto_tree_add_item( e_key_tree, hf_cip_devtype, tvb, offset + pathpos + 4, 2, ENC_LITTLE_ENDIAN);
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
                        proto_tree_add_item(mc_tree, hf_cip_fwo_comp,
                                            tvb, offset + pathpos + 8, 1, ENC_LITTLE_ENDIAN );

                        proto_item_append_text( mcpi, "%s, Major Revision: %d",
                                                val_to_str( ( temp_data & 0x80 )>>7, cip_com_bit_vals , "" ),
                                                temp_data & 0x7F );

                        /* Major revision */
                        proto_tree_add_item(mc_tree, hf_cip_fwo_mrev,
                                            tvb, offset + pathpos + 8, 1, ENC_LITTLE_ENDIAN );

                        /* Minor revision */
                        temp_data2 = tvb_get_guint8( tvb, offset + pathpos + 9 );
                        proto_tree_add_text( e_key_tree, tvb, offset + pathpos + 9, 1, "Minor Revision: %d", temp_data2 );

                        proto_item_append_text( qi, ", %d.%d", ( temp_data & 0x7F ), temp_data2 );

                        proto_item_append_text(epath_item, "[Key]" );

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
                  if ( generate )
                  {
                     ds_item = proto_tree_add_text( path_tree, NULL, 0, 0, "Simple Data Segment (0x%02X)", segment_type );
                     PROTO_ITEM_SET_GENERATED(ds_item);
                  }
                  else
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

                  proto_item_append_text(epath_item, "[Data]" );

                  break;

               case CI_DATA_SEG_SYMBOL:

                  /* ANSI extended symbol segment */
                  if ( generate )
                  {
                     ds_item = proto_tree_add_text( path_tree, NULL, 0, 0, "Extended Symbol Segment (0x%02X)", segment_type );
                     PROTO_ITEM_SET_GENERATED(ds_item);
                  }
                  else
                     ds_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 1, "Extended Symbol Segment (0x%02X)", segment_type );

                  /* Create a sub tree */
                  ds_tree = proto_item_add_subtree( ds_item, ett_data_seg );

                  /* Segment size */
                  seg_size = tvb_get_guint8( tvb, offset + pathpos+1 );
                  if ( generate )
                  {
                     it = proto_tree_add_text( ds_tree, NULL, 0, 0, "Data Size: %d", seg_size );
                     PROTO_ITEM_SET_GENERATED(it);
                  }
                  else
                     proto_tree_add_text( ds_tree, tvb, offset + pathpos+1, 1, "Data Size: %d", seg_size );

                  /* Segment data  */
                  if( seg_size != 0 )
                  {
                     if ( generate )
                     {
                        qi = proto_tree_add_text( ds_tree, NULL, 0, 0, "Data: %s",
                                                  tvb_format_text(tvb, offset + pathpos + 2, seg_size ) );
                        PROTO_ITEM_SET_GENERATED(qi);
                     }
                     else
                        qi = proto_tree_add_text( ds_tree, tvb, offset + pathpos + 2, seg_size, "Data: %s",
                                                  tvb_format_text(tvb, offset + pathpos + 2, seg_size ) );

                     proto_item_append_text(epath_item, "%s", tvb_format_text(tvb, offset + pathpos + 2, seg_size ) );

                     hidden_item = proto_tree_add_item( ds_tree, hf_cip_symbol, tvb, offset + pathpos + 2, seg_size, ENC_ASCII|ENC_NA );
                     PROTO_ITEM_SET_HIDDEN(hidden_item);

                     if( seg_size %2 )
                     {
                        /* We have a PAD BYTE */
                        if ( !generate )
                           proto_tree_add_text( ds_tree, tvb, offset + pathpos + 2 + seg_size, 1, "Pad Byte (0x%02X)",
                                                tvb_get_guint8( tvb, offset + pathpos + 2 + seg_size ) );
                        seg_size++;
                     }
                  }

                  if ( !generate )
                     proto_item_set_len( ds_item, 2 + seg_size );
                  pathpos = pathpos + 2 + seg_size;

                  break;

               default:
                  proto_tree_add_text( path_tree, tvb, 0, 0, "Unsupported Sub-Segment Type" );
                  return;

            } /* End of switch sub-type */

            break;

         case CI_NETWORK_SEGMENT:

            /* Network segment -Determine the segment sub-type */

            switch( segment_type & CI_NETWORK_SEG_TYPE_MASK )
            {
               case CI_NETWORK_SEG_SCHEDULE:
                  net_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "Network Segment - Schedule" );
                  net_tree = proto_item_add_subtree( net_item, ett_port_path );

                  proto_tree_add_text( net_tree, tvb, offset + pathpos + 1, 1, "Multiplier/Phase: %02X", tvb_get_guint8( tvb, offset + pathpos + 1 ) );

                  /* 2 bytes of path used */
                  pathpos += 2;
                  break;

               case CI_NETWORK_SEG_FIXED_TAG:
                  net_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "Network Segment - Fixed Tag" );
                  net_tree = proto_item_add_subtree( net_item, ett_port_path );

                  proto_tree_add_text( net_tree, tvb, offset + pathpos + 1, 1, "Fixed Tag: %02X", tvb_get_guint8( tvb, offset + pathpos + 1 ) );

                  /* 2 bytes of path used */
                  pathpos += 2;
                  break;

               case CI_NETWORK_SEG_PROD_INHI:
                  net_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "Network Segment - Production Inhibit" );
                  net_tree = proto_item_add_subtree( net_item, ett_port_path );

                  proto_tree_add_text( net_tree, tvb, offset + pathpos + 1, 1, "Production Inhibit Time: %dms", tvb_get_guint8( tvb, offset + pathpos + 1 ) );

                  /* 2 bytes of path used */
                  pathpos += 2;
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

      /* Next path segment */
      if( pathpos < path_length )
         proto_item_append_text( epath_item, ", " );

   } /* end of while( pathpos < path_length ) */

} /* end of dissect_epath() */

/* Dissect EPATH for class, instance, attribute, and/or member without creating a tree */
static void
dissect_epath_request( tvbuff_t *tvb, cip_simple_request_info_t* req_data, int path_length)
{
   int pathpos, offset, temp_data, seg_size;
   unsigned char segment_type, opt_link_size;

   /* can't populate req_data unless its there */
   if (req_data == NULL)
      return;

   req_data->iClass = (guint32)-1;
   req_data->iInstance = (guint32)-1;
   req_data->iAttribute = (guint32)-1;
   req_data->iMember = (guint32)-1;

   pathpos = 0;
   offset = 0;

   while( pathpos < path_length )
   {
      /* Get segement type */
      segment_type = tvb_get_guint8( tvb, offset + pathpos );

      /* Determine the segment type */
      switch( segment_type & CI_SEGMENT_TYPE_MASK )
      {
      case CI_PORT_SEGMENT:
         if( segment_type & 0x10 )
         {
            /* Add size of extended link address */
            opt_link_size = tvb_get_guint8( tvb, offset + pathpos + 1 );

            /* Pad byte */
            if( opt_link_size % 2 )
            {
              pathpos = pathpos + 3 + opt_link_size;
            }
            else
            {
              pathpos = pathpos + 2 + opt_link_size;
            }
         }
         else
         {
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
               req_data->iClass = tvb_get_guint8( tvb, offset + pathpos + 1 );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               req_data->iClass = tvb_get_letohs( tvb, offset + pathpos + 2 );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               req_data->iClass = tvb_get_letohl( tvb, offset + pathpos + 2 );

               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               return;
            }
            break;

         case CI_LOGICAL_SEG_INST_ID:

            /* Logical Instance ID, do a format check */
            if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
            {
               req_data->iInstance = tvb_get_guint8( tvb, offset + pathpos + 1 );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               req_data->iInstance = tvb_get_letohs( tvb, offset + pathpos + 2 );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               req_data->iInstance = tvb_get_letohl( tvb, offset + pathpos + 2 );

               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               return;
            }
            break;


         case CI_LOGICAL_SEG_MBR_ID:

            /* Logical Member ID, do a format check */
            if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
            {
               req_data->iMember = tvb_get_guint8( tvb, offset + pathpos + 1 );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               req_data->iMember = tvb_get_letohs( tvb, offset + pathpos + 2 );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               req_data->iMember = tvb_get_letohl( tvb, offset + pathpos + 2 );

               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               return;
            }
            break;

         case CI_LOGICAL_SEG_ATTR_ID:

            /* Logical Attribute ID, do a format check */
            if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
            {
               req_data->iAttribute = tvb_get_guint8( tvb, offset + pathpos + 1 );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               req_data->iAttribute = tvb_get_letohs( tvb, offset + pathpos + 2 );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               req_data->iAttribute = tvb_get_letohl( tvb, offset + pathpos + 2 );

               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               return;
            }
            break;


         case CI_LOGICAL_SEG_CON_POINT:

            /* Logical Connection point , do a format check */

            if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
            {
               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               /* 6 bytes of path used */
               pathpos += 6;
            }
            else
            {
               /* Unsupported logical segment format */
               return;
            }
            break;


         case CI_LOGICAL_SEG_SPECIAL:

            /* Logical Special ID, the only logical format specified is electronic key */
            if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_E_KEY )
            {
               /* Get the Key Format */
               temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );
               if( temp_data == CI_E_KEY_FORMAT_VAL )
               {
                  /* Increment the path pointer */
                  pathpos += 10;
               }
               else
               {
                  /* Unsupported electronic key format */
                  return;
               }
            }
            else
            {
               /* Unsupported special segment format */
               return;
            }
            break;

         default:

            /* Unsupported logical segment type */
            return;

         } /* end of switch( segment_type & CI_LOGICAL_SEG_TYPE_MASK ) */
         break;


      case CI_DATA_SEGMENT:

         /* Data segment, determin the logical type */
         switch( segment_type )
         {
            case CI_DATA_SEG_SIMPLE:

               /* Simple data segment */

               /* Segment size */
               seg_size = tvb_get_guint8( tvb, offset + pathpos+1 )*2;
               pathpos = pathpos + 2 + seg_size;
               break;

            case CI_DATA_SEG_SYMBOL:

               /* Segment size */
               seg_size = tvb_get_guint8( tvb, offset + pathpos+1 );

               /* Segment data  */
               if( seg_size != 0 )
               {
                  if( seg_size %2 )
                  {
                     /* We have a PAD BYTE */
                     seg_size++;
                  }
               }

               pathpos = pathpos + 2 + seg_size;
               break;

            default:
               return;

            } /* End of switch sub-type */
            break;

      case CI_NETWORK_SEGMENT:

         /* Network segment -Determine the segment sub-type */
         switch( segment_type & CI_NETWORK_SEG_TYPE_MASK )
         {
           case CI_NETWORK_SEG_SCHEDULE:
               /* 2 bytes of path used */
               pathpos += 2;
               break;

            case CI_NETWORK_SEG_FIXED_TAG:
               /* 2 bytes of path used */
               pathpos += 2;
               break;

            case CI_NETWORK_SEG_PROD_INHI:
               /* 2 bytes of path used */
               pathpos += 2;
               break;

            default:
               return;

            } /* End of switch sub-type */

      break;

     default:

         /* Unsupported segment type */
         return;

      } /* end of switch( segment_type & CI_SEGMENT_TYPE_MASK ) */

   } /* end of while( pathpos < path_length ) */

} /* end of dissect_epath_request() */

/************************************************
 *
 * Dissector for generic CIP object
 *
 ************************************************/

static void
dissect_cip_generic_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo, proto_item *ti )
{
   proto_item *pi, *temp_item;
   proto_tree *cmd_data_tree;
   int req_path_size;
   unsigned char add_stat_size;
   unsigned char i;


   if( tvb_get_guint8( tvb, offset ) & 0x80 )
   {
      /* Response message */
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cmd_data );

         /* Add data */
         add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
      }
      else
      {
         PROTO_ITEM_SET_HIDDEN( ti );
      }

   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                  cip_sc_vals , "Unknown Service (0x%02x)") );

      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {

         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cmd_data );

         /* Check what service code that recived */

         if( tvb_get_guint8( tvb, offset ) == SC_GET_ATT_LIST )
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

      }
      else
      {
         PROTO_ITEM_SET_HIDDEN( ti );
      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

} /* End of dissect_cip_generic_data() */

static int
dissect_cip_class_generic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_generic, tvb, 0, -1, ENC_BIG_ENDIAN);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_generic );

      dissect_cip_generic_data( class_tree, tvb, 0, tvb_length(tvb), pinfo, ti );
   }

   return tvb_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Message Router
 *
 ************************************************/

static void
dissect_cip_mr_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{

typedef struct mr_mult_req_info {
   guint8 service;
   int num_services;
   cip_req_info_t *requests;
} mr_mult_req_info_t;

   proto_item *pi, *rrsc_item, *temp_item, *temp_item2;
   proto_tree *temp_tree, *rrsc_tree, *cmd_data_tree;
   int req_path_size;
   int i;
   unsigned char gen_status;
   unsigned char add_stat_size;
   int num_services, serv_offset;
   unsigned char service;
   mr_mult_req_info_t *mr_mult_req_info;
   cip_req_info_t *mr_single_req_info;
   cip_req_info_t *cip_req_info;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP MR");

   /* Add Service code & Request/Response tree */
   rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_mr_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_rr, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   /* watch for service collisions */
   service = tvb_get_guint8( tvb, offset );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals, "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   if( tvb_get_guint8( tvb, offset ) & 0x80 )
   {
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_mr_cmd_data );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
           /* Success responses */

            if( ( tvb_get_guint8( tvb, offset ) & 0x7F ) == SC_MULT_SERV_PACK )
            {
               /* Multiple Service Reply (Success)*/

               /* Add number of replies */
               num_services = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 2, "Number of Replies: %d", num_services );

               /* Add replies */
               temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+add_stat_size+4, num_services*2, "Offsets: " );

               cip_req_info = (cip_req_info_t*)p_get_proto_data( pinfo->fd, proto_cip );
               mr_mult_req_info = NULL;
               if ( cip_req_info )
               {
                  mr_mult_req_info = (mr_mult_req_info_t*)cip_req_info->pData;

                  if (  mr_mult_req_info
                     && (  mr_mult_req_info->service != SC_MULT_SERV_PACK
                        || mr_mult_req_info->num_services != num_services
                        )
                     )
                     mr_mult_req_info = NULL;
               }

               for( i=0; i < num_services; i++ )
               {
                  int serv_length;
                  tvbuff_t *next_tvb;

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
                  temp_tree = proto_item_add_subtree( temp_item2, ett_mr_mult_ser );

                  /*
                  ** We call our selves again to disect embedded packet
                  */

                  col_append_str( pinfo->cinfo, COL_INFO, ", ");

                  next_tvb = tvb_new_subset(tvb, offset+serv_offset+4, serv_length, serv_length);
                  if ( mr_mult_req_info )
                  {
                     mr_single_req_info = mr_mult_req_info->requests + i;
                     dissect_cip_data( temp_tree, next_tvb, 0, pinfo, mr_single_req_info );
                  }
                  else
                  {
                     dissect_cip_data( temp_tree, next_tvb, 0, pinfo, NULL );
                  }
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

            } /* End if GetAttrList */
            else
            {
               /* Add data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
            } /* end of check service code */

         }
         else
         {
            /* Error responses */

            /* Add data */
            add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );

         } /* end of if-else( CI_CRC_SUCCESS ) */

      } /* End of if command-specific data present */

   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                   cip_sc_vals, "Unknown Service (0x%02x)") );

	  /* Add path size to tree */
      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {

         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_mr_cmd_data );

         /* Check what service code that recived */

         if( tvb_get_guint8( tvb, offset ) == SC_MULT_SERV_PACK )
         {
            /* Multiple service packet */

            /* Add number of services */
            num_services = tvb_get_letohs( tvb, offset+2+req_path_size );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 2, "Number of Services: %d", num_services );

            /* Add services */
            temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, num_services*2, "Offsets: " );

            cip_req_info = (cip_req_info_t*)p_get_proto_data( pinfo->fd, proto_cip );

            mr_mult_req_info = NULL;
            if ( cip_req_info )
            {
               if ( cip_req_info->pData == NULL )
               {
                  mr_mult_req_info = se_alloc(sizeof(mr_mult_req_info_t));
                  mr_mult_req_info->service = SC_MULT_SERV_PACK;
                  mr_mult_req_info->num_services = num_services;
                  mr_mult_req_info->requests = se_alloc(sizeof(cip_req_info_t)*num_services);
                  cip_req_info->pData = mr_mult_req_info;
               }
               else
               {
                  mr_mult_req_info = (mr_mult_req_info_t*)cip_req_info->pData;
                  if ( mr_mult_req_info && mr_mult_req_info->num_services != num_services )
                     mr_mult_req_info = NULL;
               }
            }
            for( i=0; i < num_services; i++ )
            {
               int serv_length;
               tvbuff_t *next_tvb;

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
               temp_tree = proto_item_add_subtree( temp_item2, ett_mr_mult_ser );

               /*
               ** We call our selves again to disect embedded packet
               */

               col_append_str( pinfo->cinfo, COL_INFO, ", ");

               next_tvb = tvb_new_subset(tvb, offset+serv_offset+6, serv_length, serv_length);

               if ( mr_mult_req_info )
               {
                  mr_single_req_info = mr_mult_req_info->requests + i;
                  mr_single_req_info->bService = 0;
                  mr_single_req_info->dissector = NULL;
                  mr_single_req_info->IOILen = 0;
                  mr_single_req_info->pIOI = NULL;
                  mr_single_req_info->pData = NULL;

                  dissect_cip_data( temp_tree, next_tvb, 0, pinfo, mr_single_req_info );
               }
               else
               {
                  dissect_cip_data( temp_tree, next_tvb, 0, pinfo, NULL );
               }
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

   } /* End of if-else( request ) */

} /* End of dissect_cip_mr() */

static int
dissect_cip_class_mr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_mr, tvb, 0, -1, ENC_BIG_ENDIAN);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_mr );

      dissect_cip_mr_data( class_tree, tvb, 0, tvb_length(tvb), pinfo );
   }

   return tvb_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Connection Manager
 *
 ************************************************/

static void
dissect_cip_cm_timeout(proto_tree *cmd_tree, tvbuff_t *tvb, int offset)
{
   unsigned char temp_byte;
   int temp_data;

   /* Display the priority/tick timer */
   temp_byte = tvb_get_guint8( tvb, offset);
   proto_tree_add_text( cmd_tree, tvb, offset, 1, "Priority/Time_tick: 0x%02X", temp_byte );

   /* Display the time-out ticks */
   temp_data = tvb_get_guint8( tvb, offset+1 );
   proto_tree_add_text( cmd_tree, tvb, offset+1, 1, "Time-out_ticks: %d", temp_data );

   /* Display the actual time out */
   temp_data = ( 1 << ( temp_byte & 0x0F ) ) * temp_data;
   proto_tree_add_text( cmd_tree, tvb, offset, 2, "Actual Time Out: %dms", temp_data );
}

static void
dissect_cip_cm_fwd_open_req(proto_tree *cmd_tree, tvbuff_t *tvb, int offset, gboolean large_fwd_open)
{
   proto_item *pi, *ncppi;
   proto_tree *ncp_tree;
   int conn_path_size, temp_data, net_param_offset = 0;

   /* Display timeout fields */
   dissect_cip_cm_timeout(cmd_tree, tvb, offset);

   /* Display originator to taget connection ID */
   proto_tree_add_item( cmd_tree, hf_cip_cm_ot_connid, tvb, offset+2, 4, ENC_LITTLE_ENDIAN);

   /* Display target to originator connection ID */
   proto_tree_add_item( cmd_tree, hf_cip_cm_to_connid, tvb, offset+6, 4, ENC_LITTLE_ENDIAN);

   /* Display connection serial number */
   proto_tree_add_item( cmd_tree, hf_cip_cm_conn_serial_num, tvb, offset+10, 2, ENC_LITTLE_ENDIAN);

   /* Display the originator vendor id */
   proto_tree_add_item( cmd_tree, hf_cip_vendor, tvb, offset+12, 2, ENC_LITTLE_ENDIAN);

   /* Display the originator serial number */
   proto_tree_add_item( cmd_tree, hf_cip_cm_orig_serial_num, tvb, offset+14, 4, ENC_LITTLE_ENDIAN);

   /* Display the timeout multiplier */
   temp_data = tvb_get_guint8( tvb, offset+18 );
   proto_tree_add_text( cmd_tree, tvb, offset+18, 1, "Connection Timeout Multiplier: %s (%d)", val_to_str( temp_data, cip_con_time_mult_vals , "Reserved" ), temp_data );

   /* Put out an indicator for the reserved bytes */
   proto_tree_add_text( cmd_tree, tvb, offset+19, 3, "Reserved Data" );

   /* Display originator to target requested packet interval */
   temp_data = tvb_get_letohl( tvb, offset+22 );
   proto_tree_add_text( cmd_tree, tvb, offset+22, 4, "O->T RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

   /* Display originator to target network connection parameters, in a tree */
   if (large_fwd_open)
   {
      temp_data = tvb_get_letohl( tvb, offset+26 );
      ncppi = proto_tree_add_text(cmd_tree, tvb, offset+26, 4, "O->T Network Connection Parameters: 0x%08X", temp_data );
      ncp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

      /* Add the data to the tree */
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_own, tvb, offset+26, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_typ, tvb, offset+26, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_prio, tvb, offset+26, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_fixed_var, tvb, offset+26, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_con_size, tvb, offset+26, 4, ENC_LITTLE_ENDIAN );

      net_param_offset = 4;
   }
   else
   {
      temp_data = tvb_get_letohs( tvb, offset+26 );
      ncppi = proto_tree_add_text(cmd_tree, tvb, offset+26, 2, "O->T Network Connection Parameters: 0x%04X", temp_data );
      ncp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

      /* Add the data to the tree */
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_own, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_typ, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_prio, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_fixed_var, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_con_size, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
      net_param_offset = 2;
   }

   /* Display target to originator requested packet interval */
   temp_data = tvb_get_letohl( tvb, offset+26+net_param_offset );
   proto_tree_add_text( cmd_tree, tvb, offset+26+net_param_offset, 4, "T->O RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

   /* Display target to originator network connection parameters, in a tree */
   if (large_fwd_open)
   {
      temp_data = tvb_get_letohl( tvb, offset+26+net_param_offset+4 );
      ncppi = proto_tree_add_text(cmd_tree, tvb, offset+26+net_param_offset+4, 4, "T->O Network Connection Parameters: 0x%04X", temp_data );
      ncp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

      /* Add the data to the tree */
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_own, tvb, offset+26+net_param_offset+4, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_typ, tvb, offset+26+net_param_offset+4, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_prio, tvb, offset+26+net_param_offset+4, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_fixed_var, tvb, offset+26+net_param_offset+4, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_lfwo_con_size, tvb, offset+26+net_param_offset+4, 4, ENC_LITTLE_ENDIAN );

      net_param_offset += 4;
   }
   else
   {
      temp_data = tvb_get_letohs( tvb, offset+26+net_param_offset+4 );
      ncppi = proto_tree_add_text(cmd_tree, tvb, offset+26+net_param_offset+4, 2, "T->O Network Connection Parameters: 0x%04X", temp_data );
      ncp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

      /* Add the data to the tree */
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_own, tvb, offset+26+net_param_offset+4, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_typ, tvb, offset+26+net_param_offset+4, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_prio, tvb, offset+26+net_param_offset+4, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_fixed_var, tvb, offset+26+net_param_offset+4, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_con_size, tvb, offset+26+net_param_offset+4, 2, ENC_LITTLE_ENDIAN );
      net_param_offset += 2;
   }

   /* Transport type/trigger in tree */
   temp_data = tvb_get_guint8( tvb, offset+26+net_param_offset+4 );

   ncppi = proto_tree_add_text(cmd_tree, tvb, offset+26+net_param_offset+4, 1, "Transport Type/Trigger: 0x%02X", temp_data );
   ncp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

   /* Add the data to the tree */
   proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_dir, tvb, offset+26+net_param_offset+4, 1, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_trigg, tvb, offset+26+net_param_offset+4, 1, ENC_LITTLE_ENDIAN );
   proto_tree_add_item(ncp_tree, hf_cip_cm_fwo_class, tvb, offset+26+net_param_offset+4, 1, ENC_LITTLE_ENDIAN );

   /* Add path size */
   conn_path_size = tvb_get_guint8( tvb, offset+26+net_param_offset+5 )*2;
   proto_tree_add_text( cmd_tree, tvb, offset+26+net_param_offset+5, 1, "Connection Path Size: %d (words)", conn_path_size / 2 );

   /* Add the epath */
   pi = proto_tree_add_text(cmd_tree, tvb, offset+26+net_param_offset+6, conn_path_size, "Connection Path: ");
   dissect_epath( tvb, pi, offset+26+net_param_offset+6, conn_path_size, FALSE );
}

static void
dissect_cip_cm_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *pi, *rrsc_item, *ar_item, *temp_item;
   proto_tree *temp_tree, *rrsc_tree, *cmd_data_tree;
   int req_path_size, conn_path_size, temp_data;
   unsigned char service, gen_status, add_stat_size;
   unsigned short add_status;
   unsigned char temp_byte, route_path_size;
   unsigned char app_rep_size, i;
   int msg_req_siz;
   cip_req_info_t *preq_info;
   cip_req_info_t *pembedded_req_info;

   service = tvb_get_guint8( tvb, offset );

   /* Special handling for Unconnected send response. If successful, embedded service code is sent.
    * If failed, it can be either an Unconnected send response or the embedded service code response. */
   preq_info = (cip_req_info_t*)p_get_proto_data( pinfo->fd, proto_cip );
   if (  preq_info != NULL && ( service & 0x80 )
      && preq_info->bService == SC_CM_UNCON_SEND
      )
   {
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;
      if ( add_stat_size == 2 )
         add_status = tvb_get_letohs( tvb, offset + 4 );
      else
         add_status = 0;
      if(   gen_status == 0   /* success response ) */
         || ( ( service & 0x7F ) != SC_CM_UNCON_SEND )
         || !(  ( gen_status == 0x01 && ( add_status == 0x0204 || add_status == 0x0311 || add_status == 0x0312 || add_status == 0x0315 ) )
             || gen_status == 0x02
             || gen_status == 0x04
             )
         )
      {
         pembedded_req_info = (cip_req_info_t*)preq_info->pData;

         if ( pembedded_req_info )
         {
            tvbuff_t *next_tvb;
            void *p_save_proto_data;

            p_save_proto_data = p_get_proto_data( pinfo->fd, proto_cip );
            p_remove_proto_data(pinfo->fd, proto_cip);
            p_add_proto_data(pinfo->fd, proto_cip, pembedded_req_info );

            proto_tree_add_text( item_tree, NULL, 0, 0, "(Service: Unconnected Send (Response))" );
            next_tvb = tvb_new_subset(tvb, offset, item_length, item_length);
            if ( pembedded_req_info && pembedded_req_info->dissector )
               call_dissector(pembedded_req_info->dissector, next_tvb, pinfo, item_tree );
            else
               call_dissector( cip_class_generic_handle, next_tvb, pinfo, item_tree );

            p_remove_proto_data(pinfo->fd, proto_cip);
            p_add_proto_data(pinfo->fd, proto_cip, p_save_proto_data);
            return;
         }
      }
   }

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP CM");

   /* Add Service code & Request/Response tree */
   rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_cm_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_rr, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   /* watch for service collisions */
   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_cm , "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   if( service & 0x80 )
   {
      /* Response message */
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cm_cmd_data );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
           /* Success responses */
           switch (service & 0x7F)
           {
           case SC_CM_FWD_OPEN:
           case SC_CM_LARGE_FWD_OPEN:
           {
               /* Forward open Response (Success) */
               guint32 O2TConnID;
               guint32 T2OConnID;
               guint16 ConnSerialNumber;
               guint32 DeviceSerialNumber;
               guint16 VendorID;

               /* Display originator to target connection ID */
               O2TConnID = tvb_get_letohl( tvb, offset+4+add_stat_size );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_ot_connid, tvb, offset+4+add_stat_size, 4, ENC_LITTLE_ENDIAN);

               /* Display target to originator connection ID */
               T2OConnID = tvb_get_letohl( tvb, offset+4+add_stat_size+4 );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_to_connid, tvb, offset+4+add_stat_size+4, 4, ENC_LITTLE_ENDIAN);

               /* Display connection serial number */
               ConnSerialNumber = tvb_get_letohs( tvb, offset+4+add_stat_size+8 );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+4+add_stat_size+8, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator vendor id */
               VendorID = tvb_get_letohs( tvb, offset+4+add_stat_size+10 );
               proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+4+add_stat_size+10, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator serial number */
               DeviceSerialNumber = tvb_get_letohl( tvb, offset+4+add_stat_size+12 );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+4+add_stat_size+12, 4, ENC_LITTLE_ENDIAN);

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
               proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+4+add_stat_size+25, 1, ENC_LITTLE_ENDIAN );

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

               enip_open_cip_connection( pinfo, ConnSerialNumber, VendorID, DeviceSerialNumber, O2TConnID, T2OConnID );

           } /* End of if forward open response */
           break;
           case SC_CM_FWD_CLOSE:
           {
               /* Forward close response (Success) */
               guint16 ConnSerialNumber;
               guint32 DeviceSerialNumber;
               guint16 VendorID;

               /* Display connection serial number */
               ConnSerialNumber = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+4+add_stat_size, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator vendor id */
               VendorID = tvb_get_letohs( tvb, offset+4+add_stat_size+2 );
               proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+4+add_stat_size+2, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator serial number */
               DeviceSerialNumber = tvb_get_letohl( tvb, offset+4+add_stat_size+4 );
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+4+add_stat_size+4, 4, ENC_LITTLE_ENDIAN);

               /* Display the application reply size */
               app_rep_size = tvb_get_guint8( tvb, offset+4+add_stat_size+8 ) * 2;
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+8, 1, "Application Reply Size: %d (words)", app_rep_size / 2 );

               /* Display the Reserved byte */
               proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+4+add_stat_size+9, 1, ENC_LITTLE_ENDIAN );

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

               enip_close_cip_connection( pinfo, ConnSerialNumber, VendorID, DeviceSerialNumber );

            } /* End of if forward close response */
            break;
            case SC_CM_UNCON_SEND:
            {
               /* Unconnected send response (Success) */

               /* Display service response data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
            }
            break;
            case SC_CM_GET_CONN_OWNER:
            {
               /* Get Connection owner response (Success) */

               /* Display number of connections */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_conn, tvb, offset+4+add_stat_size, 1, ENC_LITTLE_ENDIAN);

               /* Display number of COO connections */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_coo_conn, tvb, offset+4+add_stat_size+1, 1, ENC_LITTLE_ENDIAN);

               /* Display number of ROO connections */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_roo_conn, tvb, offset+4+add_stat_size+2, 1, ENC_LITTLE_ENDIAN);

               /* Display Last Action */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_gco_la, tvb, offset+4+add_stat_size+3, 1, ENC_LITTLE_ENDIAN);

               /* Display connection serial number */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+4+add_stat_size+4, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator vendor id */
               proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+4+add_stat_size+6, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator serial number */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+4+add_stat_size+8, 4, ENC_LITTLE_ENDIAN);
            }
            break;
            case SC_GET_ATT_LIST:
            {
               /* Get Attribute List Reply (Success)*/

               int att_count;

               /* Add Attribute Count */
               att_count = tvb_get_letohs( tvb, offset+4+add_stat_size );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 2, "Attribute Count: %d", att_count );

               /* Add the data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+6+add_stat_size, item_length-6-add_stat_size, "Data: " );

            } /* Get Attribute List Reply */
            break;
            default:
               /* Add data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
               break;
            }
         }
         else
         {
            /* Error responses */
            switch (service & 0x7F)
            {
            case SC_CM_FWD_OPEN:
            case SC_CM_LARGE_FWD_OPEN:
            case SC_CM_FWD_CLOSE:
               /* Forward open and forward close error response look the same */

               /* Display connection serial number */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+4+add_stat_size, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator vendor id */
               proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+4+add_stat_size+2, 2, ENC_LITTLE_ENDIAN);

               /* Display the originator serial number */
               proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+4+add_stat_size+4, 4, ENC_LITTLE_ENDIAN);

               /* Display remaining path size */
               temp_data = tvb_get_guint8( tvb, offset+4+add_stat_size+8 );
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+8, 1, "Remaining Path Size: %d", temp_data );

               /* Display the Reserved byte */
               proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+4+add_stat_size+9, 1, ENC_LITTLE_ENDIAN );
               break;
            case SC_CM_UNCON_SEND:
               /* Unconnected send response (Unsuccess) */

               /* Display remaining path size */
               temp_data = tvb_get_guint8( tvb, offset+4+add_stat_size);
               proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 1, "Remaining Path Size: %d", temp_data );
               break;
            default:
               /* Add data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
               break;
            }
         } /* end of if-else( CI_CRC_SUCCESS ) */

      } /* End of if command-specific data present */

   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                  cip_sc_vals_cm , "Unknown Service (0x%02x)") );
      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data creat a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {

         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cm_cmd_data );

         /* Check what service code that received */
         switch (service)
         {
         case SC_CM_FWD_OPEN:
            /* Forward open Request*/
            dissect_cip_cm_fwd_open_req(cmd_data_tree, tvb, offset+2+req_path_size, ENC_BIG_ENDIAN);
            break;
         case SC_CM_LARGE_FWD_OPEN:
            /* Large Forward open Request*/
            dissect_cip_cm_fwd_open_req(cmd_data_tree, tvb, offset+2+req_path_size, ENC_LITTLE_ENDIAN);
            break;
         case SC_CM_FWD_CLOSE:
            /* Forward Close Request */

            /* Display timeout fields */
            dissect_cip_cm_timeout( cmd_data_tree, tvb, offset+2+req_path_size);

            /* Display connection serial number */
            proto_tree_add_item( cmd_data_tree, hf_cip_cm_conn_serial_num, tvb, offset+2+req_path_size+2, 2, ENC_LITTLE_ENDIAN);

            /* Display the originator vendor id */
            proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+2+req_path_size+4, 2, ENC_LITTLE_ENDIAN);

            /* Display the originator serial number */
            proto_tree_add_item( cmd_data_tree, hf_cip_cm_orig_serial_num, tvb, offset+2+req_path_size+6, 4, ENC_LITTLE_ENDIAN);

            /* Add the path size */
            conn_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+10 )*2;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+10, 1, "Connection Path Size: %d (words)", conn_path_size / 2 );

            /* Display the Reserved byte */
            proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+2+req_path_size+11, 1, ENC_LITTLE_ENDIAN );

            /* Add the EPATH */
            pi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+12, conn_path_size, "Connection Path: ");
            dissect_epath( tvb, pi, offset+2+req_path_size+12, conn_path_size, FALSE );
            break;
         case SC_CM_UNCON_SEND:
         {
            /* Unconnected send */
            tvbuff_t *next_tvb;

            /* Display timeout fields */
            dissect_cip_cm_timeout( cmd_data_tree, tvb, offset+2+req_path_size);

            /* Message request size */
            msg_req_siz = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, 2, "Message Request Size: 0x%04X", msg_req_siz );

            /* Message Request */
            temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+4, msg_req_siz, "Message Request" );
            temp_tree = proto_item_add_subtree(temp_item, ett_cm_mes_req );

            /*
            ** We call our selves again to disect embedded packet
            */

            col_append_str( pinfo->cinfo, COL_INFO, ": ");

            next_tvb = tvb_new_subset(tvb, offset+2+req_path_size+4, msg_req_siz, msg_req_siz);
            preq_info = p_get_proto_data( pinfo->fd, proto_cip );
            pembedded_req_info = NULL;
            if ( preq_info )
            {
               if ( preq_info->pData == NULL )
               {
                  pembedded_req_info = (cip_req_info_t*)se_alloc(sizeof(cip_req_info_t));
                  pembedded_req_info->bService = 0;
                  pembedded_req_info->dissector = NULL;
                  pembedded_req_info->IOILen = 0;
                  pembedded_req_info->pIOI = NULL;
                  pembedded_req_info->pData = NULL;
                  preq_info->pData = pembedded_req_info;
               }
               else
               {
                  pembedded_req_info = (cip_req_info_t*)preq_info->pData;
               }
            }
            dissect_cip_data( temp_tree, next_tvb, 0, pinfo, pembedded_req_info );

            if( msg_req_siz % 2 )
            {
              /* Pad byte */
              proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+4+msg_req_siz, 1, "Pad Byte (0x%02X)",
                         tvb_get_guint8( tvb, offset+2+req_path_size+4+msg_req_siz ) );
              msg_req_siz++;  /* include the padding */
            }

            /* Route Path Size */
            route_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+4+msg_req_siz )*2;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+4+msg_req_siz, 1, "Route Path Size: %d (words)", route_path_size/2 );

            /* Display the Reserved byte */
            proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+2+req_path_size+5+msg_req_siz, 1, ENC_LITTLE_ENDIAN );

            /* Route Path */
            temp_item = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+6+msg_req_siz, route_path_size, "Route Path: ");
            dissect_epath( tvb, temp_item, offset+2+req_path_size+6+msg_req_siz, route_path_size, FALSE );
         }
         break;
         case SC_CM_GET_CONN_OWNER:
            /* Get Connection Owner Request */

            /* Display the Reserved byte */
            proto_tree_add_item(cmd_data_tree, hf_cip_reserved8, tvb, offset+2+req_path_size, 1, ENC_LITTLE_ENDIAN );

            /* Add path size */
            conn_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+1 )*2;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+1, 1, "Connection Path Size: %d (words)", conn_path_size / 2 );

            /* Add the epath */
            pi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+2, conn_path_size, "Connection Path: ");
            dissect_epath( tvb, pi, offset+2+req_path_size+2, conn_path_size, FALSE );
            break;
         case SC_GET_ATT_LIST:
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
         break;
         default:
            /* Add data */
            add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Data: " );
         }

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

} /* End of dissect_cip_cm_data() */

static int
dissect_cip_class_cm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_cm, tvb, 0, -1, ENC_BIG_ENDIAN);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_cm );

      dissect_cip_cm_data( class_tree, tvb, 0, tvb_length(tvb), pinfo );
   }

   return tvb_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Connection Configuration Object
 *
 ************************************************/
static void
dissect_cip_cco_all_attribute_common( proto_tree *cmd_tree, tvbuff_t *tvb, int offset, int item_length)
{
   proto_item *pi, *tdii, *ncpi, *ncppi, *iomapi, *confgi;
   proto_tree *tdi_tree, *iomap_tree;
   proto_tree *ncp_tree, *ncpp_tree, *confg_tree;
   int conn_path_size, variable_data_size = 0, config_data_size;
   int connection_name_size, iomap_size, ot_rtf, to_rtf;
   int temp_data, temp_data2;
   char* str_connection_name;

   /* Connection flags */
   temp_data = tvb_get_letohs( tvb, offset);
   ot_rtf = (temp_data >> 1) & 7;
   to_rtf = (temp_data >> 4) & 7;
   confgi = proto_tree_add_text( cmd_tree, tvb, offset, 2, "Connection Flags: 0x%04X", temp_data );
   confg_tree = proto_item_add_subtree(confgi, ett_cco_con_flag);

      /* Add the data to the tree */
      proto_tree_add_item(confg_tree, hf_cip_cco_con_type, tvb, offset, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(confg_tree, hf_cip_cco_ot_rtf, tvb, offset, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item(confg_tree, hf_cip_cco_to_rtf, tvb, offset, 2, ENC_LITTLE_ENDIAN );

   /* Target device id */
   tdii = proto_tree_add_text( cmd_tree, tvb, offset+2, 10, "Target Device ID");
   tdi_tree = proto_item_add_subtree(tdii, ett_cco_tdi);

      /* Target Vendor ID */
      proto_tree_add_item(tdi_tree, hf_cip_vendor, tvb, offset+2, 2, ENC_LITTLE_ENDIAN);

      /* Target Device Type */
      proto_tree_add_item(tdi_tree, hf_cip_devtype, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);

      /* Target Product Code */
      temp_data = tvb_get_letohs( tvb, offset+6);
      proto_tree_add_text(tdi_tree, tvb, offset+6, 2, "Product Code: 0x%04X", temp_data );

      /* Target Major/Minor revision*/
      temp_data = tvb_get_guint8( tvb, offset+8);
      temp_data2 = tvb_get_guint8( tvb, offset+9);
      proto_tree_add_text(tdi_tree, tvb, offset+8, 2, "Revision %d.%d", temp_data, temp_data2);

   /* CS Data Index Number */
   temp_data = tvb_get_letohl( tvb, offset+10);
   proto_tree_add_text( cmd_tree, tvb, offset+10, 4, "CS Data Index Number: 0x%08X", temp_data );

   /* Net Connection Parameters */
   ncpi = proto_tree_add_text( cmd_tree, tvb, offset+14, 14, "Net Connection Parameters");
   ncp_tree = proto_item_add_subtree(ncpi, ett_cco_ncp);

      /* Timeout multiplier */
      temp_data = tvb_get_guint8( tvb, offset+14);
      proto_tree_add_text(ncp_tree, tvb, offset+14, 1, "Connection Timeout Multiplier: %s (%d)", val_to_str( temp_data, cip_con_time_mult_vals , "Reserved" ), temp_data );

      /* Transport type/trigger in tree*/
      temp_data = tvb_get_guint8( tvb, offset+15 );

      ncppi = proto_tree_add_text(ncp_tree, tvb, offset+15, 1, "Transport Type/Trigger: 0x%02X", temp_data );
      ncpp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

         /* Add the data to the tree */
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_dir, tvb, offset+15, 1, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_trigg, tvb, offset+15, 1, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_class, tvb, offset+15, 1, ENC_LITTLE_ENDIAN );

      temp_data = tvb_get_letohl( tvb, offset+16);
      proto_tree_add_text(ncp_tree, tvb, offset+16, 4, "O->T RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

      /* Display originator to target network connection patameterts, in a tree */
      temp_data = tvb_get_letohs( tvb, offset+20 );
      ncppi = proto_tree_add_text(ncp_tree, tvb, offset+20, 2, "O->T Network Connection Parameters: 0x%04X", temp_data );
      ncpp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

         /* Add the data to the tree */
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_own, tvb, offset+20, 2, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_typ, tvb, offset+20, 2, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_prio, tvb, offset+20, 2, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_fixed_var, tvb, offset+20, 2, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_con_size, tvb, offset+20, 2, ENC_LITTLE_ENDIAN );

      temp_data = tvb_get_letohl( tvb, offset+22);
      proto_tree_add_text(ncp_tree, tvb, offset+22, 4, "T->O RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

      /* Display target to originator network connection patameters, in a tree */
      temp_data = tvb_get_letohs( tvb, offset+26);
      ncppi = proto_tree_add_text(ncp_tree, tvb, offset+26, 2, "T->O Network Connection Parameters: 0x%04X", temp_data );
      ncpp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

         /* Add the data to the tree */
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_own, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_typ, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_prio, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_fixed_var, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_con_size, tvb, offset+26, 2, ENC_LITTLE_ENDIAN );

   /* Connection Path */
   conn_path_size = tvb_get_guint8( tvb, offset+28 )*2;
   proto_tree_add_text( cmd_tree, tvb, offset+28, 1, "Connection Path Size: %d (words)", conn_path_size / 2 );

   /* Display the Reserved byte */
   proto_tree_add_item(cmd_tree, hf_cip_reserved8, tvb, offset+29, 1, ENC_LITTLE_ENDIAN );

   /* Add the epath */
   pi = proto_tree_add_text(cmd_tree, tvb, offset+30, conn_path_size, "Connection Path: ");
   dissect_epath( tvb, pi, offset+30, conn_path_size, FALSE );

   variable_data_size += (conn_path_size+30);

   /* Config #1 Data */
      config_data_size = tvb_get_letohs( tvb, offset+variable_data_size);
   proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, 2, "Proxy Config Data Size %d", config_data_size);
   if (config_data_size > 0)
      add_byte_array_text_to_proto_tree( cmd_tree, tvb, offset+variable_data_size+2, config_data_size, "Proxy Config Data: " );

   variable_data_size += (config_data_size+2);

   /* Config #2 Data */
      config_data_size = tvb_get_letohs( tvb, offset+variable_data_size);
   proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, 2, "Target Config Data Size %d", config_data_size);
   if (config_data_size > 0)
      add_byte_array_text_to_proto_tree( cmd_tree, tvb, offset+variable_data_size+2, config_data_size, "Target Config Data: " );

   variable_data_size += (config_data_size+2);

   /* Connection Name */
   connection_name_size = tvb_get_guint8( tvb, offset+variable_data_size);
   str_connection_name = tvb_get_ephemeral_faked_unicode(tvb, offset+variable_data_size+2, connection_name_size, ENC_LITTLE_ENDIAN);
   proto_tree_add_text(cmd_tree, tvb, offset+variable_data_size, connection_name_size+2, "Connection Name: %s", str_connection_name);

   variable_data_size += ((connection_name_size*2)+2);

   /* I/O Mapping */
   iomap_size = tvb_get_letohs( tvb, offset+variable_data_size+2);

   iomapi = proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, iomap_size+2, "I/O Mapping");
   iomap_tree = proto_item_add_subtree(iomapi, ett_cco_iomap);

      /* Format number */
      temp_data = tvb_get_guint8( tvb, offset+variable_data_size);
      proto_tree_add_text(iomap_tree, tvb, offset+variable_data_size, 2, "Format number: %d", temp_data );

      /* Attribute size */
      proto_tree_add_text(iomap_tree, tvb, offset+variable_data_size+2, 2, "Attribute size: %d (bytes)", iomap_size);

      /* Attribute data */
      if (iomap_size > 0)
         add_byte_array_text_to_proto_tree( iomap_tree, tvb, offset+variable_data_size+4, iomap_size, "Attribute Data: " );

   variable_data_size += (iomap_size+4);

   /* Proxy device id */
   tdii = proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, 10, "Proxy Device ID");
   tdi_tree = proto_item_add_subtree(tdii, ett_cco_tdi);

      /* Proxy Vendor ID */
      temp_data = tvb_get_letohs( tvb, offset+variable_data_size);
      proto_tree_add_item(tdi_tree, hf_cip_vendor, tvb, offset+variable_data_size, 2, ENC_LITTLE_ENDIAN);

      /* Proxy Device Type */
      temp_data = tvb_get_letohs( tvb, offset+variable_data_size+2);
      proto_tree_add_item(tdi_tree, hf_cip_devtype, tvb, offset+variable_data_size+2, 2, ENC_LITTLE_ENDIAN);

      /* Proxy Product Code */
      temp_data = tvb_get_letohs( tvb, offset+variable_data_size+4);
      proto_tree_add_text(tdi_tree, tvb, offset+variable_data_size+4, 2, "Product Code: 0x%04X", temp_data );

      /* Proxy Major/Minor revision*/
      temp_data = tvb_get_guint8( tvb, offset+variable_data_size+6);
      temp_data2 = tvb_get_guint8( tvb, offset+variable_data_size+7);
      proto_tree_add_text(tdi_tree, tvb, offset+variable_data_size+6, 2, "Revision %d.%d", temp_data, temp_data2);

   /* Add in proxy device id size */
   variable_data_size += 8;

   if ((offset+variable_data_size < item_length) &&
       ((ot_rtf == 5) || (to_rtf == 5)))
   {
      /* Safety parameters */
      add_byte_array_text_to_proto_tree( cmd_tree, tvb, offset+variable_data_size, 55, "Safety Parameters: " );

      variable_data_size += 55;
   }

   if (offset+variable_data_size < item_length)
   {
      /* Connection disable */
      temp_data = tvb_get_guint8( tvb, offset+variable_data_size) & 1;
      proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, 1, "Connection Disable: %d", temp_data );

      variable_data_size++;
   }

   if (offset+variable_data_size < item_length)
   {
      /* Net Connection Parameter Attribute Selection */
      temp_data = tvb_get_guint8( tvb, offset+variable_data_size);
      proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, 1, "Net Connection Parameter Attribute Selection: %d", temp_data );

      variable_data_size++;
   }

   if (offset+variable_data_size < item_length)
   {
      /* Large Net Connection Parameter */
      ncpi = proto_tree_add_text( cmd_tree, tvb, offset+variable_data_size, 18, "Large Net Connection Parameters");
      ncp_tree = proto_item_add_subtree(ncpi, ett_cco_ncp);

      /* Timeout multiplier */
      temp_data = tvb_get_guint8( tvb, offset+variable_data_size);
      proto_tree_add_text(ncp_tree, tvb, offset+variable_data_size, 1, "Connection Timeout Multiplier: %s (%d)", val_to_str( temp_data, cip_con_time_mult_vals , "Reserved" ), temp_data );

      /* Transport type/trigger in tree*/
      temp_data = tvb_get_guint8( tvb, offset+variable_data_size+1);

      ncppi = proto_tree_add_text(ncp_tree, tvb, offset+variable_data_size+1, 1, "Transport Type/Trigger: 0x%02X", temp_data );
      ncpp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

         /* Add the data to the tree */
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_dir, tvb, offset+variable_data_size+1, 1, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_trigg, tvb, offset+variable_data_size+1, 1, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_fwo_class, tvb, offset+variable_data_size+1, 1, ENC_LITTLE_ENDIAN );

      temp_data = tvb_get_letohl( tvb, offset+variable_data_size+2);
      proto_tree_add_text(ncp_tree, tvb, offset+variable_data_size+2, 4, "O->T RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

      /* Display originator to target network connection patameterts, in a tree */
      temp_data = tvb_get_letohl(tvb, offset+variable_data_size+6);
      ncppi = proto_tree_add_text(ncp_tree, tvb, offset+variable_data_size+6, 4, "O->T Network Connection Parameters: 0x%08X", temp_data );
      ncpp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

         /* Add the data to the tree */
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_own, tvb, offset+variable_data_size+6, 4, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_typ, tvb, offset+variable_data_size+6, 4, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_prio, tvb, offset+variable_data_size+6, 4, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_fixed_var, tvb, offset+variable_data_size+6, 4, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_con_size, tvb, offset+variable_data_size+6, 4, ENC_LITTLE_ENDIAN );

      temp_data = tvb_get_letohl( tvb, offset+variable_data_size+10);
      proto_tree_add_text(ncp_tree, tvb, offset+variable_data_size+10, 4, "T->O RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

      /* Display target to originator network connection patameterts, in a tree */
      temp_data = tvb_get_letohl(tvb, offset+variable_data_size+14);
      ncppi = proto_tree_add_text(ncp_tree, tvb, offset+variable_data_size+14, 4, "T->0 Network Connection Parameters: 0x%08X", temp_data );
      ncpp_tree = proto_item_add_subtree(ncppi, ett_cm_ncp);

         /* Add the data to the tree */
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_own, tvb, offset+variable_data_size+14, 4, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_typ, tvb, offset+variable_data_size+14, 4, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_prio, tvb, offset+variable_data_size+14, 4, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_fixed_var, tvb, offset+variable_data_size+14, 4, ENC_LITTLE_ENDIAN );
         proto_tree_add_item(ncpp_tree, hf_cip_cm_lfwo_con_size, tvb, offset+variable_data_size+14, 4, ENC_LITTLE_ENDIAN );

      variable_data_size += 18;
   }
}

static void
dissect_cip_cco_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *pi, *rrsc_item, *temp_item, *con_sti;
   proto_tree *rrsc_tree, *cmd_data_tree, *con_st_tree;
   int req_path_size;
   int temp_data;
   guint8 service;
   unsigned char gen_status;
   unsigned char add_stat_size;
   unsigned char i;
   cip_req_info_t* preq_info;
   cip_simple_request_info_t req_data;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP CCO");

   /* Add Service code & Request/Response tree */
   service = tvb_get_guint8( tvb, offset );
   rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_cco_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_rr, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_cco , "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   /* Get path information for further dissection */
   req_data.iClass = (guint32)-1;
   req_data.iInstance = (guint32)-1;
   req_data.iAttribute = (guint32)-1;
   req_data.iMember = (guint32)-1;

   preq_info = p_get_proto_data(pinfo->fd, proto_cip);
   if ( preq_info )
   {
      if ( preq_info->IOILen && preq_info->pIOI )
      {
          tvbuff_t* tvbIOI;

          tvbIOI = tvb_new_real_data( preq_info->pIOI, preq_info->IOILen * 2, preq_info->IOILen * 2);
          if ( tvbIOI )
          {
             dissect_epath_request(tvbIOI, &req_data, preq_info->IOILen*2);
             tvb_free(tvbIOI);
          }
      }
   }

   if(service & 0x80 )
   {
      /* Response message */

      /* Add additional status size */
      gen_status = tvb_get_guint8( tvb, offset+2 );
      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cco_cmd_data );

         if( gen_status == CI_GRC_SUCCESS || gen_status == CI_GRC_SERVICE_ERROR )
         {
            /* Success responses */
            if (((service & 0x7F) == SC_GET_ATT_ALL) &&
                (req_data.iInstance != (guint32)-1))
            {
               if (req_data.iInstance == 0)
               {
                  /* Get Attribute All (class) request */

                  /* Revision */
                  proto_tree_add_item(cmd_data_tree, hf_cip_class_rev, tvb, offset+4+add_stat_size, 2, ENC_LITTLE_ENDIAN );

                  /* Max Instance */
                  proto_tree_add_item(cmd_data_tree, hf_cip_class_max_inst32, tvb, offset+4+add_stat_size+2, 4, ENC_LITTLE_ENDIAN );

                  /* Num Instance */
                  proto_tree_add_item(cmd_data_tree, hf_cip_class_num_inst32, tvb, offset+4+add_stat_size+6, 4, ENC_LITTLE_ENDIAN );

                  /* Format Number */
                  temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size+8);
                  proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+8, 2, "Format Number: %d", temp_data );

                  /* Edit Signature */
                  temp_data = tvb_get_letohl( tvb, offset+4+add_stat_size+10);
                  proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size+10, 4, "Edit Signature: 0x%08X", temp_data );
               }
               else
               {
                  /* Get Attribute All (instance) request */

                  /* Connection status */
                  con_sti = proto_tree_add_text( cmd_data_tree, tvb, offset+4+add_stat_size, 4, "Connection Status");
                  con_st_tree = proto_item_add_subtree(con_sti, ett_cco_con_status);

                     /* General Status */
                     proto_tree_add_item(con_st_tree, hf_cip_genstat, tvb, offset+4+add_stat_size, 1, ENC_LITTLE_ENDIAN );

                     /* Pad */
                     temp_data = tvb_get_guint8( tvb, offset+4+add_stat_size+1);
                     proto_tree_add_text(con_st_tree, tvb, offset+4+add_stat_size+1, 1, "Pad: %d", temp_data );

                     /* Extended Status */
                     temp_data = tvb_get_letohs( tvb, offset+4+add_stat_size+2);
                     proto_tree_add_text(con_st_tree, tvb, offset+4+add_stat_size+2, 2, "Extended Status: 0x%04X", temp_data );

                  dissect_cip_cco_all_attribute_common( cmd_data_tree, tvb, offset+4+add_stat_size+4, item_length);
               }
            }
            else
            {
               /* Add data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
            }
         }
         else
         {
            /* Error responses */

            /* Add data */
            add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Data: " );
         } /* end of if-else( CI_CRC_SUCCESS ) */

      } /* End of if command-specific data present */

   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add service to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals_cco , "Unknown Service (0x%02x)") );
      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;

      /* If there is any command specific data create a sub-tree for it */
      if( (item_length-req_path_size-2) != 0 )
      {

         pi = proto_tree_add_text( item_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Command Specific Data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cco_cmd_data );

         /* Check what service code that received */

         switch (service)
         {
         case SC_CCO_AUDIT_CHANGE:
             /* Audit Change */
            temp_data = tvb_get_letohs( tvb, offset+2+req_path_size);
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 2, "Change Type: %s (%d)", val_to_str( temp_data, cip_cco_change_type_vals , "Reserved" ), temp_data );
            break;

         case SC_GET_ATT_LIST:
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

         }
         break;
         case SC_CCO_CHANGE_COMPLETE:
            /* Change complete request */

            temp_data = tvb_get_letohs( tvb, offset+2+req_path_size);
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 2, "Change Type: %s (%d)", val_to_str( temp_data, cip_cco_change_type_vals , "Reserved" ), temp_data );
            break;
         case SC_SET_ATT_ALL:
            if ((req_data.iInstance == 0) ||
                (req_data.iInstance != (guint32)-1))
            {
               /* Just add raw data */
               add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Data: " );
               break;
            }

            /* Set Attribute All (instance) request */
            dissect_cip_cco_all_attribute_common(cmd_data_tree, tvb, offset+2+req_path_size, item_length);
            break;
         default:

            /* Add data */
            add_byte_array_text_to_proto_tree( cmd_data_tree, tvb, offset+2+req_path_size, item_length-req_path_size-2, "Data: " );
         } /* End of check service code */

      } /* End of if command-specific data present */

   } /* End of if-else( request ) */

} /* End of dissect_cip_cco_data() */

static int
dissect_cip_class_cco(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *class_tree;

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip_class_cco, tvb, 0, -1, ENC_BIG_ENDIAN);
      class_tree = proto_item_add_subtree( ti, ett_cip_class_cco );

      dissect_cip_cco_data( class_tree, tvb, 0, tvb_length(tvb), pinfo );
   }

   return tvb_length(tvb);
}

/************************************************
 *
 * Dissector for CIP Request/Response
 * - matches requests/responses
 * - calls class specific dissector
 *
 ************************************************/

static void
dissect_cip_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, packet_info *pinfo, cip_req_info_t* preq_info )
{
   proto_item *ti;
   proto_tree *cip_tree;
   proto_item *pi, *rrsc_item, *status_item;
   proto_tree *rrsc_tree, *status_tree;
   int req_path_size;
   unsigned char gen_status;
   unsigned char add_stat_size;
   unsigned char i;
   guint32 classid;
   unsigned char service,ioilen,segment;
   void *p_save_proto_data;
   dissector_handle_t dissector;

   p_save_proto_data = p_get_proto_data(pinfo->fd, proto_cip);
   p_remove_proto_data(pinfo->fd, proto_cip);
   p_add_proto_data(pinfo->fd, proto_cip, preq_info);

   /* Create display subtree for the protocol */
   ti = proto_tree_add_item(item_tree, proto_cip, tvb, 0, -1, ENC_BIG_ENDIAN);
   cip_tree = proto_item_add_subtree( ti, ett_cip );

   /* Add Service code & Request/Response tree */
   rrsc_item = proto_tree_add_text( cip_tree, tvb, offset, 1, "Service: " );
   rrsc_tree = proto_item_add_subtree( rrsc_item, ett_rrsc );

   /* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_rr, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   /* watch for service collisions */
   service = tvb_get_guint8( tvb, offset );
   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( service & 0x7F ),
                  cip_sc_vals , "Unknown Service (0x%02x)"),
               val_to_str( ( service & 0x80 )>>7,
                  cip_sc_rr, "") );

   /* Add Service code */
   proto_tree_add_item(rrsc_tree, hf_cip_sc, tvb, offset, 1, ENC_LITTLE_ENDIAN );

   if( service & 0x80 )
   {
      /* Response message */
      status_item = proto_tree_add_text( cip_tree, tvb, offset+2, 1, "Status: " );
      status_tree = proto_item_add_subtree( status_item, ett_status_item );

      /* Add general status */
      gen_status = tvb_get_guint8( tvb, offset+2 );
      proto_tree_add_item(status_tree, hf_cip_genstat, tvb, offset+2, 1, ENC_LITTLE_ENDIAN );
      proto_item_append_text( status_item, "%s", val_to_str( gen_status,
                     cip_gs_vals , "Unknown Response (%x)")   );

      /* Add reply status to info column */
      col_append_str( pinfo->cinfo, COL_INFO,
               val_to_str( ( tvb_get_guint8( tvb, offset+2 ) ),
                  cip_gs_vals , "Unknown Response (%x)") );

      /* Add additional status size */
      proto_tree_add_text( status_tree, tvb, offset+3, 1, "Additional Status Size: %d (word)",
         tvb_get_guint8( tvb, offset+3 ) );

      add_stat_size = tvb_get_guint8( tvb, offset+3 ) * 2;

      if( add_stat_size )
      {
         proto_item_append_text( status_item, ", Extended:" );

         /* Add additional status */
         pi = proto_tree_add_text( status_tree, tvb, offset+4, add_stat_size, "Additional Status:" );

         for( i=0; i < add_stat_size/2; i ++ )
         {
            proto_item_append_text( pi, " 0x%04X", tvb_get_letohs( tvb, offset+4+(i*2) ) );
            proto_item_append_text( status_item, " 0x%04X", tvb_get_letohs( tvb, offset+4+(i*2) ) );
         }
      }

      proto_item_set_len( status_item, 2 + add_stat_size );


      if(  preq_info
        && !(  preq_info->bService == ( service & 0x7F )
            || ( preq_info->bService == SC_CM_UNCON_SEND && preq_info->dissector == cip_class_cm_handle )
            )
        )
         preq_info = NULL;

      if ( preq_info )
      {
         if ( preq_info->IOILen && preq_info->pIOI )
         {
            tvbuff_t* tvbIOI;

            tvbIOI = tvb_new_real_data( preq_info->pIOI, preq_info->IOILen * 2, preq_info->IOILen * 2);
            if ( tvbIOI )
            {
#if 0
               pi = add_byte_array_text_to_proto_tree( cip_tree, tvbIOI, 0, req_path_size+1, "IOI: " );
               PROTO_ITEM_SET_GENERATED(pi);
#endif

               pi = proto_tree_add_text( cip_tree, NULL, 0, 0, "Request Path Size: %d (words)", preq_info->IOILen );
               PROTO_ITEM_SET_GENERATED(pi);

               /* Add the epath */
               pi = proto_tree_add_text(cip_tree, NULL, 0, 0, "Request Path: ");
               PROTO_ITEM_SET_GENERATED(pi);
               dissect_epath( tvbIOI, pi, 0, preq_info->IOILen*2, TRUE );
               tvb_free(tvbIOI);
            }
         }
      }

      if ( preq_info && preq_info->dissector )
      {
         call_dissector( preq_info->dissector, tvb, pinfo, item_tree );
      }
      else
      {
         call_dissector( cip_class_generic_handle, tvb, pinfo, item_tree );
      }
   } /* End of if reply */
   else
   {
      /* Request message */

      /* Add path size to tree */
      req_path_size = tvb_get_guint8( tvb, offset+1 )*2;
      proto_tree_add_text( cip_tree, tvb, offset+1, 1, "Request Path Size: %d (words)", req_path_size/2 );

      /* Add the epath */
      pi = proto_tree_add_text(cip_tree, tvb, offset+2, req_path_size, "Request Path: ");
      dissect_epath( tvb, pi, offset+2, req_path_size, FALSE );

      /* parse IOI; extract class ID */
      ioilen = tvb_get_guint8( tvb, offset + 1 );
      if ( preq_info )
         preq_info->dissector = NULL;
      dissector = NULL;
      if ( ioilen >= 1 )
      {
         segment = tvb_get_guint8( tvb, offset + 2 );
         switch ( segment & CI_SEGMENT_TYPE_MASK )
         {
         case CI_LOGICAL_SEGMENT:
            /* Logical segment, determin the logical type */
            switch( segment & CI_LOGICAL_SEG_TYPE_MASK )
            {
            case CI_LOGICAL_SEG_CLASS_ID:

               /* Logical Class ID, do a format check */
               classid = 0;
               switch ( segment & CI_LOGICAL_SEG_FORMAT_MASK )
               {
               case CI_LOGICAL_SEG_8_BIT:
                  classid = tvb_get_guint8( tvb, offset + 3 );
                  break;
               case CI_LOGICAL_SEG_16_BIT:
                  if ( ioilen >= 2 )
                     classid = tvb_get_letohs( tvb, offset + 4 );
                  break;
               case CI_LOGICAL_SEG_32_BIT:
                  if ( ioilen >= 3 )
                     classid = tvb_get_letohl( tvb, offset + 4 );
                  break;
               }
               dissector = dissector_get_uint_handle( subdissector_class_table, classid );
               if ( preq_info )
                  preq_info->dissector = dissector;
               break;
            }
            break;

         case CI_DATA_SEGMENT:
            dissector = dissector_get_uint_handle( subdissector_symbol_table, segment );
            if ( preq_info )
               preq_info->dissector = dissector;
            break;
         }
         if ( preq_info )
         {
            /* copy IOI for access by response packet */
            preq_info->pIOI = se_alloc( ioilen*2);
            preq_info->IOILen = ioilen;
            tvb_memcpy(tvb, preq_info->pIOI, offset+2, ioilen*2);
         }
      }

      if( preq_info )
         preq_info->bService = service;

      if ( dissector )
      {
         call_dissector( dissector, tvb, pinfo, item_tree );
      }
      else
      {
         call_dissector( cip_class_generic_handle, tvb, pinfo, item_tree );
      }
   } /* End of if-else( request ) */

   p_remove_proto_data(pinfo->fd, proto_cip);
   p_add_proto_data(pinfo->fd, proto_cip, p_save_proto_data);

} /* End of dissect_cip_data() */


static int
dissect_cip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   enip_request_info_t *enip_info;
   cip_req_info_t *preq_info;

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "CIP");

   col_clear(pinfo->cinfo, COL_INFO);

   /* Each CIP request received by ENIP gets a unique ID */
   enip_info = (enip_request_info_t*)p_get_proto_data(pinfo->fd, proto_enip);

   if ( enip_info )
   {
      preq_info = (cip_req_info_t*)enip_info->cip_info;
      if ( preq_info == NULL )
      {
         preq_info = se_alloc( sizeof( cip_req_info_t ) );
         preq_info->bService = 0;
         preq_info->dissector = NULL;
         preq_info->IOILen = 0;
         preq_info->pIOI = NULL;
         preq_info->pData = NULL;
         enip_info->cip_info = preq_info;
      }
      dissect_cip_data( tree, tvb, 0, pinfo, enip_info->cip_info );
   }
   else
   {
      dissect_cip_data( tree, tvb, 0, pinfo, NULL );
   }

   return tvb_length(tvb);
}

/*
 * Protocol initialization
 */

static void
cip_init_protocol(void)
{
   proto_enip = proto_get_id_by_filter_name( "enip" );
}

void
proto_register_cip(void)
{
   /* Setup list of header fields */
   static hf_register_info hf[] = {

      { &hf_cip_rr,
         { "Request/Response", "cip.rr",
         FT_UINT8, BASE_HEX, VALS(cip_sc_rr), 0x80,
         "Request or Response message", HFILL }
      },
      { &hf_cip_sc,
         { "Service", "cip.sc",
         FT_UINT8, BASE_HEX, VALS(cip_sc_vals), 0x7F,
         "Service Code", HFILL }
      },
      { &hf_cip_epath,
         { "EPath", "cip.epath",
         FT_BYTES, BASE_NONE, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_genstat,
         { "General Status", "cip.genstat",
         FT_UINT8, BASE_HEX, VALS(cip_gs_vals), 0,
         NULL, HFILL }
      },
      { &hf_cip_port,
         { "Port", "cip.port",
         FT_UINT8, BASE_DEC, NULL, 0,
         "Port Identifier", HFILL }
      },
      { &hf_cip_link_address_byte,
         { "Link Address", "cip.linkaddress",
         FT_UINT8, BASE_DEC, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_link_address_string,
         { "Link Address", "cip.linkaddress",
         FT_STRING, BASE_NONE, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_class8,
         { "Class", "cip.class",
         FT_UINT8, BASE_HEX, VALS(cip_class_names_vals), 0,
         NULL, HFILL }
      },
      { &hf_cip_class16,
         { "Class", "cip.class",
         FT_UINT16, BASE_HEX, VALS(cip_class_names_vals), 0,
         NULL, HFILL }
      },
      { &hf_cip_class32,
         { "Class", "cip.class",
         FT_UINT32, BASE_HEX, VALS(cip_class_names_vals), 0,
         NULL, HFILL }
      },
      { &hf_cip_instance8,
         { "Instance", "cip.instance",
         FT_UINT8, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_instance16,
         { "Instance", "cip.instance",
         FT_UINT16, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_instance32,
         { "Instance", "cip.instance",
         FT_UINT32, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_member8,
         { "Member", "cip.member",
         FT_UINT8, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_member16,
         { "Member", "cip.member",
         FT_UINT16, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_member32,
         { "Member", "cip.member",
         FT_UINT32, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_attribute8,
         { "Attribute", "cip.attribute",
         FT_UINT8, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_attribute16,
         { "Attribute", "cip.attribute",
         FT_UINT16, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_attribute32,
         { "Attribute", "cip.attribute",
         FT_UINT32, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_conpoint8,
         { "Connection Point", "cip.connpoint",
         FT_UINT8, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_conpoint16,
         { "Connection Point", "cip.connpoint",
         FT_UINT16, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_conpoint32,
         { "Connection Point", "cip.connpoint",
         FT_UINT16, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_symbol,
         { "Symbol", "cip.symbol",
         FT_STRING, BASE_NONE, NULL, 0,
         "ANSI Extended Symbol Segment", HFILL }
      },
      { &hf_cip_vendor,
         { "Vendor ID", "cip.vendor",
         FT_UINT16, BASE_HEX, VALS(cip_vendor_vals), 0,
         NULL, HFILL }
      },
      { &hf_cip_devtype,
         { "Device Type", "cip.devtype",
         FT_UINT16, BASE_DEC, VALS(cip_devtype_vals), 0,
         NULL, HFILL }
      },
      { &hf_cip_class_rev,
         { "Class Revision", "cip.class.rev",
         FT_UINT16, BASE_DEC, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_class_max_inst32,
         { "Max Instance", "cip.class.max_inst",
         FT_UINT32, BASE_DEC, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_class_num_inst32,
         { "Number of Instances", "cip.class.num_inst",
         FT_UINT32, BASE_DEC, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_reserved8,
         { "Reserved", "cip.reserved",
         FT_UINT8, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_fwo_comp,
         { "Compatibility", "cip.fwo.cmp",
         FT_UINT8, BASE_HEX, VALS(cip_com_bit_vals), 0x80,
         "EKey: Compatibility bit", HFILL }
      },
      { &hf_cip_fwo_mrev,
         { "Major Revision", "cip.fwo.major",
         FT_UINT8, BASE_DEC, NULL, 0x7F,
         "EKey: Major Revision", HFILL }
      }
   };

   static hf_register_info hf_cm[] = {

      { &hf_cip_cm_ot_connid,
         { "O->T Network Connection ID", "cip.cm.ot_connid",
         FT_UINT32, BASE_HEX, NULL, 0,
         "O->T Network Connection ID", HFILL }
      },
      { &hf_cip_cm_to_connid,
         { "T->O Network Connection ID", "cip.cm.to_connid",
         FT_UINT32, BASE_HEX, NULL, 0,
         "T->O Network Connection ID", HFILL }
      },
      { &hf_cip_cm_conn_serial_num,
         { "Connection Serial Number", "cip.cm.conn_serial_num",
         FT_UINT16, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_cm_orig_serial_num,
         { "Originator Serial Number", "cip.cm.orig_serial_num",
         FT_UINT32, BASE_HEX, NULL, 0,
         NULL, HFILL }
      },
      { &hf_cip_cm_fwo_con_size,
         { "Connection Size", "cip.cm.fwo.consize",
         FT_UINT16, BASE_DEC, NULL, 0x01FF,
         "Fwd Open: Connection size", HFILL }
      },
      { &hf_cip_cm_lfwo_con_size,
         { "Connection Size", "cip.cm.fwo.consize",
         FT_UINT32, BASE_DEC, NULL, 0xFFFF,
         "Large Fwd Open: Connection size", HFILL }
      },
      { &hf_cip_cm_fwo_fixed_var,
         { "Connection Size Type", "cip.cm.fwo.f_v",
         FT_UINT16, BASE_DEC, VALS(cip_con_fw_vals), 0x0200,
         "Fwd Open: Fixed or variable connection size", HFILL }
      },
      { &hf_cip_cm_lfwo_fixed_var,
         { "Connection Size Type", "cip.cm.fwo.f_v",
         FT_UINT32, BASE_DEC, VALS(cip_con_fw_vals), 0x02000000,
         "Large Fwd Open: Fixed or variable connection size", HFILL }
      },
      { &hf_cip_cm_fwo_prio,
         { "Priority", "cip.cm.fwo.prio",
         FT_UINT16, BASE_DEC, VALS(cip_con_prio_vals), 0x0C00,
         "Fwd Open: Connection priority", HFILL }
      },
      { &hf_cip_cm_lfwo_prio,
         { "Priority", "cip.cm.fwo.prio",
         FT_UINT32, BASE_DEC, VALS(cip_con_prio_vals), 0x0C000000,
         "Large Fwd Open: Connection priority", HFILL }
      },
      { &hf_cip_cm_fwo_typ,
         { "Connection Type", "cip.cm.fwo.type",
         FT_UINT16, BASE_DEC, VALS(cip_con_type_vals), 0x6000,
         "Fwd Open: Connection type", HFILL }
      },
      { &hf_cip_cm_lfwo_typ,
         { "Connection Type", "cip.cm.fwo.type",
         FT_UINT32, BASE_DEC, VALS(cip_con_type_vals), 0x60000000,
         "Large Fwd Open: Connection type", HFILL }
      },
      { &hf_cip_cm_fwo_own,
         { "Owner", "cip.cm.fwo.owner",
         FT_UINT16, BASE_DEC, VALS(cip_con_owner_vals), 0x8000,
         "Fwd Open: Redundant owner bit", HFILL }
      },
      { &hf_cip_cm_lfwo_own,
         { "Owner", "cip.cm.fwo.owner",
         FT_UINT32, BASE_DEC, VALS(cip_con_owner_vals), 0x80000000,
         "Large Fwd Open: Redundant owner bit", HFILL }
      },
      { &hf_cip_cm_fwo_dir,
         { "Direction", "cip.cm.fwo.dir",
         FT_UINT8, BASE_DEC, VALS(cip_con_dir_vals), 0x80,
         "Fwd Open: Direction", HFILL }
      },
      { &hf_cip_cm_fwo_trigg,
         { "Trigger", "cip.cm.fwo.trigger",
         FT_UINT8, BASE_DEC, VALS(cip_con_trigg_vals), 0x70,
         "Fwd Open: Production trigger", HFILL }
      },
      { &hf_cip_cm_fwo_class,
         { "Class", "cip.cm.fwo.transport",
         FT_UINT8, BASE_DEC, VALS(cip_con_class_vals), 0x0F,
         "Fwd Open: Transport Class", HFILL }
      },
      { &hf_cip_cm_gco_conn,
         { "Number of Connections", "cip.cm.gco.conn",
         FT_UINT8, BASE_DEC, NULL, 0,
         "GetConnOwner: Number of Connections", HFILL }
      },
      { &hf_cip_cm_gco_coo_conn,
         { "COO Connections", "cip.cm.gco.coo_conn",
         FT_UINT8, BASE_DEC, NULL, 0,
         "GetConnOwner: COO Connections", HFILL }
      },
      { &hf_cip_cm_gco_roo_conn,
         { "ROO Connections", "cip.cm.gco.roo_conn",
         FT_UINT8, BASE_DEC, NULL, 0,
         "GetConnOwner: ROO Connections", HFILL }
      },
      { &hf_cip_cm_gco_la,
         { "Last Action", "cip.cm.gco.la",
         FT_UINT8, BASE_DEC, VALS(cip_con_last_action_vals), 0,
         "GetConnOwner: Last Action", HFILL }
      }
   };

   static hf_register_info hf_cco[] = {
      { &hf_cip_cco_con_type,
         { "Connection O_T", "cip.cco.con",
         FT_UINT16, BASE_DEC, VALS(cip_con_vals), 0x001,
         "Connection", HFILL }
      },
      { &hf_cip_cco_ot_rtf,
         { "O->T real time transfer format", "cip.cco.otrtf",
         FT_UINT16, BASE_DEC, VALS(cip_con_rtf_vals), 0x000E,
         "O->T real time transfer", HFILL }
      },
      { &hf_cip_cco_to_rtf,
         { "T->O real time transfer format", "cip.cco.tortf",
         FT_UINT16, BASE_DEC, VALS(cip_con_rtf_vals), 0x0070,
         "T->O real time transfer", HFILL }
      },
   };

   /* Setup protocol subtree array */
   static gint *ett[] = {
      &ett_cip_class_generic,
      &ett_cip,
      &ett_path,
      &ett_ekey_path,
      &ett_rrsc,
      &ett_mcsc,
      &ett_cia_path,
      &ett_data_seg,
      &ett_cmd_data,
      &ett_port_path,
      &ett_status_item
   };

   static gint *ett_mr[] = {
      &ett_cip_class_mr,
      &ett_mr_rrsc,
      &ett_mr_mult_ser,
      &ett_mr_cmd_data
   };

   static gint *ett_cm[] = {
      &ett_cip_class_cm,
      &ett_cm_rrsc,
      &ett_cm_mes_req,
      &ett_cm_ncp,
      &ett_cm_cmd_data
   };

   static gint *ett_cco[] = {
      &ett_cip_class_cco,
      &ett_cco_iomap,
      &ett_cco_con_status,
      &ett_cco_con_flag,
      &ett_cco_tdi,
      &ett_cco_ncp,
      &ett_cco_rrsc,
      &ett_cco_cmd_data
    };

   /* Register the protocol name and description */
   proto_cip = proto_register_protocol("Common Industrial Protocol",
       "CIP", "cip");

   /* Required function calls to register the header fields and subtrees used */
   proto_register_field_array(proto_cip, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
   subdissector_class_table = register_dissector_table("cip.class.iface",
      "CIP Class Interface Handle", FT_UINT32, BASE_HEX);
   subdissector_symbol_table = register_dissector_table("cip.data_segment.iface",
      "CIP Data Segment Interface Handle", FT_UINT32, BASE_HEX);

   /* Register the protocol name and description */
   proto_cip_class_generic = proto_register_protocol("CIP Class Generic",
       "CIPCLS", "cipcls");

   /* Register the protocol name and description */
   proto_cip_class_mr = proto_register_protocol("CIP Message Router",
       "CIPMR", "cipmr");
   proto_register_subtree_array(ett_mr, array_length(ett_mr));

   proto_cip_class_cm = proto_register_protocol("CIP Connection Manager",
       "CIPCM", "cipcm");
   proto_register_field_array(proto_cip_class_cm, hf_cm, array_length(hf_cm));
   proto_register_subtree_array(ett_cm, array_length(ett_cm));

   proto_cip_class_cco = proto_register_protocol("CIP Connection Configuration Object",
       "CIPCCO", "cipcco");
   proto_register_field_array(proto_cip_class_cco, hf_cco, array_length(hf_cco));
   proto_register_subtree_array(ett_cco, array_length(ett_cco));

   register_init_routine(&cip_init_protocol);
} /* end of proto_register_cip() */


void
proto_reg_handoff_cip(void)
{
   /* Create dissector handles */
   /* Register for UCMM CIP data, using EtherNet/IP SendRRData service*/
   /* Register for Connected CIP data, using EtherNet/IP SendUnitData service*/
   cip_handle = new_create_dissector_handle( dissect_cip, proto_cip );
   dissector_add_uint( "enip.srrd.iface", ENIP_CIP_INTERFACE, cip_handle );
   dissector_add_uint( "enip.sud.iface", ENIP_CIP_INTERFACE, cip_handle );

   /* Create and register dissector handle for generic class */
   cip_class_generic_handle = new_create_dissector_handle( dissect_cip_class_generic, proto_cip_class_generic );
   dissector_add_uint( "cip.class.iface", 0, cip_class_generic_handle );

   /* Create and register dissector handle for Message Router */
   cip_class_mr_handle = new_create_dissector_handle( dissect_cip_class_mr, proto_cip_class_mr );
   dissector_add_uint( "cip.class.iface", CI_CLS_MR, cip_class_mr_handle );

   /* Create and register dissector handle for Connection Manager */
   cip_class_cm_handle = new_create_dissector_handle( dissect_cip_class_cm, proto_cip_class_cm );
   dissector_add_uint( "cip.class.iface", CI_CLS_CM, cip_class_cm_handle );

   /* Create and register dissector handle for Connection Configuration Object */
   cip_class_cco_handle = new_create_dissector_handle( dissect_cip_class_cco, proto_cip_class_cco );
   dissector_add_uint( "cip.class.iface", CI_CLS_CCO, cip_class_cco_handle );

} /* end of proto_reg_handoff_cip() */


/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
