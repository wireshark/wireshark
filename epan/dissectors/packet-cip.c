/* packet-cip.c
 * Routines for Common Industrial Protocol (CIP) dissection
 * CIP Home: www.odva.org
 *
 * Copyright 2004
 * Magnus Hansson <mah@hms.se>
 * Joakim Wiberg <jow@hms.se>
 *
 * $Id$
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

#include <epan/packet.h>
#include <epan/emem.h>
#include <prefs.h>
#include "packet-tcp.h"
#include "packet-cip.h"

#define  ENIP_CIP_INTERFACE   0

/* Initialize the protocol and registered fields */
static int proto_cip              = -1;

static int hf_cip_sc              = -1;
static int hf_cip_rr              = -1;
static int hf_cip_epath           = -1;
static int hf_cip_genstat         = -1;

static int hf_cip_fwo_comp        = -1;
static int hf_cip_fwo_mrev        = -1;
static int hf_cip_fwo_con_size    = -1;
static int hf_cip_fwo_fixed_var   = -1;
static int hf_cip_fwo_prio        = -1;
static int hf_cip_fwo_typ         = -1;
static int hf_cip_fwo_own         = -1;
static int hf_cip_fwo_dir         = -1;
static int hf_cip_fwo_trigg       = -1;
static int hf_cip_fwo_class       = -1;

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
static int hf_cip_attribute8          = -1;
static int hf_cip_attribute16         = -1;
static int hf_cip_attribute32         = -1;
static int hf_cip_conpoint8           = -1;
static int hf_cip_conpoint16          = -1;
static int hf_cip_conpoint32          = -1;
static int hf_cip_symbol              = -1;

/* Initialize the subtree pointers */
static gint ett_cip           = -1;
static gint ett_ekey_path     = -1;
static gint ett_cia_path      = -1;
static gint ett_data_seg      = -1;
static gint ett_rrsc          = -1;
static gint ett_mcsc          = -1;
static gint ett_ncp           = -1;
static gint ett_lsrcf         = -1;
static gint ett_mes_req       = -1;
static gint ett_cmd_data      = -1;
static gint ett_port_path     = -1;
static gint ett_mult_ser      = -1;
static gint ett_path          = -1;
static gint ett_status_item   = -1;


/* Translate function to string - CIP Service codes */
static const value_string cip_sc_vals[] = {
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
static const value_string cip_sc_rr[] = {
	{ 0,	      "Request"  },
	{ 1,	      "Response" },

	{ 0,			NULL }
};

/* Translate function to string - Compatibility */
static const value_string cip_com_bit_vals[] = {
	{ 0,	      "Bit Cleared" },
	{ 1,	      "Bit Set"     },

	{ 0,        NULL          }
};

/* Translate function to string - Connection priority */
static const value_string cip_con_prio_vals[] = {
	{ 0,	      "Low Priority"  },
	{ 1,	      "High Priority" },
	{ 2,	      "Scheduled"     },
	{ 3,	      "Urgent"        },

	{ 0,        NULL            }
};

/* Translate function to string - Connection size fixed or variable */
static const value_string cip_con_fw_vals[] = {
	{ 0,	      "Fixed"    },
	{ 1,	      "Variable" },

	{ 0,        NULL       }
};

/* Translate function to string - Connection owner */
static const value_string cip_con_owner_vals[] = {
	{ 0,	      "Exclusive" },
	{ 1,	      "Redundant" },

	{ 0,        NULL        }
};

/* Translate function to string - Connection direction */
static const value_string cip_con_dir_vals[] = {
	{ 0,	      "Client" },
	{ 1,	      "Server" },

	{ 0,        NULL        }
};

/* Translate function to string - Production trigger */
static const value_string cip_con_trigg_vals[] = {
	{ 0,	      "Cyclic" },
	{ 1,	      "Change-Of-State" },
	{ 2,	      "Application Object" },

	{ 0,        NULL        }
};

/* Translate function to string - Transport class */
static const value_string cip_con_class_vals[] = {
	{ 0,	      "0" },
	{ 1,	      "1" },
	{ 2,	      "2" },
	{ 3,	      "3" },

	{ 0,        NULL        }
};

/* Translate function to string - Connection type */
static const value_string cip_con_type_vals[] = {
	{ 0,	      "Null"           },
	{ 1,	      "Multicast"      },
	{ 2,	      "Point to Point" },
	{ 3,	      "Reserved"       },

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

/* Translate function to string - CIP General Status codes */
static const value_string cip_gs_vals[] = {
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
   { CI_GRC_INVALID_REPLY,       "Invalid Reply Received" },
   { CI_GRC_BAD_KEY_IN_PATH,     "Key Failure in path" },
   { CI_GRC_BAD_PATH_SIZE,       "Path Size Invalid" },
   { CI_GRC_UNEXPECTED_ATTR,     "Unexpected attribute in list" },
   { CI_GRC_INVALID_MEMBER,      "Invalid Member ID" },
   { CI_GRC_MEMBER_NOT_SETTABLE, "Member not settable" },

  	{ 0,				               NULL }
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

   { 0, NULL }
};

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
dissect_epath( tvbuff_t *tvb, proto_item *epath_item, int offset, int path_length )
{
   int pathpos, temp_data, temp_data2, seg_size, i, temp_word;
   unsigned char segment_type, opt_link_size;
   proto_tree *path_tree, *port_tree, *net_tree;
   proto_item *qi, *cia_item, *ds_item;
   proto_tree *e_key_tree, *cia_tree, *ds_tree;
   proto_item *mcpi, *port_item, *net_item;
   proto_tree *mc_tree;

   /* Create a sub tree for the epath */
   path_tree = proto_item_add_subtree( epath_item, ett_path );

   proto_tree_add_item_hidden(path_tree, hf_cip_epath,
							   tvb, offset, path_length, TRUE );

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
         port_tree = proto_item_add_subtree( port_item, ett_port_path );

         /* Add port number */
         proto_tree_add_item( port_tree, hf_cip_port, tvb, offset + pathpos, 1, TRUE );
         proto_item_append_text( epath_item, "Port: %d", ( segment_type & 0x0F ) );
         proto_item_append_text( port_item, ": Port: %d", ( segment_type & 0x0F ) );

         if( segment_type & 0x10 )
         {
            /* Add Extended Link Address flag */
            proto_tree_add_text( port_tree, tvb, offset+pathpos, 1, "Extended Link Address: TRUE" );

            /* Add size of extended link address */
            opt_link_size = tvb_get_guint8( tvb, offset + pathpos + 1 );
            proto_tree_add_text( port_tree, tvb, offset+pathpos+1, 1, "Link Address Size: %d", opt_link_size  );

            /* Add extended link address */
            proto_tree_add_item( port_tree, hf_cip_link_address_string, tvb, offset+pathpos+2, opt_link_size, FALSE );
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
            proto_tree_add_text( port_tree, tvb, offset+pathpos, 1, "Extended Link Address: FALSE" );

            /* Add Link Address */
            proto_tree_add_item( port_tree, hf_cip_link_address_byte, tvb, offset+pathpos+1, 1, FALSE );
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
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Class Segment (0x%02X)", segment_type );

               /* Create a sub tree for the class */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 8-bit class number */
               proto_tree_add_item( cia_tree, hf_cip_class8, tvb, offset + pathpos + 1, 1, TRUE );
               proto_item_append_text( epath_item, "%s", val_to_str( temp_data, cip_class_names_vals , "Class: 0x%02X" ) );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 4, "16-Bit Logical Class Segment (0x%02X)", segment_type );

               /* Create a sub tree for the class */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit class number */
               proto_tree_add_item( cia_tree, hf_cip_class16, tvb, offset + pathpos + 2, 2, TRUE );
               proto_item_append_text( epath_item, "%s", val_to_str( temp_data, cip_class_names_vals , "Class: 0x%04X" ) );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 6, "32-Bit Logical Instance Segment (0x%02X)", segment_type );

               /* Create a sub tree for the class */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 32-bit class number */
               proto_tree_add_item( cia_tree, hf_cip_class32, tvb, offset + pathpos + 2, 4, TRUE );
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
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Instance Segment (0x%02X)", segment_type );

               /* Create a sub tree for the instance */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 8-bit instance number */
               proto_tree_add_item( cia_tree, hf_cip_instance8, tvb, offset + pathpos + 1, 1, TRUE );
               proto_item_append_text( epath_item, "Instance: 0x%02X", temp_data );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 4, "16-Bit Logical Instance Segment (0x%02X)", segment_type );

               /* Create a sub tree for the instance */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit instance number */
               proto_tree_add_item( cia_tree, hf_cip_instance16, tvb, offset + pathpos + 2, 2, TRUE );
               proto_item_append_text( epath_item, "Instance: 0x%04X", temp_data );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 6, "32-Bit Logical Instance Segment (0x%02X)", segment_type );

               /* Create a sub tree for the instance */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 32-bit instance number */
               proto_tree_add_item( cia_tree, hf_cip_instance32, tvb, offset + pathpos + 2, 4, TRUE );
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


         case CI_LOGICAL_SEG_ATTR_ID:

            /* Logical Attribute ID, do a format check */

   		   if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_8_BIT )
   		   {
   		      temp_data = tvb_get_guint8( tvb, offset + pathpos + 1 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 2, "8-Bit Logical Attribute Segment (0x%02X)", segment_type );

               /* Create a sub tree for the attribute */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 8-bit attribute number */
               proto_tree_add_item( cia_tree, hf_cip_attribute8, tvb, offset + pathpos + 1, 1, TRUE );
               proto_item_append_text( epath_item, "Attribute: 0x%02X", temp_data );

               /* 2 bytes of path used */
               pathpos += 2;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_16_BIT )
            {
               temp_data = tvb_get_letohs( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 4, "16-Bit Logical Attribute Segment (0x%02X)", segment_type );

               /* Create a sub tree for the attribute */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 16-bit attribute number */
               proto_tree_add_item( cia_tree, hf_cip_attribute16, tvb, offset + pathpos + 2, 2, TRUE );
               proto_item_append_text( epath_item, "Attribute: 0x%04X", temp_data );

               /* 4 bytes of path used */
               pathpos += 4;
            }
            else if( ( segment_type & CI_LOGICAL_SEG_FORMAT_MASK ) == CI_LOGICAL_SEG_32_BIT )
            {
               temp_data = tvb_get_letohl( tvb, offset + pathpos + 2 );
               cia_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 6, "32-Bit Logical Attribute Segment (0x%02X)", segment_type );

               /* Create a sub tree for the attribute */
               cia_tree = proto_item_add_subtree( cia_item, ett_cia_path );

               /* Display the 32-bit attribute number */
               proto_tree_add_item( cia_tree, hf_cip_attribute32, tvb, offset + pathpos + 2, 4, TRUE );
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
               proto_tree_add_item( cia_tree, hf_cip_conpoint8, tvb, offset + pathpos + 1, 1, TRUE );
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
               proto_tree_add_item( cia_tree, hf_cip_conpoint16, tvb, offset + pathpos + 2, 2, TRUE );
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
               proto_tree_add_item( cia_tree, hf_cip_conpoint32, tvb, offset + pathpos + 2, 4, TRUE );
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
                  proto_tree_add_item( e_key_tree, hf_cip_vendor, tvb, offset + pathpos + 2, 2, TRUE);
                  proto_item_append_text( qi, "VendorID: 0x%04X", temp_data );

                  /* Get Device Type */
   		         temp_data = tvb_get_letohs( tvb, offset + pathpos + 4 );
   		         proto_tree_add_item( e_key_tree, hf_cip_devtype, tvb, offset + pathpos + 4, 2, TRUE);
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
   							tvb, offset + pathpos + 8, 1, TRUE );

                  proto_item_append_text( mcpi, "%s, Major Revision: %d",
                              val_to_str( ( temp_data & 0x80 )>>7, cip_com_bit_vals , "" ),
                              temp_data & 0x7F );

   					/* Major revision */
   					proto_tree_add_item(mc_tree, hf_cip_fwo_mrev,
   							tvb, offset + pathpos + 8, 1, TRUE );

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
               ds_item = proto_tree_add_text( path_tree, tvb, offset + pathpos, 1, "Extended Symbol Segment (0x%02X)", segment_type );

               /* Create a sub tree */
               ds_tree = proto_item_add_subtree( ds_item, ett_data_seg );

               /* Segment size */
               seg_size = tvb_get_guint8( tvb, offset + pathpos+1 );
               proto_tree_add_text( ds_tree, tvb, offset + pathpos+1, 1, "Data Size: %d", seg_size );

               /* Segment data  */
               if( seg_size != 0 )
               {
                  qi = proto_tree_add_text( ds_tree, tvb, offset + pathpos + 2, seg_size, "Data: %s",
                        tvb_format_text(tvb, offset + pathpos + 2, seg_size ) );

                  proto_item_append_text(epath_item, "%s", tvb_format_text(tvb, offset + pathpos + 2, seg_size ) );
                  proto_tree_add_item_hidden( ds_tree, hf_cip_symbol, tvb, offset + pathpos + 2, seg_size, FALSE );

                  if( seg_size %2 )
                  {
                     /* We have a PAD BYTE */
                     proto_tree_add_text( ds_tree, tvb, offset + pathpos + 2 + seg_size, 1, "Pad Byte (0x%02X)",
                         tvb_get_guint8( tvb, offset + pathpos + 2 + seg_size ) );
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


static void
dissect_cip_data( proto_tree *item_tree, tvbuff_t *tvb, int offset, int item_length, packet_info *pinfo )
{
   proto_item *pi, *rrsc_item, *ncppi, *ar_item, *temp_item, *temp_item2, *status_item;
	proto_tree *temp_tree, *rrsc_tree, *ncp_tree, *cmd_data_tree, *status_tree;
	int req_path_size, conn_path_size, temp_data;
	unsigned char gen_status;
   unsigned char add_stat_size;
   unsigned char temp_byte, route_path_size;
   unsigned char app_rep_size, i;
   int msg_req_siz, num_services, serv_offset;


   /* Add Service code & Request/Response tree */
	rrsc_item = proto_tree_add_text( item_tree, tvb, offset, 1, "Service: " );
	rrsc_tree = proto_item_add_subtree( rrsc_item, ett_rrsc );

	/* Add Request/Response */
   proto_tree_add_item( rrsc_tree, hf_cip_rr, tvb, offset, 1, TRUE );

   proto_item_append_text( rrsc_item, "%s (%s)",
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                  cip_sc_vals , "Unknown Service (%x)"),
               val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x80 )>>7,
                  cip_sc_rr, "") );

	/* Add Service code */
	proto_tree_add_item(rrsc_tree, hf_cip_sc, tvb, offset, 1, TRUE );

	if( tvb_get_guint8( tvb, offset ) & 0x80 )
	{
	   /* Response message */
	   status_item = proto_tree_add_text( item_tree, tvb, offset+2, 1, "Status: " );
	   status_tree = proto_item_add_subtree( status_item, ett_status_item );

		/* Add general status */
		gen_status = tvb_get_guint8( tvb, offset+2 );
		proto_tree_add_item(status_tree, hf_cip_genstat, tvb, offset+2, 1, TRUE );
		proto_item_append_text( status_item, "%s", val_to_str( ( tvb_get_guint8( tvb, offset+2 ) ),
                     cip_gs_vals , "Unknown Response (%x)")   );

      /* Add reply status to info column */
      if(check_col(pinfo->cinfo, COL_INFO))
      {
         col_append_fstr( pinfo->cinfo, COL_INFO, "%s",
                  val_to_str( ( tvb_get_guint8( tvb, offset+2 ) ),
                     cip_gs_vals , "Unknown Response (%x)") );
      }

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

      /* If there is any command specific data create a sub-tree for it */
      if( ( item_length-4-add_stat_size ) != 0 )
      {
         pi = proto_tree_add_text( item_tree, tvb, offset+4+add_stat_size, item_length-4-add_stat_size, "Command Specific data" );
         cmd_data_tree = proto_item_add_subtree( pi, ett_cmd_data );

		   if( gen_status == CI_GRC_SUCCESS )
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
               proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+4+add_stat_size+10, 2, TRUE);

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
               proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+4+add_stat_size+2, 2, TRUE);

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

                  /*
                  ** We call our selves again to disect embedded packet
                  */

                  if(check_col(pinfo->cinfo, COL_INFO))
                     col_append_fstr( pinfo->cinfo, COL_INFO, ", ");

                  dissect_cip_data( temp_tree, tvb, offset+serv_offset+4, serv_length, pinfo );
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
               proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+4+add_stat_size+2, 2, TRUE);

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
	   /* Request message */

      /* Add service to info column */
      if(check_col(pinfo->cinfo, COL_INFO))
      {
         col_append_fstr( pinfo->cinfo, COL_INFO, "%s",
                  val_to_str( ( tvb_get_guint8( tvb, offset ) & 0x7F ),
                     cip_sc_vals , "Unknown Service (%x)") );
      }

	   /* Add path size to tree */
	   req_path_size = tvb_get_guint8( tvb, offset+1 )*2;
	   proto_tree_add_text( item_tree, tvb, offset+1, 1, "Request Path Size: %d (words)", req_path_size/2 );

      /* Add the epath */
      pi = proto_tree_add_text(item_tree, tvb, offset+2, req_path_size, "Request Path: ");
      dissect_epath( tvb, pi, offset+2, req_path_size );

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
            proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+2+req_path_size+12, 2, TRUE);

            /* Display the originator serial number */
            temp_data = tvb_get_letohl( tvb, offset+2+req_path_size+14 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+14, 4, "Originator Serial Number: 0x%08X", temp_data );

            /* Display the timeout multiplier */
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+18 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+18, 1, "Connection Timeout Multiplier: %s (%d)", val_to_str( temp_data, cip_con_time_mult_vals , "Reserved" ), temp_data );

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
            proto_tree_add_item(ncp_tree, hf_cip_fwo_own,
   					tvb, offset+2+req_path_size+26, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_cip_fwo_typ,
   					tvb, offset+2+req_path_size+26, 2, TRUE );
            proto_tree_add_item(ncp_tree, hf_cip_fwo_prio,
   					tvb, offset+2+req_path_size+26, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_cip_fwo_fixed_var,
   					tvb, offset+2+req_path_size+26, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_cip_fwo_con_size,
   					tvb, offset+2+req_path_size+26, 2, TRUE );

            /* Display target to originator requested packet interval */
            temp_data = tvb_get_letohl( tvb, offset+2+req_path_size+28 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+28, 4, "T->O RPI: %dms (0x%08X)", temp_data / 1000, temp_data );

   	      /* Display target to originator network connection patameterts, in a tree */
   	      temp_data = tvb_get_letohs( tvb, offset+2+req_path_size+32 );
   	      ncppi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+32, 2, "T->O Network Connection Parameters: 0x%04X", temp_data );
   	      ncp_tree = proto_item_add_subtree(ncppi, ett_ncp);

            /* Add the data to the tree */
            proto_tree_add_item(ncp_tree, hf_cip_fwo_own,
   					tvb, offset+2+req_path_size+32, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_cip_fwo_typ,
   					tvb, offset+2+req_path_size+32, 2, TRUE );
            proto_tree_add_item(ncp_tree, hf_cip_fwo_prio,
   					tvb, offset+2+req_path_size+32, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_cip_fwo_fixed_var,
   					tvb, offset+2+req_path_size+32, 2, TRUE );
   			proto_tree_add_item(ncp_tree, hf_cip_fwo_con_size,
   					tvb, offset+2+req_path_size+32, 2, TRUE );

            /* Transport type/trigger in tree*/
            temp_data = tvb_get_guint8( tvb, offset+2+req_path_size+34 );

   	      ncppi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+34, 1, "Transport Type/Trigger: 0x%02X", temp_data );
   	      ncp_tree = proto_item_add_subtree(ncppi, ett_ncp);

            /* Add the data to the tree */
            proto_tree_add_item(ncp_tree, hf_cip_fwo_dir,
   					tvb, offset+2+req_path_size+34, 1, TRUE );

   			proto_tree_add_item(ncp_tree, hf_cip_fwo_trigg,
   					tvb, offset+2+req_path_size+34, 1, TRUE );

            proto_tree_add_item(ncp_tree, hf_cip_fwo_class,
   					tvb, offset+2+req_path_size+34, 1, TRUE );

            /* Add path size */
            conn_path_size = tvb_get_guint8( tvb, offset+2+req_path_size+35 )*2;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+35, 1, "Connection Path Size: %d (words)", conn_path_size / 2 );

            /* Add the epath */
            pi = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+36, conn_path_size, "Connection Path: ");
            dissect_epath( tvb, pi, offset+2+req_path_size+36, conn_path_size );
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

            /* Display the actual time out */
            temp_data = ( 1 << ( temp_byte & 0x0F ) ) * temp_data;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 2, "Actual Time Out: %dms", temp_data );

            /* Display connection serial number */
            temp_data = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, 2, "Connection Serial Number: 0x%04X", temp_data );

            /* Display the originator vendor id */
            proto_tree_add_item( cmd_data_tree, hf_cip_vendor, tvb, offset+2+req_path_size+4, 2, TRUE);

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
            dissect_epath( tvb, pi, offset+2+req_path_size+12, conn_path_size );

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

            /* Display the actual time out */
            temp_data = ( 1 << ( temp_byte & 0x0F ) ) * temp_data;
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size, 2, "Actual Time Out: %dms", temp_data );

            /* Message request size */
            msg_req_siz = tvb_get_letohs( tvb, offset+2+req_path_size+2 );
            proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+2, 2, "Message Request Size: 0x%04X", msg_req_siz );

            /* Message Request */
            temp_item = proto_tree_add_text( cmd_data_tree, tvb, offset+2+req_path_size+4, msg_req_siz, "Message Request" );
            temp_tree = proto_item_add_subtree(temp_item, ett_mes_req );

            /*
            ** We call our selves again to disect embedded packet
            */

            if(check_col(pinfo->cinfo, COL_INFO))
               col_append_fstr( pinfo->cinfo, COL_INFO, ": ");

            dissect_cip_data( temp_tree, tvb, offset+2+req_path_size+4, msg_req_siz, pinfo );

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
            temp_item = proto_tree_add_text(cmd_data_tree, tvb, offset+2+req_path_size+6+msg_req_siz, route_path_size, "Route Path: ");
            dissect_epath( tvb, temp_item, offset+2+req_path_size+6+msg_req_siz, route_path_size );

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

               /*
               ** We call our selves again to disect embedded packet
               */

               if(check_col(pinfo->cinfo, COL_INFO))
                  col_append_fstr( pinfo->cinfo, COL_INFO, ", ");

               dissect_cip_data( temp_tree, tvb, offset+serv_offset+6, serv_length, pinfo );
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

} /* End of dissect_cip_data() */


static int
dissect_cip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *cip_tree;

   /* Make entries in Protocol column and Info column on summary display */
   if( check_col( pinfo->cinfo, COL_PROTOCOL ) )
      col_set_str( pinfo->cinfo, COL_PROTOCOL, "CIP" );

   if (check_col( pinfo->cinfo, COL_INFO ) )
      col_clear( pinfo->cinfo, COL_INFO );

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_cip, tvb, 0, -1, FALSE);
      cip_tree = proto_item_add_subtree( ti, ett_cip );

      dissect_cip_data( cip_tree, tvb, 0, tvb_length(tvb), pinfo );
   }

   return tvb_length(tvb);
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
			FT_BYTES, BASE_HEX, NULL, 0,
			"EPath", HFILL }
		},
		{ &hf_cip_genstat,
			{ "General Status", "cip.genstat",
			FT_UINT8, BASE_HEX, VALS(cip_gs_vals), 0,
			"General Status", HFILL }
		},
		{ &hf_cip_port,
			{ "Port", "cip.port",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Port Identifier", HFILL }
		},
		{ &hf_cip_link_address_byte,
			{ "Link Address", "cip.linkaddress",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Link Address", HFILL }
		},
		{ &hf_cip_link_address_string,
			{ "Link Address", "cip.linkaddress",
			FT_STRING, BASE_NONE, NULL, 0,
			"Link Address", HFILL }
		},
		{ &hf_cip_class8,
			{ "Class", "cip.class",
			FT_UINT8, BASE_HEX, VALS(cip_class_names_vals), 0,
			"Class", HFILL }
		},
		{ &hf_cip_class16,
			{ "Class", "cip.class",
			FT_UINT16, BASE_HEX, VALS(cip_class_names_vals), 0,
			"Class", HFILL }
		},
		{ &hf_cip_class32,
			{ "Class", "cip.class",
			FT_UINT32, BASE_HEX, VALS(cip_class_names_vals), 0,
			"Class", HFILL }
		},
		{ &hf_cip_instance8,
			{ "Instance", "cip.instance",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Instance", HFILL }
		},
		{ &hf_cip_instance16,
			{ "Instance", "cip.instance",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Instance", HFILL }
		},
		{ &hf_cip_instance32,
			{ "Instance", "cip.instance",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Instance", HFILL }
		},
		{ &hf_cip_attribute8,
			{ "Attribute", "cip.attribute",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Attribute", HFILL }
		},
		{ &hf_cip_attribute16,
			{ "Attribute", "cip.attribute",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Attribute", HFILL }
		},
		{ &hf_cip_attribute32,
			{ "Attribute", "cip.attribute",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Attribute", HFILL }
		},
		{ &hf_cip_conpoint8,
			{ "Connection Point", "cip.connpoint",
			FT_UINT8, BASE_HEX, NULL, 0,
			"Connection Point", HFILL }
		},
		{ &hf_cip_conpoint16,
			{ "Connection Point", "cip.connpoint",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Connection Point", HFILL }
		},
		{ &hf_cip_conpoint32,
			{ "Connection Point", "cip.connpoint",
			FT_UINT16, BASE_HEX, NULL, 0,
			"Connection Point", HFILL }
		},
		{ &hf_cip_symbol,
			{ "Symbol", "cip.symbol",
			FT_STRING, BASE_NONE, NULL, 0,
			"ANSI Extended Symbol Segment", HFILL }
		},
		{ &hf_cip_vendor,
			{ "Vendor ID", "cip.vendor",
			FT_UINT16, BASE_HEX, VALS(cip_vendor_vals), 0,
			"Vendor ID", HFILL }
		},
		{ &hf_cip_devtype,
			{ "Device Type", "cip.devtype",
			FT_UINT16, BASE_DEC, VALS(cip_devtype_vals), 0,
			"Device Type", HFILL }
		},
		{ &hf_cip_fwo_comp,
			{ "Compatibility", "cip.fwo.cmp",
			FT_UINT8, BASE_HEX, VALS(cip_com_bit_vals), 0x80,
			"Fwd Open: Compatibility bit", HFILL }
		},
      { &hf_cip_fwo_mrev,
			{ "Major Revision", "cip.fwo.major",
			FT_UINT8, BASE_DEC, NULL, 0x7F,
			"Fwd Open: Major Revision", HFILL }
		},
      { &hf_cip_fwo_con_size,
			{ "Connection Size", "cip.fwo.consize",
			FT_UINT16, BASE_DEC, NULL, 0x01FF,
			"Fwd Open: Connection size", HFILL }
		},
      { &hf_cip_fwo_fixed_var,
			{ "Connection Size Type", "cip.fwo.f_v",
			FT_UINT16, BASE_DEC, VALS(cip_con_fw_vals), 0x0200,
			"Fwd Open: Fixed or variable connection size", HFILL }
		},
      { &hf_cip_fwo_prio,
			{ "Priority", "cip.fwo.prio",
			FT_UINT16, BASE_DEC, VALS(cip_con_prio_vals), 0x0C00,
			"Fwd Open: Connection priority", HFILL }
		},
      { &hf_cip_fwo_typ,
			{ "Connection Type", "cip.fwo.type",
			FT_UINT16, BASE_DEC, VALS(cip_con_type_vals), 0x6000,
			"Fwd Open: Connection type", HFILL }
		},
      { &hf_cip_fwo_own,
			{ "Owner", "cip.fwo.owner",
			FT_UINT16, BASE_DEC, VALS(cip_con_owner_vals), 0x8000,
			"Fwd Open: Redundant owner bit", HFILL }
		},
		{ &hf_cip_fwo_dir,
			{ "Direction", "cip.fwo.dir",
			FT_UINT8, BASE_DEC, VALS(cip_con_dir_vals), 0x80,
			"Fwd Open: Direction", HFILL }
		},
      { &hf_cip_fwo_trigg,
			{ "Trigger", "cip.fwo.trigger",
			FT_UINT8, BASE_DEC, VALS(cip_con_trigg_vals), 0x70,
			"Fwd Open: Production trigger", HFILL }
		},
      { &hf_cip_fwo_class,
			{ "Class", "cip.fwo.transport",
			FT_UINT8, BASE_DEC, VALS(cip_con_class_vals), 0x0F,
			"Fwd Open: Transport Class", HFILL }
		}
   };

   /* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_cip,
		&ett_path,
		&ett_ekey_path,
		&ett_rrsc,
		&ett_mcsc,
		&ett_ncp,
		&ett_cia_path,
		&ett_data_seg,
		&ett_lsrcf,
		&ett_mes_req,
		&ett_cmd_data,
		&ett_port_path,
		&ett_mult_ser,
		&ett_path,
		&ett_status_item
	};

   /* Register the protocol name and description */
   proto_cip = proto_register_protocol("Common Industrial Protocol",
	    "CIP", "cip");

   /* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_cip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

} /* end of proto_register_cip() */


void
proto_reg_handoff_cip(void)
{
	dissector_handle_t cip_handle;

   /* Create dissector handles */
   cip_handle = new_create_dissector_handle( dissect_cip, proto_cip );

   /* Register for UCMM CIP data, using EtherNet/IP SendRRData service*/
	dissector_add( "enip.srrd.iface", ENIP_CIP_INTERFACE, cip_handle );

	/* Register for Connected CIP data, using EtherNet/IP SendUnitData service*/
	dissector_add( "enip.sud.iface", ENIP_CIP_INTERFACE, cip_handle );

} /* end of proto_reg_handoff_cip() */
