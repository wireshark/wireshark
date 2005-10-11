/* packet-enip.c
 * Routines for EtherNet/IP (Industrial Protocol) dissection
 * EtherNet/IP Home: www.odva.org
 *
 * Copyright 2003-2004
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
#include <prefs.h>
#include "packet-tcp.h"
#include "packet-cip.h"


/* Communication Ports */
#define ENIP_ENCAP_PORT		44818	/* EtherNet/IP located on port 44818    */
#define ENIP_IO_PORT		   2222	/* EtherNet/IP IO located on port 2222  */

/* Return codes of function classifying packets as query/response */
#define REQUEST_PACKET	   0
#define RESPONSE_PACKET		1
#define CANNOT_CLASSIFY		2

/* EtherNet/IP function codes */
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

/* EtherNet/IP status codes */
#define SUCCESS               0x0000
#define INVALID_CMD           0x0001
#define NO_RESOURCES          0x0002
#define INCORRECT_DATA        0x0003
#define INVALID_SESSION       0x0064
#define INVALID_LENGTH        0x0065
#define UNSUPPORTED_PROT_REV  0x0069

/* EtherNet/IP Common Data Format Type IDs */
#define CDF_NULL              0x0000
#define LIST_IDENTITY_RESP    0x000C
#define CONNECTION_BASED      0x00A1
#define CONNECTION_TRANSPORT  0x00B1
#define UNCONNECTED_MSG       0x00B2
#define LIST_SERVICES_RESP    0x0100
#define SOCK_ADR_INFO_OT      0x8000
#define SOCK_ADR_INFO_TO      0x8001
#define SEQ_ADDRESS           0x8002


/* Initialize the protocol and registered fields */
static int proto_enip              = -1;

static int hf_enip_command         = -1;
static int hf_enip_options         = -1;
static int hf_enip_sendercontex    = -1;
static int hf_enip_status          = -1;
static int hf_enip_session         = -1;

static int hf_enip_lir_sinfamily   = -1;
static int hf_enip_lir_sinport     = -1;
static int hf_enip_lir_sinaddr     = -1;
static int hf_enip_lir_sinzero     = -1;

static int hf_enip_lir_vendor     = -1;
static int hf_enip_lir_devtype     = -1;
static int hf_enip_lir_prodcode    = -1;
static int hf_enip_lir_status      = -1;
static int hf_enip_lir_serial      = -1;
static int hf_enip_lir_name        = -1;
static int hf_enip_lir_state       = -1;

static int hf_enip_lsr_tcp         = -1;
static int hf_enip_lsr_udp         = -1;

static int hf_enip_srrd_ifacehnd   = -1;

static int hf_enip_sud_ifacehnd    = -1;

static int hf_enip_cpf_typeid      = -1;
static int hf_enip_cpf_sai_connid  = -1;
static int hf_enip_cpf_sai_seqnum  = -1;

/* Initialize the subtree pointers */
static gint ett_enip          = -1;
static gint ett_count_tree    = -1;
static gint ett_type_tree     = -1;
static gint ett_command_tree  = -1;
static gint ett_sockadd       = -1;
static gint ett_lsrcf         = -1;

static proto_tree          *g_tree;
static dissector_table_t   subdissector_srrd_table;
static dissector_table_t   subdissector_sud_table;
static dissector_handle_t  data_handle;

static gboolean enip_desegment = TRUE;

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


/* Translate function to string - True/False */
static const value_string enip_true_false_vals[] = {
	{ 0,	      "False"       },
	{ 1,	      "True"        },

	{ 0,        NULL          }
};


/* Translate interface handle to string */
static const value_string enip_interface_handle_vals[] = {
	{ 0,	      "CIP" },

	{ 0,        NULL  }
};


static proto_item*
add_byte_array_text_to_proto_tree( proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char* str )
{
  const char *tmp;
  char       *tmp2, *tmp2start;
  proto_item *pi;
  int         i,tmp_length,tmp2_length;
  guint32     octet;
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

   tmp = (char *)tvb_get_ptr( tvb, start, tmp_length );
   tmp2 = (char*)g_malloc( tmp2_length );

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

   g_free( tmp2start );

   return( pi );

} /* end of add_byte_array_text_to_proto_tree() */

/* Disssect Common Packet Format */
static void
dissect_cpf( int command, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint32 ifacehndl )
{
   proto_item *temp_item, *count_item, *type_item, *sockaddr_item;
	proto_tree *temp_tree, *count_tree, *item_tree, *sockaddr_tree;
	int temp_data, item_count, item_length, item;
	unsigned char name_length;
	tvbuff_t *next_tvb;

	/* Create item count tree */
	item_count = tvb_get_letohs( tvb, offset );
   count_item  = proto_tree_add_text( tree, tvb, offset, 2, "Item Count: %d", item_count );
	count_tree  = proto_item_add_subtree( count_item, ett_count_tree );

	while( item_count-- )
	{
		/* Add item type tree to item count tree*/
		type_item = proto_tree_add_item( count_tree, hf_enip_cpf_typeid, tvb, offset+2, 2, TRUE );
		item_tree = proto_item_add_subtree( type_item, ett_type_tree );

		/* Add length field to item type tree*/
      proto_tree_add_text( item_tree, tvb, offset+4, 2, "Length: %d", tvb_get_letohs( tvb, offset+4 ) );

		item        = tvb_get_letohs( tvb, offset+2 );
		item_length = tvb_get_letohs( tvb, offset+4 );

		if( item_length )
		{
		   /* Add item data field */

			switch( item )
			{
			   case CONNECTION_BASED:

			      /* Add Connection identifier */
			      proto_tree_add_text( item_tree, tvb, offset+6, 4, "Connection Identifier: 0x%08X", tvb_get_letohl( tvb, offset + 6 )  );

			      /* Add Connection ID to Info col */
			      if(check_col(pinfo->cinfo, COL_INFO))
	            {
                  col_append_fstr(pinfo->cinfo, COL_INFO,
				         ", CONID: 0x%08X",
				         tvb_get_letohl( tvb, offset+6 ) );
				   }

			      break;

			   case UNCONNECTED_MSG:

					/* Call dissector for interface */
					next_tvb = tvb_new_subset( tvb, offset+6, item_length, item_length );

               if( tvb_length_remaining(next_tvb, 0) == 0 || !dissector_try_port(subdissector_srrd_table, ifacehndl, next_tvb, pinfo, g_tree) )
               {
                  /* Show the undissected payload */
                   if( tvb_length_remaining(tvb, offset) > 0 )
                     call_dissector( data_handle, next_tvb, pinfo, g_tree );
               }

					break;

            case CONNECTION_TRANSPORT:

               if( command == SEND_UNIT_DATA )
               {
                  /*
                  ** If the encapsulation service is SendUnit Data, this is a
                  ** encapsulated connected message
                  */

                  /* Add sequence count ( Transport Class 1,2,3 )*/
                  proto_tree_add_text( item_tree, tvb, offset+6, 2, "Sequence Count: 0x%04X", tvb_get_letohs( tvb, offset+6 ) );

                  /* Call dissector for interface */
                  next_tvb = tvb_new_subset (tvb, offset+8, item_length-2, item_length-2);

                  if( tvb_length_remaining(next_tvb, 0) == 0 || !dissector_try_port(subdissector_sud_table, ifacehndl, next_tvb, pinfo, g_tree) )
                  {
                     /* Show the undissected payload */
                      if( tvb_length_remaining(tvb, offset) > 0 )
                        call_dissector( data_handle, next_tvb, pinfo, g_tree );
                  }

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
               proto_tree_add_item(sockaddr_tree, hf_enip_lir_sinfamily,
							tvb, offset+8, 2, FALSE );

               /* Socket address struct - sin_port */
               proto_tree_add_item(sockaddr_tree, hf_enip_lir_sinport,
							tvb, offset+10, 2, FALSE );

               /* Socket address struct - sin_address */
               proto_tree_add_item(sockaddr_tree, hf_enip_lir_sinaddr,
							tvb, offset+12, 4, FALSE );

               /* Socket address struct - sin_zero */
               proto_tree_add_item(sockaddr_tree, hf_enip_lir_sinzero,
							tvb, offset+16, 8, FALSE );

               /* Vendor ID */
               proto_tree_add_item(item_tree, hf_enip_lir_vendor,
							tvb, offset+24, 2, TRUE );

               /* Device Type */
               proto_tree_add_item(item_tree, hf_enip_lir_devtype,
							tvb, offset+26, 2, TRUE );

               /* Product Code */
               proto_tree_add_item(item_tree, hf_enip_lir_prodcode,
							tvb, offset+28, 2, TRUE );

               /* Revision */
               temp_data = tvb_get_letohs( tvb, offset+30 );
               proto_tree_add_text( item_tree, tvb, offset+30, 2, "Revision: %d.%02d", temp_data & 0xFF, ( temp_data & 0xFF00 ) >> 8 );

               /* Status */
               proto_tree_add_item(item_tree, hf_enip_lir_status,
							tvb, offset+32, 2, TRUE );

               /* Serial Number */
               proto_tree_add_item(item_tree, hf_enip_lir_serial,
							tvb, offset+34, 4, TRUE );

               /* Product Name Length */
               name_length = tvb_get_guint8( tvb, offset+38 );
               proto_tree_add_text( item_tree, tvb, offset+38, 1, "Product Name Length: %d", name_length );

               /* Product Name */
               proto_tree_add_item(item_tree, hf_enip_lir_name,
							tvb, offset+39, name_length, TRUE );

               /* Append product name to info column */
               if(check_col(pinfo->cinfo, COL_INFO))
               {
                  col_append_fstr( pinfo->cinfo, COL_INFO, ", %s",
                      tvb_format_text(tvb, offset+39, name_length));
               }

               /* State */
               proto_tree_add_item(item_tree, hf_enip_lir_state,
							tvb, offset+name_length+39, 1, TRUE );
               break;


            case SOCK_ADR_INFO_OT:
            case SOCK_ADR_INFO_TO:

               /* Socket address struct - sin_family */
               proto_tree_add_item(item_tree, hf_enip_lir_sinfamily,
							tvb, offset+6, 2, FALSE );

               /* Socket address struct - sin_port */
               proto_tree_add_item(item_tree, hf_enip_lir_sinport,
							tvb, offset+8, 2, FALSE );

               /* Socket address struct - sin_address */
               proto_tree_add_item(item_tree, hf_enip_lir_sinaddr,
							tvb, offset+10, 4, FALSE );

               /* Socket address struct - sin_zero */
               proto_tree_add_item( item_tree, hf_enip_lir_sinzero,
							tvb, offset+14, 8, FALSE );
				   break;


            case SEQ_ADDRESS:
               proto_tree_add_item(item_tree, hf_enip_cpf_sai_connid,
							tvb, offset+6, 4, TRUE );

               proto_tree_add_item(item_tree, hf_enip_cpf_sai_seqnum,
							tvb, offset+10, 4, TRUE );

               /* Add info to column */

               if(check_col(pinfo->cinfo, COL_INFO))
	            {
	               col_clear(pinfo->cinfo, COL_INFO);

                  col_add_fstr(pinfo->cinfo, COL_INFO,
				         "Connection:  ID=0x%08X, SEQ=%010d",
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

               proto_tree_add_item(temp_tree, hf_enip_lsr_tcp,
                  tvb, offset+8, 2, TRUE );
      		   proto_tree_add_item(temp_tree, hf_enip_lsr_udp,
      			   tvb, offset+8, 2, TRUE );

               /* Name of service */
               temp_item = proto_tree_add_text( item_tree, tvb, offset+10, 16, "Name of Service: %s",
                   tvb_format_stringzpad(tvb, offset+10, 16) );

               /* Append service name to info column */
               if(check_col(pinfo->cinfo, COL_INFO))
               {
                  col_append_fstr( pinfo->cinfo, COL_INFO, ", %s",
                      tvb_format_stringzpad(tvb, offset+10, 16) );
               }

               break;


				default:

               add_byte_array_text_to_proto_tree( item_tree, tvb, offset+6, item_length, "Data: " );
               break;

			} /* end of switch( item type ) */

		} /* end of if( item length ) */

		offset = offset + item_length + 4;

	} /* end of while( item count ) */

} /* end of dissect_cpf() */



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

static guint
get_enip_pdu_len(tvbuff_t *tvb, int offset)
{
   guint16 plen;

   /*
    * Get the length of the data from the encapsulation header.
    */
   plen = tvb_get_letohs(tvb, offset + 2);

   /*
    * That length doesn't include the encapsulation header itself;
    * add that in.
    */
   return plen + 24;
}

/* Code to actually dissect the packets */
static void
dissect_enip_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   int	   packet_type;
   guint16  encap_cmd, encap_data_length;
   char     *pkt_type_str = "";
   guint32  ifacehndl;

   /* Set up structures needed to add the protocol subtree and manage it */
   proto_item *ti, *encaph, *csf;
   proto_tree *enip_tree, *header_tree, *csftree;

   /* Make entries in Protocol column and Info column on summary display */
   if (check_col(pinfo->cinfo, COL_PROTOCOL))
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENIP");
   if (check_col(pinfo->cinfo, COL_INFO))
      col_clear(pinfo->cinfo, COL_INFO);

   encap_cmd = tvb_get_letohs( tvb, 0 );

   if( check_col(pinfo->cinfo, COL_INFO) )
   {
      packet_type = classify_packet(pinfo);

      switch ( packet_type )
      {
         case REQUEST_PACKET:
            pkt_type_str="Req";
            break;

         case RESPONSE_PACKET:
            pkt_type_str="Rsp";
            break;

         default:
            pkt_type_str="?";
      }

      /* Add service and request/response to info column */
      col_add_fstr(pinfo->cinfo, COL_INFO,
                "%s (%s)",
	      val_to_str(encap_cmd, encap_cmd_vals, "Unknown (0x%04x)"),
	      pkt_type_str );


   } /* end of if( col exists ) */

   /* In the interest of speed, if "tree" is NULL, don't do any work not
      necessary to generate protocol tree items. */
   if (tree) {

      /* create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_enip, tvb, 0, -1, FALSE);

      enip_tree = proto_item_add_subtree(ti, ett_enip);

      /* Add encapsulation header tree */
      encaph     = proto_tree_add_text( enip_tree, tvb, 0, 24, "Encapsulation Header");
      header_tree = proto_item_add_subtree(encaph, ett_enip);

      /* Add EtherNet/IP encapsulation header */
      proto_tree_add_item( header_tree, hf_enip_command, tvb, 0, 2, TRUE );

      encap_data_length = tvb_get_letohs( tvb, 2 );
      proto_tree_add_text( header_tree, tvb, 2, 2, "Length: %u", encap_data_length );

      proto_tree_add_item( header_tree, hf_enip_session, tvb, 4, 4, TRUE );
      proto_tree_add_item( header_tree, hf_enip_status, tvb, 8, 4, TRUE );
      proto_tree_add_item( header_tree, hf_enip_sendercontex, tvb, 12, 8, TRUE );
      proto_tree_add_item( header_tree, hf_enip_options, tvb, 20, 4, TRUE );

      /* Append session and command to the protocol tree */
      proto_item_append_text( ti, ", Session: 0x%08X, %s", tvb_get_letohl( tvb, 4 ),
         val_to_str( encap_cmd, encap_cmd_vals, "Unknown (0x%04x)" ) );

      /*
      ** For some commands we want to add some info to the info column
      */

      if( check_col( pinfo->cinfo, COL_INFO ) )
      {

         switch( encap_cmd )
         {
            case REGISTER_SESSION:
            case UNREGISTER_SESSION:
                  col_append_fstr( pinfo->cinfo, COL_INFO, ", Session: 0x%08X",
                                   tvb_get_letohl( tvb, 4 ) );

         } /* end of switch() */

      } /* end of id info column */

      /* Command specific data - create tree */
      if( encap_data_length )
      {
         /* The packet have some command specific data, buid a sub tree for it */

         csf = proto_tree_add_text( enip_tree, tvb, 24, encap_data_length,
                                   "Command Specific Data");

         csftree = proto_item_add_subtree(csf, ett_command_tree);

         switch( encap_cmd )
         {
            case NOP:
               break;

            case LIST_SERVICES:
               dissect_cpf( encap_cmd, tvb, pinfo, csftree, 24, 0 );
               break;

            case LIST_IDENTITY:
               dissect_cpf( encap_cmd, tvb, pinfo, csftree, 24, 0 );
               break;

            case LIST_INTERFACES:
               dissect_cpf( encap_cmd, tvb, pinfo, csftree, 24, 0 );
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
               proto_tree_add_item(csftree, hf_enip_srrd_ifacehnd, tvb, 24, 4, TRUE);

               proto_tree_add_text( csftree, tvb, 28, 2, "Timeout: %u",
                                   tvb_get_letohs( tvb, 28 ) );

               ifacehndl = tvb_get_letohl( tvb, 24 );
               dissect_cpf( encap_cmd, tvb, pinfo, csftree, 30, ifacehndl );
               break;

            case SEND_UNIT_DATA:
               proto_tree_add_item(csftree, hf_enip_sud_ifacehnd, tvb, 24, 4, TRUE);

               proto_tree_add_text( csftree, tvb, 28, 2, "Timeout: %u",
                                   tvb_get_letohs( tvb, 28 ) );

               ifacehndl = tvb_get_letohl( tvb, 24 );
               dissect_cpf( encap_cmd, tvb, pinfo, csftree, 30, ifacehndl );
               break;

            case INDICATE_STATUS:
            case CANCEL:
            default:

               /* Can not decode - Just show the data */
               add_byte_array_text_to_proto_tree( header_tree, tvb, 24, encap_data_length, "Encap Data: " );
               break;

         } /* end of switch() */

      } /* end of if( encapsulated data ) */

   }
} /* end of dissect_enip_pdu() */

static int
dissect_enip_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   guint16  encap_cmd;

   g_tree = tree;

   /* An ENIP packet is at least 4 bytes long - we need the command type. */
   if (!tvb_bytes_exist(tvb, 0, 4))
      return 0;

   /* Get the command type and see if it's valid. */
   encap_cmd = tvb_get_letohs( tvb, 0 );
   if (match_strval(encap_cmd, encap_cmd_vals) == NULL)
      return 0;	/* not a known command */

   dissect_enip_pdu(tvb, pinfo, tree);
   return tvb_length(tvb);
}

static int
dissect_enip_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   guint16  encap_cmd;

   g_tree = tree;

   /* An ENIP packet is at least 4 bytes long - we need the command type. */
   if (!tvb_bytes_exist(tvb, 0, 4))
      return 0;

   /* Get the command type and see if it's valid. */
   encap_cmd = tvb_get_letohs( tvb, 0 );
   if (match_strval(encap_cmd, encap_cmd_vals) == NULL)
      return 0;	/* not a known command */

   tcp_dissect_pdus(tvb, pinfo, tree, enip_desegment, 4,
	get_enip_pdu_len, dissect_enip_pdu);
   return tvb_length(tvb);
}

/* Code to actually dissect the io packets*/
static void
dissect_enipio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   /* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *enip_tree;

	g_tree = tree;

   /* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENIP");

   /* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree)
	{
      /* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_enip, tvb, 0, -1, FALSE);

		enip_tree = proto_item_add_subtree(ti, ett_enip);

      dissect_cpf( 0xFFFF, tvb, pinfo, enip_tree, 0, 0 );
	}

} /* end of dissect_enipio() */


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_enip(void)
{
   /* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_enip_command,
			{ "Command", "enip.command",
			FT_UINT16, BASE_HEX, VALS(encap_cmd_vals), 0,
			"Encapsulation command", HFILL }
		},
		{ &hf_enip_session,
			{ "Session Handle", "enip.session",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Session identification", HFILL }
		},
		{ &hf_enip_status,
			{ "Status", "enip.status",
			FT_UINT32, BASE_HEX, VALS(encap_status_vals), 0,
			"Status code", HFILL }
		},
		{ &hf_enip_sendercontex,
			{ "Sender Context", "enip.context",
			FT_BYTES, BASE_HEX, NULL, 0,
			"Information pertient to the sender", HFILL }
		},
		{ &hf_enip_options,
			{ "Options", "enip.options",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Options flags", HFILL }
		},
		{ &hf_enip_lsr_tcp,
			{ "Supports CIP Encapsulation via TCP", "enip.lsr.capaflags.tcp",
			FT_UINT16, BASE_DEC, VALS(enip_true_false_vals), 0x0020,
			"ListServices Reply: Supports CIP Encapsulation via TCP", HFILL }
		},
		{ &hf_enip_lsr_udp,
			{ "Supports CIP Class 0 or 1 via UDP", "enip.lsr.capaflags.udp",
			FT_UINT16, BASE_DEC, VALS(enip_true_false_vals), 0x0100,
			"ListServices Reply: Supports CIP Class 0 or 1 via UDP", HFILL }
		},
		/* Send Request/Reply Data */
		{ &hf_enip_srrd_ifacehnd,
			{ "Interface Handle",           "enip.srrd.iface",
			FT_UINT32, BASE_HEX, VALS(enip_interface_handle_vals), 0,
			"SendRRData: Interface handle", HFILL }
		},
		/* Send Unit Data */
		{ &hf_enip_sud_ifacehnd,
			{ "Interface Handle",           "enip.sud.iface",
			FT_UINT32, BASE_HEX, VALS(enip_interface_handle_vals), 0,
			"SendUnitData: Interface handle", HFILL }
		},
		/* List identity reply */
      { &hf_enip_lir_sinfamily,
			{ "sin_family", "enip.lir.sa.sinfamily",
			FT_UINT16, BASE_DEC, NULL, 0,
			"ListIdentity Reply: Socket Address.Sin Family", HFILL }
		},
      { &hf_enip_lir_sinport,
			{ "sin_port", "enip.lir.sa.sinport",
			FT_UINT16, BASE_DEC, NULL, 0,
			"ListIdentity Reply: Socket Address.Sin Port", HFILL }
		},
      { &hf_enip_lir_sinaddr,
			{ "sin_addr", "enip.lir.sa.sinaddr",
			FT_IPv4, BASE_HEX, NULL, 0,
			"ListIdentity Reply: Socket Address.Sin Addr", HFILL }
		},
      { &hf_enip_lir_sinzero,
			{ "sin_zero", "enip.lir.sa.sinzero",
			FT_BYTES, BASE_HEX, NULL, 0,
			"ListIdentity Reply: Socket Address.Sin Zero", HFILL }
		},
		{ &hf_enip_lir_vendor,
			{ "Vendor ID", "enip.lir.vendor",
			FT_UINT16, BASE_HEX, VALS(cip_vendor_vals), 0,
			"ListIdentity Reply: Vendor ID", HFILL }
		},
      { &hf_enip_lir_devtype,
			{ "Device Type", "enip.lir.devtype",
			FT_UINT16, BASE_DEC, VALS(cip_devtype_vals), 0,
			"ListIdentity Reply: Device Type", HFILL }
		},
      { &hf_enip_lir_prodcode,
			{ "Product Code", "enip.lir.prodcode",
			FT_UINT16, BASE_DEC, NULL, 0,
			"ListIdentity Reply: Product Code", HFILL }
		},
      { &hf_enip_lir_status,
			{ "Status", "enip.lir.status",
			FT_UINT16, BASE_HEX, NULL, 0,
			"ListIdentity Reply: Status", HFILL }
		},
      { &hf_enip_lir_serial,
			{ "Serial Number", "enip.lir.serial",
			FT_UINT32, BASE_HEX, NULL, 0,
			"ListIdentity Reply: Serial Number", HFILL }
		},
      { &hf_enip_lir_name,
			{ "Product Name", "enip.lir.name",
			FT_STRING, BASE_NONE, NULL, 0,
			"ListIdentity Reply: Product Name", HFILL }
		},
      { &hf_enip_lir_state,
			{ "State", "enip.lir.state",
			FT_UINT8, BASE_HEX, NULL, 0,
			"ListIdentity Reply: State", HFILL }
		},
		/* Common Packet Format */
		{ &hf_enip_cpf_typeid,
			{ "Type ID",          "enip.cpf.typeid",
			FT_UINT16, BASE_HEX, VALS(cdf_type_vals), 0,
			"Common Packet Format: Type of encapsulated item", HFILL }
		},
		/* Sequenced Address Type */
      { &hf_enip_cpf_sai_connid,
			{ "Connection ID", "enip.cpf.sai.connid",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Common Packet Format: Sequenced Address Item, Connection Identifier", HFILL }
		},
      { &hf_enip_cpf_sai_seqnum,
			{ "Sequence Number", "enip.cpf.sai.seq",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Common Packet Format: Sequenced Address Item, Sequence Number", HFILL }
		}
   };


/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_enip,
		&ett_count_tree,
		&ett_type_tree,
	&ett_command_tree,
		&ett_sockadd,
		&ett_lsrcf,
	};
	module_t *enip_module;

/* Register the protocol name and description */
	proto_enip = proto_register_protocol("EtherNet/IP (Industrial Protocol)",
	    "ENIP", "enip");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_enip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	enip_module = prefs_register_protocol(proto_enip, NULL);
	prefs_register_bool_preference(enip_module, "desegment",
	    "Desegment all EtherNet/IP messages spanning multiple TCP segments",
	    "Whether the EtherNet/IP dissector should desegment all messages spanning multiple TCP segments",
	    &enip_desegment);

   subdissector_sud_table = register_dissector_table("enip.sud.iface",
		"SendUnitData.Interface Handle", FT_UINT32, BASE_HEX);

   subdissector_srrd_table = register_dissector_table("enip.srrd.iface",
		"SendRequestReplyData.Interface Handle", FT_UINT32, BASE_HEX);

} /* end of proto_register_enip() */


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_enip(void)
{
	dissector_handle_t enip_udp_handle, enip_tcp_handle;
	dissector_handle_t enipio_handle;

	/* Register for EtherNet/IP, using TCP */
	enip_tcp_handle = new_create_dissector_handle(dissect_enip_tcp, proto_enip);
	dissector_add("tcp.port", ENIP_ENCAP_PORT, enip_tcp_handle);

	/* Register for EtherNet/IP, using UDP */
	enip_udp_handle = new_create_dissector_handle(dissect_enip_udp, proto_enip);
	dissector_add("udp.port", ENIP_ENCAP_PORT, enip_udp_handle);

	/* Register for EtherNet/IP IO data (UDP) */
	enipio_handle = create_dissector_handle(dissect_enipio, proto_enip);
	dissector_add("udp.port", ENIP_IO_PORT, enipio_handle);

	/* Find dissector for data packet */
	data_handle = find_dissector("data");

} /* end of proto_reg_handoff_enip() */
