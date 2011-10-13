/* packet-enip.c
 * Routines for EtherNet/IP (Industrial Protocol) dissection
 * EtherNet/IP Home: www.odva.org
 *
 * Copyright 2003-2004
 * Magnus Hansson <mah@hms.se>
 * Joakim Wiberg <jow@hms.se>
 *
 * Conversation data support for CIP
 *   Jan Bartels, Siempelkamp Maschinen- und Anlagenbau GmbH & Co. KG
 *   Copyright 2007
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/etypes.h>
#include "packet-tcp.h"
#include "packet-enip.h"
#include "packet-cip.h"

/* Communication Ports */
#define ENIP_ENCAP_PORT    44818 /* EtherNet/IP located on port 44818    */
#define ENIP_IO_PORT       2222  /* EtherNet/IP IO located on port 2222  */

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
static int hf_enip_length          = -1;
static int hf_enip_options         = -1;
static int hf_enip_sendercontex    = -1;
static int hf_enip_status          = -1;
static int hf_enip_session         = -1;
static int hf_enip_encapver        = -1;
static int hf_enip_sinfamily       = -1;
static int hf_enip_sinport         = -1;
static int hf_enip_sinaddr         = -1;
static int hf_enip_sinzero         = -1;
static int hf_enip_timeout         = -1;
static int hf_enip_encap_data      = -1;

static int hf_enip_lir_vendor      = -1;
static int hf_enip_lir_devtype     = -1;
static int hf_enip_lir_prodcode    = -1;
static int hf_enip_lir_revision    = -1;
static int hf_enip_lir_status      = -1;
static int hf_enip_lir_serial      = -1;
static int hf_enip_lir_namelen     = -1;
static int hf_enip_lir_name        = -1;
static int hf_enip_lir_state       = -1;

static int hf_enip_lsr_capaflags   = -1;
static int hf_enip_lsr_tcp         = -1;
static int hf_enip_lsr_udp         = -1;
static int hf_enip_lsr_servicename = -1;

static int hf_enip_rs_version      = -1;
static int hf_enip_rs_optionflags  = -1;

static int hf_enip_srrd_ifacehnd   = -1;

static int hf_enip_sud_ifacehnd    = -1;

static int hf_enip_cpf_itemcount   = -1;
static int hf_enip_cpf_typeid      = -1;
static int hf_enip_cpf_length      = -1;
static int hf_enip_cpf_cdi_seqcnt  = -1;
static int hf_enip_cpf_cai_connid  = -1;
static int hf_enip_cpf_sai_connid  = -1;
static int hf_enip_cpf_sai_seqnum  = -1;
static int hf_enip_cpf_data        = -1;

static int hf_enip_response_in = -1;
static int hf_enip_response_to = -1;
static int hf_enip_time = -1;
static int hf_enip_connection_transport_data = -1;

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
static heur_dissector_list_t   heur_subdissector_conndata_table;

static gboolean enip_desegment = TRUE;

static int proto_dlr     = -1;

static int hf_dlr_ringsubtype      = -1;
static int hf_dlr_ringprotoversion = -1;
static int hf_dlr_frametype        = -1;
static int hf_dlr_sourceport       = -1;
static int hf_dlr_sourceip         = -1;
static int hf_dlr_sequenceid       = -1;

static int hf_dlr_ringstate            = -1;
static int hf_dlr_supervisorprecedence = -1;
static int hf_dlr_beaconinterval       = -1;
static int hf_dlr_beacontimeout        = -1;
static int hf_dlr_beaconreserved       = -1;

static int hf_dlr_nreqreserved   = -1;

static int hf_dlr_nressourceport = -1;
static int hf_dlr_nresreserved   = -1;

static int hf_dlr_lnknbrstatus   = -1;
static int hf_dlr_lnknbrreserved = -1;

static int hf_dlr_lfreserved = -1;

static int hf_dlr_anreserved = -1;

static int hf_dlr_sonumnodes = -1;
static int hf_dlr_somac      = -1;
static int hf_dlr_soip       = -1;
static int hf_dlr_soreserved = -1;

static gint ett_dlr = -1;

/* Translate function to string - Encapsulation commands */
static const value_string encap_cmd_vals[] = {
   { NOP,               "NOP"                },
   { LIST_SERVICES,     "List Services"      },
   { LIST_IDENTITY,     "List Identity"      },
   { LIST_INTERFACES,   "List Interfaces"    },
   { REGISTER_SESSION,  "Register Session"   },
   { UNREGISTER_SESSION,"Unregister Session" },
   { SEND_RR_DATA,      "Send RR Data"       },
   { SEND_UNIT_DATA,    "Send Unit Data"     },
   { INDICATE_STATUS,   "Indicate Status"    },
   { CANCEL,            "Cancel"             },

   { 0,                 NULL                 }
};

/* Translate function to string - Encapsulation status */
static const value_string encap_status_vals[] = {
   { SUCCESS,              "Success" },
   { INVALID_CMD,          "Invalid Command" },
   { NO_RESOURCES,         "No Memory Resources" },
   { INCORRECT_DATA,       "Incorrect Data" },
   { INVALID_SESSION,      "Invalid Session Handle" },
   { INVALID_LENGTH,       "Invalid Length" },
   { UNSUPPORTED_PROT_REV, "Unsupported Protocol Revision" },

   { 0,                    NULL }
};

/* Translate function to Common data format values */
static const value_string cdf_type_vals[] = {
   { CDF_NULL,             "Null Address Item" },
   { LIST_IDENTITY_RESP,   "List Identity Response" },
   { CONNECTION_BASED,     "Connected Address Item" },
   { CONNECTION_TRANSPORT, "Connected Data Item" },
   { UNCONNECTED_MSG,      "Unconnected Data Item" },
   { LIST_SERVICES_RESP,   "List Services Response" },
   { SOCK_ADR_INFO_OT,     "Socket Address Info O->T" },
   { SOCK_ADR_INFO_TO,     "Socket Address Info T->O" },
   { SEQ_ADDRESS,          "Sequenced Address Item" },

   { 0,                    NULL }
};

/* Translate interface handle to string */
static const value_string enip_interface_handle_vals[] = {
   { 0,        "CIP" },

   { 0,        NULL  }
};

/* Translate function to DLR Frame Type values */
static const value_string dlr_frame_type_vals[] = {
   { DLR_FT_BEACON,           "Beacon" },
   { DLR_FT_NEIGHBOR_REQ,     "Neighbor_Check_Request" },
   { DLR_FT_NEIGHBOR_RES,     "Neighbor_Check_Response" },
   { DLR_FT_LINK_STAT,        "Link_Status / Neighbor_Status" },
   { DLR_FT_LOCATE_FLT,       "Locate_Fault" },
   { DLR_FT_ANNOUNCE,         "Announce" },
   { DLR_FT_SIGN_ON,          "Sign_On" },

   { 0,                    NULL }
};

/* Translate function to DLR Source Port values */
static const value_string dlr_source_port_vals[] = {
   { 0,     "Port 1 or Port 2" },
   { 1,     "Port 1" },
   { 2,     "Port 2" },

   { 0,                    NULL }
};

/* Translate function to DLR Ring State values */
static const value_string dlr_ring_state_vals[] = {
   { 1,     "RING_NORMAL_STATE" },
   { 2,     "RING_FAULT_STATE" },

   { 0,                    NULL }
};


/* Translate function to DLR Link_Status/Neighbor_Status Status values */
static const value_string dlr_lnk_nbr_status_vals[] = {
   { 0x01,     "PORT_1_UP" },
   { 0x02,     "PORT_2_UP" },
   { 0x80,     "NEIGHBOR_STATUS_FLAG" },

   { 0,                    NULL }
};

static GHashTable *enip_request_hashtable = NULL;

/* Return codes of function classifying packets as query/response */
#define ENIP_REQUEST_PACKET     0
#define ENIP_RESPONSE_PACKET    1
#define ENIP_CANNOT_CLASSIFY    2

enum enip_packet_data_type { EPDT_UNKNOWN, EPDT_CONNECTED_TRANSPORT, EPDT_UNCONNECTED };

typedef struct enip_request_key {
   gint requesttype;
   enum enip_packet_data_type type;
   guint32 session_handle;
   guint64 sender_context;
   guint32 conversation;
   union {
      struct {
         guint32 connid;
         guint16 sequence;
      } connected_transport;
   } data;
} enip_request_key_t;

typedef struct enip_request_val {
   emem_tree_t *frames;
} enip_request_val_t;

/*
 * Hash Functions
 */
static gint
enip_request_equal(gconstpointer v, gconstpointer w)
{
   const enip_request_key_t *v1 = (const enip_request_key_t *)v;
   const enip_request_key_t *v2 = (const enip_request_key_t *)w;

   if (  v1->conversation == v2->conversation
         && v1->session_handle == v2->session_handle
         && v1->type == v2->type
         && ( (  v1->sender_context == v2->sender_context   /* heuristic approach */
                 && v1->type == EPDT_UNCONNECTED
                 )
              ||
              (  v1->data.connected_transport.connid == v2->data.connected_transport.connid
                 && v1->data.connected_transport.sequence == v2->data.connected_transport.sequence
                 && v1->type == EPDT_CONNECTED_TRANSPORT
                 )
            )
      )
      return 1;

   return 0;
}

static void
enip_fmt_lir_revision( gchar *result, guint32 revision )
{
   g_snprintf( result, 5, "%d.%02d", (guint8)(( revision & 0xFF00 ) >> 8), (guint8)(revision & 0xFF) );
}

static guint
enip_request_hash (gconstpointer v)
{
   const enip_request_key_t *key = (const enip_request_key_t *)v;
   guint val;

   val = (guint)( key->conversation * 37 + key->session_handle * 93 + key->type * 765
                + key->sender_context * 23
                + key->data.connected_transport.connid * 87 + key->data.connected_transport.sequence * 834 );

   return val;
}

static enip_request_info_t *
enip_match_request( packet_info *pinfo, proto_tree *tree, enip_request_key_t *prequest_key )
{
   enip_request_key_t *new_request_key;
   enip_request_val_t *request_val;
   enip_request_info_t *request_info = NULL;

   request_info = NULL;
   request_val = g_hash_table_lookup( enip_request_hashtable, prequest_key );
   if(!pinfo->fd->flags.visited)
   {
      if ( prequest_key && prequest_key->requesttype == ENIP_REQUEST_PACKET )
      {
         if ( request_val == NULL )
         {
            new_request_key = se_memdup(prequest_key, sizeof(enip_request_key_t));

            request_val = se_alloc(sizeof(enip_request_val_t));
            request_val->frames = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "enip_frames");

            g_hash_table_insert(enip_request_hashtable, new_request_key, request_val );
         }

         request_info = se_alloc(sizeof(enip_request_info_t));
         request_info->req_num = pinfo->fd->num;
         request_info->rep_num = 0;
         request_info->req_time = pinfo->fd->abs_ts;
         request_info->cip_info = NULL;
         se_tree_insert32(request_val->frames, pinfo->fd->num, (void *)request_info);
      }
      if( request_val && prequest_key && prequest_key->requesttype == ENIP_RESPONSE_PACKET )
      {
         request_info = (enip_request_info_t*)se_tree_lookup32_le( request_val->frames, pinfo->fd->num );
         if ( request_info )
         {
            request_info->rep_num = pinfo->fd->num;
         }
      }
   }
   else
   {
      if ( request_val )
         request_info = (enip_request_info_t*)se_tree_lookup32_le( request_val->frames, pinfo->fd->num );
   }

   if ( tree && request_info )
   {
      /* print state tracking in the tree */
      if ( prequest_key && prequest_key->requesttype == ENIP_REQUEST_PACKET )
      {
         /* This is a request */
         if (request_info->rep_num)
         {
            proto_item *it;

            it = proto_tree_add_uint(tree, hf_enip_response_in,
                  NULL, 0, 0, request_info->rep_num);
            PROTO_ITEM_SET_GENERATED(it);
         }
      }
      else
      {
         if ( prequest_key && prequest_key->requesttype == ENIP_RESPONSE_PACKET )
         {
            /* This is a reply */
            if (request_info->req_num)
            {
               proto_item *it;
               nstime_t ns;

               it = proto_tree_add_uint(tree, hf_enip_response_to,
                     NULL, 0, 0, request_info->req_num);
               PROTO_ITEM_SET_GENERATED(it);

               nstime_delta(&ns, &pinfo->fd->abs_ts, &request_info->req_time);
               it = proto_tree_add_time(tree, hf_enip_time, NULL, 0, 0, &ns);
               PROTO_ITEM_SET_GENERATED(it);
            }
         }
      }
   }
   return request_info;
}

/*
 * Connection management
 */

typedef struct enip_conn_key {
   guint16 ConnSerialNumber;
   guint16 VendorID;
   guint32 DeviceSerialNumber;
} enip_conn_key_t;

typedef struct enip_conn_val {
   guint16 ConnSerialNumber;
   guint16 VendorID;
   guint32 DeviceSerialNumber;
   guint32 O2TConnID;
   guint32 T2OConnID;
   guint32 openframe;
   guint32 closeframe;
   guint32 connid;
} enip_conn_val_t;

typedef struct _enip_conv_info_t {
   emem_tree_t *O2TConnIDs;
   emem_tree_t *T2OConnIDs;
} enip_conv_info_t;

static GHashTable *enip_conn_hashtable = NULL;
static guint32 enip_unique_connid = 1;

static gint
enip_conn_equal(gconstpointer v, gconstpointer w)
{
  const enip_conn_key_t *v1 = (const enip_conn_key_t *)v;
  const enip_conn_key_t *v2 = (const enip_conn_key_t *)w;

  if (  v1->ConnSerialNumber == v2->ConnSerialNumber
     && v1->VendorID == v2->VendorID
     && v1->DeviceSerialNumber == v2->DeviceSerialNumber
     )
    return 1;

  return 0;
}

static guint
enip_conn_hash (gconstpointer v)
{
   const enip_conn_key_t *key = (const enip_conn_key_t *)v;
   guint val;

   val = (guint)( key->ConnSerialNumber + key->VendorID + key->DeviceSerialNumber );

   return val;
}

void
enip_open_cip_connection(packet_info *pinfo, guint16 ConnSerialNumber,
                         guint16 VendorID, guint32 DeviceSerialNumber,
                         guint32 O2TConnID, guint32 T2OConnID )
{
   enip_conn_key_t *conn_key;
   enip_conn_val_t *conn_val;
   conversation_t *conversation;
   enip_conv_info_t *enip_info;

   if (pinfo->fd->flags.visited)
      return;

   conn_key = se_alloc(sizeof(enip_conn_key_t));
   conn_key->ConnSerialNumber = ConnSerialNumber;
   conn_key->VendorID = VendorID;
   conn_key->DeviceSerialNumber = DeviceSerialNumber;

   conn_val = g_hash_table_lookup( enip_conn_hashtable, conn_key );
   if ( conn_val == NULL )
   {
      conn_val = se_alloc(sizeof(enip_conn_val_t));

      conn_val->ConnSerialNumber = ConnSerialNumber;
      conn_val->VendorID = VendorID;
      conn_val->DeviceSerialNumber = DeviceSerialNumber;
      conn_val->O2TConnID = O2TConnID;
      conn_val->T2OConnID = T2OConnID;
      conn_val->openframe = pinfo->fd->num;
      conn_val->closeframe = 0;
      conn_val->connid = enip_unique_connid++;

      g_hash_table_insert(enip_conn_hashtable, conn_key, conn_val );

      conversation = find_or_create_conversation(pinfo);

      /*
       * Do we already have a state structure for this conv
       */
      enip_info = conversation_get_proto_data(conversation, proto_enip);
      if (!enip_info)
      {
         /*
          * No.  Attach that information to the conversation, and add
          * it to the list of information structures.
          */
         enip_info = se_alloc(sizeof(enip_conv_info_t));
         enip_info->O2TConnIDs = se_tree_create_non_persistent(
                  EMEM_TREE_TYPE_RED_BLACK, "enip_O2T");
         enip_info->T2OConnIDs = se_tree_create_non_persistent(
                  EMEM_TREE_TYPE_RED_BLACK, "enip_T2O");

         conversation_add_proto_data(conversation, proto_enip, enip_info);
      }
      se_tree_insert32(enip_info->O2TConnIDs, O2TConnID, (void *)conn_val);
      se_tree_insert32(enip_info->O2TConnIDs, T2OConnID, (void *)conn_val);
   }
}

void
enip_close_cip_connection(packet_info *pinfo, guint16 ConnSerialNumber,
                          guint16 VendorID, guint32 DeviceSerialNumber )
{
   enip_conn_key_t conn_key;
   enip_conn_val_t *conn_val;

   if (pinfo->fd->flags.visited)
      return;

   conn_key.ConnSerialNumber = ConnSerialNumber;
   conn_key.VendorID = VendorID;
   conn_key.DeviceSerialNumber = DeviceSerialNumber;

   conn_val = g_hash_table_lookup( enip_conn_hashtable, &conn_key );
   if ( conn_val )
   {
      conn_val->closeframe = pinfo->fd->num;
   }
}

static guint32
enip_get_connid(packet_info *pinfo, enip_request_key_t *prequest_key, guint32 connid)
{
   conversation_t *conversation;
   enip_conv_info_t *enip_info;
   enip_conn_val_t *conn_val;

   if (  prequest_key == NULL
      || ( prequest_key->requesttype != ENIP_REQUEST_PACKET && prequest_key->requesttype != ENIP_RESPONSE_PACKET )
      )
      return 0;

   /*
    * Do we have a conversation for this connection?
    */
   conversation = find_conversation(pinfo->fd->num,
            &pinfo->src, &pinfo->dst,
            pinfo->ptype,
            pinfo->srcport, pinfo->destport, 0);
   if (conversation == NULL)
      return 0;

   /*
    * Do we already have a state structure for this conv
    */
   enip_info = conversation_get_proto_data(conversation, proto_enip);
   if (!enip_info)
      return 0;

   conn_val = NULL;
   switch ( prequest_key->requesttype )
   {
   case ENIP_REQUEST_PACKET:
      conn_val = se_tree_lookup32( enip_info->O2TConnIDs, connid );
      if ( conn_val == NULL )
         conn_val = se_tree_lookup32( enip_info->T2OConnIDs, connid );
      break;

   case ENIP_RESPONSE_PACKET:
      conn_val = se_tree_lookup32( enip_info->T2OConnIDs, connid );
      if ( conn_val == NULL )
         conn_val = se_tree_lookup32( enip_info->O2TConnIDs, connid );
      break;
   }

   if ( conn_val == NULL )
      return 0;

   if ( conn_val->openframe > pinfo->fd->num )
      return 0;

   return conn_val->connid;
}

/*
 * Protocol initialization
 */
static void
enip_init_protocol(void)
{
   if (enip_request_hashtable)
      g_hash_table_destroy(enip_request_hashtable);
   enip_request_hashtable = g_hash_table_new(enip_request_hash, enip_request_equal);

   if (enip_conn_hashtable)
      g_hash_table_destroy(enip_conn_hashtable);
   enip_conn_hashtable = g_hash_table_new(enip_conn_hash, enip_conn_equal);
}

/* Disssect Common Packet Format */
static void
dissect_cpf(enip_request_key_t *request_key, int command, tvbuff_t *tvb,
            packet_info *pinfo, proto_tree *tree, int offset, guint32 ifacehndl)
{
   proto_item *temp_item, *count_item, *type_item, *sockaddr_item;
   proto_tree *temp_tree, *count_tree, *item_tree, *sockaddr_tree;
   int item_count, item_length, item;
   unsigned char name_length;
   tvbuff_t *next_tvb;
   enip_request_info_t *request_info;

   /* Create item count tree */
   item_count = tvb_get_letohs( tvb, offset );
   count_item = proto_tree_add_item( tree, hf_enip_cpf_itemcount, tvb, offset, 2, ENC_LITTLE_ENDIAN );
   count_tree = proto_item_add_subtree( count_item, ett_count_tree );

   while( item_count-- )
   {
      /* Add item type tree to item count tree*/
      type_item = proto_tree_add_item( count_tree, hf_enip_cpf_typeid, tvb, offset+2, 2, ENC_LITTLE_ENDIAN );
      item_tree = proto_item_add_subtree( type_item, ett_type_tree );

      /* Add length field to item type tree */
      proto_tree_add_item( item_tree, hf_enip_cpf_length, tvb, offset+4, 2, ENC_LITTLE_ENDIAN );

      item        = tvb_get_letohs( tvb, offset+2 );
      item_length = tvb_get_letohs( tvb, offset+4 );

      if( item_length )
      {
          /* Add item data field */

          switch( item )
          {
              case CONNECTION_BASED:

                  if ( request_key )
                  {
                      request_key->type = EPDT_CONNECTED_TRANSPORT;
                      request_key->data.connected_transport.connid = enip_get_connid( pinfo, request_key, tvb_get_letohl( tvb, offset+6 ) );
                  }
               /* Add Connection identifier */
               proto_tree_add_item(item_tree, hf_enip_cpf_cai_connid, tvb, offset+6, 4, ENC_LITTLE_ENDIAN );

               /* Add Connection ID to Info col */
               if(check_col(pinfo->cinfo, COL_INFO))
               {
                  col_append_fstr(pinfo->cinfo, COL_INFO,
                     ", CONID: 0x%08X",
                     tvb_get_letohl( tvb, offset+6 ) );
               }

               break;

            case UNCONNECTED_MSG:
               request_info = NULL;
               if ( request_key )
               {
                  request_key->type = EPDT_UNCONNECTED;
                  request_info = enip_match_request( pinfo, tree, request_key );
               }

               /* Call dissector for interface */
               next_tvb = tvb_new_subset( tvb, offset+6, item_length, item_length );
               p_add_proto_data(pinfo->fd, proto_enip, request_info);
               if( tvb_length_remaining(next_tvb, 0) == 0 || !dissector_try_uint(subdissector_srrd_table, ifacehndl, next_tvb, pinfo, g_tree) )
               {
                  /* Show the undissected payload */
                   if( tvb_length_remaining(tvb, offset) > 0 )
                     call_dissector( data_handle, next_tvb, pinfo, g_tree );
               }
               p_remove_proto_data(pinfo->fd, proto_enip);

               break;

            case CONNECTION_TRANSPORT:

               if( command == SEND_UNIT_DATA )
               {
                  request_info = NULL;

                  if ( request_key )
                  {
                     request_key->type = EPDT_CONNECTED_TRANSPORT;
                     request_key->data.connected_transport.sequence = tvb_get_letohs( tvb, offset+6 );
                     request_info = enip_match_request( pinfo, tree, request_key );
                  }

                  /*
                  ** If the encapsulation service is SendUnit Data, this is a
                  ** encapsulated connected message
                  */

                  /* Add sequence count ( Transport Class 1,2,3 ) */
                  proto_tree_add_item( item_tree, hf_enip_cpf_cdi_seqcnt, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );

                  /* Call dissector for interface */
                  next_tvb = tvb_new_subset (tvb, offset+8, item_length-2, item_length-2);
                  p_add_proto_data(pinfo->fd, proto_enip, request_info);
                  if( tvb_length_remaining(next_tvb, 0) == 0 || !dissector_try_uint(subdissector_sud_table, ifacehndl, next_tvb, pinfo, g_tree) )
                  {
                     /* Show the undissected payload */
                      if( tvb_length_remaining(tvb, offset) > 0 )
                        call_dissector( data_handle, next_tvb, pinfo, g_tree );
                  }
                  p_remove_proto_data(pinfo->fd, proto_enip);
               }
               else
               {
                  /* Display data */
                  if (tvb_length_remaining(tvb, offset+6) > 0)
                  {
                      next_tvb = tvb_new_subset(tvb, offset+6, item_length, item_length);
                      if(!dissector_try_heuristic(heur_subdissector_conndata_table, next_tvb, pinfo, g_tree))
                      {
                        proto_tree_add_item(item_tree, hf_enip_connection_transport_data, tvb, offset+6, item_length, ENC_NA);
                      }
                  }
               } /* End of if send unit data */

               break;


            case LIST_IDENTITY_RESP:

               /* Encapsulation version */
               proto_tree_add_item( item_tree, hf_enip_encapver, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );

               /* Socket Address */
               sockaddr_item = proto_tree_add_text( item_tree, tvb, offset+8, 16, "Socket Address");
               sockaddr_tree = proto_item_add_subtree( sockaddr_item, ett_sockadd );

               /* Socket address struct - sin_family */
               proto_tree_add_item(sockaddr_tree, hf_enip_sinfamily,
                     tvb, offset+8, 2, ENC_BIG_ENDIAN );

               /* Socket address struct - sin_port */
               proto_tree_add_item(sockaddr_tree, hf_enip_sinport,
                     tvb, offset+10, 2, ENC_BIG_ENDIAN );

               /* Socket address struct - sin_address */
               proto_tree_add_item(sockaddr_tree, hf_enip_sinaddr,
                     tvb, offset+12, 4, ENC_BIG_ENDIAN );

               /* Socket address struct - sin_zero */
               proto_tree_add_item(sockaddr_tree, hf_enip_sinzero,
                     tvb, offset+16, 8, ENC_NA );

               /* Vendor ID */
               proto_tree_add_item(item_tree, hf_enip_lir_vendor,
                     tvb, offset+24, 2, ENC_LITTLE_ENDIAN );

               /* Device Type */
               proto_tree_add_item(item_tree, hf_enip_lir_devtype,
                     tvb, offset+26, 2, ENC_LITTLE_ENDIAN );

               /* Product Code */
               proto_tree_add_item(item_tree, hf_enip_lir_prodcode,
                     tvb, offset+28, 2, ENC_LITTLE_ENDIAN );

               /* Revision */
               proto_tree_add_item(item_tree, hf_enip_lir_revision,
                     tvb, offset+30, 2, ENC_NA );

               /* Status */
               proto_tree_add_item(item_tree, hf_enip_lir_status,
                     tvb, offset+32, 2, ENC_LITTLE_ENDIAN );

               /* Serial Number */
               proto_tree_add_item(item_tree, hf_enip_lir_serial,
                     tvb, offset+34, 4, ENC_LITTLE_ENDIAN );

               /* Product Name Length */
               name_length = tvb_get_guint8( tvb, offset+38 );
               proto_tree_add_item( item_tree, hf_enip_lir_namelen,
                     tvb, offset+38, 1, ENC_NA );

               /* Product Name */
               proto_tree_add_item(item_tree, hf_enip_lir_name,
                     tvb, offset+39, name_length, ENC_NA );

               /* Append product name to info column */
               if(check_col(pinfo->cinfo, COL_INFO))
               {
                  col_append_fstr( pinfo->cinfo, COL_INFO, ", %s",
                      tvb_format_text(tvb, offset+39, name_length));
               }

               /* State */
               proto_tree_add_item(item_tree, hf_enip_lir_state,
                     tvb, offset+name_length+39, 1, ENC_NA );
               break;


            case SOCK_ADR_INFO_OT:
            case SOCK_ADR_INFO_TO:

               /* Socket address struct - sin_family */
               proto_tree_add_item(item_tree, hf_enip_sinfamily,
                     tvb, offset+6, 2, ENC_BIG_ENDIAN );

               /* Socket address struct - sin_port */
               proto_tree_add_item(item_tree, hf_enip_sinport,
                     tvb, offset+8, 2, ENC_BIG_ENDIAN );

               /* Socket address struct - sin_address */
               proto_tree_add_item(item_tree, hf_enip_sinaddr,
                     tvb, offset+10, 4, ENC_BIG_ENDIAN );

               /* Socket address struct - sin_zero */
               proto_tree_add_item( item_tree, hf_enip_sinzero,
                     tvb, offset+14, 8, ENC_NA );
               break;


            case SEQ_ADDRESS:
               proto_tree_add_item(item_tree, hf_enip_cpf_sai_connid,
                     tvb, offset+6, 4, ENC_LITTLE_ENDIAN );

               proto_tree_add_item(item_tree, hf_enip_cpf_sai_seqnum,
                     tvb, offset+10, 4, ENC_LITTLE_ENDIAN );

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
               proto_tree_add_item( item_tree, hf_enip_encapver, tvb, offset+6, 2, ENC_LITTLE_ENDIAN );

               /* Capability flags */
               temp_item = proto_tree_add_item( item_tree, hf_enip_lsr_capaflags, tvb, offset+8, 2, ENC_LITTLE_ENDIAN );
               temp_tree = proto_item_add_subtree( temp_item, ett_lsrcf );

               proto_tree_add_item( temp_tree, hf_enip_lsr_tcp, tvb, offset+8, 2, ENC_LITTLE_ENDIAN );
               proto_tree_add_item( temp_tree, hf_enip_lsr_udp, tvb, offset+8, 2, ENC_LITTLE_ENDIAN );

               /* Name of service */
               proto_tree_add_item( item_tree, hf_enip_lsr_servicename, tvb, offset+10, 16, ENC_NA );

               /* Append service name to info column */
               if(check_col(pinfo->cinfo, COL_INFO))
               {
                  col_append_fstr( pinfo->cinfo, COL_INFO, ", %s",
                      tvb_format_stringzpad(tvb, offset+10, 16) );
               }

               break;


            default:

               proto_tree_add_item(item_tree, hf_enip_cpf_data, tvb, offset+6, item_length, ENC_NA);
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
         return ENIP_RESPONSE_PACKET;
      else if ( ENIP_ENCAP_PORT == pinfo->destport )
         return ENIP_REQUEST_PACKET;
   }
   /* else, cannot classify */
   return ENIP_CANNOT_CLASSIFY;
}

static guint
get_enip_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
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
   int      packet_type;
   guint16  encap_cmd, encap_data_length;
   const char *pkt_type_str = "";
   guint32  ifacehndl;
   enip_request_key_t request_key;
   conversation_t *conversation;

   /* Set up structures needed to add the protocol subtree and manage it */
   proto_item *ti, *encaph, *csf;
   proto_tree *enip_tree, *header_tree = NULL, *csftree;

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENIP");
   col_clear(pinfo->cinfo, COL_INFO);

   encap_cmd = tvb_get_letohs( tvb, 0 );

   packet_type = classify_packet(pinfo);

   if( check_col(pinfo->cinfo, COL_INFO) )
   {
      switch ( packet_type )
      {
         case ENIP_REQUEST_PACKET:
            pkt_type_str="Req";
            break;

         case ENIP_RESPONSE_PACKET:
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


   /*
    * We need to track some state for this protocol on a per conversation
    * basis so we can do neat things like request/response tracking
    */
   conversation = find_or_create_conversation(pinfo);

   /*
    * Attach that information to the conversation, and add
    * it to the list of information structures later before dissection.
    */
   memset( &request_key, 0, sizeof(enip_request_key_t) );
   request_key.requesttype = packet_type;
   request_key.type = EPDT_UNKNOWN;
   request_key.session_handle = tvb_get_letohl( tvb, 4 );
   request_key.sender_context = tvb_get_letoh64( tvb, 12 );
   request_key.conversation = conversation->index;

   encap_data_length = tvb_get_letohs( tvb, 2 );
   enip_tree = NULL;
   /* In the interest of speed, if "tree" is NULL, don't do any work not
      necessary to generate protocol tree items. */
   if (tree) {
      /* create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_enip, tvb, 0, -1, ENC_NA );

      enip_tree = proto_item_add_subtree(ti, ett_enip);

      /* Add encapsulation header tree */
      encaph     = proto_tree_add_text( enip_tree, tvb, 0, 24, "Encapsulation Header");
      header_tree = proto_item_add_subtree(encaph, ett_enip);

      /* Add EtherNet/IP encapsulation header */
      proto_tree_add_item( header_tree, hf_enip_command, tvb, 0, 2, ENC_LITTLE_ENDIAN );

      encap_data_length = tvb_get_letohs( tvb, 2 );
      proto_tree_add_item( header_tree, hf_enip_length, tvb, 2, 2, ENC_LITTLE_ENDIAN );
      proto_tree_add_item( header_tree, hf_enip_session, tvb, 4, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item( header_tree, hf_enip_status, tvb, 8, 4, ENC_LITTLE_ENDIAN );
      proto_tree_add_item( header_tree, hf_enip_sendercontex, tvb, 12, 8, ENC_NA );
      proto_tree_add_item( header_tree, hf_enip_options, tvb, 20, 4, ENC_LITTLE_ENDIAN );

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
   } /* end of tree */

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
            dissect_cpf( &request_key, encap_cmd, tvb, pinfo, csftree, 24, 0 );
            break;

         case LIST_IDENTITY:
            dissect_cpf( &request_key, encap_cmd, tvb, pinfo, csftree, 24, 0 );
            break;

         case LIST_INTERFACES:
            dissect_cpf( &request_key, encap_cmd, tvb, pinfo, csftree, 24, 0 );
            break;

         case REGISTER_SESSION:
            proto_tree_add_item( csftree, hf_enip_rs_version, tvb, 24, 2, ENC_LITTLE_ENDIAN );
            proto_tree_add_item( csftree, hf_enip_rs_optionflags, tvb, 26, 2, ENC_LITTLE_ENDIAN );
            break;

         case UNREGISTER_SESSION:
            break;

         case SEND_RR_DATA:
            proto_tree_add_item( csftree, hf_enip_srrd_ifacehnd, tvb, 24, 4, ENC_LITTLE_ENDIAN );
            proto_tree_add_item( csftree, hf_enip_timeout, tvb, 28, 2, ENC_LITTLE_ENDIAN );

            ifacehndl = tvb_get_letohl( tvb, 24 );
            dissect_cpf( &request_key, encap_cmd, tvb, pinfo, csftree, 30, ifacehndl );
            break;

         case SEND_UNIT_DATA:
            proto_tree_add_item(csftree, hf_enip_sud_ifacehnd, tvb, 24, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item( csftree, hf_enip_timeout, tvb, 28, 2, ENC_LITTLE_ENDIAN );

            ifacehndl = tvb_get_letohl( tvb, 24 );
            dissect_cpf( &request_key, encap_cmd, tvb, pinfo, csftree, 30, ifacehndl );
            break;

         case INDICATE_STATUS:
         case CANCEL:
         default:

            /* Can not decode - Just show the data */
            proto_tree_add_item(header_tree, hf_enip_encap_data, tvb, 24, encap_data_length, ENC_NA);
            break;

      } /* end of switch() */

   } /* end of if( encapsulated data ) */
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
      return 0;   /* not a known command */

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
      return 0;   /* not a known command */

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
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENIP");

   /* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
   if (tree)
   {
      /* create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_enip, tvb, 0, -1, ENC_NA );

      enip_tree = proto_item_add_subtree(ti, ett_enip);

      dissect_cpf( NULL, 0xFFFF, tvb, pinfo, enip_tree, 0, 0 );
   }

} /* end of dissect_enipio() */


static gboolean
dissect_dlr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *dlr_tree = NULL;
   guint8      dlr_subtype;
   guint8      dlr_protover;
   guint8      dlr_frametype;

   /* Make entries in Protocol column and Info column on summary display */
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLR");

   col_clear(pinfo->cinfo, COL_INFO);

   if( tree )
   {
      /* Create display subtree for the protocol */
      ti = proto_tree_add_item(tree, proto_dlr, tvb, 0, -1, ENC_NA );
      dlr_tree = proto_item_add_subtree( ti, ett_dlr );
   }

   /* Get values for the Common Frame Header Format */
   dlr_subtype  = tvb_get_guint8(tvb, DLR_CFH_SUB_TYPE);
   dlr_protover = tvb_get_guint8(tvb, DLR_CFH_PROTO_VERSION);

   /* Dissect the Common Frame Header Format */
   proto_tree_add_uint( dlr_tree, hf_dlr_ringsubtype, tvb, DLR_CFH_SUB_TYPE, 1, dlr_subtype );
   proto_tree_add_uint( dlr_tree, hf_dlr_ringprotoversion, tvb, DLR_CFH_PROTO_VERSION, 1, dlr_protover );

   /* Get values for the DLR Message Payload Fields */
   dlr_frametype  = tvb_get_guint8(tvb, DLR_MPF_FRAME_TYPE);

   /* Dissect the DLR Message Payload Fields */
   proto_tree_add_item( dlr_tree, hf_dlr_frametype, tvb, DLR_MPF_FRAME_TYPE, 1, ENC_NA );
   proto_tree_add_item( dlr_tree, hf_dlr_sourceport, tvb, DLR_MPF_SOURCE_PORT, 1, ENC_NA );
   proto_tree_add_item( dlr_tree, hf_dlr_sourceip, tvb, DLR_MPF_SOURCE_IP, 4, ENC_BIG_ENDIAN );
   proto_tree_add_item( dlr_tree, hf_dlr_sequenceid, tvb, DLR_MPF_SEQUENCE_ID, 4, ENC_BIG_ENDIAN );

   /* Add frame type to col info */
   if( check_col(pinfo->cinfo, COL_INFO) )
   {
      col_add_fstr(pinfo->cinfo, COL_INFO,
                "%s", val_to_str(dlr_frametype, dlr_frame_type_vals, "Unknown (0x%04x)") );
   }

   if( dlr_frametype == DLR_FT_BEACON )
   {
      /* Beacon */
      proto_tree_add_item( dlr_tree, hf_dlr_ringstate, tvb, DLR_BE_RING_STATE, 1, ENC_NA );
      proto_tree_add_item( dlr_tree, hf_dlr_supervisorprecedence, tvb, DLR_BE_SUPERVISOR_PRECEDENCE, 1, ENC_NA );
      proto_tree_add_item( dlr_tree, hf_dlr_beaconinterval, tvb, DLR_BE_BEACON_INTERVAL, 4, ENC_BIG_ENDIAN );
      proto_tree_add_item( dlr_tree, hf_dlr_beacontimeout, tvb, DLR_BE_BEACON_TIMEOUT, 4, ENC_BIG_ENDIAN );
      proto_tree_add_item( dlr_tree, hf_dlr_beaconreserved, tvb, DLR_BE_RESERVED, 20, ENC_NA );
   }
   else if( dlr_frametype == DLR_FT_NEIGHBOR_REQ )
   {
      /* Neighbor_Check_Request */
      proto_tree_add_item( dlr_tree, hf_dlr_nreqreserved, tvb, DLR_NREQ_RESERVED, 30, ENC_NA );
   }
   else if( dlr_frametype == DLR_FT_NEIGHBOR_RES )
   {
      /* Neighbor_Check_Response */
      proto_tree_add_item( dlr_tree, hf_dlr_nressourceport, tvb, DLR_NRES_SOURCE_PORT, 1, ENC_NA );
      proto_tree_add_item( dlr_tree, hf_dlr_nresreserved, tvb, DLR_NRES_RESERVED, 29, ENC_NA );
   }
   else if( dlr_frametype == DLR_FT_LINK_STAT )
   {
      /* Link_Status/Neighbor_Status */
      proto_tree_add_item( dlr_tree, hf_dlr_lnknbrstatus, tvb, DLR_LNS_SOURCE_PORT, 1, ENC_NA );
      proto_tree_add_item( dlr_tree, hf_dlr_lnknbrreserved, tvb, DLR_LNS_RESERVED, 29, ENC_NA );
   }
   else if( dlr_frametype == DLR_FT_LOCATE_FLT )
   {
      /* Locate_Fault */
      proto_tree_add_item( dlr_tree, hf_dlr_lfreserved, tvb, DLR_LF_RESERVED, 30, ENC_NA );
   }
   else if( dlr_frametype == DLR_FT_ANNOUNCE )
   {
      /* Announce */
      proto_tree_add_item( dlr_tree, hf_dlr_ringstate, tvb, DLR_AN_RING_STATE, 1, ENC_NA );
      proto_tree_add_item( dlr_tree, hf_dlr_anreserved, tvb, DLR_AN_RESERVED, 29, ENC_NA );
   }
   else if( dlr_frametype == DLR_FT_SIGN_ON )
   {
      guint16  nCnt;
      guint16  nNumNodes;
      guint16  nOffset;


      /* Sign_On */
      nNumNodes = tvb_get_ntohs(tvb, DLR_SO_NUM_NODES);

      proto_tree_add_uint( dlr_tree, hf_dlr_sonumnodes, tvb, DLR_SO_NUM_NODES, 2, nNumNodes );

      /* Add each node in the list */
      for( nCnt = 0, nOffset = DLR_SO_NODE_1_MAC; nCnt < nNumNodes; nCnt++ )
      {
         proto_tree_add_item( dlr_tree, hf_dlr_somac, tvb, nOffset, 6, ENC_BIG_ENDIAN );
         nOffset += 6;
         proto_tree_add_item( dlr_tree, hf_dlr_soip, tvb, nOffset, 4, ENC_BIG_ENDIAN );
         nOffset += 4;
      }

      if( nOffset < 42 )
      {
         proto_tree_add_item( dlr_tree, hf_dlr_soreserved, tvb, nOffset, 42 - nOffset, ENC_NA );
         nOffset += (42 - nOffset);
      }
   }
   else
   {
      /* Unknown Frame type */
   }

   return tvb_length(tvb);

} /* end of dissect_dlr() */


/* Register the protocol with Wireshark */

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
      { &hf_enip_length,
        { "Length", "enip.length",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Encapsulation length", HFILL }
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
          FT_BYTES, BASE_NONE, NULL, 0,
          "Information pertient to the sender", HFILL }
      },
      { &hf_enip_options,
        { "Options", "enip.options",
          FT_UINT32, BASE_HEX, NULL, 0,
          "Options flags", HFILL }
      },
      { &hf_enip_encapver,
        { "Encapsulation Version", "enip.encapver",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      { &hf_enip_sinfamily,
        { "sin_family", "enip.sinfamily",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Socket Address.Sin Family", HFILL }
      },
      { &hf_enip_sinport,
        { "sin_port", "enip.sinport",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Socket Address.Sin Port", HFILL }
      },
      { &hf_enip_sinaddr,
        { "sin_addr", "enip.sinaddr",
          FT_IPv4, BASE_NONE, NULL, 0,
          "Socket Address.Sin Addr", HFILL }
      },
      { &hf_enip_sinzero,
        { "sin_zero", "enip.sinzero",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Socket Address.Sin Zero", HFILL }
      },
      { &hf_enip_timeout,
        { "Timeout", "enip.timeout",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Encapsulation Timeout", HFILL }
      },
      { &hf_enip_encap_data,
        { "Encap Data", "enip.encap_data",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Encapsulation Data", HFILL }
      },
      /* List Services Reply */
      { &hf_enip_lsr_capaflags,
        { "Capability Flags", "enip.lsr.capaflags",
          FT_UINT16, BASE_HEX, NULL, 0,
          "ListServices Reply: Capability Flags", HFILL }
      },
      { &hf_enip_lsr_tcp,
        { "Supports CIP Encapsulation via TCP", "enip.lsr.capaflags.tcp",
          FT_UINT16, BASE_DEC, TFS(&tfs_true_false), 0x0020,
          "ListServices Reply: Supports CIP Encapsulation via TCP", HFILL }
      },
      { &hf_enip_lsr_udp,
        { "Supports CIP Class 0 or 1 via UDP", "enip.lsr.capaflags.udp",
          FT_UINT16, BASE_DEC, TFS(&tfs_true_false), 0x0100,
          "ListServices Reply: Supports CIP Class 0 or 1 via UDP", HFILL }
      },
      { &hf_enip_lsr_servicename,
        { "Name of Service", "enip.lsr.servicename",
          FT_STRING, BASE_NONE, NULL, 0,
          "ListServices Reply: Name of Service", HFILL }
      },
      /* Register Session */
      { &hf_enip_rs_version,
        { "Protocol Version",           "enip.rs.version",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Register Session: Protocol Version", HFILL }
      },
      { &hf_enip_rs_optionflags,
        { "Option Flags",           "enip.rs.flags",
          FT_UINT16, BASE_HEX, NULL, 0,
          "Register Session: Option Flags", HFILL }
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
      { &hf_enip_lir_revision,
        { "Revision", "enip.lir.revision",
          FT_UINT16, BASE_CUSTOM, enip_fmt_lir_revision, 0,
          "ListIdentity Reply: Revision", HFILL }
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
      { &hf_enip_lir_namelen,
        { "Product Name Length", "enip.lir.namelen",
          FT_UINT8, BASE_DEC, NULL, 0,
          "ListIdentity Reply: Product Name Length", HFILL }
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
      { &hf_enip_cpf_itemcount,
        { "Item Count", "enip.cpf.itemcount",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Common Packet Format: Item Count", HFILL }
      },
      { &hf_enip_cpf_typeid,
        { "Type ID",          "enip.cpf.typeid",
          FT_UINT16, BASE_HEX, VALS(cdf_type_vals), 0,
          "Common Packet Format: Type of encapsulated item", HFILL }
      },
      { &hf_enip_cpf_length,
        { "Length", "enip.cpf.length",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Common Packet Format: Length", HFILL }
      },
      /* Connected Data Item */
      { &hf_enip_cpf_cdi_seqcnt,
        { "Connection ID", "enip.cpf.cdi.seqcnt",
          FT_UINT16, BASE_HEX, NULL, 0,
          "Common Packet Format: Connected Data Item, Sequence Count", HFILL }
      },
      /* Connection Address Item */
      { &hf_enip_cpf_cai_connid,
        { "Connection ID", "enip.cpf.cai.connid",
          FT_UINT32, BASE_HEX, NULL, 0,
          "Common Packet Format: Connection Address Item, Connection Identifier", HFILL }
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
      },
      { &hf_enip_cpf_data,
        { "Data", "enip.cpf.data",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Common Packet Format: Unknown Data", HFILL }
      },

      /* Request/Response Matching */
      { &hf_enip_response_in,
        { "Response In", "enip.response_in",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "The response to this ENIP request is in this frame", HFILL }
      },
      { &hf_enip_response_to,
        { "Request In", "enip.response_to",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "This is a response to the ENIP request in this frame", HFILL }
      },
      { &hf_enip_time,
        { "Time", "enip.time",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
          "The time between the Call and the Reply", HFILL }
      },
      { &hf_enip_connection_transport_data,
        { "Data", "enip.connection_transport_data",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          "Connection Transport Data", HFILL }
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

   /* Setup list of header fields for DLR  See Section 1.6.1 for details*/
   static hf_register_info hfdlr[] = {
      /* Ring Sub-type */
      { &hf_dlr_ringsubtype,
        { "Subtype", "enip.dlr.ringsubtype",
          FT_UINT8, BASE_HEX, NULL, 0,
          "Ring Sub-Type", HFILL }
      },
      /* Ring Protocol Version */
      { &hf_dlr_ringprotoversion,
        { "Version", "enip.dlr.protversion",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Ring Protocol Version", HFILL }
      },
      /* Frame Type */
      { &hf_dlr_frametype,
        { "Frametype", "enip.dlr.frametype",
          FT_UINT8, BASE_HEX, VALS(dlr_frame_type_vals), 0,
          "Frame Type", HFILL }
      },
      /* Source Port */
      { &hf_dlr_sourceport,
        { "Sourceport", "enip.dlr.sourceport",
          FT_UINT8, BASE_HEX, VALS(dlr_source_port_vals), 0,
          "Source Port", HFILL }
      },
      /* Source IP Address */
      { &hf_dlr_sourceip,
        { "Source IP", "enip.dlr.sourceip",
          FT_IPv4, BASE_NONE, NULL, 0,
          "Source IP Address", HFILL }
      },
      /* Sequence ID*/
      { &hf_dlr_sequenceid,
        { "Sequence Id", "enip.dlr.seqid",
          FT_UINT32, BASE_HEX, NULL, 0,
          NULL, HFILL }
      },
      /* Ring State */
      { &hf_dlr_ringstate,
        { "Ring State", "enip.dlr.state",
          FT_UINT8, BASE_HEX, VALS(dlr_ring_state_vals), 0,
          NULL, HFILL }
      },
      /* Supervisor Precedence */
      { &hf_dlr_supervisorprecedence,
        { "Supervisor Precedence", "enip.dlr.supervisorprecedence",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      /* Beacon Interval */
      { &hf_dlr_beaconinterval,
        { "Beacon Interval", "enip.dlr.beaconinterval",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      /* Beacon Timeout */
      { &hf_dlr_beacontimeout,
        { "Beacon Timeout", "enip.dlr.beacontimeout",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
      },
      /* Beacon Reserved */
      { &hf_dlr_beaconreserved,
        { "Reserved", "enip.dlr.beaconreserved",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Beacon Reserved", HFILL }
      },
      /* Neighbor_Check_Request Reserved */
      { &hf_dlr_nreqreserved,
        { "Reserved", "enip.dlr.nreqreserved",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Neighbor_Check_Request Reserved", HFILL }
      },
      /* Neighbor_Check_Response Source Port */
      { &hf_dlr_nressourceport,
        { "Sourceport", "enip.dlr.nressourceport",
          FT_UINT8, BASE_HEX, VALS(dlr_source_port_vals), 0,
          "Neighbor_Check_Response Source Port", HFILL }
      },
      /* Neighbor_Check_Response Reserved */
      { &hf_dlr_nresreserved,
        { "Reserved", "enip.dlr.nresreserved",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Neighbor_Check_Response Reserved", HFILL }
      },
      /* Link_Status/Neighbor_Status Status */
      { &hf_dlr_lnknbrstatus,
        { "Status", "enip.dlr.lnknbrstatus",
          FT_UINT8, BASE_HEX, VALS(dlr_lnk_nbr_status_vals), 0,
          "Link_Status/Neighbor_Status Status", HFILL }
      },
      /* Link_Status/Neighbor_Status Reserved */
      { &hf_dlr_lnknbrreserved,
        { "Reserved", "enip.dlr.lnknbrreserved",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Link_Status/Neighbor_Status Reserved", HFILL }
      },
      /* Locate_Fault Reserved */
      { &hf_dlr_lfreserved,
        { "Reserved", "enip.dlr.lfreserved",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Locate_Fault Reserved", HFILL }
      },
      /* Announce Reserved */
      { &hf_dlr_anreserved,
        { "Reserved", "enip.dlr.anreserved",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Announce Reserved", HFILL }
      },
      /* Number of Nodes in List */
      { &hf_dlr_sonumnodes,
        { "Num nodes", "enip.dlr.sonumnodes",
          FT_UINT16, BASE_DEC, NULL, 0,
          "Number of Nodes in List", HFILL }
      },
      /* Sign_On Node # MAC Address */
      { &hf_dlr_somac,
        { "MAC Address", "enip.dlr.somac",
          FT_ETHER, BASE_NONE, NULL, 0,
          "Sign_On Node MAC Address", HFILL }
      },
      /*  Node # IP Address */
      { &hf_dlr_soip,
        { "IP Address", "enip.dlr.soip",
          FT_IPv4, BASE_NONE, NULL, 0,
          "Sign_On Node IP Address", HFILL }
      },
      /* Sign_On Reserved */
      { &hf_dlr_soreserved,
        { "Reserved", "enip.dlr.soreserved",
          FT_BYTES, BASE_NONE, NULL, 0,
          "Sign_On Reserved", HFILL }
      }
   };

   /* Setup protocol subtree array for DLR */
   static gint *ettdlr[] = {
      &ett_dlr
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

   register_init_routine(&enip_init_protocol);

   /* Register the protocol name and description */
   proto_dlr = proto_register_protocol("Device Level Ring", "DLR", "dlr");

   /* Required function calls to register the header fields and subtrees used */
   proto_register_field_array(proto_dlr, hfdlr, array_length(hfdlr));
   proto_register_subtree_array(ettdlr, array_length(ettdlr));

   /* Register a heuristic dissector on the data in the message so encapsulated protocols
    * can dissect the data without modifying this file */
   register_heur_dissector_list("enip.cpf.conndata", &heur_subdissector_conndata_table);

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
   dissector_handle_t dlr_handle;

   /* Register for EtherNet/IP, using TCP */
   enip_tcp_handle = new_create_dissector_handle(dissect_enip_tcp, proto_enip);
   dissector_add_uint("tcp.port", ENIP_ENCAP_PORT, enip_tcp_handle);

   /* Register for EtherNet/IP, using UDP */
   enip_udp_handle = new_create_dissector_handle(dissect_enip_udp, proto_enip);
   dissector_add_uint("udp.port", ENIP_ENCAP_PORT, enip_udp_handle);

   /* Register for EtherNet/IP IO data (UDP) */
   enipio_handle = create_dissector_handle(dissect_enipio, proto_enip);
   dissector_add_uint("udp.port", ENIP_IO_PORT, enipio_handle);

   /* Find dissector for data packet */
   data_handle = find_dissector("data");

   /* Register for EtherNet/IP Device Level Ring protocol */
   dlr_handle = new_create_dissector_handle(dissect_dlr, proto_dlr);
   dissector_add_uint("ethertype", ETHERTYPE_DLR, dlr_handle);

} /* end of proto_reg_handoff_enip() */

/*
* Editor modelines - http://www.wireshark.org/tools/modelines.html
*
* Local variables:
* c-basic-offset: 3
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=3 tabstop=8 expandtab:
* :indentSize=3:tabSize=8:noTabs=true:
*/
