/* packet-giop.c
 * Routines for CORBA GIOP/IIOP packet disassembly
 *
 * Laurent Deniel <deniel@worldnet.fr>
 * Craig Rodrigues <rodrigc@mediaone.net>
 *
 * $Id: packet-giop.c,v 1.34 2001/06/18 02:17:46 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>
#include <glib.h>
#include "packet.h"

static int proto_giop = -1;
static int hf_giop_message_type = -1;
static int hf_giop_message_size = -1;

static gint ett_giop = -1;
static gint ett_giop_reply = -1;
static gint ett_giop_request = -1;
static gint ett_giop_cancel_request = -1;
static gint ett_giop_locate_request = -1;
static gint ett_giop_locate_reply = -1;
static gint ett_giop_fragment = -1;

static const value_string sync_scope[] = {
	{ 0x0, "SYNC_NONE" },
	{ 0x1, "SYNC_WITH_TRANSPORT"},
	{ 0x2, "SYNC_WITH_SERVER"},
	{ 0x3, "SYNC_WITH_TARGET"},
	{ 0, NULL}
};

static const value_string giop_message_types[] = {
	{ 0x0, "Request" },
	{ 0x1, "Reply"},
	{ 0x2, "CancelRequest"},
	{ 0x3, "LocateRequest"},
	{ 0x4, "LocateReply"},
	{ 0x5, "CloseConnection"},
	{ 0x6, "MessageError"},
	{ 0x7, "Fragment"},
	{ 0, NULL}
};

static const value_string giop_locate_status_types[] = {
	{ 0x0, "Unknown Object" },
        { 0x1, "Object Here"},
	{ 0x2, "Object Forward"},
        { 0x3, "Object Forward Perm"},
        { 0x4, "Loc System Exception"},
        { 0x5, "Loc Needs Addressing Mode"},
        { 0, NULL }	
};


/*
 * GIOP / IIOP types definition - OMG CORBA 2.x / GIOP 1.[012]
 * See CORBA 2.4 specification: http://cgi.omg.org/cgi-bin/doc?formal/00-10-1
 *
 * Notes on mapping:
 *
 * <sequence> : unsigned int (# elts) + elements
 * <string>   : unsigned int (string length) + length characters (with '\0')
 * <enum>     : unsigned int (from 0 to n)
 */

#define GIOP_MAGIC 	 "GIOP"
static const guint GIOP_MAJOR =  1;
static const guint GIOP_MINOR =  2;

static const gint GIOP_HEADER_SIZE = 12;

static const int KeyAddr       = 0;
static const int ProfileAddr   = 1;
static const int ReferenceAddr = 2;

typedef struct OctetSequence
{
  guint32 sequence_length;
  guint8 sequence_data[1];	/* of length bytes */
}
OctetSequence;

typedef OctetSequence Principal;
typedef OctetSequence String;

/* 
 * Some structures that contain sequences can not be directly used 
 * (alignment problem on 64 bit architectures)
 */

typedef struct ServiceContext
{
  guint32 context_id;
  OctetSequence context_data;
}
ServiceContext;

typedef struct ServiceContextList
{
  guint32 nr_context;
  ServiceContext service_context[1];	/* nr_context elements */
}
ServiceContextList;

typedef enum MsgType
{
  Request,
  Reply,
  CancelRequest,
  LocateRequest,
  LocateReply,
  CloseConnection,
  MessageError,
  Fragment			/* GIOP 1.1 only */
}
MsgType;

typedef struct Version
{
  guint8 major;
  guint8 minor;
}
Version;

typedef struct MessageHeader
{
  guint8 magic[4];
  Version GIOP_version;
  guint8 flags;			/* byte_order in 1.0 */
  guint8 message_type;
  guint32 message_size;
}
MessageHeader;

typedef struct RequestHeader_1_0
{
  /* ServiceContextList service_context; */
  guint32 request_id;
  guint8 response_expected;
  OctetSequence object_key;
  /* String     operation;              */
  /* Principal  requesting_principal;   */
}
RequestHeader_1_0;

typedef struct RequestHeader_1_1
{
  /* ServiceContextList service_context; */
  guint32 request_id;
  guint8 response_expected;
  guint8 reserved[3];
  OctetSequence object_key;
  /* String     operation;              */
  /* Principal  requesting_principal;   */
}
RequestHeader_1_1;

typedef enum ReplyStatusType
{
  NO_EXCEPTION,
  USER_EXCEPTION,
  SYSTEM_EXCEPTION,
  LOCATION_FORWARD,
  LOCATION_FORWARD_PERM,	/* new for GIOP 1.2 */
  NEEDS_ADDRESSING_MODE		/* new for GIOP 1.2 */
}
ReplyStatusType;

static const value_string reply_status_types[] = { 
   { NO_EXCEPTION, "No Exception" } ,
   { USER_EXCEPTION, "User Exception" } ,
   { SYSTEM_EXCEPTION, "System Exception" } ,
   { LOCATION_FORWARD, "Location Forward" } ,
   { LOCATION_FORWARD_PERM, "Location Forward Perm" } ,
   { NEEDS_ADDRESSING_MODE, "Needs Addressing Mode" } ,
   { 0, NULL }
};

typedef struct ReplyHeader
{
  /* ServiceContext service_context;    */
  guint32 request_id;
  guint32 reply_status;
}
ReplyHeader;

typedef struct SystemExceptionReplyBody
{
  String exception_id;
  u_int minor_code_value;
  u_int completion_status;
}
SystemExceptionReplyBody;

typedef struct CancelRequestHeader
{
  guint32 request_id;
}
CancelRequestHeader;

typedef struct LocateRequestHeader
{
  guint32 request_id;
  OctetSequence object_key;
}
LocateRequestHeader;

typedef enum LocateStatusType
{
  UNKNOWN_OBJECT,
  OBJECT_HERE,
  OBJECT_FORWARD,
  OBJECT_FORWARD_PERM,      /* new value for GIOP 1.2 */
  LOC_SYSTEM_EXCEPTION,     /* new value for GIOP 1.2 */
  LOC_NEEDS_ADDRESSING_MODE /* new value for GIOP 1.2 */
}
LocateStatusType;

typedef struct LocateReplyHeader
{
  guint32 request_id;
  guint32 locate_status;
}
LocateReplyHeader;

/* Take in a string and replace non-printable characters with periods */
static void
printable_string (gchar *in, guint32 len)
{
  guint32 i = 0;

  for(i=0; i < len; i++)
  {
	 if( !isprint( (unsigned char)in[i] ) ) 
		 in[i] = '.';
  }
}

/* Determine the byte order from the GIOP MessageHeader */
static gboolean 
is_big_endian (MessageHeader * header)
{
  gboolean big_endian = FALSE;

  switch (header->GIOP_version.minor)
    {
    case 2:
    case 1:
      if (header->flags & 0x01)
	big_endian = FALSE;
      else
	big_endian = TRUE;
      break;
    case 0:
      if (header->flags)
	big_endian = FALSE;
      else
	big_endian = TRUE;
      break;
    default:
      break;
    }
  return big_endian;
}

/* Copy a 4 octet sequence from the tvbuff 
 * which represents an unsigned long value, and convert
 * it to an unsigned long vaule, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned long values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */
static guint32
get_CDR_ulong(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian)
{
  guint32 val;

  /* unsigned long values must be aligned on a 4 byte boundary */
  while( ( (*offset + GIOP_HEADER_SIZE) % 4) != 0)
	  ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohl (tvb, *offset) :
                                 tvb_get_letohl (tvb, *offset);

  *offset += 4; 
  return val; 
}

/* Copy a 2 octet sequence from the tvbuff 
 * which represents an unsigned short value, and convert
 * it to an unsigned short value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned short values.
 * offset is then incremented by 2, to indicate the 2 octets which
 * have been processed.
 */
static guint16
get_CDR_ushort(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian)
{
  guint16 val;

  /* unsigned short values must be aligned on a 2 byte boundary */
  while( ( (*offset + GIOP_HEADER_SIZE) % 2) != 0)
	  ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohs (tvb, *offset) :
                                 tvb_get_letohs (tvb, *offset);

  *offset += 2; 
  return val; 
}


/* Copy a 2 octet sequence from the tvbuff 
 * which represents a signed short value, and convert
 * it to a signed short value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned short values.
 * offset is then incremented by 2, to indicate the 2 octets which
 * have been processed.
 */

gint16
get_CDR_short(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian)
{
  gint16 val;

  /* short values must be aligned on a 2 byte boundary */
  while( ( (*offset + GIOP_HEADER_SIZE) % 2) != 0)
	  ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohs (tvb, *offset) :
                                 tvb_get_letohs (tvb, *offset);

  *offset += 2; 
  return val; 
}



/* Copy a sequence of octets from the tvbuff.
 * Caller of this function must remember to free the 
 * array pointed to by seq.
 * This function also increments offset by len. 
 */
static void
get_CDR_octet_seq(tvbuff_t *tvb, gchar **seq, int *offset, int len)
{
     *seq = g_new0(gchar, len + 1);
     tvb_memcpy( tvb, *seq, *offset, len);
     *offset += len;
}

/**
 *  Dissects a TargetAddress which is defined in (CORBA 2.4, section 15.4.2)
 *  // GIOP 1.2
 *  typedef short AddressingDisposition;
 *  const short KeyAddr = 0;
 *  const short ProfileAddr = 1;
 *  const short ReferenceAddr = 2;
 *  struct IORAddressingInfo {
 *    unsigned long selected_profile_index;
 *    IOP::IOR ior;
 *  };
 *
 *  union TargetAddress switch (AddressingDisposition) {
 *      case KeyAddr: sequence <octet> object_key;
 *      case ProfileAddr: IOP::TaggedProfile profile;
 *      case ReferenceAddr: IORAddressingInfo ior;
 *  };
 */
static void
dissect_target_address(tvbuff_t * tvb, int *offset, proto_tree * sub_tree, 
		       MessageHeader * header, gboolean stream_is_big_endian)
{
   guint16 discriminant;
   gchar *object_key = NULL;
   guint32 len = 0;

   discriminant = get_CDR_ushort(tvb, offset, stream_is_big_endian);
   if(sub_tree)
   {
     proto_tree_add_text (sub_tree, tvb, *offset -2, 2,
                 "TargetAddress Discriminant: %u", discriminant);
   }
  
   switch (discriminant)
   {
	   case 0:  /* KeyAddr */
		   len = get_CDR_ulong(tvb, offset, stream_is_big_endian);
		   get_CDR_octet_seq(tvb, &object_key, offset, len);
                   printable_string( object_key, len );

		   if(sub_tree)
		   {
                      proto_tree_add_text (sub_tree, tvb, *offset -len -4, 4,
			                   "KeyAddr (object key length): %u", len);
                      proto_tree_add_text (sub_tree, tvb, *offset -len, len,
			                   "KeyAddr (object key): %s", object_key);
		   }
		   break;
	   case 1:
		   if(sub_tree)
		   {
                      proto_tree_add_text (sub_tree, tvb, *offset, tvb_length(tvb) - *offset,
			                   "ProfileAddr (not implemented) %s", object_key);
		   }
		   break;
           case 2:
		   if(sub_tree)
		   {
                      proto_tree_add_text (sub_tree, tvb, *offset, tvb_length(tvb) - *offset,
			                   "ReferenceAddr (not implemented) %s", object_key);
		   }
		   break;
	   default:
		   break;
   }
   g_free( object_key );
}

static void
dissect_reply_body (tvbuff_t *tvb, u_int offset, packet_info *pinfo,
		    proto_tree *tree, gboolean stream_is_big_endian,
		    guint32 reply_status)
{
  u_int sequence_length;
  u_int minor_code_value;
  u_int completion_status;

  switch (reply_status)
    {
    case SYSTEM_EXCEPTION:
      if (tree)
	{
	  sequence_length = get_CDR_ulong(tvb, &offset, stream_is_big_endian);

	  proto_tree_add_text(tree, tvb, offset-4, 4,
			   "Exception length: %u", sequence_length);

	  if (sequence_length != 0)
	    {
	      proto_tree_add_text(tree, tvb, offset, sequence_length,
			   "Exception id: %s",
			   tvb_format_text(tvb, offset, sequence_length - 1));
	      offset += sequence_length;
	    }

	  minor_code_value = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
	  completion_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
	
	  proto_tree_add_text(tree, tvb, offset-8, 4,
			   "Minor code value: %u", minor_code_value);
	  proto_tree_add_text(tree, tvb, offset-4, 4,
			   "Completion Status: %u", completion_status);
        }
      break;

    case USER_EXCEPTION:
      if (tree)
        {
	  sequence_length = get_CDR_ulong(tvb, &offset, stream_is_big_endian);

	  proto_tree_add_text(tree, tvb, offset-4, 4,
			   "Exception length: %u", sequence_length);

	  if (sequence_length != 0)
	    {
	      proto_tree_add_text(tree, tvb, offset, sequence_length,
			   "Exception id: %s",
			   tvb_format_text(tvb, offset, sequence_length));

	      offset += sequence_length;
	    }

	  sequence_length = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
	  proto_tree_add_text(tree, tvb, offset-4, 4,
			   "Exception member length: %u", sequence_length);

	  if (sequence_length != 0)
	    {
	      proto_tree_add_text(tree, tvb, offset, sequence_length,
			   "Exception member: %s",
			   tvb_format_text(tvb, offset, sequence_length - 1));
	    }

	}
      break;

    default:
	if (tree)
	  {
	    proto_tree_add_text(tree, tvb, offset,
			   tvb_length_remaining(tvb, offset),
			   "Reply body: <not shown>");
	  }
    }
}

/* The format of the Reply Header for GIOP 1.0 and 1.1
 * is documented in Section 15.4.3.1 * of the CORBA 2.4 standard.

    struct ReplyHeader_1_0 {
          IOP::ServiceContextList service_context;
          unsigned long request_id;
          ReplyStatusType_1_0 reply_status;
    };
 */
static void
dissect_giop_reply (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
		    proto_tree * clnp_tree, MessageHeader * header,
		    gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 nr_seq = 0;
  guint32 context_id;
  guint32 sequence_length;
  guint32 request_id;
  guint32 reply_status;
  gboolean big_endian;
  proto_tree *reply_tree = NULL;
  proto_item *tf;

  guint32 i;

  big_endian = is_big_endian (header);

  /* From Section 15.3.2.5 of the CORBA 2.4 standard, a sequence
   * is an unsigned long value (4 octets) indicating the number of 
   * items in the sequence, followed by the items in the sequence 
   */

  /* The format of the IOP::ServiceContextList struct is defined in
   * section 13.7 of the CORBA 2.4 standard  as:
   module IOP { // IDL
   typedef unsigned long ServiceId;

   struct ServiceContext {
   ServiceId context_id;
   sequence <octet> context_data;
   };
   typedef sequence <ServiceContext>ServiceContextList;
   };
   */
  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset,
				tvb_length (tvb),
				"General Inter-ORB Protocol Reply");
      if (reply_tree == NULL)
	{
	  reply_tree = proto_item_add_subtree (tf, ett_giop_reply);

	}
    }

  nr_seq = get_CDR_ulong(tvb, &offset, stream_is_big_endian);

  for (i = 1; i <= nr_seq; i++)
    {

      if (big_endian)
	{
	  context_id = tvb_get_ntohl (tvb, offset);
	  sequence_length = tvb_get_ntohl (tvb, offset + 4);
	}
      else
	{
	  context_id = tvb_get_letohl (tvb, offset);
	  sequence_length = tvb_get_letohl (tvb, offset + 4);
	}

      context_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);

      if (tree)
	{
	  proto_tree_add_text (reply_tree, tvb, offset -4, 4,
			       "Context id: %u", context_id);
	}

      sequence_length = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
      if(tree)
      {	     
	  proto_tree_add_text (reply_tree, tvb, offset -4,
			       4, "Sequence length: %u", sequence_length);
      }

      if(tree)
      {
	  if (sequence_length > 0)
	    {
	      proto_tree_add_text (reply_tree, tvb, offset,
				   sequence_length,
				   "Sequence data: <not shown>");
	    }
	}

      offset += sequence_length;	

    }				/* for */

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " %u", request_id);
    }
  if (tree)
    {
      proto_tree_add_text (reply_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

  reply_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, ": %s",
	val_to_str(reply_status, reply_status_types, "Unknown (%u)"));
    }
  if (tree)
    {
      proto_tree_add_text (reply_tree, tvb, offset-4, 4,
	"Reply status: %s",
	val_to_str(reply_status, reply_status_types, "Unknown (%u)"));

    }

  dissect_reply_body(tvb, offset, pinfo, reply_tree, stream_is_big_endian,
    reply_status);
}

/** The format of the GIOP 1.2 Reply header is very similar to the 1.0
 *  and 1.1 header, only the fields have been rearranged.  From Section
 *  15.4.3.1 of the CORBA 2.4 specification:
 *
 *   struct ReplyHeader_1_2 {
          unsigned long request_id;
          ReplyStatusType_1_2 reply_status;
          IOP:ServiceContextList service_context; // 1.2 change
     };
 */
static void
dissect_giop_reply_1_2 (tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree, proto_tree * clnp_tree,
			MessageHeader * header,
			gboolean stream_is_big_endian)
{
  u_int offset = 0;
  guint32 nr_seq = 0;
  guint32 context_id;
  guint32 sequence_length;
  guint32 request_id;
  guint32 reply_status;
  proto_tree *reply_tree = NULL;
  proto_item *tf;
  guint32 i;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset,
				tvb_length (tvb),
				"General Inter-ORB Protocol Reply");
      if (reply_tree == NULL)
	{
	  reply_tree = proto_item_add_subtree (tf, ett_giop_reply);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " %u", request_id);
    }
  if (tree)
    {
      proto_tree_add_text (reply_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

  reply_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, ": %s",
	val_to_str(reply_status, reply_status_types, "Unknown (%u)"));
    }
  if (tree)
    {
      proto_tree_add_text (reply_tree, tvb, offset-4, 4,
	"Reply status: %s",
	val_to_str(reply_status, reply_status_types, "Unknown (%u)"));

    }

  nr_seq = get_CDR_ulong(tvb, &offset, stream_is_big_endian);

  for (i = 1; i <= nr_seq; i++)
    {

      context_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
      if (tree)
	{
	  proto_tree_add_text (reply_tree, tvb, offset -4, 4,
			       "Context id: %u", context_id);
	}

      sequence_length = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
      if (tree)
      {
	  proto_tree_add_text (reply_tree, tvb, offset- 4,
			       4, "Sequence length: %u", sequence_length);
      }

      offset += sequence_length;
      if (tree)
      {
	  if (sequence_length > 0)
	    {
	      proto_tree_add_text (reply_tree, tvb, offset - sequence_length,
				   sequence_length,
				   "Sequence data: <not shown>");
	    }
      }

    }				/* for */

  dissect_reply_body(tvb, offset, pinfo, reply_tree, stream_is_big_endian,
    reply_status);
}

static void
dissect_giop_cancel_request (tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree, proto_tree * clnp_tree,
			MessageHeader * header, gboolean stream_is_big_endian)
{
  u_int offset = 0;
  guint32 request_id;
  proto_tree *cancel_request_tree = NULL;
  proto_item *tf;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset,
				tvb_length (tvb),
				"General Inter-ORB Protocol CancelRequest");
      if (cancel_request_tree == NULL)
	{
	  cancel_request_tree = proto_item_add_subtree (tf, ett_giop_cancel_request);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " %u", request_id);
    }
  if (tree)
    {
      proto_tree_add_text (cancel_request_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }


}

/**  The formats for GIOP 1.0 and 1.1 Request messages are defined
 *   in section 15.4.2.1 of the CORBA 2.4 specification.
 *
 *   struct RequestHeader{
 *          IOP::ServiceContextList   service_context;
 *          unsigned long             request_id;
 *          boolean                   response_expected;
 *          octet                     reserved[3];  // Only in GIOP 1.1
 *          sequence<octet>           object_key;
 *          string                    operation;
 *          CORBA::OctetSeq           requesting_principal;
 *   }
 */
static void
dissect_giop_request_1_1 (tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree, proto_tree * clnp_tree,
			MessageHeader * header, gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 nr_seq = 0;
  guint32 context_id;
  guint32 sequence_length;
  guint32 request_id;
  guint32 len = 0;
  gchar *object_key = NULL;
  gchar *operation = NULL;
  gchar *requesting_principal = NULL;
  guint8 response_expected;
  gchar *reserved = NULL;
  proto_tree *request_tree = NULL;
  proto_item *tf;
  guint32 i;


  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset,
				tvb_length (tvb),
				"General Inter-ORB Protocol Request");
      if (request_tree == NULL)
	{
	  request_tree = proto_item_add_subtree (tf, ett_giop_request);

	}
    }

  nr_seq = get_CDR_ulong(tvb, &offset, stream_is_big_endian);

  for (i = 1; i <= nr_seq; i++)
    {

      context_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
      if (tree)
	{
	  proto_tree_add_text (request_tree, tvb, offset-4, 4,
			       "Context id: %u", context_id);
	}

       sequence_length = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
       if(tree)
	{
	   proto_tree_add_text (request_tree, tvb, offset-4, 4, 
			        "Sequence length: %u", sequence_length);
	}

        offset +=  sequence_length;
        if (sequence_length > 0)
        {
	      proto_tree_add_text (request_tree, tvb, offset - sequence_length,
				   sequence_length,
				   "Sequence data: <not shown>");
        }
	

    } /* for */

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " %u", request_id);
    }
  if (tree)
    {
      proto_tree_add_text (request_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

  response_expected = tvb_get_guint8( tvb, offset );
  offset += 1;
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " (%s)",
		response_expected ? "two-way" : "one-way");
    }
  if (tree)
    {
      proto_tree_add_text (request_tree, tvb, offset-1, 1,
			   "Response expected: %u", response_expected);
    }

  if( header->GIOP_version.minor > 0)
  {
     get_CDR_octet_seq( tvb, &reserved, &offset, 3);
     if (tree)
       {
         proto_tree_add_text (request_tree, tvb, offset-3, 3,
	   		   "Reserved: %x %x %x", reserved[0], reserved[1], reserved[2]);
       }
  }

  /* Length of object_key sequence */
  len = get_CDR_ulong(tvb, &offset, stream_is_big_endian);

  if(tree)
  {
         proto_tree_add_text (request_tree, tvb, offset-4, 4,
         /**/                 "Object Key length: %u", len);
  } 

  if( len > 0)
  {
       get_CDR_octet_seq(tvb, &object_key, &offset, len);
       printable_string( object_key, len );

       if(tree)
       {
         proto_tree_add_text (request_tree, tvb, offset - len, len,
         /**/                 "Object Key: %s", object_key);

       }
  } 

  /* length of operation string */ 
  len = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if(tree)
  {
         proto_tree_add_text (request_tree, tvb, offset -4, 4,
         /**/                 "Operation length: %u", len);
  } 

  if( len > 0)
  {
       get_CDR_octet_seq(tvb, &operation, &offset, len);
       if (check_col(pinfo->fd, COL_INFO))
       {
         col_append_fstr(pinfo->fd, COL_INFO, ": %s", operation);
       }
       if(tree)
       {
         proto_tree_add_text (request_tree, tvb, offset - len, len,
         /**/                 "Operation: %s", operation);

       }
  }

  /* length of requesting_principal string */ 
  len = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if(tree)
  {
         proto_tree_add_text (request_tree, tvb, offset-4, 4,
         /**/                 "Requesting Principal Length: %u", len);
  } 

  if( len > 0)
  {
       get_CDR_octet_seq(tvb, &requesting_principal, &offset, len);
       if(tree)
       {
         proto_tree_add_text (request_tree, tvb, offset - len, len, 
         /**/                 "Requesting Principal: %s", requesting_principal);

       }
  }

  g_free( object_key );
  g_free( operation );
  g_free( requesting_principal );
}

/**  The format of a GIOP 1.2 RequestHeader message is 
 *   (CORBA 2.4, sec. 15.4.2):
 *
 *   struct RequestHeader_1_2 {
 *       unsigned long request_id;
 *       octet response_flags;
 *       octet reserved[3];
 *       TargetAddress target;
 *       string operation;
 *       IOP::ServiceContextList service_context;
 *       // requesting_principal not in GIOP 1.2
 *   };
 */
static void
dissect_giop_request_1_2 (tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree, proto_tree * clnp_tree,
			MessageHeader * header, gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  guint32 len = 0;
  guint8 response_flags;
  gchar *reserved = NULL;
  gchar *operation = NULL;
  proto_tree *request_tree = NULL;
  proto_item *tf;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset,
				tvb_length (tvb),
				"General Inter-ORB Protocol Request");
      if (request_tree == NULL)
	{
	  request_tree = proto_item_add_subtree (tf, ett_giop_reply);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " %u", request_id);
    }
  if (request_tree)
    {
      proto_tree_add_text (request_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

  response_flags = tvb_get_guint8( tvb, offset );
  offset += 1;
  if (request_tree)
    {
      proto_tree_add_text (request_tree, tvb, offset-1, 1,
			   "Response flags: %s (%u)",
			        match_strval(response_flags, sync_scope),  
			        response_flags);
    }

  get_CDR_octet_seq( tvb, &reserved, &offset, 3);
  if (request_tree)
   {
     proto_tree_add_text (request_tree, tvb, offset-3, 3,
 	   "Reserved: %x %x %x", reserved[0], reserved[1], reserved[2]);
   }

  dissect_target_address(tvb, &offset, request_tree, header, stream_is_big_endian);

  /* length of operation string */ 
  len = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if(tree)
  {
         proto_tree_add_text (request_tree, tvb, offset -4, 4,
         /**/                 "Operation length: %u", len);
  } 

  if( len > 0)
  {
       get_CDR_octet_seq(tvb, &operation, &offset, len);
       if (check_col(pinfo->fd, COL_INFO))
       {
         col_append_fstr(pinfo->fd, COL_INFO, ": %s", operation);
       }
       if(request_tree)
       {
         proto_tree_add_text (request_tree, tvb, offset - len, len,
         /**/                 "Operation: %s", operation);

       }

  }
  g_free(reserved);
}

static void
dissect_giop_locate_request( tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree, MessageHeader * header,
			gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  guint32 len = 0;
  gchar *object_key = NULL;
  proto_tree *locate_request_tree = NULL;
  proto_item *tf;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset,
				tvb_length (tvb),
				"General Inter-ORB Locate Request");
      if (locate_request_tree == NULL)
	{
	  locate_request_tree = proto_item_add_subtree (tf, ett_giop_locate_request);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " %u", request_id);
    }
  if (locate_request_tree)
    {
      proto_tree_add_text (locate_request_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

  if(header->GIOP_version.minor < 2)
  {
        len = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
        get_CDR_octet_seq(tvb, &object_key, &offset, len);

	if(locate_request_tree)
	{

           proto_tree_add_text (locate_request_tree, tvb, offset-len, len,
			   "Object Key: %s", object_key);


	}

  }
  else     /* GIOP 1.2 and higher */
  {
      dissect_target_address(tvb, &offset, locate_request_tree, header,
			     stream_is_big_endian);

  }
  g_free( object_key );  
}

static void
dissect_giop_locate_reply( tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree, MessageHeader * header,
			gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  guint32 locate_status;
  proto_tree *locate_reply_tree = NULL;
  proto_item *tf;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset,
				tvb_length (tvb),
				"General Inter-ORB Locate Reply");
      if (locate_reply_tree == NULL)
	{
	  locate_reply_tree = proto_item_add_subtree (tf, ett_giop_locate_reply);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " %u", request_id);
    }
  if (locate_reply_tree)
    {
      proto_tree_add_text (locate_reply_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

  locate_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (locate_reply_tree)
    {
      proto_tree_add_text (locate_reply_tree, tvb, offset-4, 4,
			   "Locate status: %s", 
			   match_strval(locate_status, giop_locate_status_types)
			   );
				   
    }

}

static void
dissect_giop_fragment( tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
			MessageHeader * header, gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  proto_tree *fragment_tree = NULL;
  proto_item *tf;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset,
				tvb_length (tvb),
				"General Inter-ORB Fragment");
      if (fragment_tree == NULL)
	{
	  fragment_tree = proto_item_add_subtree (tf, ett_giop_fragment);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian);
  if (check_col(pinfo->fd, COL_INFO))
    {
      col_append_fstr(pinfo->fd, COL_INFO, " %u", request_id);
    }
  if (fragment_tree )
    {
      proto_tree_add_text (fragment_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

				   
}


/* main entry point */
static gboolean
dissect_giop (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  u_int offset = 0;
  MessageHeader header;
  tvbuff_t *giop_header_tvb;
  tvbuff_t *payload_tvb;

  proto_tree *clnp_tree = NULL;
  proto_item *ti;
  u_int message_size;
  u_int minor_version;
  gboolean stream_is_big_endian;

  /* check magic number and version */


  /*define END_OF_GIOP_MESSAGE (offset - first_offset - GIOP_HEADER_SIZE) */

  if (tvb_length_remaining(tvb, 0) < GIOP_HEADER_SIZE)
    {
      /* Not enough data captured to hold the GIOP header; don't try
         to interpret it as GIOP. */
      return FALSE;
    }

  giop_header_tvb = tvb_new_subset (tvb, 0, GIOP_HEADER_SIZE, -1);
  payload_tvb = tvb_new_subset (tvb, GIOP_HEADER_SIZE, -1, -1);

  /*  memcpy(&header, &pd[offset], sizeof(header)); */
  tvb_memcpy (giop_header_tvb, (guint8 *)&header, 0, sizeof (header));

  if (memcmp (header.magic, GIOP_MAGIC, sizeof (header.magic)) != 0)
    {
      /* Not a GIOP message. */
      return FALSE;
    }

  if (check_col (pinfo->fd, COL_PROTOCOL))
    {
      col_set_str (pinfo->fd, COL_PROTOCOL, "GIOP");
    }

  if (header.GIOP_version.major != GIOP_MAJOR ||
      ((minor_version = header.GIOP_version.minor) > GIOP_MINOR))
    {
      /* Bad version number; should we note that and dissect the rest
         as data, or should we return FALSE on the theory that it
         might have been some other packet that happened to begin with
         "GIOP"?  We shouldn't do *both*, so we return TRUE, for now.
	 If we should return FALSE, we should do so *without* setting
	 the "Info" column, *without* setting the "Protocol" column,
	 and *without* adding anything to the protocol tree. */
      if (check_col (pinfo->fd, COL_INFO))
	{
	  col_add_fstr (pinfo->fd, COL_INFO, "Version %u.%u",
			header.GIOP_version.major, header.GIOP_version.minor);
	}
      if (tree)
	{
	  ti = proto_tree_add_item (tree, proto_giop, tvb, 0,
				    tvb_length (tvb), FALSE);
	  clnp_tree = proto_item_add_subtree (ti, ett_giop);
	  proto_tree_add_text (clnp_tree, giop_header_tvb, 0,
			       tvb_length (giop_header_tvb),
			       "Version %u.%u not supported",
			       header.GIOP_version.major,
			       header.GIOP_version.minor);
	}
      dissect_data (payload_tvb, 0, pinfo, tree);
      return TRUE;
    }

  if (check_col (pinfo->fd, COL_INFO)) 
  { 
      col_add_fstr (pinfo->fd, COL_INFO, "GIOP %u.%u %s",
                    header.GIOP_version.major, header.GIOP_version.minor,
                    val_to_str(header.message_type, giop_message_types,
                    	       "Unknown message type (0x%02x)"));
  }

  stream_is_big_endian = is_big_endian (&header);

  if (stream_is_big_endian)
    message_size = pntohl (&header.message_size);
  else
    message_size = pletohl (&header.message_size);

  if (tree)
    {
      ti = proto_tree_add_item (tree, proto_giop, tvb, 0, 12, FALSE);
      clnp_tree = proto_item_add_subtree (ti, ett_giop);
      proto_tree_add_text (clnp_tree, giop_header_tvb, offset, 4,
			   "Magic number: %s", GIOP_MAGIC);
      proto_tree_add_text (clnp_tree, giop_header_tvb, 4, 2,
			   "Version: %u.%u",
			   header.GIOP_version.major,
			   header.GIOP_version.minor);
      switch (minor_version)
	{
	case 2:
	case 1:
	  proto_tree_add_text (clnp_tree, giop_header_tvb, 6, 1,
			       "Flags: 0x%02x (%s %s)",
			       header.flags,
			       (stream_is_big_endian) ? "big-endian" : "little-endian",
			       (header.flags & 0x02) ? " fragment" : "");
	  break;
	case 0:
	  proto_tree_add_text (clnp_tree, giop_header_tvb, 6, 1,
			       "Byte ordering: %s-endian",
			       (stream_is_big_endian) ? "big" : "little");
	  break;
	default:
	  break;
	}			/* minor_version */

      proto_tree_add_uint_format (clnp_tree,
				  hf_giop_message_type,
				  giop_header_tvb, 7, 1,
				  header.message_type,
				  "Message type: %s", match_strval(header.message_type, giop_message_types));

      proto_tree_add_uint (clnp_tree,
			   hf_giop_message_size,
			   giop_header_tvb, 8, 4, message_size);

    }				/* tree */

  switch (header.message_type)
    {

    case Request:
      if(header.GIOP_version.minor < 2)
      {
	   dissect_giop_request_1_1 (payload_tvb, pinfo, tree, clnp_tree,
				     &header, stream_is_big_endian);
      }
      else
      {    
           dissect_giop_request_1_2 (payload_tvb, pinfo, tree, clnp_tree,
				     &header, stream_is_big_endian);
      }
      
      break;


    case Reply:
      if(header.GIOP_version.minor < 2)
	{
           dissect_giop_reply (payload_tvb, pinfo, tree, clnp_tree, &header,
			       stream_is_big_endian);
	}
      else
        {
	   dissect_giop_reply_1_2 (payload_tvb, pinfo, tree, clnp_tree,
				   &header, stream_is_big_endian);
	}
      break;
    case CancelRequest:
        dissect_giop_cancel_request(payload_tvb, pinfo, tree, clnp_tree,
				    &header, stream_is_big_endian);
	break;
    case LocateRequest:
	dissect_giop_locate_request(payload_tvb, pinfo, tree, &header,
				    stream_is_big_endian);
	break;
    case LocateReply:
	dissect_giop_locate_reply(payload_tvb, pinfo, tree, &header,
				  stream_is_big_endian);
	break;
    case Fragment:
        dissect_giop_fragment(payload_tvb, pinfo, tree, &header,
			      stream_is_big_endian);
        break;	
    default:
      break;

    }				/* switch message_type */
    return TRUE;
}

void
proto_register_giop (void)
{
  static hf_register_info hf[] = {
    {
     &hf_giop_message_type,
     {
      "Message type", "giop.type",
      FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
     }
    ,
    {
     &hf_giop_message_size,
     {
      "Message size", "giop.len",
      FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
     }
    ,
  };
  static gint *ett[] = {
    &ett_giop,
    &ett_giop_reply,
    &ett_giop_request,
    &ett_giop_cancel_request,
    &ett_giop_locate_request,
    &ett_giop_locate_reply,
    &ett_giop_fragment
  };
  proto_giop = proto_register_protocol("General Inter-ORB Protocol", "GIOP",
				       "giop");
  proto_register_field_array (proto_giop, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_giop (void)
{
  heur_dissector_add ("tcp", dissect_giop, proto_giop);
}
