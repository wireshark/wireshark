/* packet-giop.c
 * Routines for CORBA GIOP/IIOP packet disassembly
 *
 * Laurent Deniel <deniel@worldnet.fr>
 *
 * $Id: packet-giop.c,v 1.13 2000/05/11 08:15:09 gram Exp $
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

/*
 * GIOP / IIOP types definition - OMG CORBA 2.x / GIOP 1.[01]
 * See OMG WEB site <http://www.omg.org> - CORBA+IIOP 2.2 (98-02-01.ps)
 *
 * Notes on mapping:
 *
 * <sequence> : unsigned int (# elts) + elements
 * <string>   : unsigned int (string length) + length characters (with '\0')
 * <enum>     : unsigned int (from 0 to n)
 */

#define GIOP_MAGIC 	 "GIOP"
#define GIOP_MAJOR 	 1
#define GIOP_MINOR 	 1

#define GIOP_HEADER_SIZE 12

typedef struct OctetSequence{
  u_int 	sequence_length;
  u_char  	sequence_data[1];	       	/* of length bytes */
} OctetSequence;

typedef OctetSequence Principal;
typedef OctetSequence String;

/* 
 * Some structures that contain sequences can not be directly used 
 * (alignment problem on 64 bit architectures)
 */

typedef struct ServiceContext {
  u_int		context_id;
  OctetSequence context_data;
} ServiceContext;

typedef struct ServiceContextList{
  u_int 	  nr_context;
  ServiceContext  service_context[1]; 		/* nr_context elements */
} ServiceContextList;

typedef enum MsgType {
  Request,
  Reply,
  CancelRequest, 
  LocateRequest,
  LocateReply, 
  CloseConnection,
  MessageError,
  Fragment					/* GIOP 1.1 only */
} MsgType;

typedef struct Version {
  u_char 	major;
  u_char 	minor;
} Version;

typedef struct MessageHeader {
  char 		magic[4];
  Version 	GIOP_version;
  u_char 	flags;				/* byte_order in 1.0 */
  u_char 	message_type;
  u_int 	message_size;
} MessageHeader;

typedef struct RequestHeader_1_0 {
  /* ServiceContextList service_context;*/
  u_int 	request_id;
  u_char 	response_expected;
  OctetSequence object_key;
  /* String     operation; 	     	*/
  /* Principal  requesting_principal; 	*/
} RequestHeader_1_0;

typedef struct RequestHeader_1_1 {
  /* ServiceContextList service_context;*/
  u_int 	request_id;
  u_char 	response_expected;
  u_char 	reserved[3];
  OctetSequence object_key;
  /* String 	operation; 	     	*/
  /* Principal  requesting_principal;	*/
} RequestHeader_1_1;

typedef enum ReplyStatusType {
  NO_EXCEPTION, 
  USER_EXCEPTION, 
  SYSTEM_EXCEPTION, 
  LOCATION_FORWARD
} ReplyStatusType;

typedef struct ReplyHeader {
  /* ServiceContext service_context; 	*/
  u_int 	request_id;
  u_int 	reply_status;
} ReplyHeader;

typedef struct SystemExceptionReplyBody {
  String 	exception_id; 
  u_int		minor_code_value;
  u_int		completion_status;
} SystemExceptionReplyBody;

typedef struct CancelRequestHeader {
  u_int		request_id;
} CancelRequestHeader;

typedef struct LocateRequestHeader {
  u_int 	request_id;
  OctetSequence object_key;
} LocateRequestHeader;

typedef enum LocateStatusType {
  UNKNOWN_OBJECT, 
  OBJECT_HERE, 
  OBJECT_FORWARD
} LocateStatusType;

typedef struct LocateReplyHeader {
  u_int 	request_id;
  u_int 	locate_status;
} LocateReplyHeader;


static u_char *print_object_key(int length, u_char *from) 
{
#define MAX_OBJECT_KEY_LENGTH 64
  static u_char buffer[MAX_OBJECT_KEY_LENGTH];
  u_char *to = buffer;
  int i = 0;
  length = MIN(MAX_OBJECT_KEY_LENGTH - 3, length);
  *to++ = '"';
  while(i++ < length) {
    *to = (isprint(*from)) ? *from : '.'; 
    to++;
    from++;
  }  
  *to++ = '"';
  *to = '\0';
  return buffer;
}

/* main entry point */

static gboolean
dissect_giop(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{

  MessageHeader header;
  proto_tree *clnp_tree = NULL;
  proto_item *ti;
  u_char response_expected = 0;
  u_int first_offset = offset;
  u_int big_endian = FALSE;
  u_int request_id = 0;
  u_int message_size;
  u_int minor_version;
  u_int context_id;
  u_int reply_status;
  u_int locate_status;
  u_int sequence_length;
  u_int nr_seq;
  RequestHeader_1_1 request_1_1;
  RequestHeader_1_0 request_1_0;
  ReplyHeader reply;
  LocateReplyHeader locate_rep;
  LocateRequestHeader locate_req;
  int i;

#define END_OF_GIOP_MESSAGE (offset - first_offset - GIOP_HEADER_SIZE)

  if (!BYTES_ARE_IN_FRAME(offset, GIOP_HEADER_SIZE)) {
    /* Not enough data, or not enough captured data; perhaps it was
       a GIOP message, but we can't tell. */
    return FALSE;
  }

  /* avoid alignment problem */

  memcpy(&header, &pd[offset], sizeof(header));

  /* check magic number and version */

  if (memcmp(header.magic, GIOP_MAGIC, sizeof(header.magic)) != 0) {
    /* Not a GIOP message. */
    return FALSE;
  }

  if (header.GIOP_version.major != GIOP_MAJOR ||
      ((minor_version = header.GIOP_version.minor) >  GIOP_MINOR)) {
    /* Bad version number; should we note that and dissect the rest
       as data, or should we return FALSE on the theory that it
       might have been some other packet that happened to begin with
       "GIOP"? */
    dissect_data(pd, offset, fd, tree);
    return TRUE;
  }

  switch(minor_version) {
    case 1  :
      if (header.flags & 0x01)
	big_endian = FALSE;
      else
	big_endian = TRUE;
      break;
    case 0  :
      if (header.flags)
	big_endian = FALSE;
      else
	big_endian = TRUE;
      break;
    default :
      break;
  }
  
  if (big_endian)
    message_size = pntohl(&header.message_size);
  else
    message_size = pletohl(&header.message_size);

  if (check_col(fd, COL_PROTOCOL)) {
    col_add_str(fd, COL_PROTOCOL, "GIOP");
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_giop, NullTVB, offset, 
			  GIOP_HEADER_SIZE + message_size, NULL);
    clnp_tree = proto_item_add_subtree(ti, ett_giop);
    proto_tree_add_text(clnp_tree, NullTVB, offset,      4,
		     "Magic number: %s", GIOP_MAGIC);
    proto_tree_add_text(clnp_tree, NullTVB, offset +  4, 2, 
		     "Version: %d.%d", 
		     header.GIOP_version.major,
		     header.GIOP_version.minor);
    switch(minor_version) {
      case 1  :
	proto_tree_add_text(clnp_tree, NullTVB, offset +  6, 1, 
			 "Flags: 0x%02x (%s%s)", 
			 header.flags,
			 (big_endian) ? "little" : "big",
			 (header.flags & 0x02) ? " fragment" : "");
	break;
      case 0  :
	proto_tree_add_text(clnp_tree, NullTVB, offset +  6, 1, 
			 "Byte ordering: %s endian",
			 (big_endian) ? "little" : "big");
	break;
      default :
	break;
    } /* minor_version */

    proto_tree_add_uint_format(clnp_tree, 
			       hf_giop_message_type,
			       NullTVB, offset +  7, 1, 
			       header.message_type,
			       "Message type: %s",
			       (header.message_type == Request) ? "Request" :
			       (header.message_type == Reply) ? "Reply" :
			       (header.message_type == CancelRequest) ? "CancelRequest" :
			       (header.message_type == LocateRequest) ? "LocateRequest" :
			       (header.message_type == LocateReply) ? "LocateReply" :
			       (header.message_type == CloseConnection) ? "CloseConnection" :
			       (header.message_type == MessageError) ? "MessageError" :
			       (header.message_type == Fragment) ? "Fragment" : "?");

    proto_tree_add_item(clnp_tree, 
			hf_giop_message_size,
			NullTVB, offset +  8, 4, 
			message_size);

  } /* tree */

  offset += GIOP_HEADER_SIZE;

  if (!BYTES_ARE_IN_FRAME(offset, message_size)) {
    dissect_data(pd, offset, fd, tree);
    return TRUE;
  }

  /* skip service_context in Request/Reply messages */

  switch(header.message_type) {

    case Request:
    case Reply :

      nr_seq = (big_endian) ? pntohl(&pd[offset]) : pletohl(&pd[offset]);

      offset += sizeof(nr_seq);

      for (i = 0 ; i < nr_seq ; i++) {

	if (big_endian) {	
	  context_id = pntohl(&pd[offset]);
	  sequence_length = pntohl(&pd[offset + sizeof(context_id)]);
	}
	else {
	  context_id = pletohl(&pd[offset]);
	  sequence_length = pletohl(&pd[offset + sizeof(context_id)]);
	}

	if (tree) {
	  proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(context_id),
			   "Context id: %d", context_id);
	  proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(context_id),
			   sizeof(sequence_length),
			   "Sequence length: %d", sequence_length);
	  proto_tree_add_text(clnp_tree, NullTVB,
			   offset + 
			   sizeof(context_id) + sizeof(sequence_length),
			   sequence_length,
			   "Sequence data: <not shown>");
	}

	offset += sizeof(context_id) + sizeof(sequence_length) + sequence_length;
	offset += (sequence_length %4) ? 4 - (sequence_length%4) : 0 ;

      } /* for */

    default :
      break;

  } /* switch message_type */

  /* decode next parts according to message type */

  switch(header.message_type) {

    case Request:

      switch(minor_version) {
        case 1  :
	  memcpy(&request_1_1, &pd[offset], sizeof(request_1_1));
	  response_expected = request_1_1.response_expected;
	  request_id = (big_endian)? pntohl(&request_1_1.request_id) :
	    pletohl(&request_1_1.request_id);
	  if (tree) {
	    proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(request_id),
			     "Request id: %d", request_id);
	    proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(request_id),
			     sizeof(request_1_1.response_expected),
			     "Response expected: %d", 
			     response_expected);
	    proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(request_id) +
			     sizeof(request_1_1.response_expected),
			     3,
			     "Reserved");
	  }
	  offset += sizeof(request_id) + 
	    sizeof(request_1_1.response_expected) + 3;
	  break;
        case 0  :
	  memcpy(&request_1_0, &pd[offset], sizeof(request_1_0));
	  response_expected = request_1_0.response_expected;
	  request_id = (big_endian)? pntohl(&request_1_0.request_id) :
	    pletohl(&request_1_0.request_id);
	  if (tree) {
	    proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(request_id),
			     "Request id: %d", request_id);
	    proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(request_id),
			     sizeof(request_1_0.response_expected),
			     "Response expected: %d", 
			     response_expected);
	  }

	  offset += sizeof(request_id) + 
	    sizeof(request_1_0.response_expected);
	  break;
        default :
	  break;
      }

      /* strange thing here with some ORBs/IIOP1.0 ? */
      if ((offset - first_offset) % 4)
	offset += 4 - (offset - first_offset)%4;

      /* object_key */

      sequence_length = (big_endian) ? 
	pntohl(&pd[offset]) : pletohl(&pd[offset]);

      if (tree) {
	proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(sequence_length),
			 "Object key length: %d", sequence_length);
	proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(sequence_length),
			 sequence_length,
			 "Object key: %s",
			 print_object_key(sequence_length, 
			   (u_char *)&pd[offset + sizeof(sequence_length)]));
      }

      /* operation & requesting_principal */

      offset += sizeof(sequence_length) + sequence_length;
      offset += (sequence_length %4) ? 4 - (sequence_length%4) : 0 ;

      sequence_length = (big_endian) ? 
	pntohl(&pd[offset]) : pletohl(&pd[offset]);

      if (sequence_length > message_size) {
	dissect_data(pd, offset, fd, tree);
	return TRUE;
      }
       
      if (tree) {
	proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(sequence_length),
			 "Operation length: %d", sequence_length);
	proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(sequence_length), 
			 sequence_length,
			 "Operation: %s",
			 &pd[offset+sizeof(sequence_length)]);
	proto_tree_add_text(clnp_tree, NullTVB, offset +
			 sizeof(sequence_length)+ sequence_length,
			 message_size - END_OF_GIOP_MESSAGE - 
			 sizeof(sequence_length) - sequence_length,
			 "Requesting principal: <not shown>");
      }

      if (check_col(fd, COL_INFO)) {
        col_add_fstr(fd, COL_INFO, "Request %s %d: %s",
		response_expected ? "two-way" : "one-way" ,
		request_id,
		&pd[offset+sizeof(sequence_length)]);
      }

      break;

    case Reply :

      memcpy(&reply, &pd[offset], sizeof(reply));
      request_id =  (big_endian) ? 
	pntohl(&reply.request_id) : pletohl(&reply.request_id);
      reply_status = (big_endian) ? 
	pntohl(&reply.reply_status) : pletohl(&reply.reply_status);

      if (tree) {
	proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(request_id),
			 "Request id: %d", request_id);
	proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(request_id), 
			 sizeof(reply_status),
			 "Reply status: %s",
			 reply_status == NO_EXCEPTION ? "no exception" :
			 reply_status == USER_EXCEPTION ? "user exception" :
			 reply_status == SYSTEM_EXCEPTION ? "system exception" :
			 reply_status == LOCATION_FORWARD ? "location forward" :
			 "?");
      }

      if (check_col(fd, COL_INFO)) {
        col_add_fstr(fd, COL_INFO, "Reply %d: %s",
		request_id,
		reply_status == NO_EXCEPTION ? "no exception" :
		reply_status == USER_EXCEPTION ? "user exception" :
		reply_status == SYSTEM_EXCEPTION ? "system exception" :
		reply_status == LOCATION_FORWARD ? "location forward" :
		"?");
      }

      offset += sizeof(request_id) + sizeof(reply_status);

      if (reply_status == SYSTEM_EXCEPTION) {

	u_int minor_code_value;
	u_int completion_status;

	sequence_length = (big_endian) ? 
	  pntohl(&pd[offset]) : pletohl(&pd[offset]);

	if (sequence_length > message_size) {
	  dissect_data(pd, offset, fd, tree);
	  return TRUE;
	}

	if (tree) {
	  proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(sequence_length),
			   "Exception length: %d", sequence_length);
	  proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(sequence_length), 
			   sequence_length,
			   "Exception id: %s",
			   &pd[offset+sizeof(sequence_length)]);

	}

	offset += sizeof(sequence_length) + sequence_length;

	minor_code_value = (big_endian) ? 
	  pntohl(&pd[offset]) : pletohl(&pd[offset]);
	completion_status = (big_endian) ? 
	  pntohl(&pd[offset+sizeof(minor_code_value)]) :
	  pletohl(&pd[offset+sizeof(minor_code_value)]);
	
	if (tree) {
	  proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(minor_code_value),
			   "Minor code value: %d", minor_code_value);
	  proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(minor_code_value),
			   sizeof(completion_status),
			   "Completion Status: %d",
			   completion_status);
	  
	}

      }
      else if (reply_status == USER_EXCEPTION) {

	sequence_length = (big_endian) ? 
	  pntohl(&pd[offset]) : pletohl(&pd[offset]);

	if (sequence_length > message_size) {
	  dissect_data(pd, offset, fd, tree);
	  return TRUE;
	}

	if (tree) {
	  proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(sequence_length),
			   "Exception length: %d", sequence_length);
	  proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(sequence_length), 
			   sequence_length,
			   "Exception id: %s",
			   &pd[offset+sizeof(sequence_length)]);

	}

	offset += sizeof(sequence_length) + sequence_length;

	sequence_length = (big_endian) ? 
	  pntohl(&pd[offset]) : pletohl(&pd[offset]);

	if (sequence_length > message_size) {
	  dissect_data(pd, offset, fd, tree);
	  return TRUE;
	}

	if (tree && sequence_length) {
	  proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(sequence_length),
			   "Exception member length: %d", sequence_length);
	  proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(sequence_length), 
			   sequence_length,
			   "Exception member: %s",
			   &pd[offset+sizeof(sequence_length)]);
	}

	offset += sizeof(sequence_length) + sequence_length;

      }
      else {
	
	if (tree) {
	  proto_tree_add_text(clnp_tree, NullTVB, offset,
			   message_size - END_OF_GIOP_MESSAGE,
			   "Reply body: <not shown>");
	}

      } /* reply_status */

      break;

    case LocateRequest :

      memcpy(&locate_req, &pd[offset], sizeof(locate_req));
      request_id =  (big_endian) ? 
	pntohl(&locate_req.request_id) : pletohl(&locate_req.request_id);

      sequence_length = (big_endian) ? 
	pntohl(&pd[offset+sizeof(request_id)]) : 
	pletohl(&pd[offset+sizeof(request_id)]);

      if (tree) {
	proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(request_id),
			 "Request id: %d", request_id);
	proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(request_id), 
			 sizeof(sequence_length),
			 "Object key length: %d", sequence_length);
	offset += sizeof(request_id) + sizeof(sequence_length);
	proto_tree_add_text(clnp_tree, NullTVB,
			 offset,
			 sequence_length,
			 "Object key: %s", 
			 print_object_key(sequence_length, 
					  (u_char *)&pd[offset]));
      }

      if (check_col(fd, COL_INFO)) {
        col_add_fstr(fd, COL_INFO, "LocateRequest %d", request_id);
      }

      break;

    case LocateReply :

      memcpy(&locate_rep, &pd[offset], sizeof(locate_rep));
      request_id =  (big_endian) ? 
	pntohl(&locate_rep.request_id) : pletohl(&locate_rep.request_id);
      locate_status = (big_endian) ? 
	pntohl(&locate_rep.locate_status) : pletohl(&locate_rep.locate_status);

      if (tree) {
	proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(request_id),
			 "Request id: %d", request_id);
	proto_tree_add_text(clnp_tree, NullTVB, offset + sizeof(request_id), 
			 sizeof(locate_status),
			 "Locate status: %d", locate_status);
	offset += sizeof(request_id) + sizeof(locate_status);
	if (locate_status == OBJECT_FORWARD) {
	  proto_tree_add_text(clnp_tree, NullTVB, offset,
			   message_size - END_OF_GIOP_MESSAGE,
			   "Locate reply body: <not shown>");
	}
      }

      if (check_col(fd, COL_INFO)) {
        col_add_fstr(fd, COL_INFO, "LocateReply %d: %s",
		request_id, 
		(locate_status == UNKNOWN_OBJECT) ? "Unknown object" :
		(locate_status == OBJECT_HERE) ? "Object here" :
		(locate_status == OBJECT_FORWARD) ? "Object forward" : "?");
      }

      break;

    case CancelRequest :

      request_id =  (big_endian) ? 
	pntohl(&pd[offset]) : pletohl(&pd[offset]);

      if (tree) {
	proto_tree_add_text(clnp_tree, NullTVB, offset, sizeof(request_id),
			 "Request id: %d", request_id);
      }

      if (check_col(fd, COL_INFO)) {
        col_add_fstr(fd, COL_INFO, "CancelRequest %d", request_id);
      }

      break;

    case CloseConnection :
      if (check_col(fd, COL_INFO)) {
        col_add_str(fd, COL_INFO, "CloseConnection");
      }
      break;

    case MessageError :
      if (check_col(fd, COL_INFO)) {
        col_add_str(fd, COL_INFO, "MessageError");
      }
      break;

    case Fragment :
      if (check_col(fd, COL_INFO)) {
        col_add_str(fd, COL_INFO, "Fragment");
      }
      break;

    default :
      break;

  } /* switch message_type */


  offset = first_offset + GIOP_HEADER_SIZE + message_size;

  if (IS_DATA_IN_FRAME(offset)) {
    dissect_data(pd, offset, fd, tree);
  }

  return TRUE;
} /* dissect_giop */

void 
proto_register_giop(void)
{
  static hf_register_info hf[] = {
    { &hf_giop_message_type,
      { "Message type",		"giop.type",	FT_UINT8,	BASE_DEC, NULL, 0x0,
      	"" }},
    { &hf_giop_message_size,
      { "Message size",		"giop.len",	FT_UINT32,	BASE_DEC, NULL, 0x0,
      	"" }},
  };
  static gint *ett[] = {
    &ett_giop,
  };

  proto_giop = proto_register_protocol("General Inter-ORB Protocol", "giop");
  proto_register_field_array(proto_giop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_giop(void)
{
  heur_dissector_add("tcp", dissect_giop);
}
