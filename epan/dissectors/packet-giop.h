/* packet-giop.h
 * Declaration of routines for GIOP/IIOP (CDR) dissection
 * Copyright 2000, Frank Singleton <frank.singleton@ericsson.com>
 *
 * Based on CORBAv2.4.2  Chapter 15 GIOP Description.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_GIOP_H
#define PACKET_GIOP_H

/*
 * Useful visible data/structs
 */

#define GIOP_HEADER_SIZE    12

typedef struct Version {
  guint8 major;
  guint8 minor;
} Version;


/*
 * Useful data collected from message header. Note, this
 * struct encapsulates useful data from GIOP header, as well
 * as request_id and reply_status for use by sub dissectors.
 */

typedef struct MessageHeader {

  /* Common Data */

  guint8 magic[4];
  Version GIOP_version;
  guint8 flags;			/* byte_order in 1.0 */
  guint8 message_type;
  guint32 message_size;
  guint32 req_id;               /* request id in MSG  */

  /* MSG dependant data */

  guint32 rep_status;           /* reply status in MSG if available */
  gchar *exception_id;             /* exception string if a USER EXCEPTION occurs  */

} MessageHeader;

typedef enum MsgType {
  Request = 0,
  Reply,
  CancelRequest,
  LocateRequest,
  LocateReply,
  CloseConnection,
  MessageError,
  Fragment			/* GIOP 1.1 only */

} MsgType;



/*
 * Reply Status
 *
 */

typedef enum ReplyStatusType {
  NO_EXCEPTION = 0,
  USER_EXCEPTION,
  SYSTEM_EXCEPTION,
  LOCATION_FORWARD,
  LOCATION_FORWARD_PERM,	/* new for GIOP 1.2 */
  NEEDS_ADDRESSING_MODE		/* new for GIOP 1.2 */
} ReplyStatusType;

/*
 * Prototype for sub dissector function calls.
 */

typedef gboolean (giop_sub_dissector_t)(tvbuff_t *, packet_info *, proto_tree *, int *,
				  MessageHeader *, gchar * , gchar *);

/*
 * Generic Subdissector handle, wraps user info.
 */

typedef struct giop_sub_handle {
  giop_sub_dissector_t *sub_fn;  /* ptr to sub dissector function */
  const gchar *sub_name;         /* subdissector string name */
  protocol_t *sub_proto;         /* protocol_t for subprotocol */
} giop_sub_handle_t;

/* Main GIOP entry point */

extern gboolean dissect_giop(tvbuff_t *, packet_info *, proto_tree *); /* new interface */

/*
 * GIOP Users register interest via this function.
 * This is for heuristic dissection
 */

extern void register_giop_user(giop_sub_dissector_t *sub, const gchar *name,
    int sub_proto);

/*
 * GIOP Users remove interest via this function.
 * This is for heuristic dissection
 */

extern void delete_giop_user(giop_sub_dissector_t *sub, gchar *name);


/*
 * GIOP Users register their module and interface names via this function.
 * This is for explicit dissection.
 */

extern void register_giop_user_module(giop_sub_dissector_t *sub, gchar *name,
    gchar *module, int sub_proto);

/*
 * GIOP Users remove their module and interface names via this function.
 * This is for explicit dissection.
 */

extern void delete_giop_user_module(giop_sub_dissector_t *sub, gchar *name,
    gchar *module);


/*
 * General CDR accessors start here. They are listed in alphabetical
 * order. They may however, belong to 1 of 3 distinct CDR data types.
 *
 * - Primitive
 * - OMG IDL Constructed Types
 * - Pseudo Object Types
 *
 *
 * Altough some of these look redundant, I have separated them
 * out for all CDR types, to assist in auto generation of
 * IDL dissectors later, see idl2eth -- FS
 *
 */


/*
 * Gets data of type any. This is encoded as a TypeCode
 * followed by the encoded value.
 *
 * Data is added to tree directly if present.
 */

extern void get_CDR_any(tvbuff_t *tvb, proto_tree *tree, gint *offset,
    gboolean stream_is_big_endian, int boundary, MessageHeader * header );


/* Copy a 1 octet sequence from the tvbuff
 * which represents a boolean value, and convert
 * it to a boolean value.
 * Offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

extern gboolean get_CDR_boolean(tvbuff_t *tvb, int *offset);


/* Copy a 1 octet sequence from the tvbuff
 * which represents a char, and convert
 * it to an char value.
 * offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

extern guint8 get_CDR_char(tvbuff_t *tvb, int *offset);



/*
 * Floating Point Data Type double IEEE 754-1985
 *
 * Copy an 8 octet sequence from the tvbuff
 * which represents a double value, and convert
 * it to a double value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for double values.
 * offset is then incremented by 8, to indicate the 8 octets which
 * have been processed.
 */

extern gdouble get_CDR_double(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);


/* Copy a 4 octet sequence from the tvbuff
 * which represents an enum value, and convert
 * it to an enum value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for an enum (4)
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 *
 * Enum values are encoded as unsigned long.
 */

extern guint32 get_CDR_enum(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);



/*
 * Copy an octet sequence from the tvbuff
 * which represents a Fixed point decimal type, and create a string representing
 * a Fixed point decimal type. There are no alignment restrictions.
 * Size and scale of fixed decimal type is determined by IDL.
 *
 * digits - IDL specified number of "digits" for this fixed type
 * scale  - IDL specified "scale" for this fixed type
 *
 *
 * eg: typedef fixed <5,2> fixed_t;
 *     could represent numbers like 123.45, 789.12,
 *
 *
 * As the fixed type could be any size, I will not try to fit it into our
 * simple types like gdouble or glong etc. I will just create a string buffer holding
 * a  representation (after scale is applied), and with a decimal point or zero padding
 * inserted at the right place if necessary. The string is null terminated
 *
 * so string may look like
 *
 *
 *  "+1.234" or "-3456.78" or "1234567309475760377365465897891" or "-2789000000" etc
 *
 * According to spec, digits <= 31
 * and scale is positive (except for constants eg: 1000 has digit=1 and implied scale = -3)
 * or <4,0> ?
 *
 * User must remember to free the buffer
 *
 */

extern void get_CDR_fixed(tvbuff_t *tvb, gchar **seq, gint *offset,
    guint32 digits, gint32 scale);



/*
 * Floating Point Data Type float IEEE 754-1985
 *
 * Copy a 4 octet sequence from the tvbuff
 * which represents a float value, and convert
 * it to a float value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for float values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

extern gfloat get_CDR_float(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);


/*
 * Decode an Interface type, and display it on the tree.
 */

extern void get_CDR_interface(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int *offset, gboolean stream_is_big_endian, int boundary);


/* Copy a 4 octet sequence from the tvbuff
 * which represents a signed long value, and convert
 * it to an signed long vaule, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for long values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

extern gint32 get_CDR_long(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);



/* Copy a 16 octet sequence from the tvbuff
 * which represents a long double value, and convert
 * it to a long double value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for  long double values.
 * offset is then incremented by 16, to indicate the 16 octets which
 * have been processed.
 */

#ifdef G_HAVE_GLONG_DOUBLE

extern glong_double get_CDR_long_double(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);
#else

/* FIX -- Cast long double to gdouble until I figure this out -- FS*/

extern gdouble get_CDR_long_double(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);

#endif


/* Copy an 8 octet sequence from the tvbuff
 * which represents a signed long long value, and convert
 * it to a signed long long value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for long long values.
 * offset is then incremented by 8, to indicate the 8 octets which
 * have been processed.
 */

#ifdef G_HAVE_GINT64
extern gint64 get_CDR_long_long(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);
#endif

/*
 * Decode an Object type, and display it on the tree.
 */

extern void get_CDR_object(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree, int *offset, gboolean stream_is_big_endian, int boundary);


/* Copy a 1 octet sequence from the tvbuff
 * which represents a octet, and convert
 * it to an octet value.
 * offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

extern guint8 get_CDR_octet(tvbuff_t *tvb, int *offset);


/* Copy a sequence of octets from the tvbuff.
 * Caller of this function must remember to free the
 * array pointed to by seq.
 * This function also increments offset by len.
 */

extern void get_CDR_octet_seq(tvbuff_t *tvb, gchar **seq, int *offset, guint32 len);

/* Copy a 2 octet sequence from the tvbuff
 * which represents a signed short value, and convert
 * it to a signed short value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for short values.
 * offset is then incremented by 2, to indicate the 2 octets which
 * have been processed.
 */

extern gint16 get_CDR_short(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);


/* Copy an octet sequence from the tvbuff
 * which represents a string, and convert
 * it to an string value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for string values. (begins with an unsigned long LI)
 *
 * String sequence is copied to a  buffer "seq". This must
 * be freed by the calling program.
 * offset is then incremented  , to indicate the  octets which
 * have been processed.
 *
 * returns number of octets in the sequence
 *
 * Note: This function only supports single byte encoding at the
 *       moment until I get a handle on multibyte encoding etc.
 *
 */

extern guint32 get_CDR_string(tvbuff_t *tvb, gchar **seq, int *offset,
    gboolean stream_is_big_endian, int boundary);


/* Process a sequence of octets that represent the
 * Pseudo Object Type "TypeCode". Typecodes are used for example,
 * by "Any values".
 * This function also increments offset to the correct position.
 *
 * It will parse the TypeCode and output data to the "tree" provided
 * by the user
 *
 * It returns a guint32 representing a TCKind value.
 */

extern guint32 get_CDR_typeCode(tvbuff_t *tvb, proto_tree *tree, gint *offset,
    gboolean stream_is_big_endian, int boundary, MessageHeader * header );

/* Copy a 4 octet sequence from the tvbuff
 * which represents an unsigned long value, and convert
 * it to an unsigned long value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned long values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

extern guint32 get_CDR_ulong(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);


/* Copy an 8 octet sequence from the tvbuff
 * which represents an unsigned long long value, and convert
 * it to an unsigned long long value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned long long values.
 * offset is then incremented by 8, to indicate the 8 octets which
 * have been processed.
 */

#ifdef G_HAVE_GINT64
extern guint64 get_CDR_ulong_long(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);
#endif


/* Copy a 2 octet sequence from the tvbuff
 * which represents an unsigned short value, and convert
 * it to an unsigned short value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned short values.
 * offset is then incremented by 2, to indicate the 2 octets which
 * have been processed.
 */

extern guint16 get_CDR_ushort(tvbuff_t *tvb, int *offset,
    gboolean stream_is_big_endian, int boundary);


/* Copy a wchar from the tvbuff.
 * Caller of this function must remember to free the
 * array pointed to by seq.
 * This function also increments offset according to
 * the wchar size.
 *
 * For GIOP 1.1 read 2 octets and return size -2. The
 * negation means there is no size element in the packet
 * and therefore no size to add to the tree.
 *
 * For GIOP 1.2 read size of wchar and the size
 * octets. size is returned as a gint8.
 *
 * For both GIOP versions the wchar is returned
 * as a printable string.
 *
 */

/* NOTE: This is very primitive in that it just reads
 * the wchar as a series of octets and returns them
 * to the user. No translation is attempted based on
 * byte orientation, nor on code set. I.e it only
 * really reads past the wchar and increments the offset
 * by the length of the octet sequence.
 */

/* The "decoding" is done according to CORBA chapter 15.
 * Wchar is not supported for GIOP 1.0.
 */

extern gint get_CDR_wchar(tvbuff_t *tvb, gchar **seq, int *offset,
    MessageHeader * header);


/* Copy a wstring from the tvbuff.
 * Caller of this function must remember to free the
 * array pointed to by seq.
 * This function also increments offset, according to
 * wstring length. length is returned as guint32
 */

/* NOTE: This is very primitive in that it just reads
 * the wstring as a series of octets and returns them
 * to the user. No translation is attempted based on
 * byte orientation, nor on code set. I.e it only
 * really reads past the wstring and increments the offset
 * by the length of the octet sequence.
 */

/* The "decoding" is done according to CORBA chapter 15.
 * Wstring is not supported for GIOP 1.0.
 */

extern guint32 get_CDR_wstring(tvbuff_t *tvb, gchar **seq, int *offset,
    gboolean stream_is_big_endian, int boundary, MessageHeader * header);



/*
 *
 * End of get_CDR_xxx accessors.
 *
 */



/* Determine the byte order from the GIOP MessageHeader */

extern gboolean is_big_endian (MessageHeader * header);

/*
 * get_encap_info() for any encapsulation  (eg:sequences)
 * we come across. updates the new boundary and endianess
 * and *offset, and returns the sequence length.
 */

extern guint32 get_CDR_encap_info(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			   gboolean old_stream_is_big_endian, guint32 old_boundary,
			   gboolean *new_stream_is_big_endian_ptr, guint32 *new_boundary_ptr );

/* Take in an array of char and create a new string.
 * Replace non-printable characters with periods.
 *
 * The array may contain \0's so dont use strdup
 * The string is \0 terminated, and thus longer than
 * the initial sequence.
 * Caller must free the new string.
 */

extern gchar * make_printable_string (gchar *in, guint32 len);

/*
 * Enums for TCkind
 */

enum TCKind {
  tk_null = 0,
  tk_void,
  tk_short,
  tk_long,
  tk_ushort,
  tk_ulong,
  tk_float,
  tk_double,
  tk_boolean,
  tk_char,
  tk_octet,
  tk_any,
  tk_TypeCode,
  tk_Principal,
  tk_objref,
  tk_struct,
  tk_union,
  tk_enum,
  tk_string,
  tk_sequence,
  tk_array,
  tk_alias,
  tk_except,
  tk_longlong,
  tk_ulonglong,
  tk_longdouble,
  tk_wchar,
  tk_wstring,
  tk_fixed,
  tk_value,
  tk_value_box,
  tk_native,
  tk_abstract_interface

  /* - none -   0xffffffff TODO */
};

#define tk_none  0xffffffff

typedef enum TCKind TCKind_t;


/*
 * ServiceId's for ServiceContextList
 *
 * Chapter 13 Corba 2.4.2
 */

#define IOP_ServiceId_TransactionService                0
#define IOP_ServiceId_CodeSets                          1
#define IOP_ServiceId_ChainBypassCheck                  2
#define IOP_ServiceId_ChainBypassInfo                   3
#define IOP_ServiceId_LogicalThreadId                   4
#define IOP_ServiceId_BI_DIR_IIOP                       5
#define IOP_ServiceId_SendingContextRunTime             6
#define IOP_ServiceId_INVOCATION_POLICIES               7
#define IOP_ServiceId_FORWARD_IDENTITY                  8
#define IOP_ServiceId_UnknownExceptionInfo              9

#endif /* PACKET_GIOP_H */
