/* packet-giop.c
 * Routines for CORBA GIOP/IIOP packet disassembly
 *
 * Initial Code by,
 * Laurent Deniel <laurent.deniel@free.fr>
 * Craig Rodrigues <rodrigc@attbi.com>
 *
 * GIOP API extensions by,
 * Frank Singleton <frank.singleton@ericsson.com>
 * Trevor Shepherd <eustrsd@am1.ericsson.se>
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


/*
 * TODO: -- FS
 * 1. heuristic giop dissector table [started]
 * 2. GUI options, see 20
 * 3. Remove unneccessary reply_status in heuristic dissector calls (now
 *    part of MessageHeader) [done]
 * 4. get_CDR_xxx should be passed an alignment offset value
 *    rather than GIOP_HEADER_SIZE, as alignment can also change in a
 *    octet stream when eg: encapsulation is used [done]
 * 5. GIOP users should eventually get there own tvbuff, and
 *    not rely on the GIOP tvbuff, more robust
 * 6. get_CDR_string,wchar,wstring etc should handle different
 *    GIOP versions [started]
 * 7. Fix situation where req_id is not unique in a logfile [done, use FN/MFN, needs improving.]
 *
 * 8. Keep request_1_2 in step with request_1_1 [started]
 * 9. Explicit module name dissection [done]
 * 10. Decode IOR and put in a useful struct [IOR decode started]
 * 11. Fix encapsulation of IOR etc and boundary [done]
 * 12. handle get_CDR_typeCode() [started]
 * 13. Handle different IOR profiles
 * 14. Change printable_string to RETURN a new string, not to modify the old.
 *     or, new function, make_printable_string [done, make_printable_string]
 *
 * 15. Handle "TCKind", and forget about eg: enum translation to symbolic values
 *     otherwise need knowledge of sub dissectors data - YUK [done]
 * 16. Handle multiple RepoId representations, besides IDL:Echo:1.0 (see 13.)
 * 17. Pass subset of RepoID to explicit dissector.
 *     eg : If IDL:Mod1/Mod2/Int3:1.0 then pass "Mod1/Mode2/Int3" to sub dissector[done]
 * 18. Better hashing algorithms
 * 19. Handle hash collision properly .
 * 20. Allow users to paste a stringified IOR into the GUI, and tie it
 *     to a sub_dissector.
 * 21. Add complete_request_packet_list and complete_reply_packet_hash.[done]
 * 22. Handle case where users click in any order, AND try and match
 *     REPLY msg to the correct REQUEST msg when we have a request_id collision.[done]
 * 23. Clean up memory management for all those g_malloc's etc
 * 24. register_giop_user_module could return a key for every distinct Module/Interface
 *     the sub_dissector uses. So, instead of strcmp()'s when  handling the
 *     namespace of an operation, we could have a lookup table instead.
 * 25. A few typedefs in the right place.
 * 26  Improve handling of gchar *  and use const gchar * where possible.
 * 27. Read/write IOR etc to/from file, allows objkey hash to be built from
 *     external data [read done, write incomplete]
 * 28. Call sub dissector only if tvb_offset_exists(). [Done, this is checked
 *     inside try_explicit_giop_dissector() ]
 *
 * 29. Make add/delete routine for objkey hash as it may be useful when say reading
 *     stringified IOR's from a file to add them to our hash. ie: There are other ways
 *     to populate our object key hash besides REPLY's to RESOLVE(request) [done]
 *
 * 30. Add routine to encode/decode stringified IOR's [decode done]
 * 31. Add routine to read IOR's from file [done]
 * 32. TypeCode -none-, needs decoding.
 * 33. Complete dissect_data_for_typecode.
 * 34. For complex TypeCodes need to check final offset against original offset + sequence length.
 * 35. Update REQUEST/REPLY 1_2 according to IDL (eg; ServiceContextList etc).
 * 36. Adding decode_ServiceContextList, incomplete.
 * 37. Helper functions should not ALWAYS rely on header to find  current endianess. It should
 *     be passed from user, eg Use   stream_is_big_endian. [started]
 * 38. Remove unwanted/unused function parameters, see decode_IOR [started]
 * 40. Add sequence <IOP::TaggedComponent> components to IIOP IOR profile. Perhaps
 *     decode_IOP_TaggedComponents as a helper function. [done - NOT helper]
 *
 * 41. Make important field searchable from Message header. ie: Remove add_text_
 * 42. Use sub-tree for decode_ServiceContextList, looks better.
 * 43. dissect_reply_body, no exception dissector calls
 *       - call subdiss directly, as we already have handle.
 *       - add repoid to heuristic call also.
 *
 * 44. typedef using xxx_t in .h file.
 * 45. Subdissectors should not be passed MessageHeader to find endianness and
 *     version, they should be passed directly ?
 * 46. get_CDR_wchar and wstring need wide chars decoded (just dumped in
 *     any readable form at present, not handled well at all, suggestions welcome -- FS
 * 47. Change ...add_text to ...add_xxx (ie use hf fields).
 *
 * 48. BUG - file load with a GIOP filter set, causes the FN/MFN data struct to be
 *     not initiated properly. Hit "Reload" as a workaround, til I fix this -- FS
 *
 */



/*
 * Intended Decode strategy:
 * =========================
 *
 * Initial Pass
 * ------------
 * REQUEST: objkey -> Repo_ID -> Module/Interface -> giop_sub_handle_t
 *          and populate complete_request_packet_hash
 *
 * REPLY:   FN -> MFN (via complete_reply_packet_hash) = Request FN -> giop_sub_handle_t
 *
 * User Clicks
 * -----------
 *
 * REQUEST: FN -> giop_sub_handle_t directly (via complete_request_packet_hash)
 *
 * REPLY:   FN -> MFN (via complete_reply_packet_hash) = Request FN -> giop_sub_handle_t
 *                                                                     (via complete_request_packet_hash
 *
 *
 * Limitations.
 * ============
 *
 * 1. Request_ID's are unique only per connection.
 *
 * 2. You must be monitoring the network when the client does
 *    a REQUEST(resolve), otherwise I have no knowledge of the
 *    association between object_key and REPOID. I could talk to
 *    a Nameserver, but then I would start "generating" packets.
 *    This is probably not a good thing for a protocol analyser.
 *    Also, how could I decode logfiles offline.
 *
 *    TODO -- Read stringified IORs from an input file.[done]
 *
 * 3. User clicks (REQUEST) is currently handle the same as
 *    the initial pass handling.
 *
 *    ie: objkey -> Repo_ID -> Module/Interface -> giop_sub_handle_t
 */


/*
 * Important Data Structures:
 *
 * giop_module_hash
 * ----------------
 *
 * This is a hash table that maps IDL Module/Interface Names (Key)
 * to sub_dissector handles, giop_sub_handle_t. It is populated
 * by subdissectors, via register_giop_user_module(). This
 * table is used when we have a REPOID, and explicitly wish to
 * call the subdissector that has registered responsibility for
 * that IDL module/interface.
 *
 *
 * giop_sub_list
 * -------------
 *
 * This singly linked list is used to hold entries for
 * heuristic based subdissectors. It is populated by sub_dissectors
 * wishing to be called via heuristic mechanisms. They do this
 * via the register_giop_user() function.
 *
 *
 * giop_objkey_hash
 * ----------------
 *
 * This hash table maps object_key's (key) onto REPOID's (val).
 * Once a client has REQUEST(resolve) an object , it knows about
 * an object (interface) via its object_key (see IOR). So in order to follow
 * packets that contain an object_key only, and to be able to forward it
 * to the correct explicit subdissector, we need this table.
 *
 * So, I listen in on REQUEST(resolve) messages between client and
 * Nameserver, and store the respones (REPLY/Objkey,Repo_ID) here.
 *
 * Also, stringified IOR's can be read from a file "IOR.txt" and used
 * to populate  this hash also.
 *
 *
 * Other Data structures
 * =======================
 *
 * These structures have  been added to minimise the possibility
 * of incorrectly interpreted packets when people click all
 * over the place, in no particular order, when the request_id's are
 * not unique as captured. If all request_is'd are unique, as captured, then
 * we would not have to deal with this problem.
 *
 *
 * When the logfile or packets are initially being processed, I will
 * build 2 structures. The intent is to be able to map a REPLY message
 * back to the most recent REQUEST message with the same Request_ID
 * (TODO and matching port and IP address ??)
 *
 * Abbrevs:
 * --------
 *
 * FN  - Frame Number
 * MFN - Matching Frame Number
 *
 *
 * complete_request_packet_list
 * ----------------------------
 *
 * This is a list that contains ALL the FN's that are REQUEST's, along with
 * operation,request_id and giop_sub_handle_t
 *
 * complete_reply_packet_hash
 * --------------------------
 *
 * This is a hash table. It is populated with FN (key) and MFN (val).
 * This allows me to handle the case, where if you click on any REPLY
 * message, I can lookup the matching request. This can improve
 * the match rate between REQUEST and REPLY when people click in
 * any old fashion, but is NOT foolproof.
 *
 * The algorithm I use to populate this hash during initial pass,
 * is as follows.
 *
 * If packet is a REPLY, note the reqid, and then traverse backwards
 * through the complete_request_packet_list from its tail, looking
 * for a FN that has the same Request_id. Once found, take the found FN
 * from complete_reply_packet_hash, and insert it into the MFN field
 * of the complete_reply_packet_hash.
 *
 *
 * See TODO for improvements to above algorithm.
 *
 * So now when people click on a REQUEST packet, I can call lookup the
 * giop_sub_handle_t directly from complete_request_packet_list.
 *
 * And, when they click on a REPLY, I grab the MFN of this FN from
 * complete_reply_packet_hash, then look that up in the complete_request_packet_list
 * and call the sub_dissector directly.
 *
 * So, how do I differentiate between the initial processing of incoming
 * packets, and a user clickin on one ? Good question.
 *
 * I leverage the pinfo_fd->flags.visited  on a per frame
 * basis.
 *
 * To quote from the ever helpful development list
 *
 * " When a capture file is initially loaded, all "visited" flags
 * are 0. Ethereal then makes the first pass through file,
 * sequentially dissecting each packet. After the packet is
 * dissected the first time, "visited" is 1. (See the end of
 * dissect_packet() in epan/packet.c; that's the code that
 * sets "visited" to 1).

 * By the time a user clicks on a packet, "visited" will already
 * be 1 because Ethereal will have already done its first pass
 * through the packets.

 * Reload acts just like a normal Close/Open, except that it
 * doesn't need to ask for a filename. So yes, the reload button
 * clears the flags and re-dissects the file, just as if the file
 * had been "opened".  "
 *
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <glib.h>
#include <math.h>
#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include "isprint.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/prefs.h>

#include "packet-giop.h"
#include "packet-tcp.h"

/*
 * Set to 1 for DEBUG output - TODO make this a runtime option
 */

#define DEBUG   0



/*
 * ------------------------------------------------------------------------------------------+
 *                                 Private Helper function Declarations
 * ------------------------------------------------------------------------------------------+
 */


static void decode_IIOP_IOR_profile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                    guint32 boundary, gboolean new_endianess, gchar *repobuf,
                                    gboolean store_flag);

static void decode_ServiceContextList(tvbuff_t *tvb, proto_tree *tree, int *offset,
                                      gboolean stream_is_be, guint32 boundary);

static void decode_TaggedProfile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                                 guint32 boundary, gboolean stream_is_big_endian, gchar *repobuf);

static void decode_IOR(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                       guint32 boundary, gboolean stream_is_big_endian );

static void decode_SystemExceptionReplyBody (tvbuff_t *tvb, proto_tree *tree, gint *offset,
                                             gboolean stream_is_big_endian,
                                             guint32 boundary);

static void dissect_tk_objref_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
                                     gboolean stream_is_big_endian, guint32 boundary);

static void dissect_tk_struct_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
                                     gboolean stream_is_big_endian, guint32 boundary,
                                     MessageHeader * header);

static void dissect_tk_union_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
                                    gboolean stream_is_big_endian, guint32 boundary,
                                    MessageHeader * header );

static void dissect_tk_enum_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
                                   gboolean stream_is_big_endian, guint32 boundary);

static void dissect_tk_sequence_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			               gboolean stream_is_big_endian, guint32 boundary,
				       MessageHeader * header);

static void dissect_tk_array_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			            gboolean stream_is_big_endian, guint32 boundary,
				    MessageHeader * header);

static void dissect_tk_alias_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			            gboolean stream_is_big_endian, guint32 boundary,
				    MessageHeader * header);

static void dissect_tk_except_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			             gboolean stream_is_big_endian, guint32 boundary,
				     MessageHeader * header);

static void dissect_tk_value_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			            gboolean stream_is_big_endian, guint32 boundary,
				    MessageHeader * header);

static void dissect_tk_value_box_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			                gboolean stream_is_big_endian, guint32 boundary,
					MessageHeader * header);

static void dissect_tk_native_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			             gboolean stream_is_big_endian, guint32 boundary);

static void dissect_tk_abstract_interface_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			                         gboolean stream_is_big_endian, guint32 boundary);


static void dissect_typecode_string_param(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			                  gboolean new_stream_is_big_endian, guint32 new_boundary, int hf_id );

static void dissect_data_for_typecode(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			              gboolean stream_is_big_endian, guint32 boundary,
				      MessageHeader * header, guint32 data_type );




/*
 * ------------------------------------------------------------------------------------------+
 *                                 Data/Variables/Structs
 * ------------------------------------------------------------------------------------------+
 */


static int proto_giop = -1;
static int hf_giop_message_type = -1;
static int hf_giop_message_size = -1;
static int hf_giop_repoid = -1;
static int hf_giop_req_id = -1;
static int hf_giop_req_operation = -1;
static int hf_giop_string_length = -1;
static int hf_giop_sequence_length = -1;
static int hf_giop_profile_id = -1;
static int hf_giop_type_id = -1;
static int hf_giop_iiop_v_maj = -1;
static int hf_giop_iiop_v_min = -1;
static int hf_giop_endianess = -1; /* esp encapsulations */
static int hf_giop_IOR_tag = -1;
static int hf_giop_IIOP_tag = -1;

static int hf_giop_TCKind = -1;
static int hf_giop_typecode_count = -1;
static int hf_giop_typecode_default_used = -1;
static int hf_giop_typecode_digits = -1;
static int hf_giop_typecode_length = -1;
static int hf_giop_typecode_max_length = -1;
static int hf_giop_typecode_member_name = -1;
static int hf_giop_typecode_name = -1;
static int hf_giop_typecode_scale = -1;
static int hf_giop_typecode_ValueModifier = -1;
static int hf_giop_typecode_Visibility = -1;

static int hf_giop_type_boolean = -1;
static int hf_giop_type_char = -1;
static int hf_giop_type_double = -1;
static int hf_giop_type_enum = -1;
static int hf_giop_type_float = -1;
static int hf_giop_type_long = -1;
static int hf_giop_type_octet = -1;
static int hf_giop_type_short = -1;
static int hf_giop_type_string = -1;
static int hf_giop_type_ulong = -1;
static int hf_giop_type_ushort = -1;

static int hf_giop_iiop_host = -1;
static int hf_giop_iiop_port = -1;
static int hf_giop_iop_vscid = -1;
static int hf_giop_iop_scid = -1;

static int hf_giop_reply_status = -1;
static int hf_giop_exception_id = -1;

/*
 * (sub)Tree declares
 */

static gint ett_giop = -1;
static gint ett_giop_reply = -1;
static gint ett_giop_request = -1;
static gint ett_giop_cancel_request = -1;
static gint ett_giop_locate_request = -1;
static gint ett_giop_locate_reply = -1;
static gint ett_giop_fragment = -1;

static gint ett_giop_scl = -1;	/* ServiceContextList */
static gint ett_giop_scl_st1 = -1; 
static gint ett_giop_ior = -1;	/* IOR  */

static dissector_handle_t data_handle;
static dissector_handle_t giop_tcp_handle;
/* GIOP endianess */

static const value_string giop_endianess_vals[] = {
  { 0x0, "Big Endian" },
  { 0x1, "Little Endian" },
  { 0, NULL}
};

static const value_string sync_scope[] = {
	{ 0x0, "SYNC_NONE" },
	{ 0x1, "SYNC_WITH_TRANSPORT"},
	{ 0x2, "SYNC_WITH_SERVER"},
	{ 0x3, "SYNC_WITH_TARGET"},
	{ 0, NULL}
};

/* Profile ID's */

static const value_string profile_id_vals[] = {
	{ 0x0, "TAG_INTERNET_IOP" },
	{ 0x1, "TAG_MULTIPLE_COMPONENTS"},
	{ 0x2, "TAG_SCCP_IOP"},
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

static const value_string tckind_vals[] = {
  { 0, "tk_null"},
  { 1, "tk_void"},
  { 2, "tk_short"},
  { 3, "tk_long"},
  { 4, "tk_ushort"},
  { 5, "tk_ulong"},
  { 6, "tk_float"},
  { 7, "tk_double"},
  { 8, "tk_boolean"},
  { 9, "tk_char"},
  { 10, "tk_octet"},
  { 11, "tk_any"},
  { 12, "tk_TypeCode"},
  { 13, "tk_Principal"},
  { 14, "tk_objref"},
  { 15, "tk_struct"},
  { 16, "tk_union"},
  { 17, "tk_enum"},
  { 18, "tk_string"},
  { 19, "tk_sequence"},
  { 20, "tk_array"},
  { 21, "tk_alias"},
  { 22, "tk_except"},
  { 23, "tk_longlong"},
  { 24, "tk_ulonglong"},
  { 25, "tk_longdouble"},
  { 26, "tk_wchar"},
  { 27, "tk_wstring"},
  { 28, "tk_fixed"},
  { 29, "tk_value"},
  { 30, "tk_value_box"},
  { 31, "tk_native"},
  { 32, "tk_abstract_interface"},
  { 0, NULL }
};

/*
 *  These values are taken from the CORBA 3.0.2 standard,
 *  section 13.7.1 "Standard Service Contexts".
 */
static const guint32 max_service_context_id = 0x10;
static const value_string service_context_ids[] = {
        { 0x00, "TransactionService" },
        { 0x01, "CodeSets"},
        { 0x02, "ChainBypassCheck"},
        { 0x03, "ChainBypassInfo"},
        { 0x04, "LogicalThreadId"},
        { 0x05, "BI_DIR_IIOP"},
        { 0x06, "SendingContextRunTime"},
        { 0x07, "INVOCATION_POLICIES"},
        { 0x08, "FORWARDED_IDENTITY"},
        { 0x09, "UnknownExceptionInfo"},
        { 0x0a, "RTCorbaPriority"},
        { 0x0b, "RTCorbaPriorityRange"},
        { 0x0c, "FT_GROUP_VERSION"},
        { 0x0d, "FT_REQUEST"},
        { 0x0e, "ExceptionDetailMessage"},
        { 0x0f, "SecurityAttributeService"},
        { 0x10, "ActivityService"},
        { 0, NULL }
};




#define GIOP_MAGIC 	 "GIOP"

/*
 * TAGS for IOR Profiles
 *
 * Chapter 13 Corba 2.4.2
 *
 */

#define IOP_TAG_INTERNET_IOP          0
#define IOP_TAG_MULTIPLE_COMPONENTS   1


/* Max Supported versions */

static const guint GIOP_MAJOR =  1;
static const guint GIOP_MINOR =  2;


static const int KeyAddr       = 0;
static const int ProfileAddr   = 1;
static const int ReferenceAddr = 2;



static const value_string reply_status_types[] = {
   { NO_EXCEPTION, "No Exception" } ,
   { USER_EXCEPTION, "User Exception" } ,
   { SYSTEM_EXCEPTION, "System Exception" } ,
   { LOCATION_FORWARD, "Location Forward" } ,
   { LOCATION_FORWARD_PERM, "Location Forward Perm" } ,
   { NEEDS_ADDRESSING_MODE, "Needs Addressing Mode" } ,
   { 0, NULL }
};



typedef enum LocateStatusType
{
  UNKNOWN_OBJECT,
  OBJECT_HERE,
  OBJECT_FORWARD,
  OBJECT_FORWARD_PERM,      /* new value for GIOP 1.2 */
  LOC_SYSTEM_EXCEPTION,     /* new value for GIOP 1.2 */
  LOC_NEEDS_ADDRESSING_MODE /* new value for GIOP 1.2 */
}
LocateStatusType_t;

typedef struct LocateReplyHeader
{
  guint32 request_id;
  guint32 locate_status;
}
LocateReplyHeader_t;


/*
 * DATA - complete_request_list
 */

static GList *giop_complete_request_list;

struct comp_req_list_entry {
  guint32 fn;			/* frame number */
  gchar * operation;		/* echo echoString */
  giop_sub_handle_t *subh;      /* handle to sub dissector */
  guint32 reqid;		/* request id */
  gchar * repoid;		/* repository ID */
};

typedef struct comp_req_list_entry comp_req_list_entry_t;


/*
 * DATA - complete_reply_hash
 *
 * Maps reply FN to request MFN
 */

struct complete_reply_hash_key {
  guint32 fn;			/* reply frame number  */
};

struct complete_reply_hash_val {
  guint32 mfn;			/* matching frame number (request)  */
};

GHashTable *giop_complete_reply_hash = NULL; /* hash */

/*
 * DATA - Module Hash stuff to store data from register_giop_user_module
 *
 * ie: module (or interface ?) name, and ptr to sub_dissector handle
 *
 * With this knowledge, we can call a sub dissector directly,
 * by :
 *
 * objkey -> repoid -> sub_dissector via registered module/interface
 *
 */


static int giop_module_init_count = 100; /* storage size for our permanent data */
                                         /* ie: 100 entries -- needs tweaking -- FS */

struct giop_module_key {
  gchar *module;		/* module (interface?) name  */
};

struct giop_module_val {
  giop_sub_handle_t *subh;      /* handle to sub dissector */
};

GHashTable *giop_module_hash = NULL; /* hash */


/*
 * DATA - GSList to store list of function (dissector) pointers.
 * for heuristic dissection.
 *
 */

static GSList *giop_sub_list = NULL;

/*
 * DATA - Hash stuff to follow request/reply. This is so if we get a REPLY
 * to a REQUEST (resolve), we can dump/store the RepoId and Object Key.
 *
 * With this knowledge, we can call a sub dissector directly later
 * by :
 *
 * objkey -> repoid -> sub_dissector via registered module/interface
 *
 * rather than heuristic calls that do not provide operation context.
 * (unless we pass the RepoID for a given objkey -- hmmm)
 *
 */

/*
 * Interesting operation list, add more if you want to save
 * interesting data.
 */

static const char  giop_op_resolve[]           = "resolve";
static const char  giop_op_bind_new_context[]  = "bind_new_context";
static const char  giop_op_bind[]              = "bind";
static const char  giop_op_is_a[]              = "_is_a";

/*
 * Enums  for interesting local operations, that we may need to monitor
 * with their subsequent replies
 *
 */

enum giop_op_val {
  request_resolve_op_val,	     /* REQUEST (resolve) to get RepoID etc*/
  request_bind_new_context_op_val,   /* bind_new_context */
  request_bind_op_val,		     /* bind */
  request_get_INIT_op_val	     /* finding Nameserver */

};


/*
 * hash for mapping object keys onto object namespaces, so
 * I can call the correct dissector.
 *
 *
 */

/*
 * Where did I get the IOR from.
 */

enum ior_src {
  req_res = 0,			/* REQUEST (resolve) */
  file				/* stringified IOR' in a file */

};

typedef enum ior_src ior_src_t;



/*
 * Enums for my lists and hash's
 */

enum collection_data {
  cd_heuristic_users = 0,
  cd_module_hash,
  cd_objkey_hash,
  cd_complete_request_list,
  cd_complete_reply_hash
};

typedef enum collection_data collection_data_t;



struct giop_object_key {
  guint8 *objkey;		/* ptr to object key */
  guint32 objkey_len;		/* length */
};

struct giop_object_val {
  guint8 *repo_id;		/* ptr to Repository ID string */
  ior_src_t src;		/* where did Iget this IOR from */
};

GHashTable *giop_objkey_hash = NULL; /* hash */


gboolean giop_desegment = TRUE;

/*
 * ------------------------------------------------------------------------------------------+
 *                                 Private helper functions
 * ------------------------------------------------------------------------------------------+
 */



/*
 * Insert FN,reqid,operation and sub handle in list. DOES not check for duplicates yet.
 */

static GList *insert_in_comp_req_list(GList *list, guint32 fn, guint32 reqid, gchar * op, giop_sub_handle_t *sh ) {
  GList * newlist_start;
  comp_req_list_entry_t * entry = NULL;
  gchar * opn;

  entry =  g_malloc(sizeof(comp_req_list_entry_t));
  opn =  g_strdup(op); /* duplicate operation for storage */

  entry->fn = fn;
  entry->reqid = reqid;
  entry->subh = sh;
  entry->operation = opn;
  entry->repoid = NULL;		/* dont have yet */

  newlist_start = g_list_append (list, entry); /* append */

  return newlist_start;
}


/*
 * Used to find an entry with matching Frame Number FN
 * in the complete_request_list list.
 */

static comp_req_list_entry_t * find_fn_in_list(guint32 fn) {

  GList * element;		/*  entry in list */
  comp_req_list_entry_t * entry_ptr = NULL;

  element = g_list_last(giop_complete_request_list); /* start from  last  */

  while(element) {			/* valid list entry */
    entry_ptr = element->data;	/* grab data pointer */
    if (entry_ptr->fn == fn) {	/* similar FN  */
      return entry_ptr;
    }
    element = g_list_previous(element); /* try next previous */
  }

  return NULL;			/* no match so return NULL */
}


/*
 * Add/update a sub_dissector handle and repoid to a FN entry in the complete_request_list
 *
 * Call this when you know a FN and matching giop_sub_handle_t and repoid
 *
 * This is done in say, try_explicit_dissector for example.
 *
 */

static void add_sub_handle_repoid_to_comp_req_list(guint32 fn, giop_sub_handle_t *sh, gchar *repoid ) {

  comp_req_list_entry_t * entry = NULL;
  entry = find_fn_in_list(fn);	/* grab FN data entry */

  if (entry) {
    entry->subh = sh;
    entry->repoid = g_strdup(repoid); /* copy and store */

  }
}




/* giop_complete_reply_hash  "EQUAL" Functions */

static gint complete_reply_equal_fn(gconstpointer v, gconstpointer w) {
  const struct complete_reply_hash_key *mk1 = (const struct complete_reply_hash_key *)v;
  const struct complete_reply_hash_key *mk2 = (const struct complete_reply_hash_key *)w;

  if (mk1->fn == mk2->fn) {
    return 1;
  }

  return 0;			/* found  differences */
}

/* giop_complete_reply_hash "HASH" Functions */

static guint32 complete_reply_hash_fn(gconstpointer v) {
  guint32 val;		/* init hash value */
  const struct complete_reply_hash_key *key = (const struct complete_reply_hash_key *)v;

  val = key->fn;		/* simple and unique */

  return val;
}


/*
 * Insert the FN and MFN together in our complete_reply_hash.
 */

static void insert_in_complete_reply_hash(guint32 fn, guint32 mfn) {

  struct complete_reply_hash_key key, *new_key;
  struct complete_reply_hash_val *val = NULL;

  key.fn = fn;

  val = (struct complete_reply_hash_val *)g_hash_table_lookup(giop_complete_reply_hash, &key);

  if (val) {
    return;			/* FN collision */
  }

  new_key = se_alloc(sizeof(struct complete_reply_hash_key));
  new_key->fn = fn;		/* save FN */

  val = se_alloc(sizeof(struct complete_reply_hash_val));
  val->mfn = mfn;		/* and MFN */

  g_hash_table_insert(giop_complete_reply_hash, new_key, val);

}

/*
 * Find the MFN values from a given FN key.
 * Assumes the complete_reply_hash is already populated.
 */

static guint32 get_mfn_from_fn(guint32 fn) {

  struct complete_reply_hash_key key;
  struct complete_reply_hash_val *val = NULL;
  guint32 mfn = fn;		/* save */

  key.fn = fn;
  val = (struct complete_reply_hash_val *)g_hash_table_lookup(giop_complete_reply_hash, &key);

  if (val) {
    mfn = val->mfn;		/* grab it */
  }

  return mfn;			/* mfn or fn if not found */

}

/*
 * Attempt to find the MFN for this FN, and return it.
 * Return MFN if found, or just FN if not. This is
 * only used when we are building
 */

static guint32 get_mfn_from_fn_and_reqid(guint32 fn, guint32 reqid) {

  GList * element;		/* last entry in list */
  comp_req_list_entry_t * entry_ptr = NULL;

  /* Need Some pretty snappy code */

  /* Loop back from current end of complete_request_list looking for */
  /* a FN with the same reqid -- TODO enhance with port/address checks -- FS */

  /*
   * As this routine is only called during initial pass of data,
   * and NOT when a user clicks, it is ok to start from Current
   * end of complete_request_list when searching for a match.
   * As that list is bing populated in the same order as FN's
   * are being read.
   *
   * Also, can make check for same reqid more detailed, but I start
   * with reqid. Could add say port or address checks etc later ??
   */


  element = g_list_last(giop_complete_request_list); /* get last  */

  while(element) {			/* valid list entry */
    entry_ptr = element->data;	/* grab data pointer */
    if (entry_ptr->reqid == reqid) {	/* similar reqid  */
      return entry_ptr->fn;	/* return MFN */
    }
    element = g_list_previous(element); /* try next previous */
  }

  return fn;			/* no match so return FN */
}


/* Module Hash "EQUAL" Functions */

static gint giop_hash_module_equal(gconstpointer v, gconstpointer w) {
  const struct giop_module_key *mk1 = (const struct giop_module_key *)v;
  const struct giop_module_key *mk2 = (const struct giop_module_key *)w;

  if (strcmp(mk1->module, mk2->module) == 0) {
    return 1;
  }

  return 0;			/* found  differences */
}

/* Module Hash "HASH" Functions */

static guint32 giop_hash_module_hash(gconstpointer v) {

  int i,len;
  guint32 val = 0;		/* init hash value */

  const struct giop_module_key *key = (const struct giop_module_key *)v;

  /*
   * Hmm, try this simple hashing scheme for now.
   * ie: Simple summation, FIX later -- FS
   *
   *
   */

  len = strlen(key->module);

  for (i=0; i<len; i++) {
    val += (guint8) key->module[i];
  }

  return val;

}


/*
 * ------------------------------------------------------------------------------------------+
 *                                 Public Utility functions
 * ------------------------------------------------------------------------------------------+
 */




/*
 * Routine to  allow giop users to register their sub dissector function, name, and
 * IDL module/interface name. Store in giop_module_hash. Also pass along their proto_XXX
 * value returned from their proto_register_protocol(), so we can enable/disbale it
 * through the GUI (edit protocols).
 *
 * This is used by try_explicit_giop_dissector() to find the
 * correct sub-dissector.
 *
 */

void register_giop_user_module(giop_sub_dissector_t *sub, gchar *name, gchar *module, int sub_proto) {

  struct giop_module_key module_key, *new_module_key;
  struct giop_module_val *module_val = NULL;

  module_key.module = module; /*  module name */

  module_val = (struct giop_module_val *)g_hash_table_lookup(giop_module_hash, &module_key);

  if (module_val) {
    return;			/* module name collision */
  }

  /* So, passed module name should NOT exist in hash at this point.*/

#if DEBUG
  printf("giop:register_module: Adding Module %s to module hash \n", module);
  printf("giop:register_module: Module sub dissector name is %s \n", name);
#endif

  new_module_key = g_malloc(sizeof(struct giop_module_key));
  new_module_key->module = module; /* save Module or interface name from IDL */

  module_val = g_malloc(sizeof(struct giop_module_val));

  module_val->subh = g_malloc(sizeof (giop_sub_handle_t)); /* init subh  */

  module_val->subh->sub_name = name;	/* save dissector name */
  module_val->subh->sub_fn = sub;	/* save subdissector*/
  module_val->subh->sub_proto = find_protocol_by_id(sub_proto);	/* save protocol_t for subdissector's protocol */

  g_hash_table_insert(giop_module_hash, new_module_key, module_val);

}




/* Object Key Hash "EQUAL" Functions */

static gint giop_hash_objkey_equal(gconstpointer v, gconstpointer w) {
  const struct giop_object_key *v1 = (const struct giop_object_key *)v;
  const struct giop_object_key *v2 = (const struct giop_object_key *)w;

  if (v1->objkey_len != v2->objkey_len)
    return 0;			/* no match because different length */

  /* Now do a byte comaprison */

  if (memcmp(v1->objkey,v2->objkey, v1->objkey_len) == 0) {
    return 1;		/* compares ok */
  }

#if DEBUG
  printf("giop:giop_hash_objkey_equal: Objkey's DO NOT match");
#endif

  return 0;			/* found  differences */
}

/* Object Key Hash "HASH" Functions */

static guint32 giop_hash_objkey_hash(gconstpointer v) {
  const struct giop_object_key *key = (const struct giop_object_key *)v;

  guint32 i;
  guint32 val = 0;		/* init hash value */


  /*
   * Hmm, try this simple hashing scheme for now.
   * ie: Simple summation
   *
   *
   */

#if DEBUG
  printf("giop:hash_objkey: Key length = %u \n", key->objkey_len );
#endif

  for (i=0; i< key->objkey_len; i++) {
    val += (guint8) key->objkey[i];
  }

  return val;

}

/*
 * Routine to take an object key octet sequence, and length, and ptr to
 * a (null terminated )repository ID string, and store them in the obect key hash.
 *
 * Blindly Inserts even if it does exist, See TODO at top for reason.
 */

static void insert_in_objkey_hash(GHashTable *hash, gchar *obj, guint32 len, gchar *repoid, ior_src_t src) {

  struct giop_object_key objkey_key, *new_objkey_key;
  struct giop_object_val *objkey_val = NULL;

  objkey_key.objkey_len  = len; /*  length  */
  objkey_key.objkey  = obj;	/*  object key octet sequence  */

  /* Look it up to see if it exists */

  objkey_val = (struct giop_object_val *)g_hash_table_lookup(hash, &objkey_key);

  /* CHANGED -- Same reqid, so abandon old entry */

  if (objkey_val) {
    g_hash_table_remove(hash, &objkey_key);
  }

  /* So, passed key should NOT exist in hash at this point.*/

  new_objkey_key = se_alloc(sizeof(struct giop_object_key));
  new_objkey_key->objkey_len = len; /* save it */
  new_objkey_key->objkey = (guint8 *) g_memdup(obj,len);	/* copy from object and allocate ptr */

  objkey_val = se_alloc(sizeof(struct giop_object_val));
  objkey_val->repo_id = g_strdup(repoid); /* duplicate and store Respository ID string */
  objkey_val->src = src; /* where IOR came from */


#if DEBUG
  printf("giop: ******* Inserting Objkey with RepoID = %s and key length = %u into hash  \n",
         objkey_val->repo_id, new_objkey_key->objkey_len);
#endif

  g_hash_table_insert(hash, new_objkey_key, objkey_val);

}



/*
 * convert an ascii char representing a hex value,
 * to a numeric value.
 *
 * returns value, or -1 if problem.
 *
 */

static gint8 hex_char_to_val(guchar c){
  gint8 retval ;

  if (!isxdigit(c)) {
    return -1;
  }
  if (isdigit(c)) {
    retval = c - 48;		/* convert digit */
    return retval;
  }

  c = toupper(c);		/* convert to uppercase */
  if (c >= 'A' && c <= 'F') {
    retval = c - 55;
    return retval;
  }
  else {
    return -1;
  }

}

/*
 * Convert from  stringified IOR of the kind IOR:af4f7e459f....
 * to an IOR octet sequence.
 *
 * User must free buffer.
 *
 * Creates a new tvbuff and call decode_IOR with a NULL tree, just to
 * grab repoid etc for our objkey hash.
 *
 */

static guint32 string_to_IOR(guchar *in, guint32 in_len, guint8 **out){
  gint8 tmpval_lsb;
  gint8 tmpval_msb;
  gint8 tmpval;		/* complete value */
  guint32 i;

  *out = g_new0(guint8, in_len); /* allocate buffer */

  if (*out == NULL) {
    return 0;
  }

  /* skip past IOR:  and convert character pairs to guint8 */

  for (i=4; i<in_len-1; i+=2) {
    if ( isxdigit(in[i]) && isxdigit(in[i+1]) ) { /* hex ? */

      if ( (tmpval_msb = hex_char_to_val(in[i])) < 0 ) {
	g_warning("giop: Invalid value in IOR %i \n", tmpval_msb);

      }

      if ( (tmpval_lsb = hex_char_to_val(in[i+1])) < 0 ) {
	g_warning("giop: Invalid value in IOR %i \n", tmpval_lsb);
      }

      tmpval = tmpval_msb << 4;
      tmpval += tmpval_lsb;
      (*out)[(i-4)/2] = (guint8) tmpval;

    }
    else {
      /* hmm  */
      break;
    }

  }

  return (i-4)/2;		/* length  */

}



/*
 * Simple "get a line" routine, copied from somewhere :)
 *
 */

static int giop_getline(FILE *fp, gchar *line, int maxlen) {

  if (fgets(line,maxlen,fp) == NULL)
    return 0;
  else
    return strlen(line);

}


/*
 * Read a list of stringified IOR's from a named file, convert to IOR's
 * and store in object key hash
 */

static void read_IOR_strings_from_file(const gchar *name, int max_iorlen) {
  guchar *buf;			/* NOTE reused for every line */
  int len;
  int ior_val_len;		/* length after unstringifying. */
  FILE *fp;
  guint8 *out;			/* ptr to unstringified IOR */
  tvbuff_t *tvb;		/* temp tvbuff for dissectin IORs */
  guint32 my_offset = 0;
  gboolean stream_is_big_endian;


  fp = fopen(name,"r");	/* open read only */

  if (fp == NULL) {
    if (errno == EACCES)
      fprintf(stderr, "Error opening file IOR.txt for reading: %s\n",strerror(errno));
    return;
  }

  buf = g_malloc0(max_iorlen+1);	/* input buf */

  while ((len = giop_getline(fp,buf,max_iorlen+1)) > 0) {
    my_offset = 0;		/* reset for every IOR read */

    ior_val_len = string_to_IOR(buf,len,&out);	/* convert */

    if(ior_val_len>0) {

      /* Combination of tvb_new() and tvb_set_real_data().
         Can throw ReportedBoundsError.

         XXX - can it throw an exception in this case?  If so, we
         need to catch it and clean up, but we really shouldn't allow
         it - or "get_CDR_octet()", or "decode_IOR()" - to throw an
         exception. */

      tvb =  tvb_new_real_data(out, ior_val_len, ior_val_len);

      stream_is_big_endian = !get_CDR_octet(tvb,&my_offset);
      decode_IOR(tvb, NULL, NULL, &my_offset, 0, stream_is_big_endian);

      tvb_free(tvb);

    }

    g_free(out);

  }

  fclose(fp);			/* be nice */

  g_free(buf);
}



/*
 * Init routine, setup our request hash stuff, or delete old ref's
 *
 * Cannot setup the module hash here as my init() may not be called before
 * users start registering. So I will move the module_hash stuff to
 * proto_register_giop, as is done with packet-rpc
 *
 *
 *
 * Also, setup our objectkey/repoid hash here.
 *
 */

static void giop_init(void) {


  /*
   * Create objkey/repoid  hash, use my "equal" and "hash" functions.
   *
   */

  if (giop_objkey_hash)
    g_hash_table_destroy(giop_objkey_hash);

  /*
   * Create hash, use my "equal" and "hash" functions.
   *
   */

  giop_objkey_hash = g_hash_table_new(giop_hash_objkey_hash, giop_hash_objkey_equal);

  /*
   * Create complete_reply_hash, use my "equal" and "hash" functions.
   *
   */

  if (giop_complete_reply_hash)
    g_hash_table_destroy(giop_complete_reply_hash);


  /*
   * Create hash, use my "equal" and "hash" functions.
   *
   */

  giop_complete_reply_hash = g_hash_table_new(complete_reply_hash_fn, complete_reply_equal_fn);


  read_IOR_strings_from_file("IOR.txt", 600); /* testing */


}


/*
 * Insert an entry in the GIOP Heuristic User table.
 * Uses a GList.
 * Uses giop_sub_handle_t to wrap giop user info.
 *
 */

void register_giop_user(giop_sub_dissector_t *sub, const gchar *name, int sub_proto) {

  giop_sub_handle_t *subh;

  subh = g_malloc(sizeof (giop_sub_handle_t));

  subh->sub_name = name;
  subh->sub_fn = sub;
  subh->sub_proto = find_protocol_by_id(sub_proto);	/* protocol_t for sub dissectors's proto_register_protocol() */

  giop_sub_list = g_slist_append (giop_sub_list, subh);

}


/*
 * Lookup an object key in our object key hash, and return the corresponding
 * Repo Id.
 *
 */

static gchar * get_repoid_from_objkey(GHashTable *hash, guint8 *obj, guint32 len) {

  struct giop_object_key objkey_key;
  struct giop_object_val *objkey_val = NULL;

  objkey_key.objkey_len  = len; /*  length  */
  objkey_key.objkey  = obj;	/*  object key octet sequence  */

  /* Look it up to see if it exists */

  objkey_val = (struct giop_object_val *)g_hash_table_lookup(hash, &objkey_key);

  if (objkey_val) {
#if DEBUG
    printf("Lookup of object key returns  RepoId = %s \n",objkey_val->repo_id );
#endif
    return objkey_val->repo_id;	/* found  */
  }

#if DEBUG
  printf("FAILED Lookup of object key \n" );
#endif

  return NULL;			/* not  found */
}



/*
 * Extract top level module/interface from repoid
 *
 * eg from -  "IDL:Echo/interface1:1.0"
 * get "Echo"
 *
 * Or, from "IDL:linux.org/Penguin/Teeth:1.0" get
 * get linux.org/Penguin/Teeth
 *
 *
 * User must free returned ptr after use.
 *
 * TODO -- generalize for other Repoid encodings
 */

static gchar * get_modname_from_repoid(gchar *repoid) {

  gchar *modname = NULL;
  gchar *saved_repoid = NULL;
  gchar c = 'a';
  guint8 stop_mod = 0;		/* Index of last character of modname in Repoid  */
  guint8 start_mod = 4;		/* Index where Module name starts in repoid */
  int i;

  saved_repoid = g_strdup(repoid); /* make a copy */

  /* Must start with IDL: , otherwise I get confused */

  if (g_strncasecmp("IDL:",repoid,4))
    return NULL;

  /* Looks like a RepoID to me, so get Module or interface name */

  /* TODO -- put some code here to get Module name */

  for(i=4; c != '\0'; i++) {
    c = repoid[i];
    stop_mod = i;		/* save */
    if (c == ':' )		/* delimiters */
      break;

  }

  /* Now create a new string based on start and stop and \0 */

  modname = g_strndup(repoid+4, stop_mod - start_mod);

  return modname;

}

/*
 * DEBUG CODE
 *
 */


#if DEBUG

/*
 * Display a "module" hash entry
 */

static void display_module_hash(gpointer key, gpointer val, gpointer user_data) {

  struct giop_module_val *mv = (struct giop_module_val *) val;
  struct giop_module_key *mk = (struct giop_module_key *) key;

  printf("giop:module: Key = (%s) , Val = (%s) \n", mk->module, mv->subh->sub_name);

  return;

}

/*
 * Display a "complete_reply " hash entry
 */

static void display_complete_reply_hash(gpointer key, gpointer val, gpointer user_data) {

  struct complete_reply_hash_val *mv = (struct complete_reply_hash_val *) val;
  struct complete_reply_hash_key *mk = (struct complete_reply_hash_key *) key;

  printf("giop:complete_reply: FN (key) = %8u , MFN (val) = %8u \n", mk->fn, mv->mfn);

  return;

}


/*
 * Display an "objkey" hash entry
 */

static void display_objkey_hash(gpointer key, gpointer val, gpointer user_data) {
  guint32 i;
  struct giop_object_val *mv = (struct giop_object_val *) val;
  struct giop_object_key *mk = (struct giop_object_key *) key;


  printf("giop:objkey: Key->objkey_len = %u,  Key->objkey ",  mk->objkey_len);

  for (i=0; i<mk->objkey_len; i++) {
    printf("%.2x ", mk->objkey[i]);
  }

  /*
   * If read from file, mark it as such..
   */

  if(mv->src == 0) {
    printf(", Repo ID = %s \n", mv->repo_id);
  }
  else {
    printf(", Repo ID = %s , (file) \n", mv->repo_id);
  }

  return;

}

/*
 * Display all giop_sub_list (GSList) entries
 */

static void display_heuristic_user_list() {
  int i;
  int len;
  giop_sub_handle_t *subh;	/* handle */

  /* Get length of list */
  len = g_slist_length(giop_sub_list); /* find length */

  if (len == 0)
    return;

  for (i=0; i<len; i++) {
    subh = ( giop_sub_handle_t *) g_slist_nth_data(giop_sub_list,i); /* grab entry */
    printf("giop:heuristic_user: Element = %i, Val (user) = %s \n", i, subh->sub_name);
  }

}

/*
 * Display all complete_request_list (GList) entries
 */

static void display_complete_request_list() {
  int i;
  int len;
  comp_req_list_entry_t *entry;

  /* Get length of list */
  len = g_list_length(giop_complete_request_list); /* find length */

  if (len == 0)
    return;

  for (i=0; i<len; i++) {
    entry = (comp_req_list_entry_t *) g_list_nth_data(giop_complete_request_list,i); /* grab entry */
    printf("giop:Index = %8i , FN = %8i, reqid = %8u , operation = %20s , repoid = %30s \n", i, entry->fn,
	   entry->reqid,entry->operation, entry->repoid);
  }

}




/* Dump Hash/List contents
 *
 * collection_type specifies the list or hash to dump
 *
 */

static void giop_dump_collection(collection_data_t collection_type) {

  switch(collection_type) {
  case cd_heuristic_users:
    printf("+----------------------------------------------+ \n");
    printf("+-------------- Heuristic User (Begin) --------+ \n");
    printf("+----------------------------------------------+ \n");

    display_heuristic_user_list();

    printf("+----------------------------------------------+ \n");
    printf("+-------------- Heuristic User (End) ----------+ \n");
    printf("+----------------------------------------------+ \n");

    break;

  case cd_complete_request_list:
    printf("+----------------------------------------------+ \n");
    printf("+------------- Complete Request List (Begin) --+ \n");
    printf("+----------------------------------------------+ \n");

    display_complete_request_list();

    printf("+----------------------------------------------+ \n");
    printf("+------------ Complete Request List (End) -----+ \n");
    printf("+----------------------------------------------+ \n");

    break;

  case cd_module_hash:
    printf("+----------------------------------------------+ \n");
    printf("+-------------- Module (Begin) ----------------+ \n");
    printf("+----------------------------------------------+ \n");

    g_hash_table_foreach(giop_module_hash, display_module_hash, NULL);

    printf("+----------------------------------------------+ \n");
    printf("+-------------- Module ( End) -----------------+ \n");
    printf("+----------------------------------------------+ \n\n");

    break;

  case cd_objkey_hash:
    printf("+----------------------------------------------+ \n");
    printf("+-------------- Objkey (Begin) ----------------+ \n");
    printf("+----------------------------------------------+ \n");

    g_hash_table_foreach(giop_objkey_hash, display_objkey_hash,NULL);

    printf("+----------------------------------------------+ \n");
    printf("+-------------- Objkey (End) ------------------+ \n");
    printf("+----------------------------------------------+ \n\n");

    break;

  case cd_complete_reply_hash:
    printf("+----------------------------------------------+ \n");
    printf("+-------------- Complete_Reply_Hash (Begin) ---+ \n");
    printf("+----------------------------------------------+ \n");

    g_hash_table_foreach(giop_complete_reply_hash, display_complete_reply_hash, NULL);

    printf("+----------------------------------------------+ \n");
    printf("+------------- Complete_Reply_Hash (End) ------+ \n");
    printf("+----------------------------------------------+ \n");

    break;

  default:

    printf("giop: giop_dump_collection: Unknown type   \n");

  }


}


#endif /* DEBUG */

/*
 * Loop through all  subdissectors, and call them until someone
 * answers (returns TRUE). This function then returns TRUE, otherwise
 * it return FALSE
 *
 * But skip a subdissector if it has been disabled in GUI "edit protocols".
 */

static gboolean try_heuristic_giop_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
		MessageHeader *header, gchar *operation  ) {

  int i,len;
  gboolean res = FALSE;		/* result of calling a heuristic sub dissector */
  giop_sub_handle_t *subh = NULL;
  const char *saved_proto;

  len = g_slist_length(giop_sub_list); /* find length */

  if (len == 0)
    return FALSE;

  saved_proto = pinfo->current_proto;
  for (i=0; i<len; i++) {
    subh = (giop_sub_handle_t *) g_slist_nth_data(giop_sub_list,i); /* grab dissector handle */

    if (proto_is_protocol_enabled(subh->sub_proto)) {
      pinfo->current_proto =
	proto_get_protocol_short_name(subh->sub_proto);
      res = (subh->sub_fn)(tvb,pinfo,tree,offset,header,operation,NULL); /* callit TODO - replace NULL */
      if (res) {
      	pinfo->current_proto = saved_proto;
	return TRUE;		/* found one, lets return */
      }
    } /* protocol_is_enabled */
  } /* loop */

  if (check_col (pinfo->cinfo, COL_PROTOCOL))
      col_set_str (pinfo->cinfo, COL_PROTOCOL, "GIOP");

  pinfo->current_proto = saved_proto;
  return res;			/* result */

}


/*
 * Find the matching repoid in the module hash and call
 * the dissector function if offset exists.
 *
 *
 * Repoid is eg IDL:tux.antarctic/Penguin/Teeth:1.0 but subdissectors
 * will register possibly "tux.antarctic/Penguin" and "tux.antarctic/Penguin/Teeth".
 *
 *
 *
 */

static gboolean try_explicit_giop_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
					    MessageHeader *header, gchar *operation, gchar *repoid ) {

  giop_sub_handle_t *subdiss = NULL; /* handle */
  gboolean res = FALSE;
  gchar *modname = NULL;
  struct giop_module_key module_key;
  struct giop_module_val *module_val = NULL;
  const char *saved_proto;


  /*
   * Get top level module/interface from complete repoid
   */

  modname = get_modname_from_repoid(repoid);
  if (modname == NULL) {
    return res;			/* unknown module name */
  }


  /* Search for Module or interface name */

  module_key.module = modname; /*  module name */
  module_val = (struct giop_module_val *)g_hash_table_lookup(giop_module_hash, &module_key);

  if (module_val == NULL) {
    return res;			/* module not registered */
  }

  subdiss = (giop_sub_handle_t *) module_val->subh; /* grab dissector handle */

  if (subdiss) {
    /* Add giop_sub_handle_t and repoid into complete_request_list, so REPLY can */
    /* look it up directly, later ie: FN -> MFN -> giop_sub_handle_t and repoid */
    /* but only if user not clicking */

    if (!pinfo->fd->flags.visited)
      add_sub_handle_repoid_to_comp_req_list(pinfo->fd->num,subdiss,repoid);


    /* Call subdissector if current offset exists , and dissector is enabled in GUI "edit protocols" */

    if (tvb_offset_exists(tvb, *offset)) {
#if DEBUG
      printf("giop:try_explicit_dissector calling sub = %s with module = (%s) \n", subdiss->sub_name  , modname);
#endif

      if (proto_is_protocol_enabled(subdiss->sub_proto)) {

	saved_proto = pinfo->current_proto;
	pinfo->current_proto =
	  proto_get_protocol_short_name(subdiss->sub_proto);
	res = (subdiss->sub_fn)(tvb,pinfo,tree,offset,header,operation, modname); /* callit, TODO replace NULL with idlname */
	pinfo->current_proto = saved_proto;

      }	/* protocol_is_enabled */
    } /* offset exists */
  } /* subdiss */

  return res;			/* return result */
}



/* Take in an array of char and create a new string.
 * Replace non-printable characters with periods.
 *
 * The array may contain \0's so dont use strdup
 * The string is \0 terminated, and thus longer than
 * the initial sequence.
 * Caller must free the new string.
 */

gchar * make_printable_string (gchar *in, guint32 len) {
  guint32 i = 0;
  gchar *print_string = NULL;

  print_string = (gchar * )g_malloc0(len + 1); /* make some space and zero it */
  memcpy(print_string, in, len);        /* and make a copy of input data */

  for(i=0; i < len; i++) {
    if( !isprint( (unsigned char)print_string[i] ) )
      print_string[i] = '.';
  }

  return print_string;		/* return ptr */
}

/* Determine the byte order from the GIOP MessageHeader */

gboolean is_big_endian (MessageHeader * header) {
  gboolean big_endian = FALSE;

  switch (header->GIOP_version.minor) {
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



/*
 * Calculate new offset, based on the current offset, and user supplied
 * "offset delta" value, and the alignment requirement.
 *
 *
 *
 * eg: Used for GIOP 1.2 where Request and Reply bodies are
 *     aligned on 8 byte boundaries.
 */

static void set_new_alignment(int *offset, int delta, int  alignment) {

  while( ( (*offset + delta) % alignment) != 0)
	  ++(*offset);


}



/*
 * ------------------------------------------------------------------------------------------+
 *                                 Public get_CDR_xxx functions.
 * ------------------------------------------------------------------------------------------+
 */



/*
 * Gets data of type any. This is encoded as a TypeCode
 * followed by the encoded value.
 */

void get_CDR_any(tvbuff_t *tvb, proto_tree *tree, gint *offset,
		 gboolean stream_is_big_endian, int boundary,
		 MessageHeader * header ) {

  guint32  TCKind;    /* TypeCode */

  /* get TypeCode of any */
  TCKind = get_CDR_typeCode(tvb, tree, offset, stream_is_big_endian, boundary, header );

  /* dissect data of type TCKind */
  dissect_data_for_typecode(tvb, tree, offset, stream_is_big_endian, boundary, header, TCKind );
}


/* Copy a 1 octet sequence from the tvbuff
 * which represents a boolean value, and convert
 * it to a boolean value.
 * Offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

gboolean get_CDR_boolean(tvbuff_t *tvb, int *offset) {
  guint8 val;

  val = tvb_get_guint8(tvb, *offset); /* easy */
  (*offset)++;
  return val;
}

/* Copy a 1 octet sequence from the tvbuff
 * which represents a char, and convert
 * it to an char value.
 * offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

guint8 get_CDR_char(tvbuff_t *tvb, int *offset) {
  guint8 val;

  val = tvb_get_guint8(tvb, *offset); /* easy */
  (*offset)++;
  return val;
}



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

gdouble get_CDR_double(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian, int boundary) {

  gdouble val;

  /* double values must be aligned on a 8 byte boundary */

  while( ( (*offset + boundary) % 8) != 0)
	  ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohieee_double (tvb, *offset) :
                                 tvb_get_letohieee_double (tvb, *offset);

  *offset += 8;
  return val;

}


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


guint32 get_CDR_enum(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian, int boundary) {

  return get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary );

}


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


void get_CDR_fixed(tvbuff_t *tvb, gchar **seq, gint *offset, guint32 digits, gint32 scale) {

  guint8 sign;			/* 0x0c is positive, 0x0d is negative */
  guint32 i ;			/* loop */
  guint32 slen;			/* number of bytes to hold digits + extra 0's if scale <0 */
				/* this does not include sign, decimal point and \0 */
  guint32 sindex = 0;		/* string index */
  gchar *tmpbuf;		/* temp buff, holds string without scaling */
  guint8 tval;			/* temp val storage */

  /*
   * how many bytes to hold digits and scale (if scale <0)
   *
   * eg: fixed <5,2> = 5 digits
   *     fixed <5,-2> = 7 digits (5 + 2 added 0's)
   */

#if DEBUG
    printf("giop:get_CDR_fixed() called , digits = %u, scale = %u \n", digits, scale);
#endif

  if (scale <0) {
    slen = digits - scale;	/* allow for digits + padding 0's for negative scal */
  } else {
    slen = digits;		/*  digits */
  }

#if DEBUG
    printf("giop:get_CDR_fixed(): slen =  %.2x \n", slen);
#endif

  tmpbuf = g_new0(gchar, slen);	/* allocate temp buffer */

  /*
   * Register a cleanup function in case on of our tvbuff accesses
   * throws an exception. We need to clean up tmpbuf.
   */
  CLEANUP_PUSH(g_free, tmpbuf);

  /* If even , grab 1st dig */

  if (!(digits & 0x01)) {
    tval = get_CDR_octet(tvb,offset);
#if DEBUG
    printf("giop:get_CDR_fixed():even: octet = %.2x \n", tval);
#endif
    tmpbuf[sindex] = (tval & 0x0f) + 0x30; /* convert top nibble to ascii */
    sindex++;
  }

  /*
   * Loop, but stop BEFORE we hit last digit and sign
   * if digits = 1 or 2, then this part is skipped
   */

  if (digits>2) {
    for(i=0; i< ((digits-1)/2 ); i++) {
      tval = get_CDR_octet(tvb,offset);
#if DEBUG
      printf("giop:get_CDR_fixed():odd: octet = %.2x \n", tval);
#endif

      tmpbuf[sindex] = ((tval & 0xf0) >> 4) + 0x30; /* convert top nibble to ascii */
      sindex++;
      tmpbuf[sindex] = (tval & 0x0f)  + 0x30; /* convert bot nibble to ascii */
      sindex++;

    }
  } /* digits > 3 */

#if DEBUG
    printf("giop:get_CDR_fixed(): before last digit \n");
#endif


  /* Last digit and sign if digits >1, or 1st dig and sign if digits = 1 */

    tval = get_CDR_octet(tvb,offset);
#if DEBUG
    printf("giop:get_CDR_fixed(): octet = %.2x \n", tval);
#endif
    tmpbuf[sindex] = (( tval & 0xf0)>> 4) + 0x30; /* convert top nibble to ascii */
    sindex++;

    sign = tval & 0x0f; /* get sign */

    /* So now, we have all digits in an array, and the sign byte
     * so lets generate a printable string, taking into account the scale
     * and sign values.
     */

    sindex = 0;			        /* reset */
    *seq = g_new0(gchar, slen + 3);	/* allocate temp buffer , including space for sign, decimal point and
					 * \0 -- TODO check slen is reasonable first */
#if DEBUG
    printf("giop:get_CDR_fixed(): sign =  %.2x \n", sign);
#endif

    switch(sign) {
    case 0x0c:
      (*seq)[sindex] = '+';	/* put sign in first string position */
      break;
    case 0x0d:
      (*seq)[sindex] = '-';
      break;
    default:
      g_warning("giop: Unknown sign value in fixed type %u \n", sign);
      (*seq)[sindex] = '*';	/* flag as sign unkown */
      break;
    }

    sindex++;

    /* Add decimal point or padding 0's, depending if scale is positive or
     * negative, respectively
     */

    if (scale>0) {
      for (i=0; i<digits-scale; i++) {
	(*seq)[sindex] = tmpbuf[i]; /* digits to the left of the decimal point */
	sindex++;
      }

      (*seq)[sindex] = '.'; /* decimal point */
      sindex++;

      for (i=digits-scale; i<digits; i++) {
	(*seq)[sindex] = tmpbuf[i]; /* remaining digits to the right of the decimal point */
	sindex++;
      }

      (*seq)[sindex] = '\0'; /* string terminator */

    } else {

      /* negative scale, dump digits and  pad out with 0's */

      for (i=0; i<digits-scale; i++) {
	if (i<digits) {
	  (*seq)[sindex] = tmpbuf[i]; /* save digits */
	} else {
	  (*seq)[sindex] = '0'; /* all digits used up, so pad with 0's */
	}
	sindex++;
      }

      (*seq)[sindex] = '\0'; /* string terminator */

    }

    /*
     * We're done with tmpbuf, so we can call the cleanup handler to free
     * it, and then pop the cleanup handler.
     */
    CLEANUP_CALL_AND_POP;

#if DEBUG
    printf("giop:get_CDR_fixed(): value = %s \n", *seq);
#endif

    return;

}



/*
 * Floating Point Data Type float IEEE 754-1985
 *
 * Copy an 4 octet sequence from the tvbuff
 * which represents a float value, and convert
 * it to a float value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for float values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

gfloat get_CDR_float(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian, int boundary) {

  gfloat val;

  /* float values must be aligned on a 4 byte boundary */

  while( ( (*offset + boundary) % 4) != 0)
    ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohieee_float (tvb, *offset) :
                                 tvb_get_letohieee_float (tvb, *offset);

  *offset += 4;
  return val;

}


/*
 * Decode an Interface type, and display it on the tree.
 */

void get_CDR_interface(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
		       gboolean stream_is_big_endian, int boundary) {


  decode_IOR(tvb, pinfo, tree, offset, boundary, stream_is_big_endian);

  return;
}


/* Copy a 4 octet sequence from the tvbuff
 * which represents a signed long value, and convert
 * it to an signed long vaule, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for long values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

gint32 get_CDR_long(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian, int boundary) {

  gint32 val;

  /* unsigned long values must be aligned on a 4 byte boundary */
  while( ( (*offset + boundary) % 4) != 0)
	  ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohl (tvb, *offset) :
                                 tvb_get_letohl (tvb, *offset);

  *offset += 4;
  return val;
}

/*
 * Decode an Object type, and display it on the tree.
 */

void get_CDR_object(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
                    gboolean stream_is_big_endian, int boundary) {

  decode_IOR(tvb, pinfo, tree, offset, boundary, stream_is_big_endian);

  return;
}


/* Copy a 1 octet sequence from the tvbuff
 * which represents a octet, and convert
 * it to an octet value.
 * offset is then incremented by 1, to indicate the 1 octet which
 * has been processed.
 */

guint8 get_CDR_octet(tvbuff_t *tvb, int *offset) {
  guint8 val;

  val = tvb_get_guint8(tvb, *offset); /* easy */
  (*offset)++;
  return val;
}


/* Copy a sequence of octets from the tvbuff.
 * Caller of this function must remember to free the
 * array pointed to by seq.
 * This function also increments offset by len.
 */

void get_CDR_octet_seq(tvbuff_t *tvb, gchar **seq, int *offset, guint32 len) {

  /*
   * Make sure that the entire sequence of octets is in the buffer before
   * allocating the buffer, so that we don't have to worry about freeing
   * the buffer, and so that we don't try to allocate a buffer bigger
   * than the data we'll actually be copying, and thus don't run the risk
   * of crashing if the buffer is *so* big that we fail to allocate it
   * and "g_new0()" aborts.
   */
  tvb_ensure_bytes_exist(tvb, *offset, len);

  /*
   * XXX - should we just allocate "len" bytes, and have "get_CDR_string()"
   * do what we do now, and null-terminate the string (which also means
   * we don't need to zero out the entire allocation, just the last byte)?
   */
  *seq = g_new0(gchar, len + 1);
  tvb_memcpy( tvb, *seq, *offset, len);
  *offset += len;
}


/* Copy a 2 octet sequence from the tvbuff
 * which represents a signed short value, and convert
 * it to a signed short value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for short values.
 * offset is then incremented by 2, to indicate the 2 octets which
 * have been processed.
 */

gint16 get_CDR_short(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian, int boundary) {

  gint16 val;

  /* short values must be aligned on a 2 byte boundary */
  while( ( (*offset + boundary) % 2) != 0)
	  ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohs (tvb, *offset) :
                                 tvb_get_letohs (tvb, *offset);

  *offset += 2;
  return val;
}



/* Copy an octet sequence from the tvbuff
 * which represents a string, and convert
 * it to an string value, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for string values. (begins with an unsigned long LI)
 *
 * String sequence is copied to a  buffer "seq". This must
 * be freed by the calling program.
 * offset is then incremented, to indicate the  octets which
 * have been processed.
 *
 * returns number of octets in the sequence
 *
 * Note: This function only supports single byte encoding at the
 *       moment until I get a handle on multibyte encoding etc.
 *
 */


guint32 get_CDR_string(tvbuff_t *tvb, gchar **seq, int *offset, gboolean stream_is_big_endian,
		       int boundary ) {

  guint32 slength;

  slength = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary); /* get length first */

#if 0
  (*offset)++;			/* must step past \0 delimiter */
#endif

  if (slength > 0) {
    get_CDR_octet_seq(tvb, seq, offset, slength);
  } else {
    *seq = g_strdup("");	/* zero-length string */
  }

  return slength;		/* return length */

}

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

guint32 get_CDR_typeCode(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			 gboolean stream_is_big_endian, int boundary,
			 MessageHeader * header ) {
  guint32 val;

  gint16  s_octet2; /* signed int16 */
  guint16 u_octet2; /* unsigned int16 */
  guint32 u_octet4; /* unsigned int32 */

  val = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary); /* get TCKind enum */
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_TCKind,tvb,
			*offset-sizeof(val),4,val);
  }

  /* Grab the data according to Typecode Table - Corba Chapter 15 */

  switch (val) {
  case tk_null: /* empty parameter list */
    break;
  case tk_void: /* empty parameter list */
    break;
  case tk_short: /* empty parameter list */
    break;
  case tk_long: /* empty parameter list */
    break;
  case tk_ushort: /* empty parameter list */
    break;
  case tk_ulong: /* empty parameter list */
    break;
  case tk_float: /* empty parameter list */
    break;
  case tk_double: /* empty parameter list */
    break;
  case tk_boolean: /* empty parameter list */
    break;
  case tk_char: /* empty parameter list */
    break;
  case tk_octet: /* empty parameter list */
    break;
  case tk_any: /* empty parameter list */
    break;
  case tk_TypeCode: /* empty parameter list */
    break;
  case tk_Principal: /* empty parameter list */
    break;
  case tk_objref: /* complex parameter list */
    dissect_tk_objref_params(tvb, tree, offset, stream_is_big_endian, boundary);
    break;
  case tk_struct: /* complex parameter list */
    dissect_tk_struct_params(tvb, tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_union: /* complex parameter list */
    dissect_tk_union_params(tvb, tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_enum: /* complex parameter list */
    dissect_tk_enum_params(tvb, tree, offset, stream_is_big_endian, boundary);
    break;

  case tk_string: /* simple parameter list */
    u_octet4 = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary); /* get maximum length */
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_typecode_max_length,tvb,
			  *offset-sizeof(u_octet4),4,u_octet4);
    }
    break;

  case tk_sequence: /* complex parameter list */
    dissect_tk_sequence_params(tvb, tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_array: /* complex parameter list */
    dissect_tk_array_params(tvb, tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_alias: /* complex parameter list */
    dissect_tk_alias_params(tvb, tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_except: /* complex parameter list */
    dissect_tk_except_params(tvb, tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_longlong: /* empty parameter list */
    break;
  case tk_ulonglong: /* empty parameter list */
    break;
  case tk_longdouble: /* empty parameter list */
    break;
  case tk_wchar: /* empty parameter list */
    break;
  case tk_wstring: /* simple parameter list */
    u_octet4 = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary); /* get maximum length */
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_typecode_max_length,tvb,
			  *offset-sizeof(u_octet4),4,u_octet4);
    }
    break;

  case tk_fixed: /* simple parameter list */
    u_octet2 = get_CDR_ushort(tvb,offset,stream_is_big_endian,boundary); /* get digits */
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_typecode_digits,tvb,
			  *offset-sizeof(u_octet2),2,u_octet2);
    }

    s_octet2 = get_CDR_short(tvb,offset,stream_is_big_endian,boundary); /* get scale */
    if (tree) {
      proto_tree_add_int(tree,hf_giop_typecode_scale,tvb,
			  *offset-sizeof(s_octet2),2,s_octet2);
    }
    break;

  case tk_value: /* complex parameter list */
    dissect_tk_value_params(tvb, tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_value_box: /* complex parameter list */
    dissect_tk_value_box_params(tvb, tree, offset, stream_is_big_endian, boundary, header );
    break;
  case tk_native: /* complex parameter list */
    dissect_tk_native_params(tvb, tree, offset, stream_is_big_endian, boundary);
    break;
  case tk_abstract_interface: /* complex parameter list */
    dissect_tk_abstract_interface_params(tvb, tree, offset, stream_is_big_endian, boundary );
    break;
  default:
    g_warning("giop: Unknown TCKind %u \n", val);
    break;
  } /* val */

  return val;
}



/* Copy a 4 octet sequence from the tvbuff
 * which represents an unsigned long value, and convert
 * it to an unsigned long vaule, taking into account byte order.
 * offset is first incremented so that it falls on a proper alignment
 * boundary for unsigned long values.
 * offset is then incremented by 4, to indicate the 4 octets which
 * have been processed.
 */

guint32 get_CDR_ulong(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian, int boundary) {

  guint32 val;

  /* unsigned long values must be aligned on a 4 byte boundary */
  while( ( (*offset + boundary) % 4) != 0)
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

guint16 get_CDR_ushort(tvbuff_t *tvb, int *offset, gboolean stream_is_big_endian, int boundary) {

  guint16 val;

  /* unsigned short values must be aligned on a 2 byte boundary */
  while( ( (*offset + boundary) % 2) != 0)
	  ++(*offset);

  val = (stream_is_big_endian) ? tvb_get_ntohs (tvb, *offset) :
                                 tvb_get_letohs (tvb, *offset);

  *offset += 2;
  return val;
}



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
 * really reads past the wchar and sets the offset
 * correctly.
 */

/* The "decoding" is done according to CORBA chapter 15.
 * Wchar is not supported for GIOP 1.0.
 */

gint get_CDR_wchar(tvbuff_t *tvb, gchar **seq, int *offset, MessageHeader * header) {

  gint slength;
  gchar *raw_wstring;

  /* CORBA chapter 15:
   *   - prior to GIOP 1.2 wchar limited to two octet fixed length.
   *   - GIOP 1.2 wchar is encoded as an unsigned binary octet
   *     followed by the elements of the octet sequence representing
   *     the encoded value of the wchar.
   */

  *seq = NULL; /* set in case GIOP 1.2 length is 0 */
  slength = 2; /* set for GIOP 1.1 length in octets */

  if (header->GIOP_version.minor > 1) /* if GIOP 1.2 get length of wchar */
    slength = get_CDR_octet(tvb,offset);

  if (slength > 0) {
    /* ??? assume alignment is ok for GIOP 1.1 ??? */
    get_CDR_octet_seq(tvb, &raw_wstring, offset, slength);

    /* now turn octets (wchar) into something that can be printed by the user */
    *seq = make_printable_string(raw_wstring, slength);

    g_free(raw_wstring);
  }

  /* if GIOP 1.1 negate length to indicate not an item to add to tree */
  if (header->GIOP_version.minor < 2)
    slength = -slength;

  return slength;		/* return length */

}


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
 * really reads past the wstring and sets the offset
 * correctly.
 */

/* The "decoding" is done according to CORBA chapter 15.
 * Wstring is not supported for GIOP 1.0.
 */


guint32 get_CDR_wstring(tvbuff_t *tvb, gchar **seq, int *offset, gboolean stream_is_big_endian,
		       int boundary, MessageHeader * header) {

  guint32 slength;
  gchar *raw_wstring;

  /* CORBA chapter 15:
   *   - prior to GIOP 1.2 wstring limited to two octet fixed length.
   *     length and string are NUL terminated (length???).
   *   - GIOP 1.2 length is total number of octets. wstring is NOT NUL
   *     terminated.
   */

  *seq = NULL; /* set in case GIOP 1.2 length is 0 */

  /* get length, same for all GIOP versions,
   * although for 1.2 CORBA doesnt say, so assume.
   */
  slength = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);

#ifdef DEBUG
  if (slength>200) {
        fprintf(stderr, "giop:get_CDR_wstring, length %u > 200, truncating to 5 \n", slength);
	slength = 5;		/* better than core dumping during debug */
  }
#endif

  if (header->GIOP_version.minor < 2) {
#if 0
    (*offset)++;  /* must step past \0 delimiter */
#endif
    /* assume length is number of characters and not octets, spec not clear */
    slength = slength * 2; /* length in octets is 2 * wstring length */
  }

  if (slength > 0) {
    get_CDR_octet_seq(tvb, &raw_wstring, offset, slength);

    /* now turn octets (wstring) into something that can be printed by the user */
    *seq = make_printable_string(raw_wstring, slength);

    g_free(raw_wstring);
  }

  return slength;		/* return length */

}



/**
 *  Dissects a TargetAddress which is defined in (CORBA 2.4, section 15.4.2)
 *  GIOP 1.2
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
dissect_target_address(tvbuff_t * tvb, packet_info *pinfo, int *offset, proto_tree * tree,
		       gboolean stream_is_big_endian)
{
   guint16 discriminant;
   gchar *object_key;
   gchar *p_object_key;
   guint32 len = 0;
   guint32 u_octet4;

   discriminant = get_CDR_ushort(tvb, offset, stream_is_big_endian,GIOP_HEADER_SIZE);
   if(tree)
   {
     proto_tree_add_text (tree, tvb, *offset -2, 2,
                 "TargetAddress Discriminant: %u", discriminant);
   }

   switch (discriminant)
   {
	   case 0:  /* KeyAddr */
		   len = get_CDR_ulong(tvb, offset, stream_is_big_endian,GIOP_HEADER_SIZE);
		   if(tree)
		   {
                      proto_tree_add_text (tree, tvb, *offset -4, 4,
			                   "KeyAddr (object key length): %u", len);
		   }

		   if (len > 0) {

		     get_CDR_octet_seq(tvb, &object_key, offset, len);
		     p_object_key = make_printable_string( object_key, len );

		     if(tree)
		       {
			 proto_tree_add_text (tree, tvb, *offset -len, len,
					       "KeyAddr (object key): %s", p_object_key);
		       }
		     g_free( p_object_key );
		     g_free( object_key );
		   }
		   break;
           case 1: /* ProfileAddr */
		   decode_TaggedProfile(tvb, pinfo, tree, offset, GIOP_HEADER_SIZE,
					stream_is_big_endian, NULL);
		   break;
           case 2: /* ReferenceAddr */
		   u_octet4 = get_CDR_ulong(tvb, offset, stream_is_big_endian,GIOP_HEADER_SIZE);

		   if(tree)
		   {
                      proto_tree_add_text (tree, tvb, *offset -len -4, 4,
			                   "ReferenceAddr (selected_profile_index): %u", u_octet4);
		   }

		   decode_IOR(tvb, pinfo, tree, offset, GIOP_HEADER_SIZE, stream_is_big_endian);
		   break;
	   default:
		   break;
   }
}

static void
dissect_reply_body (tvbuff_t *tvb, guint offset, packet_info *pinfo,
		    proto_tree *tree, gboolean stream_is_big_endian,
		    guint32 reply_status, MessageHeader *header, proto_tree *clnp_tree) {

  guint sequence_length;
  gboolean exres = FALSE;		/* result of trying explicit dissectors */
  gchar * repoid = NULL;	/* Repositor ID looked up from  objkey */

  /*
   * comp_req_list stuff
   */

  comp_req_list_entry_t * entry = NULL; /* data element in our list */

  guint32 mfn;

  switch (reply_status)
    {
    case SYSTEM_EXCEPTION:

      decode_SystemExceptionReplyBody (tvb, tree, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
      break;

    case USER_EXCEPTION:

      sequence_length = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);

      if (tree)
      {
	  proto_tree_add_text(tree, tvb, offset-4, 4,
			   "Exception length: %u", sequence_length);
      }
      if (sequence_length != 0 && sequence_length < ITEM_LABEL_LENGTH)
	{
#if 1

          tvb_ensure_bytes_exist(tvb, offset, sequence_length);
          header->exception_id = g_new0(gchar,sequence_length ); /* allocate buffer */

          /* read exception id from buffer and store in*/

          tvb_get_nstringz0(tvb,offset,sequence_length, header->exception_id );

          if (tree)
          {
	      proto_tree_add_string(tree, hf_giop_exception_id, tvb,
			   offset, sequence_length, header->exception_id);
          }

#endif


	  offset += sequence_length;
	}



      /*
       * Now just fall through to the NO_EXCEPTION part
       * as this is common .
       */



    case NO_EXCEPTION:


      /* lookup MFN in hash directly */

      mfn = get_mfn_from_fn(pinfo->fd->num);

      if (mfn == pinfo->fd->num)
	return;			/* no matching frame number, what am I */

      /* get entry for this MFN */
      entry = find_fn_in_list(mfn); /* get data entry in complete_request_list */

      if (!entry)
	return;			/* no matching entry */


      /*
       * If this packet is a REPLY to a RESOLVE(request)
       * then decode IOR.
       * TODO - make this lookup faster -- FS
       */

      if (!strcmp(giop_op_resolve,entry->operation)) {
	decode_IOR(tvb, pinfo, tree, &offset, GIOP_HEADER_SIZE,stream_is_big_endian);
	return;		/* done */
      }

      /* TODO -- Put stuff here for other "interesting operations" */

      /*
       *
       * Call sub dissector.
       * First try an find a explicit sub_dissector, then if that
       * fails, try the heuristic method.
       */


      if(entry->repoid) {
	exres = try_explicit_giop_dissector(tvb,pinfo,clnp_tree, &offset, header, entry->operation, entry->repoid );
      }

      /* Only call heuristic if no explicit dissector was found */

      if(! exres) {
	exres = try_heuristic_giop_dissector(tvb,pinfo,clnp_tree,&offset,header,entry->operation);
      }

      if (!exres && !strcmp(giop_op_is_a, entry->operation) && tree) {
		  proto_tree_add_text(tree, tvb, offset - 1, 1, "Type Id%s matched",
			    get_CDR_boolean(tvb, &offset) ? "" : " not");
      }

      if(! exres) {
        gint stub_length = tvb_reported_length_remaining(tvb, offset);
		if (stub_length >0)
			proto_tree_add_text(tree, tvb, offset, -1,
                                 "Stub data (%d byte%s)", stub_length,
                                 plurality(stub_length, "", "s"));
      }

      break;

    case LOCATION_FORWARD:
      decode_IOR(tvb, pinfo, tree, &offset, GIOP_HEADER_SIZE, stream_is_big_endian);

      break;

    case LOCATION_FORWARD_PERM:
      decode_IOR(tvb, pinfo, tree, &offset, GIOP_HEADER_SIZE, stream_is_big_endian);

      break;

    case NEEDS_ADDRESSING_MODE: {
      guint16 addr_disp;
      addr_disp = get_CDR_ushort(tvb, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
      if(tree) {
        proto_tree_add_text (tree, tvb, offset -2, 2,
			     "AddressingDisposition: %u", addr_disp);
      }

      break;
    }

    default:

      g_warning("giop: Unknown reply status %i request_id = %u\n",reply_status, header->req_id);

      break;

    } /* switch */

  g_free(repoid);		/* free resource */

  return;			/* done */

}





/* The format of the Reply Header for GIOP 1.0 and 1.1
 * is documented in Section 15.4.3.1 of the CORBA 2.4 standard.

    struct ReplyHeader_1_0 {
          IOP::ServiceContextList service_context;
          unsigned long request_id;
          ReplyStatusType_1_0 reply_status;
    };
 */

static void dissect_giop_reply (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
				MessageHeader * header,
				gboolean stream_is_big_endian) {

  guint32 offset = 0;
  guint32 request_id;
  guint32 reply_status;
  proto_tree *reply_tree = NULL;
  proto_item *tf;
  guint32 mfn;			/* matching frame number */

  if (tree) {
    tf = proto_tree_add_text (tree, tvb, offset, -1,
			      "General Inter-ORB Protocol Reply");
    if (reply_tree == NULL)
      {
	reply_tree = proto_item_add_subtree (tf, ett_giop_reply);

      }
  }

  /*
   * Decode IOP::ServiceContextList
   */

  decode_ServiceContextList(tvb, reply_tree, &offset,stream_is_big_endian, GIOP_HEADER_SIZE);

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " %u", request_id);
  }

  if (tree) {
    proto_tree_add_uint(reply_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);
  }

  reply_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                    val_to_str(reply_status, reply_status_types, "Unknown (%u)"));

  }

  if (tree) {
    proto_tree_add_uint(reply_tree, hf_giop_reply_status, tvb,
                         offset-4, 4, reply_status);

  }

  /*
   * Save FN and MFN in complete_reply_hash, only if user is NOT clicking
   */

  if (! pinfo->fd->flags.visited) {
    mfn = get_mfn_from_fn_and_reqid(pinfo->fd->num,request_id);	/* find MFN for this FN */
    if (mfn != pinfo->fd->num) { /* if mfn is not fn, good */
      insert_in_complete_reply_hash(pinfo->fd->num, mfn);
    }
  }

  header->req_id = request_id;	        /* save for sub dissector */
  header->rep_status = reply_status;   /* save for sub dissector */

  /* Do we have a body */
  if (tvb_reported_length_remaining(tvb, offset))
	  dissect_reply_body(tvb, offset, pinfo, reply_tree, stream_is_big_endian,
			reply_status, header,tree);


}

/** The format of the GIOP 1.2 Reply header is very similar to the 1.0
 *  and 1.1 header, only the fields have been rearranged.  From Section
 *  15.4.3.1 of the CORBA 2.4 specification:
 *
 *   struct ReplyHeader_1_2 {
 *         unsigned long request_id;
 *         ReplyStatusType_1_2 reply_status;
 *         IOP:ServiceContextList service_context;
 *    };
 */

static void dissect_giop_reply_1_2 (tvbuff_t * tvb, packet_info * pinfo,
				    proto_tree * tree,
				    MessageHeader * header,
				    gboolean stream_is_big_endian) {

  guint offset = 0;
  guint32 request_id;
  guint32 reply_status;
  proto_tree *reply_tree = NULL;
  proto_item *tf;
  guint32 mfn;			/* matching frame number */

  if (tree) {
    tf = proto_tree_add_text (tree, tvb, offset, -1,
			      "General Inter-ORB Protocol Reply");
    reply_tree = proto_item_add_subtree (tf, ett_giop_reply);
  }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " %u", request_id);
  }

  if (tree) {
    proto_tree_add_uint (reply_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);
  }

  reply_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                    val_to_str(reply_status, reply_status_types, "Unknown (%u)"));

  }

  if (tree) {
    proto_tree_add_uint(reply_tree, hf_giop_reply_status, tvb,
                         offset-4, 4, reply_status);
  }

  /*
   * Decode IOP::ServiceContextList
   */

  decode_ServiceContextList(tvb, reply_tree, &offset,stream_is_big_endian, GIOP_HEADER_SIZE);

  /*
   * GIOP 1.2 Reply body must fall on an 8 octet alignment.
   */

  set_new_alignment(&offset, GIOP_HEADER_SIZE, 8);

  /*
   * Save FN and MFN in complete_reply_hash, only if user is NOT clicking
   */

  if (! pinfo->fd->flags.visited) {
    mfn = get_mfn_from_fn_and_reqid(pinfo->fd->num,request_id);	/* find MFN for this FN */
    if (mfn != pinfo->fd->num) { /* if mfn is not fn, good */
      insert_in_complete_reply_hash(pinfo->fd->num, mfn);
    }
  }

  /*
   * Add header to argument list so sub dissector can get header info.
   */

  header->req_id = request_id;	        /* save for sub dissector */
  header->rep_status = reply_status;   /* save for sub dissector */

  dissect_reply_body(tvb, offset, pinfo, reply_tree, stream_is_big_endian,
		     reply_status,header,tree);

}



static void dissect_giop_cancel_request (tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree,
			gboolean stream_is_big_endian) {

  guint offset = 0;
  guint32 request_id;
  proto_tree *cancel_request_tree = NULL;
  proto_item *tf;

  if (tree) {
    tf = proto_tree_add_text (tree, tvb, offset, -1,
			      "General Inter-ORB Protocol CancelRequest");
    cancel_request_tree = proto_item_add_subtree (tf, ett_giop_cancel_request);
  }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " %u", request_id);
  }

  if (tree) {
    proto_tree_add_uint (cancel_request_tree,hf_giop_req_id, tvb, offset-4, 4,  request_id);
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
			proto_tree * tree,
			MessageHeader * header, gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  guint32 len = 0;

  guint32 objkey_len = 0;	/* object key length */
  gchar *objkey = NULL;		/* object key sequence */
  gchar *print_objkey;		/* printable object key sequence */
  gboolean exres = FALSE;	/* result of trying explicit dissectors */

  gchar *operation;
  gchar *requesting_principal;
  gchar *print_requesting_principal;
  guint8 response_expected;
  gchar *reserved;
  proto_tree *request_tree = NULL;
  proto_item *tf;

  gchar *repoid = NULL;		/* from object key lookup in objkey hash */


  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset, -1,
				"General Inter-ORB Protocol Request");
      if (request_tree == NULL)
	{
	  request_tree = proto_item_add_subtree (tf, ett_giop_request);

	}
    }



  /*
   * Decode IOP::ServiceContextList
   */

  decode_ServiceContextList(tvb, request_tree, &offset,stream_is_big_endian, 0);


  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %u", request_id);
    }
  if (tree)
    {
      proto_tree_add_uint (request_tree,hf_giop_req_id, tvb, offset-4, 4,  request_id);
    }

  response_expected = tvb_get_guint8( tvb, offset );
  offset += 1;
  if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
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
     g_free(reserved);
  }



  /* Length of object_key sequence */
  objkey_len = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);


  if(tree)
  {
         proto_tree_add_text (request_tree, tvb, offset-4, 4,
         /**/                 "Object Key length: %u", objkey_len);
  }

  if (objkey_len > 0)
  {
       get_CDR_octet_seq(tvb, &objkey, &offset, objkey_len);

       print_objkey = make_printable_string(objkey, objkey_len);

       if(tree)
       {
         proto_tree_add_text (request_tree, tvb, offset - objkey_len, objkey_len,
         /**/                 "Object Key: %s", print_objkey);

       }

       g_free( print_objkey );
  }

  /*
   * Register a cleanup function in case on of our tvbuff accesses
   * throws an exception. We need to clean up objkey.
   */
  CLEANUP_PUSH(g_free, objkey);

  /* length of operation string and string */
  len = get_CDR_string(tvb, &operation, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if(tree)
  {
         proto_tree_add_text (request_tree, tvb, offset - 4 - len, 4,
         /**/                 "Operation length: %u", len);
  }

  if( len > 0)
  {
       if (check_col(pinfo->cinfo, COL_INFO))
       {
         col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", operation);
       }
       if(tree)
       {
         proto_tree_add_string (request_tree, hf_giop_req_operation,tvb, offset - len, len, operation);

       }
  }

  /*
   * Register a cleanup function in case on of our tvbuff accesses
   * throws an exception. We need to clean up operation.
   */
  CLEANUP_PUSH(g_free, operation);

  /* length of requesting_principal string */
  len = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if(tree)
  {
         proto_tree_add_text (request_tree, tvb, offset-4, 4,
         /**/                 "Requesting Principal Length: %u", len);
  }

  if( len > 0)
  {
       get_CDR_octet_seq(tvb, &requesting_principal, &offset, len);

       print_requesting_principal = make_printable_string(requesting_principal, len);

       if(tree)
       {
         proto_tree_add_text (request_tree, tvb, offset - len, len,
         /**/                 "Requesting Principal: %s", print_requesting_principal);

       }

       g_free( print_requesting_principal );
       g_free( requesting_principal );
  }


  /*
   * Save FN,reqid,and operation for later. Add sub_handle later.
   * But only if user is NOT clicking.
   */

  if (! pinfo->fd->flags.visited)
    giop_complete_request_list = insert_in_comp_req_list(giop_complete_request_list,pinfo->fd->num,
							 request_id,operation,NULL);


  /*
   * Call subdissector here before freeing "operation" and "key"
   * pass request_id also.
   * First try an find an explicit sub_dissector, then if that
   * fails, try the heuristic method.
   *
   */


  header->req_id = request_id;	        /* save for sub dissector */
  repoid = get_repoid_from_objkey(giop_objkey_hash,objkey,objkey_len);


  if(repoid) {
    exres = try_explicit_giop_dissector(tvb,pinfo,tree,&offset,header,operation,repoid);
  }

  /* Only call heuristic if no explicit dissector was found */

  if (! exres) {
    exres = try_heuristic_giop_dissector(tvb,pinfo,tree,&offset,header,operation);
  }

  if (!exres && !strcmp(giop_op_is_a, operation) && request_tree) {
    gchar *type_id;
    len = get_CDR_string(tvb, &type_id, &offset, stream_is_big_endian, 0);
    proto_tree_add_text(request_tree, tvb, offset - len - 4, 4,
			"Type Id length: %d", len);
    proto_tree_add_text(request_tree, tvb, offset - len, len,
			"Type Id: %s", type_id);
  }

  if(! exres) {
    gint stub_length = tvb_reported_length_remaining(tvb, offset);
	if (stub_length >0)
		proto_tree_add_text(request_tree, tvb, offset, -1,
			"Stub data (%d byte%s)", stub_length,
			plurality(stub_length, "", "s"));
  }

  /*
   * We're done with operation, so we can call the cleanup handler to free
   * it, and then pop the cleanup handler.
   */
  CLEANUP_CALL_AND_POP;

  /*
   * We're done with objkey, so we can call the cleanup handler to free
   * it, and then pop the cleanup handler.
   */
  CLEANUP_CALL_AND_POP;

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
			proto_tree * tree,
			MessageHeader * header, gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  guint32 len = 0;
  guint8 response_flags;
  gchar *reserved;
  gchar *operation = NULL;
  proto_tree *request_tree = NULL;
  proto_item *tf;
  gboolean exres = FALSE;		/* result of trying explicit dissectors */

  gchar *repoid = NULL;


  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset, -1,
				"General Inter-ORB Protocol Request");
      request_tree = proto_item_add_subtree (tf, ett_giop_reply);
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %u", request_id);
    }
  if (request_tree)
    {
      proto_tree_add_uint (request_tree, hf_giop_req_id, tvb, offset-4, 4, request_id);
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
  g_free(reserved);

  dissect_target_address(tvb, pinfo, &offset, request_tree, stream_is_big_endian);

  /* length of operation string */
  len = get_CDR_string(tvb, &operation, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if(tree)
  {
         proto_tree_add_text (request_tree, tvb, offset - len - 4, 4,
         /**/                 "Operation length: %u", len);
  }

  if( len > 0)
  {
       if (check_col(pinfo->cinfo, COL_INFO))
       {
         col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", operation);
       }
       if(request_tree)
       {
         proto_tree_add_string (request_tree,hf_giop_req_operation, tvb, offset - len, len, operation);

       }

  }

  /*
   * Register a cleanup function in case on of our tvbuff accesses
   * throws an exception. We need to clean up operation.
   */
  CLEANUP_PUSH(g_free, operation);

  /*
   * Decode IOP::ServiceContextList
   */

  decode_ServiceContextList(tvb, request_tree, &offset,  stream_is_big_endian, GIOP_HEADER_SIZE);

  /*
   * GIOP 1.2 Request body must fall on an 8 octet alignment, taking into
   * account we are in a new tvbuff, GIOP_HEADER_SIZE octets from the
   * GIOP octet stream start.
   */

  set_new_alignment(&offset, GIOP_HEADER_SIZE, 8);

  /*
   * Save FN,reqid,and operation for later. Add sub_handle later.
   * But only if user is NOT clicking.
   */

  if (! pinfo->fd->flags.visited)
    giop_complete_request_list = insert_in_comp_req_list(giop_complete_request_list,pinfo->fd->num,
							 request_id,operation,NULL);

  /*
   *
   * Call sub dissector.
   * First try an find a explicit sub_dissector, then if that
   * fails, try the heuristic method.
   */


  if(repoid) {
    exres = try_explicit_giop_dissector(tvb,pinfo,tree,&offset,header,operation,repoid);
  }

  /* Only call heuristic if no explicit dissector was found */

  if (! exres) {
    exres = try_heuristic_giop_dissector(tvb,pinfo,tree,&offset,header,operation);
  }

  if (!exres && !strcmp(giop_op_is_a, operation) && request_tree) {
    gchar *type_id;
    len = get_CDR_string(tvb, &type_id, &offset, stream_is_big_endian, 0);
    proto_tree_add_text(request_tree, tvb, offset - len - 4, 4,
			"Type Id length: %d", len);
    proto_tree_add_text(request_tree, tvb, offset - len, len,
			"Type Id: %s", type_id);
  }

  if(! exres) {
    gint stub_length = tvb_reported_length_remaining(tvb, offset);
	if (stub_length >0)
		proto_tree_add_text(request_tree, tvb, offset, -1,
			"Stub data (%d byte%s)", stub_length,
			plurality(stub_length, "", "s"));
  }

  /*
   * We're done with operation, so we can call the cleanup handler to free
   * it, and then pop the cleanup handler.
   */
  CLEANUP_CALL_AND_POP;
}

static void
dissect_giop_locate_request( tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree, MessageHeader * header,
			gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  guint32 len = 0;
  gchar *object_key;
  gchar *p_object_key;
  proto_tree *locate_request_tree = NULL;
  proto_item *tf;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset, -1,
				"General Inter-ORB Locate Request");
      if (locate_request_tree == NULL)
	{
	  locate_request_tree = proto_item_add_subtree (tf, ett_giop_locate_request);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %u", request_id);
    }
  if (locate_request_tree)
    {
      proto_tree_add_text (locate_request_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

  if(header->GIOP_version.minor < 2)
  {
        len = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
	if (locate_request_tree)
	  {
	    proto_tree_add_text (locate_request_tree, tvb, offset-4, 4,
				 "Object Key length: %u", len);
	  }

	if (len > 0) {
	  get_CDR_octet_seq(tvb, &object_key, &offset, len);

	  p_object_key = make_printable_string(object_key, len);

	  if(locate_request_tree)
	    {

	      proto_tree_add_text (locate_request_tree, tvb, offset-len, len,
				   "Object Key: %s", p_object_key);
	    }

	  g_free(p_object_key);
	  g_free(object_key);
	}
  }
  else     /* GIOP 1.2 and higher */
  {
      dissect_target_address(tvb, pinfo, &offset, locate_request_tree,
			     stream_is_big_endian);

  }
}

static void
dissect_giop_locate_reply( tvbuff_t * tvb, packet_info * pinfo,
			proto_tree * tree, MessageHeader * header,
			gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  guint32 locate_status;
  guint16 addr_disp;

  proto_tree *locate_reply_tree = NULL;
  proto_item *tf;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset, -1,
				"General Inter-ORB Locate Reply");
      if (locate_reply_tree == NULL)
	{
	  locate_reply_tree = proto_item_add_subtree (tf, ett_giop_locate_reply);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %u", request_id);
    }
  if (locate_reply_tree)
    {
      proto_tree_add_text (locate_reply_tree, tvb, offset-4, 4,
			   "Request id: %u", request_id);
    }

  locate_status = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if (locate_reply_tree)
    {
      proto_tree_add_text (locate_reply_tree, tvb, offset-4, 4,
			   "Locate status: %s",
			   match_strval(locate_status, giop_locate_status_types)
			   );
    }

  /* Decode the LocateReply body.
   *
   * For GIOP 1.0 and 1.1 body immediately follows header.
   * For GIOP 1.2 it is aligned on 8 octet boundary so need to
   * spin up.
   */

  if (header->GIOP_version.minor > 1) {
    while( ( (offset + GIOP_HEADER_SIZE) % 8) != 0)
      ++(offset);
  }

  switch(locate_status) {
  case OBJECT_FORWARD: /* fall through to OBJECT_FORWARD_PERM */
  case OBJECT_FORWARD_PERM:
    decode_IOR(tvb, pinfo, locate_reply_tree, &offset, GIOP_HEADER_SIZE, stream_is_big_endian);
    break;
  case LOC_SYSTEM_EXCEPTION:
    decode_SystemExceptionReplyBody (tvb, tree, &offset, stream_is_big_endian, GIOP_HEADER_SIZE);
    break;
  case LOC_NEEDS_ADDRESSING_MODE:
    addr_disp = get_CDR_ushort(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
    if(locate_reply_tree) {
      proto_tree_add_text (tree, tvb, offset -2, 2,
			   "AddressingDisposition: %u", addr_disp);
    }
    break;
  default: /* others have no reply body */
    break;
  }

}

static void
dissect_giop_fragment( tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree,
			gboolean stream_is_big_endian)
{
  guint32 offset = 0;
  guint32 request_id;
  proto_tree *fragment_tree = NULL;
  proto_item *tf;

  if (tree)
    {
      tf = proto_tree_add_text (tree, tvb, offset, -1,
				"General Inter-ORB Fragment");
      if (fragment_tree == NULL)
	{
	  fragment_tree = proto_item_add_subtree (tf, ett_giop_fragment);

	}
    }

  request_id = get_CDR_ulong(tvb, &offset, stream_is_big_endian,GIOP_HEADER_SIZE);
  if (check_col(pinfo->cinfo, COL_INFO))
    {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %u", request_id);
    }
  if (fragment_tree )
    {
      proto_tree_add_uint (fragment_tree, hf_giop_req_id, tvb, offset-4, 4,request_id);
    }

}


/* Main entry point */

static void dissect_giop_common (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {
  guint offset = 0;
  MessageHeader header;
  tvbuff_t *giop_header_tvb;
  tvbuff_t *payload_tvb;

  proto_tree *clnp_tree = NULL;
  proto_item *ti;
  guint message_size;
  guint minor_version;
  gboolean stream_is_big_endian;


  /* DEBUG */

#if DEBUG
  giop_dump_collection(cd_module_hash);
  giop_dump_collection(cd_objkey_hash);
  giop_dump_collection(cd_heuristic_users);
  giop_dump_collection(cd_complete_reply_hash);
  giop_dump_collection(cd_complete_request_list);
#endif

  header.exception_id = NULL;

  giop_header_tvb = tvb_new_subset (tvb, 0, GIOP_HEADER_SIZE, -1);
  payload_tvb = tvb_new_subset (tvb, GIOP_HEADER_SIZE, -1, -1);

  /*
   * because I have added extra elements in MessageHeader struct
   * for sub dissectors. -- FS
   */

  tvb_memcpy (giop_header_tvb, (guint8 *)&header, 0, GIOP_HEADER_SIZE );


  if (check_col (pinfo->cinfo, COL_PROTOCOL))
    {
      col_set_str (pinfo->cinfo, COL_PROTOCOL, "GIOP");
    }

  if (header.GIOP_version.major != GIOP_MAJOR ||
      ((minor_version = header.GIOP_version.minor) > GIOP_MINOR))
    {
      /* Bad version number; should we note that and dissect the rest
         as data, or should this be done outside dissect_giop_common()
         (which is called as the PDU dissector for GIOP-over-TCP,
         so it can't return anything), with the test returning FALSE
         on the theory that it might have been some other packet that
         happened to begin with "GIOP"?  We do the former, for now.
         If we should return FALSE, we should do so *without* setting
         the "Info" column, *without* setting the "Protocol" column,
         and *without* adding anything to the protocol tree. */

      if (check_col (pinfo->cinfo, COL_INFO))
	{
	  col_add_fstr (pinfo->cinfo, COL_INFO, "Version %u.%u",
			header.GIOP_version.major, header.GIOP_version.minor);
	}
      if (tree)
	{
	  ti = proto_tree_add_item (tree, proto_giop, tvb, 0, -1, FALSE);
	  clnp_tree = proto_item_add_subtree (ti, ett_giop);
	  proto_tree_add_text (clnp_tree, giop_header_tvb, 0, -1,
			       "Version %u.%u not supported",
			       header.GIOP_version.major,
			       header.GIOP_version.minor);
	}
      call_dissector(data_handle,payload_tvb, pinfo, tree);
      return;
    }

  if (check_col (pinfo->cinfo, COL_INFO))
  {
      col_add_fstr (pinfo->cinfo, COL_INFO, "GIOP %u.%u %s",
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
      ti = proto_tree_add_item (tree, proto_giop, tvb, 0, -1, FALSE);
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

#if 0
  if (check_col (pinfo->cinfo, COL_INFO))
  {
      col_add_fstr (pinfo->cinfo, COL_INFO, "GIOP %u.%u %s",
                    header.GIOP_version.major, header.GIOP_version.minor,
                    match_strval(header.message_type, giop_message_types));
  }
#endif

  switch (header.message_type)
    {

    case Request:
      if(header.GIOP_version.minor < 2)
      {
	   dissect_giop_request_1_1 (payload_tvb, pinfo, tree,
				     &header, stream_is_big_endian);
      }
      else
      {
           dissect_giop_request_1_2 (payload_tvb, pinfo, tree,
				     &header, stream_is_big_endian);
      }

      break;


    case Reply:
      if(header.GIOP_version.minor < 2)
	{
           dissect_giop_reply (payload_tvb, pinfo, tree, &header,
			       stream_is_big_endian);
	}
      else
        {
	   dissect_giop_reply_1_2 (payload_tvb, pinfo, tree,
				   &header, stream_is_big_endian);
	}
      break;
    case CancelRequest:
        dissect_giop_cancel_request(payload_tvb, pinfo, tree,
				    stream_is_big_endian);
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
        dissect_giop_fragment(payload_tvb, pinfo, tree,
			      stream_is_big_endian);
        break;
    default:
      break;

    }				/* switch message_type */


  /*
   * XXX - we should catch exceptions here, so that we can free
   * this if an exception is thrown.
   * We'd then have to forward the exception.
   */
  if (header.exception_id != NULL)
    g_free(header.exception_id);
}

static guint
get_giop_pdu_len(tvbuff_t *tvb, int offset)
{

	MessageHeader header;
	guint message_size;
	gboolean stream_is_big_endian;

	tvb_memcpy (tvb, (guint8 *)&header, offset, GIOP_HEADER_SIZE );

	stream_is_big_endian = is_big_endian (&header);

	if (stream_is_big_endian)
		message_size = pntohl (&header.message_size);
	else
		message_size = pletohl (&header.message_size);


  return message_size + GIOP_HEADER_SIZE;
}

static void 
dissect_giop_tcp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {
	tcp_dissect_pdus(tvb, pinfo, tree, giop_desegment, GIOP_HEADER_SIZE,
	    get_giop_pdu_len, dissect_giop_common);
}

gboolean dissect_giop_heur (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree) {

  guint tot_len;

  conversation_t *conversation;
  /* check magic number and version */


  /*define END_OF_GIOP_MESSAGE (offset - first_offset - GIOP_HEADER_SIZE) */

  tot_len = tvb_length_remaining(tvb, 0);
  
  if (tot_len < GIOP_HEADER_SIZE) /* tot_len < 12 */
    {
      /* Not enough data captured to hold the GIOP header; don't try
         to interpret it as GIOP. */
      return FALSE;
    }
  if ( tvb_memeql(tvb, 0, GIOP_MAGIC ,4) != 0)
	  return FALSE;

  if ( pinfo->ptype == PT_TCP )
    {
      /*
       * Make the GIOP dissector the dissector for this conversation.
       *
       * If this isn't the first time this packet has been processed,
       * we've already done this work, so we don't need to do it
       * again.
       */
      if (!pinfo->fd->flags.visited)
        {
          conversation = find_conversation(pinfo->fd->num, &pinfo->src,
              &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
          if (conversation == NULL)
            {
              conversation = conversation_new(pinfo->fd->num, &pinfo->src,
                  &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
            }
          /* Set dissector */
          conversation_set_dissector(conversation, giop_tcp_handle);
	}
      dissect_giop_tcp (tvb, pinfo, tree);
    }
  else
    {
      dissect_giop_common (tvb, pinfo, tree);
    }

  return TRUE;

}

void
proto_register_giop (void)
{
  static hf_register_info hf[] = {
    { &hf_giop_message_type,
     { "Message type", "giop.type",
       FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_message_size,
      { "Message size", "giop.len",
	FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_repoid,
     { "Repository ID", "giop.repoid",
       FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_string_length,
     { "String Length", "giop.strlen",
       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_sequence_length,
     { "Sequence Length", "giop.seqlen",
       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_profile_id,
     { "Profile ID", "giop.profid",
       FT_UINT32, BASE_DEC, VALS(profile_id_vals), 0x0, "", HFILL }
    },


    { &hf_giop_type_id,
     { "IOR::type_id", "giop.typeid",
       FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_iiop_v_maj,
     { "IIOP Major Version", "giop.iiop_vmaj",
       FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
    }
    ,
    { &hf_giop_iiop_v_min,
     { "IIOP Minor Version", "giop.iiop_vmin",
       FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_endianess,
     { "Endianess", "giop.endianess",
       FT_UINT8, BASE_DEC, VALS(giop_endianess_vals), 0x0, "", HFILL }
    },

    { &hf_giop_IIOP_tag,
     { "IIOP Component TAG", "giop.iioptag",
       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_IOR_tag,
     { "IOR Profile TAG", "giop.iortag",
       FT_UINT8, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_TCKind,
     { "TypeCode enum", "giop.TCKind",
       FT_UINT32, BASE_DEC, VALS(tckind_vals), 0x0, "", HFILL }
    },

    { &hf_giop_typecode_count,
     { "TypeCode count", "giop.tccount",
       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_typecode_default_used,
     { "default_used", "giop.tcdefault_used",
       FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_typecode_digits,
     { "Digits", "giop.tcdigits",
       FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },


    { &hf_giop_typecode_length,
     { "Length", "giop.tclength",
       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_typecode_max_length,
     { "Maximum length", "giop.tcmaxlen",
       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_typecode_member_name,
     { "TypeCode member name", "giop.tcmemname",
       FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_typecode_name,
     { "TypeCode name", "giop.tcname",
       FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_typecode_scale,
     { "Scale", "giop.tcscale",
       FT_INT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_typecode_ValueModifier,
     { "ValueModifier", "giop.tcValueModifier",
       FT_INT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_typecode_Visibility,
     { "Visibility", "giop.tcVisibility",
       FT_INT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },



    { &hf_giop_type_boolean,
      { "TypeCode boolean data", "giop.tcboolean",
	FT_BOOLEAN, BASE_DEC,  NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_char,
      { "TypeCode char data", "giop.tcchar",
	FT_UINT8, BASE_DEC,  NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_double,
      { "TypeCode double data", "giop.tcdouble",
	FT_DOUBLE, BASE_DEC,  NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_enum,
     { "TypeCode enum data", "giop.tcenumdata",
       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    /*
     * float as double ?? -- FIX
     */

    { &hf_giop_type_float,
      { "TypeCode float data", "giop.tcfloat",
	FT_DOUBLE, BASE_DEC,  NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_long,
     { "TypeCode long data", "giop.tclongdata",
       FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_octet,
      { "TypeCode octet data", "giop.tcoctet",
	FT_UINT8, BASE_DEC,  NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_short,
     { "TypeCode short data", "giop.tcshortdata",
       FT_INT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_string,
      { "TypeCode string data", "giop.tcstring",
	FT_STRING, BASE_DEC,  NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_ulong,
     { "TypeCode ulong data", "giop.tculongdata",
       FT_UINT32, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    { &hf_giop_type_ushort,
     { "TypeCode ushort data", "giop.tcushortdata",
       FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    },

    /*
     * IIOP Module - Chapter 15.10.2
     */

    { &hf_giop_iiop_host,
     { "IIOP::Profile_host", "giop.iiop.host",
       FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }
    }
    ,

    { &hf_giop_iiop_port,
     { "IIOP::Profile_port", "giop.iiop.port",
       FT_UINT16, BASE_DEC, NULL, 0x0, "", HFILL }
    }
    ,

    /*
     * IIOP ServiceContext
     */

    { &hf_giop_iop_vscid,
     { "VSCID", "giop.iiop.vscid",
       FT_UINT32, BASE_HEX, NULL, 0xffffff00, "", HFILL }
    }
    ,

    { &hf_giop_iop_scid,
     { "SCID", "giop.iiop.scid",
       FT_UINT32, BASE_HEX, NULL, 0x000000ff, "", HFILL }
    }
    ,

  { &hf_giop_req_id,
  { "Request id", "giop.request_id",
	  FT_UINT32, BASE_DEC, NULL, 0, "", HFILL }
  },
	  
  { &hf_giop_req_operation,
  { "Request operation", "giop.request_op",
	  FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }
  },
  { &hf_giop_reply_status,
  { "Reply status", "giop.replystatus",
	  FT_UINT32, BASE_DEC, VALS(reply_status_types), 0x0, "", HFILL }
  },
  { &hf_giop_exception_id,
  { "Exception id", "giop.exceptionid",
	  FT_STRING, BASE_DEC, NULL, 0x0, "", HFILL }
  },
  };
	
		
		
  static gint *ett[] = {
    &ett_giop,
    &ett_giop_reply,
    &ett_giop_request,
    &ett_giop_cancel_request,
    &ett_giop_locate_request,
    &ett_giop_locate_reply,
    &ett_giop_fragment,
    &ett_giop_scl,
    &ett_giop_scl_st1,
    &ett_giop_ior

  };
    module_t *giop_module;

  proto_giop = proto_register_protocol("General Inter-ORB Protocol", "GIOP",
				       "giop");
  proto_register_field_array (proto_giop, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));


  /* register init routine */

  register_init_routine( &giop_init); /* any init stuff */

  /* register preferences */
  giop_module = prefs_register_protocol(proto_giop, NULL);
  prefs_register_bool_preference(giop_module, "desegment_giop_messages",
    "Reassemble GIOP messages spanning multiple TCP segments",
    "Whether the GIOP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &giop_desegment);

  /*
   * Init the giop user module hash tables here, as giop users
   * will populate it via register_giop_user_module BEFORE my
   * own giop_init() is called.
   */

  giop_module_hash = g_hash_table_new(giop_hash_module_hash, giop_hash_module_equal);

}



void proto_reg_handoff_giop (void) {
  data_handle = find_dissector("data");
  giop_tcp_handle = create_dissector_handle(dissect_giop_tcp, proto_giop);
  heur_dissector_add("tcp", dissect_giop_heur, proto_giop);
  /* Support DIOP (GIOP/UDP) */
  heur_dissector_add("udp", dissect_giop_heur, proto_giop);
  /* Port will be set by conversation */
  dissector_add("tcp.port", 0, giop_tcp_handle);
}




/*
 * Decode IOR
 *
 * Ref Corba v2.4.2 Chapter 13
 *
 */

/*

module IOP{

    typedef unsigned long ProfileId;

    const ProfileId TAG_INTERNET_IOP = 0;
    const ProfileId TAG_MULTIPLE_COMPONENTS = 1;

    struct TaggedProfile {
      ProfileId tag;
      sequence <octet> profile_data;
    };

    struct IOR {
      string type_id;
      sequence <TaggedProfile> profiles;
    };

    typedef unsigned long ComponentId;

    struct TaggedComponent {
      ComponentId tag;
      sequence <octet> component_data;
    };

    typedef sequence <TaggedComponent> MultipleComponentProfile;

};

*/

void decode_IOR(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ptree, int *offset,
		guint32 boundary, gboolean stream_is_big_endian) {


  guint32 seqlen_p;		/* sequence length of profiles */
  guint32 u_octet4;

  proto_tree *tree = NULL;	/* IOR tree */
  proto_item *tf;

  gchar *repobuf;		/* for repository ID */

  guint32 i;

  /* create a subtree */

  if (ptree) {
    tf = proto_tree_add_text (ptree, tvb, *offset, -1, "IOR");
    tree = proto_item_add_subtree (tf, ett_giop_ior);
  }


  /* Get type_id  == Repository ID */

  u_octet4 = get_CDR_string(tvb,&repobuf,offset,stream_is_big_endian,boundary);

  if (tree) {
    proto_tree_add_uint(tree,hf_giop_string_length,tvb,
			*offset-u_octet4-sizeof(u_octet4),4,u_octet4);
    if (u_octet4 > 0) {
      proto_tree_add_string(tree,hf_giop_type_id,tvb,
			    *offset-u_octet4,u_octet4,repobuf);
    }
  }

  /*
   * Register a cleanup function in case on of our tvbuff accesses
   * throws an exception. We need to clean up repobuf.
   * We can't free it yet, as we must wait until we have the object
   * key, as we have to add both to the hash table.
   */
  CLEANUP_PUSH(g_free, repobuf);

  /* Now get a sequence of profiles */
  /* Get sequence length (number of elements) */

  seqlen_p = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_sequence_length,tvb,
			*offset-sizeof(seqlen_p),4,seqlen_p);
  }


  /* fetch all TaggedProfiles in this sequence */

  for (i=0; i< seqlen_p; i++) { /* for every TaggedProfile */
    decode_TaggedProfile(tvb, pinfo, tree, offset, boundary, stream_is_big_endian, repobuf);
  }

  /*
   * We're done with repobuf, so we can call the cleanup handler to free
   * it, and then pop the cleanup handler.
   */
  CLEANUP_CALL_AND_POP;

}

static void decode_TaggedProfile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
				 guint32 boundary, gboolean stream_is_big_endian, gchar *repobuf) {

  guint32 seqlen_pd;		/* sequence length of profile data */

  guint32 pidtag;		/* profile ID TAG */

  gchar *profile_data;		/* profile_data pointer */
  gchar *p_profile_data;	/* printable profile_data pointer */

  guint32 new_boundary;		/* for encapsulations encountered */
  gboolean new_big_endianess;	/* for encapsulations encountered */

  /* Get ProfileId tag */

  pidtag = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);

  if (tree) {
    proto_tree_add_uint(tree,hf_giop_profile_id,tvb,
			*offset-sizeof(pidtag),4,pidtag);
  }

  /* get sequence length, new endianness and boundary for encapsulation */

  seqlen_pd = get_CDR_encap_info(tvb, tree, offset,
				 stream_is_big_endian, boundary,
				 &new_big_endianess, &new_boundary);

  /* return if zero length sequence */

  if(seqlen_pd == 0)
    return;


  /*
   * Lets see what kind of TAG it is. If TAG_INTERNET_IOP then
   * decode it, otherwise just dump the octet sequence
   *
   * also, store IOR in our objectkey hash
   *
   * TODO - handle other TAGS
   */

  switch(pidtag) {
  case IOP_TAG_INTERNET_IOP:

    decode_IIOP_IOR_profile(tvb, pinfo, tree, offset, new_boundary, new_big_endianess, repobuf, TRUE);
    break;

  default:

    /* fetch all octets in this sequence , but skip endianess */

    get_CDR_octet_seq(tvb, &profile_data, offset, seqlen_pd -1);

    /* Make a printable string */

    p_profile_data = make_printable_string( profile_data, seqlen_pd -1);

    if(tree) {
      proto_tree_add_text (tree, tvb, *offset -seqlen_pd + 1, seqlen_pd - 1,
			   "Profile Data: %s", p_profile_data);
    }

    g_free(p_profile_data);

    g_free(profile_data);

    break;

  }

}



/*
 * Decode IIOP IOR Profile
 * Ref Chap 15.7.2 in Corba Spec
 */


static void decode_IIOP_IOR_profile(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset,
				    guint32 boundary, gboolean stream_is_big_endian, gchar *repo_id_buf,
				    gboolean store_flag) {

  guint32 i;			/* loop index */

  guint8 v_major,v_minor;	/* IIOP version */
  gchar *buf;
  guint32 u_octet4;		/* u long */
  guint16 u_octet2;		/* u short */
  guint32 seqlen;		/* generic sequence length */
  guint32 seqlen1;		/* generic sequence length */
  gchar *objkey;		/* object key pointer */
  gchar *p_chars;		/* printable characters pointer */


  /* Get major/minor version */

  v_major = get_CDR_octet(tvb,offset);
  v_minor = get_CDR_octet(tvb,offset);


  if (tree) {
    proto_tree_add_uint(tree,hf_giop_iiop_v_maj,tvb,
			*offset-sizeof(v_minor)-sizeof(v_major),1,v_major  );
    proto_tree_add_uint(tree,hf_giop_iiop_v_min,tvb,
			*offset-sizeof(v_minor),1,v_minor  );
  }


  /* host */

  u_octet4 = get_CDR_string(tvb,&buf,offset,stream_is_big_endian,boundary);

  if (tree) {
    proto_tree_add_uint(tree,hf_giop_string_length,tvb,
			*offset-u_octet4-sizeof(u_octet4),4,u_octet4);
    if (u_octet4 > 0) {
      proto_tree_add_string(tree,hf_giop_iiop_host,tvb,
			    *offset-u_octet4,u_octet4,buf);
    }
  }

  g_free(buf);		/* dont forget */

  /* Port */

  u_octet2 = get_CDR_ushort(tvb,offset,stream_is_big_endian,boundary);

  if (tree) {
    proto_tree_add_uint(tree,hf_giop_iiop_port,tvb,
			*offset-sizeof(u_octet2),2,u_octet2);
  }


  /* Object Key - sequence<octet> object_key */

  seqlen = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);

  if (tree) {
    proto_tree_add_uint(tree,hf_giop_sequence_length,tvb,
			*offset-sizeof(seqlen),4,seqlen);
  }

  if (seqlen > 0) {
    /* fetch all octets in this sequence */
    get_CDR_octet_seq(tvb, &objkey, offset, seqlen);

    /*
     * Now we may have the Repository ID from earlier, as well
     * as the object key sequence and lengh. So lets store them in
     * our objectkey hash and free buffers.
     *
     * But only insert if user is not clicking and repo id not NULL.
     *
     */

    if (repo_id_buf) {
      if (pinfo) {
	if(!pinfo->fd->flags.visited)
	  insert_in_objkey_hash(giop_objkey_hash,objkey,seqlen,repo_id_buf,req_res);
      }
      else {

	/*
	 * No pinfo, but store anyway if flag set. eg: IOR read from file
	 */

	if (store_flag)
	  insert_in_objkey_hash(giop_objkey_hash,objkey,seqlen,repo_id_buf,file);
      }
    }

    /* Make a printable string */

    p_chars = make_printable_string( objkey, seqlen );

    if(tree) {
      proto_tree_add_text (tree, tvb, *offset -seqlen, seqlen,
			 "Object Key: %s", p_chars);
    }

    g_free(p_chars);
    g_free(objkey);
  }

  /*
   * Now see if if its v1.1 or 1.2, as they can contain
   * extra sequence of IOP::TaggedComponents
   *
   */

  switch(v_minor) {
  case 0:

    /* nothing extra */
    break;

  case 1:
  case 2:

    /* sequence of IOP::TaggedComponents */
    /* Ref Chap 13 in Corba Spec */

    /* get sequence length */
    seqlen = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);

    if (tree) {
      proto_tree_add_uint(tree,hf_giop_sequence_length,tvb,
			  *offset-sizeof(seqlen),4,seqlen);
    }

    for (i=0; i< seqlen; i++) {
      /* get tag */
      u_octet4 = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);
      if (tree) {
	proto_tree_add_uint(tree,hf_giop_IIOP_tag,tvb,
			    *offset-sizeof(u_octet4),4,u_octet4);
      }

      /* get component_data */
      seqlen1 = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);
      if (tree) {
	proto_tree_add_uint(tree,hf_giop_sequence_length,tvb,
			    *offset-sizeof(seqlen1),4,seqlen1);
      }

      if (seqlen1 > 0) {
	get_CDR_octet_seq(tvb, &buf, offset, seqlen1);

	if (tree) {
	  /* Make a printable string of data */

	  p_chars = make_printable_string(buf, seqlen1);

	  proto_tree_add_text (tree, tvb, *offset -seqlen1, seqlen1,
			       "component_data: %s", p_chars);

	  g_free(p_chars);
	}

	g_free(buf);
      }

    }


    break;

  default:
    g_warning("giop:Invalid v_minor value = %u ", v_minor);
    break;
  }

}

/*
 *  From Section 13.10.2.5 of the CORBA 3.0 spec.
 *
 *   module CONV_FRAME {
 *     typedef unsigned long CodeSetId;
 *     struct CodeSetContext {
 *        CodeSetId  char_data;
 *        CodeSetId  wchar_data;
 *     };
 *   }; 
 *  
 *   Code sets are identified by a 32-bit integer id from OSF.
 *   See:  ftp://ftp.opengroup.org/pub/code_set_registry
 */
static void decode_CodeSets(tvbuff_t *tvb, proto_tree *tree, int *offset,
                            gboolean stream_is_be, guint32 boundary) {

  /* The boundary being passed in is the offset where the context_data 
   * sequence begins. */
 
  guint32 code_set_id;
  if(tree) {
  /* We pass in -boundary, because the alignment is calculated relative to
     the beginning of the context_data sequence.
     Inside get_CDR_ulong(), the calculation will be (offset +(- boundary)) % 4 
     to determine the correct alignment of the short. */
    code_set_id = get_CDR_ulong(tvb, offset, stream_is_be, -((gint32) boundary) );

    proto_tree_add_text (tree, tvb, *offset - 4, 4,
                             "char_data: 0x%08x", code_set_id);

    code_set_id = get_CDR_ulong(tvb, offset, stream_is_be, -((gint32) boundary) );

    proto_tree_add_text (tree, tvb, *offset - 4, 4,
                             "wchar_data: 0x%08x", code_set_id);
  }

}

/*
 *  From Section 2.7.3 of the Real-time CORBA 1.1 Standard, the CORBA priority
 *  is represented in the GIOP service request as:
 *
 *  module IOP {
 *     typedef short ServiceId;
 *     const ServiceId  RTCorbaPriority = 10;
 *  };
 *
 *  The RT-CORBA priority is a CDR encoded short value in a sequence<octet>
 *  buffer.
 */ 
static void decode_RTCorbaPriority(tvbuff_t *tvb, proto_tree *tree, int *offset, 
	                           gboolean stream_is_be, guint32 boundary) {

  /* The boundary being passed in is the offset where the context_data 
   * sequence begins. */
 
  gint16 rtpriority;

  /* RTCorbaPriority is stored as a CDR encoded short */
  /* We pass in -boundary, because the alignment is calculated relative to
     the beginning of the context_data sequence.
     Inside get_CDR_short(), the calculation will be (offset + (- boundary)) % 2
     to determine the correct alignment of the short. */
  rtpriority = get_CDR_short(tvb, offset, stream_is_be, -((gint32) boundary) );

  if(tree) {
    /* Highlight all of context_data except for the first endian byte */ 
    proto_tree_add_text (tree, tvb, *offset - 2, 2,
                             "RTCorbaPriority: %d", rtpriority);
  }

}

static void decode_UnknownServiceContext(tvbuff_t *tvb, proto_tree *tree, int *offset,
			       gboolean stream_is_be, guint32 boundary) {

  guint32 context_data_len;
  gchar *p_context_data;
  gchar *context_data;

   /* get sequence length, and NO  encapsulation */
  context_data_len = get_CDR_ulong(tvb, offset, stream_is_be,boundary);


  /* return if zero length sequence */
  if(context_data_len == 0)
    return;

  /*
   * Now decode sequence according to vendor ServiceId, but I dont
   * have that yet, so just dump it as data.
   */

  /* fetch all octets in this sequence */

  get_CDR_octet_seq(tvb, &context_data, offset, context_data_len);

  /* Make a printable string */

  p_context_data = make_printable_string( context_data, context_data_len );

  if(tree) {
    proto_tree_add_text (tree, tvb, *offset - context_data_len , context_data_len,
	                 "context_data: %s", p_context_data);
  }

  g_free(context_data);
  g_free(p_context_data);
}

/*
 * Corba , chp 13.7
 *
 *
 *
 *      typedef unsigned long ServiceID;
 *
 *      struct ServiceContext {
 *              ServiceID context_id;
 *              sequence <octet> context_data;
 *      };
 *      typedef sequence <ServiceContext> ServiceContextList;
 *
 *
 * Note: Spec says context_data is an encapsulation.
 *
 *
 */

void decode_ServiceContextList(tvbuff_t *tvb, proto_tree *ptree, int *offset,
			       gboolean stream_is_be, guint32 boundary) {

  guint32 seqlen;		/* sequence length  */
  guint32 context_data_len;		/* context data sequence length  */

  proto_tree *tree = NULL;	/* ServiceContext tree */
  proto_tree *sub_tree1 = NULL;
  proto_item *tf = NULL, *tf_st1;

  guint32 context_id;

  guint32 i;
  guint32 vscid;		/* Vendor Service context id */
  guint32 scid;
  const gchar *service_context_name;
  gboolean encapsulation_is_be;
  guint32 encapsulation_boundary;
  int temp_offset, temp_offset1;
  int start_offset = *offset;

  /* create a subtree */

  if (ptree) {
    /* set length to 0 now and correct with proto_item_set_len() later */
    tf = proto_tree_add_text (ptree, tvb, *offset, 0, "ServiceContextList");

    tree = proto_item_add_subtree (tf, ett_giop_scl);
  }

  /* Get sequence length (number of elements) */
  seqlen = get_CDR_ulong(tvb,offset,stream_is_be,boundary);

  if (tree) {
    proto_tree_add_uint(tree,hf_giop_sequence_length,tvb,
			*offset-sizeof(seqlen),4,seqlen);
  }

  /* return if zero length sequence */

  if (seqlen == 0) {
    if (tf) {
      if (*offset - start_offset <= 0)
        THROW(ReportedBoundsError);
      proto_item_set_len(tf, *offset - start_offset);
    }

    return;
  }

  /* Loop for all ServiceContext's */

  for (i=0; i<seqlen; i++) {

    context_id = get_CDR_ulong(tvb,offset,stream_is_be,boundary);
    vscid = (context_id & 0xffffff00) >> 8; /* vendor info, top 24 bits */
    scid = context_id  & 0x000000ff; /* standard service info, lower 8 bits */

    if (tree) {
        proto_tree_add_uint(tree,hf_giop_iop_vscid,tvb,
	  *offset-sizeof(guint32),4,vscid);

        proto_tree_add_uint(tree,hf_giop_iop_scid,tvb,
 	  *offset-sizeof(guint32),4,scid);

     }

    if( vscid == 0) { /* OMG specified */
       service_context_name = match_strval(scid, service_context_ids);
    } else { /* Proprietary vscid */
       service_context_name = NULL;
    } 

    if ( service_context_name == NULL ) {
       service_context_name = "Unknown";
    }

    if(tree) {
      proto_tree_add_text (tree, tvb, *offset -sizeof(context_id), 4,
                           "Service Context ID: %s (%u)", service_context_name, 
	                                   context_id);
    }

    temp_offset1 = *offset;
    /* The OMG has vscid of 0 reserved */
    if( vscid != 0 || scid > max_service_context_id ) {
        decode_UnknownServiceContext(tvb, tree, offset, stream_is_be, boundary); 
        continue;
    }

    temp_offset = *offset;
    /* get sequence length, new endianness and boundary for encapsulation */
    context_data_len = get_CDR_encap_info(tvb, sub_tree1, offset,
			       stream_is_be, boundary,
			       &encapsulation_is_be , &encapsulation_boundary);

    if (tree) {
      tf_st1 = proto_tree_add_text (tree, tvb, temp_offset, sizeof(context_data_len) + context_data_len , service_context_name);
      sub_tree1 = proto_item_add_subtree (tf_st1, ett_giop_scl_st1);
    }

    if (context_data_len == 0)
        continue;

    /* See CORBA 3.0.2 standard, section Section 15.3.3 "Encapsulation",
     * for how CDR types can be marshalled into a sequence<octet>.
     * The first octet in the sequence determines endian order,
     * 0 == big-endian, 1 == little-endian
     */

    switch(scid)
    {
	case 0x01: /* Codesets */
           decode_CodeSets(tvb, sub_tree1, offset, 
	                          encapsulation_is_be, encapsulation_boundary); 
	   break;
	case 0x0a: /* RTCorbaPriority */
           decode_RTCorbaPriority(tvb, sub_tree1, offset, 
	                          encapsulation_is_be, encapsulation_boundary); 
	   break;
	default:

           /* Need to fill these in as we learn them */
	   *offset = temp_offset1;
           decode_UnknownServiceContext(tvb, sub_tree1, offset, stream_is_be, 
			                boundary);
	   break;
    }
    /* Set the offset to the end of the context_data sequence */
    *offset = temp_offset1 + sizeof(context_data_len) + context_data_len; 

  } /* for seqlen  */

  if (tf) {
    if (*offset - start_offset <= 0)
      THROW(ReportedBoundsError);
    proto_item_set_len(tf, *offset - start_offset);
  }

}

/* Decode SystemExceptionReplyBody as defined in the CORBA spec chapter 15.
 */

static void decode_SystemExceptionReplyBody (tvbuff_t *tvb, proto_tree *tree, gint *offset,
					     gboolean stream_is_big_endian,
					     guint32 boundary) {

  guint32 length;            /* string length */
  guint32 minor_code_value;
  guint32 completion_status;

  gchar *buf;                /* pointer to string buffer */

  length = get_CDR_string(tvb, &buf, offset, stream_is_big_endian, boundary);

  if (tree) {
    proto_tree_add_text(tree, tvb, *offset-4, 4,
			"Exception length: %u", length);
    if (length > 0) {
      proto_tree_add_text(tree, tvb, *offset - length, length,
			  "Exception id: %s", buf );
    }
  }
  g_free(buf);

  minor_code_value = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);
  completion_status = get_CDR_ulong(tvb, offset, stream_is_big_endian, boundary);

  if (tree) {
    proto_tree_add_text(tree, tvb, *offset-8, 4,
			"Minor code value: %u", minor_code_value);
    proto_tree_add_text(tree, tvb, *offset-4, 4,
			"Completion Status: %u", completion_status);
  }
}


/*
 * Helper functions for dissecting TypeCodes
 *
 * These functions decode the complex parameter lists
 * of TypeCodes as defined in the CORBA spec chapter 15.
 */

static void dissect_tk_objref_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			             gboolean stream_is_big_endian, guint32 boundary) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 seqlen;   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

}


static void dissect_tk_struct_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
                                     gboolean stream_is_big_endian, guint32 boundary,
                                     MessageHeader * header ) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 count;    /* parameter count (of tuples)  */
  guint32 seqlen;   /* sequence length */
  guint32 i;	    /* loop index */

  /* get sequence lengt,h new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

  /* get count of tuples */
  count = get_CDR_ulong(tvb,offset,new_stream_is_big_endian,new_boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_typecode_count,tvb,
			*offset-sizeof(count),4,count);
  }

  /* get all tuples */
  for (i=0; i< count; i++) {
    /* get member name */
    dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name);

    /* get member type */
    get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);
  }

}


static void dissect_tk_union_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			            gboolean stream_is_big_endian, guint32 boundary,
				    MessageHeader * header) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32  TCKind;    /* TypeCode */
  gint32   s_octet4;  /* signed int32 */

  guint32 count;    /* parameter count (of tuples)  */
  guint32 seqlen;   /* sequence length */
  guint32 i;	    /* loop index */

  /* get sequence legnth, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

  /* get discriminant type */
  TCKind = get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);

  /* get default used */
  s_octet4 = get_CDR_long(tvb,offset,new_stream_is_big_endian,new_boundary);
  if (tree) {
    proto_tree_add_int(tree,hf_giop_typecode_default_used,tvb,
			*offset-sizeof(s_octet4),4,s_octet4);
  }
  /* get count of tuples */
  count = get_CDR_ulong(tvb,offset,new_stream_is_big_endian,new_boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_typecode_count,tvb,
			*offset-sizeof(count),4,count);
  }

  /* get all tuples */
  for (i=0; i< count; i++) {
    /* get label value, based on TCKind above  */
    dissect_data_for_typecode(tvb, tree, offset, new_stream_is_big_endian, new_boundary, header, TCKind );

    /* get member name */
    dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name);

    /* get member type */
    get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);
  }

}


static void dissect_tk_enum_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			           gboolean stream_is_big_endian, guint32 boundary) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 count;    /* parameter count (of tuples)  */
  guint32 seqlen;   /* sequence length */
  guint32 i;	    /* loop index */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

  /* get count of tuples */
  count = get_CDR_ulong(tvb,offset,new_stream_is_big_endian,new_boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_typecode_count,tvb,
			*offset-sizeof(count),4,count);
  }

  /* get all tuples */
  for (i=0; i< count; i++) {
    /* get member name */
    dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name);
  }

}


static void dissect_tk_sequence_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			               gboolean stream_is_big_endian, guint32 boundary,
				       MessageHeader * header) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 u_octet4; /* unsigned int32 */

  guint32 seqlen;   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get element type */
  get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);

  /* get max length */
  u_octet4 = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_typecode_max_length,tvb,
			*offset-sizeof(u_octet4),4,u_octet4);
  }
}


static void dissect_tk_array_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			            gboolean stream_is_big_endian, guint32 boundary,
				    MessageHeader * header) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 u_octet4; /* unsigned int32 */

  guint32 seqlen;   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get element type */
  get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);

  /* get length */
  u_octet4 = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_typecode_length,tvb,
			*offset-sizeof(u_octet4),4,u_octet4);
  }
}


static void dissect_tk_alias_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			            gboolean stream_is_big_endian, guint32 boundary,
				    MessageHeader * header) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 seqlen;   /* sequence length */

  /* get sequence legnth, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

  /* get ??? (noname) TypeCode */
  get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);

}


static void dissect_tk_except_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			             gboolean stream_is_big_endian, guint32 boundary,
				     MessageHeader * header) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 count;    /* parameter count (of tuples)  */
  guint32 seqlen;   /* sequence length */
  guint32 i;	    /* loop index */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

  /* get count of tuples */
  count = get_CDR_ulong(tvb,offset,new_stream_is_big_endian,new_boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_typecode_count,tvb,
			*offset-sizeof(count),4,count);
  }

  /* get all tuples */
  for (i=0; i< count; i++) {
    /* get member name */
    dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name);

    /* get member type */
    get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);
  }

}


static void dissect_tk_value_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			            gboolean stream_is_big_endian, guint32 boundary,
				    MessageHeader * header) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  gint16  s_octet2; /* signed int16 */

  guint32 count;    /* parameter count (of tuples)  */
  guint32 seqlen;   /* sequence length */
  guint32 i;	    /* loop index */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

  /* get ValueModifier */
  s_octet2 = get_CDR_short(tvb,offset,stream_is_big_endian,boundary);
  if (tree) {
    proto_tree_add_int(tree,hf_giop_typecode_ValueModifier,tvb,
		       *offset-sizeof(s_octet2),2,s_octet2);
  }

  /* get conrete base */
  get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);

  /* get count of tuples */
  count = get_CDR_ulong(tvb,offset,new_stream_is_big_endian,new_boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_typecode_count,tvb,
			*offset-sizeof(count),4,count);
  }

  /* get all tuples */
  for (i=0; i< count; i++) {
    /* get member name */
    dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                  hf_giop_typecode_member_name);

    /* get member type */
    get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);

    /* get Visibility */
    s_octet2 = get_CDR_short(tvb,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_int(tree,hf_giop_typecode_Visibility,tvb,
			  *offset-sizeof(s_octet2),2,s_octet2);
    }
  }

}


static void dissect_tk_value_box_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			                gboolean stream_is_big_endian, guint32 boundary,
					MessageHeader * header) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 seqlen;   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

  /* get ??? (noname) TypeCode */
  get_CDR_typeCode(tvb,tree,offset,new_stream_is_big_endian,new_boundary,header);
}


static void dissect_tk_native_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			             gboolean stream_is_big_endian, guint32 boundary) {

  guint32  new_boundary;             /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian; /* new endianness for encapsulation */

  guint32 seqlen;   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

}


static void dissect_tk_abstract_interface_params(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			                         gboolean stream_is_big_endian, guint32 boundary) {

  guint32  new_boundary;              /* new boundary for encapsulation */
  gboolean new_stream_is_big_endian;  /* new endianness for encapsulation */

  guint32 seqlen;   /* sequence length */

  /* get sequence length, new endianness and boundary for encapsulation */
  seqlen = get_CDR_encap_info(tvb, tree, offset,
                                   stream_is_big_endian, boundary,
                                   &new_stream_is_big_endian, &new_boundary);

  /* get repository ID */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_repoid);

  /* get name */
  dissect_typecode_string_param(tvb, tree, offset, new_stream_is_big_endian, new_boundary,
                                hf_giop_typecode_name);

}

/* Typecode parameter lists are encoded as encapsulations and
 * this function gets the encapsulation information; see
 * CORBA spec chapter 15
 *
 *
 * Renamed to get_CDR_encap_info() for any encapsulation
 * we come across, useful helper function
 *
 * Also, should return immediately if seqlen == 0.
 * ie: Forget about trying to grab endianess for
 *     zero length sequence.
 *
 * Caller must always check seqlen == 0, and not assume its value
 *
 *
 * Note: there seemed to be considerable confusion in corba
 * circles as to the correct interpretation of encapsulations,
 * and zero length sequences etc, but this is our best bet at the
 * moment.
 *
 * -- FS
 *
 */

guint32 get_CDR_encap_info(tvbuff_t *tvb, proto_tree *tree, gint *offset,
		       gboolean old_stream_is_big_endian, guint32 old_boundary,
		       gboolean *new_stream_is_big_endian_ptr, guint32 *new_boundary_ptr ) {

  guint32 seqlen;   /* sequence length */
  guint8  giop_endianess;

  /* Get sequence length of parameter list */
  seqlen = get_CDR_ulong(tvb,offset,old_stream_is_big_endian,old_boundary);
  if (tree) {
    proto_tree_add_uint(tree,hf_giop_sequence_length,tvb,
			*offset-sizeof(seqlen),4,seqlen);
  }



  /*
   * seqlen == 0, implies no endianess and no data
   * so just return. Populate new_boundary_ptr and
   * new_stream_is_big_endian_ptr with current (old)
   * values, just to keep everyone happy. -- FS
   *
   */

  if (seqlen == 0) {

    *new_boundary_ptr = old_boundary;
    *new_stream_is_big_endian_ptr = old_stream_is_big_endian;

    return seqlen;

  }

  /*  Start of encapsulation of parameter list */
  *new_boundary_ptr = *offset;	/* remember  */
  giop_endianess =  get_CDR_octet(tvb,offset);

  *new_stream_is_big_endian_ptr = ! giop_endianess;

  /*
   * Glib: typedef gint   gboolean;
   * ie: It is not a guint8, so cannot use sizeof to correctly
   * highlight octet.
   */


  if (tree) {
    proto_tree_add_uint(tree,hf_giop_endianess,tvb,
			*offset-1,1,giop_endianess);
  }


  return seqlen;


}

/*
 * gets a TypeCode complex string parameter and
 * displays it in the relevant tree.
 */

static void dissect_typecode_string_param(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			                  gboolean new_stream_is_big_endian, guint32 new_boundary, int hf_id ) {

  guint32 u_octet4;  /* unsigned int32 */
  gchar *buf;        /* ptr to string buffer */

  /* get string */
  u_octet4 = get_CDR_string(tvb,&buf,offset,new_stream_is_big_endian,new_boundary);

  if (tree) {
    proto_tree_add_uint(tree,hf_giop_string_length,tvb,
			*offset-u_octet4-sizeof(u_octet4),4,u_octet4);
    if (u_octet4 > 0) {
      proto_tree_add_string(tree,hf_id,tvb,*offset-u_octet4,u_octet4,buf);
    }
  }

  g_free(buf);		/* dont forget */

}

/*
 * For a given data type, given by a TypeCode gets the associated data
 * and displays it in the relevant tree.
 */

static void dissect_data_for_typecode(tvbuff_t *tvb, proto_tree *tree, gint *offset,
			              gboolean stream_is_big_endian, guint32 boundary,
				      MessageHeader * header, guint32 data_type ) {

  gboolean my_boolean; /* boolean */

  gint8  s_octet1;   /* signed int8 */
  guint8 u_octet1;   /* unsigned int8 */

  gint16  s_octet2;  /* signed int16 */
  guint16 u_octet2;  /* unsigned int16 */

  gint32  s_octet4;  /* signed int32 */
  guint32 u_octet4;  /* unsigned int32 */

  gdouble my_double; /* double */
  gfloat  my_float;  /* float */

  gchar *buf = NULL;            /* ptr to string buffer */

  /* Grab the data according to data type */

  switch (data_type) {
  case tk_null:
    /* nothing to decode */
    break;
  case tk_void:
    /* nothing to decode */
    break;
  case tk_short:
    s_octet2 = get_CDR_short(tvb,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_int(tree,hf_giop_type_short,tvb,
			 *offset-sizeof(s_octet2),2,s_octet2);
    }
    break;
  case tk_long:
    s_octet4 = get_CDR_long(tvb,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_int(tree,hf_giop_type_long,tvb,
			 *offset-sizeof(s_octet4),4,s_octet4);
    }
    break;
  case tk_ushort:
    u_octet2 = get_CDR_ushort(tvb,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_type_ushort,tvb,
			  *offset-sizeof(u_octet2),2,u_octet2);
    }
    break;
  case tk_ulong:
    u_octet4 = get_CDR_ulong(tvb,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_type_ulong,tvb,
			 *offset-sizeof(u_octet4),4,u_octet4);
    }
    break;
  case tk_float:
    my_float = get_CDR_float(tvb,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_double(tree,hf_giop_type_float,tvb,
			    *offset-sizeof(my_float),4,my_float);
    }
    break;
  case tk_double:
    my_double = get_CDR_double(tvb,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_double(tree,hf_giop_type_double,tvb,
			    *offset-sizeof(my_double),8,my_double);
    }
    break;
  case tk_boolean:
    my_boolean = get_CDR_boolean(tvb,offset);
    if (tree) {
      proto_tree_add_boolean(tree,hf_giop_type_boolean,tvb,
			     *offset-1,1,my_boolean);
    }
    break;
  case tk_char:
    u_octet1 = get_CDR_char(tvb,offset);
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_type_char,tvb,
			  *offset-sizeof(u_octet1),1,u_octet1);
    }
    break;
  case tk_octet:
    u_octet1 = get_CDR_octet(tvb,offset);
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_type_octet,tvb,
			  *offset-sizeof(u_octet1),1,u_octet1);
    }
    break;
  case tk_any:
    get_CDR_any(tvb,tree,offset,stream_is_big_endian,boundary,header);
    break;
  case tk_TypeCode:
    get_CDR_typeCode(tvb,tree,offset,stream_is_big_endian,boundary,header);
    break;
  case tk_Principal:
    break;
  case tk_objref:
    break;
  case tk_struct:
    break;
  case tk_union:
    break;
  case tk_enum:
    u_octet4 = get_CDR_enum(tvb,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_type_enum,tvb,
			  *offset-sizeof(u_octet4),4,u_octet4);
    }
    break;
  case tk_string:
    u_octet4 = get_CDR_string(tvb,&buf,offset,stream_is_big_endian,boundary);
    if (tree) {
      proto_tree_add_uint(tree,hf_giop_string_length,tvb,
			  *offset-u_octet4-sizeof(u_octet4),4,u_octet4);
      if (u_octet4 > 0) {
	proto_tree_add_string(tree,hf_giop_type_string,tvb,
			      *offset-u_octet4,u_octet4,buf);
      }
    }

    g_free(buf);		/* dont forget */
    break;
  case tk_sequence:
    break;
  case tk_array:
    break;
  case tk_alias:
    break;
  case tk_except:
    break;
  case tk_longlong:
    break;
  case tk_ulonglong:
    break;
  case tk_longdouble:
    break;
  case tk_wchar:
    s_octet1 = get_CDR_wchar(tvb,&buf,offset,header);
    if (tree) {
      /*
       * XXX - can any of these throw an exception?
       * If so, we need to catch the exception and free "buf".
       */
      if (s_octet1 < 0) { /* no size to add to tree */
	proto_tree_add_string(tree,hf_giop_type_string,tvb,
			      *offset+s_octet1,(-s_octet1),buf);
      } else {
	proto_tree_add_uint(tree,hf_giop_string_length,tvb,
			    *offset-s_octet1-sizeof(s_octet1),1,s_octet1);
	proto_tree_add_string(tree,hf_giop_type_string,tvb,
			      *offset-s_octet1,s_octet1,buf);
      }
    }

    g_free(buf);              /* dont forget */
    break;
  case tk_wstring:
    u_octet4 = get_CDR_wstring(tvb,&buf,offset,stream_is_big_endian,boundary,header);
    if (tree) {
      /*
       * XXX - can any of these throw an exception?
       * If so, we need to catch the exception and free "buf".
       */
       proto_tree_add_uint(tree,hf_giop_string_length,tvb,
			   *offset-u_octet4-sizeof(u_octet4),4,u_octet4);
       proto_tree_add_string(tree,hf_giop_type_string,tvb,
			     *offset-u_octet4,u_octet4,buf);
     }

    g_free(buf);              /* dont forget */
    break;
  case tk_fixed:
    break;
  case tk_value:
    break;
  case tk_value_box:
    break;
  case tk_native:
    break;
  case tk_abstract_interface:
    break;
  default:
    g_warning("giop: Unknown typecode data type %u \n", data_type);
  break;
  } /* data_type */

}
