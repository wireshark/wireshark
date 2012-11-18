/* packet-rtmpt.c
 * Routines for Real Time Messaging Protocol packet dissection
 * metatech <metatech@flashmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*  This dissector is called RTMPT to avoid a conflict with
*   the other RTMP protocol (Routing Table Maintenance Protocol) implemented in packet-atalk.c
*   (RTMPT normally stands for RTMP-Tunnel via http)
*
*   RTMP in a nutshell
*
*   The protocol has very few "magic words" to facilitate detection,
*   but rather has "magic lengths".
*   This protocol has plenty of special cases and few general rules,
*   especially regarding the lengths and the structures.
*
*   Documentation:
*      RTMP protocol description on Wiki of Red5 Open Source Flash Server at
*
*          http://trac.red5.org/wiki/Codecs/RTMPSpecification
*
*      and the pages to which it links:
*
*          http://osflash.org/documentation/rtmp
*          http://wiki.gnashdev.org/RTMP
*          http://wiki.gnashdev.org/RTMP_Messages_Decoded
*          http://www.acmewebworks.com/Downloads/openCS/TheAMF.pdf
*          http://www.gnashdev.org/files/rtmp-decoded.pdf
*
*   It's also available from Adobe at
*
*          http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/rtmp/pdf/rtmp_specification_1.0.pdf
*
*   For AMF, see:
*
*          http://download.macromedia.com/pub/labs/amf/amf0_spec_121207.pdf
*
*   for AMF0 and
*
*          http://amf3cplusplus.googlecode.com/svn-history/r4/trunk/doc/amf3_spec_05_05_08.pdf
*
*   for AMF3.
*      
*   Default TCP port is 1935
*/

#include "config.h"

#include <string.h>

#include <epan/packet.h>

#include <epan/emem.h>
#include <epan/conversation.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

/* #define DEBUG_RTMPT 1 */

static int proto_rtmpt = -1;

static int hf_rtmpt_handshake_c0 = -1;
static int hf_rtmpt_handshake_s0 = -1;
static int hf_rtmpt_handshake_c1 = -1;
static int hf_rtmpt_handshake_s1 = -1;
static int hf_rtmpt_handshake_c2 = -1;
static int hf_rtmpt_handshake_s2 = -1;

static int hf_rtmpt_header_format = -1;
static int hf_rtmpt_header_csid = -1;
static int hf_rtmpt_header_timestamp = -1;
static int hf_rtmpt_header_timestamp_delta = -1;
static int hf_rtmpt_header_body_size = -1;
static int hf_rtmpt_header_typeid = -1;
static int hf_rtmpt_header_streamid = -1;
static int hf_rtmpt_header_ets = -1;

static int hf_rtmpt_scm_chunksize = -1;
static int hf_rtmpt_scm_csid = -1;
static int hf_rtmpt_scm_seq = -1;
static int hf_rtmpt_scm_was = -1;
static int hf_rtmpt_scm_limittype = -1;

static int hf_rtmpt_ucm_eventtype = -1;

static int hf_rtmpt_function_call = -1;
static int hf_rtmpt_function_response = -1;

static int hf_rtmpt_audio_control = -1;
static int hf_rtmpt_audio_format = -1;
static int hf_rtmpt_audio_rate = -1;
static int hf_rtmpt_audio_size = -1;
static int hf_rtmpt_audio_type = -1;
static int hf_rtmpt_audio_data = -1;

static int hf_rtmpt_video_control = -1;
static int hf_rtmpt_video_type = -1;
static int hf_rtmpt_video_format = -1;
static int hf_rtmpt_video_data = -1;

static int hf_rtmpt_tag_type = -1;
static int hf_rtmpt_tag_datasize = -1;
static int hf_rtmpt_tag_timestamp = -1;
static int hf_rtmpt_tag_ets = -1;
static int hf_rtmpt_tag_streamid = -1;
static int hf_rtmpt_tag_tagsize = -1;

static gint ett_rtmpt = -1;
static gint ett_rtmpt_handshake = -1;
static gint ett_rtmpt_header = -1;
static gint ett_rtmpt_body = -1;
static gint ett_rtmpt_ucm = -1;
static gint ett_rtmpt_audio_control = -1;
static gint ett_rtmpt_video_control = -1;
static gint ett_rtmpt_tag = -1;
static gint ett_rtmpt_tag_data = -1;

static dissector_handle_t rtmpt_tcp_handle;
static dissector_handle_t rtmpt_http_handle;

static gboolean rtmpt_desegment = TRUE;

#define RTMP_PORT                     1935

#define RTMPT_MAGIC                   0x03
#define RTMPT_HANDSHAKE_OFFSET_1         1
#define RTMPT_HANDSHAKE_OFFSET_2      1538
#define RTMPT_HANDSHAKE_OFFSET_3      3074
#define RTMPT_HANDSHAKE_LENGTH_1      1537
#define RTMPT_HANDSHAKE_LENGTH_2      3073
#define RTMPT_HANDSHAKE_LENGTH_3      1536
#define RTMPT_DEFAULT_CHUNK_SIZE       128

/* Native Bandwidth Detection (using the checkBandwidth(), onBWCheck(),
 * onBWDone() calls) transmits a series of increasing size packets over
 * the course of 2 seconds. On a fast link the largest packet can just
 * exceed 256KB. */
/* #define RTMPT_MAX_PACKET_SIZE     131072 */
/* #define RTMPT_MAX_PACKET_SIZE     262144 */
#define RTMPT_MAX_PACKET_SIZE         524288

#define RTMPT_ID_MAX                     65599
#define RTMPT_TYPE_HANDSHAKE_1        0x100001
#define RTMPT_TYPE_HANDSHAKE_2        0x100002
#define RTMPT_TYPE_HANDSHAKE_3        0x100003

#define RTMPT_TYPE_CHUNK_SIZE         0x01
#define RTMPT_TYPE_ABORT_MESSAGE      0x02
#define RTMPT_TYPE_ACKNOWLEDGEMENT    0x03
#define RTMPT_TYPE_UCM                0x04
#define RTMPT_TYPE_WINDOW             0x05
#define RTMPT_TYPE_PEER_BANDWIDTH     0x06
#define RTMPT_TYPE_AUDIO_DATA         0x08
#define RTMPT_TYPE_VIDEO_DATA         0x09
#define RTMPT_TYPE_DATA_AMF3          0x0F
#define RTMPT_TYPE_SHARED_AMF3        0x10
#define RTMPT_TYPE_COMMAND_AMF3       0x11
#define RTMPT_TYPE_DATA_AMF0          0x12
#define RTMPT_TYPE_SHARED_AMF0        0x13
#define RTMPT_TYPE_COMMAND_AMF0       0x14
#define RTMPT_TYPE_AGGREGATE          0x16

#define RTMPT_UCM_STREAM_BEGIN        0x00
#define RTMPT_UCM_STREAM_EOF          0x01
#define RTMPT_UCM_STREAM_DRY          0x02
#define RTMPT_UCM_SET_BUFFER          0x03
#define RTMPT_UCM_STREAM_ISRECORDED   0x04
#define RTMPT_UCM_PING_REQUEST        0x06
#define RTMPT_UCM_PING_RESPONSE       0x07

#define RTMPT_TEXT_RTMP_HEADER        "RTMP Header"
#define RTMPT_TEXT_RTMP_BODY          "RTMP Body"

static const value_string rtmpt_handshake_vals[] = {
        { RTMPT_TYPE_HANDSHAKE_1,           "Handshake C0+C1" },
        { RTMPT_TYPE_HANDSHAKE_2,           "Handshake S0+S1+S2" },
        { RTMPT_TYPE_HANDSHAKE_3,           "Handshake C2" },
        { 0, NULL }
};

static const value_string rtmpt_opcode_vals[] = {
        { RTMPT_TYPE_CHUNK_SIZE,            "Set Chunk Size" },
        { RTMPT_TYPE_ABORT_MESSAGE,         "Abort Message" },
        { RTMPT_TYPE_ACKNOWLEDGEMENT,       "Acknowledgement" },
        { RTMPT_TYPE_UCM,                   "User Control Message" },
        { RTMPT_TYPE_WINDOW,                "Window Acknowledgement Size" },
        { RTMPT_TYPE_PEER_BANDWIDTH,        "Set Peer Bandwidth" },
        { RTMPT_TYPE_AUDIO_DATA,            "Audio Data" },
        { RTMPT_TYPE_VIDEO_DATA,            "Video Data" },
        { RTMPT_TYPE_DATA_AMF3,             "AMF3 Data" },
        { RTMPT_TYPE_SHARED_AMF3,           "AMF3 Shared Object" },
        { RTMPT_TYPE_COMMAND_AMF3,          "AMF3 Command" },
        { RTMPT_TYPE_DATA_AMF0,             "AMF0 Data" },
        { RTMPT_TYPE_SHARED_AMF0,           "AMF0 Shared Object" },
        { RTMPT_TYPE_COMMAND_AMF0,          "AMF0 Command" },
        { RTMPT_TYPE_AGGREGATE,             "Aggregate" },
        { 0, NULL }
};

static const value_string rtmpt_limit_vals[] = {
/* These are a complete guess, from the order of the documented
 * options - the values aren't actually specified */
        { 0,                                "Hard" },
        { 1,                                "Soft" },
        { 2,                                "Dynamic" },
        { 0, NULL }
};

static const value_string rtmpt_ucm_vals[] = {
        { RTMPT_UCM_STREAM_BEGIN,           "Stream Begin" },
        { RTMPT_UCM_STREAM_EOF,             "Stream EOF" },
        { RTMPT_UCM_STREAM_DRY,             "Stream Dry" },
        { RTMPT_UCM_SET_BUFFER,             "Set Buffer Length" },
        { RTMPT_UCM_STREAM_ISRECORDED,      "Stream Is Recorded" },
        { RTMPT_UCM_PING_REQUEST,           "Ping Request" },
        { RTMPT_UCM_PING_RESPONSE,          "Ping Response" },
        { 0, NULL }
};

static const value_string rtmpt_tag_vals[] = {
        { RTMPT_TYPE_AUDIO_DATA,            "Audio Tag" },
        { RTMPT_TYPE_VIDEO_DATA,            "Video Tag" },
        { RTMPT_TYPE_DATA_AMF0,             "Script Tag" },
        { 0, NULL }
};

/* [Spec] http://www.adobe.com/content/dam/Adobe/en/devnet/rtmp/pdf/rtmp_specification_1.0.pdf       */
/* [DevG] http://help.adobe.com/en_US/flashmediaserver/devguide/index.html "working with Live Video" => Adding metadata to a live stream */
/* [SWF] http://www.adobe.com/content/dam/Adobe/en/devnet/swf/pdf/swf_file_format_spec_v10.pdf */
static const value_string rtmpt_audio_codecs[] = {
        {  0,                               "Uncompressed" },             /* [DevG] */
        {  1,                               "ADPCM" },                    /* [DevG] */
        {  2,                               "MP3" },                      /* [DevG] */
        {  3,                               "Uncompressed, little-endian"}, /* [SWF] */
        {  4,                               "Nellymoser 16kHz" },          /* [SWF] */
        {  5,                               "Nellymoser 8kHz" },          /* [DevG] [SWF]*/
        {  6,                               "Nellymoser" },               /* [DevG] [SWF]*/
        {  7,                               "G711A" },                    /* [Spec] */
        {  8,                               "G711U" },                    /* [Spec] */
        {  9,                               "Nellymoser 16kHz" },         /* [Spec] */
        { 10,                               "HE-AAC" },                   /* [DevG] */
        { 11,                               "SPEEX" },                    /* [DevG] */
        { 0, NULL }
};

static const value_string rtmpt_audio_rates[] = {
        { 0,                                "5.5 kHz" },
        { 1,                                "11 kHz" },
        { 2,                                "22 kHz" },
        { 3,                                "44 kHz" },
        { 0, NULL }
};

static const value_string rtmpt_audio_sizes[] = {
        { 0,                                "8 bit" },
        { 1,                                "16 bit" },
        { 0, NULL }
};

static const value_string rtmpt_audio_types[] = {
        { 0,                                "mono" },
        { 1,                                "stereo" },
        { 0, NULL }
};

static const value_string rtmpt_video_types[] = {
        { 1,                                "keyframe" },
        { 2,                                "inter-frame" },
        { 3,                                "disposable inter-frame" },
        { 0, NULL }
};

static const value_string rtmpt_video_codecs[] = {
        { 2,                                "Sorensen H.263" },
        { 3,                                "Screen video" },
        { 4,                                "On2 VP6" },
        { 5,                                "On2 VP6+alpha" },
        { 6,                                "Screen video version 2" },
        { 7,                                "H.264" },
        { 0, NULL }
};

static int proto_amf = -1;

static int hf_amf_version = -1;
static int hf_amf_header_count = -1;
static int hf_amf_header_name = -1;
static int hf_amf_header_must_understand = -1;
static int hf_amf_header_length = -1;
static int hf_amf_header_value_type = -1;
static int hf_amf_message_count = -1;
static int hf_amf_message_target_uri = -1;
static int hf_amf_message_response_uri = -1;
static int hf_amf_message_length = -1;

static int hf_amf_amf0_type = -1;
static int hf_amf_amf3_type = -1;
static int hf_amf_number = -1;
static int hf_amf_integer = -1;
static int hf_amf_boolean = -1;
static int hf_amf_stringlength = -1;
static int hf_amf_string = -1;
static int hf_amf_string_reference = -1;
static int hf_amf_object_reference = -1;
static int hf_amf_date = -1;
static int hf_amf_longstringlength = -1;
static int hf_amf_longstring = -1;
static int hf_amf_xml_doc = -1;
static int hf_amf_xmllength = -1;
static int hf_amf_xml = -1;
static int hf_amf_int64 = -1;
static int hf_amf_bytearraylength = -1;
static int hf_amf_bytearray = -1;

static int hf_amf_object = -1;
static int hf_amf_traitcount = -1;
static int hf_amf_classnamelength = -1;
static int hf_amf_classname = -1;
static int hf_amf_membernamelength = -1;
static int hf_amf_membername = -1;
static int hf_amf_trait_reference = -1;
static int hf_amf_ecmaarray = -1;
static int hf_amf_strictarray = -1;
static int hf_amf_array = -1;
static int hf_amf_arraylength = -1;
static int hf_amf_arraydenselength = -1;

static gint ett_amf = -1;
static gint ett_amf_headers = -1;
static gint ett_amf_messages = -1;
static gint ett_amf_value = -1;
static gint ett_amf_property = -1;
static gint ett_amf_string = -1;
static gint ett_amf_array_element = -1;
static gint ett_amf_traits = -1;
static gint ett_amf_trait_member = -1;

/* AMF0 type markers */
#define AMF0_NUMBER              0x00
#define AMF0_BOOLEAN             0x01
#define AMF0_STRING              0x02
#define AMF0_OBJECT              0x03
#define AMF0_MOVIECLIP           0x04
#define AMF0_NULL                0x05
#define AMF0_UNDEFINED           0x06
#define AMF0_REFERENCE           0x07
#define AMF0_ECMA_ARRAY          0x08
#define AMF0_END_OF_OBJECT       0x09
#define AMF0_STRICT_ARRAY        0x0A
#define AMF0_DATE                0x0B
#define AMF0_LONG_STRING         0x0C
#define AMF0_UNSUPPORTED         0x0D
#define AMF0_RECORDSET           0x0E
#define AMF0_XML                 0x0F
#define AMF0_TYPED_OBJECT        0x10
#define AMF0_AMF3_MARKER         0x11
#define AMF0_INT64               0x22

/* AMF3 type markers */
#define AMF3_UNDEFINED           0x00
#define AMF3_NULL                0x01
#define AMF3_FALSE               0x02
#define AMF3_TRUE                0x03
#define AMF3_INTEGER             0x04
#define AMF3_DOUBLE              0x05
#define AMF3_STRING              0x06
#define AMF3_XML_DOC             0x07
#define AMF3_DATE                0x08
#define AMF3_ARRAY               0x09
#define AMF3_OBJECT              0x0A
#define AMF3_XML                 0x0B
#define AMF3_BYTEARRAY           0x0C

static const value_string amf0_type_vals[] = {
        { AMF0_NUMBER,                "Number" },
        { AMF0_BOOLEAN,               "Boolean" },
        { AMF0_STRING,                "String" },
        { AMF0_OBJECT,                "Object" },
        { AMF0_MOVIECLIP,             "Movie clip" },
        { AMF0_NULL,                  "Null" },
        { AMF0_UNDEFINED,             "Undefined" },
        { AMF0_REFERENCE,             "Reference" },
        { AMF0_ECMA_ARRAY,            "ECMA array" },
        { AMF0_END_OF_OBJECT,         "End of object" },
        { AMF0_STRICT_ARRAY,          "Strict array" },
        { AMF0_DATE,                  "Date" },
        { AMF0_LONG_STRING,           "Long string" },
        { AMF0_UNSUPPORTED,           "Unsupported" },
        { AMF0_RECORDSET,             "Record set" },
        { AMF0_XML,                   "XML" },
        { AMF0_TYPED_OBJECT,          "Typed object" },
        { AMF0_AMF3_MARKER,           "Switch to AMF3" },
        { AMF0_INT64,                 "Int64" },
        { 0, NULL }
};

static const value_string amf3_type_vals[] = {
        { AMF3_UNDEFINED,             "Undefined" },
        { AMF3_NULL,                  "Null" },
        { AMF3_FALSE,                 "False" },
        { AMF3_TRUE,                  "True" },
        { AMF3_INTEGER,               "Integer" },
        { AMF3_DOUBLE,                "Double" },
        { AMF3_STRING,                "String" },
        { AMF3_XML_DOC,               "XML document" },
        { AMF3_DATE,                  "Date" },
        { AMF3_ARRAY,                 "Array" },
        { AMF3_OBJECT,                "Object" },
        { AMF3_XML,                   "XML" },
        { AMF3_BYTEARRAY,             "ByteArray" },
        { 0, NULL }
};

/* Holds the reassembled data for a packet during un-chunking
 */
typedef struct rtmpt_packet {
        guint32          seq;
        guint32          lastseq;

        int              resident;
        union {
                guint8  *p;
                guint32  offset;
        } data;

        /* used during unchunking */
        int              want;
        int              have;
        int              chunkwant;
        int              chunkhave;

        guint8           bhlen;
        guint8           mhlen;

        /* Chunk Basic Header */
        guint8           fmt;   /* byte 0 */
        guint32          id;    /* byte 0 */

        /* Chunk Message Header (offsets assume bhlen==1) */
        guint32          ts;    /* bytes 1-3, or from ETS @ mhlen-4 if -1 */
        guint32          len;   /* bytes 4-6 */
        guint8           cmd;   /* byte 7 */
        guint32          src;   /* bytes 8-11 */

        guint32          txid;
        gint             isresponse;
        gint             otherframe;

} rtmpt_packet_t;

/* Represents a header or a chunk that is split over two TCP
 * segments
 */
typedef struct rtmpt_frag {
        int     ishdr;
        guint32 seq;
        guint32 lastseq;
        int     have;
        int     len;

        union {
                guint8 d[18]; /* enough for a complete header (3 + 11 + 4) */
                guint32 id;
        } saved;
} rtmpt_frag_t;

/* The full message header information for the last packet on a particular
 * ID - used for defaulting short headers
 */
typedef struct rtmpt_id {
        guint32 ts;   /* bytes 1-3 */
        guint32 tsd;
        guint32 len;  /* bytes 4-6 */
        guint32 src;  /* bytes 8-11 */
        guint8  cmd;  /* byte 7 */

        emem_tree_t *packets;
} rtmpt_id_t;

/* Historical view of a whole TCP connection
 */
typedef struct rtmpt_conv {
        emem_tree_t *seqs[2];
        emem_tree_t *frags[2];
        emem_tree_t *ids[2];
        emem_tree_t *packets[2];
        emem_tree_t *chunksize[2];
        emem_tree_t *txids[2];
} rtmpt_conv_t;

#ifdef DEBUG_RTMPT
static void rtmpt_debug(const char *fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
}
#define RTMPT_DEBUG rtmpt_debug
#else
static void rtmpt_debug(const char *fmt, ...){ (void)fmt; }
#define RTMPT_DEBUG 1 ? (void)0 : rtmpt_debug
#endif

/* Header length helpers */

static gint rtmpt_basic_header_length(gint id)
{
        switch (id & 0x3f) {
        case 0: return 2;
        case 1: return 3;
        default: return 1;
        }
}

static gint rtmpt_message_header_length(gint id)
{
        switch ((id>>6) & 3) {
        case 0: return 11;
        case 1: return 7;
        case 2: return 3;
        default: return 0;
        }
}

/* Lightweight access to AMF0 blobs - more complete dissection is done
 * in dissect_rtmpt_body_command */

static gint
rtmpt_get_amf_length(tvbuff_t *tvb, gint offset)
{
        guint8  iObjType;
        gint    remain  = tvb_length_remaining(tvb, offset);
        guint32 depth   = 0;
        gint    itemlen = 0;
        gint    rv      = 0;

        while (rv==0 || depth>0) {

                if (depth>0) {
                        if (remain-rv<2) return remain;
                        itemlen = tvb_get_ntohs(tvb, offset+rv) + 2;
                        if (remain-rv<itemlen+1) return remain;
                        rv += itemlen;
                }

                if (remain-rv<1) return remain;
                iObjType = tvb_get_guint8(tvb, offset+rv);

                if (depth>0 && itemlen==2 && iObjType==AMF0_END_OF_OBJECT) {
                        rv++;
                        depth--;
                        continue;
                }

                switch (iObjType) {
                case AMF0_NUMBER:
                        itemlen = 9;
                        break;
                case AMF0_BOOLEAN:
                        itemlen = 2;
                        break;
                case AMF0_STRING:
                        if (remain-rv<3) return remain;
                        itemlen = tvb_get_ntohs(tvb, offset+rv+1) + 3;
                        break;
                case AMF0_NULL:
                case AMF0_UNDEFINED:
                case AMF0_UNSUPPORTED:
                        itemlen= 1;
                        break;
                case AMF0_DATE:
                        itemlen = 11;
                        break;
                case AMF0_LONG_STRING:
                case AMF0_XML:
                        if (remain-rv<5) return remain;
                        itemlen = tvb_get_ntohl(tvb, offset+rv+1) + 5;
                        break;
                case AMF0_INT64:
                        itemlen = 9;
                        break;
                case AMF0_OBJECT:
                        itemlen = 1;
                        depth++;
                        break;
                case AMF0_ECMA_ARRAY:
                        itemlen = 5;
                        depth++;
                        break;
                default:
                        return remain;
                }

                if (remain-rv<itemlen) return remain;
                rv += itemlen;

        }

        return rv;
}

static gchar*
rtmpt_get_amf_param(tvbuff_t *tvb, gint offset, gint param, const gchar *prop)
{
        guint32 remain = tvb_length_remaining(tvb, offset);
        guint32 itemlen;
        guint32 iStringLength;

        while (remain>0 && param>0) {
                itemlen = rtmpt_get_amf_length(tvb, offset);
                offset += itemlen;
                remain -= itemlen;
                param--;
        }

        if (remain>0 && param==0) {
                guint8 iObjType = tvb_get_guint8(tvb, offset);

                if (!prop && iObjType==AMF0_STRING && remain>=3) {
                        iStringLength = tvb_get_ntohs(tvb, offset+1);
                        if (remain>=iStringLength+3) {
                                return tvb_get_ephemeral_string(tvb, offset+3, iStringLength);
                        }
                }

                if (prop && iObjType==AMF0_OBJECT) {
                        offset++;
                        remain--;

                        while (remain>2) {
                                guint32 iPropLength = tvb_get_ntohs(tvb, offset);
                                if (remain<2+iPropLength+3) break;

                                if (tvb_strneql(tvb, offset+2, prop, strlen(prop))==0) {
                                        if (tvb_get_guint8(tvb, offset+2+iPropLength)!=AMF0_STRING) break;

                                        iStringLength = tvb_get_ntohs(tvb, offset+2+iPropLength+1);
                                        if (remain<2+iPropLength+3+iStringLength) break;

                                        return tvb_get_ephemeral_string(tvb, offset+2+iPropLength+3, iStringLength);
                                }

                                itemlen = rtmpt_get_amf_length(tvb, offset+2+iPropLength);
                                offset += 2+iPropLength+itemlen;
                                remain -= 2+iPropLength+itemlen;
                        }
                }
        }

        return NULL;
}

static guint32
rtmpt_get_amf_txid(tvbuff_t *tvb, gint offset)
{
        guint32 remain = tvb_length_remaining(tvb, offset);

        if (remain>0) {
                guint32 itemlen = rtmpt_get_amf_length(tvb, offset);
                if (remain<itemlen) return 0;
                offset += itemlen;
                remain -= itemlen;
        }
        if (remain>=9) {
                guint8 iObjType = tvb_get_guint8(tvb, offset);
                if (iObjType==AMF0_NUMBER) {
                        return (guint32)tvb_get_ntohieee_double(tvb, offset+1);
                }
        }

        return 0;
}


/* Generate a useful description for various packet types */

static gchar*
rtmpt_get_packet_desc(tvbuff_t *tvb, guint32 offset, guint32 remain, rtmpt_conv_t *rconv, int cdir, rtmpt_packet_t *tp, gint *deschasopcode)
{
        if (tp->cmd==RTMPT_TYPE_CHUNK_SIZE || tp->cmd==RTMPT_TYPE_ABORT_MESSAGE ||
            tp->cmd==RTMPT_TYPE_ACKNOWLEDGEMENT || tp->cmd==RTMPT_TYPE_WINDOW) {
                if (tp->len>=4 && remain>=4) {
                        *deschasopcode = TRUE;
                        return ep_strdup_printf("%s %d",
                                                val_to_str(tp->cmd, rtmpt_opcode_vals, "Unknown (0x%01x)"),
                                                tvb_get_ntohl(tvb, offset));
                }

        } else if (tp->cmd==RTMPT_TYPE_PEER_BANDWIDTH) {
                if (tp->len>=5 && remain>=5) {
                        *deschasopcode = TRUE;
                        return ep_strdup_printf("%s %d,%s",
                                                val_to_str(tp->cmd, rtmpt_opcode_vals, "Unknown (0x%01x)"),
                                                tvb_get_ntohl(tvb, offset),
                                                val_to_str(tvb_get_guint8(tvb, offset+4), rtmpt_limit_vals, "Unknown (%d)"));
                }

        } else if (tp->cmd==RTMPT_TYPE_UCM) {
                guint16 iUCM = -1;
                const gchar *sFunc = NULL;
                const gchar *sParam = "";

                if (tp->len<2 || remain<2) return NULL;

                iUCM = tvb_get_ntohs(tvb, offset);
                sFunc = match_strval(iUCM, rtmpt_ucm_vals);
                if (sFunc==NULL) {
                        *deschasopcode = TRUE;
                        sFunc = ep_strdup_printf("User Control Message 0x%01x", iUCM);
                }

                if (iUCM==RTMPT_UCM_STREAM_BEGIN || iUCM==RTMPT_UCM_STREAM_EOF ||
                    iUCM==RTMPT_UCM_STREAM_DRY || iUCM==RTMPT_UCM_STREAM_ISRECORDED) {
                        if (tp->len>=6 && remain>=6) {
                                sParam = ep_strdup_printf(" %d", tvb_get_ntohl(tvb, offset+2));
                        }
                } else if (iUCM==RTMPT_UCM_SET_BUFFER) {
                        if (tp->len>=10 && remain>=10) {
                                sParam = ep_strdup_printf(" %d,%dms",
                                                          tvb_get_ntohl(tvb, offset+2),
                                                          tvb_get_ntohl(tvb, offset+6));
                        }
                }

                return ep_strdup_printf("%s%s", sFunc, sParam);

        } else if (tp->cmd==RTMPT_TYPE_COMMAND_AMF0 || tp->cmd==RTMPT_TYPE_COMMAND_AMF3 ||
                   tp->cmd==RTMPT_TYPE_DATA_AMF0 || tp->cmd==RTMPT_TYPE_DATA_AMF3) {
                guint32 slen = 0;
                guint32 soff = 0;
                gchar *sFunc = NULL;
                gchar *sParam = NULL;

                if (tp->cmd==RTMPT_TYPE_COMMAND_AMF3 || tp->cmd==RTMPT_TYPE_DATA_AMF3) {
                        soff = 1;
                }
                if (tp->len>=3+soff && remain>=3+soff) {
                        slen = tvb_get_ntohs(tvb, offset+1+soff);
                }
                if (slen>0) {
                        sFunc = tvb_get_ephemeral_string(tvb, offset+3+soff, slen);
                        RTMPT_DEBUG("got function call '%s'\n", sFunc);

                        if (strcmp(sFunc, "connect")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 2, "app");
                        } else if (strcmp(sFunc, "play")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 3, NULL);
                        } else if (strcmp(sFunc, "play2")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 3, "streamName");
                        } else if (strcmp(sFunc, "releaseStream")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 3, NULL);
                        } else if (strcmp(sFunc, "FCPublish")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 3, NULL);
                        } else if (strcmp(sFunc, "publish")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 3, NULL);
                        } else if (strcmp(sFunc, "onStatus")==0) {
                                if (tp->cmd==RTMPT_TYPE_COMMAND_AMF0 || tp->cmd==RTMPT_TYPE_COMMAND_AMF3) {
                                        sParam = rtmpt_get_amf_param(tvb, offset+soff, 3, "code");
                                } else {
                                        sParam = rtmpt_get_amf_param(tvb, offset+soff, 1, "code");
                                }
                        } else if (strcmp(sFunc, "onPlayStatus")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 1, "code");
                        } else if (strcmp(sFunc, "_result")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 3, "code");
                                tp->isresponse = TRUE;
                        } else if (strcmp(sFunc, "_error")==0) {
                                sParam = rtmpt_get_amf_param(tvb, offset+soff, 3, "code");
                                tp->isresponse = TRUE;
                        }

                        if (tp->txid!=0 && tp->otherframe==0) {
                                tp->otherframe = GPOINTER_TO_INT(se_tree_lookup32(rconv->txids[cdir^1], tp->txid));
                                if (tp->otherframe) {
                                        RTMPT_DEBUG("got otherframe=%d\n", tp->otherframe);
                                }
                        }
                }

                if (sFunc) {
                        if (sParam) {
                                return ep_strdup_printf("%s('%s')", sFunc, sParam);
                        } else {
                                return ep_strdup_printf("%s()", sFunc);
                        }
                }
        }

        return NULL;
}


/* Tree dissection helpers for various packet body forms */

static void
dissect_rtmpt_body_scm(tvbuff_t *tvb, gint offset, proto_tree *rtmpt_tree, guint scm)
{
        switch (scm) {
        case RTMPT_TYPE_CHUNK_SIZE:
                proto_tree_add_item(rtmpt_tree, hf_rtmpt_scm_chunksize, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;
        case RTMPT_TYPE_ABORT_MESSAGE:
                proto_tree_add_item(rtmpt_tree, hf_rtmpt_scm_csid, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;
        case RTMPT_TYPE_ACKNOWLEDGEMENT:
                proto_tree_add_item(rtmpt_tree, hf_rtmpt_scm_seq, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;
        case RTMPT_TYPE_UCM:
                proto_tree_add_item(rtmpt_tree, hf_rtmpt_ucm_eventtype, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
        case RTMPT_TYPE_WINDOW:
                proto_tree_add_item(rtmpt_tree, hf_rtmpt_scm_was, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;
        case RTMPT_TYPE_PEER_BANDWIDTH:
                proto_tree_add_item(rtmpt_tree, hf_rtmpt_scm_was, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(rtmpt_tree, hf_rtmpt_scm_limittype, tvb, offset+4, 1, ENC_BIG_ENDIAN);
                break;
        }
}

static gint
dissect_amf0_value_type(tvbuff_t *tvb, gint offset, proto_tree *tree, gboolean *amf3_encoding, proto_item *parent_ti);

/*
 * A "property list" is a sequence of name/value pairs, terminated by
 * and "end of object" indicator.  AMF0 "object"s and "ECMA array"s
 * are encoded as property lists.
 */
static gint
dissect_amf0_property_list(tvbuff_t *tvb, gint offset, proto_tree *tree, guint *countp, gboolean *amf3_encoding)
{
        proto_item *prop_ti;
        proto_tree *prop_tree;
        proto_item *name_ti;
        proto_tree *name_tree;
        guint       iStringLength;
        gchar      *iStringValue;
        guint       count = 0;

        /*
         * XXX - at least as I read "3.1 AVM+ Type Marker" in the AMF0
         * specification, the AVM+ Type Marker only affects "the following
         * Object".  For now, we have a single "AMF3 encoding" flag, and
         * set it when we see the type marker, and never clear it.
         */
        for (;;) {
                /* UTF-8: property name */
                iStringLength = tvb_get_ntohs(tvb, offset);
                if (iStringLength == 0 &&
                    tvb_get_guint8(tvb, offset + 2) == AMF0_END_OF_OBJECT)
                        break;
                count++;
                iStringValue = tvb_get_ephemeral_string(tvb, offset + 2, iStringLength);
                prop_ti = proto_tree_add_text(tree, tvb, offset, -1,
                                              "Property '%s'",
                                              iStringValue);
                prop_tree = proto_item_add_subtree(prop_ti, ett_amf_property);

                name_ti = proto_tree_add_text(prop_tree, tvb,
                                              offset, 2+iStringLength,
                                              "Name: %s", iStringValue);
                name_tree = proto_item_add_subtree(name_ti, ett_amf_string);

                proto_tree_add_uint(name_tree, hf_amf_stringlength, tvb, offset, 2, iStringLength);
                offset += 2;
                proto_tree_add_item(name_tree, hf_amf_string, tvb, offset, iStringLength, ENC_UTF_8|ENC_NA);
                offset += iStringLength;

                /* value-type: property value */
                offset = dissect_amf0_value_type(tvb, offset, prop_tree, amf3_encoding, prop_ti);
                proto_item_set_end(prop_ti, tvb, offset);
        }
        proto_tree_add_text(tree, tvb, offset, 3, "End Of Object Marker");
        offset += 3;

        *countp = count;

        return offset;
}

static gint
dissect_amf0_value_type(tvbuff_t *tvb, gint offset, proto_tree *tree, gboolean *amf3_encoding, proto_item *parent_ti)
{
        guint8      iObjType;
        proto_item *ti;
        proto_tree *val_tree;
        gint        iValueOffset = offset;
        guint32     iIntegerValue;
        double      iDoubleValue;
        gboolean    iBooleanValue;
        guint       iStringLength;
        gchar      *iStringValue;
        guint       iArrayLength;
        guint       i;
        nstime_t    t;
        gint64      iInteger64Value;
        guint       count;

        iObjType = tvb_get_guint8(tvb, offset);
        if (parent_ti != NULL)
                proto_item_append_text(parent_ti, " %s",
                                       val_to_str_const(iObjType, amf0_type_vals, "Unknown"));
        switch (iObjType) {

        case AMF0_OBJECT:
                /*
                 * For object types, make the top-level protocol tree
                 * item a field for that type.
                 */
                ti = proto_tree_add_item(tree, hf_amf_object, tvb, offset, -1, ENC_NA);
                break;

        case AMF0_ECMA_ARRAY:
                /*
                 * For ECMA array types, make the top-level protocol tree
                 * item a field for that type.
                 */
                ti = proto_tree_add_item(tree, hf_amf_ecmaarray, tvb, offset, -1, ENC_NA);
                break;

        case AMF0_STRICT_ARRAY:
                /*
                 * For strict array types, make the top-level protocol tree
                 * item a field for that type.
                 */
                ti = proto_tree_add_item(tree, hf_amf_strictarray, tvb, offset, -1, ENC_NA);
                break;

        default:
                /*
                 * For all other types, make it just a text item; the
                 * field for that type will be used for the value.
                 */
                ti = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                                         val_to_str_const(iObjType, amf0_type_vals, "Unknown"));
                break;
        }

        val_tree = proto_item_add_subtree(ti, ett_amf_value);
        proto_tree_add_uint(val_tree, hf_amf_amf0_type, tvb, iValueOffset, 1, iObjType);
        iValueOffset++;

        switch (iObjType) {
        case AMF0_NUMBER:
                iDoubleValue = tvb_get_ntohieee_double(tvb, iValueOffset);
                proto_tree_add_double(val_tree, hf_amf_number, tvb, iValueOffset, 8, iDoubleValue);
                iValueOffset += 8;
                proto_item_append_text(ti, " %." STRINGIFY(DBL_DIG) "g", iDoubleValue);
                if (parent_ti != NULL)
                        proto_item_append_text(parent_ti, " %." STRINGIFY(DBL_DIG) "g", iDoubleValue);
                break;
        case AMF0_BOOLEAN:
                iBooleanValue = tvb_get_guint8(tvb, iValueOffset);
                proto_tree_add_boolean(val_tree, hf_amf_boolean, tvb, iValueOffset, 1, iBooleanValue);
                iValueOffset += 1;
                proto_item_append_text(ti, iBooleanValue ? " true" : " false");
                if (parent_ti != NULL)
                        proto_item_append_text(parent_ti, iBooleanValue ? " true" : " false");
                break;
        case AMF0_STRING:
                iStringLength = tvb_get_ntohs(tvb, iValueOffset);
                proto_tree_add_uint(val_tree, hf_amf_stringlength, tvb, iValueOffset, 2, iStringLength);
                iValueOffset += 2;
                iStringValue = tvb_get_ephemeral_string_enc(tvb, iValueOffset, iStringLength, ENC_UTF_8|ENC_NA);
                if (iStringLength != 0)
                        proto_tree_add_string(val_tree, hf_amf_string, tvb, iValueOffset, iStringLength, iStringValue);
                iValueOffset += iStringLength;
                proto_item_append_text(ti, " '%s'", iStringValue);
                if (parent_ti != NULL)
                        proto_item_append_text(parent_ti, " '%s'", iStringValue);
                break;
        case AMF0_OBJECT:
                iValueOffset = dissect_amf0_property_list(tvb, iValueOffset, val_tree, &count, amf3_encoding);
                proto_item_append_text(ti, " (%u items)", count);
                break;
        case AMF0_NULL:
        case AMF0_UNDEFINED:
                break;
        case AMF0_REFERENCE:
                iIntegerValue = tvb_get_ntohs(tvb, iValueOffset);
                proto_tree_add_uint(val_tree, hf_amf_object_reference, tvb, iValueOffset, 2, iIntegerValue);
                iValueOffset += 2;
                proto_item_append_text(ti, " %d", iIntegerValue);
                break;
        case AMF0_ECMA_ARRAY:
                /*
                 * Counted list type, with end marker. The count appears to be
                 * more of a hint than a rule, and is sometimes sent as 0 or
                 * invalid.
                 *
                 * Basically the same as OBJECT but with the extra count field.
                 * There being many strange encoders/metadata injectors out
                 * there, sometimes you see a valid count and no end marker.
                 * Figuring out which you've got for a deeply nested structure
                 * is non-trivial.
                 */
                iArrayLength = tvb_get_ntohl(tvb, iValueOffset);
                proto_tree_add_uint(val_tree, hf_amf_arraylength, tvb, iValueOffset, 4, iArrayLength);
                iValueOffset += 4;
                iValueOffset = dissect_amf0_property_list(tvb, iValueOffset, val_tree, &count, amf3_encoding);
                proto_item_append_text(ti, " (%u items)", count);
                break;
        case AMF0_END_OF_OBJECT:
                proto_tree_add_text(tree, tvb, iValueOffset, 3, "End Of Object Marker");
                iValueOffset += 3;
                break;
        case AMF0_STRICT_ARRAY:
                /*
                 * Counted list type, without end marker. Number of values
                 * is determined by count, values are assumed to form a
                 * [0..N-1] numbered array and are presented as plain AMF
                 * types, not OBJECT or ECMA_ARRAY style named properties.
                 */
                iArrayLength = tvb_get_ntohl(tvb, iValueOffset);
                proto_tree_add_uint(val_tree, hf_amf_arraylength, tvb, iValueOffset, 4, iArrayLength);
                iValueOffset += 4;
                for (i = 0; i < iArrayLength; i++)
                        iValueOffset = dissect_amf0_value_type(tvb, iValueOffset, val_tree, amf3_encoding, NULL);
                proto_item_append_text(ti, " (%u items)", iArrayLength);
                break;
        case AMF0_DATE:
                iDoubleValue = tvb_get_ntohieee_double(tvb, iValueOffset);
                t.secs = (time_t)(iDoubleValue/1000);
                t.nsecs = (int)((iDoubleValue - 1000*(double)t.secs) * 1000000);
                proto_tree_add_time(val_tree, hf_amf_date, tvb, iValueOffset, 8, &t);
                iValueOffset += 8;
                proto_item_append_text(ti, " %s", abs_time_to_str(&t, ABSOLUTE_TIME_LOCAL, TRUE));
                if (parent_ti != NULL)
                        proto_item_append_text(parent_ti, " %s", abs_time_to_str(&t, ABSOLUTE_TIME_LOCAL, TRUE));
                /* time-zone */
                iValueOffset += 2;
                break;
        case AMF0_LONG_STRING:
        case AMF0_XML: /* same representation */
                iStringLength = tvb_get_ntohl(tvb, iValueOffset);
                proto_tree_add_uint(val_tree, hf_amf_stringlength, tvb, iValueOffset, 2, iStringLength);
                iValueOffset += 4;
                iStringValue = tvb_get_ephemeral_string_enc(tvb, iValueOffset, iStringLength, ENC_UTF_8|ENC_NA);
                if (iStringLength != 0)
                        proto_tree_add_string(val_tree, (iObjType==AMF0_XML) ? hf_amf_xml_doc : hf_amf_longstring, tvb, iValueOffset, iStringLength, iStringValue);
                iValueOffset += iStringLength;
                proto_item_append_text(ti, " '%s'", iStringValue);
                if (parent_ti != NULL)
                        proto_item_append_text(parent_ti, " '%s'", iStringValue);
                break;
        case AMF0_UNSUPPORTED:
                break;
        case AMF0_TYPED_OBJECT:
                /* class-name */
                iStringLength = tvb_get_ntohs(tvb, iValueOffset);
                proto_tree_add_uint(val_tree, hf_amf_stringlength, tvb, iValueOffset, 2, iStringLength);
                iValueOffset += 2;
                iStringValue = tvb_get_ephemeral_string_enc(tvb, iValueOffset, iStringLength, ENC_UTF_8|ENC_NA);
                proto_tree_add_string(val_tree, hf_amf_string, tvb, iValueOffset, iStringLength, iStringValue);
                iValueOffset += iStringLength;
                iValueOffset = dissect_amf0_property_list(tvb, iValueOffset, val_tree, &count, amf3_encoding);
                break;
        case AMF0_AMF3_MARKER:
                *amf3_encoding = TRUE;
                break;
        case AMF0_INT64:
                iInteger64Value = tvb_get_ntoh64(tvb, iValueOffset);
                proto_tree_add_int64(val_tree, hf_amf_int64, tvb, iValueOffset, 8, iInteger64Value);
                iValueOffset += 8;
                proto_item_append_text(ti," %" G_GINT64_MODIFIER "d", iInteger64Value);
                if (parent_ti != NULL)
                        proto_item_append_text(parent_ti," %" G_GINT64_MODIFIER "d", iInteger64Value);
                break;
        default:
                /*
                 * If we can't determine the length, don't carry on;
                 * just skip to the end of the tvbuff.
                 */
                iValueOffset = tvb_length(tvb);
                break;
        }
        proto_item_set_end(ti, tvb, iValueOffset);
        return iValueOffset;
}

static guint32
amf_get_u29(tvbuff_t *tvb, int offset, guint *lenp)
{
        guint      len = 0;
        guint8     iByte;
        guint32    iValue;

        iByte = tvb_get_guint8(tvb, offset);
        iValue = (iByte & 0x7F);
        offset++;
        len++;
        if (!(iByte & 0x80)) {
                /* 1 byte value */
                *lenp = len;
                return iValue;
        }
        iByte = tvb_get_guint8(tvb, offset);
        iValue = (iValue << 7) | (iByte & 0x7F);
        offset++;
        len++;
        if (!(iByte & 0x80)) {
                /* 2 byte value */
                *lenp = len;
                return iValue;
        }
        iByte = tvb_get_guint8(tvb, offset);
        iValue = (iValue << 7) | (iByte & 0x7F);
        offset++;
        len++;
        if (!(iByte & 0x80)) {
                /* 3 byte value */
                *lenp = len;
                return iValue;
        }
        iByte = tvb_get_guint8(tvb, offset);
        iValue = (iValue << 8) | iByte;
        len++;
        *lenp = len;
        return iValue;
}

static gint
dissect_amf3_value_type(tvbuff_t *tvb, gint offset, proto_tree *tree, proto_item *parent_ti)
{
        guint8      iObjType;
        proto_item *ti;
        proto_tree *val_tree;
        gint        iValueOffset = offset;
        guint       iValueLength;
        guint32     iIntegerValue;
        double      iDoubleValue;
        guint       iStringLength;
        gchar      *iStringValue;
        guint       iArrayLength;
        proto_item *subval_ti;
        proto_tree *subval_tree;
        guint       i;
        gboolean    iTypeIsDynamic;
        guint       iTraitCount;
        proto_item *traits_ti;
        proto_tree *traits_tree;
        proto_item *name_ti;
        proto_tree *name_tree;
        proto_item *member_ti;
        proto_tree *member_tree;
        guint8     *iByteArrayValue;

        iObjType = tvb_get_guint8(tvb, offset);
        if (parent_ti != NULL)
                proto_item_append_text(parent_ti, " %s",
                                       val_to_str_const(iObjType, amf3_type_vals, "Unknown"));
        switch (iObjType) {

        case AMF3_ARRAY:
                /*
                 * For array types, make the top-level protocol tree
                 * item a field for that type.
                 */
                ti = proto_tree_add_item(tree, hf_amf_array, tvb, offset, -1, ENC_NA);
                break;

        case AMF3_OBJECT:
                /*
                 * For object types, make the top-level protocol tree
                 * item a field for that type.
                 */
                ti = proto_tree_add_item(tree, hf_amf_object, tvb, offset, -1, ENC_NA);
                break;

        default:
                /*
                 * For all other types, make it just a text item; the
                 * field for that type will be used for the value.
                 */
                ti = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                                         val_to_str_const(iObjType, amf3_type_vals, "Unknown"));
                break;
        }

        val_tree = proto_item_add_subtree(ti, ett_amf_value);
        proto_tree_add_uint(val_tree, hf_amf_amf3_type, tvb, iValueOffset, 1, iObjType);
        iValueOffset++;

        switch (iObjType) {
        case AMF3_UNDEFINED:
        case AMF3_NULL:
                break;
        case AMF3_FALSE:
                proto_tree_add_boolean(val_tree, hf_amf_boolean, tvb, 0, 0, FALSE);
                proto_item_append_text(ti, " false");
                break;
        case AMF3_TRUE:
                proto_tree_add_boolean(val_tree, hf_amf_boolean, tvb, 0, 0, TRUE);
                proto_item_append_text(ti, " true");
                break;
        case AMF3_INTEGER:
                /* XXX - signed or unsigned? */
                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                proto_tree_add_uint(val_tree, hf_amf_integer, tvb, iValueOffset, iValueLength, iIntegerValue);
                proto_item_append_text(ti, " %u", iIntegerValue);
                if (parent_ti != NULL)
                        proto_item_append_text(parent_ti, " %u", iIntegerValue);
                iValueOffset += iValueLength;
                break;
        case AMF3_DOUBLE:
                iDoubleValue = tvb_get_ntohieee_double(tvb, iValueOffset);
                proto_tree_add_double(val_tree, hf_amf_number, tvb, iValueOffset, 8, iDoubleValue);
                iValueOffset += 8;
                proto_item_append_text(ti, " %." STRINGIFY(DBL_DIG) "g", iDoubleValue);
                if (parent_ti != NULL)
                        proto_item_append_text(parent_ti, " %." STRINGIFY(DBL_DIG) "g", iDoubleValue);
                break;
        case AMF3_STRING:
                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                if (iIntegerValue & 0x00000001) {
                        /* the upper 28 bits of the integer value is a string length */
                        iStringLength = iIntegerValue >> 1;
                        proto_tree_add_uint(val_tree, hf_amf_stringlength, tvb, iValueOffset, iValueLength, iStringLength);
                        iValueOffset += iValueLength;
                        iStringValue = tvb_get_ephemeral_string_enc(tvb, iValueOffset, iStringLength, ENC_UTF_8|ENC_NA);
                        if (iStringLength != 0)
                                proto_tree_add_string(val_tree, hf_amf_string, tvb, iValueOffset, iStringLength, iStringValue);
                        iValueOffset += iStringLength;
                        proto_item_append_text(ti, " '%s'", iStringValue);
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, " '%s'", iStringValue);
                } else {
                        /* the upper 28 bits of the integer value are a string reference index */
                        proto_tree_add_uint(val_tree, hf_amf_string_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                        iValueOffset += iValueLength;
                        proto_item_append_text(ti, " reference %u", iIntegerValue >> 1);
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, " reference %u", iIntegerValue >> 1);
                }
                break;
        case AMF3_DATE:
                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                if (iIntegerValue & 0x00000001) {
                        /*
                         * The upper 28 bits of the integer value are
                         * ignored; what follows is a double
                         * containing milliseconds since the Epoch.
                         */
                        nstime_t t;

                        iValueOffset += iValueLength;
                        iDoubleValue = tvb_get_ntohieee_double(tvb, iValueOffset);
                        t.secs = (time_t)(iDoubleValue/1000);
                        t.nsecs = (int)((iDoubleValue - 1000*(double)t.secs) * 1000000);
                        proto_tree_add_time(val_tree, hf_amf_date, tvb, iValueOffset, 8, &t);
                        iValueOffset += 8;
                        proto_item_append_text(ti, "%s", abs_time_to_str(&t, ABSOLUTE_TIME_LOCAL, TRUE));
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, "%s", abs_time_to_str(&t, ABSOLUTE_TIME_LOCAL, TRUE));
                } else {
                        /* the upper 28 bits of the integer value are an object reference index */
                        proto_tree_add_uint(val_tree, hf_amf_object_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                        iValueOffset += iValueLength;
                        proto_item_append_text(ti, " object reference %u", iIntegerValue >> 1);
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, " object reference %u", iIntegerValue >> 1);
                }
                break;
        case AMF3_ARRAY:
                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                if (iIntegerValue & 0x00000001) {
                        /*
                         * The upper 28 bits of the integer value are
                         * a count of the number of elements in
                         * the dense portion of the array.
                         */
                        iArrayLength = iIntegerValue >> 1;
                        proto_tree_add_uint(val_tree, hf_amf_arraydenselength, tvb, iValueOffset, iValueLength, iArrayLength);
                        iValueOffset += iValueLength;

                        /*
                         * The AMF3 spec bit on the Array type is slightly
                         * confusingly written, but seems to be saying that
                         * the associative portion of the array follows the
                         * size of the dense portion of the array, and the
                         * dense portion of the array follows the associative
                         * portion.
                         *
                         * Dissect the associative portion.
                         */
                        for (;;) {
                                /* Fetch the name */
                                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                                if (iIntegerValue & 0x00000001) {
                                        /* the upper 28 bits of the integer value is a string length */
                                        iStringLength = iIntegerValue >> 1;
                                        if (iStringLength == 0) {
                                                /* null name marks the end of the associative part */
                                                proto_tree_add_text(val_tree, tvb, iValueOffset, iValueLength, "End of associative part");
                                                iValueOffset += iValueLength;
                                                break;
                                        }
                                        iStringValue = tvb_get_ephemeral_string_enc(tvb, iValueOffset+iValueLength, iStringLength, ENC_UTF_8|ENC_NA);
                                        subval_ti = proto_tree_add_text(val_tree, tvb, iValueOffset, iStringLength, "%s:", iStringValue);
                                        subval_tree = proto_item_add_subtree(subval_ti, ett_amf_array_element);
                                        proto_tree_add_uint(subval_tree, hf_amf_stringlength, tvb, iValueOffset, iValueLength, iStringLength);
                                        iValueOffset += iValueLength;
                                        proto_tree_add_string(subval_tree, hf_amf_string, tvb, iValueOffset, iStringLength, iStringValue);
                                } else {
                                        /* the upper 28 bits of the integer value are a string reference index */
                                        subval_ti = proto_tree_add_text(val_tree, tvb, iValueOffset, iValueLength, "Reference %u:", iIntegerValue >> 1);
                                        subval_tree = proto_item_add_subtree(subval_ti, ett_amf_array_element);
                                        proto_tree_add_uint(subval_tree, hf_amf_string_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                                }

                                /* Fetch the value */
                                iObjType = tvb_get_guint8(tvb, offset);
                                proto_item_append_text(subval_ti, "%s",
                                                       val_to_str_const(iObjType, amf3_type_vals, "Unknown"));

                                iValueOffset = dissect_amf3_value_type(tvb, iValueOffset, subval_tree, subval_ti);
                        }

                        /*
                         * Dissect the dense portion.
                         */
                        for (i = 0; i < iArrayLength; i++)
                                iValueOffset = dissect_amf3_value_type(tvb, iValueOffset, val_tree, NULL);

                        proto_item_set_end(ti, tvb, iValueOffset);
                } else {
                        /* the upper 28 bits of the integer value are an object reference index */
                        proto_tree_add_uint(val_tree, hf_amf_object_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                        proto_item_append_text(ti, " reference %u", iIntegerValue >> 1);
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, " reference %u", iIntegerValue >> 1);
                }
                break;
        case AMF3_OBJECT:
                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                if (iIntegerValue & 0x00000001) {
                        if (iIntegerValue & 0x00000002) {
                                if (iIntegerValue & 0x00000004) {
                                        /*
                                         * U29O-traits-ext; the rest of
                                         * iIntegerValue is not significant,
                                         * and, worse, we have idea what
                                         * follows the class name, or even
                                         * how many bytes follow the class
                                         * name - that's by convention between
                                         * the client and server.
                                         */
                                        iValueOffset += iValueLength;
                                } else {
                                        /*
                                         * U29O-traits; the 0x00000008 bit
                                         * specifies whether the type is
                                         * dynamic.
                                         */
                                        iTypeIsDynamic = (iIntegerValue & 0x00000008) ? TRUE : FALSE;
                                        iTraitCount = iIntegerValue >> 4;
                                        proto_tree_add_uint(val_tree, hf_amf_traitcount, tvb, iValueOffset, iValueLength, iTraitCount);
                                        iValueOffset += iValueLength;
                                        iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                                        if (iIntegerValue & 0x00000001) {
                                                /* the upper 28 bits of the integer value is a string length */
                                                iStringLength = iIntegerValue >> 1;
                                                iStringValue = tvb_get_ephemeral_string_enc(tvb, iValueOffset+iValueLength, iStringLength, ENC_UTF_8|ENC_NA);
                                                traits_ti = proto_tree_add_text(val_tree, tvb, iValueOffset, -1, "Traits for class %s (%u member names)", iStringValue, iTraitCount);
                                                traits_tree = proto_item_add_subtree(traits_ti, ett_amf_traits);
                                                name_ti = proto_tree_add_text(traits_tree, tvb,
                                                                              iValueOffset,
                                                                              iValueLength+iStringLength,
                                                                              "Class name: %s",
                                                                              iStringValue);
                                                name_tree = proto_item_add_subtree(name_ti, ett_amf_string);
                                                proto_tree_add_uint(name_tree, hf_amf_classnamelength, tvb, iValueOffset, iValueLength, iStringLength);
                                                iValueOffset += iValueLength;
                                                proto_tree_add_string(name_tree, hf_amf_classname, tvb, iValueOffset, iStringLength, iStringValue);
                                                iValueOffset += iStringLength;
                                        } else {
                                                /* the upper 28 bits of the integer value are a string reference index */
                                                traits_ti = proto_tree_add_text(val_tree, tvb, iValueOffset, iValueLength, "Traits for class (reference %u for name)", iIntegerValue >> 1);
                                                traits_tree = proto_item_add_subtree(traits_ti, ett_amf_traits);
                                                proto_tree_add_uint(traits_tree, hf_amf_string_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                                                iValueOffset += iValueLength;
                                        }
                                        for (i = 0; i < iTraitCount; i++) {
                                                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                                                if (iIntegerValue & 0x00000001) {
                                                        /* the upper 28 bits of the integer value is a string length */
                                                        iStringLength = iIntegerValue >> 1;
                                                        iStringValue = tvb_get_ephemeral_string_enc(tvb, iValueOffset+iValueLength, iStringLength, ENC_UTF_8|ENC_NA);
                                                        member_ti = proto_tree_add_text(traits_tree, tvb, iValueOffset, iValueLength+iStringLength, "Member '%s'", iStringValue);
                                                        member_tree = proto_item_add_subtree(member_ti, ett_amf_trait_member);
                                                        proto_tree_add_uint(member_tree, hf_amf_membernamelength, tvb, iValueOffset, iValueLength, iStringLength);
                                                        iValueOffset += iValueLength;
                                                        proto_tree_add_string(member_tree, hf_amf_membername, tvb, iValueOffset, iStringLength, iStringValue);
                                                        iValueOffset += iStringLength;
                                                } else {
                                                        /* the upper 28 bits of the integer value are a string reference index */
                                                        proto_tree_add_uint(traits_tree, hf_amf_string_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                                                        iValueOffset += iValueLength;
                                                }
                                        }
                                        for (i = 0; i < iTraitCount; i++)
                                                iValueOffset = dissect_amf3_value_type(tvb, iValueOffset, traits_tree, NULL);
                                        if (iTypeIsDynamic) {
                                        	for (;;) {
                                                        /* Fetch the name */
                                                        iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                                                        if (iIntegerValue & 0x00000001) {
                                                                /* the upper 28 bits of the integer value is a string length */
                                                                iStringLength = iIntegerValue >> 1;
                                                                if (iStringLength == 0) {
                                                                        /* null name marks the end of the associative part */
                                                                        proto_tree_add_text(traits_tree, tvb, iValueOffset, iValueLength, "End of dynamic members");
                                                                        iValueOffset += iValueLength;
                                                                        break;
                                                                }
                                                                iStringValue = tvb_get_ephemeral_string_enc(tvb, iValueOffset+iValueLength, iStringLength, ENC_UTF_8|ENC_NA);
                                                                subval_ti = proto_tree_add_text(traits_tree, tvb, iValueOffset, -1, "%s:", iStringValue);
                                                                subval_tree = proto_item_add_subtree(subval_ti, ett_amf_array_element);
                                                                name_ti = proto_tree_add_text(subval_tree, tvb,
                                                                                              iValueOffset,
                                                                                              iValueLength+iStringLength,
                                                                                              "Member name: %s",
                                                                                              iStringValue);
                                                                name_tree = proto_item_add_subtree(name_ti, ett_amf_string);
                                                                proto_tree_add_uint(name_tree, hf_amf_membernamelength, tvb, iValueOffset, iValueLength, iStringLength);
                                                                iValueOffset += iValueLength;
                                                                proto_tree_add_string(name_tree, hf_amf_membername, tvb, iValueOffset, iStringLength, iStringValue);
                                                                iValueOffset += iStringLength;
                                                        } else {
                                                                /* the upper 28 bits of the integer value are a string reference index */
                                                                subval_ti = proto_tree_add_text(traits_tree, tvb, iValueOffset, iValueLength, "Reference %u:", iIntegerValue >> 1);
                                                                subval_tree = proto_item_add_subtree(subval_ti, ett_amf_array_element);
                                                                proto_tree_add_uint(subval_tree, hf_amf_string_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                                                                iValueOffset += iValueLength;
                                    	                }

                                                        /* Fetch the value */
                                                        iValueOffset = dissect_amf3_value_type(tvb, iValueOffset, subval_tree, subval_ti);
                                                        proto_item_set_end(subval_ti, tvb, iValueOffset);
                                                }
                                        }
                                        proto_item_set_end(traits_ti, tvb, iValueOffset);
                                }
                        } else {
                                /*
                                 * U29O-traits-ref; the upper 27 bits of
                                 * the integer value are a traits reference
                                 * index.
                                 */
                                proto_tree_add_uint(val_tree, hf_amf_trait_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 2);
                                iValueOffset += iValueLength;
                        }
                } else {
                        /*
                         * U29O-ref; the upper 28 bits of the integer value
                         * are an object reference index.
                         */
                        proto_tree_add_uint(val_tree, hf_amf_object_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                        proto_item_append_text(ti, " reference %u", iIntegerValue >> 1);
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, " reference %u", iIntegerValue >> 1);
                }
                break;
        case AMF3_XML:
                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                if (iIntegerValue & 0x00000001) {
                        /*
                         * The upper 28 bits of the integer value are
                         * a count of the number of bytes in the
                         * XML string.
                         */
                        iStringLength = iIntegerValue >> 1;
                        proto_tree_add_uint(val_tree, hf_amf_xmllength, tvb, iValueOffset, iValueLength, iStringLength);
                        iValueOffset += iValueLength;
                        proto_tree_add_item(val_tree, hf_amf_xml, tvb, iValueOffset, iStringLength, ENC_UTF_8|ENC_NA);
                } else {
                        /* the upper 28 bits of the integer value are a string reference index */
                        proto_tree_add_uint(val_tree, hf_amf_object_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                        proto_item_append_text(ti, " reference %u", iIntegerValue >> 1);
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, " reference %u", iIntegerValue >> 1);
                }
                break;
        case AMF3_BYTEARRAY:
                iIntegerValue = amf_get_u29(tvb, iValueOffset, &iValueLength);
                if (iIntegerValue & 0x00000001) {
                        /*
                         * The upper 28 bits of the integer value are
                         * a count of the number of bytes in the
                         * byte array.
                         */
                        iArrayLength = iIntegerValue >> 1;
                        proto_tree_add_uint(val_tree, hf_amf_bytearraylength, tvb, iValueOffset, iValueLength, iArrayLength);
                        iValueOffset += iValueLength;
                        iByteArrayValue = ep_tvb_memdup(tvb, iValueOffset, iArrayLength);
                        proto_tree_add_bytes(val_tree, hf_amf_bytearray, tvb, iValueOffset, iArrayLength, iByteArrayValue);
                        proto_item_append_text(ti, " %s", bytes_to_str(iByteArrayValue, iArrayLength));
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, " %s", bytes_to_str(iByteArrayValue, iArrayLength));
                } else {
                        /* the upper 28 bits of the integer value are a object reference index */
                        proto_tree_add_uint(val_tree, hf_amf_object_reference, tvb, iValueOffset, iValueLength, iIntegerValue >> 1);
                        proto_item_append_text(ti, " reference %u", iIntegerValue >> 1);
                        if (parent_ti != NULL)
                                proto_item_append_text(parent_ti, " reference %u", iIntegerValue >> 1);
                }
                break;
        default:
                /*
                 * If we can't determine the length, don't carry on;
                 * just skip to the end of the tvbuff.
                 */
                iValueOffset = tvb_length(tvb);
                break;
        }
        proto_item_set_end(ti, tvb, iValueOffset);
        return iValueOffset;
}

static gint
dissect_rtmpt_body_command(tvbuff_t *tvb, gint offset, proto_tree *rtmpt_tree, gboolean amf3)
{
        gboolean    amf3_encoding = FALSE;

        if (amf3) {
                /* Looks like for the AMF3 variants we get a 0 byte here,
                 * followed by AMF0 encoding - I've never seen actual AMF3
                 * encoding used, which is completely different. I speculate
                 * that if the byte is AMF0_AMF3_MARKER then the rest
                 * will be in AMF3. For now, assume AMF0 only. */
                offset++;
        }

        while (tvb_reported_length_remaining(tvb, offset) > 0)
        {
                if (amf3_encoding)
                        offset = dissect_amf3_value_type(tvb, offset, rtmpt_tree, NULL);
                else
                        offset = dissect_amf0_value_type(tvb, offset, rtmpt_tree, &amf3_encoding, NULL);
        }
        return offset;
}

static void
dissect_rtmpt_body_audio(tvbuff_t *tvb, gint offset, proto_tree *rtmpt_tree)
{
        guint8      iCtl;
        proto_item *ai;
        proto_tree *at;

        iCtl = tvb_get_guint8(tvb, offset);
        ai = proto_tree_add_uint_format(rtmpt_tree, hf_rtmpt_audio_control, tvb, offset, 1, iCtl,
                                        "Control: 0x%02x (%s %s %s %s)", iCtl,
                                        val_to_str_const((iCtl & 0xf0)>>4, rtmpt_audio_codecs, "Unknown codec"),
                                        val_to_str_const((iCtl & 0x0c)>>2, rtmpt_audio_rates, "Unknown rate"),
                                        val_to_str_const((iCtl & 0x02)>>1, rtmpt_audio_sizes, "Unknown sample size"),
                                        val_to_str_const(iCtl & 0x01, rtmpt_audio_types, "Unknown channel count"));

        at = proto_item_add_subtree(ai, ett_rtmpt_audio_control);
        proto_tree_add_uint(at, hf_rtmpt_audio_format, tvb, offset, 1, iCtl);
        proto_tree_add_uint(at, hf_rtmpt_audio_rate, tvb, offset, 1, iCtl);
        proto_tree_add_uint(at, hf_rtmpt_audio_size, tvb, offset, 1, iCtl);
        proto_tree_add_uint(at, hf_rtmpt_audio_type, tvb, offset, 1, iCtl);
        proto_tree_add_item(rtmpt_tree, hf_rtmpt_audio_data, tvb, offset+1, -1, ENC_NA);
}

static void
dissect_rtmpt_body_video(tvbuff_t *tvb, gint offset, proto_tree *rtmpt_tree)
{
        guint8      iCtl;
        proto_item *vi;
        proto_tree *vt;

        iCtl = tvb_get_guint8(tvb, offset);
        vi = proto_tree_add_uint_format(rtmpt_tree, hf_rtmpt_video_control, tvb, offset, 1, iCtl,
                                        "Control: 0x%02x (%s %s)", iCtl,
                                        val_to_str_const((iCtl & 0xf0)>>4, rtmpt_video_types, "Unknown frame type"),
                                        val_to_str_const(iCtl & 0x0f, rtmpt_video_codecs, "Unknown codec"));

        vt = proto_item_add_subtree(vi, ett_rtmpt_video_control);
        proto_tree_add_uint(vt, hf_rtmpt_video_type, tvb, offset, 1, iCtl);
        proto_tree_add_uint(vt, hf_rtmpt_video_format, tvb, offset, 1, iCtl);
        proto_tree_add_item(rtmpt_tree, hf_rtmpt_video_data, tvb, offset+1, -1, ENC_NA);
}

static void
dissect_rtmpt_body_aggregate(tvbuff_t *tvb, gint offset, proto_tree *rtmpt_tree)
{
        proto_item *tag_item  = NULL;
        proto_tree *tag_tree  = NULL;

        proto_item *data_item = NULL;
        proto_tree *data_tree = NULL;

        while (tvb_length_remaining(tvb, offset) > 0) {
                guint8 iTagType;
                guint iDataSize;

                iTagType = tvb_get_guint8(tvb, offset + 0);
                iDataSize = tvb_get_ntoh24(tvb, offset + 1);

                tag_item = proto_tree_add_text(rtmpt_tree, tvb, offset, 11+iDataSize+4, "%s",
                                               val_to_str_const(iTagType, rtmpt_tag_vals, "Unknown Tag"));
                tag_tree = proto_item_add_subtree(tag_item, ett_rtmpt_tag);
                proto_tree_add_item(tag_tree, hf_rtmpt_tag_type, tvb, offset+0, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tag_tree, hf_rtmpt_tag_datasize, tvb, offset+1, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(tag_tree, hf_rtmpt_tag_timestamp, tvb, offset+4, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(tag_tree, hf_rtmpt_tag_ets, tvb, offset+7, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tag_tree, hf_rtmpt_tag_streamid, tvb, offset+8, 3, ENC_BIG_ENDIAN);

                data_item = proto_tree_add_text(tag_tree, tvb, offset+11, iDataSize, "Data");
                data_tree = proto_item_add_subtree(data_item, ett_rtmpt_tag_data);

                switch (iTagType) {
                case 8:
                        dissect_rtmpt_body_audio(tvb, offset + 11, data_tree);
                        break;
                case 9:
                        dissect_rtmpt_body_video(tvb, offset + 11, data_tree);
                        break;
                case 18:
                        dissect_rtmpt_body_command(tvb, offset + 11, data_tree, FALSE);
                        break;
                default:
                        break;
                }

                proto_tree_add_item(tag_tree, hf_rtmpt_tag_tagsize, tvb, offset+11+iDataSize, 4, ENC_BIG_ENDIAN);
                offset += 11 + iDataSize + 4;
        }
}

/* The main dissector for unchunked packets */

static void
dissect_rtmpt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, rtmpt_conv_t *rconv, int cdir, rtmpt_packet_t *tp)
{
        proto_tree   *rtmpt_tree           = NULL;
        proto_tree   *rtmptroot_tree       = NULL;
        proto_item   *ti                   = NULL;
        static guint  iPreviousFrameNumber = 0;
        gint          offset               = 0;

        gchar        *sDesc                = NULL;
        gint          deschasopcode        = FALSE;
        gboolean      haveETS              = FALSE;
        guint32       iBodyOffset          = 0;
        guint32       iBodyRemain          = 0;

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTMP");

        RTMPT_DEBUG("Dissect: frame=%u prev=%u visited=%d len=%d col=%d tree=%p\n",
                    pinfo->fd->num, iPreviousFrameNumber, pinfo->fd->flags.visited,
                    tvb_length_remaining(tvb, offset), check_col(pinfo->cinfo, COL_INFO), tree);

        /* This is a trick to know whether this is the first PDU in this packet or not */
        if (iPreviousFrameNumber != PINFO_FD_NUM(pinfo))
                col_clear(pinfo->cinfo, COL_INFO);
        else
                col_append_str(pinfo->cinfo, COL_INFO, " | ");
        iPreviousFrameNumber = pinfo->fd->num;

        if (tvb_length_remaining(tvb, offset) < 1) return;

        if (tp->id<=RTMPT_ID_MAX) {
                if (tp->fmt<3
                    && tvb_length_remaining(tvb, offset)>=tp->bhlen+3
                    && tvb_get_ntoh24(tvb, offset+tp->bhlen)==0xffffff) {
                        haveETS = TRUE;
                }

                iBodyOffset = offset + tp->bhlen + tp->mhlen;
                iBodyRemain = tvb_length_remaining(tvb, iBodyOffset);

                if (tp->cmd==RTMPT_TYPE_CHUNK_SIZE && tp->len>=4 && iBodyRemain>=4) {
                        guint32 newchunksize = tvb_get_ntohl(tvb, iBodyOffset);
                        if (newchunksize<RTMPT_MAX_PACKET_SIZE) {
                                se_tree_insert32(rconv->chunksize[cdir], tp->lastseq, GINT_TO_POINTER(newchunksize));
                        }
                }

                if (!PINFO_FD_VISITED(pinfo)) {
                        if (tp->cmd==RTMPT_TYPE_COMMAND_AMF0 || tp->cmd==RTMPT_TYPE_COMMAND_AMF3 ||
                            tp->cmd==RTMPT_TYPE_DATA_AMF0 || tp->cmd==RTMPT_TYPE_DATA_AMF3) {
                                guint32 soff = 0;
                                if (tp->cmd==RTMPT_TYPE_COMMAND_AMF3 || tp->cmd==RTMPT_TYPE_DATA_AMF3) {
                                        soff = 1;
                                }
                                tp->txid = rtmpt_get_amf_txid(tvb, iBodyOffset+soff);
                                if (tp->txid!=0) {
                                        RTMPT_DEBUG("got txid=%d\n", tp->txid);
                                        se_tree_insert32(rconv->txids[cdir], tp->txid, GINT_TO_POINTER(pinfo->fd->num));
                                }
                        }
                }
        }

        if ((check_col(pinfo->cinfo, COL_INFO) || tree) && tp->id<=RTMPT_ID_MAX)
        {
                sDesc = rtmpt_get_packet_desc(tvb, iBodyOffset, iBodyRemain, rconv, cdir, tp, &deschasopcode);
        }

        if (check_col(pinfo->cinfo, COL_INFO))
        {
                if (tp->id>RTMPT_ID_MAX) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                                        val_to_str(tp->id, rtmpt_handshake_vals, "Unknown (0x%01x)"));
                } else if (sDesc) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s", sDesc);
                } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                                        val_to_str(tp->cmd, rtmpt_opcode_vals, "Unknown (0x%01x)"));
                }
        }

        if (tree)
        {
                ti = proto_tree_add_item(tree, proto_rtmpt, tvb, offset, -1, ENC_NA);

                if (tp->id>RTMPT_ID_MAX) {
                        /* Dissect handshake */
                        proto_item_append_text(ti, " (%s)",
                                               val_to_str(tp->id, rtmpt_handshake_vals, "Unknown (0x%01x)"));
                        rtmptroot_tree = proto_item_add_subtree(ti, ett_rtmpt);
                        ti = proto_tree_add_text(rtmptroot_tree, tvb, offset, -1, "%s",
                                                 val_to_str(tp->id, rtmpt_handshake_vals, "Unknown (0x%01x)"));
                        rtmpt_tree = proto_item_add_subtree(ti, ett_rtmpt_handshake);

                        if (tp->id == RTMPT_TYPE_HANDSHAKE_1)
                        {
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_c0, tvb, 0, 1, ENC_NA);
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_c1, tvb, 1, 1536, ENC_NA);
                        }
                        else if (tp->id == RTMPT_TYPE_HANDSHAKE_2)
                        {
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_s0, tvb, 0, 1, ENC_NA);
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_s1, tvb, 1, 1536, ENC_NA);
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_s2, tvb, 1537, 1536, ENC_NA);
                        }
                        else if (tp->id == RTMPT_TYPE_HANDSHAKE_3)
                        {
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_handshake_c2, tvb, 0, 1536, ENC_NA);
                        }

                        return;
                }

                if (sDesc && deschasopcode) {
                        proto_item_append_text(ti, " (%s)", sDesc);
                } else if (sDesc) {
                        proto_item_append_text(ti, " (%s %s)",
                                               val_to_str(tp->cmd, rtmpt_opcode_vals, "Unknown (0x%01x)"), sDesc);
                } else {
                        proto_item_append_text(ti, " (%s)",
                                               val_to_str(tp->cmd, rtmpt_opcode_vals, "Unknown (0x%01x)"));
                }
                rtmptroot_tree = proto_item_add_subtree(ti, ett_rtmpt);

                /* Function call/response matching */
                if (tp->otherframe!=0) {
                        proto_tree_add_uint(rtmptroot_tree,
                                            tp->isresponse ? hf_rtmpt_function_response : hf_rtmpt_function_call,
                                            tvb, offset, tp->bhlen+tp->mhlen+tp->len,
                                            tp->otherframe);
                }

                /* Dissect header fields */
                ti = proto_tree_add_text(rtmptroot_tree, tvb, offset, tp->bhlen+tp->mhlen, RTMPT_TEXT_RTMP_HEADER);
/*                proto_item_append_text(ti, " (%s)", val_to_str(tp->cmd, rtmpt_opcode_vals, "Unknown (0x%01x)")); */
                rtmpt_tree = proto_item_add_subtree(ti, ett_rtmpt_header);

                if (tp->fmt <= 3) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_format, tvb, offset + 0, 1, ENC_BIG_ENDIAN);
                if (tp->fmt <= 3) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_csid, tvb, offset + 0, tp->bhlen, ENC_BIG_ENDIAN);
                if (tp->fmt <= 2) {
                        if (tp->fmt>0) {
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_timestamp_delta, tvb, offset + tp->bhlen, 3, ENC_BIG_ENDIAN);
                        } else {
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_timestamp, tvb, offset + tp->bhlen, 3, ENC_BIG_ENDIAN);
                        }
                        if (haveETS) {
                                proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_ets, tvb, offset + tp->bhlen + tp->mhlen - 4, 4, ENC_BIG_ENDIAN);
                        }
                }
                if ((tp->fmt>0 && !haveETS) || tp->fmt==3) {
                        proto_tree_add_text(rtmpt_tree, tvb, offset + tp->bhlen, 0, "Timestamp: %d (calculated)", tp->ts);
                }
                if (tp->fmt <= 1) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_body_size, tvb, offset + tp->bhlen + 3, 3, ENC_BIG_ENDIAN);
                if (tp->fmt <= 1) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_typeid, tvb, offset + tp->bhlen + 6, 1, ENC_BIG_ENDIAN);
                if (tp->fmt <= 0) proto_tree_add_item(rtmpt_tree, hf_rtmpt_header_streamid, tvb, offset + tp->bhlen + 7, 4, ENC_LITTLE_ENDIAN);

                /* Dissect body */
                if (tp->len==0) return;
                offset = iBodyOffset;

                ti = proto_tree_add_text(rtmptroot_tree, tvb, offset, -1, RTMPT_TEXT_RTMP_BODY);
                rtmpt_tree = proto_item_add_subtree(ti, ett_rtmpt_body);

                switch (tp->cmd) {
                case RTMPT_TYPE_CHUNK_SIZE:
                case RTMPT_TYPE_ABORT_MESSAGE:
                case RTMPT_TYPE_ACKNOWLEDGEMENT:
                case RTMPT_TYPE_UCM:
                case RTMPT_TYPE_WINDOW:
                case RTMPT_TYPE_PEER_BANDWIDTH:
                        dissect_rtmpt_body_scm(tvb, offset, rtmpt_tree, tp->cmd);
                        break;
                case RTMPT_TYPE_COMMAND_AMF0:
                case RTMPT_TYPE_DATA_AMF0:
                        dissect_rtmpt_body_command(tvb, offset, rtmpt_tree, FALSE);
                        break;
                case RTMPT_TYPE_COMMAND_AMF3:
                case RTMPT_TYPE_DATA_AMF3:
                        dissect_rtmpt_body_command(tvb, offset, rtmpt_tree, TRUE);
                        break;
                case RTMPT_TYPE_AUDIO_DATA:
                        dissect_rtmpt_body_audio(tvb, offset, rtmpt_tree);
                        break;
                case RTMPT_TYPE_VIDEO_DATA:
                        dissect_rtmpt_body_video(tvb, offset, rtmpt_tree);
                        break;
                case RTMPT_TYPE_AGGREGATE:
                        dissect_rtmpt_body_aggregate(tvb, offset, rtmpt_tree);
                        break;
                }
        }
}

/* Unchunk a data stream into individual RTMP packets */

static void
dissect_rtmpt_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, rtmpt_conv_t *rconv, int cdir, guint32 seq, guint32 lastackseq)
{
        int offset = 0;
        int remain;
        int want;

        guint8 header_type;
        int basic_hlen;
        int message_hlen;

        guint32 id;
        guint32 ts = 0;
        guint32 tsd = 0;
        int body_len;
        guint8 cmd;
        guint32 src;
        int chunk_size;

        rtmpt_frag_t *tf;
        rtmpt_id_t *ti;
        rtmpt_packet_t *tp;
        tvbuff_t *pktbuf;

        remain = tvb_length(tvb);
        if (!remain) return;

        RTMPT_DEBUG("Segment: cdir=%d seq=%d-%d\n", cdir, seq, seq+remain-1);

        if (pinfo->fd->flags.visited) {
                /* Already done the work, so just dump the existing state */
                ep_stack_t packets;

                /* List all RTMP packets terminating in this TCP segment, from end to beginning */

                packets = ep_stack_new();
                ep_stack_push(packets, 0);

                tp = se_tree_lookup32_le(rconv->packets[cdir], seq+remain-1);
                while (tp && tp->lastseq>=seq) {
                        ep_stack_push(packets, tp);
                        tp = se_tree_lookup32_le(rconv->packets[cdir], tp->lastseq-1);
                }

                /* Dissect the generated list in reverse order (beginning to end) */

                while ((tp=ep_stack_pop(packets))!=NULL) {
                        if (tp->resident) {
                                pktbuf = tvb_new_child_real_data(tvb, tp->data.p, tp->have, tp->have);
                                add_new_data_source(pinfo, pktbuf, "Unchunked RTMP");
                        } else {
                                pktbuf = tvb_new_subset(tvb, tp->data.offset, tp->have, tp->have);
                        }
                        dissect_rtmpt(pktbuf, pinfo, tree, rconv, cdir, tp);
                }

                return;
        }

        while (remain>0) {
                tf = NULL;
                ti = NULL;
                tp = NULL;

                /* Check for outstanding fragmented headers/chunks first */

                if (offset==0) {
                        tf = se_tree_lookup32_le(rconv->frags[cdir], seq+offset-1);

                        if (tf) {
                                /* May need to reassemble cross-TCP-segment fragments */
                                RTMPT_DEBUG("  tf seq=%d lseq=%d h=%d l=%d\n", tf->seq, tf->lastseq, tf->have, tf->len);
                                if (tf->have>=tf->len || seq+offset<tf->seq || seq+offset>tf->lastseq+tf->len-tf->have) {
                                        tf = NULL;
                                } else if (!tf->ishdr) {
                                        ti = se_tree_lookup32(rconv->ids[cdir], tf->saved.id);
                                        if (ti) tp = se_tree_lookup32_le(ti->packets, seq+offset-1);
                                        if (tp && tp->chunkwant) {
                                                goto unchunk;
                                        }
                                        tf = NULL;
                                        ti = NULL;
                                        tp = NULL;
                                }

                                if (tf) {
                                        /* The preceding segment contained an incomplete chunk header */

                                        want = tf->len - tf->have;
                                        if (remain<want) want = remain;

                                        tvb_memcpy(tvb, tf->saved.d+tf->have, offset, want);

                                        id = tf->saved.d[0];
                                        header_type = (id>>6) & 3;
                                        basic_hlen = rtmpt_basic_header_length(id);

                                        if (header_type<3 && tf->have<basic_hlen+3 && tf->have+want>=basic_hlen+3) {
                                                if (pntoh24(tf->saved.d+basic_hlen)==0xffffff) {
                                                        tf->len += 4;
                                                }
                                        }

                                        tf->have += want;
                                        tf->lastseq = seq+want-1;
                                        remain -= want;
                                        offset += want;

                                        if (tf->have<tf->len) {
                                                return;
                                        }
                                }
                        }
                }

                if (!tf) {
                        /* No preceeding data, get header data starting at current position */
                        id = tvb_get_guint8(tvb, offset);

                        if (id==RTMPT_MAGIC && seq+offset==RTMPT_HANDSHAKE_OFFSET_1) {
                                header_type = 4;
                                basic_hlen = 1;
                                message_hlen = 0;
                                id = lastackseq==1 ? RTMPT_TYPE_HANDSHAKE_1 : RTMPT_TYPE_HANDSHAKE_2;
                        } else if (seq+offset==RTMPT_HANDSHAKE_OFFSET_2) {
                                header_type = 4;
                                basic_hlen = 0;
                                message_hlen = 0;
                                id = RTMPT_TYPE_HANDSHAKE_3;
                        } else {
                                header_type = (id>>6) & 3;
                                basic_hlen = rtmpt_basic_header_length(id);
                                message_hlen = rtmpt_message_header_length(id);

                                if (header_type<3 && remain>=basic_hlen+3) {
                                        if (tvb_get_ntoh24(tvb, offset+basic_hlen)==0xffffff) {
                                                message_hlen += 4;
                                        }
                                }

                                if (remain<basic_hlen+message_hlen) {
                                        /* Ran out of packet mid-header, save and try again next time */
                                        tf = se_alloc(sizeof(rtmpt_frag_t));
                                        tf->ishdr = 1;
                                        tf->seq = seq + offset;
                                        tf->lastseq = tf->seq + remain - 1;
                                        tf->len = basic_hlen + message_hlen;
                                        tvb_memcpy(tvb, tf->saved.d, offset, remain);
                                        tf->have = remain;
                                        se_tree_insert32(rconv->frags[cdir], seq+offset, tf);
                                        return;
                                }

                                id = id & 0x3f;
                                if (id==0) id = tvb_get_guint8(tvb, offset+1) + 64;
                                else if (id==1) id = tvb_get_letohs(tvb, offset+1) + 64;
                        }

                } else {
                        /* Use reassembled header data */
                        id = tf->saved.d[0];
                        header_type = (id>>6) & 3;
                        basic_hlen = rtmpt_basic_header_length(id);
                        message_hlen = tf->len - basic_hlen;

                        id = id & 0x3f;
                        if (id==0) id = tf->saved.d[1] + 64;
                        else if (id==1) id = pletohs(tf->saved.d+1) + 64;
                }

                /* Calculate header values, defaulting from previous packets with same id */

                if (id<=RTMPT_ID_MAX) ti = se_tree_lookup32(rconv->ids[cdir], id);
                if (ti) tp = se_tree_lookup32_le(ti->packets, seq+offset-1);

                if (header_type==0) src = tf ? pntohl(tf->saved.d+basic_hlen+7) : tvb_get_ntohl(tvb, offset+basic_hlen+7);
                else if (ti) src = ti->src;
                else src = 0;

                if (header_type<2) cmd = tf ? tf->saved.d[basic_hlen+6] : tvb_get_guint8(tvb, offset+basic_hlen+6);
                else if (ti) cmd = ti->cmd;
                else cmd = 0;

                /* Calculate chunk_size now as a last-resort default payload length */
                if (id>RTMPT_ID_MAX) {
                        if (id==RTMPT_TYPE_HANDSHAKE_1) chunk_size = body_len = 1536;
                        else if (id==RTMPT_TYPE_HANDSHAKE_2) chunk_size = body_len = 3072;
                        else /* if (id==RTMPT_TYPE_HANDSHAKE_3) */ chunk_size = body_len = 1536;
                } else {
                        chunk_size = GPOINTER_TO_INT(se_tree_lookup32_le(rconv->chunksize[cdir], seq+offset-1));
                        if (!chunk_size) chunk_size = RTMPT_DEFAULT_CHUNK_SIZE;

                        if (header_type<2) body_len = tf ? pntoh24(tf->saved.d+basic_hlen+3) : tvb_get_ntoh24(tvb, offset+basic_hlen+3);
                        else if (ti) body_len = ti->len;
                        else body_len = chunk_size;

                        if (body_len>RTMPT_MAX_PACKET_SIZE) {
                                return;
                        }
                }

                if (!ti || !tp || header_type<3 || tp->have==tp->want || tp->chunkhave!=tp->chunkwant) {
                        /* Start a new packet if:
                         *   no previous packet with same id
                         *   not a short 1-byte header
                         *   previous packet with same id was complete
                         *   previous incomplete chunk not handled by fragment handler
                         */
                        RTMPT_DEBUG("New packet cdir=%d seq=%d ti=%p tp=%p header_type=%d header_len=%d id=%d tph=%d tpw=%d len=%d cs=%d\n",
                                    cdir, seq+offset,
                                    ti, tp, header_type, basic_hlen+message_hlen, id, tp?tp->have:0, tp?tp->want:0, body_len, chunk_size);

                        if (!ti) {
                                ti = se_alloc(sizeof(rtmpt_id_t));
                                ti->packets = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_packets");
                                ti->ts = 0;
                                ti->tsd = 0;
                                se_tree_insert32(rconv->ids[cdir], id, ti);
                        }

                        if (header_type==0) {
                                ts = tf ? pntoh24(tf->saved.d+basic_hlen) : tvb_get_ntoh24(tvb, offset+basic_hlen);
                                if (ts==0xffffff) {
                                        ts = tf ? pntohl(tf->saved.d+basic_hlen+11) : tvb_get_ntohl(tvb, offset+basic_hlen+11);
                                }
                                tsd = ts - ti->ts;
                        } else if (header_type<3) {
                                tsd = tf ? pntoh24(tf->saved.d+basic_hlen) : tvb_get_ntoh24(tvb, offset+basic_hlen);
                                if (tsd==0xffffff) {
                                        ts = tf ? pntohl(tf->saved.d+basic_hlen+message_hlen-4) : tvb_get_ntohl(tvb, offset+basic_hlen+message_hlen-4);
                                        tsd = ti->tsd; /* questionable */
                                } else {
                                        ts = ti->ts + tsd;
                                }
                        } else {
                                ts = ti->ts + ti->tsd;
                                tsd = ti->tsd;
                        }

                        /* create a new packet structure */
                        tp = se_alloc(sizeof(rtmpt_packet_t));
                        tp->seq = tp->lastseq = tf ? tf->seq : seq+offset;
                        tp->have = 0;
                        tp->want = basic_hlen + message_hlen + body_len;
                        tp->chunkwant = 0;
                        tp->chunkhave = 0;
                        tp->bhlen = basic_hlen;
                        tp->mhlen = message_hlen;
                        tp->fmt = header_type;
                        tp->id = id;
                        tp->ts = ts;
                        tp->len = body_len;
                        if (id>RTMPT_ID_MAX) tp->cmd = id;
                        else tp->cmd = cmd & 0x7f;
                        tp->src = src;
                        tp->txid = 0;
                        tp->isresponse = FALSE;
                        tp->otherframe = 0;

                        /* Save the header information for future defaulting needs */
                        ti->ts = ts;
                        ti->tsd = tsd;
                        ti->len = body_len;
                        ti->cmd = cmd;
                        ti->src = src;

                        /* store against the id only until unchunking is complete */
                        se_tree_insert32(ti->packets, tp->seq, tp);

                        if (!tf && body_len<=chunk_size && tp->want<=remain) {
                                /* The easy case - a whole packet contiguous and fully within this segment */
                                tp->resident = FALSE;
                                tp->data.offset = offset;
                                tp->lastseq = seq+offset+tp->want-1;
                                tp->have = tp->want;

                                se_tree_insert32(rconv->packets[cdir], tp->lastseq, tp);

                                pktbuf = tvb_new_subset(tvb, tp->data.offset, tp->have, tp->have);
                                dissect_rtmpt(pktbuf, pinfo, tree, rconv, cdir, tp);

                                offset += tp->want;
                                remain -= tp->want;
                                continue;

                        } else {
                                /* Some more reassembly required */
                                tp->resident = TRUE;
                                tp->data.p = se_alloc(tp->bhlen+tp->mhlen+tp->len);

                                if (tf && tf->ishdr) {
                                        memcpy(tp->data.p, tf->saved.d, tf->len);
                                } else {
                                        tvb_memcpy(tvb, tp->data.p, offset, basic_hlen+message_hlen);
                                        offset += basic_hlen + message_hlen;
                                        remain -= basic_hlen + message_hlen;
                                }

                                tp->lastseq = seq+offset-1;
                                tp->have = basic_hlen + message_hlen;

                                if (tp->have==tp->want) {
                                        se_tree_insert32(rconv->packets[cdir], tp->lastseq, tp);

                                        pktbuf = tvb_new_child_real_data(tvb, tp->data.p, tp->have, tp->have);
                                        add_new_data_source(pinfo, pktbuf, "Unchunked RTMP");
                                        dissect_rtmpt(pktbuf, pinfo, tree, rconv, cdir, tp);
                                        continue;
                                }

                                tp->chunkwant = chunk_size;
                                if (tp->chunkwant>tp->want-tp->have) tp->chunkwant = tp->want - tp->have;
                        }
                } else {
                        RTMPT_DEBUG("Old packet cdir=%d seq=%d ti=%p tp=%p header_len=%d id=%d tph=%d tpw=%d len=%d cs=%d\n",
                                    cdir, seq+offset,
                                    ti, tp, basic_hlen+message_hlen, id, tp?tp->have:0, tp?tp->want:0, body_len, chunk_size);

                        tp->chunkwant = chunk_size;
                        if (tp->chunkwant>tp->want-tp->have) tp->chunkwant = tp->want - tp->have;

                        offset += basic_hlen + message_hlen;
                        remain -= basic_hlen + message_hlen;
                }

                tf = NULL;

                /* Last case to deal with is unchunking the packet body */
        unchunk:
                want = tp->chunkwant - tp->chunkhave;
                if (want > remain) want = remain;
                RTMPT_DEBUG("  cw=%d ch=%d r=%d w=%d\n", tp->chunkwant, tp->chunkhave, remain, want);

                tvb_memcpy(tvb, tp->data.p+tp->have, offset, want);

                if (tf) {
                        tf->have += want;
                        tf->lastseq = seq+offset+want-1;
                }
                tp->lastseq = seq+offset+want-1;
                tp->have += want;
                tp->chunkhave += want;

                offset += want;
                remain -= want;

                if (tp->chunkhave==tp->chunkwant) {
                        /* Chunk is complete - wait for next header */
                        tp->chunkhave = 0;
                        tp->chunkwant = 0;
                }

                if (tp->have==tp->want) {
                        /* Whole packet is complete */
                        se_tree_insert32(rconv->packets[cdir], tp->lastseq, tp);

                        pktbuf = tvb_new_child_real_data(tvb, tp->data.p, tp->have, tp->have);
                        add_new_data_source(pinfo, pktbuf, "Unchunked RTMP");
                        dissect_rtmpt(pktbuf, pinfo, tree, rconv, cdir, tp);
                } else if (tp->chunkhave<tp->chunkwant) {
                        /* Chunk is split across segment boundary */
                        rtmpt_frag_t *tf2 = se_alloc(sizeof(rtmpt_frag_t));
                        tf2->ishdr = 0;
                        tf2->seq = seq + offset - want;
                        tf2->lastseq = tf2->seq + remain - 1 + want;
                        tf2->have = tp->chunkhave;
                        tf2->len = tp->chunkwant;
                        tf2->saved.id = tp->id;
                        RTMPT_DEBUG("  inserting tf @ %d\n", seq+offset-want-1);
                        se_tree_insert32(rconv->frags[cdir], seq+offset-want-1, tf2);
                }
        }
}

static rtmpt_conv_t*
rtmpt_init_rconv(conversation_t *conv)
{
        rtmpt_conv_t *rconv = se_alloc(sizeof(rtmpt_conv_t));
        conversation_add_proto_data(conv, proto_rtmpt, rconv);

        rconv->seqs[0]      = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_seqs0");
        rconv->seqs[1]      = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_seqs1");
        rconv->frags[0]     = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_frags0");
        rconv->frags[1]     = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_frags1");
        rconv->ids[0]       = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_ids0");
        rconv->ids[1]       = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_ids1");
        rconv->packets[0]   = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_packets0");
        rconv->packets[1]   = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_packets1");
        rconv->chunksize[0] = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_chunksize0");
        rconv->chunksize[1] = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_chunksize1");
        rconv->txids[0]     = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_txids0");
        rconv->txids[1]     = se_tree_create_non_persistent(EMEM_TREE_TYPE_RED_BLACK, "rtmpt_txids1");

        return rconv;
}

static void
dissect_rtmpt_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        conversation_t *conv;
        rtmpt_conv_t   *rconv;
        int             cdir;
        struct tcpinfo *tcpinfo;

        conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
        if (!conv) {
                conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
        }

        rconv = (rtmpt_conv_t*)conversation_get_proto_data(conv, proto_rtmpt);
        if (!rconv) {
                rconv = rtmpt_init_rconv(conv);
        }

        cdir = (ADDRESSES_EQUAL(&conv->key_ptr->addr1, &pinfo->src) &&
                ADDRESSES_EQUAL(&conv->key_ptr->addr2, &pinfo->dst) &&
                conv->key_ptr->port1==pinfo->srcport &&
                conv->key_ptr->port2==pinfo->destport) ? 0 : 1;

        tcpinfo = pinfo->private_data;
        dissect_rtmpt_common(tvb, pinfo, tree, rconv, cdir, tcpinfo->seq, tcpinfo->lastackseq);
}

static void
dissect_rtmpt_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        conversation_t *conv;
        rtmpt_conv_t   *rconv;
        int             cdir;
        guint32         seq;
        guint32         lastackseq;
        guint32         offset;
        gint            remain;

        offset = 0;
        remain = tvb_length_remaining(tvb, 0);

        /*
         * Request flow:
         *
         *  POST /open/1
         *    request body is a single non-RTMP byte
         *    response contains a client ID <cid> followed by NL
         *  POST /send/<cid>/<seq>
         *    <seq> starts at 0 after open and increments on each
         *    subsequent post
         *    request body is pure RTMP data
         *    response is a single non-RTMP byte followed by RTMP data
         *  POST /idle/<cid>/<seq>
         *    request contains a single non-RTMP byte
         *    response is a single non-RTMP byte followed by RTMP data
         *  POST /close/<cid>/<seq>
         *    request and response contain a single non-RTMP byte
         *
         * Ideally here we'd know:
         *
         *  1) Whether this is was a HTTP request or response
         *     (this gives us cdir directly)
         *  2) The requested URL (for both cases)
         *     (this tells us the type of framing bytes present,
         *     so whether there are any real bytes present). We
         *     could also use the client ID to identify the
         *     conversation, since each POST is likely to be on
         *     a different TCP connection, and there could be
         *     multiple simultaneous sessions from a single
         *     client (which we don't deal with here.)
         *
         *  As it is, we currently have to just guess, and are
         *  likely easily confused.
         */

        cdir = pinfo->srcport==pinfo->match_uint;

        if (cdir) {
                conv = find_conversation(pinfo->fd->num, &pinfo->dst, &pinfo->src, pinfo->ptype, 0, pinfo->srcport, 0);
                if (!conv) {
                        RTMPT_DEBUG("RTMPT new conversation\n");
                        conv = conversation_new(pinfo->fd->num, &pinfo->dst, &pinfo->src, pinfo->ptype, 0, pinfo->srcport, 0);
                }
        } else {
                conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, 0, pinfo->destport, 0);
                if (!conv) {
                        RTMPT_DEBUG("RTMPT new conversation\n");
                        conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, 0, pinfo->destport, 0);
                }
        }

        rconv = (rtmpt_conv_t*)conversation_get_proto_data(conv, proto_rtmpt);
        if (!rconv) {
                rconv = rtmpt_init_rconv(conv);
        }

        /* Work out a TCP-like sequence numbers for the tunneled data stream.
         * If we've seen the packet before we'll have stored the seq of our
         * last byte against the frame number - since we know how big we are
         * we can work out the seq of our first byte. If this is the first
         * time, we use the stored seq of the last byte of the previous frame
         * plus one. If there is no previous frame then we must be at seq=1!
         * (This is per-conversation and per-direction, of course.) */

        lastackseq = GPOINTER_TO_INT(se_tree_lookup32_le(rconv->seqs[cdir ^ 1], pinfo->fd->num))+1;

        if (cdir==1 && lastackseq<2 && remain==17) {
                /* Session startup: the client makes an /open/ request and
                 * the server responds with a 16 bytes client
                 * identifier followed by a newline */
                offset += 17;
                remain -= 17;
        } else if (cdir || remain==1) {
                /* All other server responses start with one byte which
                 * is not part of the RTMP stream. Client /idle/ requests
                 * contain a single byte also not part of the stream. We
                 * must discard these */
                offset++;
                remain--;
        }

        seq = GPOINTER_TO_INT(se_tree_lookup32(rconv->seqs[cdir], pinfo->fd->num));

        if (seq==0) {
                seq = GPOINTER_TO_INT(se_tree_lookup32_le(rconv->seqs[cdir], pinfo->fd->num));
                seq += remain;
                se_tree_insert32(rconv->seqs[cdir], pinfo->fd->num, GINT_TO_POINTER(seq));
        }

        seq -= remain-1;

        RTMPT_DEBUG("RTMPT f=%d cdir=%d seq=%d lastackseq=%d len=%d\n", pinfo->fd->num, cdir, seq, lastackseq, remain);

        if (remain<1) return;

        if (offset>0) {
                tvbuff_t *tvbrtmp = tvb_new_subset(tvb, offset, remain, remain);
                dissect_rtmpt_common(tvbrtmp, pinfo, tree, rconv, cdir, seq, lastackseq);
        } else {
                dissect_rtmpt_common(tvb, pinfo, tree, rconv, cdir, seq, lastackseq);
        }
}

#if 0
static gboolean
dissect_rtmpt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        conversation_t * conversation;
        if (tvb_length(tvb) >= 12)
        {
                /* To avoid a too high rate of false positive, this heuristics only matches the protocol
                   from the first server response packet and not from the client request packets before.
                   Therefore it is necessary to a "Decode as" to properly decode the first packets */
                struct tcpinfo *tcpinfo = pinfo->private_data;
                if (tcpinfo->lastackseq == RTMPT_HANDSHAKE_OFFSET_2
                    && tcpinfo->seq == RTMPT_HANDSHAKE_OFFSET_1
                    && tvb_get_guint8(tvb, 0) == RTMPT_MAGIC)
                {
                        /* Register this dissector for this conversation */
                        conversation = NULL;
                        conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
                        if (conversation == NULL)
                        {
                                conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
                        }
                        conversation_set_dissector(conversation, rtmpt_tcp_handle);

                        /* Dissect the packet */
                        dissect_rtmpt_tcp(tvb, pinfo, tree);
                        return TRUE;
                }
        }
        return FALSE;
}
#endif

static void
dissect_amf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
        proto_item *ti;
        proto_tree *amf_tree, *headers_tree, *messages_tree;
        int offset;
        guint header_count, message_count, i;
        guint string_length;
        guint header_length, message_length;
        gboolean amf3_encoding = FALSE;

        /*
         * XXX - is "application/x-amf" just AMF3?
         */
        ti = proto_tree_add_item(tree, proto_amf, tvb, 0, -1, ENC_NA);
        amf_tree = proto_item_add_subtree(ti, ett_amf);
        offset = 0;
        proto_tree_add_item(amf_tree, hf_amf_version, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        header_count = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(amf_tree, hf_amf_header_count, tvb, offset, 2, header_count);
        offset += 2;
        if (header_count != 0) {
                ti = proto_tree_add_text(amf_tree, tvb, offset, -1, "Headers");
                headers_tree = proto_item_add_subtree(ti, ett_amf_headers);
                for (i = 0; i < header_count; i++) {
                        string_length = tvb_get_ntohs(tvb, offset);
                        proto_tree_add_item(headers_tree, hf_amf_header_name, tvb, offset, 2, ENC_BIG_ENDIAN|ENC_UTF_8);
                        offset += 2 + string_length;
                        proto_tree_add_item(headers_tree, hf_amf_header_must_understand, tvb, offset, 1, ENC_NA);
                        offset += 1;
                        header_length = tvb_get_ntohl(tvb, offset);
                        if (header_length == 0xFFFFFFFF)
                                proto_tree_add_uint_format_value(headers_tree, hf_amf_header_length, tvb, offset, 4, header_length, "Unknown");
                        else
                                proto_tree_add_uint(headers_tree, hf_amf_header_length, tvb, offset, 4, header_length);
                        offset += 4;
                        if (amf3_encoding)
                                offset = dissect_amf3_value_type(tvb, offset, headers_tree, NULL);
                        else
                                offset = dissect_amf0_value_type(tvb, offset, headers_tree, &amf3_encoding, NULL);
                }
        }
        message_count = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(amf_tree, hf_amf_message_count, tvb, offset, 2, message_count);
        offset += 2;
        if (message_count != 0) {
                ti = proto_tree_add_text(amf_tree, tvb, offset, -1, "Messages");
                messages_tree = proto_item_add_subtree(ti, ett_amf_messages);
                for (i = 0; i < message_count; i++) {
                        string_length = tvb_get_ntohs(tvb, offset);
                        proto_tree_add_item(messages_tree, hf_amf_message_target_uri, tvb, offset, 2, ENC_BIG_ENDIAN|ENC_UTF_8);
                        offset += 2 + string_length;
                        string_length = tvb_get_ntohs(tvb, offset);
                        proto_tree_add_item(messages_tree, hf_amf_message_response_uri, tvb, offset, 2, ENC_BIG_ENDIAN|ENC_UTF_8);
                        offset += 2 + string_length;
                        message_length = tvb_get_ntohl(tvb, offset);
                        if (message_length == 0xFFFFFFFF)
                                proto_tree_add_uint_format_value(messages_tree, hf_amf_message_length, tvb, offset, 4, message_length, "Unknown");
                        else
                                proto_tree_add_uint(messages_tree, hf_amf_message_length, tvb, offset, 4, message_length);
                        offset += 4;
                        offset = dissect_rtmpt_body_command(tvb, offset, messages_tree, FALSE);
                }
        }
}

void
proto_register_rtmpt(void)
{
        static hf_register_info hf[] = {
/* RTMP Handshake data */
                { &hf_rtmpt_handshake_c0,
                  { "Protocol version", "rtmpt.handshake.c0", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT Handshake C0", HFILL }},

                { &hf_rtmpt_handshake_s0,
                  { "Protocol version", "rtmpt.handshake.s0", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT Handshake S0", HFILL }},

                { &hf_rtmpt_handshake_c1,
                  { "Handshake data", "rtmpt.handshake.c1", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT Handshake C1", HFILL }},

                { &hf_rtmpt_handshake_s1,
                  { "Handshake data", "rtmpt.handshake.s1", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT Handshake S1", HFILL }},

                { &hf_rtmpt_handshake_c2,
                  { "Handshake data", "rtmpt.handshake.c2", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT Handshake C2", HFILL }},

                { &hf_rtmpt_handshake_s2,
                  { "Handshake data", "rtmpt.handshake.s2", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT Handshake S2", HFILL }},

/* RTMP chunk/packet header */
                { &hf_rtmpt_header_format,
                  { "Format", "rtmpt.header.format", FT_UINT8, BASE_DEC,
                    NULL, 0xC0, "RTMPT Basic Header format", HFILL }},

                { &hf_rtmpt_header_csid,
                  { "Chunk Stream ID", "rtmpt.header.csid", FT_UINT8, BASE_DEC,
                    NULL, 0x3F, "RTMPT Basic Header chunk stream ID", HFILL }},

                { &hf_rtmpt_header_timestamp,
                  { "Timestamp", "rtmpt.header.timestamp", FT_UINT24, BASE_DEC,
                    NULL, 0x0, "RTMPT Message Header timestamp", HFILL }},

                { &hf_rtmpt_header_timestamp_delta,
                  { "Timestamp delta", "rtmpt.header.timestampdelta", FT_UINT24, BASE_DEC,
                    NULL, 0x0, "RTMPT Message Header timestamp delta", HFILL }},

                { &hf_rtmpt_header_body_size,
                  { "Body size", "rtmpt.header.bodysize", FT_UINT24, BASE_DEC,
                    NULL, 0x0, "RTMPT Message Header body size", HFILL }},

                { &hf_rtmpt_header_typeid,
                  { "Type ID", "rtmpt.header.typeid", FT_UINT8, BASE_HEX,
                    VALS(rtmpt_opcode_vals), 0x0, "RTMPT Message Header type ID", HFILL }},

                { &hf_rtmpt_header_streamid,
                  { "Stream ID", "rtmpt.header.streamid", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT Header stream ID", HFILL }},

                { &hf_rtmpt_header_ets,
                  { "Extended timestamp", "rtmpt.header.ets", FT_UINT24, BASE_DEC,
                    NULL, 0x0, "RTMPT Message Header extended timestamp", HFILL }},

/* Stream Control Messages */

                { &hf_rtmpt_scm_chunksize,
                  { "Chunk size", "rtmpt.scm.chunksize", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT SCM chunk size", HFILL }},

                { &hf_rtmpt_scm_csid,
                  { "Chunk stream ID", "rtmpt.scm.csid", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT SCM chunk stream ID", HFILL }},

                { &hf_rtmpt_scm_seq,
                  { "Sequence number", "rtmpt.scm.seq", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT SCM acknowledgement sequence number", HFILL }},

                { &hf_rtmpt_scm_was,
                  { "Window acknowledgement size", "rtmpt.scm.was", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT SCM window acknowledgement size", HFILL }},

                { &hf_rtmpt_scm_limittype,
                  { "Limit type", "rtmpt.scm.limittype", FT_UINT8, BASE_DEC,
                    VALS(rtmpt_limit_vals), 0x0, "RTMPT SCM window acknowledgement size", HFILL }},

/* User Control Messages */
                { &hf_rtmpt_ucm_eventtype,
                  { "Event type", "rtmpt.ucm.eventtype", FT_UINT16, BASE_DEC,
                    VALS(rtmpt_ucm_vals), 0x0, "RTMPT UCM event type", HFILL }},

/* Frame links */

                { &hf_rtmpt_function_call,
                  { "Response to this call in frame", "rtmpt.function.call", FT_FRAMENUM, BASE_NONE,
                    NULL, 0x0, "RTMPT function call", HFILL }},

                { &hf_rtmpt_function_response,
                  { "Call for this response in frame", "rtmpt.function.response", FT_FRAMENUM, BASE_NONE,
                    NULL, 0x0, "RTMPT function response", HFILL }},

/* Audio packets */
                { &hf_rtmpt_audio_control,
                  { "Audio control", "rtmpt.audio.control", FT_UINT8, BASE_HEX,
                    NULL, 0x0, "RTMPT Audio control", HFILL }},

                { &hf_rtmpt_audio_format,
                  { "Format", "rtmpt.audio.format", FT_UINT8, BASE_DEC,
                    VALS(rtmpt_audio_codecs), 0xf0, "RTMPT Audio format", HFILL }},

                { &hf_rtmpt_audio_rate,
                  { "Sample rate", "rtmpt.audio.rate", FT_UINT8, BASE_DEC,
                    VALS(rtmpt_audio_rates), 0x0c, "RTMPT Audio sample rate", HFILL }},

                { &hf_rtmpt_audio_size,
                  { "Sample size", "rtmpt.audio.size", FT_UINT8, BASE_DEC,
                    VALS(rtmpt_audio_sizes), 0x02, "RTMPT Audio sample size", HFILL }},

                { &hf_rtmpt_audio_type,
                  { "Channels", "rtmpt.audio.type", FT_UINT8, BASE_DEC,
                    VALS(rtmpt_audio_types), 0x01, "RTMPT Audio channel count", HFILL }},

                { &hf_rtmpt_audio_data,
                  { "Audio data", "rtmpt.audio.data", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT Audio data", HFILL }},

/* Video packets */
                { &hf_rtmpt_video_control,
                  { "Video control", "rtmpt.video.control", FT_UINT8, BASE_HEX,
                    NULL, 0x0, "RTMPT Video control", HFILL }},

                { &hf_rtmpt_video_type,
                  { "Type", "rtmpt.video.type", FT_UINT8, BASE_DEC,
                    VALS(rtmpt_video_types), 0xf0, "RTMPT Video type", HFILL }},

                { &hf_rtmpt_video_format,
                  { "Format", "rtmpt.video.format", FT_UINT8, BASE_DEC,
                    VALS(rtmpt_video_codecs), 0x0f, "RTMPT Video format", HFILL }},

                { &hf_rtmpt_video_data,
                  { "Video data", "rtmpt.video.data", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT Video data", HFILL }},

/* Aggregate packets */
                { &hf_rtmpt_tag_type,
                  { "Type", "rtmpt.tag.type", FT_UINT8, BASE_DEC,
                    VALS(rtmpt_tag_vals), 0x0, "RTMPT Aggregate tag type", HFILL }},

                { &hf_rtmpt_tag_datasize,
                  { "Data size", "rtmpt.tag.datasize", FT_UINT24, BASE_DEC,
                    NULL, 0x0, "RTMPT Aggregate tag data size", HFILL }},

                { &hf_rtmpt_tag_timestamp,
                  { "Timestamp", "rtmpt.tag.timestamp", FT_UINT24, BASE_DEC,
                    NULL, 0x0, "RTMPT Aggregate tag timestamp", HFILL }},

                { &hf_rtmpt_tag_ets,
                  { "Timestamp Extended", "rtmpt.tag.ets", FT_UINT8, BASE_DEC,
                    NULL, 0x0, "RTMPT Aggregate tag timestamp extended", HFILL }},

                { &hf_rtmpt_tag_streamid,
                  { "Stream ID", "rtmpt.tag.streamid", FT_UINT24, BASE_DEC,
                    NULL, 0x0, "RTMPT Aggregate tag stream ID", HFILL }},

                { &hf_rtmpt_tag_tagsize,
                  { "Previous tag size", "rtmpt.tag.tagsize", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT Aggregate previous tag size", HFILL }}

        };
        static gint *ett[] = {
                &ett_rtmpt,
                &ett_rtmpt_handshake,
                &ett_rtmpt_header,
                &ett_rtmpt_body,
                &ett_rtmpt_ucm,
                &ett_rtmpt_audio_control,
                &ett_rtmpt_video_control,
                &ett_rtmpt_tag,
                &ett_rtmpt_tag_data
        };

        module_t *rtmpt_module;

        proto_rtmpt = proto_register_protocol("Real Time Messaging Protocol", "RTMPT", "rtmpt");
        proto_register_field_array(proto_rtmpt, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        rtmpt_module = prefs_register_protocol(proto_rtmpt, NULL);
        prefs_register_bool_preference(rtmpt_module, "desegment",
                                       "Reassemble RTMPT messages spanning multiple TCP segments",
                                       "Whether the RTMPT dissector should reassemble messages spanning multiple TCP segments."
                                       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\""
                                       " in the TCP protocol settings.",
                                       &rtmpt_desegment);

}

void
proto_reg_handoff_rtmpt(void)
{
        dissector_handle_t amf_handle;

/*      heur_dissector_add("tcp", dissect_rtmpt_heur, proto_rtmpt); */
        rtmpt_tcp_handle = create_dissector_handle(dissect_rtmpt_tcp, proto_rtmpt);
/*      dissector_add_handle("tcp.port", rtmpt_tcp_handle); */
        dissector_add_uint("tcp.port", RTMP_PORT, rtmpt_tcp_handle);

        rtmpt_http_handle = create_dissector_handle(dissect_rtmpt_http, proto_rtmpt);
        dissector_add_string("media_type", "application/x-fcs", rtmpt_http_handle);

        amf_handle = create_dissector_handle(dissect_amf, proto_amf);
        dissector_add_string("media_type", "application/x-amf", amf_handle);
}

void
proto_register_amf(void)
{
        static hf_register_info hf[] = {
                { &hf_amf_version,
                  { "AMF version", "amf.version", FT_UINT16, BASE_DEC,
                    NULL, 0x0, NULL, HFILL }},

                { &hf_amf_header_count,
                  { "Header count", "amf.header_count", FT_UINT16, BASE_DEC,
                    NULL, 0x0, NULL, HFILL }},

                { &hf_amf_header_name,
                  { "Name", "amf.header.name", FT_UINT_STRING, BASE_NONE,
                    NULL, 0x0, NULL, HFILL }},

                { &hf_amf_header_must_understand,
                  { "Must understand", "amf.header.must_understand", FT_BOOLEAN, BASE_NONE,
                    NULL, 0x0, NULL, HFILL }},

                { &hf_amf_header_length,
                  { "Length", "amf.header.length", FT_UINT32, BASE_DEC,
                    NULL, 0x0, NULL, HFILL }},

                { &hf_amf_header_value_type,
                  { "Value type", "amf.header.value_type", FT_UINT32, BASE_HEX,
                    /*VALS(rtmpt_type_vals)*/NULL, 0x0, NULL, HFILL }},

                { &hf_amf_message_count,
                  { "Message count", "amf.message_count", FT_UINT16, BASE_DEC,
                    NULL, 0x0, NULL, HFILL }},

                { &hf_amf_message_target_uri,
                  { "Target URI", "amf.message.target_uri", FT_UINT_STRING, BASE_NONE,
                    NULL, 0x0, NULL, HFILL }},

                { &hf_amf_message_response_uri,
                  { "Response URI", "amf.message.response_uri", FT_UINT_STRING, BASE_NONE,
                    NULL, 0x0, NULL, HFILL }},

                { &hf_amf_message_length,
                  { "Length", "amf.message.length", FT_UINT32, BASE_DEC,
                    NULL, 0x0, NULL, HFILL }},


/* AMF basic types */
                { &hf_amf_amf0_type,
                  { "AMF0 type", "amf.amf0_type", FT_UINT8, BASE_HEX,
                    VALS(amf0_type_vals), 0x0, NULL, HFILL }},

                { &hf_amf_amf3_type,
                  { "AMF3 type", "amf.amf3_type", FT_UINT8, BASE_HEX,
                    VALS(amf3_type_vals), 0x0, NULL, HFILL }},

                { &hf_amf_number,
                  { "Number", "amf.number", FT_DOUBLE, BASE_NONE,
                    NULL, 0x0, "AMF number", HFILL }},

                { &hf_amf_integer,
                  { "Integer", "amf.integer", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT AMF3 integer", HFILL }},

                { &hf_amf_boolean,
                  { "Boolean", "amf.boolean", FT_BOOLEAN, BASE_NONE,
                    NULL, 0x0, "AMF boolean", HFILL }},

                { &hf_amf_stringlength,
                  { "String length", "amf.stringlength", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF string length", HFILL }},

                { &hf_amf_string,
                  { "String", "amf.string", FT_STRING, BASE_NONE,
                    NULL, 0x0, "AMF string", HFILL }},

                { &hf_amf_string_reference,
                  { "String reference", "amf.string_reference", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT AMF3 string reference", HFILL }},

                { &hf_amf_object_reference,
                  { "Object reference", "amf.object_reference", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF object reference", HFILL }},

                { &hf_amf_date,
                  { "Date", "amf.date", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
                    NULL, 0x0, "AMF date", HFILL }},

                { &hf_amf_longstringlength,
                  { "String length", "amf.longstringlength", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF long string length", HFILL }},

                { &hf_amf_longstring,
                  { "Long string", "amf.longstring", FT_STRING, BASE_NONE,
                    NULL, 0x0, "AMF long string", HFILL }},

                { &hf_amf_xml_doc,
                  { "XML document", "amf.xml_doc", FT_STRING, BASE_NONE,
                    NULL, 0x0, "AMF XML document", HFILL }},

                { &hf_amf_xmllength,
                  { "XML text length", "amf.xmllength", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF E4X XML length", HFILL }},

                { &hf_amf_xml,
                  { "XML", "amf.xml", FT_STRING, BASE_NONE,
                    NULL, 0x0, "AMF E4X XML", HFILL }},

                { &hf_amf_int64,
                  { "Int64", "amf.int64", FT_INT64, BASE_DEC,
                    NULL, 0x0, "AMF int64", HFILL }},

                { &hf_amf_bytearraylength,
                  { "ByteArray length", "amf.bytearraylength", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "RTMPT AMF3 ByteArray length", HFILL }},

                { &hf_amf_bytearray,
                  { "ByteArray", "amf.bytearray", FT_BYTES, BASE_NONE,
                    NULL, 0x0, "RTMPT AMF3 ByteArray", HFILL }},

/* AMF object types and subfields of the object types */
                { &hf_amf_object,
                  { "Object", "amf.object", FT_NONE, BASE_NONE,
                    NULL, 0x0, "AMF object", HFILL }},

                { &hf_amf_traitcount,
                  { "Trait count", "amf.traitcount", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF count of traits for an object", HFILL }},

                { &hf_amf_classnamelength,
                  { "Class name length", "amf.classnamelength", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF class name length", HFILL }},

                { &hf_amf_classname,
                  { "Class name", "amf.classname", FT_STRING, BASE_NONE,
                    NULL, 0x0, "AMF class name", HFILL }},

                { &hf_amf_membernamelength,
                  { "Member name length", "amf.membernamelength", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF member name length", HFILL }},

                { &hf_amf_membername,
                  { "Member name", "amf.membername", FT_STRING, BASE_NONE,
                    NULL, 0x0, "AMF member name", HFILL }},

                { &hf_amf_trait_reference,
                  { "Trait reference", "amf.trait_reference", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF trait reference", HFILL }},

                { &hf_amf_ecmaarray,
                  { "ECMA array", "amf.ecmaarray", FT_NONE, BASE_NONE,
                    NULL, 0x0, "AMF ECMA array", HFILL }},

                { &hf_amf_strictarray,
                  { "Strict array", "amf.strictarray", FT_NONE, BASE_NONE,
                    NULL, 0x0, "AMF strict array", HFILL }},

                { &hf_amf_array,
                  { "Array", "amf.array", FT_NONE, BASE_NONE,
                    NULL, 0x0, "RTMPT AMF3 array", HFILL }},

                { &hf_amf_arraylength,
                  { "Array length", "amf.arraylength", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF array length", HFILL }},

                { &hf_amf_arraydenselength,
                  { "Length of dense portion", "amf.arraydenselength", FT_UINT32, BASE_DEC,
                    NULL, 0x0, "AMF length of dense portion of array", HFILL }},
        };
        static gint *ett[] = {
                &ett_amf,
                &ett_amf_headers,
                &ett_amf_messages,
                &ett_amf_value,
                &ett_amf_property,
                &ett_amf_string,
                &ett_amf_array_element,
                &ett_amf_traits,
                &ett_amf_trait_member,
        };

        proto_amf = proto_register_protocol("Action Message Format", "AMF", "amf");
        proto_register_field_array(proto_amf, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
};

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
