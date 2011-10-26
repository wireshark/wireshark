/* packet-amqp.c
 *
 * AMQP v0-9, 0-10 Wireshark dissector plug-in
 *
 * Author: Martin Sustrik <sustrik@imatix.com> (AMQP 0-9)
 * Author: Steve Huston <shuston@riverace.com> (extended for AMQP 0-10)
 *
 * Copyright (c) 1996-2007 iMatix Corporation
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * See
 *
 *     http://www.amqp.org/confluence/display/AMQP/AMQP+Specification
 *
 * for specifications for various versions of the AMQP protocol.
 */

#ifdef HAVE_CONFIG_H
#    include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/emem.h>
#include "packet-tcp.h"

/*  Generic data  */

static int amqp_port = 5672;

/*  Generic defines  */

#define AMQP_INCREMENT(offset, addend, bound) {\
    offset += (addend);\
    THROW_ON((offset > bound), ReportedBoundsError);  \
}

/*
 * This dissector handles AMQP 0-9 and 0-10. The conversation structure
 * contains the version being run - it's only really reliably detected at
 * protocol init. If this dissector starts in the middle of a conversation
 * it will try to figure it out, but conversation start is the best.
 */

/* #define AMQP_V0_8           1 */
#define AMQP_V0_9           2
/* #define AMQP_V0_91          3 */
#define AMQP_V0_10          4
typedef struct {
    guint8 version;
} amqp_conv;

/* 0-9 defines */

#define AMQP_0_9_FRAME_TYPE_METHOD                                    1
#define AMQP_0_9_FRAME_TYPE_CONTENT_HEADER                            2
#define AMQP_0_9_FRAME_TYPE_CONTENT_BODY                              3
#define AMQP_0_9_FRAME_TYPE_OOB_METHOD                                4
#define AMQP_0_9_FRAME_TYPE_OOB_CONTENT_HEADER                        5
#define AMQP_0_9_FRAME_TYPE_OOB_CONTENT_BODY                          6
#define AMQP_0_9_FRAME_TYPE_TRACE                                     7
#define AMQP_0_9_FRAME_TYPE_HEARTBEAT                                 8

#define AMQP_0_9_CLASS_CONNECTION                                     10
#define AMQP_0_9_CLASS_CHANNEL                                        20
#define AMQP_0_9_CLASS_ACCESS                                         30
#define AMQP_0_9_CLASS_EXCHANGE                                       40
#define AMQP_0_9_CLASS_QUEUE                                          50
#define AMQP_0_9_CLASS_BASIC                                          60
#define AMQP_0_9_CLASS_FILE                                           70
#define AMQP_0_9_CLASS_STREAM                                         80
#define AMQP_0_9_CLASS_TX                                             90
#define AMQP_0_9_CLASS_DTX                                            100
#define AMQP_0_9_CLASS_TUNNEL                                         110

#define AMQP_0_9_METHOD_CONNECTION_START                              10
#define AMQP_0_9_METHOD_CONNECTION_START_OK                           11
#define AMQP_0_9_METHOD_CONNECTION_SECURE                             20
#define AMQP_0_9_METHOD_CONNECTION_SECURE_OK                          21
#define AMQP_0_9_METHOD_CONNECTION_TUNE                               30
#define AMQP_0_9_METHOD_CONNECTION_TUNE_OK                            31
#define AMQP_0_9_METHOD_CONNECTION_OPEN                               40
#define AMQP_0_9_METHOD_CONNECTION_OPEN_OK                            41
#define AMQP_0_9_METHOD_CONNECTION_REDIRECT                           42
#define AMQP_0_9_METHOD_CONNECTION_CLOSE                              50
#define AMQP_0_9_METHOD_CONNECTION_CLOSE_OK                           51

#define AMQP_0_9_METHOD_CHANNEL_OPEN                                  10
#define AMQP_0_9_METHOD_CHANNEL_OPEN_OK                               11
#define AMQP_0_9_METHOD_CHANNEL_FLOW                                  20
#define AMQP_0_9_METHOD_CHANNEL_FLOW_OK                               21
#define AMQP_0_9_METHOD_CHANNEL_CLOSE                                 40
#define AMQP_0_9_METHOD_CHANNEL_CLOSE_OK                              41
#define AMQP_0_9_METHOD_CHANNEL_RESUME                                50
#define AMQP_0_9_METHOD_CHANNEL_PING                                  60
#define AMQP_0_9_METHOD_CHANNEL_PONG                                  70
#define AMQP_0_9_METHOD_CHANNEL_OK                                    80

#define AMQP_0_9_METHOD_ACCESS_REQUEST                                10
#define AMQP_0_9_METHOD_ACCESS_REQUEST_OK                             11

#define AMQP_0_9_METHOD_EXCHANGE_DECLARE                              10
#define AMQP_0_9_METHOD_EXCHANGE_DECLARE_OK                           11
#define AMQP_0_9_METHOD_EXCHANGE_DELETE                               20
#define AMQP_0_9_METHOD_EXCHANGE_DELETE_OK                            21
#define AMQP_0_9_METHOD_EXCHANGE_BIND                                 30
#define AMQP_0_9_METHOD_EXCHANGE_BIND_OK                              31

#define AMQP_0_9_METHOD_QUEUE_DECLARE                                 10
#define AMQP_0_9_METHOD_QUEUE_DECLARE_OK                              11
#define AMQP_0_9_METHOD_QUEUE_BIND                                    20
#define AMQP_0_9_METHOD_QUEUE_BIND_OK                                 21
#define AMQP_0_9_METHOD_QUEUE_UNBIND                                  50
#define AMQP_0_9_METHOD_QUEUE_UNBIND_OK                               51
#define AMQP_0_9_METHOD_QUEUE_PURGE                                   30
#define AMQP_0_9_METHOD_QUEUE_PURGE_OK                                31
#define AMQP_0_9_METHOD_QUEUE_DELETE                                  40
#define AMQP_0_9_METHOD_QUEUE_DELETE_OK                               41

#define AMQP_0_9_METHOD_BASIC_QOS                                     10
#define AMQP_0_9_METHOD_BASIC_QOS_OK                                  11
#define AMQP_0_9_METHOD_BASIC_CONSUME                                 20
#define AMQP_0_9_METHOD_BASIC_CONSUME_OK                              21
#define AMQP_0_9_METHOD_BASIC_CANCEL                                  30
#define AMQP_0_9_METHOD_BASIC_CANCEL_OK                               31
#define AMQP_0_9_METHOD_BASIC_PUBLISH                                 40
#define AMQP_0_9_METHOD_BASIC_RETURN                                  50
#define AMQP_0_9_METHOD_BASIC_DELIVER                                 60
#define AMQP_0_9_METHOD_BASIC_GET                                     70
#define AMQP_0_9_METHOD_BASIC_GET_OK                                  71
#define AMQP_0_9_METHOD_BASIC_GET_EMPTY                               72
#define AMQP_0_9_METHOD_BASIC_ACK                                     80
#define AMQP_0_9_METHOD_BASIC_REJECT                                  90
#define AMQP_0_9_METHOD_BASIC_RECOVER                                 100

#define AMQP_0_9_METHOD_FILE_QOS                                      10
#define AMQP_0_9_METHOD_FILE_QOS_OK                                   11
#define AMQP_0_9_METHOD_FILE_CONSUME                                  20
#define AMQP_0_9_METHOD_FILE_CONSUME_OK                               21
#define AMQP_0_9_METHOD_FILE_CANCEL                                   30
#define AMQP_0_9_METHOD_FILE_CANCEL_OK                                31
#define AMQP_0_9_METHOD_FILE_OPEN                                     40
#define AMQP_0_9_METHOD_FILE_OPEN_OK                                  41
#define AMQP_0_9_METHOD_FILE_STAGE                                    50
#define AMQP_0_9_METHOD_FILE_PUBLISH                                  60
#define AMQP_0_9_METHOD_FILE_RETURN                                   70
#define AMQP_0_9_METHOD_FILE_DELIVER                                  80
#define AMQP_0_9_METHOD_FILE_ACK                                      90
#define AMQP_0_9_METHOD_FILE_REJECT                                   100

#define AMQP_0_9_METHOD_STREAM_QOS                                    10
#define AMQP_0_9_METHOD_STREAM_QOS_OK                                 11
#define AMQP_0_9_METHOD_STREAM_CONSUME                                20
#define AMQP_0_9_METHOD_STREAM_CONSUME_OK                             21
#define AMQP_0_9_METHOD_STREAM_CANCEL                                 30
#define AMQP_0_9_METHOD_STREAM_CANCEL_OK                              31
#define AMQP_0_9_METHOD_STREAM_PUBLISH                                40
#define AMQP_0_9_METHOD_STREAM_RETURN                                 50
#define AMQP_0_9_METHOD_STREAM_DELIVER                                60

#define AMQP_0_9_METHOD_TX_SELECT                                     10
#define AMQP_0_9_METHOD_TX_SELECT_OK                                  11
#define AMQP_0_9_METHOD_TX_COMMIT                                     20
#define AMQP_0_9_METHOD_TX_COMMIT_OK                                  21
#define AMQP_0_9_METHOD_TX_ROLLBACK                                   30
#define AMQP_0_9_METHOD_TX_ROLLBACK_OK                                31

#define AMQP_0_9_METHOD_DTX_SELECT                                    10
#define AMQP_0_9_METHOD_DTX_SELECT_OK                                 11
#define AMQP_0_9_METHOD_DTX_START                                     20
#define AMQP_0_9_METHOD_DTX_START_OK                                  21

#define AMQP_0_9_METHOD_TUNNEL_REQUEST                                10

/* AMQP 0-10 values */

#define AMQP_0_10_FRAME_CONTROL  0
#define AMQP_0_10_FRAME_COMMAND  1
#define AMQP_0_10_FRAME_HEADER   2
#define AMQP_0_10_FRAME_BODY     3

#define AMQP_0_10_TYPE_STR16     0x95
#define AMQP_0_10_TYPE_MAP       0xa8
#define AMQP_0_10_TYPE_LIST      0xa9
#define AMQP_0_10_TYPE_ARRAY     0xaa
#define AMQP_0_10_TYPE_STRUCT32  0xab

#define AMQP_0_10_CLASS_CONNECTION           0x01
#define AMQP_0_10_METHOD_CONNECTION_START          0x01
#define AMQP_0_10_METHOD_CONNECTION_START_OK       0x02
#define AMQP_0_10_METHOD_CONNECTION_SECURE         0x03
#define AMQP_0_10_METHOD_CONNECTION_SECURE_OK      0x04
#define AMQP_0_10_METHOD_CONNECTION_TUNE           0x05
#define AMQP_0_10_METHOD_CONNECTION_TUNE_OK        0x06
#define AMQP_0_10_METHOD_CONNECTION_OPEN           0x07
#define AMQP_0_10_METHOD_CONNECTION_OPEN_OK        0x08
#define AMQP_0_10_METHOD_CONNECTION_REDIRECT       0x09
#define AMQP_0_10_METHOD_CONNECTION_HEARTBEAT      0x0a
#define AMQP_0_10_METHOD_CONNECTION_CLOSE          0x0b
#define AMQP_0_10_METHOD_CONNECTION_CLOSE_OK       0x0c

#define AMQP_0_10_CLASS_SESSION              0x02
#define AMQP_0_10_METHOD_SESSION_ATTACH            0x01
#define AMQP_0_10_METHOD_SESSION_ATTACHED          0x02
#define AMQP_0_10_METHOD_SESSION_DETACH            0x03
#define AMQP_0_10_METHOD_SESSION_DETACHED          0x04
#define AMQP_0_10_METHOD_SESSION_REQUEST_TIMEOUT   0x05
#define AMQP_0_10_METHOD_SESSION_TIMEOUT           0x06
#define AMQP_0_10_METHOD_SESSION_COMMAND_POINT     0x07
#define AMQP_0_10_METHOD_SESSION_EXPECTED          0x08
#define AMQP_0_10_METHOD_SESSION_CONFIRMED         0x09
#define AMQP_0_10_METHOD_SESSION_COMPLETED         0x0a
#define AMQP_0_10_METHOD_SESSION_KNOWN_COMPLETED   0x0b
#define AMQP_0_10_METHOD_SESSION_FLUSH             0x0c
#define AMQP_0_10_METHOD_SESSION_GAP               0x0d

#define AMQP_0_10_CLASS_EXECUTION            0x03
#define AMQP_0_10_METHOD_EXECUTION_SYNC            0x01
#define AMQP_0_10_METHOD_EXECUTION_RESULT          0x02
#define AMQP_0_10_METHOD_EXECUTION_EXCEPTION       0x03

#define AMQP_0_10_CLASS_MESSAGE              0x04
#define AMQP_0_10_STRUCT_MESSAGE_DELIVERY_PROPERTIES   0x01
#define AMQP_0_10_STRUCT_MESSAGE_FRAGMENT_PROPERTIES   0x02
#define AMQP_0_10_STRUCT_MESSAGE_MESSAGE_PROPERTIES    0x03
#define AMQP_0_10_STRUCT_MESSAGE_ACQUIRED              0x04
#define AMQP_0_10_STRUCT_MESSAGE_RESUME_RESULT         0x05
#define AMQP_0_10_METHOD_MESSAGE_TRANSFER          0x01
#define AMQP_0_10_METHOD_MESSAGE_ACCEPT            0x02
#define AMQP_0_10_METHOD_MESSAGE_REJECT            0x03
#define AMQP_0_10_METHOD_MESSAGE_RELEASE           0x04
#define AMQP_0_10_METHOD_MESSAGE_ACQUIRE           0x05
#define AMQP_0_10_METHOD_MESSAGE_RESUME            0x06
#define AMQP_0_10_METHOD_MESSAGE_SUBSCRIBE         0x07
#define AMQP_0_10_METHOD_MESSAGE_CANCEL            0x08
#define AMQP_0_10_METHOD_MESSAGE_SET_FLOW_MODE     0x09
#define AMQP_0_10_METHOD_MESSAGE_FLOW              0x0a
#define AMQP_0_10_METHOD_MESSAGE_FLUSH             0x0b
#define AMQP_0_10_METHOD_MESSAGE_STOP              0x0c

#define AMQP_0_10_CLASS_TX                   0x05
#define AMQP_0_10_METHOD_TX_SELECT                 0x01
#define AMQP_0_10_METHOD_TX_COMMIT                 0x02
#define AMQP_0_10_METHOD_TX_ROLLBACK               0x03

#define AMQP_0_10_CLASS_DTX                  0x06
#define AMQP_0_10_STRUCT_DTX_XA_RESULT          0x01
#define AMQP_0_10_STRUCT_DTX_RECOVER_RESULT     0x03
#define AMQP_0_10_METHOD_DTX_SELECT                0x01
#define AMQP_0_10_METHOD_DTX_START                 0x02
#define AMQP_0_10_METHOD_DTX_END                   0x03
#define AMQP_0_10_METHOD_DTX_COMMIT                0x04
#define AMQP_0_10_METHOD_DTX_FORGET                0x05
#define AMQP_0_10_METHOD_DTX_GET_TIMEOUT           0x06
#define AMQP_0_10_METHOD_DTX_PREPARE               0x07
#define AMQP_0_10_METHOD_DTX_RECOVER               0x08
#define AMQP_0_10_METHOD_DTX_ROLLBACK              0x09
#define AMQP_0_10_METHOD_DTX_SET_TIMEOUT           0x0a

#define AMQP_0_10_CLASS_EXCHANGE             0x07
#define AMQP_0_10_STRUCT_EXCHANGE_QUERY_RESULT  0x01
#define AMQP_0_10_STRUCT_EXCHANGE_BOUND_RESULT  0x02
#define AMQP_0_10_METHOD_EXCHANGE_DECLARE          0x01
#define AMQP_0_10_METHOD_EXCHANGE_DELETE           0x02
#define AMQP_0_10_METHOD_EXCHANGE_QUERY            0x03
#define AMQP_0_10_METHOD_EXCHANGE_BIND             0x04
#define AMQP_0_10_METHOD_EXCHANGE_UNBIND           0x05
#define AMQP_0_10_METHOD_EXCHANGE_BOUND            0x06

#define AMQP_0_10_CLASS_QUEUE                0x08
#define AMQP_0_10_STRUCT_QUEUE_QUERY_RESULT     0x01
#define AMQP_0_10_METHOD_QUEUE_DECLARE             0x01
#define AMQP_0_10_METHOD_QUEUE_DELETE              0x02
#define AMQP_0_10_METHOD_QUEUE_PURGE               0x03
#define AMQP_0_10_METHOD_QUEUE_QUERY               0x04

#define AMQP_0_10_CLASS_FILE                 0x09
#define AMQP_0_10_STRUCT_FILE_PROPERTIES        0x01
#define AMQP_0_10_METHOD_FILE_QOS                  0x01
#define AMQP_0_10_METHOD_FILE_QOS_OK               0x02
#define AMQP_0_10_METHOD_FILE_CONSUME              0x03
#define AMQP_0_10_METHOD_FILE_CONSUME_OK           0x04
#define AMQP_0_10_METHOD_FILE_CANCEL               0x05
#define AMQP_0_10_METHOD_FILE_OPEN                 0x06
#define AMQP_0_10_METHOD_FILE_OPEN_OK              0x07
#define AMQP_0_10_METHOD_FILE_STAGE                0x08
#define AMQP_0_10_METHOD_FILE_PUBLISH              0x09
#define AMQP_0_10_METHOD_FILE_RETURN               0x0a
#define AMQP_0_10_METHOD_FILE_DELIVER              0x0b
#define AMQP_0_10_METHOD_FILE_ACK                  0x0c
#define AMQP_0_10_METHOD_FILE_REJECT               0x0d

#define AMQP_0_10_CLASS_STREAM               0x0a
#define AMQP_0_10_STRUCT_STREAM_PROPERTIES      0x01
#define AMQP_0_10_METHOD_STREAM_QOS                0x01
#define AMQP_0_10_METHOD_STREAM_QOS_OK             0x02
#define AMQP_0_10_METHOD_STREAM_CONSUME            0x03
#define AMQP_0_10_METHOD_STREAM_CONSUME_OK         0x04
#define AMQP_0_10_METHOD_STREAM_CANCEL             0x05
#define AMQP_0_10_METHOD_STREAM_PUBLISH            0x06
#define AMQP_0_10_METHOD_STREAM_RETURN             0x07
#define AMQP_0_10_METHOD_STREAM_DELIVER            0x08

/*  Private functions  */

static void
dissect_amqp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
check_amqp_version(tvbuff_t *tvb, amqp_conv *conn);

static guint
get_amqp_0_10_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset);

static guint
get_amqp_0_9_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset);

static void
dissect_amqp_0_9_field_table(tvbuff_t *tvb, packet_info *pinfo, int offset, guint length, proto_item *item);

static void
dissect_amqp_0_10_map(tvbuff_t *tvb,
                      int offset,
                      int bound,
                      int length,
                      proto_item *item);

static void
dissect_amqp_0_10_array(tvbuff_t *tvb,
                        int offset,
                        int bound,
                        int length,
                        proto_item *item);

static void
dissect_amqp_0_10_xid (tvbuff_t *tvb,
                       int offset,
                       guint16 xid_length,
                       proto_item *ti);

static void
dissect_amqp_0_10_connection(tvbuff_t *tvb,
                             packet_info *pinfo,
                             proto_tree *tree,
                             int offset, guint16 length);

static void
dissect_amqp_0_10_session(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *tree,
                          int offset, guint16 length);

static void
dissect_amqp_0_10_execution(tvbuff_t *tvb,
                            packet_info *pinfo,
                            proto_tree *tree,
                            int offset, guint16 length);

static void
dissect_amqp_0_10_message(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *tree,
                          int offset, guint16 length);

static void
dissect_amqp_0_10_tx(tvbuff_t *tvb,
                     packet_info *pinfo,
                     proto_tree *tree,
                     int offset, guint16 length);

static void
dissect_amqp_0_10_dtx(tvbuff_t *tvb,
                      packet_info *pinfo,
                      proto_tree *tree,
                      int offset, guint16 length);

static void
dissect_amqp_0_10_exchange(tvbuff_t *tvb,
                           packet_info *pinfo,
                           proto_tree *tree,
                           int offset, guint16 length);

static void
dissect_amqp_0_10_queue(tvbuff_t *tvb,
                        packet_info *pinfo,
                        proto_tree *tree,
                        int offset, guint16 length);

static void
dissect_amqp_0_10_file(tvbuff_t *tvb,
                       packet_info *pinfo,
                       proto_tree *tree,
                       int offset, guint16 length);

static void
dissect_amqp_0_10_stream(tvbuff_t *tvb,
                         packet_info *pinfo,
                         proto_tree *tree,
                         int offset, guint16 length);

static void
dissect_amqp_0_10_struct_delivery_properties(tvbuff_t *tvb,
                                             proto_tree *tree,
                                             int offset,
                                             guint32 struct_length);

static void
dissect_amqp_0_10_struct_fragment_properties(tvbuff_t *tvb,
                                             proto_tree *tree,
                                             int offset,
                                             guint32 struct_length);

static void
dissect_amqp_0_10_struct_message_properties(tvbuff_t *tvb,
                                            proto_tree *tree,
                                            int offset,
                                            guint32 struct_length);

static void
dissect_amqp_0_10_struct_exchange_query_result(tvbuff_t *tvb,
                                               proto_tree *tree,
                                               int offset,
                                               guint32 struct_length);

static void
dissect_amqp_0_10_struct_queue_query_result(tvbuff_t *tvb,
                                            proto_tree *tree,
                                            int offset,
                                            guint32 struct_length);

static void
dissect_amqp_0_10_struct_file_properties(tvbuff_t *tvb,
                                         proto_tree *tree,
                                         int offset,
                                         guint32 struct_length);

static void
dissect_amqp_0_10_struct_stream_properties(tvbuff_t *tvb,
                                           proto_tree *tree,
                                           int offset,
                                           guint32 struct_length);

static void
dissect_amqp_0_10_struct32(tvbuff_t *tvb, proto_tree *tree,
                           int offset, guint32 struct_length);

static void
dissect_amqp_0_10_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_amqp_0_9_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int
dissect_amqp_0_9_method_connection_start(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_start_ok(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_secure(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_secure_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_tune(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_tune_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_open(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_open_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_redirect(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_close(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_connection_close_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_open(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_open_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_flow(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_flow_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_close(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_close_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_resume(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_ping(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_pong(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_channel_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_access_request(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_access_request_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_exchange_declare(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_exchange_declare_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_exchange_bind(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_exchange_bind_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_);

static int
dissect_amqp_0_9_method_exchange_delete(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_exchange_delete_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_declare(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_declare_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_bind(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_bind_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_unbind(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_unbind_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_purge(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_purge_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_delete(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_queue_delete_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_qos(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_qos_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_consume(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_consume_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_cancel(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_cancel_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_publish(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_return(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_deliver(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_get(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_get_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_get_empty(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_ack(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_reject(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_basic_recover(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_qos(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_qos_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_consume(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_consume_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_cancel(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_cancel_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_open(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_open_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_stage(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_publish(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_return(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_deliver(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_ack(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_file_reject(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_qos(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_qos_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_consume(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_consume_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_cancel(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_cancel_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_publish(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_return(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_stream_deliver(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_tx_select(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_tx_select_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_tx_commit(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_tx_commit_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_tx_rollback(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_tx_rollback_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_dtx_select(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_dtx_select_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_dtx_start(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_dtx_start_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_method_tunnel_request(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree);

static int
dissect_amqp_0_9_content_header_basic(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *prop_tree);

static int
dissect_amqp_0_9_content_header_file(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *prop_tree);

static int
dissect_amqp_0_9_content_header_stream(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *prop_tree);

static int
dissect_amqp_0_9_content_header_tunnel(tvbuff_t *tvb, packet_info *pifo,
    int offset, proto_tree *prop_tree);

/*  AMQP 0-10 type decoding information  */

typedef int (*type_formatter)(tvbuff_t *tvb,
                              guint offset,   /* In tvb where data starts */
                              guint bound,    /* Last byte in tvb */
                              guint length,   /* Length of data, if known */
                              const char **value); /* Receive formatted val */
struct amqp_typeinfo {
    guint8 typecode;        /* From AMQP 0-10 spec */
    const char *typename;
    type_formatter formatter;
    guint known_size;
};
static gboolean
get_amqp_0_10_type_formatter(guint8 code,
                             const char **name,
                             type_formatter *decoder,
                             guint *length_size);

static int
format_amqp_0_10_bin(tvbuff_t *tvb,
                     guint offset, guint bound, guint length,
                     const char **value);

static int
format_amqp_0_10_int(tvbuff_t *tvb,
                     guint offset, guint bound, guint length,
                     const char **value);

static int
format_amqp_0_10_uint(tvbuff_t *tvb,
                      guint offset, guint bound, guint length,
                      const char **value);

static int
format_amqp_0_10_char(tvbuff_t *tvb,
                      guint offset, guint bound, guint length,
                      const char **value);

static int
format_amqp_0_10_boolean(tvbuff_t *tvb,
                         guint offset, guint bound, guint length,
                         const char **value);

static int
format_amqp_0_10_vbin(tvbuff_t *tvb,
                      guint offset, guint bound, guint length,
                      const char **value);

static int
format_amqp_0_10_str(tvbuff_t *tvb,
                     guint offset, guint bound, guint length,
                     const char **value);

static void
format_amqp_0_10_sequence_set(tvbuff_t *tvb, guint offset, guint length,
                              proto_item *item);

/*  Various handles  */

static int proto_amqp = -1;

/* 0-10 handles */

static int hf_amqp_0_10_format = -1;
static int hf_amqp_0_10_position = -1;
static int hf_amqp_0_10_type = -1;
static int hf_amqp_0_10_size = -1;
static int hf_amqp_0_10_track = -1;
static int hf_amqp_0_10_class = -1;
static int hf_amqp_0_10_connection_method = -1;
static int hf_amqp_0_10_session_method = -1;
static int hf_amqp_0_10_execution_method = -1;
static int hf_amqp_0_10_message_method = -1;
static int hf_amqp_0_10_tx_method = -1;
static int hf_amqp_0_10_dtx_method = -1;
static int hf_amqp_0_10_exchange_method = -1;
static int hf_amqp_0_10_queue_method = -1;
static int hf_amqp_0_10_file_method = -1;
static int hf_amqp_0_10_stream_method = -1;
static int hf_amqp_0_10_argument_packing_flags = -1;
static int hf_amqp_0_10_session_header_sync = -1;
static int hf_amqp_0_10_undissected_struct32 = -1;
static int hf_amqp_0_10_message_body = -1;
static int hf_amqp_0_10_dtx_xid = -1;
static int hf_amqp_0_10_dtx_xid_format = -1;
static int hf_amqp_0_10_dtx_xid_global_id = -1;
static int hf_amqp_0_10_dtx_xid_branch_id = -1;
static int hf_amqp_0_10_struct_delivery_properties_discard_unroutable = -1;
static int hf_amqp_0_10_struct_delivery_properties_immediate = -1;
static int hf_amqp_0_10_struct_delivery_properties_redelivered = -1;
static int hf_amqp_0_10_struct_delivery_properties_priority = -1;
static int hf_amqp_0_10_struct_delivery_properties_mode = -1;
static int hf_amqp_0_10_struct_delivery_properties_ttl = -1;
static int hf_amqp_0_10_struct_delivery_properties_timestamp = -1;
static int hf_amqp_0_10_struct_delivery_properties_expiration = -1;
static int hf_amqp_0_10_struct_delivery_properties_exchange = -1;
static int hf_amqp_0_10_struct_delivery_properties_routing_key = -1;
static int hf_amqp_0_10_struct_delivery_properties_resume_ttl = -1;
static int hf_amqp_0_10_struct_fragment_properties_first = -1;
static int hf_amqp_0_10_struct_fragment_properties_last = -1;
static int hf_amqp_0_10_struct_fragment_properties_size = -1;
static int hf_amqp_0_10_struct_message_properties = -1;
static int hf_amqp_0_10_struct_message_properties_content_len = -1;
static int hf_amqp_0_10_struct_message_properties_message_id = -1;
static int hf_amqp_0_10_struct_message_properties_correlation = -1;
static int hf_amqp_0_10_struct_message_properties_reply_to = -1;
static int hf_amqp_0_10_struct_message_properties_content_type = -1;
static int hf_amqp_0_10_struct_message_properties_content_encoding = -1;
static int hf_amqp_0_10_struct_message_properties_user_id = -1;
static int hf_amqp_0_10_struct_message_properties_app_id = -1;
static int hf_amqp_0_10_struct_message_properties_application_headers = -1;
static int hf_amqp_0_10_struct_reply_to_exchange = -1;
static int hf_amqp_0_10_struct_reply_to_routing_key = -1;
static int hf_amqp_0_10_struct_acquired_transfers = -1;
static int hf_amqp_0_10_struct_resume_result_offset = -1;
static int hf_amqp_0_10_struct_exchange_query_result_durable = -1;
static int hf_amqp_0_10_struct_exchange_query_result_not_found = -1;
static int hf_amqp_0_10_struct_exchange_bound_result_exchange_not_found = -1;
static int hf_amqp_0_10_struct_exchange_bound_result_queue_not_found = -1;
static int hf_amqp_0_10_struct_exchange_bound_result_queue_not_matched = -1;
static int hf_amqp_0_10_struct_exchange_bound_result_key_not_matched = -1;
static int hf_amqp_0_10_struct_exchange_bound_result_args_not_matched = -1;
static int hf_amqp_0_10_struct_queue_query_result_durable = -1;
static int hf_amqp_0_10_struct_queue_query_result_exclusive = -1;
static int hf_amqp_0_10_struct_queue_query_result_auto_delete = -1;
static int hf_amqp_0_10_struct_queue_query_result_message_count = -1;
static int hf_amqp_0_10_struct_queue_query_result_subscriber_count = -1;
static int hf_amqp_0_10_struct_file_properties_content_type = -1;
static int hf_amqp_0_10_struct_file_properties_content_encoding = -1;
static int hf_amqp_0_10_struct_file_properties_headers = -1;
static int hf_amqp_0_10_struct_file_properties_priority = -1;
static int hf_amqp_0_10_struct_file_properties_reply_to = -1;
static int hf_amqp_0_10_struct_file_properties_message_id = -1;
static int hf_amqp_0_10_struct_file_properties_filename = -1;
static int hf_amqp_0_10_struct_file_properties_timestamp = -1;
static int hf_amqp_0_10_struct_file_properties_cluster_id = -1;
static int hf_amqp_0_10_struct_stream_properties_content_type = -1;
static int hf_amqp_0_10_struct_stream_properties_content_encoding = -1;
static int hf_amqp_0_10_struct_stream_properties_headers = -1;
static int hf_amqp_0_10_struct_stream_properties_priority = -1;
static int hf_amqp_0_10_struct_stream_properties_timestamp = -1;
static int hf_amqp_0_10_method_session_attach_name = -1;
static int hf_amqp_0_10_method_session_attach_force = -1;
static int hf_amqp_0_10_method_session_detached_code = -1;
static int hf_amqp_0_10_method_session_timeout = -1;
static int hf_amqp_0_10_method_session_completed_timely = -1;
static int hf_amqp_0_10_method_session_flush_expected = -1;
static int hf_amqp_0_10_method_session_flush_confirmed = -1;
static int hf_amqp_0_10_method_session_flush_completed = -1;
static int hf_amqp_0_10_method_session_command_point_id = -1;
static int hf_amqp_0_10_method_session_command_point_offset = -1;
static int hf_amqp_0_10_method_session_commands = -1;
static int hf_amqp_0_10_method_session_fragments = -1;
static int hf_amqp_0_10_method_execution_command_id = -1;
static int hf_amqp_0_10_method_execution_exception_error = -1;
static int hf_amqp_0_10_method_execution_field_index = -1;
static int hf_amqp_0_10_method_execution_description = -1;
static int hf_amqp_0_10_method_execution_error_info = -1;
static int hf_amqp_0_10_method_message_transfer_destination = -1;
static int hf_amqp_0_10_method_message_transfer_accept_mode = -1;
static int hf_amqp_0_10_method_message_transfer_acquire_mode = -1;
static int hf_amqp_0_10_method_message_accept_transfers = -1;
static int hf_amqp_0_10_method_message_transfer_reject_code = -1;
static int hf_amqp_0_10_method_message_reject_text = -1;
static int hf_amqp_0_10_method_message_release_set_redelivered = -1;
static int hf_amqp_0_10_method_message_dest = -1;
static int hf_amqp_0_10_method_message_resume_id = -1;
static int hf_amqp_0_10_method_message_subscribe_queue = -1;
static int hf_amqp_0_10_method_message_subscribe_exclusive = -1;
static int hf_amqp_0_10_method_message_subscribe_resume_ttl = -1;
static int hf_amqp_0_10_method_message_subscribe_args = -1;
static int hf_amqp_0_10_method_message_flow_mode = -1;
static int hf_amqp_0_10_method_message_credit_unit = -1;
static int hf_amqp_0_10_method_message_credit_value = -1;
static int hf_amqp_0_10_method_dtx_start_join = -1;
static int hf_amqp_0_10_method_dtx_start_resume = -1;
static int hf_amqp_0_10_method_dtx_end_fail = -1;
static int hf_amqp_0_10_method_dtx_end_suspend = -1;
static int hf_amqp_0_10_method_dtx_commit_one_phase = -1;
static int hf_amqp_0_10_method_dtx_set_timeout_timeout = -1;
static int hf_amqp_0_10_method_exchange_declare_exchange = -1;
static int hf_amqp_0_10_method_exchange_declare_type = -1;
static int hf_amqp_0_10_method_exchange_declare_alt_exchange = -1;
static int hf_amqp_0_10_method_exchange_declare_passive = -1;
static int hf_amqp_0_10_method_exchange_declare_durable = -1;
static int hf_amqp_0_10_method_exchange_declare_auto_delete = -1;
static int hf_amqp_0_10_method_exchange_declare_arguments = -1;
static int hf_amqp_0_10_method_exchange_delete_if_unused = -1;
static int hf_amqp_0_10_method_exchange_bind_queue = -1;
static int hf_amqp_0_10_method_exchange_binding_key = -1;
static int hf_amqp_0_10_method_queue_name = -1;
static int hf_amqp_0_10_method_queue_alt_exchange = -1;
static int hf_amqp_0_10_method_queue_declare_passive = -1;
static int hf_amqp_0_10_method_queue_declare_durable = -1;
static int hf_amqp_0_10_method_queue_declare_exclusive = -1;
static int hf_amqp_0_10_method_queue_declare_auto_delete = -1;
static int hf_amqp_0_10_method_queue_declare_arguments = -1;
static int hf_amqp_0_10_method_queue_delete_if_unused = -1;
static int hf_amqp_0_10_method_queue_delete_if_empty = -1;
static int hf_amqp_0_10_method_file_qos_prefetch_size = -1;
static int hf_amqp_0_10_method_file_qos_prefetch_count = -1;
static int hf_amqp_0_10_method_file_qos_global = -1;
static int hf_amqp_0_10_method_file_consumer_tag = -1;
static int hf_amqp_0_10_method_file_consume_no_local = -1;
static int hf_amqp_0_10_method_file_consume_no_ack = -1;
static int hf_amqp_0_10_method_file_consume_exclusive = -1;
static int hf_amqp_0_10_method_file_consume_nowait = -1;
static int hf_amqp_0_10_method_file_consume_arguments = -1;
static int hf_amqp_0_10_method_file_identifier = -1;
static int hf_amqp_0_10_method_file_open_content_size = -1;
static int hf_amqp_0_10_method_file_open_ok_staged_size = -1;
static int hf_amqp_0_10_method_file_publish_exchange = -1;
static int hf_amqp_0_10_method_file_publish_routing_key = -1;
static int hf_amqp_0_10_method_file_publish_mandatory = -1;
static int hf_amqp_0_10_method_file_publish_immediate = -1;
static int hf_amqp_0_10_method_file_return_reply_code = -1;
static int hf_amqp_0_10_method_file_return_reply_text = -1;
static int hf_amqp_0_10_method_file_return_exchange = -1;
static int hf_amqp_0_10_method_file_return_routing_key = -1;
static int hf_amqp_0_10_method_file_deliver_consumer_tag = -1;
static int hf_amqp_0_10_method_file_deliver_delivery_tag = -1;
static int hf_amqp_0_10_method_file_deliver_redelivered = -1;
static int hf_amqp_0_10_method_file_deliver_exchange = -1;
static int hf_amqp_0_10_method_file_deliver_routing_key = -1;
static int hf_amqp_0_10_method_file_ack_delivery_tag = -1;
static int hf_amqp_0_10_method_file_ack_multiple = -1;
static int hf_amqp_0_10_method_file_reject_delivery_tag = -1;
static int hf_amqp_0_10_method_file_reject_requeue = -1;
static int hf_amqp_0_10_method_stream_qos_prefetch_size = -1;
static int hf_amqp_0_10_method_stream_qos_prefetch_count = -1;
static int hf_amqp_0_10_method_stream_qos_consume_rate = -1;
static int hf_amqp_0_10_method_stream_qos_global = -1;
static int hf_amqp_0_10_method_stream_consumer_tag = -1;
static int hf_amqp_0_10_method_stream_consume_no_local = -1;
static int hf_amqp_0_10_method_stream_consume_exclusive = -1;
static int hf_amqp_0_10_method_stream_consume_nowait = -1;
static int hf_amqp_0_10_method_stream_consume_arguments = -1;
static int hf_amqp_0_10_method_stream_publish_exchange = -1;
static int hf_amqp_0_10_method_stream_publish_routing_key = -1;
static int hf_amqp_0_10_method_stream_publish_mandatory = -1;
static int hf_amqp_0_10_method_stream_publish_immediate = -1;
static int hf_amqp_0_10_method_stream_return_reply_code = -1;
static int hf_amqp_0_10_method_stream_return_reply_text = -1;
static int hf_amqp_0_10_method_stream_return_exchange = -1;
static int hf_amqp_0_10_method_stream_return_routing_key = -1;
static int hf_amqp_0_10_method_stream_deliver_consumer_tag = -1;
static int hf_amqp_0_10_method_stream_deliver_delivery_tag = -1;
static int hf_amqp_0_10_method_stream_deliver_exchange = -1;
static int hf_amqp_0_10_method_stream_deliver_queue = -1;
static int hf_amqp_channel = -1;
static int hf_amqp_0_9_type = -1;
static int hf_amqp_0_9_length = -1;
static int hf_amqp_0_9_method_class_id = -1;
static int hf_amqp_method_connection_method_id = -1;
static int hf_amqp_method_channel_method_id = -1;
static int hf_amqp_method_access_method_id = -1;
static int hf_amqp_method_exchange_method_id = -1;
static int hf_amqp_method_queue_method_id = -1;
static int hf_amqp_method_basic_method_id = -1;
static int hf_amqp_method_file_method_id = -1;
static int hf_amqp_method_stream_method_id = -1;
static int hf_amqp_method_tx_method_id = -1;
static int hf_amqp_method_dtx_method_id = -1;
static int hf_amqp_method_tunnel_method_id = -1;
static int hf_amqp_method_arguments = -1;
static int hf_amqp_method_connection_start_version_major = -1;
static int hf_amqp_method_connection_start_version_minor = -1;
static int hf_amqp_method_connection_start_server_properties = -1;
static int hf_amqp_0_9_method_connection_start_mechanisms = -1;
static int hf_amqp_0_10_method_connection_start_mechanisms = -1;
static int hf_amqp_0_9_method_connection_start_locales = -1;
static int hf_amqp_0_10_method_connection_start_locales = -1;
static int hf_amqp_method_connection_start_ok_client_properties = -1;
static int hf_amqp_method_connection_start_ok_mechanism = -1;
static int hf_amqp_method_connection_start_ok_response = -1;
static int hf_amqp_method_connection_start_ok_locale = -1;
static int hf_amqp_method_connection_secure_challenge = -1;
static int hf_amqp_method_connection_secure_ok_response = -1;
static int hf_amqp_method_connection_tune_channel_max = -1;
static int hf_amqp_0_9_method_connection_tune_frame_max = -1;
static int hf_amqp_0_10_method_connection_tune_frame_max = -1;
static int hf_amqp_0_9_method_connection_tune_heartbeat = -1;
static int hf_amqp_0_10_method_connection_tune_heartbeat_min = -1;
static int hf_amqp_0_10_method_connection_tune_heartbeat_max = -1;
static int hf_amqp_method_connection_tune_ok_channel_max = -1;
static int hf_amqp_0_9_method_connection_tune_ok_frame_max = -1;
static int hf_amqp_0_10_method_connection_tune_ok_frame_max = -1;
static int hf_amqp_method_connection_tune_ok_heartbeat = -1;
static int hf_amqp_method_connection_open_virtual_host = -1;
static int hf_amqp_0_9_method_connection_open_capabilities = -1;
static int hf_amqp_0_10_method_connection_open_capabilities = -1;
static int hf_amqp_0_9_method_connection_open_insist = -1;
static int hf_amqp_0_10_method_connection_open_insist = -1;
static int hf_amqp_0_9_method_connection_open_ok_known_hosts = -1;
static int hf_amqp_0_10_method_connection_open_ok_known_hosts = -1;
static int hf_amqp_method_connection_redirect_host = -1;
static int hf_amqp_0_9_method_connection_redirect_known_hosts = -1;
static int hf_amqp_0_10_method_connection_redirect_known_hosts = -1;
static int hf_amqp_0_9_method_connection_close_reply_code = -1;
static int hf_amqp_0_10_method_connection_close_reply_code = -1;
static int hf_amqp_method_connection_close_reply_text = -1;
static int hf_amqp_method_connection_close_class_id = -1;
static int hf_amqp_method_connection_close_method_id = -1;
static int hf_amqp_method_channel_open_out_of_band = -1;
static int hf_amqp_method_channel_open_ok_channel_id = -1;
static int hf_amqp_method_channel_flow_active = -1;
static int hf_amqp_method_channel_flow_ok_active = -1;
static int hf_amqp_method_channel_close_reply_code = -1;
static int hf_amqp_method_channel_close_reply_text = -1;
static int hf_amqp_method_channel_close_class_id = -1;
static int hf_amqp_method_channel_close_method_id = -1;
static int hf_amqp_method_channel_resume_channel_id = -1;
static int hf_amqp_method_access_request_realm = -1;
static int hf_amqp_method_access_request_exclusive = -1;
static int hf_amqp_method_access_request_passive = -1;
static int hf_amqp_method_access_request_active = -1;
static int hf_amqp_method_access_request_write = -1;
static int hf_amqp_method_access_request_read = -1;
static int hf_amqp_method_access_request_ok_ticket = -1;
static int hf_amqp_method_exchange_declare_ticket = -1;
static int hf_amqp_method_exchange_declare_exchange = -1;
static int hf_amqp_method_exchange_declare_type = -1;
static int hf_amqp_method_exchange_declare_passive = -1;
static int hf_amqp_method_exchange_declare_durable = -1;
static int hf_amqp_method_exchange_declare_auto_delete = -1;
static int hf_amqp_method_exchange_declare_internal = -1;
static int hf_amqp_method_exchange_declare_nowait = -1;
static int hf_amqp_method_exchange_declare_arguments = -1;
static int hf_amqp_method_exchange_bind_destination = -1;
static int hf_amqp_method_exchange_bind_source = -1;
static int hf_amqp_method_exchange_bind_routing_key = -1;
static int hf_amqp_method_exchange_bind_nowait = -1;
static int hf_amqp_method_exchange_bind_arguments = -1;
static int hf_amqp_method_exchange_delete_ticket = -1;
static int hf_amqp_method_exchange_delete_exchange = -1;
static int hf_amqp_method_exchange_delete_if_unused = -1;
static int hf_amqp_method_exchange_delete_nowait = -1;
static int hf_amqp_method_queue_declare_ticket = -1;
static int hf_amqp_method_queue_declare_queue = -1;
static int hf_amqp_method_queue_declare_passive = -1;
static int hf_amqp_method_queue_declare_durable = -1;
static int hf_amqp_method_queue_declare_exclusive = -1;
static int hf_amqp_method_queue_declare_auto_delete = -1;
static int hf_amqp_method_queue_declare_nowait = -1;
static int hf_amqp_method_queue_declare_arguments = -1;
static int hf_amqp_method_queue_declare_ok_queue = -1;
static int hf_amqp_method_queue_declare_ok_message_count = -1;
static int hf_amqp_method_queue_declare_ok_consumer_count = -1;
static int hf_amqp_method_queue_bind_ticket = -1;
static int hf_amqp_method_queue_bind_queue = -1;
static int hf_amqp_method_queue_bind_exchange = -1;
static int hf_amqp_method_queue_bind_routing_key = -1;
static int hf_amqp_method_queue_bind_nowait = -1;
static int hf_amqp_method_queue_bind_arguments = -1;
static int hf_amqp_method_queue_unbind_ticket = -1;
static int hf_amqp_method_queue_unbind_queue = -1;
static int hf_amqp_method_queue_unbind_exchange = -1;
static int hf_amqp_method_queue_unbind_routing_key = -1;
static int hf_amqp_method_queue_unbind_arguments = -1;
static int hf_amqp_method_queue_purge_ticket = -1;
static int hf_amqp_method_queue_purge_queue = -1;
static int hf_amqp_method_queue_purge_nowait = -1;
static int hf_amqp_method_queue_purge_ok_message_count = -1;
static int hf_amqp_method_queue_delete_ticket = -1;
static int hf_amqp_method_queue_delete_queue = -1;
static int hf_amqp_method_queue_delete_if_unused = -1;
static int hf_amqp_method_queue_delete_if_empty = -1;
static int hf_amqp_method_queue_delete_nowait = -1;
static int hf_amqp_method_queue_delete_ok_message_count = -1;
static int hf_amqp_method_basic_qos_prefetch_size = -1;
static int hf_amqp_method_basic_qos_prefetch_count = -1;
static int hf_amqp_method_basic_qos_global = -1;
static int hf_amqp_method_basic_consume_ticket = -1;
static int hf_amqp_method_basic_consume_queue = -1;
static int hf_amqp_method_basic_consume_consumer_tag = -1;
static int hf_amqp_method_basic_consume_no_local = -1;
static int hf_amqp_method_basic_consume_no_ack = -1;
static int hf_amqp_method_basic_consume_exclusive = -1;
static int hf_amqp_method_basic_consume_nowait = -1;
static int hf_amqp_method_basic_consume_filter = -1;
static int hf_amqp_method_basic_consume_ok_consumer_tag = -1;
static int hf_amqp_method_basic_cancel_consumer_tag = -1;
static int hf_amqp_method_basic_cancel_nowait = -1;
static int hf_amqp_method_basic_cancel_ok_consumer_tag = -1;
static int hf_amqp_method_basic_publish_ticket = -1;
static int hf_amqp_method_basic_publish_exchange = -1;
static int hf_amqp_method_basic_publish_routing_key = -1;
static int hf_amqp_method_basic_publish_mandatory = -1;
static int hf_amqp_method_basic_publish_immediate = -1;
static int hf_amqp_method_basic_return_reply_code = -1;
static int hf_amqp_method_basic_return_reply_text = -1;
static int hf_amqp_method_basic_return_exchange = -1;
static int hf_amqp_method_basic_return_routing_key = -1;
static int hf_amqp_method_basic_deliver_consumer_tag = -1;
static int hf_amqp_method_basic_deliver_delivery_tag = -1;
static int hf_amqp_method_basic_deliver_redelivered = -1;
static int hf_amqp_method_basic_deliver_exchange = -1;
static int hf_amqp_method_basic_deliver_routing_key = -1;
static int hf_amqp_method_basic_get_ticket = -1;
static int hf_amqp_method_basic_get_queue = -1;
static int hf_amqp_method_basic_get_no_ack = -1;
static int hf_amqp_method_basic_get_ok_delivery_tag = -1;
static int hf_amqp_method_basic_get_ok_redelivered = -1;
static int hf_amqp_method_basic_get_ok_exchange = -1;
static int hf_amqp_method_basic_get_ok_routing_key = -1;
static int hf_amqp_method_basic_get_ok_message_count = -1;
static int hf_amqp_method_basic_get_empty_cluster_id = -1;
static int hf_amqp_method_basic_ack_delivery_tag = -1;
static int hf_amqp_method_basic_ack_multiple = -1;
static int hf_amqp_method_basic_reject_delivery_tag = -1;
static int hf_amqp_method_basic_reject_requeue = -1;
static int hf_amqp_method_basic_recover_requeue = -1;
static int hf_amqp_method_file_qos_prefetch_size = -1;
static int hf_amqp_method_file_qos_prefetch_count = -1;
static int hf_amqp_method_file_qos_global = -1;
static int hf_amqp_method_file_consume_ticket = -1;
static int hf_amqp_method_file_consume_queue = -1;
static int hf_amqp_method_file_consume_consumer_tag = -1;
static int hf_amqp_method_file_consume_no_local = -1;
static int hf_amqp_method_file_consume_no_ack = -1;
static int hf_amqp_method_file_consume_exclusive = -1;
static int hf_amqp_method_file_consume_nowait = -1;
static int hf_amqp_method_file_consume_filter = -1;
static int hf_amqp_method_file_consume_ok_consumer_tag = -1;
static int hf_amqp_method_file_cancel_consumer_tag = -1;
static int hf_amqp_method_file_cancel_nowait = -1;
static int hf_amqp_method_file_cancel_ok_consumer_tag = -1;
static int hf_amqp_method_file_open_identifier = -1;
static int hf_amqp_method_file_open_content_size = -1;
static int hf_amqp_method_file_open_ok_staged_size = -1;
static int hf_amqp_method_file_publish_ticket = -1;
static int hf_amqp_method_file_publish_exchange = -1;
static int hf_amqp_method_file_publish_routing_key = -1;
static int hf_amqp_method_file_publish_mandatory = -1;
static int hf_amqp_method_file_publish_immediate = -1;
static int hf_amqp_method_file_publish_identifier = -1;
static int hf_amqp_method_file_return_reply_code = -1;
static int hf_amqp_method_file_return_reply_text = -1;
static int hf_amqp_method_file_return_exchange = -1;
static int hf_amqp_method_file_return_routing_key = -1;
static int hf_amqp_method_file_deliver_consumer_tag = -1;
static int hf_amqp_method_file_deliver_delivery_tag = -1;
static int hf_amqp_method_file_deliver_redelivered = -1;
static int hf_amqp_method_file_deliver_exchange = -1;
static int hf_amqp_method_file_deliver_routing_key = -1;
static int hf_amqp_method_file_deliver_identifier = -1;
static int hf_amqp_method_file_ack_delivery_tag = -1;
static int hf_amqp_method_file_ack_multiple = -1;
static int hf_amqp_method_file_reject_delivery_tag = -1;
static int hf_amqp_method_file_reject_requeue = -1;
static int hf_amqp_method_stream_qos_prefetch_size = -1;
static int hf_amqp_method_stream_qos_prefetch_count = -1;
static int hf_amqp_method_stream_qos_consume_rate = -1;
static int hf_amqp_method_stream_qos_global = -1;
static int hf_amqp_method_stream_consume_ticket = -1;
static int hf_amqp_method_stream_consume_queue = -1;
static int hf_amqp_method_stream_consume_consumer_tag = -1;
static int hf_amqp_method_stream_consume_no_local = -1;
static int hf_amqp_method_stream_consume_exclusive = -1;
static int hf_amqp_method_stream_consume_nowait = -1;
static int hf_amqp_method_stream_consume_filter = -1;
static int hf_amqp_method_stream_consume_ok_consumer_tag = -1;
static int hf_amqp_method_stream_cancel_consumer_tag = -1;
static int hf_amqp_method_stream_cancel_nowait = -1;
static int hf_amqp_method_stream_cancel_ok_consumer_tag = -1;
static int hf_amqp_method_stream_publish_ticket = -1;
static int hf_amqp_method_stream_publish_exchange = -1;
static int hf_amqp_method_stream_publish_routing_key = -1;
static int hf_amqp_method_stream_publish_mandatory = -1;
static int hf_amqp_method_stream_publish_immediate = -1;
static int hf_amqp_method_stream_return_reply_code = -1;
static int hf_amqp_method_stream_return_reply_text = -1;
static int hf_amqp_method_stream_return_exchange = -1;
static int hf_amqp_method_stream_return_routing_key = -1;
static int hf_amqp_method_stream_deliver_consumer_tag = -1;
static int hf_amqp_method_stream_deliver_delivery_tag = -1;
static int hf_amqp_method_stream_deliver_exchange = -1;
static int hf_amqp_method_stream_deliver_queue = -1;
static int hf_amqp_method_dtx_start_dtx_identifier = -1;
static int hf_amqp_method_tunnel_request_meta_data = -1;
static int hf_amqp_field = -1;
static int hf_amqp_header_class_id = -1;
static int hf_amqp_header_weight = -1;
static int hf_amqp_header_body_size = -1;
static int hf_amqp_header_property_flags = -1;
static int hf_amqp_header_properties = -1;
static int hf_amqp_header_basic_content_type = -1;
static int hf_amqp_header_basic_content_encoding = -1;
static int hf_amqp_header_basic_headers = -1;
static int hf_amqp_header_basic_delivery_mode = -1;
static int hf_amqp_header_basic_priority = -1;
static int hf_amqp_header_basic_correlation_id = -1;
static int hf_amqp_header_basic_reply_to = -1;
static int hf_amqp_header_basic_expiration = -1;
static int hf_amqp_header_basic_message_id = -1;
static int hf_amqp_header_basic_timestamp = -1;
static int hf_amqp_header_basic_type = -1;
static int hf_amqp_header_basic_user_id = -1;
static int hf_amqp_header_basic_app_id = -1;
static int hf_amqp_header_basic_cluster_id = -1;
static int hf_amqp_header_file_content_type = -1;
static int hf_amqp_header_file_content_encoding = -1;
static int hf_amqp_header_file_headers = -1;
static int hf_amqp_header_file_priority = -1;
static int hf_amqp_header_file_reply_to = -1;
static int hf_amqp_header_file_message_id = -1;
static int hf_amqp_header_file_filename = -1;
static int hf_amqp_header_file_timestamp = -1;
static int hf_amqp_header_file_cluster_id = -1;
static int hf_amqp_header_stream_content_type = -1;
static int hf_amqp_header_stream_content_encoding = -1;
static int hf_amqp_header_stream_headers = -1;
static int hf_amqp_header_stream_priority = -1;
static int hf_amqp_header_stream_timestamp = -1;
static int hf_amqp_header_tunnel_headers = -1;
static int hf_amqp_header_tunnel_proxy_name = -1;
static int hf_amqp_header_tunnel_data_name = -1;
static int hf_amqp_header_tunnel_durable = -1;
static int hf_amqp_header_tunnel_broadcast = -1;
static int hf_amqp_payload = -1;
static int hf_amqp_init_protocol = -1;
static int hf_amqp_init_id_major = -1;
static int hf_amqp_init_id_minor = -1;
static int hf_amqp_init_version_major = -1;
static int hf_amqp_init_version_minor = -1;

static gint ett_amqp = -1;
static gint ett_header = -1;
static gint ett_args = -1;
static gint ett_props = -1;
static gint ett_field_table = -1;
static gint ett_amqp_init = -1;
static gint ett_amqp_0_10_map = -1;
static gint ett_amqp_0_10_array = -1;

/*  Various enumerations  */

static const value_string amqp_0_10_frame_position [] = {
    {0x00,  "----"},
    {0x01,  "---e"},
    {0x02,  "--b-"},
    {0x03,  "--be"},
    {0x04,  "-E--"},
    {0x05,  "-E-e"},
    {0x06,  "-Eb-"},
    {0x07,  "-Ebe"},
    {0x08,  "B---"},
    {0x09,  "B--e"},
    {0x0a,  "B-b-"},
    {0x0b,  "B-be"},
    {0x0c,  "BE--"},
    {0x0d,  "BE-e"},
    {0x0e,  "BEb-"},
    {0x0f,  "BEbe"},
    {0, NULL}
};

static const value_string amqp_0_10_frame_types [] = {
    {0,     "Control"},
    {1,     "Command"},
    {2,     "Header"},
    {3,     "Body"},
    {0, NULL}
};

static const value_string amqp_0_10_frame_tracks [] = {
    {0,     "Control"},
    {1,     "Command"},
    {0, NULL}
};

static const value_string amqp_0_10_class [] = {
    {AMQP_0_10_CLASS_CONNECTION,  "Connection"},
    {AMQP_0_10_CLASS_SESSION,     "Session"},
    {AMQP_0_10_CLASS_EXECUTION,   "Execution"},
    {AMQP_0_10_CLASS_MESSAGE,     "Message"},
    {AMQP_0_10_CLASS_TX,          "Tx"},
    {AMQP_0_10_CLASS_DTX,         "Dtx"},
    {AMQP_0_10_CLASS_EXCHANGE,    "Exchange"},
    {AMQP_0_10_CLASS_QUEUE,       "Queue"},
    {AMQP_0_10_CLASS_FILE,        "File"},
    {AMQP_0_10_CLASS_STREAM,      "Stream"},
    {0, NULL}
};

static const value_string amqp_0_10_connection_methods [] = {
    {AMQP_0_10_METHOD_CONNECTION_START,     "connection.start"},
    {AMQP_0_10_METHOD_CONNECTION_START_OK,  "connection.start-ok"},
    {AMQP_0_10_METHOD_CONNECTION_SECURE,    "connection.secure"},
    {AMQP_0_10_METHOD_CONNECTION_SECURE_OK, "connection.secure-ok"},
    {AMQP_0_10_METHOD_CONNECTION_TUNE,      "connection.tune"},
    {AMQP_0_10_METHOD_CONNECTION_TUNE_OK,   "connection.tune-ok"},
    {AMQP_0_10_METHOD_CONNECTION_OPEN,      "connection.open"},
    {AMQP_0_10_METHOD_CONNECTION_OPEN_OK,   "connection.open-ok"},
    {AMQP_0_10_METHOD_CONNECTION_REDIRECT,  "connection.redirect"},
    {AMQP_0_10_METHOD_CONNECTION_HEARTBEAT, "connection.heartbeat"},
    {AMQP_0_10_METHOD_CONNECTION_CLOSE,     "connection.close"},
    {AMQP_0_10_METHOD_CONNECTION_CLOSE_OK,  "connection.close-ok"},
    {0, NULL}
};

static const value_string amqp_0_10_session_methods [] = {
    {AMQP_0_10_METHOD_SESSION_ATTACH,           "session.attach"},
    {AMQP_0_10_METHOD_SESSION_ATTACHED,         "session.attached"},
    {AMQP_0_10_METHOD_SESSION_DETACH,           "session.detach"},
    {AMQP_0_10_METHOD_SESSION_DETACHED,         "session.detached"},
    {AMQP_0_10_METHOD_SESSION_REQUEST_TIMEOUT,  "session.request-timeout"},
    {AMQP_0_10_METHOD_SESSION_TIMEOUT,          "session.timeout"},
    {AMQP_0_10_METHOD_SESSION_COMMAND_POINT,    "session.command-point"},
    {AMQP_0_10_METHOD_SESSION_EXPECTED,         "session.expected"},
    {AMQP_0_10_METHOD_SESSION_CONFIRMED,        "session.confirmed"},
    {AMQP_0_10_METHOD_SESSION_COMPLETED,        "session.completed"},
    {AMQP_0_10_METHOD_SESSION_KNOWN_COMPLETED,  "session.known-completed"},
    {AMQP_0_10_METHOD_SESSION_FLUSH,            "session.flush"},
    {AMQP_0_10_METHOD_SESSION_GAP,              "session.gap"},
    {0, NULL}
};

static const value_string amqp_0_10_execution_methods [] = {
    {AMQP_0_10_METHOD_EXECUTION_SYNC,       "execution.sync"},
    {AMQP_0_10_METHOD_EXECUTION_RESULT,     "execution.result"},
    {AMQP_0_10_METHOD_EXECUTION_EXCEPTION,  "execution.exception"},
    {0, NULL}
};

static const value_string amqp_0_10_message_methods [] = {
    {AMQP_0_10_METHOD_MESSAGE_TRANSFER,      "message.transfer"},
    {AMQP_0_10_METHOD_MESSAGE_ACCEPT,        "message.accept"},
    {AMQP_0_10_METHOD_MESSAGE_REJECT,        "message.reject"},
    {AMQP_0_10_METHOD_MESSAGE_RELEASE,       "message.release"},
    {AMQP_0_10_METHOD_MESSAGE_ACQUIRE,       "message.acquire"},
    {AMQP_0_10_METHOD_MESSAGE_RESUME,        "message.resume"},
    {AMQP_0_10_METHOD_MESSAGE_SUBSCRIBE,     "message.subscribe"},
    {AMQP_0_10_METHOD_MESSAGE_CANCEL,        "message.cancel"},
    {AMQP_0_10_METHOD_MESSAGE_SET_FLOW_MODE, "message.set-flow-mode"},
    {AMQP_0_10_METHOD_MESSAGE_FLOW,          "message.flow"},
    {AMQP_0_10_METHOD_MESSAGE_FLUSH,         "message.flush"},
    {AMQP_0_10_METHOD_MESSAGE_STOP,          "message.stop"},
    {0, NULL}
};

static const value_string amqp_0_10_tx_methods [] = {
    {AMQP_0_10_METHOD_TX_SELECT,    "tx.select"},
    {AMQP_0_10_METHOD_TX_COMMIT,    "tx.commit"},
    {AMQP_0_10_METHOD_TX_ROLLBACK,  "tx.rollback"},
    {0, NULL}
};

static const value_string amqp_0_10_dtx_methods [] = {
    {AMQP_0_10_METHOD_DTX_SELECT,       "dtx.select"},
    {AMQP_0_10_METHOD_DTX_START,        "dtx.start"},
    {AMQP_0_10_METHOD_DTX_END,          "dtx.end"},
    {AMQP_0_10_METHOD_DTX_COMMIT,       "dtx.commit"},
    {AMQP_0_10_METHOD_DTX_FORGET,       "dtx.forget"},
    {AMQP_0_10_METHOD_DTX_GET_TIMEOUT,  "dtx.get-timeout"},
    {AMQP_0_10_METHOD_DTX_PREPARE,      "dtx.prepare"},
    {AMQP_0_10_METHOD_DTX_RECOVER,      "dtx.recover"},
    {AMQP_0_10_METHOD_DTX_ROLLBACK,     "dtx.rollback"},
    {AMQP_0_10_METHOD_DTX_SET_TIMEOUT,  "dtx.set-timeout"},
    {0, NULL}
};

static const value_string amqp_0_10_exchange_methods [] = {
    {AMQP_0_10_METHOD_EXCHANGE_DECLARE,  "exchange.declare"},
    {AMQP_0_10_METHOD_EXCHANGE_DELETE,   "exchange.delete"},
    {AMQP_0_10_METHOD_EXCHANGE_QUERY,    "exchange.query"},
    {AMQP_0_10_METHOD_EXCHANGE_BIND,     "exchange.bind"},
    {AMQP_0_10_METHOD_EXCHANGE_UNBIND,   "exchange.unbind"},
    {AMQP_0_10_METHOD_EXCHANGE_BOUND,    "exchange.bound"},
    {0, NULL}
};

static const value_string amqp_0_10_queue_methods [] = {
    {AMQP_0_10_METHOD_QUEUE_DECLARE,  "queue.declare"},
    {AMQP_0_10_METHOD_QUEUE_DELETE,   "queue.delete"},
    {AMQP_0_10_METHOD_QUEUE_PURGE,    "queue.purge"},
    {AMQP_0_10_METHOD_QUEUE_QUERY,    "queue.query"},
    {0, NULL}
};

static const value_string amqp_0_10_file_methods [] = {
    {AMQP_0_10_METHOD_FILE_QOS,         "file.qos"},
    {AMQP_0_10_METHOD_FILE_QOS_OK,      "file.qos-ok"},
    {AMQP_0_10_METHOD_FILE_CONSUME,     "file.consume"},
    {AMQP_0_10_METHOD_FILE_CONSUME_OK,  "file.consume-ok"},
    {AMQP_0_10_METHOD_FILE_CANCEL,      "file.cancel"},
    {AMQP_0_10_METHOD_FILE_OPEN,        "file.open"},
    {AMQP_0_10_METHOD_FILE_OPEN_OK,     "file.open-ok"},
    {AMQP_0_10_METHOD_FILE_STAGE,       "file.stage"},
    {AMQP_0_10_METHOD_FILE_PUBLISH,     "file.publish"},
    {AMQP_0_10_METHOD_FILE_RETURN,      "file.return"},
    {AMQP_0_10_METHOD_FILE_DELIVER,     "file.deliver"},
    {AMQP_0_10_METHOD_FILE_ACK,         "file.ack"},
    {AMQP_0_10_METHOD_FILE_REJECT,      "file.reject"},
    {0, NULL}
};

static const value_string amqp_0_10_stream_methods [] = {
    {AMQP_0_10_METHOD_STREAM_QOS,         "stream.qos"},
    {AMQP_0_10_METHOD_STREAM_QOS_OK,      "stream.qos-ok"},
    {AMQP_0_10_METHOD_STREAM_CONSUME,     "stream.consume"},
    {AMQP_0_10_METHOD_STREAM_CONSUME_OK,  "stream.consume-ok"},
    {AMQP_0_10_METHOD_STREAM_CANCEL,      "stream.cancel"},
    {AMQP_0_10_METHOD_STREAM_PUBLISH,     "stream.publish"},
    {AMQP_0_10_METHOD_STREAM_RETURN,      "stream.return"},
    {AMQP_0_10_METHOD_STREAM_DELIVER,     "stream.deliver"},
    {0, NULL}
};

static const value_string amqp_0_10_method_connection_close_reply_codes [] = {
    {200,   "normal"},
    {320,   "connection-forced"},
    {402,   "invalid-path"},
    {501,   "framing-error"},
    {0, NULL}
};

static const true_false_string amqp_0_10_session_header_sync = {
    "notification requested", "notification NOT requested"
};

static const value_string amqp_0_10_method_session_detached_codes [] = {
    {0,    "normal"},
    {1,    "session-busy"},
    {2,    "transport-busy"},
    {3,    "not-attached"},
    {4,    "unknown-ids"},
    {0, NULL}
};

static const value_string amqp_0_10_method_execution_exception_errors [] = {
    {403,   "unauthorized-access"},
    {404,   "not-found"},
    {405,   "resource-locked"},
    {406,   "precondition-failed"},
    {408,   "resource-deleted"},
    {409,   "illegal-state"},
    {503,   "command-invalid"},
    {506,   "resource-limit-exceeded"},
    {530,   "not-allowed"},
    {531,   "illegal-argument"},
    {540,   "not-implemented"},
    {541,   "internal-error"},
    {542,   "invalid-argument"},
    {0, NULL}
};

static const value_string amqp_0_10_message_transfer_accept_modes [] = {
    {0,    "explicit"},
    {1,    "none"},
    {0, NULL}
};

static const value_string amqp_0_10_message_transfer_acquire_modes [] = {
    {0,    "pre-acquired"},
    {1,    "not-acquired"},
    {0, NULL}
};

static const value_string amqp_0_10_message_transfer_reject_codes [] = {
    {0,    "unspecified"},
    {1,    "unroutable"},
    {2,    "immediate"},
    {0, NULL}
};

static const value_string amqp_0_10_message_flow_modes [] = {
    {0,    "credit"},
    {1,    "window"},
    {0, NULL}
};

static const value_string amqp_0_10_message_credit_units [] = {
    {0,    "message"},
    {1,    "byte"},
    {0, NULL}
};

static const value_string amqp_0_10_xa_status [] = {
    {0,    "Normal execution completion. (xa-ok)"},
    {1,    "The rollback was caused for an unspecified reason. (xa-rbrollback)"},
    {2,    "A transaction branch took too long. (xa-rbtimeout)"},
    {3,    "The transaction branch may have been heuristically completed. (xa-heurhaz)"},
    {4,    "The transaction branch has been heuristically committed. (xa-heurcom)"},
    {5,    "The transaction branch has been heuristically rolled back. (xa-heurrb)"},
    {6,    "The transaction branch has been heuristically committed and rolled back. (xa-heurmix)"},
    {7,    "The transaction branch was read-only and has been committed. (xa-rdonly)"},
    {0, NULL}
};

static const value_string amqp_0_10_struct_delivery_properties_priorities [] = {
    {0,    "lowest"},
    {1,    "lower"},
    {2,    "low"},
    {3,    "below-average"},
    {4,    "medium"},
    {5,    "above-average"},
    {6,    "high"},
    {7,    "higher"},
    {8,    "very-high"},
    {9,    "highest"},
    {0, NULL}
};

static const value_string amqp_0_10_struct_delivery_properties_modes [] = {
    {1,    "non-persistent"},
    {2,    "persistent"},
    {0, NULL}
};

static const value_string amqp_0_10_file_return_codes [] = {
    {311,    "content-too-large"},
    {312,    "no-route"},
    {313,    "no-consumers"},
    {0, NULL}
};

static const value_string amqp_0_10_stream_return_codes [] = {
    {311,    "content-too-large"},
    {312,    "no-route"},
    {313,    "no-consumers"},
    {0, NULL}
};

static const value_string amqp_0_9_frame_types [] = {
    {AMQP_0_9_FRAME_TYPE_METHOD,             "Method"},
    {AMQP_0_9_FRAME_TYPE_CONTENT_HEADER,     "Content header"},
    {AMQP_0_9_FRAME_TYPE_CONTENT_BODY,       "Content body"},
    {AMQP_0_9_FRAME_TYPE_OOB_METHOD,         "OOB Method"},
    {AMQP_0_9_FRAME_TYPE_OOB_CONTENT_HEADER, "OOB Content header"},
    {AMQP_0_9_FRAME_TYPE_OOB_CONTENT_BODY,   "OOB Content body"},
    {AMQP_0_9_FRAME_TYPE_TRACE ,             "Trace"},
    {AMQP_0_9_FRAME_TYPE_HEARTBEAT,          "Heartbeat"},
    {0, NULL}
};

static const value_string amqp_0_9_method_classes [] = {
    {AMQP_0_9_CLASS_CONNECTION, "Connection"},
    {AMQP_0_9_CLASS_CHANNEL,    "Channel"},
    {AMQP_0_9_CLASS_ACCESS,     "Access"},
    {AMQP_0_9_CLASS_EXCHANGE,   "Exchange"},
    {AMQP_0_9_CLASS_QUEUE,      "Queue"},
    {AMQP_0_9_CLASS_BASIC,      "Basic"},
    {AMQP_0_9_CLASS_FILE,       "File"},
    {AMQP_0_9_CLASS_STREAM,     "Stream"},
    {AMQP_0_9_CLASS_TX,         "Tx"},
    {AMQP_0_9_CLASS_DTX,        "Dtx"},
    {AMQP_0_9_CLASS_TUNNEL,     "Tunnel"},
    {0, NULL}
};

static const value_string amqp_method_connection_methods [] = {
    {10, "Start"},
    {11, "Start-Ok"},
    {20, "Secure"},
    {21, "Secure-Ok"},
    {30, "Tune"},
    {31, "Tune-Ok"},
    {40, "Open"},
    {41, "Open-Ok"},
    {42, "Redirect"},
    {50, "Close"},
    {51, "Close-Ok"},
    {0, NULL}
};

static const value_string amqp_method_channel_methods [] = {
    {10, "Open"},
    {11, "Open-Ok"},
    {20, "Flow"},
    {21, "Flow-Ok"},
    {40, "Close"},
    {41, "Close-Ok"},
    {50, "Resume"},
    {60, "Ping"},
    {70, "Pong"},
    {80, "Ok"},
    {0, NULL}
};

static const value_string amqp_method_access_methods [] = {
    {10, "Request"},
    {11, "Request-Ok"},
    {0, NULL}
};

static const value_string amqp_method_exchange_methods [] = {
    {10, "Declare"},
    {11, "Declare-Ok"},
    {20, "Delete"},
    {21, "Delete-Ok"},
    {30, "Bind"},
    {31, "Bind-Ok"},
    {0, NULL}
};

static const value_string amqp_method_queue_methods [] = {
    {10, "Declare"},
    {11, "Declare-Ok"},
    {20, "Bind"},
    {21, "Bind-Ok"},
    {50, "Unbind"},
    {51, "Unbind-Ok"},
    {30, "Purge"},
    {31, "Purge-Ok"},
    {40, "Delete"},
    {41, "Delete-Ok"},
    {0, NULL}
};

static const value_string amqp_method_basic_methods [] = {
    {10, "Qos"},
    {11, "Qos-Ok"},
    {20, "Consume"},
    {21, "Consume-Ok"},
    {30, "Cancel"},
    {31, "Cancel-Ok"},
    {40, "Publish"},
    {50, "Return"},
    {60, "Deliver"},
    {70, "Get"},
    {71, "Get-Ok"},
    {72, "Get-Empty"},
    {80, "Ack"},
    {90, "Reject"},
    {100, "Recover"},
    {0, NULL}
};

static const value_string amqp_method_file_methods [] = {
    {10, "Qos"},
    {11, "Qos-Ok"},
    {20, "Consume"},
    {21, "Consume-Ok"},
    {30, "Cancel"},
    {31, "Cancel-Ok"},
    {40, "Open"},
    {41, "Open-Ok"},
    {50, "Stage"},
    {60, "Publish"},
    {70, "Return"},
    {80, "Deliver"},
    {90, "Ack"},
    {100, "Reject"},
    {0, NULL}
};

static const value_string amqp_method_stream_methods [] = {
    {10, "Qos"},
    {11, "Qos-Ok"},
    {20, "Consume"},
    {21, "Consume-Ok"},
    {30, "Cancel"},
    {31, "Cancel-Ok"},
    {40, "Publish"},
    {50, "Return"},
    {60, "Deliver"},
    {0, NULL}
};

static const value_string amqp_method_tx_methods [] = {
    {10, "Select"},
    {11, "Select-Ok"},
    {20, "Commit"},
    {21, "Commit-Ok"},
    {30, "Rollback"},
    {31, "Rollback-Ok"},
    {0, NULL}
};

static const value_string amqp_method_dtx_methods [] = {
    {10, "Select"},
    {11, "Select-Ok"},
    {20, "Start"},
    {21, "Start-Ok"},
    {0, NULL}
};

static const value_string amqp_method_tunnel_methods [] = {
    {10, "Request"},
    {0, NULL}
};

/*  AMQP 0-10 Type Info  */
static struct amqp_typeinfo amqp_0_10_fixed_types[] = {
    { 0x00, "bin8",    format_amqp_0_10_bin,     1 },
    { 0x01, "int8",    format_amqp_0_10_int,     1 },
    { 0x02, "uint8",   format_amqp_0_10_uint,    1 },
    { 0x04, "char",    format_amqp_0_10_char,    1 },
    { 0x08, "boolean", format_amqp_0_10_boolean, 1 },
    { 0x10, "bin16",   format_amqp_0_10_bin,     2 },
    { 0x11, "int16",   format_amqp_0_10_int,     2 },
    { 0x12, "uint16",  format_amqp_0_10_uint,    2 },
    { 0x20, "bin32",   format_amqp_0_10_bin,     4 },
    { 0x21, "int32",   format_amqp_0_10_int,     4 },
    { 0x22, "uint32",  format_amqp_0_10_uint,    4 },
    { 0xff, "end", 0, 0 }
};

static struct amqp_typeinfo amqp_0_10_var_types[] = {
    { 0x80, "vbin8",   format_amqp_0_10_vbin, 1 },
    { 0x95, "str16",   format_amqp_0_10_str, 2 },
    { 0xff, "end", 0, 0 }
};


/*  Main dissection routine  */

static void
dissect_amqp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    conversation_t *conv;
    amqp_conv *conn;
    guint fixed_length;
    guint (*length_getter)(packet_info *, tvbuff_t *, int);
    dissector_t dissector;

    /*  Minimal frame size is 8 bytes - smaller frames are malformed  */
    if (tvb_reported_length (tvb) < 8) {
        expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR,
                               "Require frame at least 8 bytes long");
        return;
    }

    /* Find (or build) conversation to remember the protocol version */
    conv = find_or_create_conversation(pinfo);
    conn = conversation_get_proto_data(conv, proto_amqp);
    if (conn == NULL) {
        conn = se_alloc0(sizeof(amqp_conv));
        conversation_add_proto_data(conv, proto_amqp, conn);
    }
    check_amqp_version(tvb, conn);
    switch(conn->version) {
    case AMQP_V0_9:
        length_getter = &get_amqp_0_9_message_len;
        dissector = dissect_amqp_0_9_frame;
        fixed_length = 7;
        break;
    case AMQP_V0_10:
        length_getter = &get_amqp_0_10_message_len;
        dissector = dissect_amqp_0_10_frame;
        fixed_length = 8;
        break;
    default:
        col_append_str(pinfo->cinfo, COL_INFO, "AMQP (unknown version)");
        col_set_fence(pinfo->cinfo, COL_INFO);
        return;
    }
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, fixed_length,
                     length_getter, dissector);
}

static void
check_amqp_version(tvbuff_t *tvb, amqp_conv *conn)
{
    guint8 proto_major;
    guint8 proto_minor;
    guint32 f0_9_length;

    /*
     * If we already know and the version and this isn't a protocol header,
     * return ok. 0-10 and up can run protocol headers in each direction,
     * so if it looks like a protocol header, snag the version even if one
     * is already recorded. Multi-protocol brokers can negotiate down.
     */
    if (conn->version != 0 && tvb_get_guint8(tvb, 0) != 'A')
        return;

    if (tvb_get_guint8(tvb, 0) == 'A' &&
        tvb_get_guint8(tvb, 1) == 'M' &&
        tvb_get_guint8(tvb, 2) == 'Q' &&
        tvb_get_guint8(tvb, 3) == 'P') {

        proto_major = tvb_get_guint8(tvb, 6);
        proto_minor = tvb_get_guint8(tvb, 7);
        if (proto_major == 0) {
            if (proto_minor == 9)
                conn->version = AMQP_V0_9;
            else if (proto_minor == 10)
                conn->version = AMQP_V0_10;
        }
        return;
    }

    /*
     * It's not a protocol header and the AMQP version isn't known. Try to
     * deduce it from the content. First indicator is the frame length. 0-9
     * has a 32-bit length in octets 3-7. If the frame length is the same
     * as the PDU length and there's a frame end where it should be, this
     * is 0-9. Else assume 0-10.
     */
    f0_9_length = tvb_get_ntohl(tvb, 3) + 7 + 1; /* Add header and end */
    if (f0_9_length == tvb_reported_length(tvb) &&
        tvb_get_guint8(tvb, f0_9_length - 1) == 0xCE)
        conn->version = AMQP_V0_9;
    else
        conn->version = AMQP_V0_10;
    return;
}

static guint
get_amqp_0_10_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    /*  Heuristic - protocol initialisation frame starts with 'AMQP'  */
    if (tvb_get_guint8(tvb, offset + 0) == 'A' &&
        tvb_get_guint8(tvb, offset + 1) == 'M' &&
        tvb_get_guint8(tvb, offset + 2) == 'Q' &&
        tvb_get_guint8(tvb, offset + 3) == 'P')
        return 8;

    return (guint) tvb_get_ntohs(tvb, offset + 2);
}

static guint
get_amqp_0_9_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    guint32 length;

    /*  Heuristic - protocol initialisation frame starts with 'AMQP'  */
    if (tvb_get_guint8(tvb, offset + 0) == 'A' &&
          tvb_get_guint8(tvb, offset + 1) == 'M' &&
          tvb_get_guint8(tvb, offset + 2) == 'Q' &&
          tvb_get_guint8(tvb, offset + 3) == 'P')
        return 8;

    /*
     * XXX - the location of the length differs from protocol version to
     * protocol version; for now, we only handle version 0-9, and we
     * clamp the length at 1MB so we don't go nuts if we get a bogus
     * length due to dissecting the wrong version (or getting a malformed
     * packet).
     */
    length = tvb_get_ntohl(tvb, offset + 3);
    if (length > 1048576)
        length = 1048576;
    return length + 8;
}

/*  Dissection routine for AMQP 0-9 field tables  */

static void
dissect_amqp_0_9_field_table(tvbuff_t *tvb, packet_info *pinfo, int offset, guint length, proto_item *item)
{
    proto_tree *field_table_tree;
    guint namelen, vallen;
    guint8 type;
    const char *name;
    const char *typename;
    const char *value;
    int field_start;
    proto_item *ti;

    field_table_tree = proto_item_add_subtree(item, ett_amqp);

    while (length != 0) {
        field_start = offset;
        namelen = tvb_get_guint8(tvb, offset);
        offset += 1;
        length -= 1;
        if (length < namelen)
            goto too_short;
        name = (char*) tvb_get_ephemeral_string(tvb, offset, namelen);
        offset += namelen;
        length -= namelen;
        if (length < 1)
            goto too_short;
        type = tvb_get_guint8(tvb, offset);
        offset += 1;
        length -= 1;
        switch (type) {
        case 'S':
            typename = "string";
            if (length < 4)
                goto too_short;
            vallen = tvb_get_ntohl(tvb, offset);
            offset += 4;
            length -= 4;
            if (length < vallen)
                goto too_short;
            value = (char*) tvb_get_ephemeral_string(tvb, offset, vallen);
            offset += vallen;
            length -= vallen;
            break;
        case 'I':
            typename = "integer";
            if (length < 4)
                goto too_short;
            value = ep_strdup_printf("%d", tvb_get_ntohl(tvb, offset));
            offset += 4;
            length -= 4;
            break;
        case 'D':
            typename = "decimal";
            if (length < 5)
                goto too_short;
            value = "...";
            offset += 5;
            length -= 5;
            break;
        case 'T':
            typename =  "timestamp";
            if (length < 8)
                goto too_short;
            value = "...";
            offset += 8;
            length -= 8;
            break;
        case 'F':
            /*  TODO: make it recursive here  */
            typename =  "field table";
            if (length < 4)
                goto too_short;
            vallen = tvb_get_ntohl(tvb, offset);
            offset += 4;
            length -= 4;
            value = "...";
            if (length < vallen)
                goto too_short;
            offset += vallen;
            length -= vallen;
            break;
        case 'V':
            typename = "void";
            value = "";
            break;
        default:
            typename = "";
            value = NULL;
            break;
        }

        if (value != NULL)
            proto_tree_add_none_format(field_table_tree, hf_amqp_field, tvb,
                                       field_start, offset - field_start,
                                       "%s (%s): %s", name, typename,
                                       value);
        else
            proto_tree_add_none_format(field_table_tree, hf_amqp_field, tvb,
                                       field_start, offset - field_start,
                                       "%s: unknown type %x (%c)",
                                       name, type, type);
    }
    return;

too_short:
    ti = proto_tree_add_text(field_table_tree, tvb, field_start,
                        offset - field_start,
                        "Field is cut off by the end of the field table");
    expert_add_info_format(pinfo, ti,
                           PI_PROTOCOL, PI_ERROR,
                           "Field is cut off by the end of the field table");
    return;
}

/*  Dissection routine for AMQP 0-10 maps  */

static void
dissect_amqp_0_10_map(tvbuff_t *tvb,
                      int offset,          /* Start of map in tvb */
                      int bound,           /* How far into tvb we can go */
                      int length,          /* Length of map */
                      proto_item *item)
{
    proto_item *map_tree;
    guint namelen, size;
    guint8 type;
    const char *name;
    const char *typename;
    const char *value;
    gint field_start, field_length;
    guint32 field_count;
    type_formatter formatter;

    field_length = 0;
    map_tree = proto_item_add_subtree(item, ett_amqp_0_10_map);
    field_count = tvb_get_ntohl(tvb, offset);
    AMQP_INCREMENT(offset, 4, bound);
    length -= 4;
    proto_item_append_text(item, " (%d entries)", field_count);
    while (field_count > 0 && length > 0) {
        field_start = offset;
        namelen = tvb_get_guint8(tvb, offset);
        AMQP_INCREMENT(offset, 1, bound);
        length -= 1;
        name = (char*) tvb_get_ephemeral_string(tvb, offset, namelen);
        AMQP_INCREMENT(offset, namelen, bound);
        length -= namelen;
        type = tvb_get_guint8(tvb, offset);
        AMQP_INCREMENT(offset, 1, bound);
        length -= 1;
        if (get_amqp_0_10_type_formatter(type, &typename, &formatter, &size)) {
            field_length = formatter(tvb, offset, bound, size, &value);
            proto_tree_add_none_format(map_tree,
                                       hf_amqp_field,
                                       tvb,
                                       field_start,
                                       field_length,
                                       "%s (%s): %s",
                                       name, typename, value);
            AMQP_INCREMENT(offset, field_length, bound);
            length -= field_length;
        }
        else {
            switch (type) {
            case AMQP_0_10_TYPE_MAP:
            case AMQP_0_10_TYPE_LIST:
            case AMQP_0_10_TYPE_ARRAY:
                field_length = tvb_get_ntohl(tvb, offset);
                proto_tree_add_none_format(map_tree, hf_amqp_field,
                                           tvb, field_start, field_length,
                                           "%s (composite): %d bytes",
                                           name, field_length);
                AMQP_INCREMENT(offset, field_length, bound);
                length -= field_length;
                break;

            default:
                typename = "unimplemented";
                if ((type & 0x80) == 0) {
                    field_length = 2 ^ ((type & 0x70) >> 4);
                }
                else if ((type & 0xd0) == 0xd0) {
                    field_length = 9;
                }
                else if ((type & 0xc0) == 0xc0) {
                    field_length = 5;
                }
                else if ((type & 0x80) == 0x80) {
                    switch (2 ^ ((type & 0x70) >> 4)) {
                    case 1:
                        field_length += tvb_get_guint8(tvb, offset);
                        break;
                    case 2:
                        field_length += tvb_get_ntohs(tvb, offset);
                        break;
                    case 4:
                        field_length += tvb_get_ntohl(tvb, offset);
                        break;
                    default:
                        field_length = 1;    /* Reserved... skip 1 */
                        typename = "reserved";
                        break;
                    }
                }
                else {
                    field_length = 1;    /* Reserved... skip 1 */
                    typename = "reserved";
                }
                proto_tree_add_none_format(map_tree, hf_amqp_field,
                                           tvb, field_start, field_length,
                                           "%s (%s): %d bytes",
                                           name, typename, field_length);
                AMQP_INCREMENT(offset, field_length, bound);
                length -= field_length;
            }
        }

        field_count -= 1;
    }
}

/*  Dissection routine for AMQP 0-10 maps  */

static void
dissect_amqp_0_10_array(tvbuff_t *tvb,
                        int offset,          /* Start of array in tvb */
                        int bound,           /* How far into tvb we can go */
                        int length,          /* Length of array */
                        proto_item *item)
{
    proto_item *array_tree;
    proto_item *sub;
    guint8 type;
    guint16 len16;
    const char *typename;
    const char *value;
    int element_start;
    int externally_formatted;
    guint32 element_count;
    guint32 struct_length;

    array_tree = 0;
    type = tvb_get_guint8(tvb, offset);
    AMQP_INCREMENT(offset, 1, bound);
    length -= 1;
    element_count = tvb_get_ntohl(tvb, offset);
    AMQP_INCREMENT(offset, 4, bound);
    length -= 4;
    proto_item_append_text(item, " (%d elements)", element_count);
    if (element_count > 1)
        array_tree = proto_item_add_subtree(item, ett_amqp_0_10_array);
    while (element_count > 0 && length > 0) {
        element_start = offset;
        externally_formatted = 0;
        switch (type) {
        case AMQP_0_10_TYPE_STR16:
            typename = "str16";
            len16 = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, bound);
            length -= 2;
            value = (char*) tvb_get_ephemeral_string(tvb, offset, len16);
            AMQP_INCREMENT(offset, len16, bound);
            length -= len16;
            break;

        case AMQP_0_10_TYPE_STRUCT32:
            typename = "struct32";
            value = "structure";
            externally_formatted = 1;
            struct_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, bound);
            length -= 4;
            /*
             * Always add a tree for structs - the struct formatter will
             * change the item text to the struct type then add elements to it.
             */
            if (array_tree == 0)
                array_tree = proto_item_add_subtree(item, ett_amqp_0_10_array);
            sub = proto_tree_add_none_format(array_tree, hf_amqp_field, tvb,
                                             element_start,
                                             offset - element_start,
                                             "(%s): ", typename);
            dissect_amqp_0_10_struct32(tvb, sub, offset, struct_length);
            AMQP_INCREMENT(offset, struct_length, bound);
            length -= struct_length;
            break;

        default:
            proto_tree_add_none_format(array_tree, hf_amqp_field, tvb,
                                       element_start,
                                       offset - element_start,
                                       "(unknown type %d)",
                                       type);
            /*  Don't bother continuing through the loop: we don't know how
             *  much to increment the offset by and the type doesn't change
             *  so there's nothing interesting to do...
             */
            return;
        }

        element_count -= 1;
        if (externally_formatted)
            continue;

        if (array_tree != 0) {
            proto_tree_add_none_format(array_tree, hf_amqp_field, tvb,
                                       element_start,
                                       offset - element_start,
                                       "(%s): %s",
                                       typename,
                                       value);
        }
        else {
            proto_item_append_text(item, ": (%s): %s", typename, value);
        }
    }
}

static void
dissect_amqp_0_10_xid (tvbuff_t *tvb,
                       int offset,
                       guint16 xid_length,
                       proto_item *ti)
{
    proto_item *xid_tree;
    guint8 flag1/*, flag2*/;
    guint8 len8;
    int max_length;

    max_length = offset + xid_length;
    xid_tree = proto_item_add_subtree(ti, ett_args);
    flag1 = tvb_get_guint8(tvb, offset);
    /*flag2 = tvb_get_guint8(tvb, offset+1);*/
    proto_tree_add_item(xid_tree, hf_amqp_0_10_argument_packing_flags,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, max_length);
    if (flag1 & 0x01) {
        /*  format (uint32) */
        proto_tree_add_item(xid_tree,
                            hf_amqp_0_10_dtx_xid_format,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 4, max_length);
    }
    if (flag1 & 0x02) {
        /* global-id (vbin8) */
        len8 = tvb_get_guint8(tvb, offset);
        if ((offset + 1 + len8) > max_length)
            THROW(ReportedBoundsError);
        proto_tree_add_item(xid_tree,
                            hf_amqp_0_10_dtx_xid_global_id,
                            tvb, offset + 1, len8, ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x04) {
        /* branch-id (vbin8) */
        len8 = tvb_get_guint8(tvb, offset);
        if ((offset + 1 + len8) > max_length)
            THROW(ReportedBoundsError);
        proto_tree_add_item(xid_tree,
                            hf_amqp_0_10_dtx_xid_branch_id,
                            tvb, offset + 1, len8, ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
}

/*  Dissection routine for AMQP 0-10 frames  */

static void
dissect_amqp_0_10_connection(tvbuff_t *tvb,
                             packet_info *pinfo,
                             proto_tree *tree,
                             int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 method;
    guint8 flag1, flag2;           /* args struct packing flags */
    guint32 arg_length;
    int flags_offset;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_connection_methods,
                                   "<invalid connection method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_connection_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset + 2, length - 2, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_CONNECTION_START:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  server-properties (map)  */
            arg_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_method_connection_start_server_properties,
                                     tvb,
                                     offset,
                                     arg_length, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + arg_length,
                                   arg_length,
                                   ti);
            AMQP_INCREMENT(offset, arg_length, length);
        }
        if (flag1 & 0x02) {
            /*  mechanisms (str16-array)  */
            arg_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_connection_start_mechanisms,
                                     tvb,
                                     offset,
                                     arg_length, ENC_NA);
            dissect_amqp_0_10_array (tvb,
                                     offset,
                                     offset + arg_length,
                                     arg_length,
                                     ti);
            AMQP_INCREMENT(offset, arg_length, length);
        }
        if (flag1 & 0x04) {
            /*  locales (str16-array)  */
            arg_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_connection_start_locales,
                                     tvb,
                                     offset,
                                     arg_length, ENC_NA);
            dissect_amqp_0_10_array (tvb,
                                     offset,
                                     offset + arg_length,
                                     arg_length,
                                     ti);
            AMQP_INCREMENT(offset, arg_length, length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_START_OK:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  client-properties (map)  */
            arg_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_method_connection_start_ok_client_properties,
                                     tvb,
                                     offset,
                                     arg_length, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + arg_length,
                                   arg_length,
                                   ti);
            AMQP_INCREMENT(offset, arg_length, length);
        }
        if (flag1 & 0x02) {
            /*  mechanism (str8)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_start_ok_mechanism,
                                tvb, offset + 1, tvb_get_guint8(tvb, offset),
                                ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + tvb_get_guint8(tvb, offset), length);
        }
        if (flag1 & 0x04) {
            /*  response (vbin32)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_start_ok_response,
                                tvb, offset + 4, tvb_get_ntohl(tvb, offset),
                                ENC_NA);
            AMQP_INCREMENT(offset, 4 + tvb_get_ntohl(tvb, offset), length);
        }
        if (flag1 & 0x08) {
            /*  locale (str8)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_start_ok_locale,
                                tvb, offset + 1, tvb_get_guint8(tvb, offset),
                                ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + tvb_get_guint8(tvb, offset), length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_SECURE:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  challenge (vbin32)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_secure_challenge,
                                tvb, offset + 4, tvb_get_ntohl(tvb, offset),
                                ENC_NA);
            AMQP_INCREMENT(offset, 4 + tvb_get_ntohl(tvb, offset), length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_SECURE_OK:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  response (vbin32)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_secure_ok_response,
                                tvb, offset + 4, tvb_get_ntohl(tvb, offset),
                                ENC_NA);
            AMQP_INCREMENT(offset, 4 + tvb_get_ntohl(tvb, offset), length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_TUNE:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  channel-max (uint16)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_tune_channel_max,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x02) {
            /*  max-frame-size (uint16)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_connection_tune_frame_max,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x04) {
            /*  heartbeat-min (uint16)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_connection_tune_heartbeat_min,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x08) {
            /*  heartbeat-max (uint16)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_connection_tune_heartbeat_max,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_TUNE_OK:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  channel-max (uint16)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_tune_ok_channel_max,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x02) {
            /*  max-frame-size (uint16)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_connection_tune_ok_frame_max,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x04) {
            /*  heartbeat (uint16)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_tune_ok_heartbeat,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_OPEN:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  virtual-host (str8)  */
            proto_tree_add_item(args_tree,
                                     hf_amqp_method_connection_open_virtual_host,
                                     tvb,
                                     offset + 1,
                                     tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, tvb_get_guint8(tvb, offset) + 1, length);
        }
        if (flag1 & 0x02) {
            /*  capabilities (str16-array)  */
            arg_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_connection_open_capabilities,
                                     tvb,
                                     offset,
                                     arg_length, ENC_NA);
            dissect_amqp_0_10_array (tvb,
                                     offset,
                                     offset + arg_length,
                                     arg_length,
                                     ti);
            AMQP_INCREMENT(offset, arg_length, length);
        }
        /*
         * 3rd argument is an optional bit, insist.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_connection_open_insist,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_CONNECTION_OPEN_OK:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  known-hosts (amqp-host-array)  */
            arg_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_connection_open_ok_known_hosts,
                                     tvb,
                                     offset,
                                     arg_length, ENC_NA);
            dissect_amqp_0_10_array (tvb,
                                     offset,
                                     offset + arg_length,
                                     arg_length,
                                     ti);
            AMQP_INCREMENT(offset, arg_length, length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_REDIRECT:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  host (amqp-host-url [str16])  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_redirect_host,
                                tvb, offset + 2, tvb_get_ntohs(tvb, offset),
                                ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 2 + tvb_get_ntohs(tvb, offset), length);
        }
        if (flag1 & 0x02) {
            /*  known-hosts (amqp-host-array)  */
            arg_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_connection_redirect_known_hosts,
                                     tvb,
                                     offset,
                                     arg_length, ENC_NA);
            dissect_amqp_0_10_array (tvb,
                                     offset,
                                     offset + arg_length,
                                     arg_length,
                                     ti);
            AMQP_INCREMENT(offset, arg_length, length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_HEARTBEAT:
        break;

    case AMQP_0_10_METHOD_CONNECTION_CLOSE:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  reply-code (uint16)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_connection_close_reply_code,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x02) {
            /*  reply-text (str8)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_method_connection_close_reply_text,
                                tvb, offset + 1, tvb_get_guint8(tvb, offset),
                                ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + tvb_get_guint8(tvb, offset), length);
        }
        break;

    case AMQP_0_10_METHOD_CONNECTION_CLOSE_OK:
        break;
    }
}

static void
dissect_amqp_0_10_session(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *tree,
                          int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 method;
    guint8 flag1, flag2;
    guint16 size;
    guint32 array_size;
    int flags_offset;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_session_methods,
                                   "<invalid session method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_session_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset, length - 2, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);
    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_SESSION_ATTACH:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  name (vbin16)  */
            size = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, length);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_session_attach_name,
                                tvb, offset, size, ENC_NA);
            AMQP_INCREMENT(offset, size, length);
        }
        /*
         * 2nd argument is an optional bit, force.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_session_attach_force,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_SESSION_ATTACHED:
    case AMQP_0_10_METHOD_SESSION_DETACH:
        if ((flag1 != 0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  name (vbin16)  */
            size = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, length);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_session_attach_name,
                                tvb, offset, size, ENC_NA);
            AMQP_INCREMENT(offset, size, length);
        }
        break;

    case AMQP_0_10_METHOD_SESSION_DETACHED:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  name (vbin16)  */
            size = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, length);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_session_attach_name,
                                tvb, offset, size, ENC_NA);
            AMQP_INCREMENT(offset, size, length);
        }
        if (flag1 & 0x02) {
            /*  code (detach-code [uint8]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_session_detached_code,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        break;

    case AMQP_0_10_METHOD_SESSION_REQUEST_TIMEOUT:
    case AMQP_0_10_METHOD_SESSION_TIMEOUT:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  timeout (uint32)  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_session_timeout,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        break;

    case AMQP_0_10_METHOD_SESSION_COMMAND_POINT:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  command-id (sequence-no [uint32])  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_session_command_point_id,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        if (flag1 & 0x02) {
            /*  command-offset (uint64) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_session_command_point_offset,
                                tvb, offset, 8, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 8, length);
        }
        break;

    case AMQP_0_10_METHOD_SESSION_EXPECTED:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  commands (commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            if ((offset + 2 + size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_session_commands,
                                     tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size + 2, length);
        }
        if (flag1 & 0x02) {
            /*  fragments (command-fragments [array of command-fragment]) */
            array_size = tvb_get_ntohl(tvb, offset);
            if ((offset + 4 + array_size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_session_fragments,
                                     tvb, offset, array_size + 4, ENC_NA);
            AMQP_INCREMENT(offset, 4, length);
            dissect_amqp_0_10_array(tvb,
                                    offset,
                                    offset + array_size,
                                    length,
                                    ti);
            AMQP_INCREMENT(offset, array_size, length);
        }
        break;

    case AMQP_0_10_METHOD_SESSION_CONFIRMED:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  commands (commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            if ((offset + 2 + size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_session_commands,
                                     tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size + 2, length);
        }
        if (flag1 & 0x02) {
            /*  fragments (command-fragments [array of command-fragment]) */
            array_size = tvb_get_ntohl(tvb, offset);
            if ((offset + 4 + array_size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_session_fragments,
                                     tvb, offset, array_size + 4, ENC_NA);
            AMQP_INCREMENT(offset, 4, length);
            dissect_amqp_0_10_array(tvb,
                                    offset,
                                    offset + array_size,
                                    length,
                                    ti);
            AMQP_INCREMENT(offset, array_size, length);
        }
        break;

    case AMQP_0_10_METHOD_SESSION_COMPLETED:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  commands (commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            if ((offset + 2 + size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_session_commands,
                                     tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size, length);
        }
        /*
         * 2nd argument is an optional bit, timely-reply.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_session_completed_timely,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_SESSION_KNOWN_COMPLETED:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  commands (commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            if ((offset + 2 + size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_session_commands,
                                     tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size, length);
        }
        break;

    case AMQP_0_10_METHOD_SESSION_FLUSH:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_session_flush_expected,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_session_flush_confirmed,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_session_flush_completed,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_SESSION_GAP:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  commands (commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            if ((offset + 2 + size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_session_commands,
                                     tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size + 2, length);
        }
        break;

    }
}

static void
dissect_amqp_0_10_execution(tvbuff_t *tvb,
                            packet_info *pinfo,
                            proto_tree *tree,
                            int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 class = 0, method;
    guint8 flag1, flag2;
    guint16 size;
    guint32 struct_size;
    int class_hf;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_execution_methods,
                                   "<invalid execution method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_execution_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * Session header is 2 bytes; one that tells it's 1 byte long, then
     * the byte itself. Bit 0 is sync.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    if (flag1 != 1 || (flag2 & 0xfe) != 0)
        proto_tree_add_text(tree, tvb, offset, 2, "Invalid session header");
    else
        proto_tree_add_item(tree, hf_amqp_0_10_session_header_sync,
                            tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset, length - 4, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);
    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_EXECUTION_SYNC:
        if (flag1 != 0 || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        break;

    case AMQP_0_10_METHOD_EXECUTION_RESULT:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  command-id (sequence-no [uint32])  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_execution_command_id,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        if (flag1 & 0x02) {
            /*  value (struct32) */
            struct_size = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            if ((offset + struct_size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_undissected_struct32,
                                     tvb, offset, struct_size, ENC_NA);
            dissect_amqp_0_10_struct32(tvb, ti, offset, struct_size);
            AMQP_INCREMENT(offset, struct_size, length);
        }
        break;

    case AMQP_0_10_METHOD_EXECUTION_EXCEPTION:
        if ((flag1 & ~0x7f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /* error-code (error-code [uint16]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_execution_exception_error,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x02) {
            /*  command-id (sequence-no [uint32])  */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_execution_command_id,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        if (flag1 & 0x04) {
            /*  class-code (uint8) */
            class = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(args_tree, hf_amqp_0_10_class,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        if (flag1 & 0x08) {
            /*  command-code (uint8) */
            switch(class) {
            case AMQP_0_10_CLASS_CONNECTION:
                class_hf = hf_amqp_0_10_connection_method;
                break;
            case AMQP_0_10_CLASS_SESSION:
                class_hf = hf_amqp_0_10_session_method;
                break;
            case AMQP_0_10_CLASS_EXECUTION:
                class_hf = hf_amqp_0_10_execution_method;
                break;
            case AMQP_0_10_CLASS_MESSAGE:
                class_hf = hf_amqp_0_10_message_method;
                break;
            case AMQP_0_10_CLASS_TX:
                class_hf = hf_amqp_0_10_tx_method;
                break;
            case AMQP_0_10_CLASS_DTX:
                class_hf = hf_amqp_0_10_dtx_method;
                break;
            case AMQP_0_10_CLASS_EXCHANGE:
                class_hf = hf_amqp_0_10_exchange_method;
                break;
            case AMQP_0_10_CLASS_QUEUE:
                class_hf = hf_amqp_0_10_queue_method;
                break;
            case AMQP_0_10_CLASS_FILE:
                class_hf = hf_amqp_0_10_file_method;
                break;
            case AMQP_0_10_CLASS_STREAM:
                class_hf = hf_amqp_0_10_stream_method;
                break;
            default:
                class_hf = -1;
                break;
            }
            if (class_hf != -1)
                proto_tree_add_item(args_tree, class_hf,
                                    tvb, offset, 1, ENC_BIG_ENDIAN);
            else
                expert_add_info_format(pinfo, args_tree, PI_PROTOCOL, PI_WARN,
                                       "Invalid class code %x", class);
            AMQP_INCREMENT(offset, 1, length);
        }
        if (flag1 & 0x10) {
            /*  field-index (uint8) */
            proto_tree_add_item(args_tree, hf_amqp_0_10_method_execution_field_index,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        if (flag1 & 0x20) {
            /*  description (str16) */
            size = tvb_get_ntohs(tvb, offset);
            if ((offset + 2 + size) > length)
                THROW(ReportedBoundsError);
            proto_tree_add_item(args_tree, hf_amqp_0_10_method_execution_description,
                                tvb, offset + 2, size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (2 + size), length);
        }
        if (flag1 & 0x40) {
            /*  error-info (map) */
            struct_size = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_execution_error_info,
                                     tvb,
                                     offset,
                                     struct_size, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + struct_size,
                                   struct_size,
                                   ti);
            AMQP_INCREMENT(offset, struct_size, length);
        }
        break;
    }
}

static void
dissect_amqp_0_10_message(tvbuff_t *tvb,
                          packet_info *pinfo,
                          proto_tree *tree,
                          int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 method, str_size;
    guint8 flag1, flag2;
    guint16 size;
    guint32 map_size;
    int flags_offset;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_message_methods,
                                   "<invalid message method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_message_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * Session header is 2 bytes; one that tells it's 1 byte long, then
     * the byte itself. Bit 0 is sync.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    if (flag1 != 1 || (flag2 & 0xfe) != 0)
        proto_tree_add_text(tree, tvb, offset, 2, "Invalid session header");
    else
        proto_tree_add_item(tree, hf_amqp_0_10_session_header_sync,
                            tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset, length - 4, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);
    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_MESSAGE_TRANSFER:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* destination (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            if ((offset + 1 + str_size) > length)
                THROW(ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_transfer_destination,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* accept-mode (accept-mode [uint8]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_transfer_accept_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        if (flag1 & 0x04) {     /* acquire-mode (acquire-mode [uint8]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_transfer_acquire_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_ACCEPT:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  transfers (session.commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            if ((offset + 2 + size) > length)
                THROW(ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_message_accept_transfers,
                                     tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_REJECT:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  transfers (session.commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            THROW_ON(((offset + 2 + size) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_message_accept_transfers,
                                     tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size, length);
        }
        if (flag1 & 0x02) {     /* reject-code (reject-code [uint16]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_transfer_reject_code,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x04) {     /* text (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_reject_text,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_RELEASE:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  transfers (session.commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            THROW_ON(((offset + 2 + size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_accept_transfers,
                                tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size, length);
        }
        /*
         * 2nd argument is an optional bit, set-redelivered.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_message_release_set_redelivered,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_MESSAGE_ACQUIRE:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  transfers (session.commands [sequence-set])  */
            size = tvb_get_ntohs(tvb, offset);
            THROW_ON(((offset + 2 + size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_accept_transfers,
                                tvb, offset, size + 2, ENC_NA);
            AMQP_INCREMENT(offset, 2, length);
            format_amqp_0_10_sequence_set(tvb, offset, size, ti);
            AMQP_INCREMENT(offset, size, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_RESUME:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  destination (destination [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_dest,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + str_size, length);
        }
        if (flag1 & 0x02) {
            /*  resume-id (resume-id [str16]) */
            size = tvb_get_ntohs(tvb, offset);
            THROW_ON(((offset + 2 + size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_resume_id,
                                tvb, offset + 2, size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 2 + size, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_SUBSCRIBE:
        if (flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  queue (queue.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_subscribe_queue,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + str_size, length);
        }
        if (flag1 & 0x02) {
            /*  destination (destination [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_dest,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + str_size, length);
        }
        if (flag1 & 0x04) {     /* accept-mode (accept-mode [uint8]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_transfer_accept_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        if (flag1 & 0x08) {     /* acquire-mode (acquire-mode [uint8]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_transfer_acquire_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        /*
         * 5th argument is an optional bit, exclusive.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_message_subscribe_exclusive,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        if (flag1 & 0x20) {
            /*  resume-id (resume-id [str16]) */
            size = tvb_get_ntohs(tvb, offset);
            THROW_ON(((offset + 2 + size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_resume_id,
                                tvb, offset, 2 + size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 2 + size, length);
        }
        if (flag1 & 0x40) {
            /*  resume-ttl (uint64) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_subscribe_resume_ttl,
                                tvb, offset, 8, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 8, length);
        }
        if (flag1 & 0x80) {
            /*  arguments (map) */
            map_size = tvb_get_ntohl(tvb, offset);
            THROW_ON(((offset + 4 + map_size) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_message_subscribe_args,
                                     tvb,
                                     offset,
                                     4 + map_size, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset + 4,
                                   offset + 4 + map_size,
                                   map_size,
                                   ti);
            AMQP_INCREMENT(offset, 4 + map_size, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_CANCEL:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  destination (destination [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_dest,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + str_size, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_SET_FLOW_MODE:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  destination (destination [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_dest,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + str_size, length);
        }
        if (flag1 & 0x02) {
            /*  flow-mode (flow-mode [uint8]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_flow_mode,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_FLOW:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  destination (destination [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_dest,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + str_size, length);
        }
        if (flag1 & 0x02) {
            /*  unit (credit-unit [uint8]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_credit_unit,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 1, length);
        }
        if (flag1 & 0x04) {
            /*  value (uint32) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_credit_value,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_FLUSH:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  destination (destination [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_dest,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + str_size, length);
        }
        break;

    case AMQP_0_10_METHOD_MESSAGE_STOP:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {
            /*  destination (destination [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_message_dest,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, 1 + str_size, length);
        }
        break;
    }
}

static void
dissect_amqp_0_10_tx(tvbuff_t *tvb,
                     packet_info *pinfo,
                     proto_tree *tree,
                     int offset, guint16 length)
{
    guint8 method;
    guint8 flag1, flag2;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_tx_methods,
                                   "<invalid tx method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_tx_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * Session header is 2 bytes; one that tells it's 1 byte long, then
     * the byte itself. Bit 0 is sync.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    if (flag1 != 1 || (flag2 & 0xfe) != 0)
        proto_tree_add_text(tree, tvb, offset, 2, "Invalid session header");
    else
        proto_tree_add_item(tree, hf_amqp_0_10_session_header_sync,
                            tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    /* No args on any method in this class */
}

static void
dissect_amqp_0_10_dtx(tvbuff_t *tvb,
                      packet_info *pinfo,
                      proto_tree *tree,
                      int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 method;
    guint8 flag1, flag2;
    guint16 xid_length;
    int flags_offset;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_dtx_methods,
                                   "<invalid dtx method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_dtx_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * Session header is 2 bytes; one that tells it's 1 byte long, then
     * the byte itself. Bit 0 is sync.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    if (flag1 != 1 || (flag2 & 0xfe) != 0)
        proto_tree_add_text(tree, tvb, offset, 2, "Invalid session header");
    else
        proto_tree_add_item(tree, hf_amqp_0_10_session_header_sync,
                            tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    /* No args for dtx.select or dtx.recover */
    if (method == AMQP_0_10_METHOD_DTX_SELECT ||
        method == AMQP_0_10_METHOD_DTX_RECOVER)
        return;

    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset, length - 4, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);

    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_DTX_START:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* xid (xid) */
            xid_length = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, length);
            THROW_ON(((offset + xid_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_dtx_xid,
                                     tvb,
                                     offset - 2,
                                     xid_length + 2, ENC_NA);
            dissect_amqp_0_10_xid (tvb,
                                   offset,
                                   xid_length,
                                   ti);
            AMQP_INCREMENT(offset, xid_length, length);
        }
        /*
         * 2nd, 3rd arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_dtx_start_join,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_dtx_start_resume,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);

        break;

    case AMQP_0_10_METHOD_DTX_END:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* xid (xid) */
            xid_length = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, length);
            THROW_ON(((offset + xid_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_dtx_xid,
                                     tvb,
                                     offset - 2,
                                     xid_length + 2, ENC_NA);
            dissect_amqp_0_10_xid (tvb,
                                   offset,
                                   xid_length,
                                   ti);
            AMQP_INCREMENT(offset, xid_length, length);
        }
        /*
         * 2nd, 3rd arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_dtx_end_fail,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_dtx_end_suspend,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_DTX_COMMIT:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* xid (xid) */
            xid_length = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, length);
            THROW_ON(((offset + xid_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_dtx_xid,
                                     tvb,
                                     offset - 2,
                                     xid_length + 2, ENC_NA);
            dissect_amqp_0_10_xid (tvb,
                                   offset,
                                   xid_length,
                                   ti);
            AMQP_INCREMENT(offset, xid_length, length);
        }
        /*
         * 2nd argument is an optional bit.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_dtx_commit_one_phase,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_DTX_FORGET:
    case AMQP_0_10_METHOD_DTX_GET_TIMEOUT:
    case AMQP_0_10_METHOD_DTX_PREPARE:
    case AMQP_0_10_METHOD_DTX_ROLLBACK:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* xid (xid) */
            xid_length = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, length);
            THROW_ON(((offset + xid_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_dtx_xid,
                                     tvb,
                                     offset - 2,
                                     xid_length + 2, ENC_NA);
            dissect_amqp_0_10_xid (tvb,
                                   offset,
                                   xid_length,
                                   ti);
            AMQP_INCREMENT(offset, xid_length, length);
        }
        break;

    case AMQP_0_10_METHOD_DTX_SET_TIMEOUT:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* xid (xid) */
            xid_length = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(offset, 2, length);
            THROW_ON(((offset + xid_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_dtx_xid,
                                     tvb,
                                     offset - 2,
                                     xid_length + 2, ENC_NA);
            dissect_amqp_0_10_xid (tvb,
                                   offset,
                                   xid_length,
                                   ti);
            AMQP_INCREMENT(offset, xid_length, length);
        }
        if (flag1 & 0x02) {    /* timeout (uint32) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_dtx_set_timeout_timeout,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        break;

    }
}

static void
dissect_amqp_0_10_exchange(tvbuff_t *tvb,
                           packet_info *pinfo,
                           proto_tree *tree,
                           int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 method;
    guint8 flag1, flag2;
    guint8 str_size;
    guint32 map_length;
    int flags_offset;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_exchange_methods,
                                   "<invalid exchange method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_exchange_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * Session header is 2 bytes; one that tells it's 1 byte long, then
     * the byte itself. Bit 0 is sync.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    if (flag1 != 1 || (flag2 & 0xfe) != 0)
        proto_tree_add_text(tree, tvb, offset, 2, "Invalid session header");
    else
        proto_tree_add_item(tree, hf_amqp_0_10_session_header_sync,
                            tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset, length - 4, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);

    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_EXCHANGE_DECLARE:
        if ((flag1 & ~0x7f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* exchange (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_declare_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* type (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_declare_type,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x04) {     /* alternate-exchange (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_declare_alt_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        /*
         * 4th-6th arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_exchange_declare_passive,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_exchange_declare_durable,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_exchange_declare_auto_delete,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        if (flag1 & 0x40) {     /* arguments (map) */
            map_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            THROW_ON(((offset + map_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_exchange_declare_arguments,
                                     tvb,
                                     offset - 4,
                                     map_length + 4, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + map_length,
                                   map_length,
                                   ti);
            AMQP_INCREMENT(offset, map_length, length);
        }
        break;

    case AMQP_0_10_METHOD_EXCHANGE_DELETE:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* exchange (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_declare_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        /*
         * 2nd argument is an optional bit.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_exchange_delete_if_unused,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_EXCHANGE_QUERY:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* exchange (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_declare_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_EXCHANGE_BIND:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* queue (queue.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_bind_queue,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* exchange (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_declare_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x04) {     /* binding-key (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_binding_key,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x08) {     /* arguments (map) */
            map_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            THROW_ON(((offset + map_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_exchange_declare_arguments,
                                     tvb,
                                     offset - 4,
                                     map_length + 4, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + map_length,
                                   map_length,
                                   ti);
            AMQP_INCREMENT(offset, map_length, length);
        }
        break;

    case AMQP_0_10_METHOD_EXCHANGE_UNBIND:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* queue (queue.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_bind_queue,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* exchange (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_declare_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x04) {     /* binding-key (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_binding_key,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_EXCHANGE_BOUND:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* exchange (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_declare_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* queue (queue.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_bind_queue,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x04) {     /* binding-key (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_exchange_binding_key,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x08) {     /* arguments (map) */
            map_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            THROW_ON(((offset + map_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_exchange_declare_arguments,
                                     tvb,
                                     offset - 4,
                                     map_length + 4, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + map_length,
                                   map_length,
                                   ti);
            AMQP_INCREMENT(offset, map_length, length);
        }
        break;
    }
}

static void
dissect_amqp_0_10_queue(tvbuff_t *tvb,
                        packet_info *pinfo,
                        proto_tree *tree,
                        int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 method;
    guint8 flag1, flag2;
    guint8 str_size;
    guint32 map_length;
    int flags_offset;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_queue_methods,
                                   "<invalid queue method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_queue_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * Session header is 2 bytes; one that tells it's 1 byte long, then
     * the byte itself. Bit 0 is sync.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    if (flag1 != 1 || (flag2 & 0xfe) != 0)
        proto_tree_add_text(tree, tvb, offset, 2, "Invalid session header");
    else
        proto_tree_add_item(tree, hf_amqp_0_10_session_header_sync,
                            tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset, length - 4, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);

    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_QUEUE_DECLARE:
        if ((flag1 & ~0x7f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* queue (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_queue_name,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* alternate-exchange (exchange.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_queue_alt_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        /*
         * 3rd-6th arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_queue_declare_passive,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_queue_declare_durable,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_queue_declare_exclusive,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_queue_declare_auto_delete,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        if (flag1 & 0x40) {     /* arguments (map) */
            map_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            THROW_ON(((offset + map_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_queue_declare_arguments,
                                     tvb,
                                     offset - 4,
                                     map_length + 4, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + map_length,
                                   map_length,
                                   ti);
            AMQP_INCREMENT(offset, map_length, length);
        }
        break;

    case AMQP_0_10_METHOD_QUEUE_DELETE:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* queue (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_queue_name,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        /*
         * 2nd-3rd arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_queue_delete_if_unused,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_queue_delete_if_empty,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_QUEUE_PURGE:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* queue (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_queue_name,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_QUEUE_QUERY:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* queue (name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_queue_name,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;
    }
}

static void
dissect_amqp_0_10_file(tvbuff_t *tvb,
                       packet_info *pinfo,
                       proto_tree *tree,
                       int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 method;
    guint8 flag1, flag2;
    guint8 str_size;
    guint32 map_length;
    int flags_offset;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_file_methods,
                                   "<invalid file method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_file_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * Session header is 2 bytes; one that tells it's 1 byte long, then
     * the byte itself. Bit 0 is sync.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    if (flag1 != 1 || (flag2 & 0xfe) != 0)
        proto_tree_add_text(tree, tvb, offset, 2, "Invalid session header");
    else
        proto_tree_add_item(tree, hf_amqp_0_10_session_header_sync,
                            tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset, length - 4, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);

    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_FILE_QOS:
        if ((flag1 & ~0x07) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* prefetch-size (uint32) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_qos_prefetch_size,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        if (flag1 & 0x02) {     /* prefetch-count (uint16) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_qos_prefetch_count,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        /*
         * 3rd argument is an optional bit.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_qos_global,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_FILE_QOS_OK:
    case AMQP_0_10_METHOD_FILE_STAGE:
        /* No args */
        break;

    case AMQP_0_10_METHOD_FILE_CONSUME:
        if ((flag1 & ~0x7f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* queue (queue.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) <= length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_queue_name,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* consumer-tag (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_consumer_tag,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        /*
         * 3rd-6th arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_consume_no_local,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_consume_no_ack,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_consume_exclusive,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_consume_nowait,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        if (flag1 & 0x40) {     /* arguments (map) */
            map_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            THROW_ON(((offset + map_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_file_consume_arguments,
                                     tvb,
                                     offset - 4,
                                     map_length + 4, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + map_length,
                                   map_length,
                                   ti);
            AMQP_INCREMENT(offset, map_length, length);
        }
        break;

    case AMQP_0_10_METHOD_FILE_CONSUME_OK:
    case AMQP_0_10_METHOD_FILE_CANCEL:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* consumer-tag (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_consumer_tag,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_FILE_OPEN:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* identifier (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_identifier,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* content-size (uint64) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_open_content_size,
                                tvb, offset, 8, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 8, length);
        }
        break;

    case AMQP_0_10_METHOD_FILE_OPEN_OK:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* staged-size (uint64) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_open_ok_staged_size,
                                tvb, offset, 8, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 8, length);
        }
        break;

    case AMQP_0_10_METHOD_FILE_PUBLISH:
        if ((flag1 & ~0x1f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* exchange (exchange.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_publish_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* routing-key (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_publish_routing_key,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        /*
         * 3rd-4th arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_publish_mandatory,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_publish_immediate,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        if (flag1 & 0x10) {     /* identifier (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_identifier,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_FILE_RETURN:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* reply-code (return-code [uint16]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_return_reply_code,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x02) {     /* reply-text (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_return_reply_text,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x04) {     /* exchange (exchange.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_return_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x08) {     /* routing-key (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_return_routing_key,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_FILE_DELIVER:
        if ((flag1 & ~0x3f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* consumer-tag (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_deliver_consumer_tag,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* delivery-tag (uint64) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_deliver_delivery_tag,
                                tvb, offset, 8, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 8, length);
        }
        /*
         * 3rd argument is an optional bit.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_deliver_redelivered,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        if (flag1 & 0x08) {     /* exchange (exchange.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_deliver_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x10) {     /* routing-key (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_deliver_routing_key,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x20) {     /* identifier (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_identifier,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_FILE_ACK:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* delivery-tag (uint64) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_ack_delivery_tag,
                                tvb, offset, 8, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 8, length);
        }
        /*
         * 2nd argument is an optional bit.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_ack_multiple,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_FILE_REJECT:
        if ((flag1 & ~0x03) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* delivery-tag (uint64) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_file_reject_delivery_tag,
                                tvb, offset, 8, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 8, length);
        }
        /*
         * 2nd argument is an optional bit.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_file_reject_requeue,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;
    }
}

static void
dissect_amqp_0_10_stream(tvbuff_t *tvb,
                         packet_info *pinfo,
                         proto_tree *tree,
                         int offset, guint16 length)
{
    proto_item *args_tree;
    proto_item *ti;
    proto_item *flags_item;
    guint8 method;
    guint8 flag1, flag2;
    guint8 str_size;
    guint32 map_length;
    int flags_offset;
    const gchar* method_name;

    method = tvb_get_guint8(tvb, offset+1);
    method_name = val_to_str_const(method, amqp_0_10_stream_methods,
                                   "<invalid stream method>");
    col_append_str(pinfo->cinfo, COL_INFO, method_name);
    col_append_str(pinfo->cinfo, COL_INFO, " ");
    col_set_fence(pinfo->cinfo, COL_INFO);

    proto_tree_add_item(tree, hf_amqp_0_10_stream_method,
                        tvb, offset+1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    /*
     * Session header is 2 bytes; one that tells it's 1 byte long, then
     * the byte itself. Bit 0 is sync.
     */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    if (flag1 != 1 || (flag2 & 0xfe) != 0)
        proto_tree_add_text(tree, tvb, offset, 2, "Invalid session header");
    else
        proto_tree_add_item(tree, hf_amqp_0_10_session_header_sync,
                            tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);

    ti = proto_tree_add_item(tree, hf_amqp_method_arguments,
                             tvb, offset, length - 4, ENC_NA);
    args_tree = proto_item_add_subtree(ti, ett_args);

    /*
     * The flag bits are a simple bit string, not a net-byte-order
     * field. tvb_get_bits16() doesn't know how to do little-endian
     * at this time, so just pick out two bytes.
     */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    AMQP_INCREMENT(offset, 2, length);
    switch (method) {
    case AMQP_0_10_METHOD_STREAM_QOS:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* prefetch-size (uint32) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_qos_prefetch_size,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        if (flag1 & 0x02) {     /* prefetch-count (uint16) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_qos_prefetch_count,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x04) {     /* consume-rate (uint32) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_qos_prefetch_size,
                                tvb, offset, 4, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 4, length);
        }
        /*
         * 4th argument is an optional bit.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_stream_qos_global,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_STREAM_QOS_OK:
        /* No args */
        break;

    case AMQP_0_10_METHOD_STREAM_CONSUME:
        if ((flag1 & ~0x3f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* queue (queue.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_queue_name,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* consumer-tag (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_consumer_tag,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        /*
         * 3rd-5th arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_stream_consume_no_local,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_stream_consume_exclusive,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_stream_consume_nowait,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        if (flag1 & 0x20) {     /* arguments (map) */
            map_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(offset, 4, length);
            THROW_ON(((offset + map_length) > length), ReportedBoundsError);
            ti = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_method_stream_consume_arguments,
                                     tvb,
                                     offset - 4,
                                     map_length + 4, ENC_NA);
            dissect_amqp_0_10_map (tvb,
                                   offset,
                                   offset + map_length,
                                   map_length,
                                   ti);
            AMQP_INCREMENT(offset, map_length, length);
        }
        break;

    case AMQP_0_10_METHOD_STREAM_CONSUME_OK:
    case AMQP_0_10_METHOD_STREAM_CANCEL:
        if ((flag1 & ~0x01) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* consumer-tag (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_consumer_tag,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_STREAM_PUBLISH:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* exchange (exchange.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) <= length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_publish_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* routing-key (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_publish_routing_key,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        /*
         * 3rd-4th arguments are optional bits.
         */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_stream_publish_mandatory,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_stream_publish_immediate,
                            tvb, flags_offset, 1, ENC_BIG_ENDIAN);
        break;

    case AMQP_0_10_METHOD_STREAM_RETURN:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* reply-code (return-code [uint16]) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_return_reply_code,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 2, length);
        }
        if (flag1 & 0x02) {     /* reply-text (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_return_reply_text,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x04) {     /* exchange (exchange.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_return_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x08) {     /* routing-key (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_return_routing_key,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;

    case AMQP_0_10_METHOD_STREAM_DELIVER:
        if ((flag1 & ~0x0f) || flag2 != 0)
            proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
        if (flag1 & 0x01) {     /* consumer-tag (str8) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_deliver_consumer_tag,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x02) {     /* delivery-tag (uint64) */
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_deliver_delivery_tag,
                                tvb, offset, 8, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(offset, 8, length);
        }
        if (flag1 & 0x04) {     /* exchange (exchange.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_deliver_exchange,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        if (flag1 & 0x08) {     /* queue (queue.name [str8]) */
            str_size = tvb_get_guint8(tvb, offset);
            THROW_ON(((offset + 1 + str_size) > length), ReportedBoundsError);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_method_stream_deliver_queue,
                                tvb, offset + 1, str_size, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + str_size), length);
        }
        break;
    }
}

static void
dissect_amqp_0_10_struct_delivery_properties(tvbuff_t *tvb,
                                             proto_tree *tree,
                                             int offset,
                                             guint32 struct_length)
{
    proto_item *args_tree;
    proto_item *flags_item;
    guint8 flag1, flag2;
    guint8 len8;
    guint16 len16;
    guint64 timestamp;
    int flags_offset;
    int max_length;
    nstime_t tv;

    max_length = offset + struct_length;
    args_tree = proto_item_add_subtree(tree, ett_args);
    AMQP_INCREMENT(offset, 2, max_length);  /* Skip class and struct codes */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    if (flag2 & ~0x0f)
        proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
    AMQP_INCREMENT(offset, 2, max_length);

    /* First 3 fields are bits */
    proto_tree_add_item(args_tree,
                        hf_amqp_0_10_struct_delivery_properties_discard_unroutable,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(args_tree,
                        hf_amqp_0_10_struct_delivery_properties_immediate,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(args_tree,
                        hf_amqp_0_10_struct_delivery_properties_redelivered,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    if (flag1 & 0x08) {
        /* delivery-priority (delivery-priority [uint8]) */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_struct_delivery_properties_priority,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 1, max_length);
    }
    if (flag1 & 0x10) {
        /* delivery-mode (delivery-mode [uint8]) */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_struct_delivery_properties_mode,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 1, max_length);
    }
    if (flag1 & 0x20) {
        /* ttl (uint64) */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_struct_delivery_properties_ttl,
                            tvb, offset, 8, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 8, max_length);
    }
    if (flag1 & 0x40) {
        /* timestamp (datetime [uint64]) */
        timestamp = tvb_get_ntoh64(tvb, offset);
        tv.secs = (time_t)timestamp;
        tv.nsecs = 0;
        proto_tree_add_time(args_tree,
                            hf_amqp_0_10_struct_delivery_properties_timestamp,
                            tvb, offset, 8, &tv);
        AMQP_INCREMENT(offset, 8, max_length);
    }
    if (flag1 & 0x80) {
        /* expiration (datetime [uint64]) */
        timestamp = tvb_get_ntoh64(tvb, offset);
        tv.secs = (time_t)timestamp;
        tv.nsecs = 0;
        proto_tree_add_time(args_tree,
                            hf_amqp_0_10_struct_delivery_properties_expiration,
                            tvb, offset, 8, &tv);
        AMQP_INCREMENT(offset, 8, max_length);
    }
    if (flag2 & 0x01) {
        /* exchange (exchange.name [str8]) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_struct_delivery_properties_exchange,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag2 & 0x02) {
        /* routing-key (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_struct_delivery_properties_routing_key,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag2 & 0x04) {
        /*  resume-id (resume-id [str16]) */
        len16 = tvb_get_ntohs(tvb, offset);
        THROW_ON(((offset + 2 + len16) > max_length), ReportedBoundsError);
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_method_message_resume_id,
                            tvb, offset + 2, len16, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (2 + len16), max_length);
    }
    if (flag2 & 0x08) {
        /*  resume-ttl (uint64) */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_struct_delivery_properties_resume_ttl,
                            tvb, offset, 8, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 8, max_length);
    }
}

static void
dissect_amqp_0_10_struct_fragment_properties(tvbuff_t *tvb,
                                             proto_tree *tree,
                                             int offset,
                                             guint32 struct_length)
{
    proto_item *args_tree;
    proto_item *flags_item;
    guint8 flag1, flag2;
    int flags_offset;
    int max_length;

    max_length = offset + struct_length;
    args_tree = proto_item_add_subtree(tree, ett_args);
    AMQP_INCREMENT(offset, 2, max_length);  /* Skip class and struct codes */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(args_tree,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    if ((flag1 & ~0x07) || flag2 != 0)
        proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
    AMQP_INCREMENT(offset, 2, max_length);

    /* First 2 fields are bits */
    proto_tree_add_item(args_tree,
                        hf_amqp_0_10_struct_fragment_properties_first,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(args_tree,
                        hf_amqp_0_10_struct_fragment_properties_last,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    if (flag1 & 0x04) {
        /* fragment-size (uint64) */
        proto_tree_add_item(args_tree,
                            hf_amqp_0_10_struct_fragment_properties_size,
                            tvb, offset, 8, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 8, max_length);
    }
}

static void
dissect_amqp_0_10_struct_message_properties(tvbuff_t *tvb,
                                            proto_tree *tree,
                                            int offset,
                                            guint32 struct_length)
{
    proto_item *ti;
    proto_item *frag;
    proto_item *args_tree;
    proto_item *flags_item, *subflags_item;
    guint8 flag1, flag2;
    guint8 subflag1, subflag2;
    guint8 len8;
    guint16 len16;
    guint32 map_length;
    e_guid_t uuid;
    int max_length;

    max_length = offset + struct_length;
    frag = proto_item_add_subtree(tree, ett_args);
    AMQP_INCREMENT(offset, 2, max_length);  /* Skip class and struct codes */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(frag,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    if (flag2 & ~0x01)
        proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
    AMQP_INCREMENT(offset, 2, max_length);
    if (flag1 & 0x01) {
        /*  content-length (uint64) */
        proto_tree_add_item(frag,
                            hf_amqp_0_10_struct_message_properties_content_len,
                            tvb, offset, 8, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 8, max_length);
    }
    if (flag1 & 0x02) {
        /* message-id (uuid) */
        tvb_get_guid(tvb, offset, &uuid, ENC_BIG_ENDIAN);
        proto_tree_add_guid(frag,
                            hf_amqp_0_10_struct_message_properties_message_id,
                            tvb, offset, 16, &uuid);
        AMQP_INCREMENT(offset, 16, max_length);
    }
    if (flag1 & 0x04) {
        /* correlation-id (vbin16) */
        len16 = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(frag,
                            hf_amqp_0_10_struct_message_properties_correlation,
                            tvb, offset + 2, len16, ENC_NA);
        AMQP_INCREMENT(offset, (2 + len16), max_length);
    }
    if (flag1 & 0x08) {
        /* reply-to (reply-to) */
        /* This is another struct, length 2, packing 2 */
        len16 = tvb_get_ntohs(tvb, offset);
        AMQP_INCREMENT(offset, 2, max_length);
        ti = proto_tree_add_item(frag,
                                 hf_amqp_0_10_struct_message_properties_reply_to,
                                 tvb, offset, len16, ENC_NA);
        args_tree = proto_item_add_subtree(ti, ett_args);
        subflags_item = proto_tree_add_item(args_tree,
                                            hf_amqp_0_10_argument_packing_flags,
                                            tvb, offset, 2, ENC_BIG_ENDIAN);
        subflag1 = tvb_get_guint8(tvb, offset);
        subflag2 = tvb_get_guint8(tvb, offset + 1);
        if ((subflag1 & ~0x03) || subflag2 != 0)
            proto_item_set_expert_flags(subflags_item, PI_PROTOCOL, PI_WARN);
        AMQP_INCREMENT(offset, 2, max_length);
        if (subflag1 & 0x01) {
            /* exchange (str8) */
            len8 = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_struct_reply_to_exchange,
                                tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + len8), max_length);
        }
        if (subflag1 & 0x02) {
            /* routing-key (str8) */
            len8 = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(args_tree,
                                hf_amqp_0_10_struct_reply_to_routing_key,
                                tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
            AMQP_INCREMENT(offset, (1 + len8), max_length);
        }
    }
    if (flag1 & 0x10) {
        /* content-type (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(frag,
                            hf_amqp_0_10_struct_message_properties_content_type,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x20) {
        /* content-encoding (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(frag,
                            hf_amqp_0_10_struct_message_properties_content_encoding,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x40) {
        /* user-id (vbin16 ) */
        len16 = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(frag,
                            hf_amqp_0_10_struct_message_properties_user_id,
                            tvb, offset + 2, len16, ENC_NA);
        AMQP_INCREMENT(offset, (2 + len16), max_length);
    }
    if (flag1 & 0x80) {
        /* app-id (vbin16 ) */
        len16 = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(frag,
                            hf_amqp_0_10_struct_message_properties_app_id,
                            tvb, offset + 2, len16, ENC_NA);
        AMQP_INCREMENT(offset, (2 + len16), max_length);
    }
    if (flag2 & 0x01) {
        /* application-headers (map) */
        map_length = tvb_get_ntohl(tvb, offset);
        AMQP_INCREMENT(offset, 4, max_length);
        ti = proto_tree_add_item(frag,
                                 hf_amqp_0_10_struct_message_properties_application_headers,
                                 tvb,
                                 offset,
                                 map_length, ENC_NA);
        dissect_amqp_0_10_map (tvb,
                               offset,
                               offset + map_length,
                               map_length,
                               ti);
        AMQP_INCREMENT(offset, map_length, max_length);
    }
}

static void
dissect_amqp_0_10_struct_exchange_query_result(tvbuff_t *tvb,
                                               proto_item *tree,
                                               int offset,
                                               guint32 struct_length)
{
    proto_item *ti;
    proto_item *result;
    proto_item *flags_item;
    guint8 flag1, flag2;
    guint8 len8;
    guint32 map_length;
    int flags_offset;
    int max_length;

    max_length = offset + struct_length;
    result = proto_item_add_subtree(tree, ett_args);
    AMQP_INCREMENT(offset, 2, max_length);  /* Skip class and struct codes */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(result,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    if (flag2 & ~0x0f)
        proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
    AMQP_INCREMENT(offset, 2, max_length);
    if (flag1 & 0x01) {
        /*  type (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        THROW_ON(((offset + 1 + len8) > max_length), ReportedBoundsError);
        proto_tree_add_item(result,
                            hf_amqp_0_10_method_exchange_declare_type,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    proto_tree_add_item(result,
                        hf_amqp_0_10_struct_exchange_query_result_durable,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(result,
                        hf_amqp_0_10_struct_exchange_query_result_not_found,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    if (flag1 & 0x08) {
        /*  arguments (map) */
        map_length = tvb_get_ntohl(tvb, offset);
        AMQP_INCREMENT(offset, 4, max_length);
        THROW_ON(((offset + (int)map_length) > max_length), ReportedBoundsError);
        ti = proto_tree_add_item(result,
                                 hf_amqp_0_10_method_exchange_declare_arguments,
                                 tvb,
                                 offset - 4,
                                 map_length + 4, ENC_NA);
        dissect_amqp_0_10_map (tvb,
                               offset,
                               offset + map_length,
                               map_length,
                               ti);
        AMQP_INCREMENT(offset, map_length, max_length);
    }
}

static void
dissect_amqp_0_10_struct_queue_query_result(tvbuff_t *tvb,
                                            proto_item *tree,
                                            int offset,
                                            guint32 struct_length)
{
    proto_item *ti;
    proto_item *result;
    proto_item *flags_item;
    guint8 flag1, flag2;
    guint8 len8;
    guint32 map_length;
    int flags_offset;
    int max_length;

    max_length = offset + struct_length;
    result = proto_item_add_subtree(tree, ett_args);
    AMQP_INCREMENT(offset, 2, max_length);  /* Skip class and struct codes */
    flags_offset = offset;
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(result,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);

    if (flag2 != 0)
        proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
    AMQP_INCREMENT(offset, 2, max_length);
    if (flag1 & 0x01) {
        /*  queue (name [str8]) */
        len8 = tvb_get_guint8(tvb, offset);
        THROW_ON(((offset + 1 + len8) > max_length), ReportedBoundsError);
        proto_tree_add_item(result,
                            hf_amqp_0_10_method_queue_name,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x02) {     /* alternate-exchange (exchange.name [str8]) */
        len8 = tvb_get_guint8(tvb, offset);
        THROW_ON(((offset + 1 + len8) > max_length), ReportedBoundsError);
        proto_tree_add_item(result,
                            hf_amqp_0_10_method_queue_alt_exchange,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    /*
     * 3rd-5th arguments are optional bits.
     */
    proto_tree_add_item(result,
                        hf_amqp_0_10_struct_queue_query_result_durable,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(result,
                        hf_amqp_0_10_struct_queue_query_result_exclusive,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(result,
                        hf_amqp_0_10_struct_queue_query_result_auto_delete,
                        tvb, flags_offset, 1, ENC_BIG_ENDIAN);
    if (flag1 & 0x20) {     /* arguments (map) */
        map_length = tvb_get_ntohl(tvb, offset);
        AMQP_INCREMENT(offset, 4, max_length);
        THROW_ON(((offset + (int)map_length) > max_length), ReportedBoundsError);
        ti = proto_tree_add_item(result,
                                 hf_amqp_0_10_method_queue_declare_arguments,
                                 tvb,
                                 offset - 4,
                                 map_length + 4, ENC_NA);
        dissect_amqp_0_10_map (tvb,
                               offset,
                               offset + map_length,
                               map_length,
                               ti);
        AMQP_INCREMENT(offset, (int)map_length, max_length);
    }
    if (flag1 & 0x40) {     /* message-count (uint32) */
        proto_tree_add_item(result,
                            hf_amqp_0_10_struct_queue_query_result_message_count,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 4, max_length);
    }
    if (flag1 & 0x80) {     /* subscriber-count (uint32) */
        proto_tree_add_item(result,
                            hf_amqp_0_10_struct_queue_query_result_subscriber_count,
                            tvb, offset, 4, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 4, max_length);
    }
}

static void
dissect_amqp_0_10_struct_file_properties(tvbuff_t *tvb,
                                         proto_tree *tree,
                                         int offset,
                                         guint32 struct_length)
{
    proto_item *ti;
    proto_item *props;
    proto_item *flags_item;
    guint8 flag1, flag2;
    guint8 len8;
    guint32 map_length;
    guint64 timestamp;
    int max_length;
    nstime_t tv;

    max_length = offset + struct_length;
    props = proto_item_add_subtree(tree, ett_args);
    AMQP_INCREMENT(offset, 2, max_length);  /* Skip class and struct codes */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(props,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    if (flag2 & ~0x01)
        proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
    AMQP_INCREMENT(offset, 2, max_length);
    if (flag1 & 0x01) {
        /*  content-type (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_file_properties_content_type,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x02) {
        /*  content-encoding (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_file_properties_content_encoding,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x04) {
        /* headers (map) */
        map_length = tvb_get_ntohl(tvb, offset);
        AMQP_INCREMENT(offset, 4, max_length);
        ti = proto_tree_add_item(props,
                                 hf_amqp_0_10_struct_file_properties_headers,
                                 tvb,
                                 offset,
                                 map_length, ENC_NA);
        dissect_amqp_0_10_map (tvb,
                               offset,
                               offset + map_length,
                               map_length,
                               ti);
        AMQP_INCREMENT(offset, map_length, max_length);
    }
    if (flag1 & 0x08) {
        /* priority (uint8) */
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_file_properties_priority,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 1, max_length);
    }
    if (flag1 & 0x10) {
        /* reply-to (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_file_properties_reply_to,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x20) {
        /* message-id (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_file_properties_message_id,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x40) {
        /* filename (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_file_properties_filename,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x80) {
        /* timestamp (datetime [uint64]) */
        timestamp = tvb_get_ntoh64(tvb, offset);
        tv.secs = (time_t)timestamp;
        tv.nsecs = 0;
        proto_tree_add_time(props,
                            hf_amqp_0_10_struct_file_properties_timestamp,
                            tvb, offset, 8, &tv);
        AMQP_INCREMENT(offset, 8, max_length);
    }
    if (flag2 & 0x01) {
        /* cluster-id (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_file_properties_cluster_id,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
}

static void
dissect_amqp_0_10_struct_stream_properties(tvbuff_t *tvb,
                                           proto_tree *tree,
                                           int offset,
                                           guint32 struct_length)
{
    proto_item *ti;
    proto_item *props;
    proto_item *flags_item;
    guint8 flag1, flag2;
    guint8 len8;
    guint32 map_length;
    guint64 timestamp;
    int max_length;
    nstime_t tv;

    max_length = offset + struct_length;
    props = proto_item_add_subtree(tree, ett_args);
    AMQP_INCREMENT(offset, 2, max_length);  /* Skip class and struct codes */
    flag1 = tvb_get_guint8(tvb, offset);
    flag2 = tvb_get_guint8(tvb, offset+1);
    flags_item = proto_tree_add_item(props,
                                     hf_amqp_0_10_argument_packing_flags,
                                     tvb, offset, 2, ENC_BIG_ENDIAN);
    if ((flag1 & ~0x1f) || flag2 != 0)
        proto_item_set_expert_flags(flags_item, PI_PROTOCOL, PI_WARN);
    AMQP_INCREMENT(offset, 2, max_length);
    if (flag1 & 0x01) {
        /*  content-type (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_stream_properties_content_type,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x02) {
        /*  content-encoding (str8) */
        len8 = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_stream_properties_content_encoding,
                            tvb, offset + 1, len8, ENC_ASCII|ENC_NA);
        AMQP_INCREMENT(offset, (1 + len8), max_length);
    }
    if (flag1 & 0x04) {
        /* headers (map) */
        map_length = tvb_get_ntohl(tvb, offset);
        AMQP_INCREMENT(offset, 4, max_length);
        ti = proto_tree_add_item(props,
                                 hf_amqp_0_10_struct_stream_properties_headers,
                                 tvb,
                                 offset,
                                 map_length, ENC_NA);
        dissect_amqp_0_10_map (tvb,
                               offset,
                               offset + map_length,
                               map_length,
                               ti);
        AMQP_INCREMENT(offset, map_length, max_length);
    }
    if (flag1 & 0x08) {
        /* priority (uint8) */
        proto_tree_add_item(props,
                            hf_amqp_0_10_struct_stream_properties_priority,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
        AMQP_INCREMENT(offset, 1, max_length);
    }
    if (flag1 & 0x10) {
        /* timestamp (datetime [uint64]) */
        timestamp = tvb_get_ntoh64(tvb, offset);
        tv.secs = (time_t)timestamp;
        tv.nsecs = 0;
        proto_tree_add_time(props,
                            hf_amqp_0_10_struct_stream_properties_timestamp,
                            tvb, offset, 8, &tv);
        AMQP_INCREMENT(offset, 8, max_length);
    }
}

static void
dissect_amqp_0_10_struct32(tvbuff_t *tvb,
                           proto_tree *tree,
                           int offset,
                           guint32 struct_length)
{
    guint8 class_code;
    guint8 struct_code;
    guint8 flag1;
    guint16 size;
    guint16 value;
    guint32 array_length;
    guint32 consumed;
    proto_tree *ti;
    proto_tree *result;

    consumed = 0;
    class_code = tvb_get_guint8(tvb, offset);
    struct_code = tvb_get_guint8(tvb, offset + 1);
    switch(class_code) {
    case AMQP_0_10_CLASS_MESSAGE:
        switch (struct_code) {
        case AMQP_0_10_STRUCT_MESSAGE_DELIVERY_PROPERTIES:
            proto_item_set_text(tree, "message.delivery-properties");
            dissect_amqp_0_10_struct_delivery_properties(tvb,
                                                         tree,
                                                         offset,
                                                         struct_length);
            break;
        case AMQP_0_10_STRUCT_MESSAGE_FRAGMENT_PROPERTIES:
            proto_item_set_text(tree, "message.fragment-properties");
            dissect_amqp_0_10_struct_fragment_properties(tvb,
                                                         tree,
                                                         offset,
                                                         struct_length);
            break;
        case AMQP_0_10_STRUCT_MESSAGE_MESSAGE_PROPERTIES:
            proto_item_set_text(tree, "message.message-properties");
            dissect_amqp_0_10_struct_message_properties(tvb,
                                                        tree,
                                                        offset,
                                                        struct_length);
            break;
        case AMQP_0_10_STRUCT_MESSAGE_ACQUIRED:
            proto_item_set_text(tree, "message.acquired");
            result = proto_item_add_subtree(tree, ett_args);
            AMQP_INCREMENT(consumed, 2, struct_length);  /* Class/type codes */
            offset += 2;
            flag1 = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(result, hf_amqp_0_10_argument_packing_flags,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(consumed, 2, struct_length);
            offset += 2;
            if (flag1 & 0x01) {
                /*  transfers (commands [sequence-set])  */
                size = tvb_get_ntohs(tvb, offset);
                THROW_ON(((consumed + size) > struct_length), ReportedBoundsError);
                ti = proto_tree_add_item(result,
                                         hf_amqp_0_10_struct_acquired_transfers,
                                         tvb, offset, size + 2, ENC_NA);
                format_amqp_0_10_sequence_set(tvb, offset + 2, size, ti);
            }
            break;
        case AMQP_0_10_STRUCT_MESSAGE_RESUME_RESULT:
            proto_item_set_text(tree, "message.resume-result");
            result = proto_item_add_subtree(tree, ett_args);
            AMQP_INCREMENT(consumed, 2, struct_length);  /* Class/type codes */
            offset += 2;
            flag1 = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(result, hf_amqp_0_10_argument_packing_flags,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            AMQP_INCREMENT(consumed, 2, struct_length);
            offset += 2;
            if (flag1 & 0x01) {
                /*  offset (uint64)  */
                proto_tree_add_item(result,
                                    hf_amqp_0_10_struct_resume_result_offset,
                                    tvb, offset, 8, ENC_BIG_ENDIAN);
            }
            break;
        }
        break;

    case AMQP_0_10_CLASS_DTX:
        switch (struct_code) {
        case AMQP_0_10_STRUCT_DTX_XA_RESULT:
            AMQP_INCREMENT(consumed, 2, struct_length);  /* Class/type codes */
            offset += 2;
            /*flag1 = tvb_get_guint8(tvb, offset);*/
            AMQP_INCREMENT(consumed, 2, struct_length);  /* Packing bytes */
            offset += 2;
            value = tvb_get_ntohs(tvb, offset);
            AMQP_INCREMENT(consumed, 2, struct_length);  /* xa status value */
            /*offset += 2;*/
            proto_item_set_text(tree, "dtx.xa-status: %s",
                                val_to_str(value,
                                           amqp_0_10_xa_status,
                                           "Invalid xa-status %d"));
            break;

        case AMQP_0_10_STRUCT_DTX_RECOVER_RESULT:
            proto_item_set_text(tree, "dtx.recover-result");
            AMQP_INCREMENT(consumed, 2, struct_length);  /* Class/type codes */
            offset += 2;
            /*flag1 = tvb_get_guint8(tvb, offset);*/
            AMQP_INCREMENT(consumed, 2, struct_length);  /* Packing bytes */
            offset += 2;
            array_length = tvb_get_ntohl(tvb, offset);
            AMQP_INCREMENT(consumed, 4, struct_length);
            offset += 4;
            dissect_amqp_0_10_array(tvb,
                                    offset,
                                    offset + array_length,
                                    array_length,
                                    tree);
            break;
        }
        break;

    case AMQP_0_10_CLASS_EXCHANGE:
        switch (struct_code) {
        case AMQP_0_10_STRUCT_EXCHANGE_QUERY_RESULT:
            proto_item_set_text(tree, "exchange.exchange-query-result");
            dissect_amqp_0_10_struct_exchange_query_result(tvb,
                                                           tree,
                                                           offset,
                                                           struct_length);
            break;

        case AMQP_0_10_STRUCT_EXCHANGE_BOUND_RESULT:
            proto_item_set_text(tree, "exchange.exchange-bound-result");
            result = proto_item_add_subtree(tree, ett_args);
            AMQP_INCREMENT(consumed, 2, struct_length);  /* Class/type codes */
            offset += 2;
            proto_tree_add_item(result,
                                hf_amqp_0_10_struct_exchange_bound_result_exchange_not_found,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(result,
                                hf_amqp_0_10_struct_exchange_bound_result_queue_not_found,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(result,
                                hf_amqp_0_10_struct_exchange_bound_result_queue_not_matched,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(result,
                                hf_amqp_0_10_struct_exchange_bound_result_key_not_matched,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(result,
                                hf_amqp_0_10_struct_exchange_bound_result_args_not_matched,
                                tvb, offset, 1, ENC_BIG_ENDIAN);
            break;
        }
        break;

    case AMQP_0_10_CLASS_QUEUE:
        switch (struct_code) {
        case AMQP_0_10_STRUCT_QUEUE_QUERY_RESULT:
            proto_item_set_text(tree, "queue.queue-query-result");
            dissect_amqp_0_10_struct_queue_query_result(tvb,
                                                        tree,
                                                        offset,
                                                        struct_length);
            break;
        }
        break;

    case AMQP_0_10_CLASS_FILE:
        switch (struct_code) {
        case AMQP_0_10_STRUCT_FILE_PROPERTIES:
            proto_item_set_text(tree, "file.file-properties");
            dissect_amqp_0_10_struct_file_properties(tvb,
                                                     tree,
                                                     offset,
                                                     struct_length);
            break;
        }
        break;

    case AMQP_0_10_CLASS_STREAM:
        switch (struct_code) {
        case AMQP_0_10_STRUCT_STREAM_PROPERTIES:
            proto_item_set_text(tree, "stream.stream-properties");
            dissect_amqp_0_10_struct_stream_properties(tvb,
                                                       tree,
                                                       offset,
                                                       struct_length);
            break;
        }
        break;
    }
}

static void
dissect_amqp_0_10_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_item *amqp_tree;
    guint8 frame_type;
    guint8 proto_major;
    guint8 proto_minor;
    guint16 length;
    guint32 struct_length;
    int offset;
    emem_strbuf_t *strbuf;

#if 0  /* XXX: Not currently used ?? */
    conversation_t *conv;
    amqp_conv *conn;

    /* Find (or build) conversation to remember the protocol version */
    conv = find_or_create_conversation(pinfo);
    conn = conversation_get_proto_data(conv, proto_amqp);
#endif

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMQP");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        /*  Heuristic - protocol initialisation frame starts with 'AMQP'  */
        if (tvb_get_guint8(tvb, 0) == 'A' &&
            tvb_get_guint8(tvb, 1) == 'M' &&
            tvb_get_guint8(tvb, 2) == 'Q' &&
            tvb_get_guint8(tvb, 3) == 'P') {

            proto_major = tvb_get_guint8(tvb, 6);
            proto_minor = tvb_get_guint8(tvb, 7);
            strbuf = ep_strbuf_new_label("");
            ep_strbuf_append_printf(strbuf,
                                    "Protocol-Header %d-%d ",
                                    proto_major,
                                    proto_minor);
            col_append_str(pinfo->cinfo, COL_INFO, strbuf->str);
            col_set_fence(pinfo->cinfo, COL_INFO);

            ti = proto_tree_add_item(tree, proto_amqp, tvb, 0, -1, ENC_NA);
            amqp_tree = proto_item_add_subtree(ti, ett_amqp_init);
            proto_tree_add_item(amqp_tree, hf_amqp_init_protocol, tvb, 0, 4, ENC_ASCII|ENC_NA);
            proto_tree_add_item(amqp_tree, hf_amqp_init_id_major, tvb, 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_init_id_minor, tvb, 5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_init_version_major, tvb, 6, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_init_version_minor, tvb, 7, 1, ENC_BIG_ENDIAN);

            return;
        }

        /* Protocol frame */
        ti = proto_tree_add_item(tree, proto_amqp, tvb, 0, -1, ENC_NA);
        amqp_tree = proto_item_add_subtree(ti, ett_amqp);
        proto_tree_add_item(amqp_tree, hf_amqp_0_10_format, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(amqp_tree, hf_amqp_0_10_position, tvb, 0, 1, ENC_BIG_ENDIAN);
        frame_type = tvb_get_guint8(tvb, 1);
        proto_tree_add_item(amqp_tree, hf_amqp_0_10_type, tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(amqp_tree, hf_amqp_0_10_size, tvb, 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(amqp_tree, hf_amqp_0_10_track, tvb, 5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(amqp_tree, hf_amqp_channel, tvb, 6, 2, ENC_BIG_ENDIAN);
        length = tvb_get_ntohs(tvb, 2);
        offset = 12;
        THROW_ON((length <= 13), ReportedBoundsError);

        switch(frame_type) {
        case AMQP_0_10_FRAME_COMMAND:
          /* Fall through */
        case AMQP_0_10_FRAME_CONTROL:
            proto_tree_add_item(amqp_tree, hf_amqp_0_10_class, tvb, offset+0, 1, ENC_BIG_ENDIAN);
            switch(tvb_get_guint8(tvb, offset + 0)) {
            case AMQP_0_10_CLASS_CONNECTION:
                dissect_amqp_0_10_connection(tvb, pinfo, amqp_tree,
                                             offset, length);
                break;
            case AMQP_0_10_CLASS_SESSION:
                dissect_amqp_0_10_session(tvb, pinfo, amqp_tree,
                                          offset, length);
                break;
            case AMQP_0_10_CLASS_EXECUTION:
                dissect_amqp_0_10_execution(tvb, pinfo, amqp_tree,
                                            offset, length);
                break;
            case AMQP_0_10_CLASS_MESSAGE:
                dissect_amqp_0_10_message(tvb, pinfo, amqp_tree,
                                          offset, length);
                break;
            case AMQP_0_10_CLASS_TX:
                dissect_amqp_0_10_tx(tvb, pinfo, amqp_tree,
                                     offset, length);
                break;
            case AMQP_0_10_CLASS_DTX:
                dissect_amqp_0_10_dtx(tvb, pinfo, amqp_tree,
                                      offset, length);
                break;
            case AMQP_0_10_CLASS_EXCHANGE:
                dissect_amqp_0_10_exchange(tvb, pinfo, amqp_tree,
                                           offset, length);
                break;
            case AMQP_0_10_CLASS_QUEUE:
                dissect_amqp_0_10_queue(tvb, pinfo, amqp_tree,
                                        offset, length);
                break;
            case AMQP_0_10_CLASS_FILE:
                dissect_amqp_0_10_file(tvb, pinfo, amqp_tree,
                                       offset, length);
                break;
            case AMQP_0_10_CLASS_STREAM:
                dissect_amqp_0_10_stream(tvb, pinfo, amqp_tree,
                                         offset, length);
                break;
            default:
              expert_add_info_format(pinfo, amqp_tree, PI_PROTOCOL, PI_ERROR,
                                     "Unknown command/control class %d",
                                     tvb_get_guint8(tvb, offset + 0));
            }
            break;

        case AMQP_0_10_FRAME_HEADER:
            col_append_str(pinfo->cinfo, COL_INFO, "header ");
            col_set_fence(pinfo->cinfo, COL_INFO);
            do {
                struct_length = tvb_get_ntohl(tvb, offset);
                AMQP_INCREMENT(offset, 4, length);
                THROW_ON((offset + struct_length > length), ReportedBoundsError);

                ti = proto_tree_add_item(amqp_tree,
                                         hf_amqp_0_10_undissected_struct32,
                                         tvb, offset, struct_length, ENC_NA);
                dissect_amqp_0_10_struct32(tvb, ti, offset, struct_length);
                AMQP_INCREMENT(offset, struct_length, length);
            } while (offset < length);
            break;

        case AMQP_0_10_FRAME_BODY:
            col_append_str(pinfo->cinfo, COL_INFO, "message-body ");
            col_set_fence(pinfo->cinfo, COL_INFO);
            proto_tree_add_item(amqp_tree,
                                hf_amqp_0_10_message_body,
                                tvb, offset, length - 12, ENC_NA);
            break;

        default:
            expert_add_info_format(pinfo, amqp_tree, PI_PROTOCOL, PI_ERROR,
                                   "Unknown frame type %d", frame_type);
        }
    }
}

/*  Dissection routine for AMQP 0-9 frames  */

static void
dissect_amqp_0_9_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_item *amqp_tree;
    proto_item *args_tree;
    proto_item *prop_tree;
    guint8 proto_major;
    guint8 proto_minor;
    guint length;
    emem_strbuf_t *strbuf;
    guint8 frame_type;
    guint16 class_id, method_id;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMQP");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        /*  Heuristic - protocol initialisation frame starts with 'AMQP'  */
        if (tvb_get_guint8(tvb, 0) == 'A' &&
              tvb_get_guint8(tvb, 1) == 'M' &&
              tvb_get_guint8(tvb, 2) == 'Q' &&
              tvb_get_guint8(tvb, 3) == 'P') {

            proto_major = tvb_get_guint8(tvb, 6);
            proto_minor = tvb_get_guint8(tvb, 7);
            strbuf = ep_strbuf_new_label("");
            ep_strbuf_append_printf(strbuf,
                                    "Protocol-Header %u-%u",
                                    proto_major,
                                    proto_minor);
            col_append_str(pinfo->cinfo, COL_INFO, strbuf->str);
            col_set_fence(pinfo->cinfo, COL_INFO);

            ti = proto_tree_add_item(tree, proto_amqp, tvb, 0, -1, ENC_NA);
            amqp_tree = proto_item_add_subtree(ti, ett_amqp_init);
            proto_tree_add_item(amqp_tree, hf_amqp_init_protocol, tvb, 0, 4, ENC_ASCII|ENC_NA);
            proto_tree_add_item(amqp_tree, hf_amqp_init_id_major, tvb, 4, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_init_id_minor, tvb, 5, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_init_version_major, tvb, 6, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_init_version_minor, tvb, 7, 1, ENC_BIG_ENDIAN);

            return;
        }

        ti = proto_tree_add_item(tree, proto_amqp, tvb, 0, -1, ENC_NA);
        amqp_tree = proto_item_add_subtree(ti, ett_amqp);
        frame_type = tvb_get_guint8(tvb, 0);
        proto_tree_add_item(amqp_tree, hf_amqp_0_9_type, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(amqp_tree, hf_amqp_channel, tvb, 1, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(amqp_tree, hf_amqp_0_9_length, tvb, 3, 4, ENC_BIG_ENDIAN);
        length = tvb_get_ntohl(tvb, 3);
        switch (frame_type) {
        case AMQP_0_9_FRAME_TYPE_METHOD:
            class_id = tvb_get_ntohs(tvb, 7);
            proto_tree_add_item(amqp_tree, hf_amqp_0_9_method_class_id,
                tvb, 7, 2, ENC_BIG_ENDIAN);
            switch (class_id) {
            case AMQP_0_9_CLASS_CONNECTION:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_connection_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);
				col_append_fstr(pinfo->cinfo, COL_INFO, "Connection.%s",
					val_to_str( method_id, amqp_method_connection_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);
                switch (method_id) {
                case AMQP_0_9_METHOD_CONNECTION_START:
                    dissect_amqp_0_9_method_connection_start(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_START_OK:
                    dissect_amqp_0_9_method_connection_start_ok(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_SECURE:
                    dissect_amqp_0_9_method_connection_secure(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_SECURE_OK:
                    dissect_amqp_0_9_method_connection_secure_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_TUNE:
                    dissect_amqp_0_9_method_connection_tune(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_TUNE_OK:
                    dissect_amqp_0_9_method_connection_tune_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_OPEN:
                    dissect_amqp_0_9_method_connection_open(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_OPEN_OK:
                    dissect_amqp_0_9_method_connection_open_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_REDIRECT:
                    dissect_amqp_0_9_method_connection_redirect(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_CLOSE:
                    dissect_amqp_0_9_method_connection_close(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CONNECTION_CLOSE_OK:
                    dissect_amqp_0_9_method_connection_close_ok(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown connection method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_CHANNEL:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_channel_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);

				col_append_fstr(pinfo->cinfo, COL_INFO, "Channel.%s",
					val_to_str( method_id, amqp_method_channel_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);

				switch (method_id) {
                case AMQP_0_9_METHOD_CHANNEL_OPEN:
                    dissect_amqp_0_9_method_channel_open(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_OPEN_OK:
                    dissect_amqp_0_9_method_channel_open_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_FLOW:
                    dissect_amqp_0_9_method_channel_flow(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_FLOW_OK:
                    dissect_amqp_0_9_method_channel_flow_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_CLOSE:
                    dissect_amqp_0_9_method_channel_close(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_CLOSE_OK:
                    dissect_amqp_0_9_method_channel_close_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_RESUME:
                    dissect_amqp_0_9_method_channel_resume(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_PING:
                    dissect_amqp_0_9_method_channel_ping(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_PONG:
                    dissect_amqp_0_9_method_channel_pong(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_CHANNEL_OK:
                    dissect_amqp_0_9_method_channel_ok(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown channel method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_ACCESS:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_access_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);
                switch (method_id) {
                case AMQP_0_9_METHOD_ACCESS_REQUEST:
                    dissect_amqp_0_9_method_access_request(tvb,
                        11, args_tree);
                    col_append_str(pinfo->cinfo, COL_INFO,
                        "Access.Request ");
                    col_set_fence(pinfo->cinfo, COL_INFO);
                    break;
                case AMQP_0_9_METHOD_ACCESS_REQUEST_OK:
                    dissect_amqp_0_9_method_access_request_ok(tvb,
                        11, args_tree);
                    col_append_str(pinfo->cinfo, COL_INFO,
                        "Access.Request-Ok ");
                    col_set_fence(pinfo->cinfo, COL_INFO);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown access method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_EXCHANGE:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_exchange_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);
				col_append_fstr(pinfo->cinfo, COL_INFO, "Exchange.%s",
					val_to_str( method_id, amqp_method_exchange_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);
                switch (method_id) {
                case AMQP_0_9_METHOD_EXCHANGE_DECLARE:
                    dissect_amqp_0_9_method_exchange_declare(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_EXCHANGE_DECLARE_OK:
                    dissect_amqp_0_9_method_exchange_declare_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_EXCHANGE_BIND:
                    dissect_amqp_0_9_method_exchange_bind(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_EXCHANGE_BIND_OK:
                    dissect_amqp_0_9_method_exchange_bind_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_EXCHANGE_DELETE:
                    dissect_amqp_0_9_method_exchange_delete(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_EXCHANGE_DELETE_OK:
                    dissect_amqp_0_9_method_exchange_delete_ok(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown exchange method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_QUEUE:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_queue_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);
				col_append_fstr(pinfo->cinfo, COL_INFO, "Queue.%s",
					val_to_str( method_id, amqp_method_queue_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);

                switch (method_id) {
                case AMQP_0_9_METHOD_QUEUE_DECLARE:
                    dissect_amqp_0_9_method_queue_declare(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_DECLARE_OK:
                    dissect_amqp_0_9_method_queue_declare_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_BIND:
                    dissect_amqp_0_9_method_queue_bind(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_BIND_OK:
                    dissect_amqp_0_9_method_queue_bind_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_UNBIND:
                    dissect_amqp_0_9_method_queue_unbind(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_UNBIND_OK:
                    dissect_amqp_0_9_method_queue_unbind_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_PURGE:
                    dissect_amqp_0_9_method_queue_purge(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_PURGE_OK:
                    dissect_amqp_0_9_method_queue_purge_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_DELETE:
                    dissect_amqp_0_9_method_queue_delete(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_QUEUE_DELETE_OK:
                    dissect_amqp_0_9_method_queue_delete_ok(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown queue method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_BASIC:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_basic_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);

				col_append_fstr(pinfo->cinfo, COL_INFO, "Basic.%s",
					val_to_str( method_id, amqp_method_basic_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);

				switch (method_id) {
                case AMQP_0_9_METHOD_BASIC_QOS:
                    dissect_amqp_0_9_method_basic_qos(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_QOS_OK:
                    dissect_amqp_0_9_method_basic_qos_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_CONSUME:
                    dissect_amqp_0_9_method_basic_consume(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_CONSUME_OK:
                    dissect_amqp_0_9_method_basic_consume_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_CANCEL:
                    dissect_amqp_0_9_method_basic_cancel(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_CANCEL_OK:
                    dissect_amqp_0_9_method_basic_cancel_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_PUBLISH:
                    dissect_amqp_0_9_method_basic_publish(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_RETURN:
                    dissect_amqp_0_9_method_basic_return(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_DELIVER:
                    dissect_amqp_0_9_method_basic_deliver(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_GET:
                    dissect_amqp_0_9_method_basic_get(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_GET_OK:
                    dissect_amqp_0_9_method_basic_get_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_GET_EMPTY:
                    dissect_amqp_0_9_method_basic_get_empty(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_ACK:
                    dissect_amqp_0_9_method_basic_ack(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_REJECT:
                    dissect_amqp_0_9_method_basic_reject(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_BASIC_RECOVER:
                    dissect_amqp_0_9_method_basic_recover(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown basic method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_FILE:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_file_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);

				col_append_fstr(pinfo->cinfo, COL_INFO, "File.%s",
					val_to_str( method_id, amqp_method_file_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);

                switch (method_id) {
                case AMQP_0_9_METHOD_FILE_QOS:
                    dissect_amqp_0_9_method_file_qos(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_QOS_OK:
                    dissect_amqp_0_9_method_file_qos_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_CONSUME:
                    dissect_amqp_0_9_method_file_consume(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_CONSUME_OK:
                    dissect_amqp_0_9_method_file_consume_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_CANCEL:
                    dissect_amqp_0_9_method_file_cancel(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_CANCEL_OK:
                    dissect_amqp_0_9_method_file_cancel_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_OPEN:
                    dissect_amqp_0_9_method_file_open(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_OPEN_OK:
                    dissect_amqp_0_9_method_file_open_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_STAGE:
                    dissect_amqp_0_9_method_file_stage(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_PUBLISH:
                    dissect_amqp_0_9_method_file_publish(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_RETURN:
                    dissect_amqp_0_9_method_file_return(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_DELIVER:
                    dissect_amqp_0_9_method_file_deliver(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_ACK:
                    dissect_amqp_0_9_method_file_ack(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_FILE_REJECT:
                    dissect_amqp_0_9_method_file_reject(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown file method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_STREAM:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_stream_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);

				col_append_fstr(pinfo->cinfo, COL_INFO, "Stream.%s",
					val_to_str( method_id, amqp_method_stream_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);

                switch (method_id) {
                case AMQP_0_9_METHOD_STREAM_QOS:
                    dissect_amqp_0_9_method_stream_qos(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_STREAM_QOS_OK:
                    dissect_amqp_0_9_method_stream_qos_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_STREAM_CONSUME:
                    dissect_amqp_0_9_method_stream_consume(tvb,
                        pinfo, 11, args_tree);
                    break;
                case AMQP_0_9_METHOD_STREAM_CONSUME_OK:
                    dissect_amqp_0_9_method_stream_consume_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_STREAM_CANCEL:
                    dissect_amqp_0_9_method_stream_cancel(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_STREAM_CANCEL_OK:
                    dissect_amqp_0_9_method_stream_cancel_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_STREAM_PUBLISH:
                    dissect_amqp_0_9_method_stream_publish(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_STREAM_RETURN:
                    dissect_amqp_0_9_method_stream_return(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_STREAM_DELIVER:
                    dissect_amqp_0_9_method_stream_deliver(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown stream method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_TX:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_tx_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);

				col_append_fstr(pinfo->cinfo, COL_INFO, "Tx.%s",
					val_to_str( method_id, amqp_method_tx_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);

                switch (method_id) {
                case AMQP_0_9_METHOD_TX_SELECT:
                    dissect_amqp_0_9_method_tx_select(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_TX_SELECT_OK:
                    dissect_amqp_0_9_method_tx_select_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_TX_COMMIT:
                    dissect_amqp_0_9_method_tx_commit(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_TX_COMMIT_OK:
                    dissect_amqp_0_9_method_tx_commit_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_TX_ROLLBACK:
                    dissect_amqp_0_9_method_tx_rollback(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_TX_ROLLBACK_OK:
                    dissect_amqp_0_9_method_tx_rollback_ok(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown tx method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_DTX:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_dtx_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);

				col_append_fstr(pinfo->cinfo, COL_INFO, "Dtx.%s",
					val_to_str( method_id, amqp_method_dtx_methods, "Unknown (%u)"));
                col_set_fence(pinfo->cinfo, COL_INFO);

                switch (method_id) {
                case AMQP_0_9_METHOD_DTX_SELECT:
                    dissect_amqp_0_9_method_dtx_select(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_DTX_SELECT_OK:
                    dissect_amqp_0_9_method_dtx_select_ok(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_DTX_START:
                    dissect_amqp_0_9_method_dtx_start(tvb,
                        11, args_tree);
                    break;
                case AMQP_0_9_METHOD_DTX_START_OK:
                    dissect_amqp_0_9_method_dtx_start_ok(tvb,
                        11, args_tree);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown dtx method %u",
                                           method_id);
                }
                break;
            case AMQP_0_9_CLASS_TUNNEL:
                method_id = tvb_get_ntohs(tvb, 9);
                proto_tree_add_item(amqp_tree, hf_amqp_method_tunnel_method_id,
                    tvb, 9, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(amqp_tree, hf_amqp_method_arguments,
                    tvb, 11, length - 4, ENC_NA);
                args_tree = proto_item_add_subtree(ti, ett_args);
                switch (method_id) {
                case AMQP_0_9_METHOD_TUNNEL_REQUEST:
                    dissect_amqp_0_9_method_tunnel_request(tvb,
                        pinfo, 11, args_tree);
                    col_append_str(pinfo->cinfo, COL_INFO,
                        "Tunnel.Request ");
                    col_set_fence(pinfo->cinfo, COL_INFO);
                    break;
                default:
                    expert_add_info_format(pinfo, amqp_tree,
                                           PI_PROTOCOL, PI_ERROR,
                                           "Unknown tunnel method %u",
                                           method_id);
                }
                break;
            default:
                expert_add_info_format(pinfo, amqp_tree,
                                       PI_PROTOCOL, PI_ERROR,
                                       "Unknown method class %u",
                                       class_id);
            }
            break;
        case AMQP_0_9_FRAME_TYPE_CONTENT_HEADER:
            class_id = tvb_get_ntohs(tvb, 7);
            proto_tree_add_item(amqp_tree, hf_amqp_header_class_id,
                tvb, 7, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_header_weight,
                tvb, 9, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_header_body_size,
                tvb, 11, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(amqp_tree, hf_amqp_header_property_flags,
                tvb, 19, 2, ENC_BIG_ENDIAN);
            ti = proto_tree_add_item(amqp_tree, hf_amqp_header_properties,
                tvb, 21, length - 14, ENC_NA);
            prop_tree = proto_item_add_subtree(ti, ett_props);
            switch (class_id) {
            case AMQP_0_9_CLASS_BASIC:
                dissect_amqp_0_9_content_header_basic(tvb,
                    pinfo, 21, prop_tree);
                break;
            case AMQP_0_9_CLASS_FILE:
                dissect_amqp_0_9_content_header_file(tvb,
                    pinfo, 21, prop_tree);
                break;
            case AMQP_0_9_CLASS_STREAM:
                dissect_amqp_0_9_content_header_stream(tvb,
                    pinfo, 21, prop_tree);
                break;
            case AMQP_0_9_CLASS_TUNNEL:
                dissect_amqp_0_9_content_header_tunnel(tvb,
                    pinfo, 21, prop_tree);
                break;
            default:
                expert_add_info_format(pinfo, amqp_tree,
                                       PI_PROTOCOL, PI_ERROR,
                                       "Unknown header class %u",
                                       class_id);
            }
            col_append_str(pinfo->cinfo, COL_INFO, "Content-Header ");
            col_set_fence(pinfo->cinfo, COL_INFO);
            break;
        case AMQP_0_9_FRAME_TYPE_CONTENT_BODY:
            proto_tree_add_item(amqp_tree, hf_amqp_payload,
                tvb, 7, length, ENC_NA);
            col_append_str(pinfo->cinfo, COL_INFO, "Content-Body ");
            col_set_fence(pinfo->cinfo, COL_INFO);
            break;
        default:
            expert_add_info_format(pinfo, amqp_tree,
                                   PI_PROTOCOL, PI_ERROR,
                                   "Unknown frame type %u",
                                   frame_type);
        }
    }
}

/*  Dissection routine for method Connection.Start                        */

static int
dissect_amqp_0_9_method_connection_start(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  version-major (octet)    */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_start_version_major,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*  version-minor (octet)    */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_start_version_minor,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*  server-properties (table)  */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_connection_start_server_properties,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    /*  mechanisms (longstr)     */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_start_mechanisms,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    /*  locales (longstr)        */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_start_locales,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Connection.Start-Ok                     */

static int
dissect_amqp_0_9_method_connection_start_ok(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  client-properties (table)  */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_connection_start_ok_client_properties,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    /*  mechanism (shortstr)     */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_start_ok_mechanism,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  response (longstr)       */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_start_ok_response,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    /*  locale (shortstr)        */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_start_ok_locale,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Connection.Secure                       */

static int
dissect_amqp_0_9_method_connection_secure(tvbuff_t *tvb,
    int offset, proto_tree *args_tree)
{
    /*  challenge (longstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_secure_challenge,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Connection.Secure-Ok                    */

static int
dissect_amqp_0_9_method_connection_secure_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree)
{
    /*  response (longstr)       */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_secure_ok_response,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Connection.Tune                         */

static int
dissect_amqp_0_9_method_connection_tune(tvbuff_t *tvb,
    int offset, proto_tree *args_tree)
{
    /*  channel-max (short)      */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_tune_channel_max,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  frame-max (long)         */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_tune_frame_max,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*  heartbeat (short)        */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_tune_heartbeat,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*  Dissection routine for method Connection.Tune-Ok                      */

static int
dissect_amqp_0_9_method_connection_tune_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree)
{
    /*  channel-max (short)      */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_tune_ok_channel_max,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  frame-max (long)         */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_tune_ok_frame_max,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*  heartbeat (short)        */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_tune_ok_heartbeat,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*  Dissection routine for method Connection.Open                         */

static int
dissect_amqp_0_9_method_connection_open(tvbuff_t *tvb,
    int offset, proto_tree *args_tree)
{
    /*  virtual-host (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_open_virtual_host,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  capabilities (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_open_capabilities,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  insist (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_open_insist,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Connection.Open-Ok                      */

static int
dissect_amqp_0_9_method_connection_open_ok(tvbuff_t *tvb,
    int offset, proto_tree *args_tree)
{
    /*  known-hosts (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_open_ok_known_hosts,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Connection.Redirect                     */

static int
dissect_amqp_0_9_method_connection_redirect(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  host (shortstr)          */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_redirect_host,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  known-hosts (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_redirect_known_hosts,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Connection.Close                        */

static int
dissect_amqp_0_9_method_connection_close(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  reply-code (short)       */
    proto_tree_add_item(args_tree, hf_amqp_0_9_method_connection_close_reply_code,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  reply-text (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_close_reply_text,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  class-id (short)         */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_close_class_id,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  method-id (short)        */
    proto_tree_add_item(args_tree, hf_amqp_method_connection_close_method_id,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*  Dissection routine for method Connection.Close-Ok                     */

static int
dissect_amqp_0_9_method_connection_close_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Channel.Open                            */

static int
dissect_amqp_0_9_method_channel_open(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  out-of-band (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_open_out_of_band,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Channel.Open-Ok                         */

static int
dissect_amqp_0_9_method_channel_open_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  channel-id (longstr)     */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_open_ok_channel_id,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Channel.Flow                            */

static int
dissect_amqp_0_9_method_channel_flow(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  active (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_flow_active,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Channel.Flow-Ok                         */

static int
dissect_amqp_0_9_method_channel_flow_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  active (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_flow_ok_active,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Channel.Close                           */

static int
dissect_amqp_0_9_method_channel_close(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  reply-code (short)       */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_close_reply_code,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  reply-text (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_close_reply_text,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  class-id (short)         */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_close_class_id,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  method-id (short)        */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_close_method_id,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*  Dissection routine for method Channel.Close-Ok                        */

static int
dissect_amqp_0_9_method_channel_close_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Channel.Resume                          */

static int
dissect_amqp_0_9_method_channel_resume(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  channel-id (longstr)     */
    proto_tree_add_item(args_tree, hf_amqp_method_channel_resume_channel_id,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Channel.Ping                            */

static int
dissect_amqp_0_9_method_channel_ping(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Channel.Pong                            */

static int
dissect_amqp_0_9_method_channel_pong(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Channel.Ok                              */

static int
dissect_amqp_0_9_method_channel_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Access.Request                          */

static int
dissect_amqp_0_9_method_access_request(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  realm (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_access_request_realm,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  exclusive (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_access_request_exclusive,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  passive (bit)            */
    proto_tree_add_item(args_tree, hf_amqp_method_access_request_passive,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  active (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_access_request_active,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  write (bit)              */
    proto_tree_add_item(args_tree, hf_amqp_method_access_request_write,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  read (bit)               */
    proto_tree_add_item(args_tree, hf_amqp_method_access_request_read,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Access.Request-Ok                       */

static int
dissect_amqp_0_9_method_access_request_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_access_request_ok_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

/*  Dissection routine for method Exchange.Declare                        */

static int
dissect_amqp_0_9_method_exchange_declare(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  type (shortstr)          */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_type,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  passive (bit)            */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_passive,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  durable (bit)            */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_durable,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  auto-delete (bit)        */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_auto_delete,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  internal (bit)           */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_internal,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  arguments (table)        */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_exchange_declare_arguments,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Exchange.Declare-Ok                     */

static int
dissect_amqp_0_9_method_exchange_declare_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Exchange.Bind                           */

static int
dissect_amqp_0_9_method_exchange_bind(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_declare_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  destination (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_bind_destination,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  source (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_bind_source,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_bind_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_bind_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /*  arguments (table)        */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_exchange_bind_arguments,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Exchange.Bind-Ok                        */

static int
dissect_amqp_0_9_method_exchange_bind_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Exchange.Delete                         */

static int
dissect_amqp_0_9_method_exchange_delete(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_delete_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_delete_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  if-unused (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_delete_if_unused,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_exchange_delete_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Exchange.Delete-Ok                      */

static int
dissect_amqp_0_9_method_exchange_delete_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Queue.Declare                           */

static int
dissect_amqp_0_9_method_queue_declare(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  passive (bit)            */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_passive,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  durable (bit)            */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_durable,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  exclusive (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_exclusive,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  auto-delete (bit)        */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_auto_delete,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  arguments (table)        */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_queue_declare_arguments,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Queue.Declare-Ok                        */

static int
dissect_amqp_0_9_method_queue_declare_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_ok_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  message-count (long)     */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_ok_message_count,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*  consumer-count (long)    */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_declare_ok_consumer_count,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*  Dissection routine for method Queue.Bind                              */

static int
dissect_amqp_0_9_method_queue_bind(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_bind_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_bind_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_bind_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_bind_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_bind_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  arguments (table)        */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_queue_bind_arguments,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Queue.Bind-Ok                           */

static int
dissect_amqp_0_9_method_queue_bind_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Queue.Unbind                            */

static int
dissect_amqp_0_9_method_queue_unbind(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_unbind_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_unbind_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_unbind_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_unbind_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  arguments (table)        */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_queue_unbind_arguments,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Queue.Unbind-Ok                         */

static int
dissect_amqp_0_9_method_queue_unbind_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Queue.Purge                             */

static int
dissect_amqp_0_9_method_queue_purge(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_purge_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_purge_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_purge_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Queue.Purge-Ok                          */

static int
dissect_amqp_0_9_method_queue_purge_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  message-count (long)     */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_purge_ok_message_count,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*  Dissection routine for method Queue.Delete                            */

static int
dissect_amqp_0_9_method_queue_delete(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_delete_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_delete_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  if-unused (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_delete_if_unused,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  if-empty (bit)           */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_delete_if_empty,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_delete_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Queue.Delete-Ok                         */

static int
dissect_amqp_0_9_method_queue_delete_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  message-count (long)     */
    proto_tree_add_item(args_tree, hf_amqp_method_queue_delete_ok_message_count,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*  Dissection routine for method Basic.Qos                               */

static int
dissect_amqp_0_9_method_basic_qos(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  prefetch-size (long)     */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_qos_prefetch_size,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*  prefetch-count (short)   */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_qos_prefetch_count,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  global (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_qos_global,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Basic.Qos-Ok                            */

static int
dissect_amqp_0_9_method_basic_qos_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Basic.Consume                           */

static int
dissect_amqp_0_9_method_basic_consume(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_consume_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_consume_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_consume_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  no-local (bit)           */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_consume_no_local,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  no-ack (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_consume_no_ack,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  exclusive (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_consume_exclusive,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_consume_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  filter (table)           */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_basic_consume_filter,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Basic.Consume-Ok                        */

static int
dissect_amqp_0_9_method_basic_consume_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_consume_ok_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Basic.Cancel                            */

static int
dissect_amqp_0_9_method_basic_cancel(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_cancel_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_cancel_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Basic.Cancel-Ok                         */

static int
dissect_amqp_0_9_method_basic_cancel_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_cancel_ok_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Basic.Publish                           */

static int
dissect_amqp_0_9_method_basic_publish(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_publish_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_publish_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_publish_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  mandatory (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_publish_mandatory,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  immediate (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_publish_immediate,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Basic.Return                            */

static int
dissect_amqp_0_9_method_basic_return(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  reply-code (short)       */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_return_reply_code,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  reply-text (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_return_reply_text,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_return_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_return_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Basic.Deliver                           */

static int
dissect_amqp_0_9_method_basic_deliver(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_deliver_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  delivery-tag (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_deliver_delivery_tag,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /*  redelivered (bit)        */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_deliver_redelivered,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_deliver_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_deliver_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Basic.Get                               */

static int
dissect_amqp_0_9_method_basic_get(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  no-ack (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_no_ack,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Basic.Get-Ok                            */

static int
dissect_amqp_0_9_method_basic_get_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  delivery-tag (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_ok_delivery_tag,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /*  redelivered (bit)        */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_ok_redelivered,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_ok_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_ok_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  message-count (long)     */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_ok_message_count,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

/*  Dissection routine for method Basic.Get-Empty                         */

static int
dissect_amqp_0_9_method_basic_get_empty(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  cluster-id (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_get_empty_cluster_id,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Basic.Ack                               */

static int
dissect_amqp_0_9_method_basic_ack(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  delivery-tag (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_ack_delivery_tag,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /*  multiple (bit)           */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_ack_multiple,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Basic.Reject                            */

static int
dissect_amqp_0_9_method_basic_reject(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  delivery-tag (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_reject_delivery_tag,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /*  requeue (bit)            */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_reject_requeue,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Basic.Recover                           */

static int
dissect_amqp_0_9_method_basic_recover(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  requeue (bit)            */
    proto_tree_add_item(args_tree, hf_amqp_method_basic_recover_requeue,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method File.Qos                                */

static int
dissect_amqp_0_9_method_file_qos(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  prefetch-size (long)     */
    proto_tree_add_item(args_tree, hf_amqp_method_file_qos_prefetch_size,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*  prefetch-count (short)   */
    proto_tree_add_item(args_tree, hf_amqp_method_file_qos_prefetch_count,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  global (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_file_qos_global,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method File.Qos-Ok                             */

static int
dissect_amqp_0_9_method_file_qos_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method File.Consume                            */

static int
dissect_amqp_0_9_method_file_consume(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_file_consume_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_file_consume_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_consume_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  no-local (bit)           */
    proto_tree_add_item(args_tree, hf_amqp_method_file_consume_no_local,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  no-ack (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_file_consume_no_ack,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  exclusive (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_file_consume_exclusive,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_file_consume_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  filter (table)           */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_file_consume_filter,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method File.Consume-Ok                         */

static int
dissect_amqp_0_9_method_file_consume_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_consume_ok_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method File.Cancel                             */

static int
dissect_amqp_0_9_method_file_cancel(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_cancel_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_file_cancel_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method File.Cancel-Ok                          */

static int
dissect_amqp_0_9_method_file_cancel_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_cancel_ok_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method File.Open                               */

static int
dissect_amqp_0_9_method_file_open(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  identifier (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_file_open_identifier,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  content-size (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_open_content_size,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/*  Dissection routine for method File.Open-Ok                            */

static int
dissect_amqp_0_9_method_file_open_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  staged-size (longlong)   */
    proto_tree_add_item(args_tree, hf_amqp_method_file_open_ok_staged_size,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

/*  Dissection routine for method File.Stage                              */

static int
dissect_amqp_0_9_method_file_stage(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method File.Publish                            */

static int
dissect_amqp_0_9_method_file_publish(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_file_publish_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_file_publish_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_file_publish_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  mandatory (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_file_publish_mandatory,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  immediate (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_file_publish_immediate,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  identifier (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_file_publish_identifier,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method File.Return                             */

static int
dissect_amqp_0_9_method_file_return(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  reply-code (short)       */
    proto_tree_add_item(args_tree, hf_amqp_method_file_return_reply_code,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  reply-text (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_file_return_reply_text,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_file_return_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_file_return_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method File.Deliver                            */

static int
dissect_amqp_0_9_method_file_deliver(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_deliver_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  delivery-tag (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_deliver_delivery_tag,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /*  redelivered (bit)        */
    proto_tree_add_item(args_tree, hf_amqp_method_file_deliver_redelivered,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_file_deliver_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_file_deliver_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  identifier (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_file_deliver_identifier,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method File.Ack                                */

static int
dissect_amqp_0_9_method_file_ack(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  delivery-tag (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_ack_delivery_tag,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /*  multiple (bit)           */
    proto_tree_add_item(args_tree, hf_amqp_method_file_ack_multiple,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method File.Reject                             */

static int
dissect_amqp_0_9_method_file_reject(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  delivery-tag (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_file_reject_delivery_tag,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /*  requeue (bit)            */
    proto_tree_add_item(args_tree, hf_amqp_method_file_reject_requeue,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Stream.Qos                              */

static int
dissect_amqp_0_9_method_stream_qos(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  prefetch-size (long)     */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_qos_prefetch_size,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*  prefetch-count (short)   */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_qos_prefetch_count,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  consume-rate (long)      */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_qos_consume_rate,
        tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /*  global (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_qos_global,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Stream.Qos-Ok                           */

static int
dissect_amqp_0_9_method_stream_qos_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Stream.Consume                          */

static int
dissect_amqp_0_9_method_stream_consume(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_consume_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_consume_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_consume_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  no-local (bit)           */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_consume_no_local,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  exclusive (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_consume_exclusive,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_consume_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;
    /*  filter (table)           */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_stream_consume_filter,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}

/*  Dissection routine for method Stream.Consume-Ok                       */

static int
dissect_amqp_0_9_method_stream_consume_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_consume_ok_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Stream.Cancel                           */

static int
dissect_amqp_0_9_method_stream_cancel(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_cancel_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  nowait (bit)             */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_cancel_nowait,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Stream.Cancel-Ok                        */

static int
dissect_amqp_0_9_method_stream_cancel_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_cancel_ok_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Stream.Publish                          */

static int
dissect_amqp_0_9_method_stream_publish(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  ticket (short)           */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_publish_ticket,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_publish_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_publish_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  mandatory (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_publish_mandatory,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    /*  immediate (bit)          */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_publish_immediate,
        tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset;
}

/*  Dissection routine for method Stream.Return                           */

static int
dissect_amqp_0_9_method_stream_return(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  reply-code (short)       */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_return_reply_code,
        tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*  reply-text (shortstr)    */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_return_reply_text,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_return_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  routing-key (shortstr)   */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_return_routing_key,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Stream.Deliver                          */

static int
dissect_amqp_0_9_method_stream_deliver(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  consumer-tag (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_deliver_consumer_tag,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  delivery-tag (longlong)  */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_deliver_delivery_tag,
        tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /*  exchange (shortstr)      */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_deliver_exchange,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    /*  queue (shortstr)         */
    proto_tree_add_item(args_tree, hf_amqp_method_stream_deliver_queue,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Tx.Select                               */

static int
dissect_amqp_0_9_method_tx_select(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Tx.Select-Ok                            */

static int
dissect_amqp_0_9_method_tx_select_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Tx.Commit                               */

static int
dissect_amqp_0_9_method_tx_commit(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Tx.Commit-Ok                            */

static int
dissect_amqp_0_9_method_tx_commit_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Tx.Rollback                             */

static int
dissect_amqp_0_9_method_tx_rollback(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Tx.Rollback-Ok                          */

static int
dissect_amqp_0_9_method_tx_rollback_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Dtx.Select                              */

static int
dissect_amqp_0_9_method_dtx_select(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Dtx.Select-Ok                           */

static int
dissect_amqp_0_9_method_dtx_select_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Dtx.Start                               */

static int
dissect_amqp_0_9_method_dtx_start(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    /*  dtx-identifier (shortstr)  */
    proto_tree_add_item(args_tree, hf_amqp_method_dtx_start_dtx_identifier,
        tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
    offset += 1 + tvb_get_guint8(tvb, offset);

    return offset;
}

/*  Dissection routine for method Dtx.Start-Ok                            */

static int
dissect_amqp_0_9_method_dtx_start_ok(tvbuff_t *tvb _U_,
    int offset _U_, proto_tree *args_tree _U_)
{
    return offset;
}

/*  Dissection routine for method Tunnel.Request                          */

static int
dissect_amqp_0_9_method_tunnel_request(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *args_tree)
{
    proto_item *ti;

    /*  meta-data (table)        */
    ti = proto_tree_add_item(
        args_tree, hf_amqp_method_tunnel_request_meta_data,
        tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
    dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
    offset += 4 + tvb_get_ntohl(tvb, offset);

    return offset;
}


/*  Dissection routine for content headers of class basic          */

static int
dissect_amqp_0_9_content_header_basic(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *prop_tree)
{
    proto_item *ti;
    guint16 prop_flags;

    prop_flags = tvb_get_ntohs(tvb, 19);

    if (prop_flags & 0x8000) {
        /*  content-type (shortstr)  */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_content_type,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  content-encoding (shortstr)  */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_content_encoding,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  headers (table)          */
        ti = proto_tree_add_item(
            prop_tree, hf_amqp_header_basic_headers,
            tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
        dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
        offset += 4 + tvb_get_ntohl(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  delivery-mode (octet)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_delivery_mode,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  priority (octet)         */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_priority,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  correlation-id (shortstr)  */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_correlation_id,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  reply-to (shortstr)      */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_reply_to,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  expiration (shortstr)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_expiration,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  message-id (shortstr)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_message_id,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  timestamp (timestamp)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_timestamp,
            tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  type (shortstr)          */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_type,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  user-id (shortstr)       */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_user_id,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  app-id (shortstr)        */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_app_id,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  cluster-id (shortstr)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_basic_cluster_id,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    /*prop_flags <<= 1;*/

    return offset;
}
/*  Dissection routine for content headers of class file           */

static int
dissect_amqp_0_9_content_header_file(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *prop_tree)
{
    proto_item *ti;
    guint16 prop_flags;

    prop_flags = tvb_get_ntohs(tvb, 19);

    if (prop_flags & 0x8000) {
        /*  content-type (shortstr)  */
        proto_tree_add_item(prop_tree, hf_amqp_header_file_content_type,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  content-encoding (shortstr)  */
        proto_tree_add_item(prop_tree, hf_amqp_header_file_content_encoding,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  headers (table)          */
        ti = proto_tree_add_item(prop_tree, hf_amqp_header_file_headers,
            tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
        dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
        offset += 4 + tvb_get_ntohl(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  priority (octet)         */
        proto_tree_add_item(prop_tree, hf_amqp_header_file_priority,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  reply-to (shortstr)      */
        proto_tree_add_item(prop_tree, hf_amqp_header_file_reply_to,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  message-id (shortstr)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_file_message_id,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  filename (shortstr)      */
        proto_tree_add_item(prop_tree, hf_amqp_header_file_filename,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  timestamp (timestamp)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_file_timestamp,
            tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  cluster-id (shortstr)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_file_cluster_id,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    /*prop_flags <<= 1;*/

    return offset;
}
/*  Dissection routine for content headers of class stream         */

static int
dissect_amqp_0_9_content_header_stream(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *prop_tree)
{
    proto_item *ti;
    guint16 prop_flags;

    prop_flags = tvb_get_ntohs(tvb, 19);

    if (prop_flags & 0x8000) {
        /*  content-type (shortstr)  */
        proto_tree_add_item(prop_tree, hf_amqp_header_stream_content_type,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  content-encoding (shortstr)  */
        proto_tree_add_item(prop_tree, hf_amqp_header_stream_content_encoding,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  headers (table)          */
        ti = proto_tree_add_item(prop_tree, hf_amqp_header_stream_headers,
            tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
        dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
        offset += 4 + tvb_get_ntohl(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  priority (octet)         */
        proto_tree_add_item(prop_tree, hf_amqp_header_stream_priority,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  timestamp (timestamp)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_stream_timestamp,
            tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    /*prop_flags <<= 1;*/

    return offset;
}
/*  Dissection routine for content headers of class tunnel         */

static int
dissect_amqp_0_9_content_header_tunnel(tvbuff_t *tvb, packet_info *pinfo,
    int offset, proto_tree *prop_tree)
{
    proto_item *ti;
    guint16 prop_flags;

    prop_flags = tvb_get_ntohs(tvb, 19);

    if (prop_flags & 0x8000) {
        /*  headers (table)          */
        ti = proto_tree_add_item(prop_tree, hf_amqp_header_tunnel_headers,
            tvb, offset + 4, tvb_get_ntohl(tvb, offset), ENC_NA);
        dissect_amqp_0_9_field_table(tvb, pinfo, offset + 4, tvb_get_ntohl(tvb, offset), ti);
        offset += 4 + tvb_get_ntohl(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  proxy-name (shortstr)    */
        proto_tree_add_item(prop_tree, hf_amqp_header_tunnel_proxy_name,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  data-name (shortstr)     */
        proto_tree_add_item(prop_tree, hf_amqp_header_tunnel_data_name,
            tvb, offset + 1, tvb_get_guint8(tvb, offset), ENC_ASCII|ENC_NA);
        offset += 1 + tvb_get_guint8(tvb, offset);
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  durable (octet)          */
        proto_tree_add_item(prop_tree, hf_amqp_header_tunnel_durable,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    prop_flags <<= 1;

    if (prop_flags & 0x8000) {
        /*  broadcast (octet)        */
        proto_tree_add_item(prop_tree, hf_amqp_header_tunnel_broadcast,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    /*prop_flags <<= 1;*/

    return offset;
}

/*  AMQP 0-10 Type Decoders  */

static gboolean
get_amqp_0_10_type_formatter(guint8 code,
                             const char **name,
                             type_formatter *formatter,
                             guint *length_size)
{
    int i;
    struct amqp_typeinfo *table;
    if (code & 0x80)
        table = amqp_0_10_var_types;
    else
        table = amqp_0_10_fixed_types;
    for (i = 0; table[i].typecode != 0xff; ++i) {
        if (table[i].typecode == code) {
            *name = ep_strdup(table[i].typename);
            *formatter = table[i].formatter;
            *length_size = table[i].known_size;
            return 1;
        }
    }
    return 0;
}

static int
format_amqp_0_10_bin(tvbuff_t *tvb,
                     guint offset, guint bound _U_, guint length,
                     const char **value)
{
    *value = tvb_bytes_to_str(tvb, offset, length);
    return length;
}

static int
format_amqp_0_10_int(tvbuff_t *tvb,
                     guint offset, guint bound _U_, guint length,
                     const char **value)
{
    int val;

    if (length == 1)
        val = (gint8)tvb_get_guint8(tvb, offset);
    else if (length == 2)
        val = (gint16)tvb_get_ntohs(tvb, offset);
    else if (length == 4)
        val = (gint32)tvb_get_ntohl(tvb, offset);
    else {
        *value = ep_strdup_printf("Invalid int length %d!", length);
        return length;
    }
    *value = ep_strdup_printf("%d", val);
    return length;
}

static int
format_amqp_0_10_uint(tvbuff_t *tvb,
                      guint offset, guint bound _U_, guint length,
                      const char **value)
{
    unsigned int val;

    if (length == 1)
        val = tvb_get_guint8(tvb, offset);
    else if (length == 2)
        val = tvb_get_ntohs(tvb, offset);
    else if (length == 4)
        val = tvb_get_ntohl(tvb, offset);
    else {
        *value = ep_strdup_printf("Invalid uint length %d!", length);
        return length;
    }
    *value = ep_strdup_printf("%u", val);
    return length;
}

static int
format_amqp_0_10_char(tvbuff_t *tvb,
                      guint offset, guint bound _U_, guint length _U_,
                      const char **value)
{
    *value = tvb_format_text(tvb, offset, 1);
    return 1;
}

static int
format_amqp_0_10_boolean(tvbuff_t *tvb,
                         guint offset, guint bound _U_, guint length _U_,
                         const char **value)
{
    guint8 val;

    val = tvb_get_guint8(tvb, offset);
    *value = ep_strdup(val ? "true" : "false");
    return 1;
}

static int
format_amqp_0_10_vbin(tvbuff_t *tvb,
                      guint offset, guint bound, guint length,
                      const char **value)
{
    guint bin_length;

    if (length == 1)
        bin_length = tvb_get_guint8(tvb, offset);
    else if (length == 2)
        bin_length = tvb_get_ntohs(tvb, offset);
    else if (length == 4)
        bin_length = tvb_get_ntohl(tvb, offset);
    else {
        *value = ep_strdup_printf("Invalid vbin length size %d!", length);
        return length;
    }
    AMQP_INCREMENT(offset, length, bound);
    *value = tvb_bytes_to_str(tvb, offset, bin_length);
    AMQP_INCREMENT(offset, bin_length, bound);
    return (bin_length + length);
}

static int
format_amqp_0_10_str(tvbuff_t *tvb,
                     guint offset, guint bound, guint length,
                     const char **value)
{
    guint string_length;

    if (length == 1)
        string_length = tvb_get_guint8(tvb, offset);
    else if (length == 2)
        string_length = tvb_get_ntohs(tvb, offset);
    else if (length == 4)
        string_length = tvb_get_ntohl(tvb, offset);
    else {
        *value = ep_strdup_printf("Invalid string length size %d!", length);
        return length;
    }
    AMQP_INCREMENT(offset, length, bound);
    *value = tvb_get_ephemeral_string(tvb, offset, string_length);
    AMQP_INCREMENT(offset, string_length, bound);
    return (string_length + length);
}

static void
format_amqp_0_10_sequence_set(tvbuff_t *tvb, guint offset, guint length,
                              proto_item *item)
{
    guint values;
    /* Must be 4-byte values */
    if ((length % 4) != 0) {
        proto_item_append_text(item, "Invalid sequence set length %u",
                               length);
    }

    values = length / 4;
    /* There must be pairs of values */
    if ((values % 2) != 0) {
        proto_item_append_text(item, "Invalid sequence set value count %u",
                               values);
    }
    proto_item_append_text(item, " [");
    while(values > 0) {
        proto_item_append_text(item, "(%u, %u)%s",
                               tvb_get_ntohl(tvb, offset),
                               tvb_get_ntohl(tvb, offset + 4),
                               values > 2 ? ", " : "");
        offset += 8;
        values -= 2;
    }
    proto_item_append_text(item, "]");
}

/*  Basic registration functions  */

void
proto_register_amqp(void)
{
    /*
     * Setup of field format array. A few of the 0-9 fields are reused
     * in 0-10, but there are many separate.
     */
    static hf_register_info hf[] = {
        {&hf_amqp_0_10_format, {
            "Format", "amqp.format",
            FT_UINT8, BASE_DEC, NULL, 0xc0,
            "Framing version", HFILL}},
        {&hf_amqp_0_10_position, {
            "Position", "amqp.frame-position",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_frame_position), 0x0f,
            "Framing position", HFILL}},
        {&hf_amqp_0_10_type, {
            "Type", "amqp.type",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_frame_types), 0x0,
            "Frame type", HFILL}},
        {&hf_amqp_0_10_size, {
            "Length", "amqp.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Length of the frame", HFILL}},
        {&hf_amqp_0_10_track, {
            "Track", "amqp.track-number",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_frame_tracks), 0x0,
            "Track number", HFILL}},
        {&hf_amqp_0_10_class, {
            "Class", "amqp.class",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_class), 0x0,
            "Class ID", HFILL}},
        {&hf_amqp_0_10_connection_method, {
            "Method", "amqp.connection.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_connection_methods), 0x0,
            "Connection Class Method", HFILL}},
        {&hf_amqp_0_10_session_method, {
            "Method", "amqp.session.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_session_methods), 0x0,
            "Session Class Method", HFILL}},
        {&hf_amqp_0_10_execution_method, {
            "Method", "amqp.execution.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_execution_methods), 0x0,
            "Execution Class Method", HFILL}},
        {&hf_amqp_0_10_message_method, {
            "Method", "amqp.message.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_message_methods), 0x0,
            "Message Class Method", HFILL}},
        {&hf_amqp_0_10_tx_method, {
            "Method", "amqp.tx.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_tx_methods), 0x0,
            "Tx Class Method", HFILL}},
        {&hf_amqp_0_10_dtx_method, {
            "Method", "amqp.dtx.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_dtx_methods), 0x0,
            "Dtx Class Method", HFILL}},
        {&hf_amqp_0_10_exchange_method, {
            "Method", "amqp.exchange.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_exchange_methods), 0x0,
            "Exchange Class Method", HFILL}},
        {&hf_amqp_0_10_queue_method, {
            "Method", "amqp.queue.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_queue_methods), 0x0,
            "Queue Class Method", HFILL}},
        {&hf_amqp_0_10_file_method, {
            "Method", "amqp.file.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_file_methods), 0x0,
            "File Class Method", HFILL}},
        {&hf_amqp_0_10_stream_method, {
            "Method", "amqp.stream.method",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_stream_methods), 0x0,
            "Stream Class Method", HFILL}},
        {&hf_amqp_0_10_message_body, {
            "Message body", "amqp.message-body",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Message body content", HFILL}},
        {&hf_amqp_0_10_dtx_xid, {
            "Xid", "amqp.dtx.xid",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Dtx transaction id", HFILL}},
        {&hf_amqp_0_10_dtx_xid_format, {
            "Format", "amqp.dtx.xid.format",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Implementation-specific xid format code", HFILL}},
        {&hf_amqp_0_10_dtx_xid_global_id, {
            "Global-id", "amqp.dtx.xid.global-id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Global transaction id", HFILL}},
        {&hf_amqp_0_10_dtx_xid_branch_id, {
            "Branch-id", "amqp.dtx.xid.branch-id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Transaction branch qualifier", HFILL}},
        {&hf_amqp_0_10_undissected_struct32, {
            "(undissected struct)", "amqp.undissected",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Message header struct not yet dissected", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_discard_unroutable, {
            "Discard-unroutable", "amqp.message.delivery-properties.discard-unroutable",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            "Discard message if unroutable", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_immediate, {
            "Immediate", "amqp.message.delivery-properties.immediate",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Consider unroutable if can't be routed immediately", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_redelivered, {
            "Redelivered", "amqp.message.delivery-properties.redelivered",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            "Message may have been previously delivered", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_priority, {
            "Delivery-priority", "amqp.message.delivery-properties.delivery-priority",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_struct_delivery_properties_priorities), 0x0,
            "Message delivery priority", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_mode, {
            "Delivery-mode", "amqp.message.delivery-properties.delivery-mode",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_struct_delivery_properties_modes), 0x0,
            "Message delivery persistence mode", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_ttl, {
            "TTL", "amqp.message.delivery-properties.ttl",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Message time-to-live in msec", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_timestamp, {
            "Timestamp", "amqp.message.delivery-properties.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "Time of arrival at broker", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_expiration, {
            "Expiration", "amqp.message.delivery-properties.expiration",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "Expiration time calculated by broker", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_exchange, {
            "Exchange", "amqp.message.delivery-properties.exchange",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Originating exchange", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_routing_key, {
            "Routing-key", "amqp.message.delivery-properties.routing-key",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Message routing key", HFILL}},
        {&hf_amqp_0_10_struct_delivery_properties_resume_ttl, {
            "Resume-ttl", "amqp.message.delivery-properties.resume-ttl",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "TTL to use when resuming", HFILL}},
        {&hf_amqp_0_10_struct_fragment_properties_first, {
            "First", "amqp.message.fragment-properties.first",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            "Fragment contains the start of the message", HFILL}},
        {&hf_amqp_0_10_struct_fragment_properties_last, {
            "Last", "amqp.message.fragment-properties.last",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
            "Fragment contains the end of the message", HFILL}},
        {&hf_amqp_0_10_struct_fragment_properties_size, {
            "Fragment-size", "amqp.message.fragment-properties.fragment-size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Size of the message fragment", HFILL}},
        {&hf_amqp_0_10_struct_message_properties, {
            "message.message-properties", "amqp.message.message-properties",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Message properties struct", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_content_len, {
            "Content-length", "amqp.message.message-properties.content-length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of associated message", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_message_id, {
            "Message-id", "amqp.message.message-properties.message-id",
            FT_GUID, BASE_NONE, NULL, 0x0,
            "Message Id", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_correlation, {
            "Correlation-id", "amqp.message.message-properties.correlation-id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Correlation id", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_reply_to, {
            "Reply-to", "amqp.message.message-properties.reply-to",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Address to reply to", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_content_type, {
            "Content-type", "amqp.message.message-properties.content-type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MIME content type", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_content_encoding, {
            "Content-encoding", "amqp.message.message-properties.content-encoding",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MIME content encoding method", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_user_id, {
            "User-id", "amqp.message.message-properties.user-id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Creating user id", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_app_id, {
            "App-id", "amqp.message.message-properties.app-id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Creating user id", HFILL}},
        {&hf_amqp_0_10_struct_message_properties_application_headers, {
            "Application-headers", "amqp.message.message-properties.application-headers",
            FT_NONE, BASE_NONE, NULL, 0,
            "Application-private headers", HFILL}},
        {&hf_amqp_0_10_struct_reply_to_exchange, {
            "Exchange", "amqp.message.message-properties.reply-to.exchange",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Exchange to reply to", HFILL}},
        {&hf_amqp_0_10_struct_reply_to_routing_key, {
            "Routing-key", "amqp.message.message-properties.reply-to.routing-key",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Routing key to reply with", HFILL}},
        {&hf_amqp_0_10_struct_acquired_transfers, {
            "Transfers", "amqp.message.acquired.transfers",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Command set", HFILL}},
        {&hf_amqp_0_10_struct_resume_result_offset, {
            "Offset", "amqp.message.resume-result.offset",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Amount of data already transferred", HFILL}},
        {&hf_amqp_0_10_struct_exchange_query_result_durable, {
            "Durable", "amqp.exchange.exchange-query-result.durable",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Exchange is durable", HFILL}},
        {&hf_amqp_0_10_struct_exchange_query_result_not_found, {
            "Not-found", "amqp.exchange.exchange-query-result.not-found",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
            "Exchange was not found", HFILL}},
        {&hf_amqp_0_10_struct_exchange_bound_result_exchange_not_found, {
            "Exchange-not-found", "amqp.exchange.exchange-bound-result.exchange-not-found",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x01,
            "Exchange was not found", HFILL}},
        {&hf_amqp_0_10_struct_exchange_bound_result_queue_not_found, {
            "Queue-not-found", "amqp.exchange.exchange-bound-result.queue-not-found",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
            "Queue was not found", HFILL}},
        {&hf_amqp_0_10_struct_exchange_bound_result_queue_not_matched, {
            "Queue-not-matched", "amqp.exchange.exchange-bound-result.queue-not-matched",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
            "No binding from exchange to queue", HFILL}},
        {&hf_amqp_0_10_struct_exchange_bound_result_key_not_matched, {
            "Key-not-matched", "amqp.exchange.exchange-bound-result.key-not-matched",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
            "No binding from exchange with binding-key", HFILL}},
        {&hf_amqp_0_10_struct_exchange_bound_result_args_not_matched, {
            "Args-not-matched", "amqp.exchange.exchange-bound-result.args-not-matched",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x10,
            "No binding from exchange with specified arguments", HFILL}},
        {&hf_amqp_0_10_struct_queue_query_result_durable, {
            "Durable", "amqp.queue.queue-query-result.durable",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            "Queue is durable", HFILL}},
        {&hf_amqp_0_10_struct_queue_query_result_exclusive, {
            "Exclusive", "amqp.queue.queue-query-result.exclusive",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            "Queue created exclusive-use", HFILL}},
        {&hf_amqp_0_10_struct_queue_query_result_auto_delete, {
            "Auto-delete", "amqp.queue.queue-query-result.auto-delete",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            "Queue created auto-delete", HFILL}},
        {&hf_amqp_0_10_struct_queue_query_result_message_count, {
            "Message-count", "amqp.queue.queue-query-result.message-countt",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of messages in the queue", HFILL}},
        {&hf_amqp_0_10_struct_queue_query_result_subscriber_count, {
            "Subscriber-count", "amqp.queue.queue-query-result.subscriber-count",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of subscribers for the queue", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_content_type, {
            "Content-type", "amqp.file.file-properties.content-type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MIME content type", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_content_encoding, {
            "Content-encoding", "amqp.file.file-properties.content-encoding",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MIME content encoding", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_headers, {
            "Headers", "amqp.file.file-properties.headers",
            FT_NONE, BASE_NONE, NULL, 0,
            "Message header fields", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_priority, {
            "Priority", "amqp.file.file-properties.priority",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Message priority, 0 to 9", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_reply_to, {
            "Reply-to", "amqp.file.file-properties.reply-to",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Destination to reply to", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_message_id, {
            "Message-id", "amqp.file.file-properties.message-id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Application message identifier", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_filename, {
            "Filename", "amqp.file.file-properties.filename",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Message filename", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_timestamp, {
            "Timestamp", "amqp.file.file-properties.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "Message timestamp", HFILL}},
        {&hf_amqp_0_10_struct_file_properties_cluster_id, {
            "Cluster-id", "amqp.file.file-properties.cluster-id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Intra-cluster routing identifier", HFILL}},
        {&hf_amqp_0_10_struct_stream_properties_content_type, {
            "Content-type", "amqp.stream.stream-properties.content-type",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MIME content type", HFILL}},
        {&hf_amqp_0_10_struct_stream_properties_content_encoding, {
            "Content-encoding", "amqp.stream.stream-properties.content-encoding",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "MIME content encoding", HFILL}},
        {&hf_amqp_0_10_struct_stream_properties_headers, {
            "Headers", "amqp.stream.stream-properties.headers",
            FT_NONE, BASE_NONE, NULL, 0,
            "Message header fields", HFILL}},
        {&hf_amqp_0_10_struct_stream_properties_priority, {
            "Priority", "amqp.stream.stream-properties.priority",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Message priority, 0 to 9", HFILL}},
        {&hf_amqp_0_10_struct_stream_properties_timestamp, {
            "Timestamp", "amqp.stream.stream-properties.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            "Message timestamp", HFILL}},
        {&hf_amqp_0_10_argument_packing_flags, {
            "Packing Flags", "amqp.struct.packing",
            FT_UINT16, BASE_HEX, NULL, 0xffff,
            "Argument Struct Packing Flags", HFILL}},
        {&hf_amqp_0_10_session_header_sync, {
            "Sync", "amqp.session.header.sync",
            FT_BOOLEAN, 8, TFS(&amqp_0_10_session_header_sync), 0x01,
            "Sync requested", HFILL}},
        {&hf_amqp_0_10_method_session_attach_name, {
            "Name", "amqp.session.attach.name",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Session name", HFILL}},
        {&hf_amqp_0_10_method_session_attach_force, {
            "Force", "amqp.session.attach.force",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Session forced", HFILL}},
        {&hf_amqp_0_10_method_session_detached_code, {
            "Code", "amqp.session.detached.code",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_method_session_detached_codes), 0x0,
            "Reason for detach", HFILL}},
        {&hf_amqp_0_10_method_session_timeout, {
            "Timeout", "amqp.session.timeout",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Session timeout (seconds)", HFILL}},
        {&hf_amqp_0_10_method_session_completed_timely, {
            "Timely-reply", "amqp.session.completed.timely-reply",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Timely reply requested", HFILL}},
        {&hf_amqp_0_10_method_session_flush_expected, {
            "Expected", "amqp.session.flush.expected",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01,
            "Request notification of expected commands", HFILL}},
        {&hf_amqp_0_10_method_session_flush_confirmed, {
            "Confirmed", "amqp.session.flush.confirmed",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02,
            "Request notification of confirmed commands", HFILL}},
        {&hf_amqp_0_10_method_session_flush_completed, {
            "Completed", "amqp.session.flush.completed",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04,
            "Request notification of completed commands", HFILL}},
        {&hf_amqp_0_10_method_session_command_point_id, {
            "Command-id", "amqp.session.command_point.command_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Next command's sequence number", HFILL}},
        {&hf_amqp_0_10_method_session_command_point_offset, {
            "Command-offset", "amqp.session.command_point.command_offset",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Byte offset within command", HFILL}},
        {&hf_amqp_0_10_method_session_commands, {
            "Commands", "amqp.session.expected.commands",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Command set", HFILL}},
        {&hf_amqp_0_10_method_session_fragments, {
            "Fragments", "amqp.session.expected.fragments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Command Fragments", HFILL}},
        {&hf_amqp_0_10_method_execution_command_id, {
            "Command-id", "amqp.execution.command_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Command's sequence number", HFILL}},
        {&hf_amqp_0_10_method_execution_exception_error, {
            "Error-code", "amqp.execution.exception.error-code",
            FT_UINT16, BASE_DEC, VALS(amqp_0_10_method_execution_exception_errors), 0x0,
            "Exception error code", HFILL}},
        {&hf_amqp_0_10_method_execution_field_index, {
            "Field-index", "amqp.execution.exception.field-index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "0-based index of exceptional field", HFILL}},
        {&hf_amqp_0_10_method_execution_description, {
            "Description", "amqp.execution.exception.description",
            FT_STRING, BASE_NONE, NULL, 0,
            "Description of exception", HFILL}},
        {&hf_amqp_0_10_method_execution_error_info, {
            "Error-info", "amqp.execution.exception.error-info",
            FT_NONE, BASE_NONE, NULL, 0,
            "client-properties", HFILL}},
        {&hf_amqp_0_10_method_message_transfer_destination, {
            "Description", "amqp.message.transfer.destination",
            FT_STRING, BASE_NONE, NULL, 0,
            "Message destination", HFILL}},
        {&hf_amqp_0_10_method_message_transfer_accept_mode, {
            "Accept-mode", "amqp.message.transfer.accept-mode",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_message_transfer_accept_modes), 0x0,
            "Message accept mode", HFILL}},
        {&hf_amqp_0_10_method_message_transfer_acquire_mode, {
            "Acquire-mode", "amqp.message.transfer.acquire-mode",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_message_transfer_acquire_modes), 0x0,
            "Message acquire mode", HFILL}},
        {&hf_amqp_0_10_method_message_accept_transfers, {
            "Commands", "amqp.message.accept.transfers",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Previously transferred messages", HFILL}},
        {&hf_amqp_0_10_method_message_transfer_reject_code, {
            "Reject-code", "amqp.message.reject.reject-code",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_message_transfer_reject_codes), 0x0,
            "Message reject code", HFILL}},
        {&hf_amqp_0_10_method_message_reject_text, {
            "Text", "amqp.message.reject.text",
            FT_STRING, BASE_NONE, NULL, 0,
            "Reject description", HFILL}},
        {&hf_amqp_0_10_method_message_release_set_redelivered, {
            "Set-redelivered", "amqp.message.release.set-redelivered",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Mark redelivered on next transfer from queue", HFILL}},
        {&hf_amqp_0_10_method_message_dest, {
            "Destination", "amqp.message.destination",
            FT_STRING, BASE_NONE, NULL, 0,
            "Message destination", HFILL}},
        {&hf_amqp_0_10_method_message_resume_id, {
            "Resume-Id", "amqp.message.resume.id",
            FT_STRING, BASE_NONE, NULL, 0,
            "Message id to resume", HFILL}},
        {&hf_amqp_0_10_method_message_subscribe_queue, {
            "Queue", "amqp.message.subscribe.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            "Queue to subscribe to", HFILL}},
        {&hf_amqp_0_10_method_message_subscribe_exclusive, {
            "Exclusive", "amqp.message.subscribe.exclusive",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            "Request exclusive subscription", HFILL}},
        {&hf_amqp_0_10_method_message_subscribe_resume_ttl, {
            "Resume-ttl", "amqp.message.subscribe.resume_ttl",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "TTL to use when resuming", HFILL}},
        {&hf_amqp_0_10_method_message_subscribe_args, {
            "Extended arguments", "amqp.message.subscribe.arguments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Implementation-specific arguments", HFILL}},
        {&hf_amqp_0_10_method_message_flow_mode, {
            "Flow-mode", "amqp.message.flow-mode",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_message_flow_modes), 0x0,
            "Method for allocating message flow credit", HFILL}},
        {&hf_amqp_0_10_method_message_credit_unit, {
            "Credit-unit", "amqp.message.flow.credit-unit",
            FT_UINT8, BASE_DEC, VALS(amqp_0_10_message_credit_units), 0x0,
            "Unit of message flow value", HFILL}},
        {&hf_amqp_0_10_method_message_credit_value, {
            "Value", "amqp.message.flow.value",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Message flow value", HFILL}},
        {&hf_amqp_0_10_method_dtx_start_join, {
            "Join", "amqp.dtx.start.join",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Join with existing xid", HFILL}},
        {&hf_amqp_0_10_method_dtx_start_resume, {
            "Resume", "amqp.dtx.start.resume",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            "Resume suspended transaction", HFILL}},
        {&hf_amqp_0_10_method_dtx_end_fail, {
            "Fail", "amqp.dtx.end.fail",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "This portion of work has failed", HFILL}},
        {&hf_amqp_0_10_method_dtx_end_suspend, {
            "Suspend", "amqp.dtx.end.suspend",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            "Temporarily suspending transaction", HFILL}},
        {&hf_amqp_0_10_method_dtx_commit_one_phase, {
            "One-phase", "amqp.dtx.commit.one-phase",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Use one-phase optimization", HFILL}},
        {&hf_amqp_0_10_method_dtx_set_timeout_timeout, {
            "Timeout", "amqp.dtx.set-timeout.timeout",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Transaction timeout value in seconds", HFILL}},
        {&hf_amqp_0_10_method_exchange_declare_exchange, {
            "Exchange", "amqp.exchange.declare.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Exchange to declare", HFILL}},
        {&hf_amqp_0_10_method_exchange_declare_type, {
            "Type", "amqp.exchange.declare.type",
            FT_STRING, BASE_NONE, NULL, 0,
            "Type of exchange to declare", HFILL}},
        {&hf_amqp_0_10_method_exchange_declare_alt_exchange, {
            "Alternate-exchange", "amqp.exchange.declare.alternate-exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Alternate exchange for unroutable messages", HFILL}},
        {&hf_amqp_0_10_method_exchange_declare_passive, {
            "Passive", "amqp.exchange.declare.passive",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            "Do not create the exchange", HFILL}},
        {&hf_amqp_0_10_method_exchange_declare_durable, {
            "Durable", "amqp.exchange.declare.durable",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            "Create a durable exchange", HFILL}},
        {&hf_amqp_0_10_method_exchange_declare_auto_delete, {
            "Auto-delete", "amqp.exchange.declare.auto-delete",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            "Delete exchange when last binding removed", HFILL}},
        {&hf_amqp_0_10_method_exchange_declare_arguments, {
            "Arguments", "amqp.exchange.declare.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            "Declaration arguments", HFILL}},
        {&hf_amqp_0_10_method_exchange_delete_if_unused, {
            "If-unused", "amqp.exchange.delete.if-unused",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Delete exchange only if it has no queue bindings", HFILL}},
        {&hf_amqp_0_10_method_exchange_bind_queue, {
            "Queue", "amqp.exchange.bind.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            "Queue to bind to", HFILL}},
        {&hf_amqp_0_10_method_exchange_binding_key, {
            "Binding-key", "amqp.exchange.bind.binding-key",
            FT_STRING, BASE_NONE, NULL, 0,
            "Binding between exchange and queue", HFILL}},
        {&hf_amqp_0_10_method_queue_name, {
            "Queue", "amqp.queue.declare.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            "Queue name", HFILL}},
        {&hf_amqp_0_10_method_queue_alt_exchange, {
            "Alternate-exchange", "amqp.queue.declare.alternate-exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Alternate Exchange", HFILL}},
        {&hf_amqp_0_10_method_queue_declare_passive, {
            "Passive", "amqp.queue.declare.passive",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            "Do not create the queue", HFILL}},
        {&hf_amqp_0_10_method_queue_declare_durable, {
            "Durable", "amqp.queue.declare.durable",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
            "Create a durable queue", HFILL}},
        {&hf_amqp_0_10_method_queue_declare_exclusive, {
            "Exclusive", "amqp.queue.declare.exclusive",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
            "Create a queue usable from only one session", HFILL}},
        {&hf_amqp_0_10_method_queue_declare_auto_delete, {
            "Auto-delete", "amqp.queue.declare.auto-delete",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
            "Delete queue when all uses completed", HFILL}},
        {&hf_amqp_0_10_method_queue_declare_arguments, {
            "Arguments", "amqp.queue.declare.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            "Declaration arguments", HFILL}},
        {&hf_amqp_0_10_method_queue_delete_if_unused, {
            "If-unused", "amqp.queue.delete.if-unused",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
            "Delete the queue only if there are no consumers", HFILL}},
        {&hf_amqp_0_10_method_queue_delete_if_empty, {
            "If-empty", "amqp.queue.delete.if-empty",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
            "Delete queue only if empty", HFILL}},
        {&hf_amqp_0_10_method_file_qos_prefetch_size, {
            "Prefetch-size", "amqp.file.qos.prefetch-size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Pre-fetch window size in octets", HFILL}},
        {&hf_amqp_0_10_method_file_qos_prefetch_count, {
            "Prefetch-count", "amqp.file.qos.prefetch-count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Pre-fetch window size in messages", HFILL}},
        {&hf_amqp_0_10_method_file_qos_global, {
            "Global", "amqp.file.qos.global",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
            "Apply QoS to entire connection", HFILL}},
        {&hf_amqp_0_10_method_file_consumer_tag, {
            "Consumer-tag", "amqp.file.consumer-tag",
            FT_STRING, BASE_NONE, NULL, 0,
            "Consumer tag", HFILL}},
        {&hf_amqp_0_10_method_file_consume_no_local, {
            "No-local", "amqp.file.consume.no-local",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
            "Don't send messages to connection that publishes them", HFILL}},
        {&hf_amqp_0_10_method_file_consume_no_ack, {
            "No-ack", "amqp.file.consume.no-ack",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
            "No acknowledgement needed", HFILL}},
        {&hf_amqp_0_10_method_file_consume_exclusive, {
            "Exclusive", "amqp.file.consume.exclusive",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x10,
            "Request exclusive access", HFILL}},
        {&hf_amqp_0_10_method_file_consume_nowait, {
            "Nowait", "amqp.file.consume.nowait",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x20,
            "Do not send a reply", HFILL}},
        {&hf_amqp_0_10_method_file_consume_arguments, {
            "Arguments", "amqp.file.consume.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            "Arguments for consuming", HFILL}},
        {&hf_amqp_0_10_method_file_identifier, {
            "Identifier", "amqp.file.identifier",
            FT_STRING, BASE_NONE, NULL, 0,
            "Staging identifier", HFILL}},
        {&hf_amqp_0_10_method_file_open_content_size, {
            "Content-size", "amqp.file.open.content-size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Message content size in octets", HFILL}},
        {&hf_amqp_0_10_method_file_open_ok_staged_size, {
            "Staged-size", "amqp.file.open_ok.staged-size",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Amount of previously staged content in octets", HFILL}},
        {&hf_amqp_0_10_method_file_publish_exchange, {
            "Exchange", "amqp.file.publish.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Exchange to publish to", HFILL}},
        {&hf_amqp_0_10_method_file_publish_routing_key, {
            "Routing-key", "amqp.file.publish.routing-key",
            FT_STRING, BASE_NONE, NULL, 0,
            "Message routing key", HFILL}},
        {&hf_amqp_0_10_method_file_publish_mandatory, {
            "Mandatory", "amqp.file.publish.mandatory",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
            "Mandatory routing", HFILL}},
        {&hf_amqp_0_10_method_file_publish_immediate, {
            "Immediate", "amqp.file.publish.immediate",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
            "Request immediate delivery", HFILL}},
        {&hf_amqp_0_10_method_file_return_reply_code, {
            "Reply-code", "amqp.file.return.reply-code",
            FT_UINT16, BASE_DEC, VALS(amqp_0_10_file_return_codes), 0x0,
            "Reply code", HFILL}},
        {&hf_amqp_0_10_method_file_return_reply_text, {
            "Reply-text", "amqp.file.return.reply-text",
            FT_STRING, BASE_NONE, NULL, 0,
            "Localized reply text", HFILL}},
        {&hf_amqp_0_10_method_file_return_exchange, {
            "Exchange", "amqp.file.return.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Exchange the original message was published to", HFILL}},
        {&hf_amqp_0_10_method_file_return_routing_key, {
            "Routing-key", "amqp.file.return.routing-key",
            FT_STRING, BASE_NONE, NULL, 0,
            "Message routing key", HFILL}},
        {&hf_amqp_0_10_method_file_deliver_consumer_tag, {
            "Consumer-tag", "amqp.file.deliver.consumer-tag",
            FT_STRING, BASE_NONE, NULL, 0,
            "Consumer tag", HFILL}},
        {&hf_amqp_0_10_method_file_deliver_delivery_tag, {
            "Delivery-tag", "amqp.file.deliver.delivery-tag",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Server-assigned, session-specific delivery tag", HFILL}},
        {&hf_amqp_0_10_method_file_deliver_redelivered, {
            "Redelivered", "amqp.file.deliver.redelivered",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
            "Possible duplicate delivery", HFILL}},
        {&hf_amqp_0_10_method_file_deliver_exchange, {
            "Exchange", "amqp.file.deliver.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Exchange the original message was published to", HFILL}},
        {&hf_amqp_0_10_method_file_deliver_routing_key, {
            "Routing-key", "amqp.file.deliver.routing-key",
            FT_STRING, BASE_NONE, NULL, 0,
            "Message routing key", HFILL}},
        {&hf_amqp_0_10_method_file_ack_delivery_tag, {
            "Delivery-tag", "amqp.file.ack.delivery-tag",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Identifier of message being acknowledged", HFILL}},
        {&hf_amqp_0_10_method_file_ack_multiple, {
            "Multiple", "amqp.file.ack.multiple",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x02,
            "Acknowledge multiple messages", HFILL}},
        {&hf_amqp_0_10_method_file_reject_delivery_tag, {
            "Delivery-tag", "amqp.file.reject.delivery-tag",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Identifier of message to be rejected", HFILL}},
        {&hf_amqp_0_10_method_file_reject_requeue, {
            "Requeue", "amqp.file.reject.multiple",
            FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
            "Requeue the message", HFILL}},
        {&hf_amqp_0_10_method_stream_qos_prefetch_size, {
            "Prefetch-size", "amqp.stream.qos.prefetch-size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Pre-fetch window size in octets", HFILL}},
        {&hf_amqp_0_10_method_stream_qos_prefetch_count, {
            "Prefetch-count", "amqp.stream.qos.prefetch-count",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Pre-fetch window size in messages", HFILL}},
        {&hf_amqp_0_10_method_stream_qos_consume_rate, {
            "Prefetch-size", "amqp.stream.qos.consume_rate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Desired transfer rate in octets/second", HFILL}},
        {&hf_amqp_0_10_method_stream_qos_global, {
            "Global", "amqp.stream.qos.global",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
            "Apply QoS to entire connection", HFILL}},
        {&hf_amqp_0_10_method_stream_consumer_tag, {
            "Consumer-tag", "amqp.stream.consumer-tag",
            FT_STRING, BASE_NONE, NULL, 0,
            "Consumer tag", HFILL}},
        {&hf_amqp_0_10_method_stream_consume_no_local, {
            "No-local", "amqp.stream.consume.no-local",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
            "Don't send messages to connection that publishes them", HFILL}},
        {&hf_amqp_0_10_method_stream_consume_exclusive, {
            "Exclusive", "amqp.stream.consume.exclusive",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
            "Request exclusive access", HFILL}},
        {&hf_amqp_0_10_method_stream_consume_nowait, {
            "Nowait", "amqp.stream.consume.nowait",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x10,
            "Do not send a reply", HFILL}},
        {&hf_amqp_0_10_method_stream_consume_arguments, {
            "Arguments", "amqp.stream.consume.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            "Arguments for consuming", HFILL}},
        {&hf_amqp_0_10_method_stream_publish_exchange, {
            "Exchange", "amqp.stream.publish.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Exchange to publish to", HFILL}},
        {&hf_amqp_0_10_method_stream_publish_routing_key, {
            "Routing-key", "amqp.stream.publish.routing-key",
            FT_STRING, BASE_NONE, NULL, 0,
            "Message routing key", HFILL}},
        {&hf_amqp_0_10_method_stream_publish_mandatory, {
            "Mandatory", "amqp.stream.publish.mandatory",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x04,
            "Mandatory routing", HFILL}},
        {&hf_amqp_0_10_method_stream_publish_immediate, {
            "Immediate", "amqp.stream.publish.immediate",
            FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x08,
            "Request immediate delivery", HFILL}},
        {&hf_amqp_0_10_method_stream_return_reply_code, {
            "Reply-code", "amqp.stream.return.reply-code",
            FT_UINT16, BASE_DEC, VALS(amqp_0_10_stream_return_codes), 0x0,
            "Reply code", HFILL}},
        {&hf_amqp_0_10_method_stream_return_reply_text, {
            "Reply-text", "amqp.stream.return.reply-text",
            FT_STRING, BASE_NONE, NULL, 0,
            "Localized reply text", HFILL}},
        {&hf_amqp_0_10_method_stream_return_exchange, {
            "Exchange", "amqp.stream.return.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Exchange the original message was published to", HFILL}},
        {&hf_amqp_0_10_method_stream_return_routing_key, {
            "Routing-key", "amqp.stream.return.routing-key",
            FT_STRING, BASE_NONE, NULL, 0,
            "Message routing key", HFILL}},
        {&hf_amqp_0_10_method_stream_deliver_consumer_tag, {
            "Consumer-tag", "amqp.stream.deliver.consumer-tag",
            FT_STRING, BASE_NONE, NULL, 0,
            "Consumer tag", HFILL}},
        {&hf_amqp_0_10_method_stream_deliver_delivery_tag, {
            "Delivery-tag", "amqp.stream.deliver.delivery-tag",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Server-assigned, session-specific delivery tag", HFILL}},
        {&hf_amqp_0_10_method_stream_deliver_exchange, {
            "Exchange", "amqp.stream.deliver.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            "Exchange the original message was published to", HFILL}},
        {&hf_amqp_0_10_method_stream_deliver_queue, {
            "Queue", "amqp.stream.deliver.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            "Name of the queue the message came from", HFILL}},
        {&hf_amqp_channel,{
            "Channel", "amqp.channel",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Channel ID", HFILL}},
        {&hf_amqp_0_9_type, {
            "Type", "amqp.type",
            FT_UINT8, BASE_DEC, VALS(amqp_0_9_frame_types), 0x0,
            "Frame type", HFILL}},
        {&hf_amqp_0_9_length, {
            "Length", "amqp.length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Length of the frame", HFILL}},
        {&hf_amqp_0_9_method_class_id, {
            "Class", "amqp.method.class",
            FT_UINT16, BASE_DEC, VALS(amqp_0_9_method_classes), 0x0,
            "Class ID", HFILL}},
        {&hf_amqp_method_connection_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_connection_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_channel_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_channel_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_access_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_access_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_exchange_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_exchange_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_queue_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_queue_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_basic_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_basic_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_file_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_file_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_stream_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_stream_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_tx_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_tx_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_dtx_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_dtx_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_tunnel_method_id, {
            "Method", "amqp.method.method",
            FT_UINT16, BASE_DEC, VALS(amqp_method_tunnel_methods), 0x0,
            "Method ID", HFILL}},
        {&hf_amqp_method_arguments, {
            "Arguments", "amqp.method.arguments",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Method arguments", HFILL}},
        {&hf_amqp_method_connection_start_version_major, {
            "Version-Major", "amqp.method.arguments.version_major",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_start_version_minor, {
            "Version-Minor", "amqp.method.arguments.version_minor",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_start_server_properties, {
            "Server-Properties", "amqp.method.arguments.server_properties",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_9_method_connection_start_mechanisms, {
            "Mechanisms", "amqp.method.arguments.mechanisms",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_start_mechanisms, {
            "Mechanisms", "amqp.method.arguments.mechanisms",
            FT_NONE, BASE_NONE, NULL, 0,
            "Supported security mechanisms", HFILL}},
        {&hf_amqp_0_9_method_connection_start_locales, {
            "Locales", "amqp.method.arguments.locales",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_start_locales, {
            "Locales", "amqp.method.arguments.locales",
            FT_NONE, BASE_NONE, NULL, 0,
            "Supported message locales", HFILL}},
        {&hf_amqp_method_connection_start_ok_client_properties, {
            "Client-Properties", "amqp.method.arguments.client_properties",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_start_ok_mechanism, {
            "Mechanism", "amqp.method.arguments.mechanism",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_start_ok_response, {
            "Response", "amqp.method.arguments.response",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_start_ok_locale, {
            "Locale", "amqp.method.arguments.locale",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_secure_challenge, {
            "Challenge", "amqp.method.arguments.challenge",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_secure_ok_response, {
            "Response", "amqp.method.arguments.response",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_tune_channel_max, {
            "Channel-Max", "amqp.method.arguments.channel_max",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_9_method_connection_tune_frame_max, {
            "Frame-Max", "amqp.method.arguments.frame_max",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_tune_frame_max, {
            "Frame-Max", "amqp.method.arguments.frame_max",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Server-proposed maximum frame size", HFILL}},
        {&hf_amqp_0_9_method_connection_tune_heartbeat, {
            "Heartbeat", "amqp.method.arguments.heartbeat",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_tune_heartbeat_min, {
            "Heartbeat-Min", "amqp.method.arguments.heartbeat_min",
             FT_UINT16, BASE_DEC, NULL, 0,
            "Minimum heartbeat delay (seconds)", HFILL}},
        {&hf_amqp_0_10_method_connection_tune_heartbeat_max, {
            "Heartbeat-Max", "amqp.method.arguments.heartbeat_max",
             FT_UINT16, BASE_DEC, NULL, 0,
            "Maximum heartbeat delay (seconds)", HFILL}},
        {&hf_amqp_method_connection_tune_ok_channel_max, {
            "Channel-Max", "amqp.method.arguments.channel_max",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_9_method_connection_tune_ok_frame_max, {
            "Frame-Max", "amqp.method.arguments.frame_max",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_tune_ok_frame_max, {
            "Frame-Max", "amqp.method.arguments.frame_max",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Negotiated maximum frame size", HFILL}},
        {&hf_amqp_method_connection_tune_ok_heartbeat, {
            "Heartbeat", "amqp.method.arguments.heartbeat",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_open_virtual_host, {
            "Virtual-Host", "amqp.method.arguments.virtual_host",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_9_method_connection_open_capabilities, {
            "Capabilities", "amqp.method.arguments.capabilities",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_open_capabilities, {
            "Capabilities", "amqp.method.arguments.capabilities",
            FT_NONE, BASE_NONE, NULL, 0,
            "Required capabilities", HFILL}},
        {&hf_amqp_0_9_method_connection_open_insist, {
            "Insist", "amqp.method.arguments.insist",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_open_insist, {
            "Insist", "amqp.method.arguments.insist",
            FT_BOOLEAN, 8, NULL, 0x04,
            "Client insists on this server", HFILL}},
        {&hf_amqp_0_9_method_connection_open_ok_known_hosts, {
            "Known-Hosts", "amqp.method.arguments.known_hosts",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_open_ok_known_hosts, {
            "Known-Hosts", "amqp.method.arguments.known_hosts",
            FT_NONE, BASE_NONE, NULL, 0,
            "Equivalent or alternate hosts for reconnection", HFILL}},
        {&hf_amqp_method_connection_redirect_host, {
            "Host", "amqp.method.arguments.host",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_9_method_connection_redirect_known_hosts, {
            "Known-Hosts", "amqp.method.arguments.known_hosts",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_redirect_known_hosts, {
            "Known-Hosts", "amqp.method.arguments.known_hosts",
            FT_NONE, BASE_NONE, NULL, 0,
            "Equivalent or alternate hosts to redirect to", HFILL}},
        {&hf_amqp_0_9_method_connection_close_reply_code, {
            "Reply-Code", "amqp.method.arguments.reply_code",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_0_10_method_connection_close_reply_code, {
            "Reply-Code", "amqp.method.arguments.reply_code",
             FT_UINT16, BASE_DEC,
            VALS(amqp_0_10_method_connection_close_reply_codes), 0,
            "Close reason", HFILL}},
        {&hf_amqp_method_connection_close_reply_text, {
            "Reply-Text", "amqp.method.arguments.reply_text",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_close_class_id, {
            "Class-Id", "amqp.method.arguments.class_id",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_connection_close_method_id, {
            "Method-Id", "amqp.method.arguments.method_id",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_channel_open_out_of_band, {
            "Out-Of-Band", "amqp.method.arguments.out_of_band",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_channel_open_ok_channel_id, {
            "Channel-Id", "amqp.method.arguments.channel_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_channel_flow_active, {
            "Active", "amqp.method.arguments.active",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_channel_flow_ok_active, {
            "Active", "amqp.method.arguments.active",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_channel_close_reply_code, {
            "Reply-Code", "amqp.method.arguments.reply_code",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_channel_close_reply_text, {
            "Reply-Text", "amqp.method.arguments.reply_text",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_channel_close_class_id, {
            "Class-Id", "amqp.method.arguments.class_id",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_channel_close_method_id, {
            "Method-Id", "amqp.method.arguments.method_id",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_channel_resume_channel_id, {
            "Channel-Id", "amqp.method.arguments.channel_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_access_request_realm, {
            "Realm", "amqp.method.arguments.realm",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_access_request_exclusive, {
            "Exclusive", "amqp.method.arguments.exclusive",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_access_request_passive, {
            "Passive", "amqp.method.arguments.passive",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_access_request_active, {
            "Active", "amqp.method.arguments.active",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}},
        {&hf_amqp_method_access_request_write, {
            "Write", "amqp.method.arguments.write",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}},
        {&hf_amqp_method_access_request_read, {
            "Read", "amqp.method.arguments.read",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}},
        {&hf_amqp_method_access_request_ok_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_type, {
            "Type", "amqp.method.arguments.type",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_passive, {
            "Passive", "amqp.method.arguments.passive",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_durable, {
            "Durable", "amqp.method.arguments.durable",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_auto_delete, {
            "Auto-Delete", "amqp.method.arguments.auto_delete",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_internal, {
            "Internal", "amqp.method.arguments.internal",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_declare_arguments, {
            "Arguments", "amqp.method.arguments.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_bind_destination, {
            "Destination", "amqp.method.arguments.destination",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_bind_source, {
            "Destination", "amqp.method.arguments.source",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_bind_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_bind_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_bind_arguments, {
            "Arguments", "amqp.method.arguments.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_delete_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_delete_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_delete_if_unused, {
            "If-Unused", "amqp.method.arguments.if_unused",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_exchange_delete_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_passive, {
            "Passive", "amqp.method.arguments.passive",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_durable, {
            "Durable", "amqp.method.arguments.durable",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_exclusive, {
            "Exclusive", "amqp.method.arguments.exclusive",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_auto_delete, {
            "Auto-Delete", "amqp.method.arguments.auto_delete",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_arguments, {
            "Arguments", "amqp.method.arguments.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_ok_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_ok_message_count, {
            "Message-Count", "amqp.method.arguments.message_count",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_declare_ok_consumer_count, {
            "Consumer-Count", "amqp.method.arguments.consumer_count",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_bind_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_bind_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_bind_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_bind_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_bind_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_queue_bind_arguments, {
            "Arguments", "amqp.method.arguments.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_unbind_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_unbind_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_unbind_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_unbind_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_unbind_arguments, {
            "Arguments", "amqp.method.arguments.arguments",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_purge_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_purge_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_purge_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_queue_purge_ok_message_count, {
            "Message-Count", "amqp.method.arguments.message_count",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_delete_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_delete_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_queue_delete_if_unused, {
            "If-Unused", "amqp.method.arguments.if_unused",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_queue_delete_if_empty, {
            "If-Empty", "amqp.method.arguments.if_empty",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_queue_delete_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}},
        {&hf_amqp_method_queue_delete_ok_message_count, {
            "Message-Count", "amqp.method.arguments.message_count",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_qos_prefetch_size, {
            "Prefetch-Size", "amqp.method.arguments.prefetch_size",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_qos_prefetch_count, {
            "Prefetch-Count", "amqp.method.arguments.prefetch_count",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_qos_global, {
            "Global", "amqp.method.arguments.global",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_no_local, {
            "No-Local", "amqp.method.arguments.no_local",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_no_ack, {
            "No-Ack", "amqp.method.arguments.no_ack",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_exclusive, {
            "Exclusive", "amqp.method.arguments.exclusive",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_filter, {
            "Filter", "amqp.method.arguments.filter",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_consume_ok_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_cancel_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_cancel_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_cancel_ok_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_publish_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_publish_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_publish_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_publish_mandatory, {
            "Mandatory", "amqp.method.arguments.mandatory",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_publish_immediate, {
            "Immediate", "amqp.method.arguments.immediate",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_basic_return_reply_code, {
            "Reply-Code", "amqp.method.arguments.reply_code",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_return_reply_text, {
            "Reply-Text", "amqp.method.arguments.reply_text",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_return_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_return_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_deliver_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_deliver_delivery_tag, {
            "Delivery-Tag", "amqp.method.arguments.delivery_tag",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_deliver_redelivered, {
            "Redelivered", "amqp.method.arguments.redelivered",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_deliver_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_deliver_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_no_ack, {
            "No-Ack", "amqp.method.arguments.no_ack",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_ok_delivery_tag, {
            "Delivery-Tag", "amqp.method.arguments.delivery_tag",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_ok_redelivered, {
            "Redelivered", "amqp.method.arguments.redelivered",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_ok_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_ok_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_ok_message_count, {
            "Message-Count", "amqp.method.arguments.message_count",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_get_empty_cluster_id, {
            "Cluster-Id", "amqp.method.arguments.cluster_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_ack_delivery_tag, {
            "Delivery-Tag", "amqp.method.arguments.delivery_tag",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_ack_multiple, {
            "Multiple", "amqp.method.arguments.multiple",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_reject_delivery_tag, {
            "Delivery-Tag", "amqp.method.arguments.delivery_tag",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_basic_reject_requeue, {
            "Requeue", "amqp.method.arguments.requeue",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_basic_recover_requeue, {
            "Requeue", "amqp.method.arguments.requeue",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_file_qos_prefetch_size, {
            "Prefetch-Size", "amqp.method.arguments.prefetch_size",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_qos_prefetch_count, {
            "Prefetch-Count", "amqp.method.arguments.prefetch_count",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_qos_global, {
            "Global", "amqp.method.arguments.global",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_no_local, {
            "No-Local", "amqp.method.arguments.no_local",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_no_ack, {
            "No-Ack", "amqp.method.arguments.no_ack",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_exclusive, {
            "Exclusive", "amqp.method.arguments.exclusive",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_filter, {
            "Filter", "amqp.method.arguments.filter",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_consume_ok_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_cancel_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_cancel_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_file_cancel_ok_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_open_identifier, {
            "Identifier", "amqp.method.arguments.identifier",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_open_content_size, {
            "Content-Size", "amqp.method.arguments.content_size",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_open_ok_staged_size, {
            "Staged-Size", "amqp.method.arguments.staged_size",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_publish_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_publish_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_publish_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_publish_mandatory, {
            "Mandatory", "amqp.method.arguments.mandatory",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_file_publish_immediate, {
            "Immediate", "amqp.method.arguments.immediate",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_file_publish_identifier, {
            "Identifier", "amqp.method.arguments.identifier",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_return_reply_code, {
            "Reply-Code", "amqp.method.arguments.reply_code",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_return_reply_text, {
            "Reply-Text", "amqp.method.arguments.reply_text",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_return_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_return_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_deliver_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_deliver_delivery_tag, {
            "Delivery-Tag", "amqp.method.arguments.delivery_tag",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_deliver_redelivered, {
            "Redelivered", "amqp.method.arguments.redelivered",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_file_deliver_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_deliver_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_deliver_identifier, {
            "Identifier", "amqp.method.arguments.identifier",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_ack_delivery_tag, {
            "Delivery-Tag", "amqp.method.arguments.delivery_tag",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_ack_multiple, {
            "Multiple", "amqp.method.arguments.multiple",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_file_reject_delivery_tag, {
            "Delivery-Tag", "amqp.method.arguments.delivery_tag",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_file_reject_requeue, {
            "Requeue", "amqp.method.arguments.requeue",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_stream_qos_prefetch_size, {
            "Prefetch-Size", "amqp.method.arguments.prefetch_size",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_qos_prefetch_count, {
            "Prefetch-Count", "amqp.method.arguments.prefetch_count",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_qos_consume_rate, {
            "Consume-Rate", "amqp.method.arguments.consume_rate",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_qos_global, {
            "Global", "amqp.method.arguments.global",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_stream_consume_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_consume_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_consume_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_consume_no_local, {
            "No-Local", "amqp.method.arguments.no_local",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_stream_consume_exclusive, {
            "Exclusive", "amqp.method.arguments.exclusive",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_stream_consume_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}},
        {&hf_amqp_method_stream_consume_filter, {
            "Filter", "amqp.method.arguments.filter",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_consume_ok_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_cancel_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_cancel_nowait, {
            "Nowait", "amqp.method.arguments.nowait",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_stream_cancel_ok_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_publish_ticket, {
            "Ticket", "amqp.method.arguments.ticket",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_publish_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_publish_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_publish_mandatory, {
            "Mandatory", "amqp.method.arguments.mandatory",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}},
        {&hf_amqp_method_stream_publish_immediate, {
            "Immediate", "amqp.method.arguments.immediate",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}},
        {&hf_amqp_method_stream_return_reply_code, {
            "Reply-Code", "amqp.method.arguments.reply_code",
             FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_return_reply_text, {
            "Reply-Text", "amqp.method.arguments.reply_text",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_return_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_return_routing_key, {
            "Routing-Key", "amqp.method.arguments.routing_key",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_deliver_consumer_tag, {
            "Consumer-Tag", "amqp.method.arguments.consumer_tag",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_deliver_delivery_tag, {
            "Delivery-Tag", "amqp.method.arguments.delivery_tag",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_deliver_exchange, {
            "Exchange", "amqp.method.arguments.exchange",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_stream_deliver_queue, {
            "Queue", "amqp.method.arguments.queue",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_dtx_start_dtx_identifier, {
            "Dtx-Identifier", "amqp.method.arguments.dtx_identifier",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_method_tunnel_request_meta_data, {
            "Meta-Data", "amqp.method.arguments.meta_data",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_field, {
            "AMQP", "amqp.field",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_class_id, {
            "Class ID", "amqp.header.class",
            FT_UINT16, BASE_DEC, VALS(amqp_0_9_method_classes), 0,
            NULL, HFILL}},
        {&hf_amqp_header_weight, {
            "Weight", "amqp.header.weight",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_body_size, {
            "Body size", "amqp.header.body-size",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_property_flags, {
            "Property flags", "amqp.header.property-flags",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_properties, {
            "Properties", "amqp.header.properties",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Message properties", HFILL}},
        {&hf_amqp_header_basic_content_type, {
            "Content-Type", "amqp.method.properties.content_type",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_content_encoding, {
            "Content-Encoding", "amqp.method.properties.content_encoding",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_headers, {
            "Headers", "amqp.method.properties.headers",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_delivery_mode, {
            "Delivery-Mode", "amqp.method.properties.delivery_mode",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_priority, {
            "Priority", "amqp.method.properties.priority",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_correlation_id, {
            "Correlation-Id", "amqp.method.properties.correlation_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_reply_to, {
            "Reply-To", "amqp.method.properties.reply_to",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_expiration, {
            "Expiration", "amqp.method.properties.expiration",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_message_id, {
            "Message-Id", "amqp.method.properties.message_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_timestamp, {
            "Timestamp", "amqp.method.properties.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_type, {
            "Type", "amqp.method.properties.type",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_user_id, {
            "User-Id", "amqp.method.properties.user_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_app_id, {
            "App-Id", "amqp.method.properties.app_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_basic_cluster_id, {
            "Cluster-Id", "amqp.method.properties.cluster_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_content_type, {
            "Content-Type", "amqp.method.properties.content_type",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_content_encoding, {
            "Content-Encoding", "amqp.method.properties.content_encoding",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_headers, {
            "Headers", "amqp.method.properties.headers",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_priority, {
            "Priority", "amqp.method.properties.priority",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_reply_to, {
            "Reply-To", "amqp.method.properties.reply_to",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_message_id, {
            "Message-Id", "amqp.method.properties.message_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_filename, {
            "Filename", "amqp.method.properties.filename",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_timestamp, {
            "Timestamp", "amqp.method.properties.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_file_cluster_id, {
            "Cluster-Id", "amqp.method.properties.cluster_id",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_stream_content_type, {
            "Content-Type", "amqp.method.properties.content_type",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_stream_content_encoding, {
            "Content-Encoding", "amqp.method.properties.content_encoding",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_stream_headers, {
            "Headers", "amqp.method.properties.headers",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_stream_priority, {
            "Priority", "amqp.method.properties.priority",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_stream_timestamp, {
            "Timestamp", "amqp.method.properties.timestamp",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_tunnel_headers, {
            "Headers", "amqp.method.properties.headers",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_tunnel_proxy_name, {
            "Proxy-Name", "amqp.method.properties.proxy_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_tunnel_data_name, {
            "Data-Name", "amqp.method.properties.data_name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_tunnel_durable, {
            "Durable", "amqp.method.properties.durable",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_header_tunnel_broadcast, {
            "Broadcast", "amqp.method.properties.broadcast",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_payload, {
            "Payload", "amqp.payload",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Message payload", HFILL}},
        {&hf_amqp_init_protocol, {
            "Protocol", "amqp.init.protocol",
            FT_STRING, BASE_NONE, NULL, 0,
            "Protocol name", HFILL}},
        {&hf_amqp_init_id_major, {
            "Protocol ID Major", "amqp.init.id_major",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_init_id_minor, {
            "Protocol ID Minor", "amqp.init.id_minor",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}},
        {&hf_amqp_init_version_major, {
            "Version Major", "amqp.init.version_major",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Protocol version major", HFILL}},
        {&hf_amqp_init_version_minor, {
            "Version Minor", "amqp.init.version_minor",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Protocol version minor", HFILL}}
    };

    /*  Setup of protocol subtree array  */

    static gint *ett [] = {
         &ett_amqp,
         &ett_header,
         &ett_args,
         &ett_props,
         &ett_field_table,
         &ett_amqp_init,
         &ett_amqp_0_10_map,
         &ett_amqp_0_10_array
    };

    proto_amqp = proto_register_protocol(
        "Advanced Message Queueing Protocol", "AMQP", "amqp");
    proto_register_field_array(proto_amqp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_amqp(void)
{
    dissector_add_uint("tcp.port", amqp_port,
        create_dissector_handle(dissect_amqp, proto_amqp));
}
