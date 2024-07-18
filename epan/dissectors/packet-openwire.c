/* packet-openwire.c
 * Routines for ActiveMQ OpenWire protocol
 *
 * metatech <metatechbe@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
    OpenWire has two wire formats :
    - "loose" : more verbose, less CPU-intensive, less network-intensive (1-pass)
    - "tight" : more compact, more CPU-intensive, more network-intensive (2-pass)
    This dissector only supports the "loose" syntax, which is not the default.
    This dissector only supports version 6 of the protocol.
    It can be changed on the broker in the activemq.xml file by specifying "tightEncodingEnabled=false" :

    <transportConnectors>
        <transportConnector name="tcp-connector" uri="tcp://0.0.0.0:61616?wireFormat.tightEncodingEnabled=false&amp;wireFormat.cacheEnabled=false"/>
    </transportConnectors>

    Note : The WIREFORMAT_INFO command is always sent in "loose" format.

*/
#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-tcp.h"

void proto_register_openwire(void);
void proto_reg_handoff_openwire(void);

static int proto_openwire;
static int hf_openwire_none;
static int hf_openwire_length;
static int hf_openwire_command;

static int hf_openwire_command_id;
static int hf_openwire_command_response_required;

static int hf_openwire_response_correlationid;

static int hf_openwire_dataresponse_data;

static int hf_openwire_exceptionresponse_exception;

static int hf_openwire_connectionerror_exception;
static int hf_openwire_connectionerror_connectionid;

static int hf_openwire_controlcommand_command;

static int hf_openwire_wireformatinfo_magic;
static int hf_openwire_wireformatinfo_version;
static int hf_openwire_wireformatinfo_data;
static int hf_openwire_wireformatinfo_length;

static int hf_openwire_sessioninfo_sessionid;

static int hf_openwire_connectioninfo_connectionid;
static int hf_openwire_connectioninfo_clientid;
static int hf_openwire_connectioninfo_password;
static int hf_openwire_connectioninfo_username;
static int hf_openwire_connectioninfo_brokerpath;
static int hf_openwire_connectioninfo_brokermasterconnector;
static int hf_openwire_connectioninfo_manageable;
static int hf_openwire_connectioninfo_clientmaster;
static int hf_openwire_connectioninfo_faulttolerant;
static int hf_openwire_connectioninfo_failoverreconnect;

static int hf_openwire_destinationinfo_connectionid;
static int hf_openwire_destinationinfo_destination;
static int hf_openwire_destinationinfo_operationtype;
static int hf_openwire_destinationinfo_timeout;
static int hf_openwire_destinationinfo_brokerpath;

static int hf_openwire_brokerinfo_brokerid;
static int hf_openwire_brokerinfo_brokerurl;
static int hf_openwire_brokerinfo_peerbrokerinfos;
static int hf_openwire_brokerinfo_brokername;
static int hf_openwire_brokerinfo_slavebroker;
static int hf_openwire_brokerinfo_masterbroker;
static int hf_openwire_brokerinfo_faulttolerantconfiguration;
static int hf_openwire_brokerinfo_duplexconnection;
static int hf_openwire_brokerinfo_networkconnection;
static int hf_openwire_brokerinfo_connectionid;
static int hf_openwire_brokerinfo_brokeruploadurl;
static int hf_openwire_brokerinfo_networkproperties;

static int hf_openwire_connectioncontrol_close;
static int hf_openwire_connectioncontrol_exit;
static int hf_openwire_connectioncontrol_faulttolerant;
static int hf_openwire_connectioncontrol_resume;
static int hf_openwire_connectioncontrol_suspend;
static int hf_openwire_connectioncontrol_connectedbrokers;
static int hf_openwire_connectioncontrol_reconnectto;
static int hf_openwire_connectioncontrol_rebalanceconnection;

static int hf_openwire_consumercontrol_destination;
static int hf_openwire_consumercontrol_close;
static int hf_openwire_consumercontrol_consumerid;
static int hf_openwire_consumercontrol_prefetch;
static int hf_openwire_consumercontrol_flush;
static int hf_openwire_consumercontrol_start;
static int hf_openwire_consumercontrol_stop;

static int hf_openwire_consumerinfo_consumerid;
static int hf_openwire_consumerinfo_browser;
static int hf_openwire_consumerinfo_destination;
static int hf_openwire_consumerinfo_prefetchsize;
static int hf_openwire_consumerinfo_maximumpendingmessagelimit;
static int hf_openwire_consumerinfo_dispatchasync;
static int hf_openwire_consumerinfo_selector;
static int hf_openwire_consumerinfo_subscriptionname;
static int hf_openwire_consumerinfo_nolocal;
static int hf_openwire_consumerinfo_exclusive;
static int hf_openwire_consumerinfo_retroactive;
static int hf_openwire_consumerinfo_priority;
static int hf_openwire_consumerinfo_brokerpath;
static int hf_openwire_consumerinfo_additionalpredicate;
static int hf_openwire_consumerinfo_networksubscription;
static int hf_openwire_consumerinfo_optimizedacknowledge;
static int hf_openwire_consumerinfo_norangeacks;
static int hf_openwire_consumerinfo_networkconsumerpath;

static int hf_openwire_producerinfo_producerid;
static int hf_openwire_producerinfo_destination;
static int hf_openwire_producerinfo_brokerpath;
static int hf_openwire_producerinfo_dispatchasync;
static int hf_openwire_producerinfo_windowsize;

static int hf_openwire_removeinfo_objectid;
static int hf_openwire_removeinfo_lastdeliveredsequenceid;

static int hf_openwire_removesubscriptioninfo_connectionid;
static int hf_openwire_removesubscriptioninfo_subscriptionname;
static int hf_openwire_removesubscriptioninfo_clientid;

static int hf_openwire_transactioninfo_connectionid;
static int hf_openwire_transactioninfo_transactionid;
static int hf_openwire_transactioninfo_type;

static int hf_openwire_producerack_producerid;
static int hf_openwire_producerack_size;


static int hf_openwire_messagedispatch_consumerid;
static int hf_openwire_messagedispatch_destination;
static int hf_openwire_messagedispatch_message;
static int hf_openwire_messagedispatch_redeliverycounter;

static int hf_openwire_messageack_destination;
static int hf_openwire_messageack_transactionid;
static int hf_openwire_messageack_consumerid;
static int hf_openwire_messageack_acktype;
static int hf_openwire_messageack_firstmessageid;
static int hf_openwire_messageack_lastmessageid;
static int hf_openwire_messageack_messagecount;

static int hf_openwire_messagepull_consumerid;
static int hf_openwire_messagepull_destinationid;
static int hf_openwire_messagepull_timeout;
static int hf_openwire_messagepull_correlationid;
static int hf_openwire_messagepull_messageid;

static int hf_openwire_message_producerid;
static int hf_openwire_message_destination;
static int hf_openwire_message_transactionid;
static int hf_openwire_message_originaldestination;
static int hf_openwire_message_messageid;
static int hf_openwire_message_originaldestinationid;
static int hf_openwire_message_groupid;
static int hf_openwire_message_groupsequence;
static int hf_openwire_message_correlationid;
static int hf_openwire_message_persistent;
static int hf_openwire_message_expiration;
static int hf_openwire_message_priority;
static int hf_openwire_message_replyto;
static int hf_openwire_message_timestamp;
static int hf_openwire_message_type;
static int hf_openwire_message_body;
static int hf_openwire_message_properties;
static int hf_openwire_message_datastructure;
static int hf_openwire_message_targetconsumerid;
static int hf_openwire_message_compressed;
static int hf_openwire_message_redeliverycount;
static int hf_openwire_message_brokerpath;
static int hf_openwire_message_arrival;
static int hf_openwire_message_userid;
static int hf_openwire_message_receivedbydfbridge;
static int hf_openwire_message_droppable;
static int hf_openwire_message_cluster;
static int hf_openwire_message_brokerintime;
static int hf_openwire_message_brokerouttime;

static int hf_openwire_producerid_connectionid;
static int hf_openwire_producerid_value;
static int hf_openwire_producerid_sessionid;

static int hf_openwire_consumerid_connectionid;
static int hf_openwire_consumerid_value;
static int hf_openwire_consumerid_sessionid;

static int hf_openwire_destination_name;

static int hf_openwire_messageid_producerid;
static int hf_openwire_messageid_producersequenceid;
static int hf_openwire_messageid_brokersequenceid;

static int hf_openwire_connectionid_value;

static int hf_openwire_sessionid_connectionid;
static int hf_openwire_sessionid_value;

static int hf_openwire_brokerid_value;

static int hf_openwire_localtransactionid_value;
static int hf_openwire_localtransactionid_connectionid;

static int hf_openwire_xatransactionid_formatid;
static int hf_openwire_xatransactionid_globaltransactionid;
static int hf_openwire_xatransactionid_branchqualifier;

static int hf_openwire_map_length;
static int hf_openwire_map_key;
static int hf_openwire_map_entry;

static int hf_openwire_throwable_class;
static int hf_openwire_throwable_message;
static int hf_openwire_throwable_element;
static int hf_openwire_throwable_classname;
static int hf_openwire_throwable_methodname;
static int hf_openwire_throwable_filename;
static int hf_openwire_throwable_linenumber;

static int hf_openwire_type_integer;
static int hf_openwire_type_short;
static int hf_openwire_type_string;
static int hf_openwire_type_bytes;
static int hf_openwire_type_boolean;
static int hf_openwire_type_byte;
static int hf_openwire_type_char;
static int hf_openwire_type_notnull;
static int hf_openwire_type_long;
static int hf_openwire_type_float;
static int hf_openwire_type_double;
static int hf_openwire_type_object;
static int hf_openwire_type;

static int hf_openwire_cached_inlined;
static int hf_openwire_cached_id;
static int hf_openwire_cached_enabled;

static int ett_openwire;
static int ett_openwire_type;

static expert_field ei_openwire_tight_encoding_not_supported;
static expert_field ei_openwire_encoding_not_supported;
static expert_field ei_openwire_type_not_supported;
static expert_field ei_openwire_command_not_supported;
static expert_field ei_openwire_body_type_not_supported;

static dissector_handle_t openwire_tcp_handle;

static bool openwire_desegment = true;
static bool openwire_verbose_type;

#define OPENWIRE_PORT_TCP    61616

#define OPENWIRE_MAGIC_PART_1    0x41637469 /* "Acti" */
#define OPENWIRE_MAGIC_PART_2    0x76654D51 /* "veMQ" */

#define OPENWIRE_WIREFORMAT_INFO                 1
#define OPENWIRE_BROKER_INFO                     2
#define OPENWIRE_CONNECTION_INFO                 3
#define OPENWIRE_SESSION_INFO                    4
#define OPENWIRE_CONSUMER_INFO                   5
#define OPENWIRE_PRODUCER_INFO                   6
#define OPENWIRE_TRANSACTION_INFO                7
#define OPENWIRE_DESTINATION_INFO                8
#define OPENWIRE_REMOVE_SUBSCRIPTION_INFO        9
#define OPENWIRE_KEEP_ALIVE_INFO                10
#define OPENWIRE_SHUTDOWN_INFO                  11
#define OPENWIRE_REMOVE_INFO                    12
#define OPENWIRE_CONTROL_COMMAND                14
#define OPENWIRE_FLUSH_COMMAND                  15
#define OPENWIRE_CONNECTION_ERROR               16
#define OPENWIRE_CONSUMER_CONTROL               17
#define OPENWIRE_CONNECTION_CONTROL             18
#define OPENWIRE_PRODUCER_ACK                   19
#define OPENWIRE_MESSAGE_PULL                   20
#define OPENWIRE_MESSAGE_DISPATCH               21
#define OPENWIRE_MESSAGE_ACK                    22
#define OPENWIRE_ACTIVEMQ_MESSAGE               23
#define OPENWIRE_ACTIVEMQ_BYTES_MESSAGE         24
#define OPENWIRE_ACTIVEMQ_MAP_MESSAGE           25
#define OPENWIRE_ACTIVEMQ_OBJECT_MESSAGE        26
#define OPENWIRE_ACTIVEMQ_STREAM_MESSAGE        27
#define OPENWIRE_ACTIVEMQ_TEXT_MESSAGE          28
#define OPENWIRE_ACTIVEMQ_BLOB_MESSAGE          29
#define OPENWIRE_RESPONSE                       30
#define OPENWIRE_EXCEPTION_RESPONSE             31
#define OPENWIRE_DATA_RESPONSE                  32
#define OPENWIRE_DATA_ARRAY_RESPONSE            33
#define OPENWIRE_INTEGER_RESPONSE               34
#define OPENWIRE_DISCOVERY_EVENT                40
#define OPENWIRE_JOURNAL_ACK                    50
#define OPENWIRE_JOURNAL_REMOVE                 52
#define OPENWIRE_JOURNAL_TRACE                  53
#define OPENWIRE_JOURNAL_TRANSACTION            54
#define OPENWIRE_DURABLE_SUBSCRIPTION_INFO      55
#define OPENWIRE_PARTIAL_COMMAND                60
#define OPENWIRE_PARTIAL_LAST_COMMAND           61
#define OPENWIRE_REPLAY                         65
#define OPENWIRE_BYTE_TYPE                      70
#define OPENWIRE_CHAR_TYPE                      71
#define OPENWIRE_SHORT_TYPE                     72
#define OPENWIRE_INTEGER_TYPE                   73
#define OPENWIRE_LONG_TYPE                      74
#define OPENWIRE_DOUBLE_TYPE                    75
#define OPENWIRE_FLOAT_TYPE                     76
#define OPENWIRE_STRING_TYPE                    77
#define OPENWIRE_BOOLEAN_TYPE                   78
#define OPENWIRE_BYTE_ARRAY_TYPE                79
#define OPENWIRE_MESSAGE_DISPATCH_NOTIFICATION  90
#define OPENWIRE_NETWORK_BRIDGE_FILTER          91
#define OPENWIRE_ACTIVEMQ_QUEUE                100
#define OPENWIRE_ACTIVEMQ_TOPIC                101
#define OPENWIRE_ACTIVEMQ_TEMP_QUEUE           102
#define OPENWIRE_ACTIVEMQ_TEMP_TOPIC           103
#define OPENWIRE_MESSAGE_ID                    110
#define OPENWIRE_ACTIVEMQ_LOCAL_TRANSACTION_ID 111
#define OPENWIRE_ACTIVEMQ_XA_TRANSACTION_ID    112
#define OPENWIRE_CONNECTION_ID                 120
#define OPENWIRE_SESSION_ID                    121
#define OPENWIRE_CONSUMER_ID                   122
#define OPENWIRE_PRODUCER_ID                   123
#define OPENWIRE_BROKER_ID                     124

static const value_string openwire_opcode_vals[] = {
    { OPENWIRE_WIREFORMAT_INFO,               "WireFormatInfo" },
    { OPENWIRE_BROKER_INFO,                   "BrokerInfo" },
    { OPENWIRE_CONNECTION_INFO,               "ConnectionInfo" },
    { OPENWIRE_SESSION_INFO,                  "SessionInfo" },
    { OPENWIRE_CONSUMER_INFO,                 "ConsumerInfo" },
    { OPENWIRE_PRODUCER_INFO,                 "ProducerInfo" },
    { OPENWIRE_TRANSACTION_INFO,              "TransactionInfo" },
    { OPENWIRE_DESTINATION_INFO,              "DestinationInfo" },
    { OPENWIRE_REMOVE_SUBSCRIPTION_INFO,      "RemoveSubscriptionInfo" },
    { OPENWIRE_KEEP_ALIVE_INFO,               "KeepAliveInfo" },
    { OPENWIRE_SHUTDOWN_INFO,                 "ShutdownInfo" },
    { OPENWIRE_REMOVE_INFO,                   "RemoveInfo" },
    { OPENWIRE_CONTROL_COMMAND,               "ControlCommand" },
    { OPENWIRE_FLUSH_COMMAND,                 "FlushCommand" },
    { OPENWIRE_CONNECTION_ERROR,              "ConnectionError" },
    { OPENWIRE_CONSUMER_CONTROL,              "ConsumerControl" },
    { OPENWIRE_CONNECTION_CONTROL,            "ConnectionControl" },
    { OPENWIRE_PRODUCER_ACK,                  "ProducerAck" },
    { OPENWIRE_MESSAGE_PULL,                  "MessagePull" },
    { OPENWIRE_MESSAGE_DISPATCH,              "MessageDispatch" },
    { OPENWIRE_MESSAGE_ACK,                   "MessageAck" },
    { OPENWIRE_ACTIVEMQ_MESSAGE,              "ActiveMQMessage" },
    { OPENWIRE_ACTIVEMQ_BYTES_MESSAGE,        "ActiveMQBytesMessage" },
    { OPENWIRE_ACTIVEMQ_MAP_MESSAGE,          "ActiveMQMapMessage" },
    { OPENWIRE_ACTIVEMQ_OBJECT_MESSAGE,       "ActiveMQObjectMessage" },
    { OPENWIRE_ACTIVEMQ_STREAM_MESSAGE,       "ActiveMQStreamMessage" },
    { OPENWIRE_ACTIVEMQ_TEXT_MESSAGE,         "ActiveMQTextMessage" },
    { OPENWIRE_ACTIVEMQ_BLOB_MESSAGE,         "ActiveMQBlobMessage" },
    { OPENWIRE_RESPONSE,                      "Response" },
    { OPENWIRE_EXCEPTION_RESPONSE,            "ExceptionResponse" },
    { OPENWIRE_DATA_RESPONSE,                 "DataResponse" },
    { OPENWIRE_DATA_ARRAY_RESPONSE,           "DataArrayResponse" },
    { OPENWIRE_INTEGER_RESPONSE,              "IntegerResponse" },
    { OPENWIRE_DISCOVERY_EVENT,               "DiscoveryEvent" },
    { OPENWIRE_JOURNAL_ACK,                   "JournalTopicAck" },
    { OPENWIRE_JOURNAL_REMOVE,                "JournalQueueAck" },
    { OPENWIRE_JOURNAL_TRACE,                 "JournalTrace" },
    { OPENWIRE_JOURNAL_TRANSACTION,           "JournalTransaction" },
    { OPENWIRE_DURABLE_SUBSCRIPTION_INFO,     "SubscriptionInfo" },
    { OPENWIRE_PARTIAL_COMMAND,               "PartialCommand" },
    { OPENWIRE_PARTIAL_LAST_COMMAND,          "LastPartialCommand" },
    { OPENWIRE_REPLAY,                        "ReplayCommand" },
    { OPENWIRE_BYTE_TYPE,                     "Byte" },
    { OPENWIRE_CHAR_TYPE,                     "Char" },
    { OPENWIRE_SHORT_TYPE,                    "Short" },
    { OPENWIRE_INTEGER_TYPE,                  "Integer" },
    { OPENWIRE_LONG_TYPE,                     "Long" },
    { OPENWIRE_DOUBLE_TYPE,                   "Double" },
    { OPENWIRE_FLOAT_TYPE,                    "Float" },
    { OPENWIRE_STRING_TYPE,                   "String" },
    { OPENWIRE_BOOLEAN_TYPE,                  "Boolean" },
    { OPENWIRE_BYTE_ARRAY_TYPE,               "ByteArray" },
    { OPENWIRE_MESSAGE_DISPATCH_NOTIFICATION, "MessageDispatchNotification" },
    { OPENWIRE_NETWORK_BRIDGE_FILTER,         "NetworkBridgeFilter" },
    { OPENWIRE_ACTIVEMQ_QUEUE,                "ActiveMQQueue" },
    { OPENWIRE_ACTIVEMQ_TOPIC,                "ActiveMQTopic" },
    { OPENWIRE_ACTIVEMQ_TEMP_QUEUE,           "ActiveMQTempQueue" },
    { OPENWIRE_ACTIVEMQ_TEMP_TOPIC,           "ActiveMQTempTopic" },
    { OPENWIRE_MESSAGE_ID,                    "MessageId" },
    { OPENWIRE_ACTIVEMQ_LOCAL_TRANSACTION_ID, "LocalTransactionId" },
    { OPENWIRE_ACTIVEMQ_XA_TRANSACTION_ID,    "XATransactionId" },
    { OPENWIRE_CONNECTION_ID,                 "ConnectionId" },
    { OPENWIRE_SESSION_ID,                    "SessionId" },
    { OPENWIRE_CONSUMER_ID,                   "ConsumerId" },
    { OPENWIRE_PRODUCER_ID,                   "ProducerId" },
    { OPENWIRE_BROKER_ID,                     "BrokerId" },
    { 0,          NULL }
};

static value_string_ext openwire_opcode_vals_ext = VALUE_STRING_EXT_INIT(openwire_opcode_vals);

#define OPENWIRE_COMMAND_INNER        -5
#define OPENWIRE_TYPE_OBJECT_ARRAY    -4
#define OPENWIRE_TYPE_CACHED          -3
#define OPENWIRE_TYPE_NESTED          -2
#define OPENWIRE_TYPE_THROWABLE       -1
#define OPENWIRE_TYPE_NULL             0
#define OPENWIRE_TYPE_BOOLEAN          1
#define OPENWIRE_TYPE_BYTE             2
#define OPENWIRE_TYPE_CHAR             3
#define OPENWIRE_TYPE_SHORT            4
#define OPENWIRE_TYPE_INTEGER          5
#define OPENWIRE_TYPE_LONG             6
#define OPENWIRE_TYPE_DOUBLE           7
#define OPENWIRE_TYPE_FLOAT            8
#define OPENWIRE_TYPE_STRING           9
#define OPENWIRE_TYPE_BYTE_ARRAY      10
#define OPENWIRE_TYPE_MAP             11
#define OPENWIRE_TYPE_LIST            12
#define OPENWIRE_TYPE_BIG_STRING      13

static const value_string openwire_type_vals[] = {
    { OPENWIRE_TYPE_NULL,                      "Null" },
    { OPENWIRE_TYPE_BOOLEAN,                   "Boolean" },
    { OPENWIRE_TYPE_BYTE,                      "Byte" },
    { OPENWIRE_TYPE_CHAR,                      "Char" },
    { OPENWIRE_TYPE_SHORT,                     "Short" },
    { OPENWIRE_TYPE_INTEGER,                   "Integer" },
    { OPENWIRE_TYPE_LONG,                      "Long" },
    { OPENWIRE_TYPE_DOUBLE,                    "Double" },
    { OPENWIRE_TYPE_FLOAT,                     "Float" },
    { OPENWIRE_TYPE_STRING,                    "String" },
    { OPENWIRE_TYPE_BYTE_ARRAY,                "ByteArray" },
    { OPENWIRE_TYPE_MAP,                       "Map" },
    { OPENWIRE_TYPE_LIST,                      "List" },
    { OPENWIRE_TYPE_BIG_STRING,                "BigString" },
    { OPENWIRE_ACTIVEMQ_MESSAGE,               "ActiveMQMessage" },
    { OPENWIRE_ACTIVEMQ_BYTES_MESSAGE,         "ActiveMQBytesMessage" },
    { OPENWIRE_ACTIVEMQ_MAP_MESSAGE,           "ActiveMQMapMessage" },
    { OPENWIRE_ACTIVEMQ_OBJECT_MESSAGE,        "ActiveMQObjectMessage" },
    { OPENWIRE_ACTIVEMQ_STREAM_MESSAGE,        "ActiveMQStreamMessage" },
    { OPENWIRE_ACTIVEMQ_TEXT_MESSAGE,          "ActiveMQTextMessage" },
    { OPENWIRE_ACTIVEMQ_BLOB_MESSAGE,          "ActiveMQBlobMessage" },
    { OPENWIRE_ACTIVEMQ_QUEUE,                 "ActiveMQQueue" },
    { OPENWIRE_ACTIVEMQ_TOPIC,                 "ActiveMQTopic" },
    { OPENWIRE_ACTIVEMQ_TEMP_QUEUE,            "ActiveMQTempQueue" },
    { OPENWIRE_ACTIVEMQ_TEMP_TOPIC,            "ActiveMQTempTopic" },
    { OPENWIRE_MESSAGE_ID,                     "MessageId" },
    { OPENWIRE_ACTIVEMQ_LOCAL_TRANSACTION_ID,  "LocalTransactionId" },
    { OPENWIRE_ACTIVEMQ_XA_TRANSACTION_ID,     "XATransactionId" },
    { OPENWIRE_CONNECTION_ID,                  "ConnectionId" },
    { OPENWIRE_SESSION_ID,                     "SessionId" },
    { OPENWIRE_CONSUMER_ID,                    "ConsumerId" },
    { OPENWIRE_PRODUCER_ID,                    "ProducerId" },
    { OPENWIRE_BROKER_ID,                      "BrokerId" },
    { OPENWIRE_TYPE_OBJECT_ARRAY,              "ObjectArray" },
    { OPENWIRE_TYPE_THROWABLE,                 "Throwable" },
    { 0,                                        NULL }
};

static value_string_ext openwire_type_vals_ext = VALUE_STRING_EXT_INIT(openwire_type_vals);

#define OPENWIRE_TRANSACTIONTYPE_BEGIN              0
#define OPENWIRE_TRANSACTIONTYPE_PREPARE            1
#define OPENWIRE_TRANSACTIONTYPE_COMMIT_ONE_PHASE   2
#define OPENWIRE_TRANSACTIONTYPE_COMMIT_TWO_PHASE   3
#define OPENWIRE_TRANSACTIONTYPE_ROLLBACK           4
#define OPENWIRE_TRANSACTIONTYPE_RECOVER            5
#define OPENWIRE_TRANSACTIONTYPE_FORGET             6
#define OPENWIRE_TRANSACTIONTYPE_END                7

static const value_string openwire_transaction_type_vals[] = {
    { OPENWIRE_TRANSACTIONTYPE_BEGIN,                "Begin" },
    { OPENWIRE_TRANSACTIONTYPE_PREPARE,              "Prepare" },
    { OPENWIRE_TRANSACTIONTYPE_COMMIT_ONE_PHASE,     "CommitOnePhase" },
    { OPENWIRE_TRANSACTIONTYPE_COMMIT_TWO_PHASE,     "CommitTwoPhase" },
    { OPENWIRE_TRANSACTIONTYPE_ROLLBACK,             "Rollback" },
    { OPENWIRE_TRANSACTIONTYPE_RECOVER,              "Recover" },
    { OPENWIRE_TRANSACTIONTYPE_FORGET,               "Forget" },
    { OPENWIRE_TRANSACTIONTYPE_END,                  "End" },
    { 0,                                             NULL }
};

static value_string_ext openwire_transaction_type_vals_ext = VALUE_STRING_EXT_INIT(openwire_transaction_type_vals);

#define OPENWIRE_MESSAGE_ACK_TYPE_DELIVERED       0
#define OPENWIRE_MESSAGE_ACK_TYPE_POISON          1
#define OPENWIRE_MESSAGE_ACK_TYPE_STANDARD        2
#define OPENWIRE_MESSAGE_ACK_TYPE_REDELIVERED     3
#define OPENWIRE_MESSAGE_ACK_TYPE_INDIVIDUAL      4
#define OPENWIRE_MESSAGE_ACK_TYPE_UNMATCHED       5

static const value_string openwire_message_ack_type_vals[] = {
    { OPENWIRE_MESSAGE_ACK_TYPE_DELIVERED,         "Delivered" },
    { OPENWIRE_MESSAGE_ACK_TYPE_POISON,            "Poison" },
    { OPENWIRE_MESSAGE_ACK_TYPE_STANDARD,          "Standard" },
    { OPENWIRE_MESSAGE_ACK_TYPE_REDELIVERED,       "Redelivered" },
    { OPENWIRE_MESSAGE_ACK_TYPE_INDIVIDUAL,        "Individual" },
    { OPENWIRE_MESSAGE_ACK_TYPE_UNMATCHED,         "Unmatched" },
    { 0,                                           NULL }
};

#define OPENWIRE_OPERATION_TYPE_ADD       0
#define OPENWIRE_OPERATION_TYPE_REMOVE    1

static const value_string openwire_operation_type_vals[] = {
    { OPENWIRE_OPERATION_TYPE_ADD,          "Add" },
    { OPENWIRE_OPERATION_TYPE_REMOVE,       "Remove" },
    { 0,                                    NULL }
};

typedef struct openwire_conv_data {
    bool caching;
    bool tight;
} openwire_conv_data;

static void
validate_boolean(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, int offset, proto_item *boolean_item)
{
    /* Sanity check of boolean : must be 0x00 or 0x01 */
    uint8_t booleanByte;
    booleanByte = tvb_get_uint8(tvb, offset);
    if (booleanByte != false && booleanByte != true)
    {
        expert_add_info(pinfo, boolean_item, &ei_openwire_encoding_not_supported);
    }
}

static int
particularize(int specificField, int genericField)
{
    return (specificField == hf_openwire_none ? genericField : specificField);
}

static void
detect_protocol_options(tvbuff_t *tvb, packet_info *pinfo, int offset, int iCommand)
{
    /* This function is level-2 heuristic to detect the protocol options, after the level-1 heuristic to detect the protocol.
       The WireFormatInfo structure reliably declares whether tight encoding and/or caching are used.
       However, only the response must be used, which is the result of the "negotiation" handshake with the server.
       However, if the capture is started after the connection initial handshake, it must be deduced in a heuristic way.
       For the sake of generality, we do not consider the handshake, but only the heuristic way.
    */
    if (tvb_captured_length_remaining(tvb, offset) >= 12)
    {
        /* Only check commands which start with a "OPENWIRE_TYPE_CACHED" object */
        if (iCommand == OPENWIRE_SESSION_INFO
            || iCommand == OPENWIRE_DESTINATION_INFO
            || iCommand == OPENWIRE_CONNECTION_INFO
            || iCommand == OPENWIRE_CONSUMER_INFO
            || iCommand == OPENWIRE_PRODUCER_INFO
            || iCommand == OPENWIRE_BROKER_INFO
            || iCommand == OPENWIRE_TRANSACTION_INFO
            || iCommand == OPENWIRE_REMOVE_SUBSCRIPTION_INFO
            || iCommand == OPENWIRE_MESSAGE_DISPATCH
            || iCommand == OPENWIRE_MESSAGE_ACK
            || iCommand == OPENWIRE_MESSAGE_PULL)
        {
            conversation_t *conv = NULL;
            openwire_conv_data *cd = NULL;
            conv = find_or_create_conversation(pinfo);
            cd = (openwire_conv_data*)conversation_get_proto_data(conv, proto_openwire);
            if (!cd)
            {
                uint8_t present, type;
                int command_id = 0;

                present = tvb_get_uint8(tvb, offset + 10);
                type = tvb_get_uint8(tvb, offset + 11);
                command_id = tvb_get_ntohl(tvb, offset + 5);

                cd = wmem_new(wmem_file_scope(), openwire_conv_data);
                cd->caching = false;
                cd->tight = false;
                if (command_id > (1 << 24))
                {
                    /* If "tight" encoding is enabled, the command_id first byte is non-zero.
                       This can be misdetected with "loose" encoding if the capture is started after 16 millions commands on the connection,
                       which we will assume that it happens very rarely.  */
                    cd->tight = true;
                }
                else
                {
                    if (present == true && type == OPENWIRE_TYPE_NULL)
                    {
                        /* If a cached object is not-null, it should be the "NULL" object.
                           This can be misdetected with "loose" encoding if the capture is started after 256 cached objects on the connection,
                           which we will assume that it happens rarely.  */
                        cd->caching = true;
                    }
                }
                conversation_add_proto_data(conv, proto_openwire, cd);
            }
        }
    }
    else if ((tvb_get_uint8(tvb, 4) == OPENWIRE_KEEP_ALIVE_INFO)
            && (tvb_captured_length(tvb) == 11))
    {
        /* If the capture is started after a long-lived connection is started,
           a keep-alive command of 11 bytes detects tight encoding (not caching stays unknown).
        */
        conversation_t *conv = NULL;
        openwire_conv_data *cd = NULL;
        conv = find_or_create_conversation(pinfo);
        cd = (openwire_conv_data*)conversation_get_proto_data(conv, proto_openwire);
        if (!cd)
        {
            cd = wmem_new(wmem_file_scope(), openwire_conv_data);
            cd->tight = true;
            cd->caching = false; /* Dummy value */
            conversation_add_proto_data(conv, proto_openwire, cd);
        }
    }
}

static bool
retrieve_caching(packet_info *pinfo)
{
    conversation_t     *conv;
    openwire_conv_data *cd;

    conv = find_or_create_conversation(pinfo);
    cd = (openwire_conv_data*)conversation_get_proto_data(conv, proto_openwire);
    if (cd) return cd->caching;
    /* Default : non-caching is recommended */
    return false;
}

static bool
retrieve_tight(packet_info *pinfo)
{
    conversation_t     *conv;
    openwire_conv_data *cd;

    conv = find_or_create_conversation(pinfo);
    cd = (openwire_conv_data*)conversation_get_proto_data(conv, proto_openwire);
    if (cd && cd->tight) return true;
    return false;
}

static int
dissect_openwire_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int parentType);

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_openwire_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int field, int type, int parentType, bool nullable)
{
    int         startOffset  = offset;
    proto_item *boolean_item = NULL;
    const char *cache_str = "";

    if (type == OPENWIRE_TYPE_CACHED && retrieve_caching(pinfo) == true && tvb_reported_length_remaining(tvb, offset) >= 3)
    {
        uint8_t inlined = 0;
        int cachedID = 0;
        proto_item * cached_item = NULL;
        inlined = tvb_get_uint8(tvb, offset + 0) == true ? true : false;
        cachedID = tvb_get_ntohs(tvb, offset + 1);
        cache_str = wmem_strdup_printf(pinfo->pool, " (CachedID: %d)", cachedID);
        if (openwire_verbose_type)
        {
            proto_tree_add_item(tree, hf_openwire_cached_inlined, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        cached_item  = proto_tree_add_item(tree, hf_openwire_cached_id, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        if (!openwire_verbose_type)
        {
            /* Hide it but allow it in search filters */
            proto_item_set_hidden(cached_item);
        }
        if (inlined == false)
        {
            proto_item    *ti;
            ti = proto_tree_add_item(tree, particularize(field, hf_openwire_type_object), tvb, startOffset, 3, ENC_NA);
            proto_item_append_text(ti, "%s", cache_str);
            return 3;
        }
        else
        {
            offset += 3;
        }
    }
    if (nullable == true && (type == OPENWIRE_TYPE_NESTED || type == OPENWIRE_TYPE_CACHED || type == OPENWIRE_COMMAND_INNER) && tvb_reported_length_remaining(tvb, offset) >= 1)
    {
        nullable = tvb_get_uint8(tvb, offset + 0) == false ? true : false;
        if (openwire_verbose_type)
        {
            boolean_item = proto_tree_add_item(tree, hf_openwire_type_notnull, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        validate_boolean(tvb, pinfo, tree, offset, boolean_item);
        if (nullable == true)
        {
            proto_tree_add_item(tree, particularize(field, hf_openwire_none), tvb, offset, 1, ENC_NA);
            return offset - startOffset + 1;
        }
        offset += 1;
    }
    if (type == OPENWIRE_COMMAND_INNER && tvb_reported_length_remaining(tvb, offset) >= 1)
    {
        proto_item * inner_item = NULL;
        proto_tree * object_tree = NULL;
        uint8_t iCommand = parentType;
        iCommand = tvb_get_uint8(tvb, offset + 0);
        inner_item = proto_tree_add_item(tree, particularize(field, hf_openwire_none), tvb, startOffset, -1, ENC_NA);
        proto_item_append_text(inner_item, ": %s", val_to_str_ext(iCommand, &openwire_opcode_vals_ext, "Unknown (0x%02x)"));
        object_tree = proto_item_add_subtree(inner_item, ett_openwire_type);
        increment_dissection_depth(pinfo);
        int command_offset = 1 + dissect_openwire_command(tvb, pinfo, object_tree, offset, parentType);
        decrement_dissection_depth(pinfo);
        return command_offset;

    }
    if ((type == OPENWIRE_TYPE_NESTED || type == OPENWIRE_TYPE_CACHED) && tvb_reported_length_remaining(tvb, offset) >= 1)
    {
        type = tvb_get_uint8(tvb, offset + 0);
        if (openwire_verbose_type)
        {
            proto_tree_add_item(tree, hf_openwire_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        offset += 1;
    }
    if (nullable == true && tvb_reported_length_remaining(tvb, offset) >= 1)
    {
        nullable = tvb_get_uint8(tvb, offset + 0) == false ? true : false;
        if (openwire_verbose_type)
        {
            boolean_item = proto_tree_add_item(tree, hf_openwire_type_notnull, tvb, offset, 1, ENC_BIG_ENDIAN);
        }
        validate_boolean(tvb, pinfo, tree, offset, boolean_item);
        if (nullable == true)
        {
            proto_tree_add_item(tree, particularize(field, hf_openwire_none), tvb, offset, 1, ENC_NA);
            return offset - startOffset + 1;
        }
        offset += 1;
    }

    /* First check for primitives types */
    if (type == OPENWIRE_TYPE_NULL)
    {
        offset += 0;
    }
    else if (type == OPENWIRE_TYPE_INTEGER && tvb_reported_length_remaining(tvb, offset) >= 4)
    {
        proto_tree_add_item(tree, particularize(field, hf_openwire_type_integer), tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    else if (type == OPENWIRE_TYPE_SHORT && tvb_reported_length_remaining(tvb, offset) >= 2)
    {
        proto_tree_add_item(tree, particularize(field, hf_openwire_type_short), tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    else if (type == OPENWIRE_TYPE_LONG && tvb_reported_length_remaining(tvb, offset) >= 8)
    {
        proto_tree_add_item(tree, particularize(field, hf_openwire_type_long), tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    else if (type == OPENWIRE_TYPE_BOOLEAN && tvb_reported_length_remaining(tvb, offset) >= 1)
    {
        boolean_item = proto_tree_add_item(tree, particularize(field, hf_openwire_type_boolean), tvb, offset, 1, ENC_BIG_ENDIAN);
        validate_boolean(tvb, pinfo, tree, offset, boolean_item);
        offset += 1;
    }
    else if (type == OPENWIRE_TYPE_BYTE && tvb_reported_length_remaining(tvb, offset) >= 1)
    {
        proto_tree_add_item(tree, particularize(field, hf_openwire_type_byte), tvb, offset, 1, ENC_NA);
        offset += 1;
    }
    else if (type == OPENWIRE_TYPE_CHAR && tvb_reported_length_remaining(tvb, offset) >= 2)
    {
        proto_tree_add_item(tree, particularize(field, hf_openwire_type_char), tvb, offset, 2, ENC_NA);
        offset += 2;
    }
    else if (type == OPENWIRE_TYPE_FLOAT && tvb_reported_length_remaining(tvb, offset) >= 4)
    {
        proto_tree_add_item(tree, particularize(field, hf_openwire_type_float), tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    else if (type == OPENWIRE_TYPE_DOUBLE && tvb_reported_length_remaining(tvb, offset) >= 8)
    {
        proto_tree_add_item(tree, particularize(field, hf_openwire_type_double), tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    else if (type == OPENWIRE_TYPE_STRING && tvb_reported_length_remaining(tvb, offset) >= 2)
    {
        int iStringLength = 0;
        iStringLength = tvb_get_ntohs(tvb, offset);
        if (openwire_verbose_type)
        {
            proto_tree_add_item(tree, hf_openwire_type_short, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        offset += 2;
        if (tvb_reported_length_remaining(tvb, offset) >= iStringLength)
        {
            proto_tree_add_item(tree, particularize(field, hf_openwire_type_string), tvb, offset, iStringLength, ENC_NA);
            offset += iStringLength;
        }
    }
    else if (type == OPENWIRE_TYPE_BIG_STRING && tvb_reported_length_remaining(tvb, offset) >= 4)
    {
        int iStringLength = 0;
        iStringLength = tvb_get_ntohl(tvb, offset);
        if (openwire_verbose_type)
        {
            proto_tree_add_item(tree, hf_openwire_type_integer, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset += 4;
        if (tvb_reported_length_remaining(tvb, offset) >= iStringLength)
        {
            proto_tree_add_item(tree, particularize(field, hf_openwire_type_string), tvb, offset, iStringLength, ENC_NA);
            offset += iStringLength;
        }
    }
    else if (type == OPENWIRE_TYPE_BYTE_ARRAY && tvb_reported_length_remaining(tvb, offset) >= 4)
    {
        int iArrayLength = 0;
        iArrayLength = tvb_get_ntohl(tvb, offset);
        if (openwire_verbose_type)
        {
            proto_tree_add_item(tree, hf_openwire_type_integer, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset += 4;
        if (tvb_reported_length_remaining(tvb, offset) >= iArrayLength)
        {
            proto_item * array_item = NULL;
            proto_tree * object_tree = NULL;
            array_item = proto_tree_add_item(tree, particularize(field, hf_openwire_type_bytes), tvb, offset, iArrayLength, ENC_NA);
            object_tree = proto_item_add_subtree(array_item, ett_openwire_type);
            if (field == hf_openwire_message_body)
            {
                tvbuff_t* next_tvb = NULL;
                if (parentType == OPENWIRE_ACTIVEMQ_TEXT_MESSAGE)
                {
                    dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_none, OPENWIRE_TYPE_BIG_STRING, type, false);
                    next_tvb = tvb_new_subset_length(tvb, offset, iArrayLength);
                    add_new_data_source(pinfo, next_tvb, "Body");
                }
                else if (parentType == OPENWIRE_ACTIVEMQ_MAP_MESSAGE)
                {
                    dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_none, OPENWIRE_TYPE_MAP, type, false);
                }
                else if (parentType == OPENWIRE_ACTIVEMQ_STREAM_MESSAGE)
                {
                    int streamOffset = offset;
                    while (streamOffset < offset + iArrayLength)
                    {
                        streamOffset += dissect_openwire_type(tvb, pinfo, object_tree, streamOffset, hf_openwire_none, OPENWIRE_TYPE_NESTED, type, false);
                    }
                }
                else if (parentType == OPENWIRE_ACTIVEMQ_BYTES_MESSAGE
                    || parentType == OPENWIRE_ACTIVEMQ_OBJECT_MESSAGE
                    || parentType == OPENWIRE_ACTIVEMQ_BLOB_MESSAGE)
                {
                    next_tvb = tvb_new_subset_length(tvb, offset, iArrayLength);
                    add_new_data_source(pinfo, next_tvb, "Body");
                    expert_add_info(pinfo, array_item, &ei_openwire_body_type_not_supported);
                }
            }
            else if (field == hf_openwire_message_properties)
            {
                dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_none, OPENWIRE_TYPE_MAP, type, false);
            }
            offset += iArrayLength;
        }
    }
    else if (tvb_reported_length_remaining(tvb, offset) >= 1)
    {
        /* Check for complex types */
        proto_tree    *object_tree;
        proto_item    *ti;
        ti = proto_tree_add_item(tree, particularize(field, hf_openwire_type_object), tvb, startOffset, -1, ENC_NA);
        proto_item_append_text(ti, ": %s", val_to_str_ext(type, &openwire_type_vals_ext, "Unknown (0x%02x)"));
        proto_item_append_text(ti, "%s", cache_str);

        object_tree = proto_item_add_subtree(ti, ett_openwire_type);

        if (type == OPENWIRE_TYPE_OBJECT_ARRAY && tvb_reported_length_remaining(tvb, offset) >= 2)
        {
            int iArrayLength;
            int iArrayItem = 0;
            iArrayLength = tvb_get_ntohs(tvb, offset);
            if (openwire_verbose_type)
            {
                proto_tree_add_item(object_tree, hf_openwire_type_short, tvb, offset + 0, 2, ENC_BIG_ENDIAN);
            }
            proto_item_append_text(ti, " (Size : %d)", iArrayLength);
            offset += 2;
            for (iArrayItem = 0; iArrayItem < iArrayLength; iArrayItem++)
            {
                if (tvb_reported_length_remaining(tvb, offset) >= 0)
                {
                    offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_none, OPENWIRE_TYPE_NESTED, type, true);
                }
            }
        }
        else if (type == OPENWIRE_TYPE_MAP && tvb_reported_length_remaining(tvb, offset) >= 4)
        {
            int iMapItem = 0;
            int iMapLength = 0;
            iMapLength = tvb_get_ntohl(tvb, offset);
            if (openwire_verbose_type)
            {
                proto_tree_add_item(object_tree, hf_openwire_map_length, tvb, offset, 4, ENC_BIG_ENDIAN);
            }
            proto_item_append_text(ti, " (Size : %d)", iMapLength);
            offset += 4;
            for (iMapItem = 0; (iMapItem < iMapLength) && (tvb_reported_length_remaining(tvb, offset) > 0); iMapItem++)
            {
                proto_item * map_entry;
                proto_tree * entry_tree;
                int entryStartOffset = offset;

                map_entry = proto_tree_add_item(object_tree, hf_openwire_map_entry, tvb, offset, 0, ENC_NA);
                entry_tree = proto_item_add_subtree(map_entry, ett_openwire_type);

                /* Key */
                offset += dissect_openwire_type(tvb, pinfo, entry_tree, offset, hf_openwire_map_key, OPENWIRE_TYPE_STRING, type, false);
                /* Value */
                offset += dissect_openwire_type(tvb, pinfo, entry_tree, offset, hf_openwire_none, OPENWIRE_TYPE_NESTED, type, false);
                proto_item_set_len(map_entry, offset - entryStartOffset);
            }
        }
        else if (type == OPENWIRE_TYPE_THROWABLE && tvb_reported_length_remaining(tvb, offset) >= 2)
        {
            int iStackTraceDepth, iStackTraceItem;
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_throwable_class, OPENWIRE_TYPE_STRING, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_throwable_message, OPENWIRE_TYPE_STRING, type, true);
            iStackTraceDepth = tvb_get_ntohs(tvb, offset);
            if (openwire_verbose_type)
            {
                proto_tree_add_item(tree, hf_openwire_type_short, tvb, offset, 2, ENC_BIG_ENDIAN);
            }
            offset += 2;
            if (iStackTraceDepth  > 0)
            {
                for (iStackTraceItem = 0; iStackTraceItem < iStackTraceDepth; iStackTraceItem++)
                {
                    proto_item    *element;
                    proto_tree    *element_tree;
                    int startElementOffset = offset;
                    element = proto_tree_add_item(object_tree, hf_openwire_throwable_element, tvb, startElementOffset, -1, ENC_NA);
                    element_tree = proto_item_add_subtree(element, ett_openwire_type);

                    if (tvb_reported_length_remaining(tvb, offset) >= 0)
                    {
                        offset += dissect_openwire_type(tvb, pinfo, element_tree, offset, hf_openwire_throwable_classname, OPENWIRE_TYPE_STRING, type, true);
                        offset += dissect_openwire_type(tvb, pinfo, element_tree, offset, hf_openwire_throwable_methodname, OPENWIRE_TYPE_STRING, type, true);
                        offset += dissect_openwire_type(tvb, pinfo, element_tree, offset, hf_openwire_throwable_filename, OPENWIRE_TYPE_STRING, type, true);
                        offset += dissect_openwire_type(tvb, pinfo, element_tree, offset, hf_openwire_throwable_linenumber, OPENWIRE_TYPE_INTEGER, type, false);
                        proto_item_set_len(element, offset - startElementOffset);
                    }
                }
                offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_exceptionresponse_exception, OPENWIRE_TYPE_THROWABLE, type, true);
            }
        }
        else if (type == OPENWIRE_TYPE_LIST && tvb_reported_length_remaining(tvb, offset) >= 4)
        {
            /* TODO (unused) */
        }
        else if (type == OPENWIRE_CONNECTION_ID && tvb_reported_length_remaining(tvb, offset) >= 1)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_connectionid_value, OPENWIRE_TYPE_STRING, type, true);
        }
        else if (type == OPENWIRE_SESSION_ID && tvb_reported_length_remaining(tvb, offset) >= 2)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_sessionid_connectionid, OPENWIRE_TYPE_STRING, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_sessionid_value, OPENWIRE_TYPE_LONG, type, false);
        }
        else if (type == OPENWIRE_CONSUMER_ID && tvb_reported_length_remaining(tvb, offset) >= 3)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_consumerid_connectionid, OPENWIRE_TYPE_STRING, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_consumerid_value, OPENWIRE_TYPE_LONG, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_consumerid_sessionid, OPENWIRE_TYPE_LONG, type, false);
        }
        else if (type == OPENWIRE_PRODUCER_ID && tvb_reported_length_remaining(tvb, offset) >= 3)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_producerid_connectionid, OPENWIRE_TYPE_STRING, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_producerid_value, OPENWIRE_TYPE_LONG, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_producerid_sessionid, OPENWIRE_TYPE_LONG, type, false);
        }
        else if (type == OPENWIRE_BROKER_ID && tvb_reported_length_remaining(tvb, offset) >= 1)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_brokerid_value, OPENWIRE_TYPE_STRING, type, true);
        }
        else if (type == OPENWIRE_MESSAGE_ID && tvb_reported_length_remaining(tvb, offset) >= 3)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_messageid_producerid, OPENWIRE_TYPE_CACHED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_messageid_producersequenceid, OPENWIRE_TYPE_LONG, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_messageid_brokersequenceid, OPENWIRE_TYPE_LONG, type, false);
        }
        else if (type == OPENWIRE_ACTIVEMQ_LOCAL_TRANSACTION_ID && tvb_reported_length_remaining(tvb, offset) >= 2)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_localtransactionid_value, OPENWIRE_TYPE_LONG, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_localtransactionid_connectionid, OPENWIRE_TYPE_CACHED, type, true);
        }
        else if (type == OPENWIRE_ACTIVEMQ_XA_TRANSACTION_ID && tvb_reported_length_remaining(tvb, offset) >= 3)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_xatransactionid_formatid, OPENWIRE_TYPE_INTEGER, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_xatransactionid_globaltransactionid, OPENWIRE_TYPE_BYTE_ARRAY, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_xatransactionid_branchqualifier, OPENWIRE_TYPE_BYTE_ARRAY, type, true);
        }
        else if ((type == OPENWIRE_ACTIVEMQ_QUEUE
            || type == OPENWIRE_ACTIVEMQ_TOPIC
            || type == OPENWIRE_ACTIVEMQ_TEMP_QUEUE
            || type == OPENWIRE_ACTIVEMQ_TEMP_TOPIC)
            && tvb_reported_length_remaining(tvb, offset) >= 1)
        {
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_destination_name, OPENWIRE_TYPE_STRING, type, true);
        }
        else if (type == OPENWIRE_ACTIVEMQ_MESSAGE
                || type == OPENWIRE_ACTIVEMQ_BYTES_MESSAGE
                || type == OPENWIRE_ACTIVEMQ_MAP_MESSAGE
                || type == OPENWIRE_ACTIVEMQ_OBJECT_MESSAGE
                || type == OPENWIRE_ACTIVEMQ_STREAM_MESSAGE
                || type == OPENWIRE_ACTIVEMQ_TEXT_MESSAGE
                || type == OPENWIRE_ACTIVEMQ_BLOB_MESSAGE)
        {
            if (parentType != type)
            {
                offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_command_id, OPENWIRE_TYPE_INTEGER, type, false);
                offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_command_response_required, OPENWIRE_TYPE_BOOLEAN, type, false);
            }
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_producerid, OPENWIRE_TYPE_CACHED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_destination, OPENWIRE_TYPE_CACHED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_transactionid, OPENWIRE_TYPE_CACHED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_originaldestination, OPENWIRE_TYPE_CACHED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_messageid, OPENWIRE_TYPE_NESTED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_originaldestinationid, OPENWIRE_TYPE_CACHED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_groupid, OPENWIRE_TYPE_STRING, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_groupsequence, OPENWIRE_TYPE_INTEGER, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_correlationid, OPENWIRE_TYPE_STRING, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_persistent, OPENWIRE_TYPE_BOOLEAN, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_expiration, OPENWIRE_TYPE_LONG, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_priority, OPENWIRE_TYPE_BYTE, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_replyto, OPENWIRE_TYPE_NESTED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_timestamp, OPENWIRE_TYPE_LONG, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_type, OPENWIRE_TYPE_STRING, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_body, OPENWIRE_TYPE_BYTE_ARRAY, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_properties, OPENWIRE_TYPE_BYTE_ARRAY, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_datastructure, OPENWIRE_COMMAND_INNER, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_targetconsumerid, OPENWIRE_TYPE_CACHED, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_compressed, OPENWIRE_TYPE_BOOLEAN, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_redeliverycount, OPENWIRE_TYPE_INTEGER, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_brokerpath, OPENWIRE_TYPE_OBJECT_ARRAY, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_arrival, OPENWIRE_TYPE_LONG, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_userid, OPENWIRE_TYPE_STRING, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_receivedbydfbridge, OPENWIRE_TYPE_BOOLEAN, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_droppable, OPENWIRE_TYPE_BOOLEAN, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_cluster, OPENWIRE_TYPE_OBJECT_ARRAY, type, true);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_brokerintime, OPENWIRE_TYPE_LONG, type, false);
            offset += dissect_openwire_type(tvb, pinfo, object_tree, offset, hf_openwire_message_brokerouttime, OPENWIRE_TYPE_LONG, type, false);
        }
        else if (tvb_reported_length_remaining(tvb, offset) > 0)
        {
            expert_add_info_format(pinfo, object_tree, &ei_openwire_type_not_supported, "OpenWire type not supported by Wireshark : %d", type);
            offset += tvb_captured_length_remaining(tvb, offset);
        }
        proto_item_set_len(ti, offset - startOffset);

    }
    return (offset - startOffset);
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_openwire_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int parentType)
{
    int    startOffset = offset;
    uint8_t iCommand;

    iCommand = tvb_get_uint8(tvb, offset + 0);

    proto_tree_add_item(tree, hf_openwire_command, tvb, offset + 0, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (iCommand == OPENWIRE_WIREFORMAT_INFO)
    {
        if (tvb_reported_length_remaining(tvb, offset) >= 17)
        {
            proto_tree_add_item(tree, hf_openwire_wireformatinfo_magic, tvb, offset + 0, 8, ENC_ASCII);
            proto_tree_add_item(tree, hf_openwire_wireformatinfo_version, tvb, offset + 8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_openwire_wireformatinfo_data, tvb, offset + 12, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_openwire_wireformatinfo_length, tvb, offset + 13, 4, ENC_BIG_ENDIAN);
            offset += 17;
            offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_none, OPENWIRE_TYPE_MAP, iCommand, false);
        }
    }
    else
    {
        if (tvb_reported_length_remaining(tvb, offset) >= 5)
        {
            proto_tree_add_item(tree, hf_openwire_command_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_openwire_command_response_required, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            offset += 5;
            if (iCommand == OPENWIRE_SHUTDOWN_INFO || iCommand == OPENWIRE_KEEP_ALIVE_INFO  || iCommand == OPENWIRE_FLUSH_COMMAND)
            {
                /* No additional fields */
            }
            else if (iCommand == OPENWIRE_SESSION_INFO)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_sessioninfo_sessionid, OPENWIRE_TYPE_CACHED, iCommand, true);
            }
            else if (iCommand == OPENWIRE_DESTINATION_INFO)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_destinationinfo_connectionid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_destinationinfo_destination, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_destinationinfo_operationtype, OPENWIRE_TYPE_BYTE, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_destinationinfo_timeout, OPENWIRE_TYPE_LONG, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_destinationinfo_brokerpath, OPENWIRE_TYPE_OBJECT_ARRAY, iCommand, true);
            }
            else if (iCommand == OPENWIRE_CONNECTION_INFO)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_connectionid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_clientid, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_password, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_username, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_brokerpath, OPENWIRE_TYPE_OBJECT_ARRAY, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_brokermasterconnector, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_manageable, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_clientmaster, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_faulttolerant, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioninfo_failoverreconnect, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
            }
            else if (iCommand == OPENWIRE_CONNECTION_CONTROL)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioncontrol_close, OPENWIRE_TYPE_BOOLEAN, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioncontrol_exit, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioncontrol_faulttolerant, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioncontrol_resume, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioncontrol_suspend, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioncontrol_connectedbrokers, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioncontrol_reconnectto, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectioncontrol_rebalanceconnection, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
            }
            else if (iCommand == OPENWIRE_CONSUMER_INFO)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_consumerid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_browser, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_destination, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_prefetchsize, OPENWIRE_TYPE_INTEGER, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_maximumpendingmessagelimit, OPENWIRE_TYPE_INTEGER, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_dispatchasync, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_selector, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_subscriptionname, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_nolocal, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_exclusive, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_retroactive, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_priority, OPENWIRE_TYPE_BYTE, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_brokerpath, OPENWIRE_TYPE_OBJECT_ARRAY, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_additionalpredicate, OPENWIRE_TYPE_NESTED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_networksubscription, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_optimizedacknowledge, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_norangeacks, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumerinfo_networkconsumerpath, OPENWIRE_TYPE_OBJECT_ARRAY, iCommand, true);
            }
            else if (iCommand == OPENWIRE_PRODUCER_INFO)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_producerinfo_producerid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_producerinfo_destination, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_producerinfo_brokerpath, OPENWIRE_TYPE_OBJECT_ARRAY, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_producerinfo_dispatchasync, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_producerinfo_windowsize, OPENWIRE_TYPE_INTEGER, iCommand, false);
            }
            else if (iCommand == OPENWIRE_CONSUMER_CONTROL)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumercontrol_destination, OPENWIRE_TYPE_NESTED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumercontrol_close, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumercontrol_consumerid, OPENWIRE_TYPE_NESTED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumercontrol_prefetch, OPENWIRE_TYPE_INTEGER, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumercontrol_flush, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumercontrol_start, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_consumercontrol_stop, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
            }
            else if (iCommand == OPENWIRE_BROKER_INFO)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_brokerid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_brokerurl, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_peerbrokerinfos, OPENWIRE_TYPE_OBJECT_ARRAY, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_brokername, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_slavebroker, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_masterbroker, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_faulttolerantconfiguration, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_duplexconnection, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_networkconnection, OPENWIRE_TYPE_BOOLEAN, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_connectionid, OPENWIRE_TYPE_LONG, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_brokeruploadurl, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_brokerinfo_networkproperties, OPENWIRE_TYPE_STRING, iCommand, true);
            }
            else if (iCommand == OPENWIRE_TRANSACTION_INFO)
            {
                uint8_t iTransactionType;
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_transactioninfo_connectionid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_transactioninfo_transactionid, OPENWIRE_TYPE_CACHED, iCommand, true);
                if (tvb_reported_length_remaining(tvb, offset) >= 1)
                {
                    iTransactionType = tvb_get_uint8(tvb, offset);
                    offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_transactioninfo_type, OPENWIRE_TYPE_BYTE, iCommand, false);
                    proto_item_append_text(tree, " (%s)", val_to_str_ext(iTransactionType, &openwire_transaction_type_vals_ext, "Unknown (0x%02x)"));
                }
            }
            else if (iCommand == OPENWIRE_PRODUCER_ACK)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_producerack_producerid, OPENWIRE_TYPE_NESTED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_producerack_size, OPENWIRE_TYPE_INTEGER, iCommand, false);
            }
            else if (iCommand == OPENWIRE_REMOVE_INFO)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_removeinfo_objectid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_removeinfo_lastdeliveredsequenceid, OPENWIRE_TYPE_LONG, iCommand, false);
            }
            else if (iCommand == OPENWIRE_REMOVE_SUBSCRIPTION_INFO)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_removesubscriptioninfo_connectionid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_removesubscriptioninfo_subscriptionname, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_removesubscriptioninfo_clientid, OPENWIRE_TYPE_STRING, iCommand, true);
            }
            else if (iCommand == OPENWIRE_MESSAGE_DISPATCH)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagedispatch_consumerid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagedispatch_destination, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagedispatch_message, OPENWIRE_TYPE_NESTED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagedispatch_redeliverycounter, OPENWIRE_TYPE_INTEGER, iCommand, false);
            }
            else if (iCommand == OPENWIRE_MESSAGE_ACK)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messageack_destination, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messageack_transactionid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messageack_consumerid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messageack_acktype, OPENWIRE_TYPE_BYTE, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messageack_firstmessageid, OPENWIRE_TYPE_NESTED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messageack_lastmessageid, OPENWIRE_TYPE_NESTED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messageack_messagecount, OPENWIRE_TYPE_INTEGER, iCommand, false);
            }
            else if (iCommand == OPENWIRE_MESSAGE_PULL)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagepull_consumerid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagepull_destinationid, OPENWIRE_TYPE_CACHED, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagepull_timeout, OPENWIRE_TYPE_LONG, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagepull_correlationid, OPENWIRE_TYPE_STRING, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_messagepull_messageid, OPENWIRE_TYPE_NESTED, iCommand, true);
            }
            else if (iCommand == OPENWIRE_RESPONSE)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_response_correlationid, OPENWIRE_TYPE_INTEGER, iCommand, false);
            }
            else if (iCommand == OPENWIRE_DATA_RESPONSE)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_response_correlationid, OPENWIRE_TYPE_INTEGER, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_dataresponse_data, OPENWIRE_COMMAND_INNER, iCommand, true);
            }
            else if (iCommand == OPENWIRE_CONNECTION_ERROR)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectionerror_exception, OPENWIRE_TYPE_THROWABLE, iCommand, true);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_connectionerror_connectionid, OPENWIRE_TYPE_NESTED, iCommand, true);
            }
            else if (iCommand == OPENWIRE_EXCEPTION_RESPONSE)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_response_correlationid, OPENWIRE_TYPE_INTEGER, iCommand, false);
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_exceptionresponse_exception, OPENWIRE_TYPE_THROWABLE, iCommand, true);
            }
            else if (iCommand == OPENWIRE_CONTROL_COMMAND)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_controlcommand_command, OPENWIRE_TYPE_STRING, iCommand, true);
            }
            else if (iCommand == OPENWIRE_ACTIVEMQ_MESSAGE
                    || iCommand == OPENWIRE_ACTIVEMQ_BYTES_MESSAGE
                    || iCommand == OPENWIRE_ACTIVEMQ_MAP_MESSAGE
                    || iCommand == OPENWIRE_ACTIVEMQ_OBJECT_MESSAGE
                    || iCommand == OPENWIRE_ACTIVEMQ_STREAM_MESSAGE
                    || iCommand == OPENWIRE_ACTIVEMQ_TEXT_MESSAGE
                    || iCommand == OPENWIRE_ACTIVEMQ_BLOB_MESSAGE)
            {
                offset += dissect_openwire_type(tvb, pinfo, tree, offset, hf_openwire_none, iCommand, parentType, false);
            }
            else if (tvb_reported_length_remaining(tvb, offset) > 0)
            {
                expert_add_info_format(pinfo, tree, &ei_openwire_command_not_supported, "OpenWire command not supported by Wireshark: %d", iCommand);
            }
        }
    }
    return (offset - startOffset);
}

static int
dissect_openwire(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int         offset            = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OpenWire");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tvb_reported_length_remaining(tvb, offset) >= 5)
    {
        uint8_t     iCommand;
        proto_tree *openwireroot_tree;
        proto_item *ti;
        bool        caching;

        iCommand = tvb_get_uint8(tvb, offset + 4);

        col_append_sep_str(pinfo->cinfo, COL_INFO, " | ",
                            val_to_str_ext(iCommand, &openwire_opcode_vals_ext, "Unknown (0x%02x)"));
        col_set_fence(pinfo->cinfo, COL_INFO);

        detect_protocol_options(tvb, pinfo, offset, iCommand);

        ti = proto_tree_add_item(tree, proto_openwire, tvb, offset, -1, ENC_NA);
        proto_item_append_text(ti, " (%s)", val_to_str_ext(iCommand, &openwire_opcode_vals_ext, "Unknown (0x%02x)"));
        openwireroot_tree = proto_item_add_subtree(ti, ett_openwire);

        proto_tree_add_item(openwireroot_tree, hf_openwire_length, tvb, offset + 0, 4, ENC_BIG_ENDIAN);

        /* Abort dissection if tight encoding is enabled*/
        if (iCommand != OPENWIRE_WIREFORMAT_INFO && retrieve_tight(pinfo) == true)
        {
            proto_tree_add_item(openwireroot_tree, hf_openwire_command, tvb, offset + 4, 1, ENC_BIG_ENDIAN);
            expert_add_info(pinfo, openwireroot_tree, &ei_openwire_tight_encoding_not_supported);
            return tvb_captured_length(tvb);
        }

        caching = retrieve_caching(pinfo);
        if (caching)
        {
            proto_tree_add_boolean(openwireroot_tree, hf_openwire_cached_enabled, tvb, offset, 0, caching);
        }

        offset += 4;
        offset += dissect_openwire_command(tvb, pinfo, openwireroot_tree, offset, iCommand);
        if (tvb_reported_length_remaining(tvb, offset) > 0)
        {
            expert_add_info_format(pinfo, tree, &ei_openwire_command_not_supported, "OpenWire command fields unknown to Wireshark: %d", iCommand);
        }
    }

    return tvb_captured_length(tvb);
}

static unsigned
get_openwire_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (tvb_get_ntohl(tvb, offset) + 4);
}

static int
dissect_openwire_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, openwire_desegment, 5, get_openwire_pdu_len, dissect_openwire, data);
    return tvb_captured_length(tvb);
}


static bool
dissect_openwire_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conversation;
    bool        detected = false;

    if (tvb_reported_length(tvb) == 10 || tvb_reported_length(tvb) == 11)
    {
        /* KeepAlive is sent by default every 30 second.  It is 10 bytes (loose) or 11 bytes (tight) long. */
        if ((tvb_get_uint8(tvb, 4) == OPENWIRE_KEEP_ALIVE_INFO)
            && (tvb_get_ntohl(tvb, 0) + 4 == tvb_reported_length(tvb)))
        {
            detected = true;
        }
    }
    else if (tvb_reported_length(tvb) == 14 || tvb_reported_length(tvb) == 15)
    {
        /* Response is sent after several commands.  It is 14 bytes (loose) or 15 bytes (tight) long. */
        if ((tvb_get_uint8(tvb, 4) == OPENWIRE_RESPONSE)
            && (tvb_get_ntohl(tvb, 0) + 4 == tvb_reported_length(tvb)))
        {
            detected = true;
        }
    }
    else if (tvb_reported_length(tvb) >= 13)
    {
        /* Only the WIREFORMAT_INFO command contains a "magic". It is the first command sent on a connection.
           If the capture was started after this command, a manual "Decode As..." might be required.
           */
        if (tvb_captured_length(tvb) >= 10
            && (tvb_get_uint8(tvb, 4) == OPENWIRE_WIREFORMAT_INFO)
            && (tvb_get_ntohl(tvb, 5) == OPENWIRE_MAGIC_PART_1)
            && (tvb_get_ntohl(tvb, 9) == OPENWIRE_MAGIC_PART_2))
        {
            detected = true;
        }
    }
    if (detected)
    {
        /* Register this dissector for this conversation */
        conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, openwire_tcp_handle);

        /* Dissect the packet */
        dissect_openwire(tvb, pinfo, tree, data);
        return true;
    }
    return false;
}

void
proto_register_openwire(void)
{
    static hf_register_info hf[] = {
     { &hf_openwire_length,
        { "Length", "openwire.length", FT_UINT32, BASE_DEC, NULL, 0x0, "OpenWire length", HFILL }},

     { &hf_openwire_command,
        { "Command", "openwire.command", FT_UINT8, BASE_DEC, VALS(openwire_opcode_vals), 0x0, "Openwire command", HFILL }},

     { &hf_openwire_command_id,
        { "Command Id", "openwire.command.id", FT_UINT32, BASE_DEC, NULL, 0x0, "Openwire command id", HFILL }},

     { &hf_openwire_command_response_required,
        { "Command response required", "openwire.command.response_required", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire command response required", HFILL }},

     { &hf_openwire_response_correlationid,
        { "CorrelationId", "openwire.response.correlationid", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire Response CorrelationId", HFILL }},

     { &hf_openwire_dataresponse_data,
        { "Data", "openwire.responsedata.data", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ResponseData Data", HFILL }},

     { &hf_openwire_exceptionresponse_exception,
        { "Exception", "openwire.exceptionresponse.exception", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ExceptionResponse Exception", HFILL }},

     { &hf_openwire_connectionerror_exception,
        { "Exception", "openwire.connectionerror.exception", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConnectionError Exception", HFILL }},

     { &hf_openwire_connectionerror_connectionid,
        { "ConnectionId", "openwire.connectionerror.connectionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConnectionError ConnectionId", HFILL }},

     { &hf_openwire_controlcommand_command,
        { "Command", "openwire.controlcommand.command", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ControlCommand Command", HFILL }},

     { &hf_openwire_wireformatinfo_magic,
        { "Magic", "openwire.wireformatinfo.magic", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire WireFormatInfo Magic", HFILL }},

     { &hf_openwire_wireformatinfo_version,
        { "Version", "openwire.wireformatinfo.version", FT_UINT32, BASE_DEC, NULL, 0x0, "Openwire WireFormatInfo Version", HFILL }},

     { &hf_openwire_wireformatinfo_data,
        { "Data", "openwire.wireformatinfo.data", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire WireFormatInfo Data", HFILL }},

     { &hf_openwire_wireformatinfo_length,
        { "Length", "openwire.wireformatinfo.length", FT_UINT32, BASE_DEC, NULL, 0x0, "Openwire WireFormatInfo Length", HFILL }},

     { &hf_openwire_sessioninfo_sessionid,
        { "SessionId", "openwire.sessioninfo.sessionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire SessionInfo SessionId", HFILL }},

     { &hf_openwire_destinationinfo_connectionid,
        { "ConnectionId", "openwire.destinationinfo.connectionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire DestinationInfo ConnectionId", HFILL }},

     { &hf_openwire_destinationinfo_destination,
        { "Destination", "openwire.destinationinfo.destination", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire DestinationInfo Destination", HFILL }},

     { &hf_openwire_destinationinfo_operationtype,
        { "OperationType", "openwire.destinationinfo.operationtype", FT_UINT8, BASE_DEC, VALS(openwire_operation_type_vals), 0x0, "Openwire DestinationInfo OperationType", HFILL }},

     { &hf_openwire_destinationinfo_timeout,
        { "Timeout", "openwire.destinationinfo.timeout", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire DestinationInfo Timeout", HFILL }},

     { &hf_openwire_destinationinfo_brokerpath,
        { "BrokerPath", "openwire.destinationinfo.brokerpath", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire DestinationInfo BrokerPath", HFILL }},

     { &hf_openwire_brokerinfo_brokerid,
        { "BrokerId", "openwire.brokerinfo.brokerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire BrokerInfo BrokerId", HFILL }},

     { &hf_openwire_brokerinfo_brokerurl,
        { "BrokerURL", "openwire.brokerinfo.brokerurl", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire BrokerInfo BrokerURL", HFILL }},

     { &hf_openwire_brokerinfo_peerbrokerinfos,
        { "PeerBrokerInfos", "openwire.brokerinfo.peerbrokerinfos", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire BrokerInfo PeerBrokerInfos", HFILL }},

     { &hf_openwire_brokerinfo_brokername,
        { "BrokerName", "openwire.brokerinfo.brokername", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire BrokerInfo BrokerName", HFILL }},

     { &hf_openwire_brokerinfo_slavebroker,
        { "SlaveBroker", "openwire.brokerinfo.slavebroker", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire BrokerInfo SlaveBroker", HFILL }},

     { &hf_openwire_brokerinfo_masterbroker,
        { "MasterBroker", "openwire.brokerinfo.masterbroker", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire BrokerInfo MasterBroker", HFILL }},

     { &hf_openwire_brokerinfo_faulttolerantconfiguration,
        { "FaultTolerantConfiguration", "openwire.brokerinfo.faulttolerantconfiguration", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire BrokerInfo FaultTolerantConfiguration", HFILL }},

     { &hf_openwire_brokerinfo_duplexconnection,
        { "DuplexConnection", "openwire.brokerinfo.duplexconnection", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire BrokerInfo DuplexConnection", HFILL }},

     { &hf_openwire_brokerinfo_networkconnection,
        { "NetworkConnection", "openwire.brokerinfo.networkconnection", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire BrokerInfo NetworkConnection", HFILL }},

     { &hf_openwire_brokerinfo_connectionid,
        { "ConnectionId", "openwire.brokerinfo.connectionid", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire BrokerInfo ConnectionId", HFILL }},

     { &hf_openwire_brokerinfo_brokeruploadurl,
        { "BrokerUploadUrl", "openwire.brokerinfo.brokeruploadurl", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire BrokerInfo BrokerUploadUrl", HFILL }},

     { &hf_openwire_brokerinfo_networkproperties,
        { "NetworkProperties", "openwire.brokerinfo.networkproperties", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire BrokerInfo NetworkProperties", HFILL }},

     { &hf_openwire_connectioninfo_connectionid,
        { "ConnectionId", "openwire.connectioninfo.connectionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConnectionInfo ConnectionId", HFILL }},

     { &hf_openwire_connectioninfo_clientid,
        { "ClientId", "openwire.connectioninfo.clientid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConnectionInfo ClientId", HFILL }},

     { &hf_openwire_connectioninfo_password,
        { "Password", "openwire.connectioninfo.password", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConnectionInfo Password", HFILL }},

     { &hf_openwire_connectioninfo_username,
        { "UserName", "openwire.connectioninfo.username", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConnectionInfo UserName", HFILL }},

     { &hf_openwire_connectioninfo_brokerpath,
        { "BrokerPath", "openwire.connectioninfo.brokerpath", FT_BYTES, BASE_NONE, NULL, 0x0, "Openwire ConnectionInfo BrokerPath", HFILL }},

     { &hf_openwire_connectioninfo_brokermasterconnector,
        { "BrokerMasterConnector", "openwire.connectioninfo.brokermasterconnector", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionInfo BrokerMasterConnector", HFILL }},

     { &hf_openwire_connectioninfo_manageable,
        { "Manageable", "openwire.connectioninfo.manageable", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionInfo Manageable", HFILL }},

     { &hf_openwire_connectioninfo_clientmaster,
        { "ClientMaster", "openwire.connectioninfo.clientmaster", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionInfo ClientMaster", HFILL }},

     { &hf_openwire_connectioninfo_faulttolerant,
        { "FaultTolerant", "openwire.connectioninfo.faulttolerant", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionInfo FaultTolerant", HFILL }},

     { &hf_openwire_connectioninfo_failoverreconnect,
        { "FailoverReconnect", "openwire.connectioninfo.failoverreconnect", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionInfo FailoverReconnect", HFILL } },

     { &hf_openwire_consumerinfo_consumerid,
        { "ConsumerId", "openwire.consumerinfo.consumerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConsumerInfo ConsumerId", HFILL }},

     { &hf_openwire_consumerinfo_browser,
        { "Browser", "openwire.consumerinfo.browser", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo Browser", HFILL }},

     { &hf_openwire_consumerinfo_destination,
        { "Destination", "openwire.consumerinfo.destination", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConsumerInfo Destination", HFILL }},

     { &hf_openwire_consumerinfo_prefetchsize,
        { "PrefetchSize", "openwire.consumerinfo.prefetchsize", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo PrefetchSize", HFILL }},

     { &hf_openwire_consumerinfo_maximumpendingmessagelimit,
        { "MaximumPendingMessageLimit", "openwire.consumerinfo.maximumpendingmessagelimit", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo MaximumPendingMessageLimit", HFILL }},

     { &hf_openwire_consumerinfo_dispatchasync,
        { "DispatchAsync", "openwire.consumerinfo.dispatchasync", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo DispatchAsync", HFILL }},

     { &hf_openwire_consumerinfo_selector,
        { "Selector", "openwire.consumerinfo.selector", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConsumerInfo Selector", HFILL }},

     { &hf_openwire_consumerinfo_subscriptionname,
        { "SubscriptionName", "openwire.consumerinfo.subscriptionname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConsumerInfo SubscriptionName", HFILL }},

     { &hf_openwire_consumerinfo_nolocal,
        { "NoLocal", "openwire.consumerinfo.nolocal", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo NoLocal", HFILL }},

     { &hf_openwire_consumerinfo_exclusive,
        { "Exclusive", "openwire.consumerinfo.exclusive", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo Exclusive", HFILL }},

     { &hf_openwire_consumerinfo_retroactive,
        { "RetroActive", "openwire.consumerinfo.retroactive", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo RetroActive", HFILL }},

     { &hf_openwire_consumerinfo_priority,
        { "Priority", "openwire.consumerinfo.priority", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo Priority", HFILL }},

     { &hf_openwire_consumerinfo_brokerpath,
        { "BrokerPath", "openwire.consumerinfo.brokerpath", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConsumerInfo BrokerPath", HFILL }},

     { &hf_openwire_consumerinfo_additionalpredicate,
        { "AdditionalPredicate", "openwire.consumerinfo.additionalpredicate", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConsumerInfo AdditionalPredicate", HFILL   }},

     { &hf_openwire_consumerinfo_networksubscription,
        { "NetworkSubscription", "openwire.consumerinfo.networksubscription", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo NetworkSubscription", HFILL   }},

     { &hf_openwire_consumerinfo_optimizedacknowledge,
        { "OptimizedAcknowledge", "openwire.consumerinfo.optimizedacknowledge", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo OptimizedAcknowledge",  HFILL }},

     { &hf_openwire_consumerinfo_norangeacks,
        { "NoRangeAcks", "openwire.consumerinfo.norangeacks", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerInfo NoRangeAcks", HFILL }},

     { &hf_openwire_consumerinfo_networkconsumerpath,
        { "NetworkConsumerPath", "openwire.consumerinfo.networkconsumerpath", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConsumerInfo NetworkConsumerPath", HFILL   }},

     { &hf_openwire_consumercontrol_destination,
        { "Destination", "openwire.consumercontrol.destination", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConsumerControl Destination", HFILL }},

     { &hf_openwire_consumercontrol_close,
        { "Close", "openwire.consumercontrol.close", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerControl Close", HFILL }},

     { &hf_openwire_consumercontrol_consumerid,
        { "ConsumerId", "openwire.consumercontrol.consumerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ConsumerControl ConsumerId", HFILL }},

     { &hf_openwire_consumercontrol_prefetch,
        { "Prefetch", "openwire.consumercontrol.prefetch", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire ConsumerControl Prefetch", HFILL }},

     { &hf_openwire_consumercontrol_flush,
        { "Flush", "openwire.consumercontrol.flush", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerControl Flush", HFILL }},

     { &hf_openwire_consumercontrol_start,
        { "Start", "openwire.consumercontrol.start", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerControl Start", HFILL }},

     { &hf_openwire_consumercontrol_stop,
        { "Stop", "openwire.consumercontrol.stop", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConsumerControl Stop", HFILL }},

     { &hf_openwire_connectioncontrol_close,
        { "Close", "openwire.connectioncontrol.close", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionControl Close", HFILL }},

     { &hf_openwire_connectioncontrol_exit,
        { "Exit", "openwire.connectioncontrol.exit", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionControl Exit", HFILL }},

     { &hf_openwire_connectioncontrol_faulttolerant,
        { "FaultTolerant", "openwire.connectioncontrol.faulttolerant", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionControl FaultTolerant", HFILL }},

     { &hf_openwire_connectioncontrol_resume,
        { "Resume", "openwire.connectioncontrol.resume", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionControl Resume", HFILL }},

     { &hf_openwire_connectioncontrol_suspend,
        { "Suspend", "openwire.connectioncontrol.suspend", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionControl Suspend", HFILL }},

     { &hf_openwire_connectioncontrol_connectedbrokers,
        { "ConnectedBrokers", "openwire.connectioncontrol.connectedbrokers", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConnectionControl ConnectedBrokers",  HFILL }},

     { &hf_openwire_connectioncontrol_reconnectto,
        { "ReconnectTo", "openwire.connectioncontrol.reconnectto", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConnectionControl ReconnectTo", HFILL }},

     { &hf_openwire_connectioncontrol_rebalanceconnection,
        { "RebalanceConnection", "openwire.connectioncontrol.rebalanceconnection", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ConnectionControl RebalanceConnection", HFILL }},

     { &hf_openwire_removeinfo_objectid,
        { "ObjectId", "openwire.removeinfo.objectid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire RemoveInfo ObjectId", HFILL }},

     { &hf_openwire_removeinfo_lastdeliveredsequenceid,
        { "LastDeliveredSequenceId", "openwire.removeinfo.lastdeliveredsequenceid", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire RemoveInfo LastDeliveredSequenceId" ,  HFILL }},

     { &hf_openwire_removesubscriptioninfo_connectionid,
        { "ConnectionId", "openwire.removesubscriptioninfo.connectionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire RemoveSubscriptionInfo ConnectionId", HFILL  } },

     { &hf_openwire_removesubscriptioninfo_subscriptionname,
        { "SubscriptionName", "openwire.removesubscriptioninfo.subscriptionname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire RemoveSubscriptionInfo SubscriptionName", HFILL }},

     { &hf_openwire_removesubscriptioninfo_clientid,
        { "ClientId", "openwire.removesubscriptioninfo.clientid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire RemoveSubscriptionInfo ClientId", HFILL }},

     { &hf_openwire_producerinfo_producerid,
        { "ProducerId", "openwire.producerinfo.producerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ProducerInfo ProducerId", HFILL }},

     { &hf_openwire_producerinfo_destination,
        { "Destination", "openwire.producerinfo.destination", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ProducerInfo Destination", HFILL }},

     { &hf_openwire_producerinfo_brokerpath,
        { "BrokerPath", "openwire.producerinfo.brokerpath", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ProducerInfo BrokerPath", HFILL }},

     { &hf_openwire_producerinfo_dispatchasync,
        { "DispatchAsync", "openwire.producerinfo.dispatchasync", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire ProducerInfo DispatchAsync", HFILL }},

     { &hf_openwire_producerinfo_windowsize,
        { "WindowSize", "openwire.producerinfo.windowsize", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire ProducerInfo WindowSize", HFILL }},

     { &hf_openwire_transactioninfo_connectionid,
        { "ConnectionId", "openwire.transactioninfo.connectionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire TransactionInfo ConnectionId", HFILL }},

     { &hf_openwire_transactioninfo_transactionid,
        { "TransactionId", "openwire.transactioninfo.transactionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire TransactionInfo TransactionId", HFILL }},

     { &hf_openwire_transactioninfo_type,
        { "Type", "openwire.transactioninfo.type", FT_UINT8, BASE_DEC, VALS(openwire_transaction_type_vals), 0x0, "Openwire TransactionInfo Type", HFILL }},

     { &hf_openwire_producerack_producerid,
        { "ProducerId", "openwire.producerack.producerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire ProducerAck ProducerId", HFILL }},

     { &hf_openwire_producerack_size,
        { "Size", "openwire.producerack.size", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire ProducerAck Size", HFILL }},

     { &hf_openwire_messagedispatch_consumerid,
        { "ConsumerId", "openwire.messagedispatch.consumerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageDispatch ConsumerId", HFILL }},

     { &hf_openwire_messagedispatch_destination,
        { "Destination", "openwire.messagedispatch.destination", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageDispatch Destination", HFILL }},

     { &hf_openwire_messagedispatch_message,
        { "Message", "openwire.messagedispatch.message", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageDispatch Message", HFILL }},

     { &hf_openwire_messagedispatch_redeliverycounter,
        { "RedeliveryCounter", "openwire.messagedispatch.redeliverycounter", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire MessageDispatch RedeliveryCounter", HFILL }},

     { &hf_openwire_messageack_destination,
        { "Destination", "openwire.messageack.destination", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageAck Destination", HFILL }},

     { &hf_openwire_messageack_transactionid,
        { "TransactionId", "openwire.messageack.transactionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageAck TransactionId", HFILL }},

     { &hf_openwire_messageack_consumerid,
        { "ConsumerId", "openwire.messageack.consumerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageAck ConsumerId", HFILL }},

     { &hf_openwire_messageack_acktype,
        { "AckType", "openwire.messageack.acktype", FT_UINT8, BASE_DEC, VALS(openwire_message_ack_type_vals), 0x0, "Openwire MessageAck AckType", HFILL }},

     { &hf_openwire_messageack_firstmessageid,
        { "FirstMessageId", "openwire.messageack.firstmessageid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageAck FirstMessageId", HFILL }},

     { &hf_openwire_messageack_lastmessageid,
        { "LastMessageId", "openwire.messageack.lastmessageid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageAck LastMessageId", HFILL }},

     { &hf_openwire_messageack_messagecount,
        { "MessageCount", "openwire.messageack.messagecount", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire MessageAck MessageCount", HFILL }},

     { &hf_openwire_messagepull_consumerid,
        { "ConsumerId", "openwire.messagepull.consumerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessagePull ConsumerId", HFILL }},

     { &hf_openwire_messagepull_destinationid,
        { "DestinationId", "openwire.messagepull.destinationid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessagePull DestinationId", HFILL }},

     { &hf_openwire_messagepull_timeout,
        { "Timeout", "openwire.messagepull.timeout", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire MessagePull Timeout", HFILL }},

     { &hf_openwire_messagepull_correlationid,
        { "CorrelationId", "openwire.messagepull.correlationid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire MessagePull CorrelationId", HFILL }},

     { &hf_openwire_messagepull_messageid,
        { "MessageId", "openwire.messagepull.messageid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessagePull MessageId", HFILL }},

     { &hf_openwire_message_producerid,
        { "ProducerId", "openwire.message.producerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message ProducerID", HFILL }},

     { &hf_openwire_message_destination,
        { "Destination", "openwire.message.destination", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message Destination", HFILL }},

     { &hf_openwire_message_transactionid,
        { "TransactionId", "openwire.message.transactionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message TransactionId", HFILL }},

     { &hf_openwire_message_originaldestination,
        { "OriginalDestination", "openwire.message.originaldestination", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message OriginalDestination", HFILL }},

     { &hf_openwire_message_messageid,
        { "MessageId", "openwire.message.messageid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message MessageId", HFILL }},

     { &hf_openwire_message_originaldestinationid,
        { "OriginalDestinationId", "openwire.message.originaldestinationid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message OriginalDestinationId", HFILL }},

     { &hf_openwire_message_groupid,
        { "GroupID", "openwire.message.groupid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire message GroupID", HFILL }},

     { &hf_openwire_message_groupsequence,
        { "GroupSequence", "openwire.message.groupsequence", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire message GroupSequence", HFILL }},

     { &hf_openwire_message_correlationid,
        { "CorrelationId", "openwire.message.correlationid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire message CorrelationID", HFILL }},

     { &hf_openwire_message_persistent,
        { "Persistent", "openwire.message.persistent", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire message Persistent", HFILL }},

     { &hf_openwire_message_expiration,
        { "Expiration", "openwire.message.expiration", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire message Expiration", HFILL }},

     { &hf_openwire_message_priority,
        { "Priority", "openwire.message.priority", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire message Priority", HFILL }},

     { &hf_openwire_message_replyto,
        { "ReplyTo", "openwire.message.replyto", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message ReplyTo", HFILL }},

     { &hf_openwire_message_timestamp,
        { "Timestamp", "openwire.message.timestamp", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire message Timestamp", HFILL }},

     { &hf_openwire_message_type,
        { "Type", "openwire.message.type", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire message Type", HFILL }},

     { &hf_openwire_message_body,
        { "Body", "openwire.message.body", FT_BYTES, BASE_NONE, NULL, 0x0, "Openwire message Body", HFILL }},

     { &hf_openwire_message_properties,
        { "Properties", "openwire.message.properties", FT_BYTES, BASE_NONE, NULL, 0x0, "Openwire message Properties", HFILL }},

     { &hf_openwire_message_datastructure,
        { "DataStructure", "openwire.message.datastructure", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message DataStructure", HFILL }},

     { &hf_openwire_message_targetconsumerid,
        { "TargetConsumerId", "openwire.message.targetconsumerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message TargetConsumerId", HFILL }},

     { &hf_openwire_message_compressed,
        { "Compressed", "openwire.message.compressed", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire message Compressed", HFILL }},

     { &hf_openwire_message_redeliverycount,
        { "RedeliveryCount", "openwire.message.redeliverycount", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire message RedeliveryCount", HFILL }},

     { &hf_openwire_message_brokerpath,
        { "BrokerPath", "openwire.message.brokerpath", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message BrokerPath", HFILL }},

     { &hf_openwire_message_arrival,
        { "Arrival", "openwire.message.arrival", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire message Arrival", HFILL }},

     { &hf_openwire_message_userid,
        { "UserID", "openwire.message.userid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire message UserID", HFILL }},

     { &hf_openwire_message_receivedbydfbridge,
        { "ReceivedByDFBridge", "openwire.message.receivedbydfbridge", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire message ReceivedByDFBridge", HFILL }},

     { &hf_openwire_message_droppable,
        { "Droppable", "openwire.message.droppable", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire message Droppable", HFILL }},

     { &hf_openwire_message_cluster,
        { "Cluster", "openwire.message.cluster", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire message Cluster", HFILL }},

     { &hf_openwire_message_brokerintime,
        { "BrokerInTime", "openwire.message.brokerintime", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire message BrokerInTime", HFILL }},

     { &hf_openwire_message_brokerouttime,
        { "BrokerOutTime", "openwire.message.brokerouttime", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire message BrokerOutTime", HFILL }},

     { &hf_openwire_producerid_connectionid,
        { "ConnectionId", "openwire.producerid.connectionid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ProducerId ConnectionId", HFILL }},

     { &hf_openwire_producerid_value,
        { "Value", "openwire.producerid.value", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire ProducerId Value", HFILL }},

     { &hf_openwire_producerid_sessionid,
        { "SessionId", "openwire.producerid.sessionid", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire ProducerId SessionId", HFILL }},

     { &hf_openwire_consumerid_connectionid,
        { "ConnectionId", "openwire.consumerid.connectionid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConsumerId ConnectionId", HFILL }},

     { &hf_openwire_consumerid_value,
        { "Value", "openwire.consumerid.value", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire ConsumerId Value", HFILL }},

     { &hf_openwire_consumerid_sessionid,
        { "SessionId", "openwire.consumerid.sessionid", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire ConsumerId SessionId", HFILL }},

     { &hf_openwire_destination_name,
        { "Name", "openwire.destination.name", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire Destination Name", HFILL }},

     { &hf_openwire_messageid_producerid,
        { "ProducerId", "openwire.messageid.producerid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire MessageId ProducerId", HFILL }},

     { &hf_openwire_messageid_producersequenceid,
        { "ProducerSequenceId", "openwire.messageid.producersequenceid", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire MessageId ProducerSequenceId", HFILL }},

     { &hf_openwire_messageid_brokersequenceid,
        { "BrokerSequenceId", "openwire.messageid.brokersequenceid", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire MessageId BrokerSequenceId", HFILL }},

     { &hf_openwire_connectionid_value,
        { "Value", "openwire.connectionid.value", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire ConnectionId Value", HFILL }},

     { &hf_openwire_sessionid_connectionid,
        { "ConnectionId", "openwire.sessionid.connectionid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire SessionId ConnectionId", HFILL }},

     { &hf_openwire_sessionid_value,
        { "Value", "openwire.sessionid.value", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire SessionId Value", HFILL }},

     { &hf_openwire_brokerid_value,
        { "Value", "openwire.brokerid.value", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire BrokerId Value", HFILL }},

     { &hf_openwire_localtransactionid_value,
        { "Value", "openwire.localtransactionid.value", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire LocalTransactionId Value", HFILL }},

     { &hf_openwire_localtransactionid_connectionid,
        { "ConnectionId", "openwire.localtransactionid.connectionid", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire LocalTransactionId ConnecctionId", HFILL }},

     { &hf_openwire_xatransactionid_formatid,
        { "FormatId", "openwire.xatransactionid.formatid", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire XATransactionId FormatId", HFILL }},

     { &hf_openwire_xatransactionid_globaltransactionid,
        { "GlobalTransactionId", "openwire.xatransactionid.globaltransactionid", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire XATransactionId GlobalTransactionId", HFILL }},

     { &hf_openwire_xatransactionid_branchqualifier,
        { "BranchQualifier", "openwire.xatransactionid.branchqualifier", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire XATransactionId BranchQualifier", HFILL }},

     { &hf_openwire_none,
        { "Generic field", "openwire.generic", FT_BYTES, BASE_NONE, NULL, 0x0, "Openwire integer type", HFILL }},

     { &hf_openwire_map_length,
        { "Length", "openwire.map.length", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire map length", HFILL }},

     { &hf_openwire_map_key,
        { "Key", "openwire.map.key", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire map Key", HFILL }},

     { &hf_openwire_map_entry,
        { "Entry", "openwire.map.entry", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire map Entry", HFILL }},

     { &hf_openwire_throwable_class,
        { "Class", "openwire.throwable.class", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire Throwable Class", HFILL }},

     { &hf_openwire_throwable_message,
        { "Message", "openwire.throwable.message", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire Throwable Message", HFILL }},

     { &hf_openwire_throwable_element,
        { "Element", "openwire.throwable.element", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire Throwable Element", HFILL }},

     { &hf_openwire_throwable_classname,
        { "ClassName", "openwire.throwable.classname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire Throwable ClassName", HFILL }},

     { &hf_openwire_throwable_methodname,
        { "MethodName", "openwire.throwable.methodname", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire Throwable MethodName", HFILL }},

     { &hf_openwire_throwable_filename,
        { "FileName", "openwire.throwable.filename", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire Throwable FileName", HFILL }},

     { &hf_openwire_throwable_linenumber,
        { "LineNumber", "openwire.throwable.linenumber", FT_UINT32, BASE_DEC, NULL, 0x0, "Openwire Throwable LineNumber", HFILL }},

     { &hf_openwire_type_integer,
        { "Integer", "openwire.type.integer", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire Integer type", HFILL }},

     { &hf_openwire_type_short,
        { "Short", "openwire.type.short", FT_INT32, BASE_DEC, NULL, 0x0, "Openwire Short type", HFILL }},

     { &hf_openwire_type_string,
        { "String", "openwire.type.string", FT_STRINGZ, BASE_NONE, NULL, 0x0, "Openwire String type", HFILL }},

     { &hf_openwire_type_bytes,
        { "Bytes", "openwire.type.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, "Openwire Bytes type", HFILL }},

     { &hf_openwire_type_boolean,
        { "Boolean", "openwire.type.boolean", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire Boolean type", HFILL }},

     { &hf_openwire_type_byte,
        { "Byte", "openwire.type.byte", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire Byte type", HFILL }},

     { &hf_openwire_type_char,
        { "Char", "openwire.type.char", FT_UINT16, BASE_DEC, NULL, 0x0, "Openwire Char type", HFILL }},

     { &hf_openwire_type_long,
        { "Long", "openwire.type.long", FT_INT64, BASE_DEC, NULL, 0x0, "Openwire Cong type", HFILL }},

     { &hf_openwire_type_float,
        { "Float", "openwire.type.float", FT_FLOAT, BASE_NONE, NULL, 0x0, "Openwire Float type", HFILL }},

     { &hf_openwire_type_double,
        { "Double", "openwire.type.double", FT_DOUBLE, BASE_NONE, NULL, 0x0, "Openwire Double type", HFILL }},

     { &hf_openwire_type_notnull,
        { "NotNull", "openwire.type.notnull", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire NotNull type", HFILL }},

     { &hf_openwire_cached_inlined,
        { "Inlined", "openwire.cached.inlined", FT_UINT8, BASE_DEC, NULL, 0x0, "Openwire Cached Inlined", HFILL }},

     { &hf_openwire_cached_id,
        { "CachedID", "openwire.cached.id", FT_UINT16, BASE_DEC, NULL, 0x0, "Openwire Cached ID", HFILL }},

     { &hf_openwire_cached_enabled,
        { "CachedEnabled", "openwire.cached.enabled", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Openwire Cached Enabled", HFILL }},

     { &hf_openwire_type_object,
        { "Object", "openwire.type.object", FT_NONE, BASE_NONE, NULL, 0x0, "Openwire object", HFILL }},

     { &hf_openwire_type,
        { "Type", "openwire.type", FT_UINT8, BASE_DEC, VALS(openwire_type_vals), 0x0, "Openwire type", HFILL }}

    };
    static int *ett[] = {
        &ett_openwire,
        &ett_openwire_type
    };

    static ei_register_info ei[] = {
        { &ei_openwire_encoding_not_supported, { "openwire.encoding_not_supported", PI_PROTOCOL, PI_WARN, "OpenWire encoding not supported by Wireshark or dissector bug", EXPFILL }},
        { &ei_openwire_body_type_not_supported, { "openwire.body_type_not_supported", PI_UNDECODED, PI_NOTE, "OpenWire body type not supported by Wireshark", EXPFILL }},
        { &ei_openwire_type_not_supported, { "openwire.type.not_supported", PI_UNDECODED, PI_NOTE, "OpenWire type not supported by Wireshark", EXPFILL }},
        { &ei_openwire_command_not_supported, { "openwire.command.not_supported", PI_UNDECODED, PI_NOTE, "OpenWire command not supported by Wireshark", EXPFILL }},
        { &ei_openwire_tight_encoding_not_supported, { "openwire.tight_encoding_not_supported", PI_UNDECODED, PI_NOTE, "OpenWire tight encoding not supported by Wireshark", EXPFILL }},
    };

    module_t *openwire_module;
    expert_module_t* expert_openwire;

    proto_openwire = proto_register_protocol("OpenWire", "OpenWire", "openwire");
    proto_register_field_array(proto_openwire, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_openwire = expert_register_protocol(proto_openwire);
    expert_register_field_array(expert_openwire, ei, array_length(ei));

    openwire_tcp_handle = register_dissector("openwire", dissect_openwire_tcp, proto_openwire);

    openwire_module = prefs_register_protocol(proto_openwire, NULL);
    prefs_register_bool_preference(openwire_module, "desegment",
        "Reassemble Openwire messages spanning multiple TCP segments",
        "Whether the Openwire dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &openwire_desegment);
    prefs_register_bool_preference(openwire_module, "verbose_type",
        "Show verbose type information",
        "Whether verbose type and length information are displayed in the protocol tree",
        &openwire_verbose_type);
}

void
proto_reg_handoff_openwire(void)
{
    heur_dissector_add("tcp", dissect_openwire_heur, "OpenWire over TCP", "openwire_tcp", proto_openwire, HEURISTIC_ENABLE);
    dissector_add_for_decode_as_with_preference("tcp.port", openwire_tcp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
