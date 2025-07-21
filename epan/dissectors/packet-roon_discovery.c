/* packet-roon_discovery.c
 * Routines for Roon Discovery dissection
 * Copyright 2022, Aaron Turner <synfinatic@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Roon Discovery is used by devices running "Roon" from roonlabs.com
 * to discover streaming endpoints and the "Roon Core".  Reverse engineered
 * as no public documentation exists.
 */

#include <config.h>
#include <stdlib.h>
#include <ctype.h>

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/tap.h>
#include <wireshark.h>
#include <wsutil/str_util.h>

// Transaction tracking structure
typedef struct _roon_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    nstime_t rqst_time;
    nstime_t resp_time;
} roon_transaction_t;

// roon conversation information
typedef struct _roon_conv_info_t {
    wmem_tree_t *unmatched_pdus;
    wmem_tree_t *matched_pdus;
} roon_conv_info_t;

// Roon field mapping
typedef struct {
    char *key;
    char *name;
    int *value;
} roon_map;

// Roon UUID mapping
typedef struct {
    char *uuid;
    char *name;
} roon_uuid_map;

// Prototypes
void proto_reg_handoff_roon_discover(void);
void proto_register_roon_discover(void);
conversation_t *roon_find_or_create_conversation(packet_info *pinfo,
                                                 bool ephemeral);
static roon_transaction_t *transaction_start(packet_info *pinfo,
                                             proto_tree *tree,
                                             char *tid,
                                             bool ephemeral);
static roon_transaction_t *transaction_end(packet_info *pinfo,
                                           proto_tree *tree,
                                           char *tid);

// Global variables
static dissector_handle_t roon_discover_handle;
static int roon_tap;

// Initialize the protocol and registered fields
static int proto_roon_discover;
static int hf_roon_disco_config_version;
static int hf_roon_disco_device_type;
static int hf_roon_disco_device_class;
static int hf_roon_disco_direction;
static int hf_roon_disco_display_version;
static int hf_roon_disco_http_port;
static int hf_roon_disco_https_port;
static int hf_roon_disco_is_dev;
static int hf_roon_disco_machine_id;
static int hf_roon_disco_machine_name;
static int hf_roon_disco_marker;
static int hf_roon_disco_name;
static int hf_roon_disco_os_version;
static int hf_roon_disco_protocol_version;
static int hf_roon_disco_protocol_hash;
static int hf_roon_disco_query_service_id;
static int hf_roon_disco_raat_version;
static int hf_roon_disco_service_id;
static int hf_roon_disco_tcp_port;
static int hf_roon_disco_tid;
static int hf_roon_disco_unique_id;
static int hf_roon_disco_user_id;

// transaction tracking
static int hf_roon_disco_resp_in;
static int hf_roon_disco_resp_to;
static int hf_roon_disco_resptime;
static int hf_roon_disco_no_resp;


#define ROON_DISCOVERY_ID "SOOD"
#define ROON_QUERY 0x0251 // Q(uery)
#define ROON_REPLY 0x0252 // R(eply)
#define ROON_DISCOVERY_UDP_PORT 9003 // Not IANA-assigned
#define ROON_DISCOVERY_MIN_LENGTH 98 // empirically defined

// Initialize the subtree pointers
static int ett_roon_discover;

// table to map field keys to our protocol tree entry.  The order of entries
// must be sorted by they key field.
static const roon_map roon_disco_string_fields[] = {
    { "_tid"             , "TransactionID"    , &hf_roon_disco_tid }              ,
    { "config_version"   , "Config Version"   , &hf_roon_disco_config_version }   ,
    { "device_class"     , "Device Class"     , &hf_roon_disco_device_class }     ,
    { "device_type"      , "Device Type"      , &hf_roon_disco_device_type }      ,
    { "direction"        , "Direction"        , &hf_roon_disco_direction }        ,
    { "display_version"  , "Display Version"  , &hf_roon_disco_display_version }  ,
    { "http_port"        , "HTTP Port"        , &hf_roon_disco_http_port }        ,
    { "https_port"       , "HTTPS Port"       , &hf_roon_disco_https_port }       ,
    { "machine_id"       , "MachineID"        , &hf_roon_disco_machine_id }       ,
    { "machine_name"     , "Machine Name"     , &hf_roon_disco_machine_name }     ,
    { "marker"           , "Discovery Marker" , &hf_roon_disco_marker }           ,
    { "name"             , "Host Name"        , &hf_roon_disco_name }             ,
    { "os_version"       , "OS Version"       , &hf_roon_disco_os_version }       ,
    { "protocol_hash"    , "Protocol Hash"    , &hf_roon_disco_protocol_hash }    ,
    { "protocol_version" , "Protocol Version" , &hf_roon_disco_protocol_version } ,
    { "query_service_id" , "Query ServiceID"  , &hf_roon_disco_query_service_id } ,
    { "raat_version"     , "RAAT Version"     , &hf_roon_disco_raat_version }     ,
    { "service_id"       , "ServiceID"        , &hf_roon_disco_service_id }       ,
    { "tcp_port"         , "TCP Port"         , &hf_roon_disco_tcp_port }         ,
    { "unique_id"        , "UniqueID"         , &hf_roon_disco_unique_id }        ,
    { "user_id"          , "UserID"           , &hf_roon_disco_user_id }          ,
    { NULL               , NULL               , NULL }                            ,
};

static const roon_map roon_disco_bool_fields[] = {
    { "is_dev" , "Devel Version" , &hf_roon_disco_is_dev } ,
    { NULL     , NULL            , NULL }                  ,
};

#define ROON_DISCOVERY_ALT_METHOD "d7634b85-8190-470f-aa51-6cb5538dc1b9" // this is the discovery that happens over ephemeral ports
// Roon ServiceIDs and their names.  Must be sorted by uuid.
static const roon_uuid_map roon_service_ids[] = {
    {"00720724-5143-4a9b-abac-0e50cba674bb", "Roon Node.js"}  , // Roon Node.js SDK https://github.com/RoonLabs/node-roon-api/blob/master/lib.js#L137
    {"5a955bb8-9673-4f8d-9437-4c6b7b18fba8", "Roon Endpoint"} , // audio output available for Roon (bridge, RoonApp, etc)
    {"d52b2cb7-02c5-48fc-981b-a10f0aadd93b", "Roon Server"}   , // query on broadcast:9003, replies from udp/9003
    {ROON_DISCOVERY_ALT_METHOD,              "Roon DiscoAlt"} , // Both clients and servers do this ephemeral discovery thing
    {NULL,                                   NULL}            ,
};

// compares two roon_map entries by their key
static int
compare_keys(const void *va, const void *vb) {
    const roon_map *a = va, *b = vb;
    return strcmp(a->key, b->key);
}

static size_t
roon_map_length(const roon_map rm[]) {
    size_t len = 0;
    while (rm[len].key != NULL) {
        len++;
    }
    return len;
}

// returns the value of key from the roon_map or NULL
static int *
roon_map_value(char *key, const roon_map rm[]) {
    size_t len = roon_map_length(rm);
    roon_map map[1] = {{ key, NULL, NULL }};
    roon_map *pair = bsearch(map, rm, len, sizeof(roon_map), compare_keys);
    return pair ? pair->value : NULL;
}

// returns the name of key from the roon_map or NULL.
static char *
roon_map_name(char *key, const roon_map rm[]) {
    size_t len = roon_map_length(rm);
    roon_map map[1] = {{ key, NULL, NULL }};
    roon_map *pair = bsearch(map, rm, len, sizeof(roon_map), compare_keys);
    return pair ? pair->name : NULL;
}

// returns the length of the roon_uuid_map
static size_t
roon_uuid_length(const roon_uuid_map rm[]) {
    size_t len = 0;
    while (rm[len].uuid != NULL) {
        len++;
    }
    return len;
}

// compares two roon_uuid_map entries by their uuid in a case-insensitive manner
static int
compare_uuids(const void *va, const void *vb) {
    const roon_uuid_map *a = va, *b = vb;
    return g_ascii_strcasecmp(a->uuid, b->uuid);
}

// returns the name of the UUID from the roon_uuid_map or NULL if not exists
const char *
roon_map_uuid(char *key, const roon_uuid_map rm[]) {
    size_t len = roon_uuid_length(rm);
    roon_uuid_map map[1] = {{ key, NULL }};
    roon_uuid_map *pair = bsearch(map, rm, len, sizeof(roon_uuid_map), compare_uuids);
    return pair ? pair->name : NULL;
}

/* Code to actually dissect the packets
 *
 * The protocol is basically a static prefix of "SOOD" followed by a two byte
 * type indicating a query or reply.  The rest of the fields are an odd TLV-like
 * format where the type is an ASCII encoded string with a length prefix, followed
 * by a NULL byte terminator and then an ASCII encoded value also with a length
 * prefix, but no NULL terminator.
 */
static int
dissect_roon_discover(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    bool is_reply = false;
    proto_item *ti;
    proto_tree *roon_discover_tree;

    // verify this is actually a Roon Discovery packet we can process at a basic level
    if ((tvb_reported_length(tvb) < ROON_DISCOVERY_MIN_LENGTH || (tvb_captured_length(tvb) < 6)))
        return 0;

    // Must start with SOOD
    char *marker = tvb_get_string_enc(pinfo->pool, tvb, 0, 4, ENC_ASCII);
    if (strcmp(ROON_DISCOVERY_ID, marker) != 0)
        return 0;

    // query or reply are the next two bytes.
    switch (tvb_get_int16(tvb, 4, ENC_BIG_ENDIAN)) {
        case ROON_REPLY:
            is_reply = true;
            break;
        case ROON_QUERY:
            break;
        default:
            // dunno what we are
            return 0;
    }

    /* Set the Protocol column to the constant string of roon_discover */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RoonDisco");
    col_clear(pinfo->cinfo, COL_INFO);

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_roon_discover, tvb, 0, -1, ENC_NA);
    roon_discover_tree = proto_item_add_subtree(ti, ett_roon_discover);
    proto_tree_add_string(roon_discover_tree, hf_roon_disco_marker, tvb, 0, 4, ROON_DISCOVERY_ID);
    proto_tree_add_string(roon_discover_tree, hf_roon_disco_direction, tvb, 4, 2, is_reply ? "Reply" : "Query");

    int next;
    char *tid = NULL;

    // iterate over the rest of our message bytes
    const char *roon_service_name = NULL;
    bool use_ephemeral_port = false;
    for (unsigned i = 6; i < tvb_reported_length(tvb) ; i += next) {
        uint8_t key_len, value_len;
        unsigned offset;
        char *key, *value;

        key_len = tvb_get_uint8(tvb, i);
        offset = i + 1;
        key = tvb_get_string_enc(pinfo->pool, tvb, offset, key_len, ENC_ASCII);

        offset += key_len + 1;
        value_len = tvb_get_uint8(tvb, offset);
        offset += 1;
        value = tvb_get_string_enc(pinfo->pool, tvb, offset, value_len, ENC_ASCII);

        next = key_len + value_len + 3;

        // Is our value a string?
        char *treeName = roon_map_name(key, roon_disco_string_fields);
        int *treeValue;
        if (treeName != NULL) {
            treeValue = roon_map_value(key, roon_disco_string_fields);

            // Special handling for service_id and query_service_id
            if (strcmp(key, "service_id") == 0 || strcmp(key, "query_service_id") == 0) {
                // figure out the service name from the UUID
                roon_service_name = roon_map_uuid(value, roon_service_ids);
                roon_service_name = roon_service_name ? roon_service_name : "Unknown Roon Service";
                // add it to the tree
                proto_tree_add_string_format_value(roon_discover_tree, *treeValue, tvb, i, next, value, "%s [%s]", value, roon_service_name);
                if (g_ascii_strcasecmp(value, ROON_DISCOVERY_ALT_METHOD) == 0) {
                    use_ephemeral_port = true;
                }
                continue;  // next iteration... don't add the field again
            }

            // Special case: Store the TID for transaction tracking
            if (strcmp(key, "_tid") == 0) {
                tid = value;
            }

            // if not a service_id or query_service_id, just add the string
            proto_tree_add_string(roon_discover_tree, *treeValue, tvb, i, next, value);
            continue;
        }

        // Is our value a boolean?
        treeName = roon_map_name(key, roon_disco_bool_fields);
        if (treeName != NULL) {
            treeValue = roon_map_value(key, roon_disco_bool_fields);
            int val = strcmp(value, "0") == 0 ? 0 : 1;
            proto_tree_add_boolean(roon_discover_tree, *treeValue, tvb, i, next, val);
            continue;
        }
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", roon_service_name,
                 is_reply ? "Reply" : "Query");

    /* Handle transaction tracking if we have a TID */
    roon_transaction_t *trans = NULL;
    if (tid != NULL) {
        // lowercase the TID for consistent processing
        ascii_strdown_inplace(tid);

        if (is_reply) {
            trans = transaction_end(pinfo, roon_discover_tree, tid);
        } else {
            trans = transaction_start(pinfo, roon_discover_tree, tid, use_ephemeral_port);
        }
        tap_queue_packet(roon_tap, pinfo, trans);
    }

    return tvb_captured_length(tvb);
} // dissect_roon_discover

// Register the protocol with Wireshark.
void
proto_register_roon_discover(void)
{
    /*
     *  const char        *name;              **< [FIELDNAME] full name of this field
     *  const char        *abbrev;            **< [FIELDFILTERNAME] filter name of this field
     *  enum ftenum        type;              **< [FIELDTYPE] field type, one of FT_ (from ftypes.h)
     *  int                display;           **< [FIELDDISPLAY] one of BASE_, or field bit-width if FT_BOOLEAN and non-zero bitmask
     *  const void        *strings;           **< [FIELDCONVERT] value_string, val64_string, range_string or true_false_string,
     *                                          typically converted by VALS(), RVALS() or TFS().
     *                                          If this is an FT_PROTOCOL or BASE_PROTOCOL_INFO then it points to the
     *                                          associated protocol_t structure
     *  guint64            bitmask;           **< [BITMASK] bitmask of interesting bits
     *  const char        *blurb;             **< [FIELDDESCR] Brief description of field
    */
    static hf_register_info hf[] = {
        { &hf_roon_disco_config_version,
          { "Config Version", "roon_disco.config_version",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_display_version,
          { "Display Version", "roon_disco.display_version",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_direction,
          { "Direction", "roon_disco.direction",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_device_type,
          { "Device Type", "roon_disco.device_type",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_device_class,
          { "Device Class", "roon_disco.device_class",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_http_port,
          { "HTTP Port", "roon_disco.http_port",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_https_port,
          { "HTTPS Port", "roon_disco.https_port",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_is_dev,
            { "Development Version", "roon_disco.is_dev",
                FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_machine_id,
          { "MachineID", "roon_disco.machine_id",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_machine_name,
          { "Machine Name", "roon_disco.machine_name",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_marker,
          { "Protocol Marker", "roon_disco.marker",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_name,
          { "Device Name", "roon_disco.name",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_os_version,
          { "OS Version", "roon_disco.os_version",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_protocol_hash,
          { "Protocol Hash", "roon_disco.protocol_hash",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_protocol_version,
          { "Protocol Version", "roon_disco.protocol_version",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_query_service_id,
          { "Query ServiceID", "roon_disco.query_service_id",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_raat_version,
          { "RAAT Version", "roon_disco.raat_version",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_service_id,
          { "ServiceId", "roon_disco.service_id",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_tcp_port,
          { "TCP PORT", "roon_disco.tcp_port",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_tid,
          { "TID", "roon_disco.tid",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_user_id,
          { "UserID", "roon_disco.user_id",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_unique_id,
          { "UniqueID", "roon_disco.unique_id",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        // Transaction tracking fields
        { &hf_roon_disco_resp_in,
          { "Response frame", "roon_disco.resp_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            "The frame number of the corresponding response", HFILL } },

        { &hf_roon_disco_no_resp,
          { "No response seen", "roon_disco.no_resp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "No corresponding response frame was seen", HFILL } },

        { &hf_roon_disco_resp_to,
          { "Request frame", "roon_disco.resp_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            "The frame number of the corresponding request", HFILL } },

        { &hf_roon_disco_resptime,
          { "Response time", "roon_disco.resptime",
            FT_DOUBLE, BASE_NONE, NULL, 0x0,
            "The time between the request and the response, in ms.", HFILL } },
    };

    // Setup protocol subtree array
    static int *ett[] = {
        &ett_roon_discover
    };

    // Register the protocol name and description
    proto_roon_discover = proto_register_protocol("Roon Discovery", "RoonDisco", "roon_disco");

    // Required function calls to register the header fields and subtrees
    proto_register_field_array(proto_roon_discover, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    roon_discover_handle = register_dissector("roon_disco", dissect_roon_discover, proto_roon_discover);
    roon_tap = register_tap("roon_disco");
} // proto_register_roon_discover

void
proto_reg_handoff_roon_discover(void)
{
    dissector_add_uint_with_preference("udp.port", ROON_DISCOVERY_UDP_PORT, roon_discover_handle);
}

/*  A helper function that calls find_conversation() and, if a conversation is
 *  not found, calls conversation_new().
 *  The frame number and addresses are taken from pinfo.
 *  Ignores the destination address as it may be a broadcast/multicast address.
*/
conversation_t *
roon_find_or_create_conversation(packet_info *pinfo, bool ephemeral)
{
    conversation_t *conv=NULL;
    // Have we seen this conversation before?  destination address is not used
    // as it may be to a broadcast/multicast address.
    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                                  conversation_pt_to_conversation_type(pinfo->ptype),
                                  pinfo->srcport, pinfo->destport, ephemeral ? NO_ADDR_B|NO_PORT_B : NO_ADDR_B);
    if (conv == NULL) {
        // No, this is a new conversation.
        conv = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst,
                                conversation_pt_to_conversation_type(pinfo->ptype),
                                pinfo->srcport, pinfo->destport, ephemeral ? NO_ADDR2|NO_PORT2 : NO_ADDR2);
        // Link our dissector to the conversation if we expect the reply to come
        // from an ephemeral port.
        if (ephemeral) {
            conversation_set_dissector(conv, roon_discover_handle);
        }
    }

    return conv;
}

/*
 * Transaction tracking implementation
 * This function starts a transaction for the given TID and packet info.
 * It creates a new transaction structure if this is the first time we've seen
 * this TID, or retrieves an existing one if we've already seen it.
 * It also updates the conversation information with the transaction details.
*/
static roon_transaction_t *
transaction_start(packet_info *pinfo, proto_tree *tree, char *tid, bool ephemeral)
{
    conversation_t *conversation;
    roon_conv_info_t *roon_info;
    roon_transaction_t *roon_trans;
    wmem_tree_key_t roon_key[3];
    proto_item *it;
    guint32 tid_hash;


    // Create a hash of the TID string for use as key
    tid_hash = wmem_strong_hash((const guint8*)tid, (size_t)strlen(tid));

    // Handle the conversation tracking
    conversation = roon_find_or_create_conversation(pinfo, ephemeral);
    roon_info = (roon_conv_info_t *)conversation_get_proto_data(conversation, proto_roon_discover);
    if (roon_info == NULL) {
        roon_info = wmem_new(wmem_file_scope(), roon_conv_info_t);
        roon_info->unmatched_pdus = wmem_tree_new(wmem_file_scope());
        roon_info->matched_pdus   = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_roon_discover, roon_info);
    }

    if (!PINFO_FD_VISITED(pinfo)) {
        // this is a new request, create a new transaction structure and map it to the
        // unmatched table
        roon_key[0].length = 1;
        roon_key[0].key = &tid_hash;
        roon_key[1].length = 0;
        roon_key[1].key = NULL;

        roon_trans = wmem_new(wmem_file_scope(), roon_transaction_t);
        roon_trans->rqst_frame = pinfo->num;
        roon_trans->resp_frame = 0;
        roon_trans->rqst_time = pinfo->abs_ts;
        nstime_set_zero(&roon_trans->resp_time);
        wmem_tree_insert32_array(roon_info->unmatched_pdus, roon_key,
                               (void *) roon_trans);
    } else {
        // Already visited this frame
        guint32 frame_num = pinfo->num;

        roon_key[0].length = 1;
        roon_key[0].key = &tid_hash;
        roon_key[1].length = 1;
        roon_key[1].key = &frame_num;
        roon_key[2].length = 0;
        roon_key[2].key = NULL;

        roon_trans = (roon_transaction_t *)wmem_tree_lookup32_array(roon_info->matched_pdus,
                                                                   roon_key);
    }

    if (roon_trans == NULL) {
        if (PINFO_FD_VISITED(pinfo)) {
            // No response found - add field and expert info
            it = proto_tree_add_item(tree, hf_roon_disco_no_resp, NULL, 0, 0, ENC_NA);
            proto_item_set_generated(it);
        }
        return NULL;
    }

    // Print state tracking in the tree
    if (roon_trans->resp_frame) {
        it = proto_tree_add_uint(tree, hf_roon_disco_resp_in, NULL, 0, 0,
                                 roon_trans->resp_frame);
        proto_item_set_generated(it);

        col_append_frame_number(pinfo, COL_INFO, " [reply in %u]",
                               roon_trans->resp_frame);
    }

    return roon_trans;
} // transaction_start

/*
 * End a transaction for the given TID and packet info
 * This function retrieves the transaction structure for the given TID,
 * updates it with the response frame and time, and adds it to the matched
 * transactions table.
 * It also updates the protocol tree with the response information.
 */
static roon_transaction_t *
transaction_end(packet_info *pinfo, proto_tree *tree, char *tid)
{
    conversation_t *conversation;
    roon_conv_info_t *roon_info;
    roon_transaction_t *roon_trans;
    wmem_tree_key_t roon_key[3];
    proto_item *it;
    nstime_t ns;
    double resp_time;
    guint32 tid_hash;

    // Create a hash of the TID string for use as key
    tid_hash = wmem_strong_hash((const guint8*)tid, (size_t)strlen(tid));

    // don't use the source address as it may not exist in the list of conversations
    // since the original query may have been sent to a broadcast/multicast address.
    conversation = find_conversation(pinfo->num, NULL, &pinfo->dst,
                                    conversation_pt_to_conversation_type(pinfo->ptype),
                                    pinfo->srcport, pinfo->destport, 0);
    if (conversation == NULL) {
        return NULL;
    }

    roon_info = (roon_conv_info_t *)conversation_get_proto_data(conversation, proto_roon_discover);
    if (roon_info == NULL) {
        return NULL;
    }

    // first time visiting this frame?
    if (!PINFO_FD_VISITED(pinfo)) {
        guint32 frame_num;

        roon_key[0].length = 1;
        roon_key[0].key = &tid_hash;
        roon_key[1].length = 0;
        roon_key[1].key = NULL;

        roon_trans = (roon_transaction_t *)wmem_tree_lookup32_array(roon_info->unmatched_pdus,
                                                                   roon_key);
        if (roon_trans == NULL) {
            return NULL;
        }

        // we have already seen this response, or an identical one
        if (roon_trans->resp_frame != 0) {
            return NULL;
        }

        roon_trans->resp_frame = pinfo->num;

        // we found a match. Add entries to the matched table for both request and reply frames
        roon_key[0].length = 1;
        roon_key[0].key = &tid_hash;
        roon_key[1].length = 1;
        roon_key[1].key = &frame_num;
        roon_key[2].length = 0;
        roon_key[2].key = NULL;

        frame_num = roon_trans->rqst_frame;
        wmem_tree_insert32_array(roon_info->matched_pdus, roon_key, (void *) roon_trans);

        frame_num = roon_trans->resp_frame;
        wmem_tree_insert32_array(roon_info->matched_pdus, roon_key, (void *) roon_trans);
    } else {
        // Already visited this frame
        guint32 frame_num = pinfo->num;

        roon_key[0].length = 1;
        roon_key[0].key = &tid_hash;
        roon_key[1].length = 1;
        roon_key[1].key = &frame_num;
        roon_key[2].length = 0;
        roon_key[2].key = NULL;

        roon_trans = (roon_transaction_t *)wmem_tree_lookup32_array_le(roon_info->matched_pdus,
                                                                   roon_key);
        if (roon_trans == NULL) {
            return NULL;
        }
    }

    it = proto_tree_add_uint(tree, hf_roon_disco_resp_to, NULL, 0, 0,
                             roon_trans->rqst_frame);
    proto_item_set_generated(it);

    nstime_delta(&ns, &pinfo->abs_ts, &roon_trans->rqst_time);
    roon_trans->resp_time = ns;
    resp_time = nstime_to_msec(&ns);
    it = proto_tree_add_double_format_value(tree, hf_roon_disco_resptime,
                                            NULL, 0, 0, resp_time,
                                            "%.3f ms", resp_time);
    proto_item_set_generated(it);

    col_append_frame_number(pinfo, COL_INFO, " [response to %u]",
                           roon_trans->rqst_frame);

    return roon_trans;
} // transaction_end

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
