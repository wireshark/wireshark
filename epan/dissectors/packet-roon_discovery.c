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

#include <stdlib.h> /* For bsearch() */

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_roon_discover(void);
void proto_register_roon_discover(void);

/* Initialize the protocol and registered fields */
static int proto_roon_discover = -1;
static int hf_roon_disco_config_version   = -1;
static int hf_roon_disco_device_type      = -1;
static int hf_roon_disco_device_class     = -1;
static int hf_roon_disco_display_version  = -1;
static int hf_roon_disco_http_port        = -1;
static int hf_roon_disco_https_port       = -1;
static int hf_roon_disco_is_dev           = -1;
static int hf_roon_disco_machine_id       = -1;
static int hf_roon_disco_machine_name     = -1;
static int hf_roon_disco_marker           = -1;
static int hf_roon_disco_name             = -1;
static int hf_roon_disco_os_version       = -1;
static int hf_roon_disco_protocol_version = -1;
static int hf_roon_disco_protocol_hash    = -1;
static int hf_roon_disco_raat_version     = -1;
static int hf_roon_disco_service_id       = -1;
static int hf_roon_disco_tcp_port         = -1;
static int hf_roon_disco_tid              = -1;
static int hf_roon_disco_type             = -1;
static int hf_roon_disco_unique_id        = -1;
static int hf_roon_disco_user_id          = -1;


#define ROON_DISCOVERY_ID "SOOD"
#define ROON_QUERY 0x0251 // Q(uery)
#define ROON_REPLY 0x0252 // R(eply)
#define ROON_DISCOVERY_UDP_PORT 9003 /* Not IANA-assigned */

/* Initialize the subtree pointers */
static gint ett_roon_discover = -1;

#define ROON_DISCOVERY_MIN_LENGTH 98 // empirically defined

typedef struct {
    char *key;
    char *name;
    int *value;
} roon_map;

// table to map field keys to our protocol tree entry.  The order of entries
// must be sorted by they key field.
static const roon_map roon_disco_string_fields[] = {
    { "_tid"             , "TransactionID"    , &hf_roon_disco_tid }              ,
    { "config_version"   , "Config Version"   , &hf_roon_disco_config_version }   ,
    { "device_class"     , "Device Class"     , &hf_roon_disco_device_class }     ,
    { "device_type"      , "Device Type"      , &hf_roon_disco_device_type }      ,
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
    { "raat_version"     , "RAAT Version"     , &hf_roon_disco_raat_version }     ,
    { "service_id"       , "ServiceID"        , &hf_roon_disco_service_id }       ,
    { "tcp_port"         , "TCP Port"         , &hf_roon_disco_tcp_port }         ,
    { "type"             , "Message Type"     , &hf_roon_disco_type }             ,
    { "unique_id"        , "UniqueID"         , &hf_roon_disco_unique_id }        ,
    { "user_id"          , "UserID"           , &hf_roon_disco_user_id }          ,
    { NULL               , NULL               , NULL }                            ,
};

static const roon_map roon_disco_bool_fields[] = {
    { "is_dev" , "Devel Version" , &hf_roon_disco_is_dev } ,
    { NULL     , NULL            , NULL }                  ,
};

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

// returns the name of key from the roon_map or NULL
static char *
roon_map_name(char *key, const roon_map rm[]) {
    size_t len = roon_map_length(rm);
    roon_map map[1] = {{ key, NULL, NULL }};
    roon_map *pair = bsearch(map, rm, len, sizeof(roon_map), compare_keys);
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
    switch (tvb_get_gint16(tvb, 4, ENC_BIG_ENDIAN)) {
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

    if (is_reply) {
        col_set_str(pinfo->cinfo, COL_INFO, "Roon Discovery Reply");
        proto_tree_add_string(roon_discover_tree, hf_roon_disco_type, tvb, 4, 2, "Reply");
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "Roon Discovery Query");
        proto_tree_add_string(roon_discover_tree, hf_roon_disco_type, tvb, 4, 2, "Query");
    }

    int next;
    // iterate over the rest of our message bytes
    for (guint i = 6; i < tvb_reported_length(tvb) ; i += next) {
        guint8 key_len, value_len;
        guint offset;
        char *key, *value;

        key_len = tvb_get_guint8(tvb, i);
        offset = i + 1;
        key = tvb_get_string_enc(pinfo->pool, tvb, offset, key_len, ENC_ASCII);

        offset += key_len + 1;
        value_len = tvb_get_guint8(tvb, offset);
        offset += 1;
        value = tvb_get_string_enc(pinfo->pool, tvb, offset, value_len, ENC_ASCII);

        next = key_len + value_len + 3;

        // Is our value a string?
        char *treeName = roon_map_name(key, roon_disco_string_fields);
        int *treeValue;
        if (treeName != NULL) {
            treeValue = roon_map_value(key, roon_disco_string_fields);
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

        // If we reach here, unsupported field
        // fprintf(stderr, "no match for %s\n", key);
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.  */
void
proto_register_roon_discover(void)
{
    static hf_register_info hf[] = {
        { &hf_roon_disco_config_version,
          { "Config Version", "roon_disco.config_version",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_display_version,
          { "Display Version", "roon_disco.display_version",
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

        { &hf_roon_disco_type,
          { "Message Type", "roon_disco.type",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_user_id,
          { "UserID", "roon_disco.user_id",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },

        { &hf_roon_disco_unique_id,
          { "UniqueID", "roon_disco.unique_id",
              FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_roon_discover
    };

    /* Register the protocol name and description */
    proto_roon_discover = proto_register_protocol("Roon Discovery", "RoonDisco", "roon_disco");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_roon_discover, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_roon_discover(void)
{
    static dissector_handle_t roon_discover_handle;

    roon_discover_handle = create_dissector_handle(dissect_roon_discover, proto_roon_discover);
    dissector_add_uint_with_preference("udp.port", ROON_DISCOVERY_UDP_PORT, roon_discover_handle);
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
