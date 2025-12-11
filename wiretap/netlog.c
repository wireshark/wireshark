/* netlog.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * NetLog file support
 * Copyright (c) 2025 by Moshe Kaplan
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * About NetLog:
 * NetLog files are JSON files representing each event occurring in the browser.
 * If configured to capture raw bytes, NetLog files will also contain the packet data.
 * For more information about NetLog, see https://www.chromium.org/developers/design-documents/network-stack/netlog/
 */

#include "config.h"
#include "netlog.h"

#include <string.h>

#include "wtap_module.h"
#include "file_wrappers.h"

/* Grab constants for generating supporting layers */
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-iana-data.h>

#include <wsutil/wsjson.h>

#define WS_LOG_DOMAIN "NetLog"

/* This is to avoid having large files overload the JSON parser. Adjust as appropriate. */
#define MAX_FILE_SIZE (1024*1024*1024)

#define DECRYPTED_TRAFFIC_PORT 44380
#define CLIENT_SEQ_START 10000
#define SERVER_SEQ_START 20000
#define IPV4_HEADER_LEN 20
#define IPV6_HEADER_LEN 40
#define TCP_HEADER_LEN  20
#define UDP_HEADER_LEN   8

#define NETLOG_TCP_IDENTICATION_NUMBER  0x1234

static int netlog_file_type_subtype = -1;

void register_netlog(void);

typedef struct {
    int64_t timeTickOffset;
    int64_t TCP_CONNECT;
    int64_t SOCKET_BYTES_RECEIVED;
    int64_t SOCKET_BYTES_SENT;
    int64_t SOCKET_CLOSED;
    int64_t SSL_SOCKET_BYTES_RECEIVED;
    int64_t SSL_SOCKET_BYTES_SENT;
    int64_t UDP_BYTES_RECEIVED;
    int64_t UDP_BYTES_SENT;
    int64_t UDP_CONNECT;
    int64_t UDP_LOCAL_ADDRESS;
} NetLogEventConstants;


typedef enum {
    IP_VERSION_4,
    IP_VERSION_6
} IPVersion;

typedef enum {
    TransportProtocol_TCP,
    TransportProtocol_UDP
} TransportProtocol;

typedef enum {
    TrafficDirection_CTS, /* Client to Server */
    TrafficDirection_STC  /* Server to Client */
} TrafficDirection;

typedef union {
    ws_in4_addr ipv4;
    ws_in6_addr ipv6;
} IPAddress;

/**
 * Represents a TCP or UDP session at the moment bytes are being transferred.
 * UDP does not use sequence number fields.
*/
typedef struct {
    IPVersion ip_version;
    TransportProtocol transport;
    IPAddress client_ip;
    IPAddress server_ip;
    uint16_t client_port;
    uint16_t server_port;
    uint32_t client_seq;
    uint32_t server_seq;
    TrafficDirection direction;
    int64_t timestamp;
} TransportSession;

/**
 * Represents the byte offset of a single JSON object
 * which can be parsed to obtain the associated data
 */
 typedef struct {
    uint32_t offset;
    uint32_t length;
    TransportSession session;
} JSONPacket;

typedef struct {
    IPVersion ip_version;
    IPAddress ip;
    uint16_t port;
} IP_Port;

typedef struct {
    uint32_t idx;
    GHashTable* json_packets_ht;
} NetLogState;

/**
 * Parse a string like "127.0.0.1:443" or "[2001::1]:443" into an IP_port combination
 * Stores the result in the provided `dest`.
 * Returns true on successful parse, false on failure.
 */
static bool parse_address_port(const char* address_port, IP_Port* dest)
{
    const char* dest_port_str = strrchr(address_port, ':');
    if (dest_port_str == NULL || strlen(dest_port_str) <= 1){
        return false;
    }
    const int dest_port = (int) g_ascii_strtoll(dest_port_str+1, NULL, 10);
    dest->port = dest_port;
    ws_debug("dest_port: %i", dest_port);

    char* dest_ip = g_strndup(address_port, dest_port_str - address_port);
    if (dest_ip == NULL){
        return false;
    }

    ws_in4_addr ipv4_addr;
    if (ws_inet_pton4(dest_ip, &ipv4_addr)){
        dest->ip_version = IP_VERSION_4;
        dest->ip.ipv4 = ipv4_addr;
        g_free(dest_ip);
        return true;
    }

    /* Must be IPv6. The input is in brackets (e.g., "[2001::1]:443"),
     * so we'll need to remove the brackets and parse it afterward */
    if (strlen(dest_ip) <= 2){
        g_free(dest_ip);
        return false;
    }
    /* Done with dest_ip, get rid of it */
    g_free(dest_ip);
    ws_in6_addr ipv6_addr;
    char* dest_ip2 = g_strndup(address_port + 1, dest_port_str - address_port - 2);
    if (dest_ip2 == NULL){
        return false;
    }
    if (ws_inet_pton6(dest_ip2, &ipv6_addr)){
        dest->ip_version = IP_VERSION_6;
        memcpy(dest->ip.ipv6.bytes, ipv6_addr.bytes, sizeof(ipv6_addr.bytes));
        g_free(dest_ip2);
        return true;
    }
    /* Not able to be parsed as IPv4 or IPv6 */
    g_free(dest_ip2);
    return false;
}

/**
 * Parses all of the significant log event constants from JSON data and stores them in `out`
 */
static bool parse_log_event_constants(char *filebuf, jsmntok_t *root_json_token, NetLogEventConstants *out)
{
    if (!filebuf || !root_json_token || !out) {
        return false;
    }

    jsmntok_t* json_constants = json_get_object(filebuf, root_json_token, "constants");
    if (json_constants == NULL){
        ws_debug("Failed to parse the JSON constants");
        return false;
    }
    jsmntok_t* json_logevent_constants = json_get_object(filebuf, json_constants, "logEventTypes");
    if (json_logevent_constants == NULL){
        ws_debug("Failed to parse the JSON logEventTypes");
        return false;
    }

    bool ok = true;
    ok &= json_get_int(filebuf, json_constants, "timeTickOffset", &out->timeTickOffset);
    ok &= json_get_int(filebuf, json_logevent_constants, "TCP_CONNECT", &out->TCP_CONNECT);
    ok &= json_get_int(filebuf, json_logevent_constants, "SOCKET_BYTES_RECEIVED", &out->SOCKET_BYTES_RECEIVED);
    ok &= json_get_int(filebuf, json_logevent_constants, "SOCKET_BYTES_SENT", &out->SOCKET_BYTES_SENT);
    ok &= json_get_int(filebuf, json_logevent_constants, "SOCKET_CLOSED", &out->SOCKET_CLOSED);
    ok &= json_get_int(filebuf, json_logevent_constants, "SSL_SOCKET_BYTES_RECEIVED", &out->SSL_SOCKET_BYTES_RECEIVED);
    ok &= json_get_int(filebuf, json_logevent_constants, "SSL_SOCKET_BYTES_SENT", &out->SSL_SOCKET_BYTES_SENT);
    ok &= json_get_int(filebuf, json_logevent_constants, "UDP_BYTES_RECEIVED", &out->UDP_BYTES_RECEIVED);
    ok &= json_get_int(filebuf, json_logevent_constants, "UDP_BYTES_SENT", &out->UDP_BYTES_SENT);
    ok &= json_get_int(filebuf, json_logevent_constants, "UDP_CONNECT", &out->UDP_CONNECT);
    ok &= json_get_int(filebuf, json_logevent_constants, "UDP_LOCAL_ADDRESS", &out->UDP_LOCAL_ADDRESS);

    ws_debug("TCP_CONNECT: %" PRIi64, out->TCP_CONNECT);
    ws_debug("SOCKET_BYTES_RECEIVED: %" PRIi64, out->SOCKET_BYTES_RECEIVED);
    ws_debug("SOCKET_BYTES_SENT: %" PRIi64, out->SOCKET_BYTES_SENT);
    ws_debug("SOCKET_CLOSED: %" PRIi64, out->SOCKET_CLOSED);
    ws_debug("SSL_SOCKET_BYTES_RECEIVED: %" PRIi64, out->SSL_SOCKET_BYTES_RECEIVED);
    ws_debug("SSL_SOCKET_BYTES_SENT: %" PRIi64, out->SSL_SOCKET_BYTES_SENT);
    ws_debug("UDP_BYTES_RECEIVED: %" PRIi64, out->UDP_BYTES_RECEIVED);
    ws_debug("UDP_BYTES_SENT: %" PRIi64, out->UDP_BYTES_SENT);
    ws_debug("UDP_CONNECT: %" PRIi64, out->UDP_CONNECT);
    ws_debug("UDP_LOCAL_ADDRESS: %" PRIi64, out->UDP_LOCAL_ADDRESS);


    if (ok) {
        ws_debug("Successfully parsed all values");
    } else {
        ws_debug("Failed to parse all values!");
    }
    return ok;
}


/**
 * Given a provided session and traffic payload, generates the complete Wireshark 'packet'
 * with the IPv4/IPv6 header, TCP/UDP header, and payload, and stores them in the supplied wtap rec.
 */
static bool generate_packet(const wtap* wth, wtap_rec* rec, const TransportSession* session, const uint8_t* payload, const size_t payload_len)
{
    if (payload == NULL){
        return false;
    }
    size_t packet_size;
    /* First calculate total bytes needed: */
    if (session->ip_version == IP_VERSION_4) {
        if (session->transport == TransportProtocol_TCP) {
            packet_size = (uint32_t)(IPV4_HEADER_LEN + TCP_HEADER_LEN + payload_len);
        }
        else if (session->transport == TransportProtocol_UDP) {
            packet_size = (uint32_t)(IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len);
        }
        else {
            return false;
        }
    }
    else if (session->ip_version == IP_VERSION_6) {
        if (session->transport == TransportProtocol_TCP) {
            packet_size = (uint32_t)(IPV6_HEADER_LEN + TCP_HEADER_LEN + payload_len);
        }
        else if (session->transport == TransportProtocol_UDP) {
            packet_size = (uint32_t)(IPV6_HEADER_LEN + UDP_HEADER_LEN + payload_len);
        }
        else {
            return false;
        }
    } else {
        return false;
    }

    /* Set the wtap record data */
    ws_buffer_assure_space(&rec->data, packet_size);
    ws_buffer_increase_length(&rec->data, packet_size);

    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->rec_header.packet_header.caplen = (uint32_t) packet_size;
    rec->rec_header.packet_header.len = (uint32_t) packet_size;
    rec->presence_flags = WTAP_HAS_TS;
    rec->ts.secs = (time_t)session->timestamp / 1000;
    rec->ts.nsecs = (int)((session->timestamp % 1000) * 1000 * 1000);

    /* Fill in the packet data, starting with the IP header */
    uint8_t* p = ws_buffer_start_ptr(&rec->data);
    if (session->ip_version == IP_VERSION_4) {
        // --- IPv4 Header ---
        *p++ = 0x45; // Version 4, IHL 5
        *p++ = 0x00; // DSCP/ECN
        uint16_t total_len = (uint16_t)packet_size;
        *(uint16_t*)p = g_htons(total_len); p += 2;
        *(uint16_t*)p = g_htons(NETLOG_TCP_IDENTICATION_NUMBER); p += 2;
        *(uint16_t*)p = g_htons(0x4000); p += 2; // Flags + Fragment offset
        *p++ = 64; // TTL
        if (session->transport == TransportProtocol_TCP) {
            *p++ = IP_PROTO_TCP;
        }
        else if (session->transport == TransportProtocol_UDP) {
            *p++ = IP_PROTO_UDP;
        }
        *(uint16_t*)p = 0; p += 2; // Header checksum (optional)
        if (session->direction == TrafficDirection_CTS) {
            memcpy(p, &session->client_ip.ipv4, 4); p += 4;
            memcpy(p, &session->server_ip.ipv4, 4); p += 4;
        }
        else {
            memcpy(p, &session->server_ip.ipv4, 4); p += 4;
            memcpy(p, &session->client_ip.ipv4, 4); p += 4;
        }
    }
    else {
        // --- IPv6 Header ---
        uint32_t ver_tc_fl = g_htonl(0x60000000); // Version 6, TC=0, Flow=0
        memcpy(p, &ver_tc_fl, 4); p += 4;
        uint16_t ipv6_payload_len = (uint16_t)(TCP_HEADER_LEN + payload_len);
        *(uint16_t*)p = g_htons(ipv6_payload_len); p += 2;
        if (session->transport == TransportProtocol_TCP) {
            *p++ = IP_PROTO_TCP;
        }
        else if (session->transport == TransportProtocol_UDP) {
            *p++ = IP_PROTO_UDP;
        }
        *p++ = 64; // Hop limit
        if (session->direction == TrafficDirection_CTS) {
            memcpy(p, session->client_ip.ipv6.bytes, 16); p += 16;
            memcpy(p, session->server_ip.ipv6.bytes, 16); p += 16;
        }
        else {
            memcpy(p, session->server_ip.ipv6.bytes, 16); p += 16;
            memcpy(p, session->client_ip.ipv6.bytes, 16); p += 16;
        }
    }

    /* Fill in the packet data, continuing with the TCP/UDP header */
    if (session->transport == TransportProtocol_TCP) {
        // --- TCP Header ---
        if (session->direction == TrafficDirection_CTS) {
            *(uint16_t*)p = g_htons(session->client_port); p += 2;
            *(uint16_t*)p = g_htons(session->server_port); p += 2;
            *(uint32_t*)p = g_htonl(session->client_seq); p += 4;
            *(uint32_t*)p = g_htonl(session->server_seq); p += 4;
        }
        else {
            *(uint16_t*)p = g_htons(session->server_port); p += 2;
            *(uint16_t*)p = g_htons(session->client_port); p += 2;
            *(uint32_t*)p = g_htonl(session->server_seq); p += 4;
            *(uint32_t*)p = g_htonl(session->client_seq); p += 4;
        }
        *p++ = (5 << 4); // Data offset = 5 (20 bytes), reserved
        *p++ = TH_ACK;    // TCP flags
        *(uint16_t*)p = g_htons(8192); p += 2; // Window size
        *(uint16_t*)p = 0; p += 2; // Checksum (optional)
        *(uint16_t*)p = 0; p += 2; // Urgent pointer
    }
    else if (session->transport == TransportProtocol_UDP) {
        // --- UDP Header ---
        if (session->direction == TrafficDirection_CTS) {
            *(uint16_t*)p = g_htons(session->client_port); p += 2;
            *(uint16_t*)p = g_htons(session->server_port); p += 2;
        }
        else {
            *(uint16_t*)p = g_htons(session->server_port); p += 2;
            *(uint16_t*)p = g_htons(session->client_port); p += 2;
        }
        *(uint16_t*)p = g_htons(UDP_HEADER_LEN + payload_len); p += 2;
        *(uint16_t*)p = 0; p += 2; // Checksum (optional)
    }

    /* Fill in the packet data, continuing with the TCP/UDP payload */
    memcpy(p, payload, payload_len);
    return true;
}

/**
 * Given a hash table of indexes to JSONPacket*, and an index, read the data from the fh and store it in the provided wtap rec
 */
static bool netlog_read_packet(const wtap* wth, wtap_rec* rec, GHashTable *json_packets_ht, const int idx, int* err, char **err_info, FILE_T fh)
{
    JSONPacket* json_packet = g_hash_table_lookup(json_packets_ht, GINT_TO_POINTER(idx));
    if (!json_packet){
        return false;
    }

    /* Now we have the offset, length, and context. Let's read the data! */
    if (file_seek(fh, json_packet->offset, SEEK_SET, err) == -1) {
        return false;
    }
    uint8_t* filebuf = (uint8_t*)g_malloc(json_packet->length);
    if (!filebuf){
        return false;
    }
    int bytes_read = file_read(filebuf, (unsigned int) json_packet->length, fh);
    if (bytes_read < 0) {
        /* Read error. */
        *err = file_error(fh, err_info);
        g_free(filebuf);
        return false;
    }
    if (bytes_read == 0) {
        /* empty file, not *anybody's* */
        g_free(filebuf);
        return false;
    }

    int num_tokens = json_parse_len((const char*)filebuf, json_packet->length, NULL, 0);
    if (num_tokens < 0) {
        g_free(filebuf);
        return false;
    }
    jsmntok_t* json_tokens = g_new0(jsmntok_t, num_tokens);
    if (!json_tokens) {
        g_free(filebuf);
        return false;
    }
    int json_parse_result = json_parse_len((const char*)filebuf, json_packet->length, json_tokens, num_tokens);
    if (json_parse_result < 0){
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    jsmntok_t* params_entry = json_tokens;
    const char* base64_bytes = json_get_string((char*)filebuf, params_entry, "bytes");
    if (base64_bytes == NULL){
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }
    size_t payload_len;
    uint8_t* payload = g_base64_decode(base64_bytes, &payload_len);
    /* Now that we have the TCP/UDP packet's payload, let's build the packet */

    bool result = generate_packet(wth, rec, &json_packet->session, payload, payload_len);
    g_free(payload);
    g_free(json_tokens);
    g_free(filebuf);
    return result;
}


/**
 * Generates a JSONPacket* for a provided event with bytes transferred, given the context of the existing session table and the traffic direction.
 */
JSONPacket* handle_traffic_event(char* filebuf, jsmntok_t* event_entry, GHashTable* sessions_table, int64_t event_id, TrafficDirection direction){
    jsmntok_t* params_entry = json_get_object(filebuf, event_entry, "params");
    if (params_entry == NULL)
        return NULL;

    TransportSession* session = g_hash_table_lookup(sessions_table, GINT_TO_POINTER(event_id));
    if (!session){
        return NULL;
    }

    /* Now we need to save the packet metadata */
    JSONPacket* json_packet = g_new0(JSONPacket, 1);
    if (!json_packet){
        return NULL;
    }

    json_packet->session = *session;
    json_packet->length = params_entry->end - params_entry->start;
    json_packet->offset = params_entry->start;
    json_packet->session.direction = direction;

    /* After copying the session object, increase the sequence numbers for the next packet */
    if (session->transport == TransportProtocol_TCP) {
        /* We need the payload's size to increment the sequence numbers */
        int64_t payload_len = 0;
        if (!json_get_int(filebuf, params_entry, "byte_count", &payload_len)){
            g_free(json_packet);
            return NULL;
        }
        if (direction == TrafficDirection_STC){
            session->server_seq += (uint32_t)payload_len;
        }
        else if (direction == TrafficDirection_CTS){
            session->client_seq += (uint32_t)payload_len;
        }
    }
    return json_packet;
}

/**
 * Generates a TransportSession* from the provided local_address, remote_address, and TransportProtocol.
 */
TransportSession* create_transport_session(const IP_Port* local_address, const IP_Port* remote_address, const TransportProtocol transport){
    /* As a quick sanity check, confirm that both source and destination are the same IP version */
    if (local_address->ip_version != remote_address->ip_version){
        ws_warning("IP versions are different! local_address->ip_version: %d, remote_address_ptr: %d", local_address->ip_version, remote_address->ip_version);
        return NULL;
    }

    TransportSession* session = g_new0(TransportSession, 1);
    if (session == NULL){
        return NULL;
    }
    session->transport = transport;
    session->ip_version = remote_address->ip_version;
    if (session->ip_version == IP_VERSION_4){
        session->client_ip.ipv4 = local_address->ip.ipv4;
        session->server_ip.ipv4 = remote_address->ip.ipv4;
    }
    else if (session->ip_version == IP_VERSION_6){
        memcpy(session->client_ip.ipv6.bytes, local_address->ip.ipv6.bytes, sizeof(local_address->ip.ipv6.bytes));
        memcpy(session->server_ip.ipv6.bytes, remote_address->ip.ipv6.bytes, sizeof(remote_address->ip.ipv6.bytes));
    }
    session->client_port = local_address->port;
    session->server_port = remote_address->port;

    if (transport == TransportProtocol_TCP){
        session->client_seq = CLIENT_SEQ_START;
        session->server_seq = SERVER_SEQ_START;
    }
    return session;
}

/**
 * Iterate through the Netlog file's events and store them in the provided GHashTable*, so that they can
 * be efficiently accessed via index.
 */
static bool parse_json_events(char* filebuf, const NetLogEventConstants netlog_event_constants, jsmntok_t* json_events, GHashTable *json_packets_ht)
{
    /* We'll need to store the session information independently of individual events, so let's do that:*/
    GHashTable* TCP_sessions = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    GHashTable* decrypted_sessions = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    GHashTable* UDP_sessions = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    /* For UDP, we don't have a single connection with both the local and remote address, so we'll need a mapping of IDs to local address
     * So we can build the connection objects.
     */
    GHashTable* UDP_connection_ids_to_remote_address = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    int json_packets_ht_index = 0;
    const int json_array_len = json_get_array_len(json_events);
    jsmntok_t* event_entry = json_get_array_index(json_events, 0);
    for (int i = 0; i < json_array_len && event_entry != NULL; i++, event_entry = json_get_next_object(event_entry))
    {
        if (event_entry->type != JSMN_OBJECT){
            ws_debug("Skipping non-object at index %i", i);
            continue;
        }
        int64_t type_val = 0;
        if (json_get_int(filebuf, event_entry, "type", &type_val)){
            ws_debug("Processing event %d type: %" PRIi64, i, type_val);
        } else {
            ws_warning("Failed to read the event's 'type'");
            continue;
        }

        /* Now that we've confirmed that this is an event with a type,
           let's confirm it's of interest and then we can parse that event type
        */
        /* Events of interest must have a source ID: */
        jsmntok_t* source_entry = json_get_object(filebuf, event_entry, "source");
        if (source_entry == NULL) {
           continue;
        }
        int64_t event_id = 0;
        if (!json_get_int(filebuf, source_entry, "id", &event_id)){
           continue;
        }

        const char* timestamp_str = json_get_string(filebuf, event_entry, "time");
        if (timestamp_str == NULL){
            continue;
        }
        uint64_t timestamp = g_ascii_strtoll(timestamp_str, NULL, 10);

        if (type_val == netlog_event_constants.TCP_CONNECT) {
            /* There can be multiple TCP_CONNECT lines - we cheat by
            only storing the final one which includes both the local and remote addresses */
            jsmntok_t* params_entry = json_get_object(filebuf, event_entry, "params");
            if (params_entry == NULL)
                continue;
            const char* local_address_str = json_get_string(filebuf, params_entry, "local_address");
            const char* remote_address_str = json_get_string(filebuf, params_entry, "remote_address");
            if (remote_address_str == NULL || local_address_str == NULL)
                continue;

            IP_Port local_address, remote_address;
            if (!parse_address_port(local_address_str, &local_address)){
                continue;
            }
            if (!parse_address_port(remote_address_str, &remote_address)){
                continue;
            }
            /* Now we have both the local and remote IPs and ports. Store them in a session! */
            TransportSession* session = create_transport_session(&local_address, &remote_address, TransportProtocol_TCP);
            if (session == NULL){
                continue;
            }
            g_hash_table_insert(TCP_sessions, GINT_TO_POINTER(event_id), session);

            /* Create a second session for the TLS traffic */
            TransportSession* decrypted_session = create_transport_session(&local_address, &remote_address, TransportProtocol_TCP);
            if (decrypted_session == NULL){
                continue;
            }
            /* Override the dest port to avoid messing up reassembly */
            decrypted_session->server_port = DECRYPTED_TRAFFIC_PORT;
            g_hash_table_insert(decrypted_sessions, GINT_TO_POINTER(event_id), decrypted_session);
        } else if (type_val == netlog_event_constants.SOCKET_BYTES_RECEIVED) {
            /* Now we need to save the packet metadata */
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, TCP_sessions, event_id, TrafficDirection_STC);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.SOCKET_BYTES_SENT) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, TCP_sessions, event_id, TrafficDirection_CTS);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.SOCKET_CLOSED) {
            /* We could, but don't bother creating the FINs, similar to how we skip SYNs*/
        } else if (type_val == netlog_event_constants.SSL_SOCKET_BYTES_RECEIVED) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, decrypted_sessions, event_id, TrafficDirection_STC);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.SSL_SOCKET_BYTES_SENT) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, decrypted_sessions, event_id, TrafficDirection_CTS);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.UDP_BYTES_RECEIVED) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, UDP_sessions, event_id, TrafficDirection_STC);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.UDP_BYTES_SENT) {
            JSONPacket* json_packet = handle_traffic_event(filebuf, event_entry, UDP_sessions, event_id, TrafficDirection_CTS);
            if (!json_packet){
                continue;
            }
            json_packet->session.timestamp = netlog_event_constants.timeTickOffset + timestamp;
            g_hash_table_insert(json_packets_ht, GINT_TO_POINTER(json_packets_ht_index), json_packet);
            json_packets_ht_index++;
        } else if (type_val == netlog_event_constants.UDP_CONNECT) {
            /* Unlike TCP which has both sides in a single event, UDP does not, so we need
             * to store the first half of the connection as a separate entity here. */
            jsmntok_t* params_entry = json_get_object(filebuf, event_entry, "params");
            if (params_entry == NULL)
                continue;
            const char* remote_address = json_get_string(filebuf, params_entry, "address");
            if (remote_address == NULL)
                continue;
            IP_Port* server_ip = g_new0(IP_Port, 1);
            if (!server_ip){
                continue;
            }
            if (!parse_address_port(remote_address, server_ip)){
                g_free(server_ip);
                continue;
            }
            g_hash_table_insert(UDP_connection_ids_to_remote_address, GINT_TO_POINTER(event_id), server_ip);

        } else if (type_val == netlog_event_constants.UDP_LOCAL_ADDRESS) {
            /* Builds a UDP session with the data from UDP_CONNECT */
            const IP_Port *remote_address_ptr = g_hash_table_lookup(UDP_connection_ids_to_remote_address, GINT_TO_POINTER(event_id));
            if (!remote_address_ptr){
                continue;
            }

            /* Read the local_address from JSON */
            jsmntok_t* params_entry = json_get_object(filebuf, event_entry, "params");
            if (params_entry == NULL)
                continue;
            const char* local_address_str = json_get_string(filebuf, params_entry, "address");
            if (local_address_str == NULL)
                continue;
            /* Parse the address into an IP and port */
            IP_Port local_address;
            if (!parse_address_port(local_address_str, &local_address)){
                continue;
            }

            /* Now we have both the local and remote IPs and ports. Store them in a session! */
            TransportSession* session = create_transport_session(&local_address, remote_address_ptr, TransportProtocol_UDP);
            if (session == NULL){
                continue;
            }
            g_hash_table_insert(UDP_sessions, GINT_TO_POINTER(event_id), session);
        } else {
            /* This is expected and we can ignore these */
        }
    }
    /* Clean up after ourselves */
    g_hash_table_destroy(TCP_sessions);
    g_hash_table_destroy(decrypted_sessions);
    g_hash_table_destroy(UDP_sessions);
    g_hash_table_destroy(UDP_connection_ids_to_remote_address);
    return true;
}

/**
 * Parses the entire NetLog JSON file from `fh` and stores the packets in json_packets_ht.
 * Returns true on success, false on failure.
 */
static bool netlog_parse_entirety(wtap *wth, FILE_T fh, int *err, char **err_info, GHashTable *json_packets_ht)
{
    int64_t file_size;

    if ((file_size = wtap_file_size(wth, err)) == -1)
        return false;

    if (file_size > MAX_FILE_SIZE) {
        /* Avoid allocating space for an immensely-large file. */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("%s: File has %" PRId64 "-byte packet, bigger than maximum of %u",
                wtap_encap_name(wth->file_encap), file_size, MAX_FILE_SIZE);
        return false;
    }

    uint8_t* filebuf = (uint8_t*)g_malloc(file_size);
    if (!filebuf)
        return false;

    /* Read the entire file into memory */
    int bytes_read = file_read(filebuf, (unsigned int) file_size, fh);

    if (bytes_read < 0) {
        /* Read error. */
        *err = file_error(fh, err_info);
        g_free(filebuf);
        return false;
    }
    if (bytes_read == 0) {
        /* empty file, not *anybody's* */
        g_free(filebuf);
        return false;
    }

    int num_tokens = json_parse_len((const char*)filebuf, bytes_read, NULL, 0);
    if (num_tokens < 0) {
        g_free(filebuf);
        return false;
    }

    jsmntok_t* json_tokens = g_new0(jsmntok_t, num_tokens);
    if (!json_tokens) {
        g_free(filebuf);
        return false;
    }

    if (json_parse_len((const char*)filebuf, bytes_read, json_tokens, num_tokens) < 0){
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    /*
     * We now have a fully parsed JSON object. Let's start extracting some data!
     * First (root) object is an Object (dictionary), which is an unordered collection of key-value pairs, enclosed in curly braces
    */
    jsmntok_t* root_json_token = json_tokens;

    NetLogEventConstants netlog_event_constants = {0};
    if (!parse_log_event_constants((char*)filebuf, root_json_token, &netlog_event_constants)) {
        ws_debug("Failed to parse one or more netlog event constants.");
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    /* At this point, we have all of the constants needed within 'json_logevent_constants'
       We can now begin parsing the events to extract the data!
    */
    jsmntok_t* json_events = json_get_array((const char*)filebuf, root_json_token, "events");

    if (!parse_json_events((char*)filebuf, netlog_event_constants, json_events, json_packets_ht)){
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    if (g_hash_table_size(json_packets_ht) == 0){
        /* Might be a NetLog capture without any data. Skip it so it can be parsed by the JSON parser. */
        g_free(json_tokens);
        g_free(filebuf);
        return false;
    }

    g_free(json_tokens);
    g_free(filebuf);
    return true;
}

/* Read the next packet */
static bool netlog_read(wtap* wth, wtap_rec* rec, int* err, char** err_info, int64_t* data_offset)
{
    /* Release the data, one packet at a time: */
    NetLogState* netlog_state = wth->priv;

    if (!netlog_read_packet(wth, rec, netlog_state->json_packets_ht, netlog_state->idx, err, err_info, wth->fh)) {
        return false;
    }

    *data_offset = netlog_state->idx;
    netlog_state->idx += 1;

    return true;
}

/* Read the packet at the specified offset (effectively, the index) */
static bool netlog_seek_read(wtap* wth, int64_t seek_off, wtap_rec* rec, int* err, char** err_info)
{
    /* Release the requested packet */
    NetLogState* netlog_state = wth->priv;
    if (!netlog_read_packet(wth, rec, netlog_state->json_packets_ht, (int)seek_off, err, err_info, wth->random_fh)) {
        return false;
    }

    return true;
}

/* close handler to free any persistent data */
static void netlog_close(wtap* wth) {
    if (wth->priv != NULL) {
        NetLogState* netlog_state = wth->priv;
        g_hash_table_destroy(netlog_state->json_packets_ht);
    }
}

/**
 * Called to determine if a file matches this handler.
 * Returns WTAP_OPEN_MINE if the provided file is a NetLog file.
 *
 * Note: Allocates memory for a netlog_state and stores it as wth->priv.
 */
wtap_open_return_val netlog_open(wtap* wth, int* err, char** err_info)
{
    /**
     * Parsing JSON is very slow. To avoid parsing the entire
     * file multiple times, store the cached result.
     */
    NetLogState* netlog_state = g_new0(NetLogState, 1);
    if (!netlog_state) {
        return WTAP_OPEN_ERROR;
    }
    /* Mapping of 'offset' (index) to json data */
    netlog_state->json_packets_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    /* Parse and store the packets for future use: */
    if (!netlog_parse_entirety(wth, wth->fh, err, err_info, netlog_state->json_packets_ht)) {
        g_hash_table_destroy(netlog_state->json_packets_ht);
        g_free(netlog_state);
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        g_hash_table_destroy(netlog_state->json_packets_ht);
        g_free(netlog_state);
        return WTAP_OPEN_ERROR;
    }

    wth->priv = netlog_state;
    wth->file_type_subtype = netlog_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_RAW_IP;
    wth->file_tsprec = WTAP_TSPREC_MSEC;
    wth->subtype_read = netlog_read;
    wth->subtype_seek_read = netlog_seek_read;
    wth->subtype_close = netlog_close;
    wth->snapshot_length = 0;
    return WTAP_OPEN_MINE;
}

static const struct supported_block_type netlog_blocks_supported[] = {
    /* We support packet blocks, with no comments or other options. */
    { WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info netlog_info = {
    "NetLog", "netlog", "json", NULL,
    false, BLOCKS_SUPPORTED(netlog_blocks_supported),
    NULL, NULL, NULL
};

void register_netlog(void)
{
    netlog_file_type_subtype = wtap_register_file_type_subtype(&netlog_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("netlog",
        netlog_file_type_subtype);
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
