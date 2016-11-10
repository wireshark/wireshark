/* androiddump.c
 * androiddump is extcap tool used to capture Android specific stuff
 *
 * Copyright 2015, Michal Labedzki for Tieto Corporation
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
#include "config.h"

#include "extcap-base.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#endif

#ifdef HAVE_UNISTD_H
    #include <unistd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
    #include <sys/socket.h>
#endif

#ifdef HAVE_ARPA_INET_H
    #include <arpa/inet.h>
#endif

/* Configuration options */
/* #define ANDROIDDUMP_USE_LIBPCAP */
#define EXTCAP_ENCAP_BLUETOOTH_H4_WITH_PHDR    1
#define EXTCAP_ENCAP_WIRESHARK_UPPER_PDU       2
#define EXTCAP_ENCAP_ETHERNET                  3
#define PCAP_GLOBAL_HEADER_LENGTH              24
#define PCAP_RECORD_HEADER_LENGTH              16

#ifdef ANDROIDDUMP_USE_LIBPCAP
    #include <pcap.h>
    #include <pcap-bpf.h>
    #include <pcap/bluetooth.h>

    #ifndef DLT_BLUETOOTH_H4_WITH_PHDR
    #define DLT_BLUETOOTH_H4_WITH_PHDR 201
    #endif

    #ifndef DLT_WIRESHARK_UPPER_PDU
    #define DLT_WIRESHARK_UPPER_PDU  252
    #endif

    #ifndef PCAP_TSTAMP_PRECISION_MICRO
    #define PCAP_TSTAMP_PRECISION_MICRO 0
    #endif

    #ifndef PCAP_TSTAMP_PRECISION_NANO
    #define PCAP_TSTAMP_PRECISION_NANO 1
    #endif
#else
    #include "wiretap/wtap.h"
#endif

#define WIRESHARK_UPPER_PDU_TAG_DISSECTOR_NAME  0x000C

#define INTERFACE_ANDROID_LOGCAT_MAIN                   "android-logcat-main"
#define INTERFACE_ANDROID_LOGCAT_SYSTEM                 "android-logcat-system"
#define INTERFACE_ANDROID_LOGCAT_RADIO                  "android-logcat-radio"
#define INTERFACE_ANDROID_LOGCAT_EVENTS                 "android-logcat-events"
#define INTERFACE_ANDROID_LOGCAT_TEXT_MAIN              "android-logcat-text-main"
#define INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM            "android-logcat-text-system"
#define INTERFACE_ANDROID_LOGCAT_TEXT_RADIO             "android-logcat-text-radio"
#define INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS            "android-logcat-text-events"
#define INTERFACE_ANDROID_LOGCAT_TEXT_CRASH             "android-logcat-text-crash"
#define INTERFACE_ANDROID_BLUETOOTH_HCIDUMP             "android-bluetooth-hcidump"
#define INTERFACE_ANDROID_BLUETOOTH_EXTERNAL_PARSER     "android-bluetooth-external-parser"
#define INTERFACE_ANDROID_BLUETOOTH_BTSNOOP_NET         "android-bluetooth-btsnoop-net"
#define INTERFACE_ANDROID_WIFI_TCPDUMP                  "android-wifi-tcpdump"

#define ANDROIDDUMP_VERSION_MAJOR    "1"
#define ANDROIDDUMP_VERSION_MINOR    "0"
#define ANDROIDDUMP_VERSION_RELEASE  "3"

#define SERIAL_NUMBER_LENGTH_MAX  512
#define MODEL_NAME_LENGTH_MAX      64

#define PACKET_LENGTH 65535

#define SOCKET_SEND_TIMEOUT_MS 500

#define verbose_print(...) { if (verbose) printf(__VA_ARGS__); }

enum exit_code {
    EXIT_CODE_SUCCESS = 0,
    EXIT_CODE_CANNOT_GET_INTERFACES_LIST = 1,
    EXIT_CODE_UNKNOWN_ENCAPSULATION_WIRETAP,
    EXIT_CODE_UNKNOWN_ENCAPSULATION_LIBPCAP,
    EXIT_CODE_CANNOT_SAVE_WIRETAP_DUMP,
    EXIT_CODE_CANNOT_SAVE_LIBPCAP_DUMP,
    EXIT_CODE_NO_INTERFACE_SPECIFIED,
    EXIT_CODE_INVALID_INTERFACE,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_1,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_2,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_3,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_4,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_5,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_6,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_7,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_8,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_9,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_10,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_11,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_12,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_13,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_14,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_15,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_16,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_17,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_18,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_19,
    EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_20,
    EXIT_CODE_ERROR_WHILE_SENDING_ADB_PACKET_1,
    EXIT_CODE_ERROR_WHILE_SENDING_ADB_PACKET_2,
    EXIT_CODE_ERROR_WHILE_SENDING_ADB_PACKET_3,
    EXIT_CODE_ERROR_WHILE_SENDING_ADB_PACKET_4,
    EXIT_CODE_ERROR_WHILE_RECEIVING_ADB_PACKET_STATUS,
    EXIT_CODE_ERROR_WHILE_RECEIVING_ADB_PACKET_DATA,
    EXIT_CODE_INVALID_SOCKET_INTERFACES_LIST,
    EXIT_CODE_INVALID_SOCKET_1,
    EXIT_CODE_INVALID_SOCKET_2,
    EXIT_CODE_INVALID_SOCKET_3,
    EXIT_CODE_INVALID_SOCKET_4,
    EXIT_CODE_INVALID_SOCKET_5,
    EXIT_CODE_INVALID_SOCKET_6,
    EXIT_CODE_INVALID_SOCKET_7,
    EXIT_CODE_INVALID_SOCKET_8,
    EXIT_CODE_INVALID_SOCKET_9,
    EXIT_CODE_INVALID_SOCKET_10,
    EXIT_CODE_INVALID_SOCKET_11,
    EXIT_CODE_GENERIC = -1
};

enum {
    EXTCAP_BASE_OPTIONS_ENUM,
    OPT_HELP,
    OPT_VERSION,
    OPT_VERBOSE,
    OPT_CONFIG_ADB_SERVER_IP,
    OPT_CONFIG_ADB_SERVER_TCP_PORT,
    OPT_CONFIG_LOGCAT_TEXT,
    OPT_CONFIG_BT_SERVER_TCP_PORT,
    OPT_CONFIG_BT_FORWARD_SOCKET,
    OPT_CONFIG_BT_LOCAL_IP,
    OPT_CONFIG_BT_LOCAL_TCP_PORT
};

static struct option longopts[] = {
    EXTCAP_BASE_OPTIONS,
    { "help",                 no_argument,       NULL, OPT_HELP},
    { "version",              no_argument,       NULL, OPT_VERSION},
    { "verbose",              optional_argument, NULL, OPT_VERBOSE},
    { "adb-server-ip",        required_argument, NULL, OPT_CONFIG_ADB_SERVER_IP},
    { "adb-server-tcp-port",  required_argument, NULL, OPT_CONFIG_ADB_SERVER_TCP_PORT},
    { "logcat-text",          required_argument, NULL, OPT_CONFIG_LOGCAT_TEXT},
    { "bt-server-tcp-port",   required_argument, NULL, OPT_CONFIG_BT_SERVER_TCP_PORT},
    { "bt-forward-socket",    required_argument, NULL, OPT_CONFIG_BT_FORWARD_SOCKET},
    { "bt-local-ip",          required_argument, NULL, OPT_CONFIG_BT_LOCAL_IP},
    { "bt-local-tcp-port",    required_argument, NULL, OPT_CONFIG_BT_LOCAL_TCP_PORT},
    { 0, 0, 0, 0 }
};

struct interface_t {
    const char          *display_name;
    const char          *interface_name;
    struct interface_t  *next;
};

struct exported_pdu_header {
    uint16_t  tag;
    uint16_t  length;
/*  unsigned char value[0]; */
};


typedef struct _own_pcap_bluetooth_h4_header {
    uint32_t direction;
} own_pcap_bluetooth_h4_header;

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

/* This fix compilator warning like "warning: cast from 'char *' to 'uint32_t *' (aka 'unsigned int *') increases required alignment from 1 to 4 " */
typedef union {
    char      *value_char;
    uint8_t   *value_u8;
    uint16_t  *value_u16;
    uint32_t  *value_u32;
    uint64_t  *value_u64;
    int8_t    *value_i8;
    int16_t   *value_i16;
    int32_t   *value_i32;
    int64_t   *value_i64;
    own_pcap_bluetooth_h4_header  *value_own_pcap_bluetooth_h4_header;
} data_aligned_t;

#define SET_DATA(dest, type, src) \
    { \
        data_aligned_t data_aligned; \
            \
        data_aligned.value_char = src; \
        dest = data_aligned.type; \
    }

struct extcap_dumper {
    int encap;
    union  {
#ifdef ANDROIDDUMP_USE_LIBPCAP
        pcap_dumper_t  *pcap;
#else
        wtap_dumper    *wtap;
#endif
    } dumper;
};

/* Globals */
static int verbose = 0;
static int endless_loop = 1;

/* Functions */
static inline int is_specified_interface(char *interface, const char *interface_prefix) {
    return !strncmp(interface, interface_prefix, strlen(interface_prefix));
}

static void useSndTimeout(socket_handle_t  sock) {
#ifdef _WIN32
    const DWORD socket_timeout = SOCKET_SEND_TIMEOUT_MS;

    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *) &socket_timeout, sizeof(socket_timeout));
#else
    const struct timeval socket_timeout = {
        .tv_sec = SOCKET_SEND_TIMEOUT_MS / 1000,
        .tv_usec = (SOCKET_SEND_TIMEOUT_MS % 1000) * 1000
    };

    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &socket_timeout, sizeof(socket_timeout));
#endif
}

static struct extcap_dumper extcap_dumper_open(char *fifo, int encap) {
    struct extcap_dumper extcap_dumper;
    int                  encap_ext;

#ifdef ANDROIDDUMP_USE_LIBPCAP
    pcap_t  *pcap;

    if (encap == EXTCAP_ENCAP_BLUETOOTH_H4_WITH_PHDR)
        encap_ext = DLT_BLUETOOTH_H4_WITH_PHDR;
    else if (encap == EXTCAP_ENCAP_WIRESHARK_UPPER_PDU)
        encap_ext = DLT_WIRESHARK_UPPER_PDU;
    else if (encap == EXTCAP_ENCAP_ETHERNET)
        encap_ext = DLT_EN10MB;
    else {
        errmsg_print("ERROR: Unknown encapsulation");
        exit(EXIT_CODE_UNKNOWN_ENCAPSULATION_LIBPCAP);
    }

    pcap = pcap_open_dead_with_tstamp_precision(encap_ext, PACKET_LENGTH, PCAP_TSTAMP_PRECISION_NANO);
    extcap_dumper.dumper.pcap = pcap_dump_open(pcap, fifo);
    if (!extcap_dumper.dumper.pcap) {
        errmsg_print("ERROR: Cannot save lipcap dump file");
        exit(EXIT_CODE_CANNOT_SAVE_LIBPCAP_DUMP);
    }
    extcap_dumper.encap = encap;
    pcap_dump_flush(extcap_dumper.dumper.pcap);
#else
    int err = 0;

    init_open_routines();
#ifdef HAVE_PLUGINS
    wtap_register_plugin_types();
    register_all_wiretap_modules();
#endif

    if (encap == EXTCAP_ENCAP_BLUETOOTH_H4_WITH_PHDR)
        encap_ext = WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR;
    else if (encap == EXTCAP_ENCAP_WIRESHARK_UPPER_PDU)
        encap_ext = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
    else if (encap == EXTCAP_ENCAP_ETHERNET)
        encap_ext = WTAP_ENCAP_ETHERNET;
    else {
        errmsg_print("ERROR: Unknown Wiretap encapsulation");
        exit(EXIT_CODE_UNKNOWN_ENCAPSULATION_WIRETAP);
    }

    extcap_dumper.dumper.wtap = wtap_dump_open(fifo, WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC, encap_ext, PACKET_LENGTH, FALSE, &err);
    if (!extcap_dumper.dumper.wtap) {
        errmsg_print("ERROR: Cannot save dump file");
        exit(EXIT_CODE_CANNOT_SAVE_WIRETAP_DUMP);
    }
    extcap_dumper.encap = encap;
    wtap_dump_flush(extcap_dumper.dumper.wtap);
#endif

    return extcap_dumper;
}

static gboolean extcap_dumper_dump(struct extcap_dumper extcap_dumper, char *buffer,
        gssize captured_length, gssize reported_length,
        time_t seconds, int nanoseconds) {
#ifdef ANDROIDDUMP_USE_LIBPCAP
    struct pcap_pkthdr  pcap_header;

    pcap_header.caplen = (bpf_u_int32) captured_length;
    pcap_header.len = (bpf_u_int32) reported_length;
    pcap_header.ts.tv_sec = seconds;
    pcap_header.ts.tv_usec = nanoseconds / 1000;

    pcap_dump((u_char *) extcap_dumper.dumper.pcap, &pcap_header, buffer);
    pcap_dump_flush(extcap_dumper.dumper.pcap);
#else
    int                 err = 0;
    char               *err_info;
    struct wtap_pkthdr  hdr;

    hdr.presence_flags = WTAP_HAS_TS;
    hdr.caplen = (guint32) captured_length;
    hdr.len = (guint32) reported_length;

    hdr.ts.secs = seconds;
    hdr.ts.nsecs = (int) nanoseconds;

    hdr.opt_comment = 0;
    hdr.opt_comment = NULL;
    hdr.drop_count = 0;
    hdr.pack_flags = 0;
    hdr.rec_type = REC_TYPE_PACKET;

/*  NOTE: Try to handle pseudoheaders manually */
    if (extcap_dumper.encap == EXTCAP_ENCAP_BLUETOOTH_H4_WITH_PHDR) {
        uint32_t *direction;

        SET_DATA(direction, value_u32, buffer)

        hdr.pseudo_header.bthci.sent = GINT32_FROM_BE(*direction) ? 0 : 1;

        hdr.len -= (guint32)sizeof(own_pcap_bluetooth_h4_header);
        hdr.caplen -= (guint32)sizeof(own_pcap_bluetooth_h4_header);

        buffer += sizeof(own_pcap_bluetooth_h4_header);
        hdr.pkt_encap = WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR;
    }
    else if (extcap_dumper.encap == EXTCAP_ENCAP_ETHERNET) {
        hdr.pkt_encap = WTAP_ENCAP_ETHERNET;
    }
    else {
        hdr.pkt_encap = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
    }

    if (!wtap_dump(extcap_dumper.dumper.wtap, &hdr, (const guint8 *) buffer, &err, &err_info)) {
        errmsg_print("ERROR: Cannot dump: %s", err_info);
        return FALSE;
    }

    wtap_dump_flush(extcap_dumper.dumper.wtap);
#endif

    return TRUE;
}


static socket_handle_t adb_connect(const char *server_ip, unsigned short *server_tcp_port) {
    socket_handle_t        sock;
    socklen_t              length;
    struct sockaddr_in     server;

    memset(&server, 0x0, sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = GINT16_TO_BE(*server_tcp_port);
    server.sin_addr.s_addr = inet_addr(server_ip);

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
        errmsg_print("ERROR: Cannot open system TCP socket: %s", strerror(errno));
        return INVALID_SOCKET;
    }

    useSndTimeout(sock);

    if (connect(sock, (struct sockaddr *) &server, sizeof(server)) == SOCKET_ERROR) {
#if 0
/* NOTE: This does not work well - make significant delay while initializing Wireshark.
         Do fork() then call "adb" also does not make sense, because there is need to
         do something like sleep(1) to ensure adb is started... system() cannot be used
         on Windows, because open console window. This helper does not work as expected,
         so disable it and user must ensure that adb is started (adb start-server,
         but also all other command start-server automatically)
*/
#ifdef _WIN32
        if (_execlp("adb", "adb", "start-server", NULL)) {
#else
        if (execlp("adb", "adb", "start-server", NULL)) {
#endif
            errmsg("WARNING: Cannot execute system command to start adb: %s", strerror(errno));
            closesocket(sock);
            return INVALID_SOCKET;
        };

        if (connect(sock, (struct sockaddr *) &server, sizeof(server)) == SOCKET_ERROR) {
            errmsg_print("ERROR: Cannot connect to ADB: <%s> Please check that adb daemon is running.", strerror(errno));
            closesocket(sock);
            return INVALID_SOCKET;
        }
#else
    verbose_print("Cannot connect to ADB: <%s> Please check that adb daemon is running.\n", strerror(errno));
    closesocket(sock);
    return INVALID_SOCKET;
#endif
    }

    if (verbose) {
        struct sockaddr_in  client;

        length = sizeof(client);
        if (getsockname(sock, (struct sockaddr *) &client, &length)) {
            errmsg_print("ERROR getsockname: %s", strerror(errno));
            closesocket(sock);
            return INVALID_SOCKET;
        }

        if (length != sizeof(client)) {
            errmsg_print("ERROR: incorrect length");
            closesocket(sock);
            return INVALID_SOCKET;
        }

        verbose_print("VERBOSE: Client port %u\n", GUINT16_FROM_BE(client.sin_port));
    }

    return sock;
}


static char *adb_send_and_receive(socket_handle_t sock, const char *adb_service,
        char *buffer, int buffer_length, gssize *data_length) {
    gssize   used_buffer_length;
    gssize   length;
    gssize   result;
    char     status[4];
    char     tmp_buffer;
    size_t   adb_service_length;

    adb_service_length = strlen(adb_service);

    result = send(sock, adb_service, (int) adb_service_length, 0);
    if (result != (gssize) adb_service_length) {
        errmsg_print("ERROR: Error while sending <%s> to ADB daemon", adb_service);
        if (data_length)
            *data_length = 0;
        return NULL;
    }

    used_buffer_length = 0;
    while (used_buffer_length < 8) {
        result = recv(sock, buffer + used_buffer_length,  (int)(buffer_length - used_buffer_length), 0);

        if (result <= 0) {
            errmsg_print("ERROR: Broken socket connection while fetching reply status for <%s>", adb_service);

            return NULL;
        }

        used_buffer_length += result;
    }

    memcpy(status, buffer, 4);
    tmp_buffer = buffer[8];
    buffer[8] = '\0';
    length = (gssize) g_ascii_strtoll(buffer + 4, NULL, 16);
    buffer[8] = tmp_buffer;

    while (used_buffer_length < length + 8) {
        result = recv(sock, buffer + used_buffer_length,  (int)(buffer_length - used_buffer_length), 0);

        if (result <= 0) {
            errmsg_print("ERROR: Broken socket connection while reading reply for <%s>", adb_service);

            return NULL;
        }

        used_buffer_length += result;
    }

    if (data_length)
        *data_length = used_buffer_length - 8;

    if (memcmp(status, "OKAY", 4)) {
        errmsg_print("ERROR: Error while receiving by ADB for <%s>", adb_service);
        if (data_length)
            *data_length = 0;
        return NULL;
    }

    return buffer + 8;
}


static char *adb_send_and_read(socket_handle_t sock, const char *adb_service, char *buffer,
        int buffer_length, gssize *data_length) {
    gssize   used_buffer_length;
    gssize   result;
    char     status[4];
    size_t   adb_service_length;

    adb_service_length = strlen(adb_service);

    result = send(sock, adb_service, (int) adb_service_length, 0);
    if (result != (gssize) adb_service_length) {
        errmsg_print("ERROR: Error while sending <%s> to ADB", adb_service);
        if (data_length)
            *data_length = 0;
        return NULL;
    }

    used_buffer_length = 0;
    while (used_buffer_length < 4) {
        result = recv(sock, buffer + used_buffer_length,  (int)(buffer_length - used_buffer_length), 0);

        if (result <= 0) {
            errmsg_print("ERROR: Broken socket connection while fetching reply status for <%s>", adb_service);

            return NULL;
        }

        used_buffer_length += result;
    }

    memcpy(status, buffer, 4);

    while (result > 0) {
        result= recv(sock, buffer + used_buffer_length,  (int)(buffer_length - used_buffer_length), 0);

        if (result < 0) {
            errmsg_print("ERROR: Broken socket connection while reading reply for <%s>", adb_service);

            return NULL;
        } else if (result == 0) {
            break;
        }

        used_buffer_length += result;
    }

    if (data_length)
        *data_length = used_buffer_length - 4;

    if (memcmp(status, "OKAY", 4)) {
        errmsg_print("ERROR: Error while receiving by ADB for <%s>", adb_service);
        if (data_length)
            *data_length = 0;
        return NULL;
    }

    return buffer + 4;
}


static int adb_send(socket_handle_t sock, const char *adb_service) {
    char buffer[4];
    gssize   used_buffer_length;
    gssize   result;
    size_t   adb_service_length;

    adb_service_length = strlen(adb_service);

    result = send(sock, adb_service, (int) adb_service_length, 0);
    if (result != (gssize) adb_service_length) {
        errmsg_print("ERROR: Error while sending <%s> to ADB", adb_service);
        return EXIT_CODE_ERROR_WHILE_SENDING_ADB_PACKET_1;
    }

    used_buffer_length = 0;
    while (used_buffer_length < 4) {
        result = recv(sock, buffer + used_buffer_length,  (int)(sizeof(buffer) - used_buffer_length), 0);

        if (result <= 0) {
            errmsg_print("ERROR: Broken socket connection while fetching reply status for <%s>", adb_service);

            return EXIT_CODE_ERROR_WHILE_RECEIVING_ADB_PACKET_STATUS;
        }

        used_buffer_length += result;
    }

    if (memcmp(buffer, "OKAY", 4)) {
        errmsg_print("ERROR: Error while receiving by ADB for <%s>", adb_service);

        return EXIT_CODE_ERROR_WHILE_RECEIVING_ADB_PACKET_DATA;
    }

    return EXIT_CODE_SUCCESS;
}

static void new_interface(extcap_parameters * extcap_conf, const gchar *interface_id,
        const gchar *model_name, const gchar *serial_number, const gchar *display_name)
{
    char *interface = g_strdup_printf("%s-%s", interface_id, serial_number);
    char *ifdisplay = g_strdup_printf("%s %s %s", display_name, model_name, serial_number);

    if (is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_HCIDUMP) ||
            is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_EXTERNAL_PARSER) ||
            is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_BTSNOOP_NET)) {

        extcap_base_register_interface_ext(extcap_conf, interface, ifdisplay, 99, "BluetoothH4", "Bluetooth HCI UART transport layer plus pseudo-header" );
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_MAIN) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_RADIO) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_CRASH)) {
        extcap_base_register_interface(extcap_conf, interface, ifdisplay, 252, "Upper PDU" );
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_WIFI_TCPDUMP)) {
        extcap_base_register_interface(extcap_conf, interface, ifdisplay, 1, "Ethernet");
    }
    g_free(interface);
    g_free(ifdisplay);
}


static int register_interfaces(extcap_parameters * extcap_conf, const char *adb_server_ip, unsigned short *adb_server_tcp_port) {
    static char            packet[PACKET_LENGTH];
    static char            helpful_packet[PACKET_LENGTH];
    char                  *response;
    char                  *device_list;
    gssize                 data_length;
    gssize                 device_length;
    socket_handle_t        sock;
    const char            *adb_transport_serial_templace = "%04x""host:transport:%s";
    const char            *adb_check_port_templace       = "%04x""shell:cat /proc/%s/net/tcp";
    const char            *adb_devices            = "000E""host:devices-l";
    const char            *adb_api_level          = "0022""shell:getprop ro.build.version.sdk";
    const char            *adb_hcidump_version    = "0017""shell:hcidump --version";
    const char            *adb_ps_droid_bluetooth = "0018""shell:ps droid.bluetooth";
    const char            *adb_ps_bluetooth_app   = "001E""shell:ps com.android.bluetooth";
    const char            *adb_tcpdump_help       = "0010""shell:tcpdump -h";
    char                   serial_number[SERIAL_NUMBER_LENGTH_MAX];
    size_t                 serial_number_length;
    char                   model_name[MODEL_NAME_LENGTH_MAX];
    int                    result;
    char                  *pos;
    char                  *i_pos;
    char                  *model_pos;
    char                  *device_pos;
    char                  *prev_pos;
    int                    api_level;
    int                    disable_interface;

/* NOTE: It seems that "adb devices" and "adb shell" closed connection
         so cannot send next command after them, there is need to reconnect */

    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
    if (sock == INVALID_SOCKET)
        return EXIT_CODE_INVALID_SOCKET_INTERFACES_LIST;

    device_list = adb_send_and_receive(sock, adb_devices, packet, sizeof(packet), &device_length);
    closesocket(sock);

    if (!device_list) {
        errmsg_print("ERROR: Cannot get list of interfaces from devices");

        return EXIT_CODE_CANNOT_GET_INTERFACES_LIST;
    }

    device_list[device_length] = '\0';
    pos = (char *) device_list;

    while (pos < (char *) (device_list + device_length)) {
        prev_pos = pos;
        pos = strchr(pos, ' ');
        i_pos = pos;
        result = (int) (pos - prev_pos);
        pos = strchr(pos, '\n') + 1;
        if (result >= (int) sizeof(serial_number)) {
            verbose_print("WARNING: Serial number too long, ignore device\n");
            continue;
        }
        memcpy(serial_number, prev_pos, result);
        serial_number[result] = '\0';
        serial_number_length = strlen(serial_number);

        model_name[0] = '\0';
        model_pos = g_strstr_len(i_pos, pos - i_pos, "model:");
        if (model_pos) {
            device_pos = g_strstr_len(i_pos, pos - i_pos, "device:");
            if (device_pos && device_pos - model_pos - 6 - 1 < MODEL_NAME_LENGTH_MAX) {
                memcpy(model_name, model_pos + 6, device_pos - model_pos - 6 - 1);
                model_name[device_pos - model_pos - 6 - 1] = '\0';
            }
        }

        if (model_name[0] == '\0')
            strcpy(model_name, "unknown");

        verbose_print("VERBOSE: Processing device: \"%s\" <%s>\n" , serial_number, model_name);

        /* Check for the presence of tcpdump in the android device. */

        sock = adb_connect(adb_server_ip, adb_server_tcp_port);
        if (sock == INVALID_SOCKET) continue;

        result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet for transport");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_1;
        }

        result = adb_send(sock, helpful_packet);
        if (result) {
            verbose_print("WARNING: Error while setting adb transport for <%s>\n", helpful_packet);
            closesocket(sock);
        } else {
            response = adb_send_and_read(sock, adb_tcpdump_help, helpful_packet, sizeof(helpful_packet), &data_length);
            closesocket(sock);

            if (response) {
                response[data_length] = '\0';

                /* If tcpdump is found in the android device, add Android Wifi Tcpdump as an interface  */
                if (strstr(response,"tcpdump version")) {
                    new_interface(extcap_conf, INTERFACE_ANDROID_WIFI_TCPDUMP, model_name, serial_number, "Android WiFi");
                }
            } else {
                verbose_print("WARNING: Error on socket: <%s>\n", helpful_packet);
            }
        }

        sock = adb_connect(adb_server_ip, adb_server_tcp_port);
        if (sock == INVALID_SOCKET) continue;

        result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_2;
        }

        result = adb_send(sock, helpful_packet);
        if (result) {
            verbose_print("WARNING: Error while setting adb transport for <%s>\n", helpful_packet);
            closesocket(sock);
            continue;
        }

        response = adb_send_and_read(sock, adb_api_level, helpful_packet, sizeof(helpful_packet), &data_length);
        closesocket(sock);

        if (!response) {
            verbose_print("WARNING: Error on socket: <%s>\n", helpful_packet);
            continue;
        }

        response[data_length] = '\0';
        api_level = (int) g_ascii_strtoll(response, NULL, 10);
        verbose_print("VERBOSE: Android API Level for %s is %i\n", serial_number, api_level);

        if (api_level < 21) {
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_MAIN,   model_name, serial_number, "Android Logcat Main");
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_SYSTEM, model_name, serial_number, "Android Logcat System");
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_RADIO,  model_name, serial_number, "Android Logcat Radio");
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_EVENTS, model_name, serial_number, "Android Logcat Events");
        } else {
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_TEXT_MAIN,   model_name, serial_number, "Android Logcat Main");
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM, model_name, serial_number, "Android Logcat System");
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_TEXT_RADIO,  model_name, serial_number, "Android Logcat Radio");
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS, model_name, serial_number, "Android Logcat Events");
            new_interface(extcap_conf, INTERFACE_ANDROID_LOGCAT_TEXT_CRASH,  model_name, serial_number, "Android Logcat Crash");
        }

        if (api_level >= 5 && api_level < 17) {
            disable_interface = 0;

            sock = adb_connect(adb_server_ip, adb_server_tcp_port);
            if (sock == INVALID_SOCKET) continue;

            result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
            if (result <= 0 || result > PACKET_LENGTH) {
                errmsg_print("ERROR: Error while completing adb packet");
                closesocket(sock);
                return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_3;
            }

            result = adb_send(sock, helpful_packet);
            if (result) {
                errmsg_print("ERROR: Error while setting adb transport for <%s>", helpful_packet);
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            response = adb_send_and_read(sock, adb_hcidump_version, helpful_packet, sizeof(helpful_packet), &data_length);
            closesocket(sock);
            if (!response || data_length < 1) {
                verbose_print("WARNING: Error while getting hcidump version by <%s> (%p len=%"G_GSSIZE_FORMAT")\n",
                    adb_hcidump_version, (void*)response, data_length);
                verbose_print("VERBOSE: Android hcidump version for %s is unknown\n", serial_number);
                disable_interface = 1;
            } else {
                response[data_length] = '\0';

                if (g_ascii_strtoull(response, NULL, 10) == 0) {
                    verbose_print("VERBOSE: Android hcidump version for %s is unknown\n", serial_number);
                    disable_interface = 1;
                } else {
                    verbose_print("VERBOSE: Android hcidump version for %s is %s\n", serial_number, response);
                }
            }

            if (!disable_interface) {
                new_interface(extcap_conf, INTERFACE_ANDROID_BLUETOOTH_HCIDUMP, model_name, serial_number, "Android Bluetooth Hcidump");
            }
        }

        if (api_level >= 17 && api_level < 21) {
            disable_interface = 0;
            sock = adb_connect(adb_server_ip, adb_server_tcp_port);
            if (sock == INVALID_SOCKET) continue;

            result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
            if (result <= 0 || result > PACKET_LENGTH) {
                errmsg_print("ERROR: Error while completing adb packet");
                closesocket(sock);
                return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_4;
            }

            result = adb_send(sock, helpful_packet);
            if (result) {
                errmsg_print("ERROR: Error while setting adb transport for <%s>", helpful_packet);
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            response = adb_send_and_read(sock, adb_ps_droid_bluetooth, helpful_packet, sizeof(helpful_packet), &data_length);
            closesocket(sock);
            if (!response || data_length < 1) {
                verbose_print("WARNING: Error while getting Bluetooth application process id by <%s> "
                    "(%p len=%"G_GSSIZE_FORMAT")\n", adb_hcidump_version, (void*)response, data_length);
                verbose_print( "VERBOSE: Android Bluetooth application PID for %s is unknown\n", serial_number);
                disable_interface = 1;
            } else {
                char  *data_str;
                char   pid[16];

                memset(pid, 0, sizeof(pid));
                response[data_length] = '\0';

                data_str = strchr(response, '\n');
                if (data_str && sscanf(data_str, "%*s %s", pid) == 1) {
                    verbose_print("VERBOSE: Android Bluetooth application PID for %s is %s\n", serial_number, pid);

                    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
                    if (sock == INVALID_SOCKET)
                        return EXIT_CODE_INVALID_SOCKET_1;

                    result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
                    if (result <= 0 || result > PACKET_LENGTH) {
                        errmsg_print("ERROR: Error while completing adb packet");
                        closesocket(sock);
                        return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_5;
                    }

                    result = adb_send(sock, helpful_packet);
                    if (result) {
                        errmsg_print("ERROR: Error while setting adb transport for <%s>", helpful_packet);
                        closesocket(sock);
                        return EXIT_CODE_GENERIC;
                    }

                    result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_check_port_templace, strlen(adb_check_port_templace) - 6 + strlen(pid), pid);
                    if (result <= 0 || result > PACKET_LENGTH) {
                        errmsg_print("ERROR: Error while completing adb packet");
                        closesocket(sock);
                        return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_6;
                    }

                    response = adb_send_and_read(sock, helpful_packet, helpful_packet, sizeof(helpful_packet), &data_length);
                    closesocket(sock);

                    if (!response) {
                        disable_interface = 1;
                    } else {
                        response[data_length] = '\0';

                        data_str = strchr(response, '\n');
                        if (data_str && sscanf(data_str, "%*s %s", pid) == 1 && strcmp(pid + 9, "10EA") == 0) {
                            verbose_print("VERBOSE: Bluedroid External Parser Port for %s is %s\n", serial_number, pid + 9);
                        } else {
                            disable_interface = 1;
                            verbose_print("VERBOSE: Bluedroid External Parser Port for %s is unknown\n", serial_number);
                        }
                    }
                } else {
                    disable_interface = 1;
                    verbose_print("VERBOSE: Android Bluetooth application PID for %s is unknown\n", serial_number);
                }
            }

            if (!disable_interface) {
                new_interface(extcap_conf, INTERFACE_ANDROID_BLUETOOTH_EXTERNAL_PARSER, model_name, serial_number, "Android Bluetooth External Parser");
            }
        }

        if (api_level >= 21) {
            disable_interface = 0;
            sock = adb_connect(adb_server_ip, adb_server_tcp_port);
            if (sock == INVALID_SOCKET) continue;

            result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
            if (result <= 0 || result > PACKET_LENGTH) {
                errmsg_print("ERROR: Error while completing adb packet");
                closesocket(sock);
                return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_7;
            }

            result = adb_send(sock, helpful_packet);
            if (result) {
                errmsg_print("ERROR: Error while setting adb transport for <%s>", helpful_packet);
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            if (api_level >= 23) {
                response = adb_send_and_read(sock, adb_ps_bluetooth_app, helpful_packet, sizeof(helpful_packet), &data_length);
            }  else
                response = adb_send_and_read(sock, adb_ps_droid_bluetooth, helpful_packet, sizeof(helpful_packet), &data_length);
            closesocket(sock);
            if (!response || data_length < 1) {
                verbose_print("WARNING: Error while getting Bluetooth application process id by <%s> "
                    "(%p len=%"G_GSSIZE_FORMAT")\n", adb_hcidump_version, (void*)response, data_length);
                verbose_print("VERBOSE: Android Bluetooth application PID for %s is unknown\n", serial_number);
                disable_interface = 1;
            } else {
                char  *data_str;
                char   pid[16];

                memset(pid, 0, sizeof(pid));
                response[data_length] = '\0';

                data_str = strchr(response, '\n');
                if (data_str && sscanf(data_str, "%*s %s", pid) == 1) {
                    verbose_print("VERBOSE: Android Bluetooth application PID for %s is %s\n", serial_number, pid);

                    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
                    if (sock == INVALID_SOCKET)
                        return EXIT_CODE_INVALID_SOCKET_2;

                    result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
                    if (result <= 0 || result > PACKET_LENGTH) {
                        errmsg_print("ERROR: Error while completing adb packet");
                        closesocket(sock);
                        return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_8;
                    }

                    result = adb_send(sock, helpful_packet);
                    if (result) {
                        errmsg_print("ERROR: Error while setting adb transport for <%s>", helpful_packet);
                        closesocket(sock);
                        return EXIT_CODE_GENERIC;
                    }

                    result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_check_port_templace, strlen(adb_check_port_templace) - 6 + strlen(pid), pid);
                    if (result <= 0 || result > PACKET_LENGTH) {
                        errmsg_print("ERROR: Error while completing adb packet");
                        closesocket(sock);
                        return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_9;
                    }

                    response = adb_send_and_read(sock, helpful_packet, helpful_packet, sizeof(helpful_packet), &data_length);
                    closesocket(sock);

                    if (!response) {
                        disable_interface = 1;
                    } else {
                        response[data_length] = '\0';

                        data_str = strchr(response, '\n');
                        if (data_str && sscanf(data_str, "%*s %s", pid) == 1 && strcmp(pid + 9, "22A8") == 0) {
                            verbose_print("VERBOSE: Btsnoop Net Port for %s is %s\n", serial_number, pid + 9);
                        } else {
                            disable_interface = 1;
                            verbose_print("VERBOSE: Btsnoop Net Port for %s is unknown\n", serial_number);
                        }
                    }
                } else {
                    disable_interface = 1;
                    verbose_print("VERBOSE: Android Bluetooth application PID for %s is unknown\n", serial_number);
                }
            }

            if (!disable_interface) {
                new_interface(extcap_conf, INTERFACE_ANDROID_BLUETOOTH_BTSNOOP_NET, model_name, serial_number, "Android Bluetooth Btsnoop Net");
            }
        }
    }

    return EXIT_CODE_SUCCESS;
}

static int list_config(char *interface) {
    if (!interface) {
        errmsg_print("ERROR: No interface specified.");
        return EXIT_CODE_NO_INTERFACE_SPECIFIED;
    }

    if (is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_EXTERNAL_PARSER)) {
        printf("arg {number=0}{call=--adb-server-ip}{display=ADB Server IP Address}{type=string}{default=127.0.0.1}\n"
                "arg {number=1}{call=--adb-server-tcp-port}{display=ADB Server TCP Port}{type=integer}{range=0,65535}{default=5037}\n"
                "arg {number=2}{call=--bt-server-tcp-port}{display=Bluetooth Server TCP Port}{type=integer}{range=0,65535}{default=4330}\n"
                "arg {number=3}{call=--bt-forward-socket}{display=Forward Bluetooth Socket}{type=boolean}{default=false}\n"
                "arg {number=4}{call=--bt-local-ip}{display=Bluetooth Local IP Address}{type=string}{default=127.0.0.1}\n"
                "arg {number=5}{call=--bt-local-tcp-port}{display=Bluetooth Local TCP Port}{type=integer}{range=0,65535}{default=4330}{tooltip=Used to do \"adb forward tcp:LOCAL_TCP_PORT tcp:SERVER_TCP_PORT\"}\n"
                "arg {number=6}{call=--verbose}{display=Verbose/Debug output on console}{type=boolean}{default=false}\n");
        return EXIT_CODE_SUCCESS;
    } else  if (is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_HCIDUMP) ||
            is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_BTSNOOP_NET) ||
            is_specified_interface(interface, INTERFACE_ANDROID_WIFI_TCPDUMP)) {
        printf("arg {number=0}{call=--adb-server-ip}{display=ADB Server IP Address}{type=string}{default=127.0.0.1}\n"
                "arg {number=1}{call=--adb-server-tcp-port}{display=ADB Server TCP Port}{type=integer}{range=0,65535}{default=5037}\n"
                "arg {number=2}{call=--verbose}{display=Verbose/Debug output on console}{type=boolean}{default=false}\n");
        return EXIT_CODE_SUCCESS;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS)) {
        printf("arg {number=0}{call=--adb-server-ip}{display=ADB Server IP Address}{type=string}{default=127.0.0.1}\n"
                "arg {number=1}{call=--adb-server-tcp-port}{display=ADB Server TCP Port}{type=integer}{range=0,65535}{default=5037}\n"
                "arg {number=2}{call=--logcat-text}{display=Use text logcat}{type=boolean}{default=false}\n"
                "arg {number=3}{call=--verbose}{display=Verbose/Debug output on console}{type=boolean}{default=false}\n");
        return EXIT_CODE_SUCCESS;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_MAIN) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_RADIO) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS) ||
            is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_CRASH)) {
        printf("arg {number=0}{call=--adb-server-ip}{display=ADB Server IP Address}{type=string}{default=127.0.0.1}\n"
                "arg {number=1}{call=--adb-server-tcp-port}{display=ADB Server TCP Port}{type=integer}{range=0,65535}{default=5037}\n"
                "arg {number=2}{call=--verbose}{display=Verbose/Debug output on console}{type=boolean}{default=false}\n");
        return EXIT_CODE_SUCCESS;
    }

    errmsg_print("ERROR: Invalid interface: <%s>", interface);
    return EXIT_CODE_INVALID_INTERFACE;
}


static void help(void) {
    unsigned int  i_opt;

    printf("Help\n");
    printf(" Usage:\n"
        " androiddump --extcap-interfaces [--adb-server-ip=<arg>] [--adb-server-tcp-port=<arg>]\n"
        " androiddump --extcap-interface=INTERFACE --extcap-dlts\n"
        " androiddump --extcap-interface=INTERFACE --extcap-config\n"
        " androiddump --extcap-interface=INTERFACE --fifo=PATH_FILENAME --capture \n");

    printf("\n Parameters:\n");
    for (i_opt = 0; i_opt < (sizeof(longopts) / sizeof(longopts[0])) - 1; i_opt += 1) {
        printf("  --%s%s\n", longopts[i_opt].name,
            (longopts[i_opt].has_arg == required_argument) ? "=<arg>" :
            ((longopts[i_opt].has_arg == optional_argument) ? "[=arg]" : ""));
    }

}


/*----------------------------------------------------------------------------*/
/* Android Bluetooth Hcidump */
/*----------------------------------------------------------------------------*/

static int capture_android_bluetooth_hcidump(char *interface, char *fifo,
        const char *adb_server_ip, unsigned short *adb_server_tcp_port) {
    struct extcap_dumper           extcap_dumper;
    static char                    data[PACKET_LENGTH];
    static char                    packet[PACKET_LENGTH];
    static char                    helpful_packet[PACKET_LENGTH];
    gssize                         length;
    gssize                         used_buffer_length = 0;
    socket_handle_t                sock;
    const char                    *adb_transport  = "0012""host:transport-any";
    const char                    *adb_transport_serial_templace = "%04x""host:transport:%s";
    const char                    *adb_shell_hcidump = "0013""shell:hcidump -R -t";
    const char                    *adb_shell_su_hcidump = "0019""shell:su -c hcidump -R -t";
    int                            result;
    char                          *serial_number = NULL;
    size_t                         serial_number_length = 0;
    time_t                         ts = 0;
    unsigned int                   captured_length;
    gint64                         hex;
    char                          *hex_data;
    char                          *new_hex_data;
    own_pcap_bluetooth_h4_header  *h4_header;
    gint64                         raw_length = 0;
    gint64                         frame_length;
    int                            ms = 0;
    struct tm                      date;
    char                           direction_character;
    int                            try_next = 0;

    SET_DATA(h4_header, value_own_pcap_bluetooth_h4_header, packet);

    extcap_dumper = extcap_dumper_open(fifo, EXTCAP_ENCAP_BLUETOOTH_H4_WITH_PHDR);

    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
    if (sock == INVALID_SOCKET)
        return EXIT_CODE_INVALID_SOCKET_3;

    if (is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_HCIDUMP) &&
            strlen(interface) > strlen(INTERFACE_ANDROID_BLUETOOTH_HCIDUMP) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_BLUETOOTH_HCIDUMP) + 1;
        serial_number_length = strlen(serial_number);
    }

    if (!serial_number) {
        result = adb_send(sock, adb_transport);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport for <%s>", adb_transport);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    } else {
        result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_10;
        }

        result = adb_send(sock, helpful_packet);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport for <%s>", helpful_packet);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    }

    result = adb_send(sock, adb_shell_hcidump);
    if (result) {
        errmsg_print("ERROR: Error while starting capture by sending command: %s", adb_shell_hcidump);
        closesocket(sock);
        return EXIT_CODE_GENERIC;
    }

    while (endless_loop) {
        char  *i_position;

        errno = 0;
        length = recv(sock, data + used_buffer_length, (int)(PACKET_LENGTH - used_buffer_length), 0);
        if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
            || errno == EWOULDBLOCK
#endif
            ) {
            continue;
        }
        else if (errno != 0) {
            errmsg_print("ERROR capture: %s", strerror(errno));
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        if (length <= 0) {
            errmsg_print("ERROR: Broken socket connection.");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        used_buffer_length += length;
        i_position =  (char *) memchr(data, '\n', used_buffer_length);
        if (i_position && i_position < data + used_buffer_length) {
            char *state_line_position = i_position + 1;

            if (!strncmp(data, "/system/bin/sh: hcidump: not found", 34)) {
                errmsg_print("ERROR: Command not found for <%s>", adb_shell_hcidump);
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            i_position =  (char *) memchr(i_position + 1, '\n', used_buffer_length);
            if (i_position) {
                i_position += 1;
                if (!strncmp(state_line_position, "Can't access device: Permission denied", 38)) {
                    verbose_print("WARNING: No permission for command <%s>\n", adb_shell_hcidump);
                    used_buffer_length = 0;
                    try_next += 1;
                    break;
                }
                memmove(data, i_position, used_buffer_length - (i_position - data));
                used_buffer_length = used_buffer_length - (gssize)(i_position - data);
                break;
            }
        }
    }

    if (try_next == 1) {
        sock = adb_connect(adb_server_ip, adb_server_tcp_port);
        if (sock == INVALID_SOCKET)
            return EXIT_CODE_INVALID_SOCKET_4;

        result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_11;
        }

        result = adb_send(sock, helpful_packet);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport for <%s>", helpful_packet);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        result = adb_send(sock, adb_shell_su_hcidump);
        if (result) {
            errmsg_print("ERROR: Error while starting capture by sending command: <%s>", adb_shell_su_hcidump);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        used_buffer_length = 0;
        while (endless_loop) {
            char  *i_position;

            errno = 0;
            length = recv(sock, data + used_buffer_length, (int)(PACKET_LENGTH - used_buffer_length), 0);
            if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
                || errno == EWOULDBLOCK
#endif
                ) {
                continue;
            }
            else if (errno != 0) {
                errmsg_print("ERROR capture: %s", strerror(errno));
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            if (length <= 0) {
                errmsg_print("ERROR: Broken socket connection.");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            used_buffer_length += length;
            i_position =  (char *) memchr(data, '\n', used_buffer_length);
            if (i_position && i_position < data + used_buffer_length) {
                if (!strncmp(data, "/system/bin/sh: su: not found", 29)) {
                    errmsg_print("ERROR: Command 'su' not found for <%s>", adb_shell_su_hcidump);
                    closesocket(sock);
                    return EXIT_CODE_GENERIC;
                }

                i_position =  (char *) memchr(i_position + 1, '\n', used_buffer_length);
                if (i_position) {
                    i_position += 1;
                    memmove(data, i_position, used_buffer_length - (i_position - data));
                    used_buffer_length = used_buffer_length - (gssize)(i_position - data);
                    break;
                }
            }
        }
    }

    while (endless_loop) {
        errno = 0;
        length = recv(sock, data + used_buffer_length,  (int)(PACKET_LENGTH - used_buffer_length), 0);
        if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
            || errno == EWOULDBLOCK
#endif
            ) {
            continue;
        }
        else if (errno != 0) {
            errmsg_print("ERROR capture: %s", strerror(errno));
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        if (length <= 0) {
            errmsg_print("ERROR: Broken socket connection.");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        while (endless_loop) {
            if (used_buffer_length + length >= 1) {
                hex_data = data + 29;
                hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);

                if  ((hex == 0x01 && used_buffer_length + length >= 4) ||
                        (hex == 0x02 && used_buffer_length + length >= 5) ||
                        (hex == 0x04 && used_buffer_length + length >= 3)) {

                    if (hex == 0x01) {
                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);
                        if (hex < 0 || hex >= 256 || hex_data == new_hex_data) {
                            errmsg_print("ERROR: data format error: %s", strerror(errno));
                            closesocket(sock);
                            return EXIT_CODE_GENERIC;
                        }

                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);
                        if (hex < 0 || hex >= 256 || hex_data == new_hex_data) {
                            errmsg_print("ERROR: data format error: %s", strerror(errno));
                            closesocket(sock);
                            return EXIT_CODE_GENERIC;
                        }

                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);

                        raw_length = hex + 4;
                    } else if (hex == 0x04) {
                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);
                        if (hex < 0 || hex >= 256 || hex_data == new_hex_data) {
                            errmsg_print("ERROR: data format error: %s", strerror(errno));
                            closesocket(sock);
                            return EXIT_CODE_GENERIC;
                        }

                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);

                        raw_length = hex + 3;
                    } else if (hex == 0x02) {
                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);
                        if (hex < 0 || hex >= 256 || hex_data == new_hex_data) {
                            errmsg_print("ERROR: data format error: %s", strerror(errno));
                            closesocket(sock);
                            return EXIT_CODE_GENERIC;
                        }

                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);
                        if (hex < 0 || hex >= 256 || hex_data == new_hex_data) {
                            errmsg_print("ERROR: data format error: %s", strerror(errno));
                            closesocket(sock);
                            return EXIT_CODE_GENERIC;
                        }

                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);
                        raw_length = hex + 5;

                        hex_data = new_hex_data;
                        hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);
                        raw_length += hex << 8;
                    }

                } else {
                    errmsg_print("ERROR: bad raw stream");
                    closesocket(sock);
                    return EXIT_CODE_GENERIC;
                }
            } else {
                used_buffer_length += length;
                break;
            }

            frame_length = raw_length * 3 + (raw_length / 20) * 4 + ((raw_length % 20) ? 2 : -2) + 29;

            if (used_buffer_length + length < frame_length) {
                used_buffer_length += length;
                break;
            }

            if (8 == sscanf(data, "%04d-%02d-%02d %02d:%02d:%02d.%06d %c",
                    &date.tm_year, &date.tm_mon, &date.tm_mday, &date.tm_hour,
                    &date.tm_min, &date.tm_sec, &ms, &direction_character)) {

                verbose_print("time %04d-%02d-%02d %02d:%02d:%02d.%06d %c\n",
                            date.tm_year, date.tm_mon, date.tm_mday, date.tm_hour,
                            date.tm_min, date.tm_sec, ms, direction_character);
                date.tm_mon -= 1;
                date.tm_year -= 1900;
                ts = mktime(&date);

                new_hex_data = data + 29;
            }

            captured_length = 0;

            while ((long)(new_hex_data - data + sizeof(own_pcap_bluetooth_h4_header)) < frame_length) {
                hex_data = new_hex_data;
                hex = g_ascii_strtoll(hex_data, &new_hex_data, 16);

                packet[sizeof(own_pcap_bluetooth_h4_header) + captured_length] = (char) hex;
                captured_length += 1;
            }

            h4_header->direction = GINT32_TO_BE(direction_character == '>');

            endless_loop = extcap_dumper_dump(extcap_dumper, packet,
                    captured_length + sizeof(own_pcap_bluetooth_h4_header),
                    captured_length + sizeof(own_pcap_bluetooth_h4_header),
                    ts,
                    ms * 1000);

            if (used_buffer_length + length >= frame_length) {
                memmove(data, data + frame_length, (size_t)(used_buffer_length + length - frame_length));
                used_buffer_length = (gssize)(used_buffer_length + length - frame_length);
                length = 0;
                continue;
            }
            length = 0;
        }
    }

    closesocket(sock);
    return EXIT_CODE_SUCCESS;
}

/*----------------------------------------------------------------------------*/
/* Android Bluetooth External Parser */
/*----------------------------------------------------------------------------*/

#define BLUEDROID_H4_PACKET_TYPE  0
#define BLUEDROID_TIMESTAMP_SIZE  8
#define BLUEDROID_H4_SIZE  1

static const uint64_t BLUEDROID_TIMESTAMP_BASE = G_GUINT64_CONSTANT(0x00dcddb30f2f8000);

#define BLUEDROID_H4_PACKET_TYPE_HCI_CMD  0x01
#define BLUEDROID_H4_PACKET_TYPE_ACL      0x02
#define BLUEDROID_H4_PACKET_TYPE_SCO      0x03
#define BLUEDROID_H4_PACKET_TYPE_HCI_EVT  0x04

#define BLUEDROID_DIRECTION_SENT  0
#define BLUEDROID_DIRECTION_RECV  1

static int adb_forward(char *serial_number, const char *adb_server_ip, unsigned short *adb_server_tcp_port,
        unsigned short local_tcp_port, unsigned short server_tcp_port) {
    socket_handle_t       sock;
    int                   result;
    static char           helpful_packet[PACKET_LENGTH];
    static const char    *adb_forward_template = "%04x""%s%s:forward:tcp:%05u;tcp:%05u";

    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
    if (sock == INVALID_SOCKET)
        return EXIT_CODE_INVALID_SOCKET_5;

    result = g_snprintf(helpful_packet, PACKET_LENGTH, adb_forward_template, (serial_number) ? 5 + 7 + strlen(serial_number) + 28 : 4 + 28, (serial_number) ? "host-serial:" : "host", (serial_number) ?  serial_number: "", local_tcp_port, server_tcp_port);
    if (result <= 0 || result > PACKET_LENGTH) {
        errmsg_print("ERROR: Error while completing adb packet");
        closesocket(sock);
        return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_12;
    }

    result = adb_send(sock, helpful_packet);
    closesocket(sock);

    return result;
}

static int capture_android_bluetooth_external_parser(char *interface,
        char *fifo, const char *adb_server_ip, unsigned short *adb_server_tcp_port,
        unsigned short *bt_server_tcp_port, unsigned int bt_forward_socket, const char *bt_local_ip,
        unsigned short *bt_local_tcp_port) {
    struct extcap_dumper           extcap_dumper;
    static char                    buffer[PACKET_LENGTH];
    uint64_t                      *timestamp;
    char                          *packet = buffer + BLUEDROID_TIMESTAMP_SIZE - sizeof(own_pcap_bluetooth_h4_header); /* skip timestamp (8 bytes) and reuse its space for header */
    own_pcap_bluetooth_h4_header  *h4_header;
    guint8                        *payload = packet + sizeof(own_pcap_bluetooth_h4_header);
    const char                    *adb_transport  = "0012""host:transport-any";
    const char                    *adb_transport_serial_templace              = "%04x""host:transport:%s";
    const char                    *adb_tcp_bluedroid_external_parser_template = "%04x""tcp:%05u";
    gssize                         length;
    gssize                         used_buffer_length = 0;
    uint64_t                       ts;
    socket_handle_t                sock;
    struct sockaddr_in             server;
    int                            captured_length;
    char                          *serial_number = NULL;
    size_t                         serial_number_length = 0;

    SET_DATA(timestamp, value_u64, buffer);
    SET_DATA(h4_header, value_own_pcap_bluetooth_h4_header, packet);

    extcap_dumper = extcap_dumper_open(fifo, EXTCAP_ENCAP_BLUETOOTH_H4_WITH_PHDR);

    if (is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_EXTERNAL_PARSER) &&
            strlen(interface) > strlen(INTERFACE_ANDROID_BLUETOOTH_EXTERNAL_PARSER) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_BLUETOOTH_EXTERNAL_PARSER) + 1;
        serial_number_length = strlen(serial_number);
    }

    if (bt_forward_socket) {
        if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
            errmsg_print("ERROR: Cannot open system TCP socket: %s", strerror(errno));
            return EXIT_CODE_GENERIC;
        }

        verbose_print("Using config: Server TCP Port=%u, Local IP=%s, Local TCP Port=%u\n",
                    *bt_server_tcp_port, bt_local_ip, *bt_local_tcp_port);

        if (*bt_local_tcp_port != 0) {
            int result;

            result = adb_forward(serial_number, adb_server_ip, adb_server_tcp_port, *bt_local_tcp_port, *bt_server_tcp_port);
            verbose_print("DO: adb forward tcp:%u (local) tcp:%u (remote) result=%i\n",
                        *bt_local_tcp_port, *bt_server_tcp_port, result);
        }

        memset(&server, 0 , sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = GINT16_TO_BE(*bt_local_tcp_port);
        server.sin_addr.s_addr = inet_addr(bt_local_ip);

        useSndTimeout(sock);

        if (connect(sock, (struct sockaddr *) &server, sizeof(server)) == SOCKET_ERROR) {
            errmsg_print("ERROR: <%s> Please check that adb daemon is running.", strerror(errno));
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        if (verbose) {
            struct sockaddr_in  client;

            length = sizeof(client);
            if (getsockname(sock, (struct sockaddr *) &client, (socklen_t *) &length)) {
                errmsg_print("ERROR getsockname: %s", strerror(errno));
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            if (length != sizeof(client)) {
                errmsg_print("ERROR: incorrect length");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            verbose_print("VERBOSE: Client port %u\n", GUINT16_FROM_BE(client.sin_port));
        }
    } else {
        int  result;

        sock = adb_connect(adb_server_ip, adb_server_tcp_port);
        if (sock == INVALID_SOCKET)
            return EXIT_CODE_INVALID_SOCKET_6;

        if (!serial_number) {
            result = adb_send(sock, adb_transport);
            if (result) {
                errmsg_print("ERROR: Error while setting adb transport");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }
        } else {
            result = g_snprintf((char *) buffer, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
            if (result <= 0 || result > PACKET_LENGTH) {
                errmsg_print("ERROR: Error while completing adb packet");
                closesocket(sock);
                return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_13;
            }

            result = adb_send(sock, buffer);
            if (result) {
                errmsg_print("ERROR: Error while setting adb transport");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }
        }

        result = g_snprintf((char *) buffer, PACKET_LENGTH, adb_tcp_bluedroid_external_parser_template, 4 + 5, *bt_server_tcp_port);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_14;
        }

        result = adb_send(sock, buffer);
        if (result) {
            errmsg_print("ERROR: Error while forwarding adb port");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    }

    while (endless_loop) {
        errno = 0;
        length = recv(sock, buffer + used_buffer_length,  (int)(PACKET_LENGTH - used_buffer_length), 0);
        if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
            || errno == EWOULDBLOCK
#endif
            ) {
            continue;
        }
        else if (errno != 0) {
            errmsg_print("ERROR capture: %s", strerror(errno));
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        if (length <= 0) {
            if (bt_forward_socket) {
                /* NOTE: Workaround... It seems that Bluedroid is slower and we can connect to socket that are not really ready... */
                verbose_print("WARNING: Broken socket connection. Try reconnect.\n");
                closesocket(sock);

                if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) {
                    errmsg_print("ERROR: %s", strerror(errno));
                    return EXIT_CODE_GENERIC;
                }

                server.sin_family = AF_INET;
                server.sin_port = GINT16_TO_BE(*bt_local_tcp_port);
                server.sin_addr.s_addr = inet_addr(bt_local_ip);

                useSndTimeout(sock);

                if (connect(sock, (struct sockaddr *) &server, sizeof(server)) == SOCKET_ERROR) {
                    errmsg_print("ERROR reconnect: <%s> Please check that adb daemon is running.", strerror(errno));
                    closesocket(sock);
                    return EXIT_CODE_GENERIC;
                }
            } else {
                errmsg_print("ERROR: Broken socket connection.");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            continue;
        }

        used_buffer_length += length;

        verbose_print("Received: length=%"G_GSSIZE_FORMAT"\n", length);

        while (((payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_HCI_CMD || payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_SCO) &&
                    used_buffer_length >= BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + 1 &&
                    BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + payload[BLUEDROID_H4_SIZE + 2] + 1 <= used_buffer_length) ||
                (payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_ACL &&
                    used_buffer_length >= BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + 2 &&
                    BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + payload[BLUEDROID_H4_SIZE + 2] + (payload[BLUEDROID_H4_SIZE + 2 + 1] << 8) + 2 <= used_buffer_length) ||
                (payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_SCO &&
                    used_buffer_length >= BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + 1 &&
                    BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 2 + payload[BLUEDROID_H4_SIZE + 2] + 1 <= used_buffer_length) ||
                (payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_HCI_EVT &&
                    used_buffer_length >= BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 1 + 1 &&
                    BLUEDROID_TIMESTAMP_SIZE + BLUEDROID_H4_SIZE + 1 + payload[BLUEDROID_H4_SIZE + 1] + 1 <= used_buffer_length)) {

            ts = GINT64_FROM_BE(*timestamp);

            switch (payload[BLUEDROID_H4_PACKET_TYPE]) {
            case BLUEDROID_H4_PACKET_TYPE_HCI_CMD:
                h4_header->direction = GINT32_TO_BE(BLUEDROID_DIRECTION_SENT);

                captured_length = (unsigned int)sizeof(own_pcap_bluetooth_h4_header) + payload[3] + 4;

                length = sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_H4_SIZE + 2 + 1 + payload[3];

                break;
            case BLUEDROID_H4_PACKET_TYPE_ACL:
                h4_header->direction = (payload[2] & 0x80) ? GINT32_TO_BE(BLUEDROID_DIRECTION_RECV) : GINT32_TO_BE(BLUEDROID_DIRECTION_SENT);

                captured_length = (unsigned int)sizeof(own_pcap_bluetooth_h4_header) + payload[3] + (payload[3 + 1] << 8) + 5;

                length = sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_H4_SIZE + 2 + 2 + payload[3] + (gssize)(payload[3 + 1] << 8);

                break;
            case BLUEDROID_H4_PACKET_TYPE_SCO:
                h4_header->direction = (payload[2] & 0x80) ? GINT32_TO_BE(BLUEDROID_DIRECTION_RECV) : GINT32_TO_BE(BLUEDROID_DIRECTION_SENT);

                captured_length = (unsigned int)sizeof(own_pcap_bluetooth_h4_header) + payload[3] + 4;

                length = sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_H4_SIZE + 2 + 1 + payload[3];

                break;
            case BLUEDROID_H4_PACKET_TYPE_HCI_EVT:
                h4_header->direction = GINT32_TO_BE(BLUEDROID_DIRECTION_RECV);

                captured_length = (unsigned int)sizeof(own_pcap_bluetooth_h4_header) + payload[2] + 3;

                length = sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_H4_SIZE + 1 + 1 + payload[2];

                break;
            default:
                errmsg_print("ERROR: Invalid stream");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            if (verbose) {
                static unsigned int id = 1;
                verbose_print("\t Packet %u: used_buffer_length=%"G_GSSIZE_FORMAT" length=%"G_GSSIZE_FORMAT" captured_length=%i type=0x%02x\n", id, used_buffer_length, length, captured_length, payload[BLUEDROID_H4_PACKET_TYPE]);
                if (payload[BLUEDROID_H4_PACKET_TYPE] == BLUEDROID_H4_PACKET_TYPE_HCI_EVT)
                    verbose_print("\t Packet: %02x %02x %02x\n", (unsigned int) payload[0], (unsigned int) payload[1], (unsigned int)payload[2]);
                id +=1;
            }

            ts -= BLUEDROID_TIMESTAMP_BASE;

            endless_loop = extcap_dumper_dump(extcap_dumper, packet,
                    captured_length,
                    captured_length,
                    (uint32_t)(ts / 1000000),
                    ((uint32_t)(ts % 1000000)) * 1000);

            used_buffer_length -= length - sizeof(own_pcap_bluetooth_h4_header) + BLUEDROID_TIMESTAMP_SIZE;
            if (used_buffer_length < 0) {
                errmsg_print("ERROR: Internal error: Negative used buffer length.");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }
            memmove(buffer, packet + length, used_buffer_length);
        }
    }

    closesocket(sock);
    return EXIT_CODE_SUCCESS;
}

/*----------------------------------------------------------------------------*/
/* Android Btsnoop Net */
/*----------------------------------------------------------------------------*/

static int capture_android_bluetooth_btsnoop_net(char *interface, char *fifo,
        const char *adb_server_ip, unsigned short *adb_server_tcp_port) {
    struct extcap_dumper           extcap_dumper;
    static char                    packet[PACKET_LENGTH];
    gssize                         length;
    gssize                         used_buffer_length = 0;
    socket_handle_t                sock;
    const char                    *adb_transport  = "0012""host:transport-any";
    const char                    *adb_transport_serial_templace = "%04x""host:transport:%s";
    const char                    *adb_tcp_btsnoop_net   = "0008""tcp:8872";
    int                            result;
    char                          *serial_number = NULL;
    size_t                         serial_number_length;
    uint64_t                       ts;
    static const uint64_t          BTSNOOP_TIMESTAMP_BASE = G_GUINT64_CONSTANT(0x00dcddb30f2f8000);
    uint32_t                      *reported_length;
    uint32_t                      *captured_length;
    uint32_t                      *flags;
/*    uint32_t                     *cumulative_dropped_packets; */
    uint64_t                      *timestamp;
    char                          *payload                     =  packet + sizeof(own_pcap_bluetooth_h4_header) + 24;
    own_pcap_bluetooth_h4_header  *h4_header;

    SET_DATA(reported_length, value_u32, packet + sizeof(own_pcap_bluetooth_h4_header) + 0);
    SET_DATA(captured_length, value_u32, packet + sizeof(own_pcap_bluetooth_h4_header) + 4);
    SET_DATA(flags, value_u32, packet + sizeof(own_pcap_bluetooth_h4_header) + 8);
/*    SET_DATA(cumulative_dropped_packets, value_u32, packet + sizeof(own_pcap_bluetooth_h4_header) + 12); */
    SET_DATA(timestamp, value_u64, packet + sizeof(own_pcap_bluetooth_h4_header) + 16);
    SET_DATA(h4_header, value_own_pcap_bluetooth_h4_header, payload - sizeof(own_pcap_bluetooth_h4_header));

    extcap_dumper = extcap_dumper_open(fifo, EXTCAP_ENCAP_BLUETOOTH_H4_WITH_PHDR);

    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
    if (sock == INVALID_SOCKET)
        return EXIT_CODE_INVALID_SOCKET_7;

    if (is_specified_interface(interface, INTERFACE_ANDROID_BLUETOOTH_BTSNOOP_NET) &&
            strlen(interface) > strlen(INTERFACE_ANDROID_BLUETOOTH_BTSNOOP_NET) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_BLUETOOTH_BTSNOOP_NET) + 1;
        serial_number_length = strlen(serial_number);
    }

    if (!serial_number) {
        result = adb_send(sock, adb_transport);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport for <%s>", adb_transport);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    } else {
        result = g_snprintf((char *) packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_15;
        }

        result = adb_send(sock, packet);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport for <%s>", packet);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    }

    result = adb_send(sock, adb_tcp_btsnoop_net);
    if (result) {
        errmsg_print("ERROR: Error while sending command <%s>", adb_tcp_btsnoop_net);
        closesocket(sock);
        return EXIT_CODE_ERROR_WHILE_SENDING_ADB_PACKET_2;
    }

    /* Read "btsnoop" header - 16 bytes */
    while (used_buffer_length < 16) {
        length = recv(sock, packet + used_buffer_length,  (int)(PACKET_LENGTH - used_buffer_length), 0);

        if (length <= 0) {
            errmsg_print("ERROR: Broken socket connection.");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        used_buffer_length += length;
    }
    if (used_buffer_length > 16)
        memmove(packet, packet + 16, used_buffer_length - 16);

    used_buffer_length = 0;

    while (endless_loop) {
        errno = 0;
        length = recv(sock, packet + used_buffer_length + sizeof(own_pcap_bluetooth_h4_header),
                (int)(PACKET_LENGTH - sizeof(own_pcap_bluetooth_h4_header) - used_buffer_length), 0);
        if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
            || errno == EWOULDBLOCK
#endif
            ) {
            continue;
        }
        else if (errno != 0) {
            errmsg_print("ERROR capture: %s", strerror(errno));
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        if (length <= 0) {
            errmsg_print("ERROR: Broken socket connection.");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        used_buffer_length += length;

        while (used_buffer_length >= 24 &&
                used_buffer_length >= (int) (24 + GINT32_FROM_BE(*captured_length))) {
            gint32 direction;

            ts = GINT64_FROM_BE(*timestamp);
            ts -= BTSNOOP_TIMESTAMP_BASE;

            direction = GINT32_FROM_BE(*flags) & 0x01;
            h4_header->direction = GINT32_TO_BE(direction);

            endless_loop = extcap_dumper_dump(extcap_dumper, payload - sizeof(own_pcap_bluetooth_h4_header),
                    GINT32_FROM_BE(*captured_length) + sizeof(own_pcap_bluetooth_h4_header),
                    GINT32_FROM_BE(*reported_length) + sizeof(own_pcap_bluetooth_h4_header),
                    (uint32_t)(ts / 1000000),
                    ((uint32_t)(ts % 1000000)) * 1000);

            used_buffer_length -= 24 + GINT32_FROM_BE(*captured_length);
            if (used_buffer_length < 0) {
                errmsg_print("ERROR: Internal error: Negative used buffer length.");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            if  (used_buffer_length > 0)
                memmove(packet + sizeof(own_pcap_bluetooth_h4_header), payload + GINT32_FROM_BE(*captured_length), used_buffer_length);
        }
    }

    closesocket(sock);
    return EXIT_CODE_SUCCESS;
}

/*----------------------------------------------------------------------------*/
/* Android Logcat Text*/
/*----------------------------------------------------------------------------*/

static int capture_android_logcat_text(char *interface, char *fifo,
        const char *adb_server_ip, unsigned short *adb_server_tcp_port) {
    struct extcap_dumper        extcap_dumper;
    static char                 packet[PACKET_LENGTH];
    gssize                      length;
    size_t                      used_buffer_length = 0;
    socket_handle_t             sock;
    const char                 *protocol_name;
    size_t                      exported_pdu_headers_size = 0;
    struct exported_pdu_header  exported_pdu_header_protocol_normal;
    struct exported_pdu_header *exported_pdu_header_protocol;
    struct exported_pdu_header  exported_pdu_header_end = {0, 0};
    static const char          *wireshark_protocol_logcat_text = "logcat_text_threadtime";
    const char                 *adb_transport = "0012""host:transport-any";
    const char                 *adb_logcat_template = "%04x""shell:export ANDROID_LOG_TAGS=\"\" ; exec logcat -v threadtime%s%s";
    const char                 *adb_transport_serial_templace = "%04x""host:transport:%s";
    char                       *serial_number = NULL;
    size_t                      serial_number_length = 0;
    int                         result;
    char                       *pos;
    const char                 *logcat_buffer;

    extcap_dumper = extcap_dumper_open(fifo, EXTCAP_ENCAP_WIRESHARK_UPPER_PDU);

    exported_pdu_header_protocol_normal.tag = GUINT16_TO_BE(WIRESHARK_UPPER_PDU_TAG_DISSECTOR_NAME);
    exported_pdu_header_protocol_normal.length = GUINT16_TO_BE(strlen(wireshark_protocol_logcat_text) + 2);

    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
    if (sock == INVALID_SOCKET)
        return EXIT_CODE_INVALID_SOCKET_8;

    if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_MAIN) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_MAIN) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_SYSTEM) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_SYSTEM) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_RADIO) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_RADIO) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_EVENTS) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_EVENTS) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_MAIN) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_TEXT_MAIN) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_TEXT_MAIN) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_RADIO) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_TEXT_RADIO) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_TEXT_RADIO) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_CRASH) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_TEXT_CRASH) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_TEXT_CRASH) + 1;
    }

    if (!serial_number) {
        result = adb_send(sock, adb_transport);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport for <%s>", adb_transport);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    } else {
        serial_number_length = strlen(serial_number);

        result = g_snprintf((char *) packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_16;
        }

        result = adb_send(sock, packet);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport for <%s>", packet);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    }

    if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) || is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_MAIN))
        logcat_buffer = " -b main";
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) || is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM))
        logcat_buffer = " -b system";
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) || is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_RADIO))
        logcat_buffer = " -b radio";
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS) || is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS))
        logcat_buffer = " -b events";
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_TEXT_CRASH))
        logcat_buffer = " -b crash";
    else {
        errmsg_print("ERROR: Unknown interface: <%s>", interface);
        closesocket(sock);
        return EXIT_CODE_GENERIC;
    }


    result = g_snprintf((char *) packet, PACKET_LENGTH, adb_logcat_template, strlen(adb_logcat_template) + -8 + strlen(logcat_buffer), logcat_buffer, "");
    if (result <= 0 || result > PACKET_LENGTH) {
        errmsg_print("ERROR: Error while completing adb packet");
        closesocket(sock);
        return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_17;
    }

    result = adb_send(sock, packet);
    if (result) {
        errmsg_print("ERROR: Error while sending command <%s>", packet);
        closesocket(sock);
        return EXIT_CODE_ERROR_WHILE_SENDING_ADB_PACKET_3;
    }

    protocol_name = wireshark_protocol_logcat_text;
    exported_pdu_header_protocol = &exported_pdu_header_protocol_normal;

    memcpy(packet, exported_pdu_header_protocol, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header);

    memcpy(packet + exported_pdu_headers_size, protocol_name, GUINT16_FROM_BE(exported_pdu_header_protocol->length) - 2);
    exported_pdu_headers_size += GUINT16_FROM_BE(exported_pdu_header_protocol->length);

    packet[exported_pdu_headers_size - 1] = 0;
    packet[exported_pdu_headers_size - 2] = 0;

    memcpy(packet + exported_pdu_headers_size, &exported_pdu_header_end, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header) + GUINT16_FROM_BE(exported_pdu_header_end.length);

    used_buffer_length = 0;
    while (endless_loop) {
        errno = 0;
        length = recv(sock, packet + exported_pdu_headers_size + used_buffer_length,  (int)(PACKET_LENGTH - exported_pdu_headers_size - used_buffer_length), 0);
        if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
            || errno == EWOULDBLOCK
#endif
            ) {
            continue;
        }
        else if (errno != 0) {
            errmsg_print("ERROR capture: %s", strerror(errno));
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        if (length <= 0) {
            errmsg_print("ERROR: Broken socket connection. Try reconnect.");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        used_buffer_length += length;

        while (used_buffer_length > 0 && (pos = (char *) memchr(packet + exported_pdu_headers_size, '\n', used_buffer_length))) {
            int        ms;
            struct tm  date;
            time_t     seconds;
            time_t     secs = 0;
            int        nsecs = 0;

            length = (gssize)(pos - packet) + 1;

            if (6 == sscanf(packet + exported_pdu_headers_size, "%d-%d %d:%d:%d.%d", &date.tm_mon, &date.tm_mday, &date.tm_hour,
                            &date.tm_min, &date.tm_sec, &ms)) {
                date.tm_year = 70;
                date.tm_mon -= 1;
                seconds = mktime(&date);
                secs = (time_t) seconds;
                nsecs = (int) (ms * 1e6);
            }

            endless_loop = extcap_dumper_dump(extcap_dumper, packet,
                    length,
                    length,
                    secs, nsecs);

            memmove(packet + exported_pdu_headers_size, packet + length, used_buffer_length + exported_pdu_headers_size - length);
            used_buffer_length -= length - exported_pdu_headers_size;
        }
    }

    closesocket(sock);
    return EXIT_CODE_SUCCESS;
}

/*----------------------------------------------------------------------------*/
/* Android Logger / Logcat */
/*----------------------------------------------------------------------------*/

static int capture_android_logcat(char *interface, char *fifo,
        const char *adb_server_ip, unsigned short *adb_server_tcp_port) {
    struct extcap_dumper        extcap_dumper;
    static char                 packet[PACKET_LENGTH];
    static char                 helper_packet[PACKET_LENGTH];
    gssize                      length;
    size_t                      used_buffer_length = 0;
    socket_handle_t             sock;
    const char                 *protocol_name;
    size_t                      exported_pdu_headers_size = 0;
    struct exported_pdu_header  exported_pdu_header_protocol_events;
    struct exported_pdu_header  exported_pdu_header_protocol_normal;
    struct exported_pdu_header *exported_pdu_header_protocol;
    struct exported_pdu_header  exported_pdu_header_end = {0, 0};
    static const char          *wireshark_protocol_logcat = "logcat";
    static const char          *wireshark_protocol_logcat_events = "logcat_events";
    const char                 *adb_transport  = "0012""host:transport-any";
    const char                 *adb_log_main   = "0008""log:main";
    const char                 *adb_log_system = "000A""log:system";
    const char                 *adb_log_radio  = "0009""log:radio";
    const char                 *adb_log_events = "000A""log:events";
    const char                 *adb_transport_serial_templace = "%04x""host:transport:%s";
    const char                 *adb_command;
    uint16_t                   *payload_length;
    uint16_t                   *try_header_size;
    uint32_t                   *timestamp_secs;
    uint32_t                   *timestamp_nsecs;
    uint16_t                    header_size;
    int                         result;
    char                       *serial_number = NULL;
    size_t                      serial_number_length = 0;

    extcap_dumper = extcap_dumper_open(fifo, EXTCAP_ENCAP_WIRESHARK_UPPER_PDU);

    exported_pdu_header_protocol_events.tag = GUINT16_TO_BE(WIRESHARK_UPPER_PDU_TAG_DISSECTOR_NAME);
    exported_pdu_header_protocol_events.length = GUINT16_TO_BE(strlen(wireshark_protocol_logcat_events) + 2);

    exported_pdu_header_protocol_normal.tag = GUINT16_TO_BE(WIRESHARK_UPPER_PDU_TAG_DISSECTOR_NAME);
    exported_pdu_header_protocol_normal.length = GUINT16_TO_BE(strlen(wireshark_protocol_logcat) + 2);

    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
    if (sock == INVALID_SOCKET)
        return EXIT_CODE_INVALID_SOCKET_9;

    if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_MAIN) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_MAIN) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_SYSTEM) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_SYSTEM) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_RADIO) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_RADIO) + 1;
    } else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS) && strlen(interface) > strlen(INTERFACE_ANDROID_LOGCAT_EVENTS) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_LOGCAT_EVENTS) + 1;
    }

    if (!serial_number) {
        result = adb_send(sock, adb_transport);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    } else {
        serial_number_length = strlen(serial_number);

        result = g_snprintf(packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_18;
        }

        result = adb_send(sock, packet);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    }

    if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN))
        adb_command = adb_log_main;
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM))
        adb_command = adb_log_system;
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO))
        adb_command = adb_log_radio;
    else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS))
        adb_command = adb_log_events;
    else {
        errmsg_print("ERROR: Unknown interface: <%s>", interface);
        closesocket(sock);
        return EXIT_CODE_GENERIC;
    }

    result = adb_send(sock, adb_command);
    if (result) {
        errmsg_print("ERROR: Error while sending command <%s>", adb_command);
        closesocket(sock);
        return EXIT_CODE_ERROR_WHILE_SENDING_ADB_PACKET_4;
    }

    if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS))
    {
        protocol_name = wireshark_protocol_logcat_events;
        exported_pdu_header_protocol = &exported_pdu_header_protocol_events;
    } else {
        protocol_name = wireshark_protocol_logcat;
        exported_pdu_header_protocol = &exported_pdu_header_protocol_normal;
    }

    memcpy(packet, exported_pdu_header_protocol, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header);

    memcpy(packet + exported_pdu_headers_size, protocol_name, GUINT16_FROM_BE(exported_pdu_header_protocol->length) - 2);
    exported_pdu_headers_size += GUINT16_FROM_BE(exported_pdu_header_protocol->length);

    packet[exported_pdu_headers_size - 1] = 0;
    packet[exported_pdu_headers_size - 2] = 0;

    memcpy(packet + exported_pdu_headers_size, &exported_pdu_header_end, sizeof(struct exported_pdu_header));
    exported_pdu_headers_size += sizeof(struct exported_pdu_header) + GUINT16_FROM_BE(exported_pdu_header_end.length);

    SET_DATA(payload_length,  value_u16, packet + exported_pdu_headers_size +  0);
    SET_DATA(try_header_size, value_u16, packet + exported_pdu_headers_size +  2);
    SET_DATA(timestamp_secs,  value_u32, packet + exported_pdu_headers_size + 12);
    SET_DATA(timestamp_nsecs, value_u32, packet + exported_pdu_headers_size + 16);

    while (endless_loop) {
        errno = 0;
        length = recv(sock, packet + exported_pdu_headers_size + used_buffer_length, (int)(PACKET_LENGTH - exported_pdu_headers_size - used_buffer_length), 0);
        if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
            || errno == EWOULDBLOCK
#endif
            ) {
            continue;
        }
        else if (errno != 0) {
            errmsg_print("ERROR capture: %s", strerror(errno));
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        if (length <= 0) {
            while (endless_loop) {
                verbose_print("WARNING: Broken socket connection. Try reconnect.\n");
                used_buffer_length = 0;
                closesocket(sock);

                sock = adb_connect(adb_server_ip, adb_server_tcp_port);
                if (sock == INVALID_SOCKET)
                    return EXIT_CODE_INVALID_SOCKET_10;

                if (!serial_number) {
                    result = adb_send(sock, adb_transport);
                    if (result) {
                        errmsg_print("ERROR: Error while setting adb transport for <%s>", adb_transport);
                        closesocket(sock);
                        return EXIT_CODE_GENERIC;
                    }
                } else {
                    result = g_snprintf((char *) helper_packet, PACKET_LENGTH, adb_transport_serial_templace, 15 + serial_number_length, serial_number);
                    if (result <= 0 || result > PACKET_LENGTH) {
                        errmsg_print("ERROR: Error while completing adb packet");
                        closesocket(sock);
                        return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_19;
                    }

                    result = adb_send(sock, helper_packet);
                    if (result) {
                        errmsg_print("ERROR: Error while setting adb transport for <%s>", helper_packet);
                        closesocket(sock);
                        return EXIT_CODE_GENERIC;
                    }
                }

                if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_MAIN))
                    adb_command = adb_log_main;
                else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_SYSTEM))
                    adb_command = adb_log_system;
                else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_RADIO))
                    adb_command = adb_log_radio;
                else if (is_specified_interface(interface, INTERFACE_ANDROID_LOGCAT_EVENTS))
                    adb_command = adb_log_events;
                else {
                    errmsg_print("ERROR: Unknown interface: <%s>", interface);
                    closesocket(sock);
                    return EXIT_CODE_GENERIC;
                }

                result = adb_send(sock, adb_command);
                if (result) {
                    errmsg_print("WARNIG: Error while sending command <%s>", adb_command);
                    continue;
                }

                break;
            }
        }

        used_buffer_length += length + exported_pdu_headers_size;

        if (*try_header_size != 24)
            header_size = 20;
        else
            header_size = *try_header_size;

        length = (*payload_length) + header_size + (gssize)exported_pdu_headers_size;

        while (used_buffer_length >= exported_pdu_headers_size + header_size && (size_t)length <= used_buffer_length) {
            endless_loop = extcap_dumper_dump(extcap_dumper, packet,
                    length,
                    length,
                    *timestamp_secs, *timestamp_nsecs);

            memmove(packet + exported_pdu_headers_size, packet + length, used_buffer_length - length);
            used_buffer_length -= length;
            used_buffer_length += exported_pdu_headers_size;


            length = (*payload_length) + header_size + (gssize)exported_pdu_headers_size;

            if (*try_header_size != 24)
                header_size = 20;
            else
                header_size = *try_header_size;
        }
        used_buffer_length -= exported_pdu_headers_size;
    }

    closesocket(sock);

    return EXIT_CODE_SUCCESS;
}

/*----------------------------------------------------------------------------*/
/* Android Wifi Tcpdump                                                       */
/* The Tcpdump sends data in pcap format. So for using the extcap_dumper we   */
/* need to unpack the pcap and then send the packet data to the dumper.       */
/*----------------------------------------------------------------------------*/
static int capture_android_wifi_tcpdump(char *interface, char *fifo,
        const char *adb_server_ip, unsigned short *adb_server_tcp_port) {
    struct extcap_dumper                     extcap_dumper;
    static char                              data[PACKET_LENGTH];
    static char                              helpful_packet[PACKET_LENGTH];
    gssize                                   length;
    gssize                                   used_buffer_length =  0;
    gssize                                   filter_buffer_length = 0;
    gssize                                   frame_length=0;
    socket_handle_t                          sock;
    const char                               *adb_transport = "0012" "host:transport-any";
    const char                               *adb_transport_serial_templace = "%04x" "host:transport:%s";
    const char                               *adb_shell_tcpdump = "001D" "shell:tcpdump -n -s 0 -u -w -";
    gint                                     result;
    char                                     *serial_number = NULL;
    static char                              filter_buffer[PACKET_LENGTH];
    gint                                     device_endiness = G_LITTLE_ENDIAN;
    gboolean                                 global_header_skipped=FALSE;
    pcaprec_hdr_t                            p_header;

    /* First check for the device if it is connected or not */
    sock = adb_connect(adb_server_ip, adb_server_tcp_port);
    if (sock == INVALID_SOCKET)
        return EXIT_CODE_INVALID_SOCKET_11;

    if (is_specified_interface(interface, INTERFACE_ANDROID_WIFI_TCPDUMP)
            && strlen(interface) > strlen(INTERFACE_ANDROID_WIFI_TCPDUMP) + 1) {
        serial_number = interface + strlen(INTERFACE_ANDROID_WIFI_TCPDUMP) + 1;
    }
    if (!serial_number) {
        result = adb_send(sock, adb_transport);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport");
            fflush(stdout);

            errmsg_print("ERROR: Error while setting adb transport for <%s>",
                adb_transport);
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    } else {
        result = g_snprintf((char *) helpful_packet, PACKET_LENGTH, adb_transport_serial_templace,
            15 + strlen(serial_number), serial_number);
        if (result <= 0 || result > PACKET_LENGTH) {
            errmsg_print("ERROR: Error while completing adb packet");
            closesocket(sock);
            return EXIT_CODE_BAD_SIZE_OF_ASSEMBLED_ADB_PACKET_20;
        }

        result = adb_send(sock, helpful_packet);
        if (result) {
            errmsg_print("ERROR: Error while setting adb transport");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }
    }
    result = adb_send(sock, adb_shell_tcpdump);
    if (result) {
        errmsg_print("ERROR: Error while setting adb transport");
        closesocket(sock);
        return EXIT_CODE_GENERIC;
    }

    extcap_dumper = extcap_dumper_open(fifo, EXTCAP_ENCAP_ETHERNET);
    while (endless_loop) {
        char *i_position;
        errno = 0;
        length = recv(sock, data + used_buffer_length, (int)(PACKET_LENGTH - used_buffer_length), 0);
        if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
            || errno == EWOULDBLOCK
#endif
            ) {
            continue;
        }
        else if (errno != 0) {
            errmsg_print("ERROR capture: %s", strerror(errno));
            return EXIT_CODE_GENERIC;
        }

        if (length <= 0) {
            errmsg_print("ERROR: Broken socket connection.");
            closesocket(sock);
            return EXIT_CODE_GENERIC;
        }

        used_buffer_length += length;

        /*
         * Checking for the starting for the pcap global header using the magic number
         */
        if (used_buffer_length > 4) {
            guint * magic_number;
            magic_number= (guint *)data;
            if (*magic_number == 0xd4c3b2a1 || *magic_number == 0xa1b2c3d4) {
                if (data[0] == (char)0xd4){
                    device_endiness = G_LITTLE_ENDIAN;
                }
                else {
                    device_endiness = G_BIG_ENDIAN;
                }
                break;
            }
        }

        i_position = (char *) memchr(data, '\n', used_buffer_length);
        if (i_position && i_position < data + used_buffer_length) {
            memmove(data, i_position + 1 , used_buffer_length - (i_position + 1 - data));
            used_buffer_length = used_buffer_length - (gssize) (i_position + 1 - data);
        }
    }
    /*
     * The data we are getting from the tcpdump stdoutput stream as the stdout is the text stream it is
     * convertinng the 0A=0D0A; So we need to remove these extra character.
     */
    filter_buffer_length=0;
    while (endless_loop) {
        gssize i = 0,read_offset,j=0;
       /*Filter the received data to get rid of unwanted 0DOA*/
        for (i = 0; i < (used_buffer_length - 1); i++) {
            if (data[i] == 0x0d && data[i + 1] == 0x0a) {
                i++;
            }
            filter_buffer[filter_buffer_length++] = data[i];
        }

        /* Put the last characters in the start if it is still left in buffer.*/
        for (j=0; i < used_buffer_length; i++,j++) {
            data[j] = data[i];
        }
        used_buffer_length = j;
        if (global_header_skipped==FALSE && filter_buffer_length >= PCAP_GLOBAL_HEADER_LENGTH) {
            /*Skip the Global pcap header*/
            filter_buffer_length -= PCAP_GLOBAL_HEADER_LENGTH;

            /*Move the remaining content from start*/
            memmove(filter_buffer , filter_buffer + PCAP_GLOBAL_HEADER_LENGTH , filter_buffer_length);
            global_header_skipped = TRUE;
        }
        else if (global_header_skipped && filter_buffer_length > PCAP_RECORD_HEADER_LENGTH) {
            read_offset=0;
            while (filter_buffer_length > PCAP_RECORD_HEADER_LENGTH) {
                gchar *packet;
                packet = filter_buffer + read_offset;
                 /*
                 * This fills the pcap header info based upon the endianess of the machine and android device.
                 * If the endianess are different, pcap header bytes received from the android device are swapped
                 * to be read properly by the machine else pcap header bytes are taken as it is.
                 */
                if (device_endiness == G_BYTE_ORDER) {
                    p_header = *((pcaprec_hdr_t*)packet);
                }
                else {
                    p_header.ts_sec = GUINT32_SWAP_LE_BE(*((guint32*)packet));
                    p_header.ts_usec = GUINT32_SWAP_LE_BE(*(guint32*)(packet +4));
                    p_header.incl_len = GUINT32_SWAP_LE_BE(*(guint32*)(packet +8));
                    p_header.orig_len = GUINT32_SWAP_LE_BE(*(guint32*)(packet +12));
                }

                if ((gssize)(p_header.incl_len + PCAP_RECORD_HEADER_LENGTH) <= filter_buffer_length) {

                    /*
                     * It was observed that some times tcpdump reports the length of packet as '0' and that leads to the
                     * error: ( Warn Error "Less data was read than was expected" while reading )
                     * So to avoid this error we are checking for length of packet before passing it to dumper.
                     */
                    if (p_header.incl_len > 0) {
                        endless_loop = extcap_dumper_dump(extcap_dumper , filter_buffer + read_offset+ PCAP_RECORD_HEADER_LENGTH,
                        p_header.incl_len , p_header.orig_len , p_header.ts_sec , p_header.ts_usec);
                    }
                    frame_length = p_header.incl_len + PCAP_RECORD_HEADER_LENGTH;

                    /*update the offset value for the next packet*/
                    filter_buffer_length -= frame_length;
                    read_offset += frame_length;
                }
                else {
                    /*The complete packet has not yet received*/
                    break;
                }
            }
            if (read_offset!=0) {
                /*Move the rest of the filter  data to the beginning of the filter_buffer */
                memmove(filter_buffer, filter_buffer + read_offset , filter_buffer_length);
            }
        }

        /*Get the data from the tcpdump process running in the android device*/
        while (endless_loop) {
            errno = 0;
            length = recv(sock, data + used_buffer_length, (int)(PACKET_LENGTH -(used_buffer_length + filter_buffer_length)), 0);
            if (errno == EAGAIN
#if EWOULDBLOCK != EAGAIN
                || errno == EWOULDBLOCK
#endif
                ) {
                continue;
            }
            else if (errno != 0) {
                errmsg_print("ERROR capture: %s", strerror(errno));
                return EXIT_CODE_GENERIC;
            }

            if (length <= 0) {
                errmsg_print("ERROR: Broken socket connection.");
                closesocket(sock);
                return EXIT_CODE_GENERIC;
            }

            if (used_buffer_length += length > 1) {
                break;
            }
        }
    }

    closesocket(sock);
    return EXIT_CODE_SUCCESS;
}

int main(int argc, char **argv) {
    int              option_idx = 0;
    int              result;
    const char      *adb_server_ip       = NULL;
    unsigned short  *adb_server_tcp_port = NULL;
    unsigned int     logcat_text   = 0;
    const char      *default_adb_server_ip = "127.0.0.1";
    unsigned short   default_adb_server_tcp_port = 5037;
    unsigned short   local_adb_server_tcp_port;
    unsigned short   local_bt_server_tcp_port;
    unsigned short   local_bt_local_tcp_port;
    unsigned short  *bt_server_tcp_port  = NULL;
    unsigned int     bt_forward_socket   = 0;
    const char      *bt_local_ip         = NULL;
    unsigned short  *bt_local_tcp_port   = NULL;
    unsigned short   default_bt_server_tcp_port = 4330;
    const char      *default_bt_local_ip = "127.0.0.1";
    unsigned short   default_bt_local_tcp_port  = 4330;
    extcap_parameters * extcap_conf = NULL;

#ifdef _WIN32
    WSADATA          wsaData;

    attach_parent_console();
#endif  /* _WIN32 */

    opterr = 0;
    optind = 0;

    if (argc == 1) {
        help();
        return EXIT_CODE_SUCCESS;
    }
    extcap_conf = g_new0(extcap_parameters, 1);

    extcap_base_set_util_info(extcap_conf, ANDROIDDUMP_VERSION_MAJOR, ANDROIDDUMP_VERSION_MINOR, ANDROIDDUMP_VERSION_RELEASE, NULL);

    while ((result = getopt_long(argc, argv, "", longopts, &option_idx)) != -1) {
        switch (result) {

        case OPT_VERSION:
            printf("%s.%s.%s\n", ANDROIDDUMP_VERSION_MAJOR, ANDROIDDUMP_VERSION_MINOR, ANDROIDDUMP_VERSION_RELEASE);
            return EXIT_CODE_SUCCESS;
        case OPT_VERBOSE:
            if (optarg)
                verbose = (g_ascii_strncasecmp(optarg, "TRUE", 4) == 0);
            else
                verbose = 1;

            {
                int j = 0;

                verbose_print("VERBOSE: Command line: ");
                while(j < argc) {
                    verbose_print("%s ", argv[j]);
                    j += 1;
                }
                verbose_print("\n");
            }
            break;
        case OPT_HELP:
            help();
            return EXIT_CODE_SUCCESS;
        case OPT_CONFIG_ADB_SERVER_IP:
            adb_server_ip = optarg;
            break;
        case OPT_CONFIG_ADB_SERVER_TCP_PORT:
            adb_server_tcp_port = &local_adb_server_tcp_port;
            if (!optarg){
                errmsg_print("ERROR: Impossible exception. Parameter required argument, but there is no it right now.");
                return EXIT_CODE_GENERIC;
            }
            *adb_server_tcp_port = (unsigned short) g_ascii_strtoull(optarg, NULL, 10);
            break;
        case OPT_CONFIG_LOGCAT_TEXT:
            logcat_text = (g_ascii_strncasecmp(optarg, "TRUE", 4) == 0);
            break;
        case OPT_CONFIG_BT_SERVER_TCP_PORT:
            bt_server_tcp_port = &local_bt_server_tcp_port;
            if (!optarg){
                errmsg_print("ERROR: Impossible exception. Parameter required argument, but there is no it right now.");
                return EXIT_CODE_GENERIC;
            }
            *bt_server_tcp_port = (unsigned short) g_ascii_strtoull(optarg, NULL, 10);
            break;
        case OPT_CONFIG_BT_FORWARD_SOCKET:
            bt_forward_socket = (g_ascii_strncasecmp(optarg, "TRUE", 4) == 0);
            break;
        case OPT_CONFIG_BT_LOCAL_IP:
            bt_local_ip = optarg;
            break;
        case OPT_CONFIG_BT_LOCAL_TCP_PORT:
            bt_local_tcp_port = &local_bt_local_tcp_port;
            if (!optarg){
                errmsg_print("ERROR: Impossible exception. Parameter required argument, but there is no it right now.");
                return EXIT_CODE_GENERIC;
            }
            *bt_local_tcp_port = (unsigned short) g_ascii_strtoull(optarg, NULL, 10);
            break;
        default:
            if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, optarg))
            {
                printf("Invalid argument <%s>. Try --help.\n", argv[optind - 1]);
                return EXIT_CODE_GENERIC;
            }
        }
    }

    if (!adb_server_ip)
        adb_server_ip = default_adb_server_ip;

    if (!adb_server_tcp_port)
        adb_server_tcp_port = &default_adb_server_tcp_port;

    if (!bt_server_tcp_port)
        bt_server_tcp_port = &default_bt_server_tcp_port;

    if (!bt_local_ip)
        bt_local_ip = default_bt_local_ip;

    if (!bt_local_tcp_port)
        bt_local_tcp_port = &default_bt_local_tcp_port;

#ifdef _WIN32
    result = WSAStartup(MAKEWORD(1,1), &wsaData);
    if (result != 0) {
        errmsg_print("ERROR: WSAStartup failed with error: %d", result);
        return EXIT_CODE_GENERIC;
    }
#endif  /* _WIN32 */

    if (extcap_conf->do_list_interfaces)
        register_interfaces(extcap_conf, adb_server_ip, adb_server_tcp_port);

    if (extcap_base_handle_interface(extcap_conf))
        return EXIT_CODE_SUCCESS;

    if (extcap_conf->show_config)
        return list_config(extcap_conf->interface);

    if (extcap_conf->capture) {
        if (extcap_conf->interface && (is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_MAIN) ||
                is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_SYSTEM) ||
                is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_RADIO) ||
                is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_EVENTS)))
            if (logcat_text)
                return capture_android_logcat_text(extcap_conf->interface, extcap_conf->fifo, adb_server_ip, adb_server_tcp_port);
            else
                return capture_android_logcat(extcap_conf->interface, extcap_conf->fifo, adb_server_ip, adb_server_tcp_port);
        else if (extcap_conf->interface && (is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_TEXT_MAIN) ||
                is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_TEXT_SYSTEM) ||
                is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_TEXT_RADIO) ||
                is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_TEXT_EVENTS) ||
                (is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_LOGCAT_TEXT_CRASH))))
            return capture_android_logcat_text(extcap_conf->interface, extcap_conf->fifo, adb_server_ip, adb_server_tcp_port);
        else if (extcap_conf->interface && is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_BLUETOOTH_HCIDUMP))
            return capture_android_bluetooth_hcidump(extcap_conf->interface, extcap_conf->fifo, adb_server_ip, adb_server_tcp_port);
        else if (extcap_conf->interface && is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_BLUETOOTH_EXTERNAL_PARSER))
            return capture_android_bluetooth_external_parser(extcap_conf->interface, extcap_conf->fifo, adb_server_ip, adb_server_tcp_port,
                    bt_server_tcp_port, bt_forward_socket, bt_local_ip, bt_local_tcp_port);
        else if (extcap_conf->interface && (is_specified_interface(extcap_conf->interface, INTERFACE_ANDROID_BLUETOOTH_BTSNOOP_NET)))
            return capture_android_bluetooth_btsnoop_net(extcap_conf->interface, extcap_conf->fifo, adb_server_ip, adb_server_tcp_port);
        else if (extcap_conf->interface && (is_specified_interface(extcap_conf->interface,INTERFACE_ANDROID_WIFI_TCPDUMP)))
            return capture_android_wifi_tcpdump(extcap_conf->interface, extcap_conf->fifo, adb_server_ip,adb_server_tcp_port);
        else
            return EXIT_CODE_GENERIC;
    }

    /* clean up stuff */
    extcap_base_cleanup(&extcap_conf);

    return EXIT_CODE_SUCCESS;
}

#ifdef _WIN32
int _stdcall
WinMain (struct HINSTANCE__ *hInstance,
         struct HINSTANCE__ *hPrevInstance,
         char               *lpszCmdLine,
         int                 nCmdShow)
{
    return main(__argc, __argv);
}
#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
