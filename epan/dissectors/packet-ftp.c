/* packet-ftp.c
 * Routines for ftp packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * Copyright 2001, Juan Toledo <toledo@users.sourceforge.net> (Passive FTP)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>      /* for sscanf() */
#include <wsutil/strtoi.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include <epan/proto_data.h>
#include "packet-acdr.h"

#include <tap.h>
#include <epan/export_object.h>
#include <ui/tap-credentials.h>

#include "packet-tls.h"
#include "packet-tls-utils.h"

void proto_register_ftp(void);
void proto_reg_handoff_ftp(void);

static int credentials_tap = -1;

static int proto_ftp = -1;
static int proto_ftp_data = -1;
static int hf_ftp_current_working_directory = -1;
static int hf_ftp_response = -1;
static int hf_ftp_request = -1;
static int hf_ftp_request_command = -1;
static int hf_ftp_request_arg = -1;
static int hf_ftp_response_code = -1;
static int hf_ftp_response_arg = -1;
static int hf_ftp_pasv_ip = -1 ;
static int hf_ftp_pasv_port = -1;
static int hf_ftp_pasv_nat = -1;
static int hf_ftp_active_ip = -1;
static int hf_ftp_active_port = -1;
static int hf_ftp_active_nat = -1;
static int hf_ftp_eprt_af = -1;
static int hf_ftp_eprt_ip = -1;
static int hf_ftp_eprt_ipv6 = -1;
static int hf_ftp_eprt_port = -1;
static int hf_ftp_epsv_ip = -1;
static int hf_ftp_epsv_ipv6 = -1;
static int hf_ftp_epsv_port = -1;
static int hf_ftp_command_response_frames = -1;
static int hf_ftp_command_response_bytes = -1;
static int hf_ftp_command_response_first_frame_num = -1;
static int hf_ftp_command_response_last_frame_num = -1;
static int hf_ftp_command_response_duration = -1;
static int hf_ftp_command_response_kbps = -1;
static int hf_ftp_command_setup_frame = -1;
static int hf_ftp_command_command_frame = -1;
static int hf_ftp_command_command = -1;

static int hf_ftp_data_setup_frame = -1;
static int hf_ftp_data_setup_method = -1;
static int hf_ftp_data_command = -1;
static int hf_ftp_data_command_frame = -1;
static int hf_ftp_data_current_working_directory = -1;

static gint ett_ftp = -1;
static gint ett_ftp_reqresp = -1;

static expert_field ei_ftp_eprt_args_invalid = EI_INIT;
static expert_field ei_ftp_epsv_args_invalid = EI_INIT;
static expert_field ei_ftp_response_code_invalid = EI_INIT;
static expert_field ei_ftp_pwd_response_invalid = EI_INIT;

static int ftp_eo_tap = -1;

static dissector_handle_t ftpdata_handle;
static dissector_handle_t ftp_handle;
static dissector_handle_t data_text_lines_handle;
static dissector_handle_t tls_handle;

#define TCP_PORT_FTPDATA        20
#define TCP_PORT_FTP            21

static const value_string response_table[] = {
    { 110, "Restart marker reply" },
    { 120, "Service ready in nnn minutes" },
    { 125, "Data connection already open; transfer starting" },
    { 150, "File status okay; about to open data connection" },
    { 200, "Command okay" },
    { 202, "Command not implemented, superfluous at this site" },
    { 211, "System status, or system help reply" },
    { 212, "Directory status" },
    { 213, "File status" },
    { 214, "Help message" },
    { 215, "NAME system type" },
    { 220, "Service ready for new user" },
    { 221, "Service closing control connection" },
    { 225, "Data connection open; no transfer in progress" },
    { 226, "Closing data connection" },
    { 227, "Entering Passive Mode" },
    { 229, "Entering Extended Passive Mode" },
    { 230, "User logged in, proceed" },
    { 232, "User logged in, authorized by security data exchange" },
    { 234, "Security data exchange complete" },
    { 235, "Security data exchange completed successfully" },
    { 250, "Requested file action okay, completed" },
    { 257, "PATHNAME created" },
    { 331, "User name okay, need password" },
    { 332, "Need account for login" },
    { 334, "Requested security mechanism is ok" },
    { 335, "Security data is acceptable, more is required" },
    { 336, "Username okay, need password. Challenge is ..." },
    { 350, "Requested file action pending further information" },
    { 421, "Service not available, closing control connection" },
    { 425, "Can't open data connection" },
    { 426, "Connection closed; transfer aborted" },
    { 431, "Need some unavailable resource to process security" },
    { 450, "Requested file action not taken" },
    { 451, "Requested action aborted: local error in processing" },
    { 452, "Requested action not taken. Insufficient storage space in system" },
    { 500, "Syntax error, command unrecognized" },
    { 501, "Syntax error in parameters or arguments" },
    { 502, "Command not implemented" },
    { 503, "Bad sequence of commands" },
    { 504, "Command not implemented for that parameter" },
    { 522, "Network protocol not supported" },
    { 530, "Not logged in" },
    { 532, "Need account for storing files" },
    { 533, "Command protection level denied for policy reasons" },
    { 534, "Request denied for policy reasons" },
    { 535, "Failed security check (hash, sequence, etc)" },
    { 536, "Requested PROT level not supported by mechanism" },
    { 537, "Command protection level not supported by security mechanism" },
    { 550, "Requested action not taken: File unavailable" },
    { 551, "Requested action aborted: page type unknown" },
    { 552, "Requested file action aborted: Exceeded storage allocation" },
    { 553, "Requested action not taken: File name not allowed" },
    { 631, "Integrity protected reply" },
    { 632, "Confidentiality and integrity protected reply" },
    { 633, "Confidentiality protected reply" },
    { 0,   NULL }
};
static value_string_ext response_table_ext = VALUE_STRING_EXT_INIT(response_table);

#define EPRT_AF_IPv4 1
#define EPRT_AF_IPv6 2
static const value_string eprt_af_vals[] = {
    { EPRT_AF_IPv4, "IPv4" },
    { EPRT_AF_IPv6, "IPv6" },
    { 0, NULL }
};

/* Used for FTP-DATA's Export Object feature
   This will be controlled by the preferences setting "export.maxsize".
   It will be used to set the maximum file size for FTP's export
   objects (in megabytes). Use 0 for no limit.
 */
static guint pref_export_maxsize = 0;

typedef struct _ftp_eo_t {
    gchar    *command;      /* Command this data stream answers (e.g., RETR foo.txt) */
    guint32  command_frame; /* Where command for this data was seen */
    guint32  payload_len;   /* Length of packet's data */
    gchar    *payload_data; /* Packet's data */
} ftp_eo_t;

/* Stores mappings of the command packet number to the export object
   table's row number, so we can append data from later FTP packets
   to the entries.
 */
GHashTable *command_packet_to_eo_row = NULL;

/* Track which row number in the export object table we're up to */
guint32 eo_row_count = 0;

/**
 * This is the callback passed to register_export_object()
 * as the tap processing function. It will be called each time
 * tap_queue_packet() sends a packet to the export objects tap.
 *
 * The general approach is that when a file transfer begins,
 * besides storing the standard export object data, like
 * the source system, filename, data, and length,
 * an entry is added to the command_packet_to_eo_row hashtable,
 * mapping the FTP command packet's number to the
 * export object list's row number.
 *
 * When a later packet has a command packet number
 * that's already present in the command_packet_to_eo_row hashtable,
 * we detect that's it's a continuation of a previous
 * file transfer, so we look up the associated entry in the export
 * object list and append the data to there.
 *
 * FTP is complex in that there's no guarantee that the file transmission
 * was completely captured. It might be possible to infer a successful
 * transfer with either the "SIZE" command or with a 226 response code
 * (indicating that the STOR or RETR command was succesful), but there
 * is no guarantee that either of these are present. As such, this
 * implementation takes a best-effort approach of simply appending
 * all associated ftp-data packets to the export objects entry.
 */
static tap_packet_status
ftp_eo_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data, tap_flags_t flags _U_)
{
    export_object_list_t *object_list = (export_object_list_t *)tapdata;
    const ftp_eo_t *eo_info = (const ftp_eo_t *)data;

    if(eo_info) { /* We have data waiting for us */
        /* Only export files transferred with STOR or RETR*/
        if (strncmp(eo_info->command, "STOR", 4) != 0 && strncmp(eo_info->command, "RETR", 4) != 0) {
            return TAP_PACKET_DONT_REDRAW; /* State unchanged - no window updates needed */
        }
        /* Create the command_packet_to_eo_row hashtable for mapping the FTP
          command packet's number to the export object list's row number */
        if(command_packet_to_eo_row == NULL) {
            command_packet_to_eo_row = g_hash_table_new(g_direct_hash, g_direct_equal);
        }
        if (!g_hash_table_contains(command_packet_to_eo_row, GUINT_TO_POINTER(eo_info->command_frame))) {
            /* Command packet not previously seen. Create the new entry in the hashtable. */
            export_object_entry_t *entry = g_new(export_object_entry_t, 1);
            entry->pkt_num = pinfo->num;
            /* If the command is STOR, the transfer is from the client to the server
               If the command is RETR, the transfer is from the server to the client
               However, ftp-data will always have the file's origin as pinfo->src */
            entry->hostname = g_strdup(address_to_str(pinfo->pool, &pinfo->src));
            entry->content_type = g_strdup("FTP file");

            /* Remove the "STOR " or "RETR " to extract the filename */
            if (strlen(eo_info->command) > 5){
                entry->filename = g_strdup(eo_info->command + 5);
            } else {
                entry->filename = g_strdup("(MISSING)");
            }

            gsize bytes_to_copy;
            if (pref_export_maxsize != 0 && (eo_info->payload_len > pref_export_maxsize*1024*1024)) {
                bytes_to_copy = pref_export_maxsize*1024*1024;
            }
            else {
                bytes_to_copy = eo_info->payload_len;
            }
            entry->payload_len = bytes_to_copy;
            entry->payload_data = (guint8 *)g_memdup2(eo_info->payload_data, bytes_to_copy);

            /* Add the mapping of the command frame and the export object
               list's row number to the hash table */
            g_hash_table_insert(command_packet_to_eo_row, GUINT_TO_POINTER(eo_info->command_frame), GUINT_TO_POINTER(eo_row_count));
            eo_row_count += 1;
            object_list->add_entry(object_list->gui_data, entry);
        } else {
            /* This command packet number is already present in the
               command_packet_to_eo_row hashtable, so it's a continuation of
               a previous. Let's look up the entry in the export
               object list and append the data to there */
            guint32 row_num = GPOINTER_TO_UINT(g_hash_table_lookup(command_packet_to_eo_row, GUINT_TO_POINTER(eo_info->command_frame)));
            export_object_entry_t *entry = object_list->get_entry(object_list->gui_data, row_num);

            gsize bytes_to_copy;
            if (pref_export_maxsize != 0 && (entry->payload_len + eo_info->payload_len) > pref_export_maxsize*1024*1024) {
                bytes_to_copy = pref_export_maxsize*1024*1024 - entry->payload_len;
            }
            else {
                bytes_to_copy = eo_info->payload_len;
            }

            entry->payload_data = (guint8 *) g_realloc(entry->payload_data, entry->payload_len + bytes_to_copy);
            memcpy(entry->payload_data + entry->payload_len, eo_info->payload_data, bytes_to_copy);
            entry->payload_len = entry->payload_len + bytes_to_copy;
        }
        /* payload_data will be freed when the Export Object window is closed. */
        return TAP_PACKET_REDRAW; /* State changed - window should be redrawn */
    } else {
        return TAP_PACKET_DONT_REDRAW; /* State unchanged - no window updates needed */
    }
}

/**
 * This is the callback passed to register_export_object()
 * as the reset_cb. This will be used in the export_object module
 * to cleanup any previous private data of the export object functionality
 * before performing the eo_reset function or when the window closes */
static void
ftp_eo_cleanup(void)
{
    if(command_packet_to_eo_row != NULL) {
        g_hash_table_destroy(command_packet_to_eo_row);
        command_packet_to_eo_row = NULL;
    }
    eo_row_count = 0;
}



/********************************************************************/
/* Storing session state and linking between control (ftp) and data */
/* data (ftp-data) conversations                                    */

typedef struct ftp_data_conversation_t
{
    const gchar   *command;      /* Command that this data answers */
    guint32       command_frame; /* Frame command was seen */
    const gchar   *setup_method; /* Type of command used to set up data conversation */
    guint32       setup_frame;   /* Frame where this happened */
    wmem_strbuf_t *current_working_directory;

    /* Summary details of stream to show in command frame. */
    guint         first_frame_num;
    nstime_t      first_frame_time;
    guint         last_frame_num;
    nstime_t      last_frame_time;
    guint         frames_seen;
    guint         bytes_seen;
} ftp_data_conversation_t;

/* Data to associate with individual FTP frame */
typedef struct ftp_packet_data_t
{
    wmem_strbuf_t *current_working_directory;
} ftp_packet_data_t;

/* State of FTP conversation */
typedef struct ftp_conversation_t
{
    const gchar *last_command;       /* Most recent request command seen (on first pass) */
    guint32     last_command_frame;  /* When request was seen */
    wmem_strbuf_t *current_working_directory;
    ftp_data_conversation_t *current_data_conv;  /* Current data conversation (during first pass) */
    guint32     current_data_setup_frame;
    gchar *username;
    guint username_pkt_num;
    gboolean tls_requested;
} ftp_conversation_t;

/* For a given packet, retrieve or initialise a new conversation, and return it */
static ftp_conversation_t *find_or_create_ftp_conversation(packet_info *pinfo)
{
    /* Create control conversation if necessary */
    conversation_t *conv = find_or_create_conversation(pinfo);
    ftp_conversation_t *p_ftp_conv;

    /* Control conversation data */
    p_ftp_conv = (ftp_conversation_t *)conversation_get_proto_data(conv, proto_ftp);
    if (!p_ftp_conv) {
        p_ftp_conv = wmem_new0(wmem_file_scope(), ftp_conversation_t);
        /* Start with an empty string - assume relative path unless/until find out differently. */
        p_ftp_conv->current_working_directory = wmem_strbuf_new(wmem_file_scope(), "");
        conversation_add_proto_data(conv, proto_ftp, p_ftp_conv);
    }

    return p_ftp_conv;
}

/* Keep track of ftp_data_conversation_t*, keyed by the ftp command frame */
static GHashTable *ftp_command_to_data_hash = NULL;


/* When new data conversation is being created, should:
 * - create data conversation
 * - create control conversation, and have it point at control conversation
 */
static void create_and_link_data_conversation(packet_info *pinfo,
                                              address *addr_a,
                                              guint16 port_a,
                                              address *addr_b,
                                              guint16 port_b,
                                              const char *method)
{
    /* Only to do on first pass */
    if (pinfo->fd->visited) {
        return;
    }

    ftp_conversation_t *p_ftp_conv = find_or_create_ftp_conversation(pinfo);

    /* Create data conversation and set dissector */
    ftp_data_conversation_t *p_ftp_data_conv;
    conversation_t *data_conversation = conversation_new(pinfo->num,
                                                         addr_a, addr_b,
                                                         CONVERSATION_TCP,
                                                         port_a, port_b,
                                                         NO_PORT2);
    conversation_set_dissector(data_conversation, ftpdata_handle);

    /* Allocate data for data conversation. Note that control conversation will update it with commands. */
    p_ftp_data_conv = wmem_new0(wmem_file_scope(), ftp_data_conversation_t);
    /* Set method */
    p_ftp_data_conv->setup_method = method;
    /* Copy snapshot of what cwd is at this point */
    p_ftp_data_conv->current_working_directory = p_ftp_conv->current_working_directory;

    /* Point control conversation at current data conversation */
    conversation_add_proto_data(data_conversation, proto_ftp_data,
                                p_ftp_data_conv);
    p_ftp_conv->current_data_conv = p_ftp_data_conv;
    p_ftp_conv->current_data_setup_frame = pinfo->num;
}

/********************************************************************/


/*
 * Parse the address and port information in a PORT command or in the
 * response to a PASV command.  Return TRUE if we found an address and
 * port, and supply the address and port; return FALSE if we didn't find
 * them.
 *
 * We ignore the IP address in the reply, and use the address from which
 * the request came.
 *
 * XXX - are there cases where they differ?  What if the FTP server is
 * behind a NAT box, so that the address it puts into the reply isn't
 * the address at which you should contact it?  Do all NAT boxes detect
 * FTP PASV replies and rewrite the address?  (I suspect not.)
 *
 * RFC 959 doesn't say much about the syntax of the 227 reply.
 *
 * A proposal from Dan Bernstein at
 *
 *  http://cr.yp.to/ftp/retr.html
 *
 * "recommend[s] that clients use the following strategy to parse the
 * response line: look for the first digit after the initial space; look
 * for the fourth comma after that digit; read two (possibly negative)
 * integers, separated by a comma; the TCP port number is p1*256+p2, where
 * p1 is the first integer modulo 256 and p2 is the second integer modulo
 * 256."
 *
 * wget 1.5.3 looks for a digit, although it doesn't handle negative
 * integers.
 *
 * The FTP code in the source of the cURL library, at
 *
 *  https://github.com/curl/curl/blob/master/lib/ftp.c
 *
 * says that cURL "now scans for a sequence of six comma-separated numbers
 * and will take them as IP+port indicators"; it loops, doing "sscanf"s
 * looking for six numbers separated by commas, stepping the start pointer
 * in the scanf one character at a time - i.e., it tries rather exhaustively.
 *
 * An optimization would be to scan for a digit, and start there, and if
 * the scanf doesn't find six values, scan for the next digit and try
 * again; this will probably succeed on the first try.
 *
 * The cURL code also says that "found reply-strings include":
 *
 *  "227 Entering Passive Mode (127,0,0,1,4,51)"
 *  "227 Data transfer will passively listen to 127,0,0,1,4,51"
 *  "227 Entering passive mode. 127,0,0,1,4,51"
 *
 * so it appears that you can't assume there are parentheses around
 * the address and port number.
 */
static gboolean
parse_port_pasv(const guchar *line, int linelen, guint32 *ftp_ip, guint16 *ftp_port,
    guint32 *pasv_offset, guint *ftp_ip_len, guint *ftp_port_len)
{
    char     *args;
    char     *p;
    guchar    c;
    int       i;
    int       ip_address[4], port[2];
    gboolean  ret = FALSE;

    /*
     * Copy the rest of the line into a null-terminated buffer.
     */
    args = wmem_strndup(wmem_packet_scope(), line, linelen);
    p = args;

    for (;;) {
        /*
         * Look for a digit.
         */
        while ((c = *p) != '\0' && !g_ascii_isdigit(c))
            p++;

        if (*p == '\0') {
            /*
             * We ran out of text without finding anything.
             */
            break;
        }

        /*
         * See if we have six numbers.
         */
        i = sscanf(p, "%d,%d,%d,%d,%d,%d",
            &ip_address[0], &ip_address[1], &ip_address[2], &ip_address[3],
            &port[0], &port[1]);
        if (i == 6) {
            /*
             * We have a winner!
             */
            *ftp_port = ((port[0] & 0xFF)<<8) | (port[1] & 0xFF);
            *ftp_ip = g_htonl((ip_address[0] << 24) | (ip_address[1] <<16) | (ip_address[2] <<8) | ip_address[3]);
            *pasv_offset = (guint32)(p - args);
            *ftp_port_len = (port[0] < 10 ? 1 : (port[0] < 100 ? 2 : 3 )) + 1 +
                            (port[1] < 10 ? 1 : (port[1] < 100 ? 2 : 3 ));
            *ftp_ip_len = (ip_address[0] < 10 ? 1 : (ip_address[0] < 100 ? 2 : 3)) + 1 +
                          (ip_address[1] < 10 ? 1 : (ip_address[1] < 100 ? 2 : 3)) + 1 +
                          (ip_address[2] < 10 ? 1 : (ip_address[2] < 100 ? 2 : 3)) + 1 +
                          (ip_address[3] < 10 ? 1 : (ip_address[3] < 100 ? 2 : 3));
            ret = TRUE;
            break;
        }

        /*
         * Well, that didn't work.  Skip the first number we found,
         * and keep trying.
         */
        while ((c = *p) != '\0' && g_ascii_isdigit(c))
            p++;
    }

    return ret;
}

static gboolean
isvalid_rfc2428_delimiter(const guchar c)
{
    /* RFC2428 sect. 2 states rules for a valid delimiter */
    const gchar *forbidden = "0123456789abcdef.:";
    if (!g_ascii_isgraph(c))
        return FALSE;
    if (strchr(forbidden, g_ascii_tolower(c)))
        return FALSE;
    return TRUE;
}


/*
 * RFC2428 states...
 *
 *     AF Number   Protocol
 *     ---------   --------
 *     1           Internet Protocol, Version 4
 *     2           Internet Protocol, Version 6
 *
 *     AF Number   Address Format      Example
 *     ---------   --------------      -------
 *     1           dotted decimal      132.235.1.2
 *     2           IPv6 string         1080::8:800:200C:417A
 *                 representations
 *                 defined in
 *
 *     The following are sample EPRT commands:
 *          EPRT |1|132.235.1.2|6275|
 *          EPRT |2|1080::8:800:200C:417A|5282|
 *
 *     The first command specifies that the server should use IPv4 to open a
 *     data connection to the host "132.235.1.2" on TCP port 6275.  The
 *     second command specifies that the server should use the IPv6 network
 *     protocol and the network address "1080::8:800:200C:417A" to open a
 *     TCP data connection on port 5282.
 *
 * ... which means in fact that RFC2428 is capable to handle both,
 * IPv4 and IPv6 so we have to care about the address family and properly
 * act depending on it.
 *
 */
static gboolean
parse_eprt_request(const guchar* line, gint linelen, guint32 *eprt_af,
        guint32 *eprt_ip, guint16 *eprt_ipv6, guint16 *ftp_port,
        guint32 *eprt_ip_len, guint32 *ftp_port_len)
{
    gint      delimiters_seen = 0;
    gchar     delimiter;
    gint      fieldlen;
    gchar    *field;
    gint      n;
    gint      lastn;
    char     *args, *p;
    gboolean  ret = TRUE;


    /* line contains the EPRT parameters, we need at least the 4 delimiters */
    if (!line || linelen<4)
        return FALSE;

    /* Copy the rest of the line into a null-terminated buffer. */
    args = wmem_strndup(wmem_packet_scope(), line, linelen);
    p = args;
    /*
     * Handle a NUL being in the line; if there's a NUL in the line,
     * strlen(args) will terminate at the NUL and will thus return
     * a value less than linelen.
     */
    if ((gint)strlen(args) < linelen)
        linelen = (gint)strlen(args);

    /*
     * RFC2428 sect. 2 states ...
     *
     *     The EPRT command keyword MUST be followed by a single space (ASCII
     *     32). Following the space, a delimiter character (<d>) MUST be
     *     specified.
     *
     * ... the preceding <space> is already stripped so we know that the first
     * character must be the delimiter and has just to be checked to be valid.
     */
    if (!isvalid_rfc2428_delimiter(*p))
        return FALSE;  /* EPRT command does not follow a vaild delimiter;
                        * malformed EPRT command - immediate escape */

    delimiter = *p;
    /* Validate that the delimiter occurs 4 times in the string */
    for (n = 0; n < linelen; n++) {
        if (*(p+n) == delimiter)
            delimiters_seen++;
    }
    if (delimiters_seen != 4)
        return FALSE; /* delimiter doesn't occur 4 times
                       * probably no EPRT request - immediate escape */

    /* we know that the first character is a delimiter... */
    delimiters_seen = 1;
    lastn = 0;
    /* ... so we can start searching from the 2nd onwards */
    for (n=1; n < linelen; n++) {

        if (*(p+n) != delimiter)
            continue;

        /* we found a delimiter */
        delimiters_seen++;

        fieldlen = n - lastn - 1;
        if (fieldlen<=0)
            return FALSE; /* all fields must have data in them */
        field =  p + lastn + 1;

        if (delimiters_seen == 2) {     /* end of address family field */
            gchar *af_str;
            af_str = wmem_strndup(wmem_packet_scope(), field, fieldlen);
            if (!ws_strtou32(af_str, NULL, eprt_af))
                return FALSE;
        }
        else if (delimiters_seen == 3) {/* end of IP address field */
            gchar *ip_str;
            ip_str = wmem_strndup(wmem_packet_scope(), field, fieldlen);

            if (*eprt_af == EPRT_AF_IPv4) {
                if (str_to_ip(ip_str, eprt_ip))
                   ret = TRUE;
                else
                   ret = FALSE;
            }
            else if (*eprt_af == EPRT_AF_IPv6) {
                if (str_to_ip6(ip_str, eprt_ipv6))
                   ret = TRUE;
                else
                   ret = FALSE;
            }
            else
                return FALSE; /* invalid/unknown address family */

            *eprt_ip_len = fieldlen;
        }
        else if (delimiters_seen == 4) {/* end of port field */
            gchar *pt_str;
            pt_str = wmem_strndup(wmem_packet_scope(), field, fieldlen);

            if (!ws_strtou16(pt_str, NULL, ftp_port))
                return FALSE;
            *ftp_port_len = fieldlen;
        }

        lastn = n;
    }

    return ret;
}

/*
 * RFC2428 states ....
 *
 *   The first two fields contained in the parenthesis MUST be blank. The
 *   third field MUST be the string representation of the TCP port number
 *   on which the server is listening for a data connection.
 *
 *   The network protocol used by the data connection will be the same network
 *   protocol used by the control connection. In addition, the network
 *   address used to establish the data connection will be the same
 *   network address used for the control connection.
 *
 *   An example response    string follows:
 *
 *       Entering Extended Passive Mode (|||6446|)
 *
 * ... which in fact means that again both address families IPv4 and IPv6
 * are supported. But gladly it's not necessary to parse because it doesn't
 * occur in EPSV responses. We can leverage ftp_ip_address which is
 * protocol independent and already set.
 *
 */
static gboolean
parse_extended_pasv_response(const guchar *line, gint linelen, guint16 *ftp_port,
        guint *pasv_offset, guint *ftp_port_len)
{
    gint       n;
    gchar     *args;
    gchar     *p;
    gchar     *e;
    guchar     c;
    gboolean   ret             = FALSE;
    gboolean   delimiters_seen = FALSE;

    /*
     * Copy the rest of the line into a null-terminated buffer.
     */
    args = wmem_strndup(wmem_packet_scope(), line, linelen);
    p = args;

    /*
     * Look for ( <d> <d> <d>
       (Try to cope with '(' in description)
     */
    for (; !delimiters_seen;) {
        guchar delimiter = '\0';
        while ((c = *p) != '\0' && (c != '('))
            p++;

        if (*p == '\0') {
            return FALSE;
        }

        /* Skip '(' */
        p++;

        /* Make sure same delimiter is used 3 times */
        for (n=0; n<3; n++) {
            if ((c = *p) != '\0') {
                if (delimiter == '\0' && isvalid_rfc2428_delimiter(c)) {
                    delimiter = c;
                }
                if (c != delimiter) {
                    break;
                }
            p++;
            }
            else {
                break;
            }
        }
        delimiters_seen = TRUE;
    }

    /*
     * Should now be at digits.
     */
    if (*p != '\0') {
        const gchar* endptr;
        gboolean port_valid;
        /*
         * We didn't run out of text without finding anything.
         */
        port_valid = ws_strtou16(p, &endptr, ftp_port);
        /* the conversion returned false, but the converted value could
           be valid instead, check it out */
        if (!port_valid && *endptr == '|')
            port_valid = TRUE;
        if (port_valid) {
            *pasv_offset = (guint32)(p - args);

            ret = TRUE;

            /* get port string length */
            if ((e=strchr(p,')')) == NULL) {
                ret = FALSE;
            }
            else {
                *ftp_port_len = (guint)(--e - p);
            }
        }
    }

    return ret;
}

/* Get the last character out of a string */
static gchar wmem_strbuf_get_last_char(wmem_strbuf_t *string)
{
    gsize len = wmem_strbuf_get_len(string);
    if (len > 0) {
        const gchar *buf = wmem_strbuf_get_str(string);
        return buf[len-1];
    }
    else {
        /* Error */
        return '\0';
    }
}

/* Get the nth character out of string */
static gchar wmem_strbuf_get_char_n(wmem_strbuf_t *string, size_t n)
{
    if (n > wmem_strbuf_get_len(string)-1) {
        return '\0';
    }
    else {
        return wmem_strbuf_get_str(string)[n];
    }
}

/* Does the path end with the separator character? */
static gboolean ends_with_separator(wmem_strbuf_t *path)
{
    if (wmem_strbuf_get_len(path) == 0) {
        return FALSE;
    }

    gchar last = wmem_strbuf_get_last_char(path);
    return last == '/';
}

/* Does the path begin with the separator character? */
static gboolean begins_with_separator(wmem_strbuf_t *path)
{
    if (wmem_strbuf_get_len(path) == 0) {
        return FALSE;
    }

    gchar first = wmem_strbuf_get_char_n(path, 0);
    return first == '/';
}


/* Add new_path to the current working directory of the conversation, then normalise. */
/* N.B. could use e.g. g_build_path() here, but doesn't really buy us anything */
static void add_directory_to_conv(ftp_conversation_t *conv, const char *new_path)
{
    wmem_strbuf_t *appended_path = wmem_strbuf_new(wmem_packet_scope(), NULL);

    if (!wmem_strbuf_get_len(conv->current_working_directory)) {
        /* Currently empty so just assign to new */
        wmem_strbuf_append(conv->current_working_directory, new_path);
        return;
    }
    if (ends_with_separator(conv->current_working_directory)) {
        /* Ends in separator, so don't need to write one */
        wmem_strbuf_append_printf(appended_path, "%s%s", wmem_strbuf_get_str(conv->current_working_directory), new_path);
    }
    else {
        /* Separator needed */
        wmem_strbuf_append_printf(appended_path, "%s/%s", wmem_strbuf_get_str(conv->current_working_directory), new_path);
    }

    /* Now normalise, by going through the string one directory at a time.  If see "..",
       remove it and the previous folder. If see ".", ignore it. */
    guint offset;

    /* Initialise with empty path */
    wmem_strbuf_t *normalised_directory = wmem_strbuf_new(wmem_file_scope(), NULL);
    wmem_strbuf_t *this_folder = wmem_strbuf_new(wmem_packet_scope(), NULL);

    offset = 0;
    /* If absolute, add root to this one too */
    if (begins_with_separator(conv->current_working_directory)) {
        wmem_strbuf_append_c(normalised_directory, '/');
        offset++;
    }

    /* Now go through the appended path, one directory at a time, and
       copy to normalised_directory */
    for (; offset <= wmem_strbuf_get_len(appended_path); offset++) {
        gchar ch = wmem_strbuf_get_char_n(appended_path, offset);
        if ((offset == wmem_strbuf_get_len(appended_path)) || ch == '/' || ch == '\0') {
            /* Folder name is complete */
            if (offset>0 && wmem_strbuf_get_len(this_folder) > 0) {

                /* Up a level.  Rewind to before last directory - don't output this one */
                if (strcmp(wmem_strbuf_get_str(this_folder), "..") == 0) {
                    while (wmem_strbuf_get_len(normalised_directory) && !ends_with_separator(normalised_directory)) {
                        wmem_strbuf_truncate(normalised_directory, wmem_strbuf_get_len(normalised_directory)-1);
                    }
                    /* Potentially skip left-over trailing '/' too */
                    if ((wmem_strbuf_get_len(normalised_directory) > 1) &&
                        (wmem_strbuf_get_last_char(normalised_directory) == '/')) {

                        wmem_strbuf_truncate(normalised_directory, wmem_strbuf_get_len(normalised_directory)-1);
                    }
                }
                /* Current directory - ignore */
                else if (strcmp(wmem_strbuf_get_str(this_folder), ".") == 0) {
                    /* Don't copy to normalised_directory */
                }
                else {
                    /* Regular directory name - copy this one out */
                    if (wmem_strbuf_get_len(normalised_directory) > 0 && !ends_with_separator(normalised_directory)) {
                        wmem_strbuf_append_c(normalised_directory, '/');
                    }
                    wmem_strbuf_append(normalised_directory, wmem_strbuf_get_str(this_folder));
                }

                /* Reset folder name for next time */
                this_folder = wmem_strbuf_new(wmem_packet_scope(), NULL);
            }
        }
        else {
            /* Keep copying this folder name */
            wmem_strbuf_append_c(this_folder, ch);
        }
        if (ch == '\0') {
            /* Reached end - get out of loop */
            break;
        }
    }

    /* Copy normalised path into conversation */
    conv->current_working_directory = normalised_directory;
}

/* In response to the arg to a CWD command succeeding, update the conversation's current working directory */
static void process_cwd_success(ftp_conversation_t *conv, const char *new_path)
{
    if (g_path_is_absolute(new_path)) {
        /* Just adopt new_path */
        conv->current_working_directory = wmem_strbuf_new(wmem_file_scope(), new_path);
    }
    else {
        /* Add new_path to what we already have */
        add_directory_to_conv(conv, new_path);
    }
}

/* When get a PWD command response, extract directory and set it in conversation.  */
static void process_pwd_success(ftp_conversation_t *conv, const char *line,
                                int linelen, packet_info *pinfo, proto_item *pi)
{
    wmem_strbuf_t *output = wmem_strbuf_new(wmem_file_scope(), NULL);
    int offset;
    gboolean outputStarted = FALSE;

    /* Line must start with quotes */
    if ((linelen < 2) || (line[0] != '"')) {
        expert_add_info(pinfo, pi, &ei_ftp_pwd_response_invalid);
        return;
    }

    /* For each character */
    for (offset=0;
         (offset < linelen) && (line[offset] != '\r') && (line[offset] != '\n');
         offset++) {

        if (line[offset] == '"') {
            if ((offset+1 < linelen) && (line[offset+1] == '"')) {
                /* Double, so output one */
                wmem_strbuf_append_c(output, '"');
                offset++;
            }
            else {
                if (outputStarted) {
                    /* End of path */
                    break;
                }
                outputStarted = TRUE;
            }
        }
        else {
            /* Part of path - append */
            wmem_strbuf_append_c(output, line[offset]);
        }
    }

    /* Make sure output ends in " */
    if (offset >= linelen || line[offset] != '"') {
        expert_add_info(pinfo, pi, &ei_ftp_pwd_response_invalid);
        return;
    }

    /* Save result */
    conv->current_working_directory = output;
}


/* Associate the conversation's current working directory with the given packet */
static void store_directory_in_packet(packet_info *pinfo, ftp_conversation_t *p_ftp_conv)
{
    ftp_packet_data_t *p_packet_data = wmem_new0(wmem_file_scope(), ftp_packet_data_t);
    /* Take deep copy of current path, and associate with this packet */
    p_packet_data->current_working_directory = wmem_strbuf_new(wmem_file_scope(),
                                                               wmem_strbuf_get_str(p_ftp_conv->current_working_directory));
    p_add_proto_data(wmem_file_scope(), pinfo, proto_ftp, 0, p_packet_data);
}


static int
dissect_ftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gboolean        is_request;
    proto_tree     *ftp_tree;
    proto_tree     *reqresp_tree;
    proto_item     *ti, *hidden_item;
    gint            offset;
    const guchar   *line;
    guint32         code;
    gchar           code_str[4];
    gboolean        is_port_request   = FALSE;
    gboolean        is_eprt_request   = FALSE;
    gboolean        is_pasv_response  = FALSE;
    gboolean        is_epasv_response = FALSE;
    gint            next_offset;
    int             linelen;
    int             tokenlen          = 0;
    const guchar   *next_token;
    guint32         pasv_ip;
    guint32         pasv_offset;
    guint32         ftp_ip;
    guint32         ftp_ip_len;
    guint32         eprt_offset;
    guint32         eprt_af           = 0;
    guint32         eprt_ip;
    guint16         eprt_ipv6[8];
    guint32         eprt_ip_len       = 0;
    guint16         ftp_port;
    guint32         ftp_port_len;
    address         ftp_ip_address;
    gboolean        ftp_nat;

    copy_address_shallow(&ftp_ip_address, &pinfo->src);

    if (pinfo->match_uint == pinfo->destport)
        is_request = TRUE;
    else
        is_request = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTP");

    /* Get the conversation */
    ftp_conversation_t *p_ftp_conv = find_or_create_ftp_conversation(pinfo);

    /* Store the current working directory */
    if (!pinfo->fd->visited) {
        store_directory_in_packet(pinfo, p_ftp_conv);
    }

    /*
     * Find the end of the first line.
     *
     * Note that "tvb_find_line_end()" will return a value that is
     * not longer than what's in the buffer, so the "tvb_get_ptr()"
     * call won't throw an exception.
     */
    linelen = tvb_find_line_end(tvb, 0, -1, &next_offset, FALSE);
    line    = tvb_get_ptr(tvb, 0, linelen);

    /*
     * Put the first line from the buffer into the summary
     * (but leave out the line terminator).
     */
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
        is_request ? "Request" : "Response",
        format_text(wmem_packet_scope(), line, linelen));

    ti = proto_tree_add_item(tree, proto_ftp, tvb, 0, -1, ENC_NA);
    ftp_tree = proto_item_add_subtree(ti, ett_ftp);

    hidden_item = proto_tree_add_boolean(ftp_tree,
            hf_ftp_request, tvb, 0, 0, is_request);
    proto_item_set_hidden(hidden_item);
    hidden_item = proto_tree_add_boolean(ftp_tree,
            hf_ftp_response, tvb, 0, 0, is_request == FALSE);
    proto_item_set_hidden(hidden_item);

    /* Put the line into the protocol tree. */
    ti = proto_tree_add_format_text(ftp_tree, tvb, 0, next_offset);
    reqresp_tree = proto_item_add_subtree(ti, ett_ftp_reqresp);

    if (is_request) {
        /*
         * Extract the first token, and, if there is a first
         * token, add it as the request.
         */
        tokenlen = get_token_len(line, line + linelen, &next_token);
        if (tokenlen != 0) {
            proto_tree_add_item(reqresp_tree, hf_ftp_request_command,
                    tvb, 0, tokenlen, ENC_ASCII);
            if (strncmp(line, "PORT", tokenlen) == 0)
                is_port_request = TRUE;
            /*
             * EPRT request command, as per RFC 2428
             */
            else if (strncmp(line, "EPRT", tokenlen) == 0)
                is_eprt_request = TRUE;
            else if (strncmp(line, "USER", tokenlen) == 0) {
                if (p_ftp_conv && !p_ftp_conv->username && linelen - tokenlen > 1) {
                    p_ftp_conv->username = wmem_strndup(wmem_file_scope(), line + tokenlen + 1, linelen - tokenlen - 1);
                    p_ftp_conv->username_pkt_num = pinfo->num;
                }
            } else if (strncmp(line, "PASS", tokenlen) == 0) {
                if (p_ftp_conv && p_ftp_conv->username) {
                    tap_credential_t* auth = wmem_new0(wmem_packet_scope(), tap_credential_t);
                    auth->num = pinfo->num;
                    auth->proto = "FTP";
                    auth->password_hf_id = hf_ftp_request_arg;
                    auth->username = p_ftp_conv->username;
                    auth->username_num = p_ftp_conv->username_pkt_num;
                    auth->info = wmem_strdup_printf(wmem_packet_scope(), "Username in packet: %u", p_ftp_conv->username_pkt_num);
                    tap_queue_packet(credentials_tap, pinfo, auth);
                }
            }
        }

        /* If there is an ftp data conversation that doesn't have a
           command yet, attempt to update here */
        if (p_ftp_conv) {
            p_ftp_conv->last_command = wmem_strndup(wmem_file_scope(), line, linelen);
            p_ftp_conv->last_command_frame = pinfo->num;

            if ( ( linelen == 8 ) && ! strncmp( "AUTH TLS", line, 8 ) )
                p_ftp_conv->tls_requested = TRUE ;
        }
        /* And make sure set for FTP data conversation */
        if (p_ftp_conv && p_ftp_conv->current_data_conv && !p_ftp_conv->current_data_conv->command) {
            /* Store command and frame where it happened */
            p_ftp_conv->current_data_conv->command = wmem_strndup(wmem_file_scope(), line, linelen);
            p_ftp_conv->current_data_conv->command_frame = pinfo->num;

            /* Add to table to ftp-data response can be shown with this frame on later passes */
            g_hash_table_insert(ftp_command_to_data_hash, GUINT_TO_POINTER(pinfo->num),
                                p_ftp_conv->current_data_conv);
            g_hash_table_insert(ftp_command_to_data_hash, GUINT_TO_POINTER(p_ftp_conv->current_data_setup_frame),
                                p_ftp_conv->current_data_conv);
        }
    } else {
        /*
         * This is a response; the response code is 3 digits,
         * followed by a space or hyphen, possibly followed by
         * text.
         *
         * If the line doesn't start with 3 digits, it's part of
         * a continuation.
         *
         * XXX - keep track of state in the first pass, and
         * treat non-continuation lines not beginning with digits
         * as errors?
         */
        if (linelen >= 3 && g_ascii_isdigit(line[0]) && g_ascii_isdigit(line[1])
            && g_ascii_isdigit(line[2])) {
            gboolean code_valid;
            proto_item* pi;
            /*
             * One-line reply, or first or last line
             * of a multi-line reply.
             */
            tvb_get_raw_bytes_as_string(tvb, 0, code_str, sizeof code_str);
            code_valid = ws_strtou32(code_str, NULL, &code);

            pi = proto_tree_add_uint(reqresp_tree,
                    hf_ftp_response_code, tvb, 0, 3, code);

            if (!code_valid)
                expert_add_info(pinfo, pi, &ei_ftp_response_code_invalid);

            /*
             * See if it's a passive-mode response.
             *
             * XXX - does anybody do FOOBAR, as per RFC
             * 1639, or has that been supplanted by RFC 2428?
             */
            if (code == 227)
                is_pasv_response = TRUE;

            /*
             * Responses to EPSV command, as per RFC 2428
             */
            if (code == 229)
                is_epasv_response = TRUE;

            /*
             * Response to AUTH TLS command as per RFC 4217
             */
            if (code == 234) {
                if ( p_ftp_conv->tls_requested ) {
                    /* AUTH TLS accepted, next reply will be TLS */
                    ssl_starttls_ack( tls_handle, pinfo, ftp_handle);

                    p_ftp_conv->tls_requested = FALSE ;
                }
            }

            /*
             * Responses to CWD command.
             */
            if (code == 250) {
                if (!pinfo->fd->visited) {
                    if (p_ftp_conv && p_ftp_conv->last_command) {
                        /* Explicit Change Working Directory command */
                        if (strncmp(p_ftp_conv->last_command, "CWD ", 4) == 0) {
                            process_cwd_success(p_ftp_conv, p_ftp_conv->last_command+4);
                            /* Update path in packet */
                            store_directory_in_packet(pinfo, p_ftp_conv);
                        }
                        /* Change Directory Up command (i.e. "CWD ..") */
                        else if (strncmp(p_ftp_conv->last_command, "CDUP", 4) == 0) {
                            process_cwd_success(p_ftp_conv, "..");
                            /* Update path in packet */
                            store_directory_in_packet(pinfo, p_ftp_conv);
                        }
                    }
                }
            }

            /*
             * Responses to PWD command. Overwrite whatever is stored - this is the truth!
             */
            if (code == 257) {
                if (!pinfo->fd->visited) {
                    if (p_ftp_conv && linelen >= 4) {
                        /* Want directory name, which will be between " " */
                        process_pwd_success(p_ftp_conv, line+4, linelen-4, pinfo, pi);

                        /* Update path in packet */
                        if (!pinfo->fd->visited) {
                            store_directory_in_packet(pinfo, p_ftp_conv);
                        }
                    }
                }
            }


            /*
             * Skip the 3 digits and, if present, the
             * space or hyphen.
             */
            if (linelen >= 4)
                next_token = line + 4;
            else
                next_token = line + linelen;
        } else {
            /*
             * Line doesn't start with 3 digits; assume it's
             * a line in the middle of a multi-line reply.
             */
            next_token = line;
        }
    }

    offset   = (gint) (next_token - line);
    linelen -= (int) (next_token - line);
    line     = next_token;

    /*
     * Add the rest of the first line as request or
     * reply data.
     */
    if (linelen != 0) {
        if (is_request) {
            proto_tree_add_item(reqresp_tree,
                    hf_ftp_request_arg, tvb, offset,
                    linelen, ENC_ASCII);
        } else {
            proto_tree_add_item(reqresp_tree,
                    hf_ftp_response_arg, tvb, offset,
                    linelen, ENC_ASCII);
        }
    }
    offset = next_offset;


    /*
     * If this is a PORT request or a PASV response, handle it.
     */
    if (is_port_request) {
        if (parse_port_pasv(line, linelen, &ftp_ip, &ftp_port, &pasv_offset, &ftp_ip_len, &ftp_port_len)) {
            proto_tree_add_ipv4(reqresp_tree, hf_ftp_active_ip,
                    tvb, pasv_offset + (tokenlen+1) , ftp_ip_len, ftp_ip);
            proto_tree_add_uint(reqresp_tree, hf_ftp_active_port,
                    tvb, pasv_offset + 1 + (tokenlen+1) + ftp_ip_len, ftp_port_len, ftp_port);
            set_address(&ftp_ip_address, AT_IPv4, 4, (const guint8 *)&ftp_ip);
            ftp_nat = !addresses_equal(&pinfo->src, &ftp_ip_address);
            if (ftp_nat) {
                proto_tree_add_boolean(reqresp_tree, hf_ftp_active_nat,
                        tvb, 0, 0, ftp_nat);
            }

            /* Set up data conversation */
            create_and_link_data_conversation(pinfo,
                                              &pinfo->dst, 20,
                                              &ftp_ip_address, ftp_port,
                                              "PORT");
        }
    }

    if (is_pasv_response) {
        if (linelen != 0) {
            /*
             * This frame contains a PASV response; set up a
             * conversation for the data.
             */
            if (parse_port_pasv(line, linelen, &pasv_ip, &ftp_port, &pasv_offset, &ftp_ip_len, &ftp_port_len)) {
                proto_tree_add_ipv4(reqresp_tree, hf_ftp_pasv_ip,
                        tvb, pasv_offset + 4, ftp_ip_len, pasv_ip);
                proto_tree_add_uint(reqresp_tree, hf_ftp_pasv_port,
                        tvb, pasv_offset + 4 + 1 + ftp_ip_len, ftp_port_len, ftp_port);
                set_address(&ftp_ip_address, AT_IPv4, 4,
                    (const guint8 *)&pasv_ip);
                ftp_nat = !addresses_equal(&pinfo->src, &ftp_ip_address);
                if (ftp_nat) {
                    proto_tree_add_boolean(reqresp_tree, hf_ftp_pasv_nat,
                            tvb, 0, 0, ftp_nat);
                }

                create_and_link_data_conversation(pinfo, &ftp_ip_address, ftp_port, &pinfo->dst, pinfo->destport, "PASV");
            }
        }
    }

    if (is_eprt_request) {
        /*
         * RFC2428 - sect. 2
         * This frame contains a EPRT request; let's dissect it and set up a
         * conversation for the data connection.
         */
        if (parse_eprt_request(line, linelen,
                    &eprt_af, &eprt_ip, eprt_ipv6, &ftp_port,
                    &eprt_ip_len, &ftp_port_len)) {

            /* since parse_eprt_request() returned TRUE,
               we know that we have a valid address family */
            eprt_offset = tokenlen + 1 + 1;  /* token, space, 1st delimiter */
            proto_tree_add_uint(reqresp_tree, hf_ftp_eprt_af, tvb,
                    eprt_offset, 1, eprt_af);
            eprt_offset += 1 + 1; /* addr family, 2nd delimiter */

            if (eprt_af == EPRT_AF_IPv4) {
                proto_tree_add_ipv4(reqresp_tree, hf_ftp_eprt_ip,
                        tvb, eprt_offset, eprt_ip_len, eprt_ip);
                set_address(&ftp_ip_address, AT_IPv4, 4,
                        (const guint8 *)&eprt_ip);
            }
            else if (eprt_af == EPRT_AF_IPv6) {
                proto_tree_add_ipv6(reqresp_tree, hf_ftp_eprt_ipv6,
                        tvb, eprt_offset, eprt_ip_len, (const ws_in6_addr *)eprt_ipv6);
                set_address(&ftp_ip_address, AT_IPv6, 16, eprt_ipv6);
            }
            eprt_offset += eprt_ip_len + 1; /* addr, 3rd delimiter */

            proto_tree_add_uint(reqresp_tree, hf_ftp_eprt_port,
                    tvb, eprt_offset, ftp_port_len, ftp_port);

            /* Set up data conversation */
            create_and_link_data_conversation(pinfo,
                                              &pinfo->src, ftp_port,
                                              &ftp_ip_address, 0,
                                              "EPRT");
        }
        else {
            proto_tree_add_expert(reqresp_tree, pinfo, &ei_ftp_eprt_args_invalid,
                    tvb, offset - linelen - 1, linelen);
        }
    }

    if (is_epasv_response) {
        if (linelen != 0) {
            proto_item *addr_it;
            /*
             * RFC2428 - sect. 3
             * This frame contains an  EPSV response; set up a
             * conversation for the data.
             */
            if (parse_extended_pasv_response(line, linelen,
                        &ftp_port, &pasv_offset, &ftp_port_len)) {
                /* Add IP address and port number to tree */

                if (ftp_ip_address.type == AT_IPv4) {
                    guint32 addr;
                    memcpy(&addr, ftp_ip_address.data, 4);
                    addr_it = proto_tree_add_ipv4(reqresp_tree,
                            hf_ftp_epsv_ip, tvb, 0, 0, addr);
                    proto_item_set_generated(addr_it);
                }
                else if (ftp_ip_address.type == AT_IPv6) {
                    addr_it = proto_tree_add_ipv6(reqresp_tree,
                            hf_ftp_epsv_ipv6, tvb, 0, 0,
                            (const ws_in6_addr *)ftp_ip_address.data);
                    proto_item_set_generated(addr_it);
                }

                proto_tree_add_uint(reqresp_tree,
                        hf_ftp_epsv_port, tvb, pasv_offset + 4,
                        ftp_port_len, ftp_port);

                /* Set up data conversation */
                create_and_link_data_conversation(pinfo,
                                                  &ftp_ip_address, ftp_port,
                                                  &pinfo->dst, 0, "EPASV");             }
            else {
                proto_tree_add_expert(reqresp_tree, pinfo, &ei_ftp_epsv_args_invalid,
                        tvb, offset - linelen - 1, linelen);
            }
        }
    }

    /*
     * Show the rest of the request or response as text,
     * a line at a time.
     * XXX - only if there's a continuation indicator?
     */
    while (tvb_offset_exists(tvb, offset)) {
        /*
         * Find the end of the line.
         */
        tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);

        /*
         * Put this line.
         */
        proto_tree_add_format_text(ftp_tree, tvb, offset,
                next_offset - offset);
        offset = next_offset;
    }

    /* Show current working directory */
    ftp_packet_data_t *ftp_packet_data = (ftp_packet_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ftp, 0);
    if (ftp_packet_data != NULL) {
        /* Should always be set.. */
        if (ftp_packet_data->current_working_directory) {
            proto_item *cwd_ti = proto_tree_add_string(tree, hf_ftp_current_working_directory,
                                                       tvb, 0, 0, wmem_strbuf_get_str(ftp_packet_data->current_working_directory));
            proto_item_set_generated(cwd_ti);
        }
    }

    /* If this is a command resulting in an ftp-data stream, show details */
    if (pinfo->fd->visited) {
        /* Look up what has been stored for this frame */
        ftp_data_conversation_t *ftp_data =
                (ftp_data_conversation_t *)g_hash_table_lookup(ftp_command_to_data_hash, GUINT_TO_POINTER(pinfo->num));
        if (ftp_data) {
            /* Show these for the command frame only */
            if (pinfo->num == ftp_data->command_frame) {
                /* Number of frames */
                ti = proto_tree_add_uint(tree, hf_ftp_command_response_frames,
                                         tvb, 0, 0, ftp_data->frames_seen);
                proto_item_set_generated(ti);

                /* Number of bytes */
                ti = proto_tree_add_uint(tree, hf_ftp_command_response_bytes,
                                         tvb, 0, 0, ftp_data->bytes_seen);
                proto_item_set_generated(ti);

                /* First frame */
                ti = proto_tree_add_uint(tree, hf_ftp_command_response_first_frame_num,
                                         tvb, 0, 0, ftp_data->first_frame_num);
                proto_item_set_generated(ti);

                /* Last frame */
                ti = proto_tree_add_uint(tree, hf_ftp_command_response_last_frame_num,
                                         tvb, 0, 0, ftp_data->last_frame_num);
                proto_item_set_generated(ti);

                /* Length of stream */
                if (ftp_data->frames_seen > 1) {
                    /* Work out gap between frames */
                    gint seconds = (gint)
                              (ftp_data->last_frame_time.secs - ftp_data->first_frame_time.secs);
                    gint nseconds =
                              ftp_data->last_frame_time.nsecs - ftp_data->first_frame_time.nsecs;

                    /* Round gap to nearest ms. */
                    gint gap_ms = (seconds*1000) + ((nseconds+500000) / 1000000);
                    ti = proto_tree_add_uint(tree, hf_ftp_command_response_duration,
                                         tvb, 0, 0, gap_ms);
                    proto_item_set_generated(ti);

                    /* Bitrate (kbps)*/
                    guint bitrate = (guint)(((ftp_data->bytes_seen*8.0)/(gap_ms/1000.0))/1000);
                    ti = proto_tree_add_uint(tree, hf_ftp_command_response_kbps,
                                             tvb, offset, 0, bitrate);
                    proto_item_set_generated(ti);
                }

                ti = proto_tree_add_uint(tree, hf_ftp_command_setup_frame,
                                         tvb, 0, 0, ftp_data->setup_frame);
                proto_item_set_generated(ti);
            }

            /* Show this only under the setup frame */
            if (pinfo->num == ftp_data->setup_frame) {
                ti = proto_tree_add_string(tree, hf_ftp_command_command,
                                           tvb, 0, 0, ftp_data->command);
                proto_item_set_generated(ti);

                ti = proto_tree_add_uint(tree, hf_ftp_command_command_frame,
                                         tvb, 0, 0, ftp_data->command_frame);
                proto_item_set_generated(ti);
            }
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_ftpdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *data_ti, *ti;
    int         data_length = tvb_captured_length(tvb);
    gboolean    is_text = TRUE;
    gint        check_chars, i;
    conversation_t *p_conv;
    ftp_data_conversation_t *p_ftp_data_conv;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FTP-DATA");

    col_add_fstr(pinfo->cinfo, COL_INFO, "FTP Data: %u bytes",
        tvb_reported_length(tvb));

    data_ti = proto_tree_add_item(tree, proto_ftp_data, tvb, 0, -1, ENC_NA);

    /* Link back to setup of this stream */
    p_conv = find_conversation_pinfo(pinfo, 0);

    if (p_conv) {
        /* Link back to FTP frame where this conversation was created */
        ti = proto_tree_add_uint(tree, hf_ftp_data_setup_frame,
                                 tvb, 0, 0, p_conv->setup_frame);
        proto_item_set_generated(ti);

        p_ftp_data_conv = (ftp_data_conversation_t*)conversation_get_proto_data(p_conv, proto_ftp_data);

        if (p_ftp_data_conv) {
            /* First time around, update info. */
            if (!pinfo->fd->visited) {
                if (!p_ftp_data_conv->first_frame_num) {
                    p_ftp_data_conv->first_frame_num = pinfo->num;
                    p_ftp_data_conv->first_frame_time = pinfo->abs_ts;
                }
                if (pinfo->num > p_ftp_data_conv->last_frame_num) {
                    p_ftp_data_conv->last_frame_num = pinfo->num;
                    p_ftp_data_conv->last_frame_time = pinfo->abs_ts;
                }
                p_ftp_data_conv->frames_seen++;
                p_ftp_data_conv->bytes_seen += tvb_reported_length(tvb);

                /* Also store setup_frame here for benefit of ftp (control) */
                p_ftp_data_conv->setup_frame = p_conv->setup_frame;
            }

            /* Show setup method as field and in info column */
            if (p_ftp_data_conv->setup_method) {
                ti = proto_tree_add_string(tree, hf_ftp_data_setup_method,
                                           tvb, 0, 0, p_ftp_data_conv->setup_method);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", p_ftp_data_conv->setup_method);
                proto_item_set_generated(ti);
            }

            /* Show command in info column */
            if (p_ftp_data_conv->command) {
                ti = proto_tree_add_string(tree, hf_ftp_data_command,
                                           tvb, 0, 0, p_ftp_data_conv->command);
                proto_item_set_generated(ti);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", p_ftp_data_conv->command);

                proto_tree_add_uint(tree, hf_ftp_data_command_frame,
                                    tvb, 0, 0, p_ftp_data_conv->command_frame);
                proto_item_set_generated(ti);
            }

            /* Show current working directory */
            if (p_ftp_data_conv->current_working_directory) {
                ti = proto_tree_add_string(tree, hf_ftp_data_current_working_directory,
                                           tvb, 0, 0, wmem_strbuf_get_str(p_ftp_data_conv->current_working_directory));
                proto_item_set_generated(ti);
            }
            if (have_tap_listener(ftp_eo_tap)) {
                if (p_ftp_data_conv->command_frame) {
                    ftp_eo_t *eo_info = wmem_new0(wmem_packet_scope(), ftp_eo_t);
                    eo_info->command = wmem_strdup(wmem_packet_scope(), p_ftp_data_conv->command);
                    eo_info->command_frame = p_ftp_data_conv->command_frame;
                    eo_info->payload_len = tvb_reported_length(tvb);
                    eo_info->payload_data = (gchar *) tvb_memdup(wmem_packet_scope(), tvb, 0, tvb_reported_length(tvb));
                    tap_queue_packet(ftp_eo_tap, pinfo, eo_info);
                }
            }
        }
    }

    /* Check the first few chars to see whether it looks like a text file or output */
    check_chars = MIN(20, data_length);
    for (i=0; i < check_chars; i++) {
        guint8 c = tvb_get_guint8(tvb, i);
        if (c!='\r' && c!='\n' && !g_ascii_isprint(c)) {
            is_text = FALSE;
            break;
        }
    }

    /* Show the number of bytes */
    proto_item_append_text(data_ti, " (%u bytes data)", data_length);

    /* Show line-by-line if text */
    if (is_text) {
        call_dissector(data_text_lines_handle, tvb, pinfo, tree);
    }

    return data_length;
}

static void ftp_init_protocol(void)
{
    ftp_command_to_data_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void ftp_cleanup_protocol(void)
{
    g_hash_table_destroy(ftp_command_to_data_hash);
}

void
proto_register_ftp(void)
{
    static hf_register_info hf[] = {
        { &hf_ftp_current_working_directory,
          { "Current working directory", "ftp.current-working-directory",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},

        { &hf_ftp_response,
          { "Response",           "ftp.response",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "TRUE if FTP response", HFILL }},

        { &hf_ftp_request,
          { "Request",            "ftp.request",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "TRUE if FTP request", HFILL }},

        { &hf_ftp_request_command,
          { "Request command",    "ftp.request.command",
            FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ftp_request_arg,
          { "Request arg",        "ftp.request.arg",
            FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ftp_response_code,
          { "Response code",      "ftp.response.code",
            FT_UINT32,   BASE_DEC|BASE_EXT_STRING, &response_table_ext, 0x0,
            NULL, HFILL }},

        { &hf_ftp_response_arg,
          { "Response arg",      "ftp.response.arg",
            FT_STRING,  BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_ftp_pasv_ip,
          { "Passive IP address", "ftp.passive.ip",
            FT_IPv4, BASE_NONE, NULL,0x0,
            "Passive IP address (check NAT)", HFILL}},

        { &hf_ftp_pasv_port,
          { "Passive port", "ftp.passive.port",
            FT_UINT16, BASE_DEC, NULL,0x0,
            "Passive FTP server port", HFILL }},

        { &hf_ftp_pasv_nat,
          {"Passive IP NAT", "ftp.passive.nat",
           FT_BOOLEAN, BASE_NONE, NULL, 0x0,
           "NAT is active SIP and passive IP different", HFILL }},

        { &hf_ftp_active_ip,
          { "Active IP address", "ftp.active.cip",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            "Active FTP client IP address", HFILL }},

        { &hf_ftp_active_port,
          {"Active port", "ftp.active.port",
           FT_UINT16, BASE_DEC, NULL, 0x0,
           "Active FTP client port", HFILL }},

        { &hf_ftp_active_nat,
          { "Active IP NAT", "ftp.active.nat",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "NAT is active", HFILL}},

        { &hf_ftp_eprt_af,
          { "Extended active address family", "ftp.eprt.af",
            FT_UINT8, BASE_DEC, VALS(eprt_af_vals), 0,
            NULL, HFILL }},

        { &hf_ftp_eprt_ip,
          { "Extended active IP address", "ftp.eprt.ip",
            FT_IPv4, BASE_NONE, NULL, 0,
            "Extended active FTP client IPv4 address", HFILL }},

        { &hf_ftp_eprt_ipv6,
          { "Extended active IPv6 address", "ftp.eprt.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0,
            "Extended active FTP client IPv6 address", HFILL }},

        { &hf_ftp_eprt_port,
          { "Extended active port", "ftp.eprt.port",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Extended active FTP client listener port", HFILL }},

        { &hf_ftp_epsv_ip,
          { "Extended passive IPv4 address", "ftp.epsv.ip",
            FT_IPv4, BASE_NONE, NULL, 0,
            "Extended passive FTP server IPv4 address", HFILL }},

        { &hf_ftp_epsv_ipv6,
          { "Extended passive IPv6 address", "ftp.epsv.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0,
            "Extended passive FTP server IPv6 address", HFILL }},

        { &hf_ftp_epsv_port,
          { "Extended passive port", "ftp.epsv.port",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Extended passive FTP server port", HFILL }},

        { &hf_ftp_command_response_first_frame_num,
          { "Command response first frame", "ftp.command-response.first-frame-num",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
            "First frame seen in resulting ftp-data stream", HFILL }},

        { &hf_ftp_command_response_last_frame_num,
          { "Command response last frame", "ftp.command-response.last-frame-num",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0,
            "Last frame seen in resulting ftp-data stream", HFILL }},

        { &hf_ftp_command_response_duration,
          { "Response duration", "ftp.command-response.duration",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_milliseconds, 0,
            "Duration of command response in ms", HFILL }},

        { &hf_ftp_command_response_kbps,
          { "Response bitrate", "ftp.command-response.bitrate",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_kbps, 0,
            "Bitrate of command response", HFILL }},

        { &hf_ftp_command_response_frames,
          { "Command response frames", "ftp.command-response.frames",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Number of frames seen in resulting ftp-data stream", HFILL }},

        { &hf_ftp_command_response_bytes,
          { "Command response bytes", "ftp.command-response.bytes",
            FT_UINT32, BASE_DEC, NULL, 0,
            "Number of bytes seen in resulting ftp-data stream", HFILL }},

        { &hf_ftp_command_setup_frame,
          { "Setup frame", "ftp.setup-frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
            "Where ftp-data conversation for this command was signalled", HFILL }},

        { &hf_ftp_command_command_frame,
          { "Command frame", "ftp.command-frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0,
            "Where command for setup was seen", HFILL }},

        { &hf_ftp_command_command,
          { "Command", "ftp.command",
            FT_STRING, BASE_NONE, NULL, 0,
            "Command corresponding to this setup frame", HFILL }},
    };
    static gint *ett[] = {
        &ett_ftp,
        &ett_ftp_reqresp
    };

    static hf_register_info data_hf[] = {
        { &hf_ftp_data_setup_frame,
          { "Setup frame", "ftp-data.setup-frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Where ftp-data conversation was signalled", HFILL }},

        { &hf_ftp_data_setup_method,
          { "Setup method", "ftp-data.setup-method",
            FT_STRING, BASE_NONE, NULL, 0,
            "Method used to set up data conversation", HFILL }},

        { &hf_ftp_data_command,
          { "Command", "ftp-data.command",
            FT_STRING, BASE_NONE, NULL, 0,
            "Command that this data stream answers", HFILL }},

        { &hf_ftp_data_command_frame,
          { "Command frame", "ftp-data.command-frame",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "Where command for this data was seen", HFILL }},

        { &hf_ftp_data_current_working_directory,
          { "Current working directory", "ftp-data.current-working-directory",
            FT_STRING, BASE_NONE, NULL, 0,
            "Current working directory at time of command", HFILL }}
    };

    static ei_register_info ei[] = {
        { &ei_ftp_eprt_args_invalid, { "ftp.eprt.args_invalid", PI_MALFORMED, PI_WARN, "EPRT arguments must have the form: |<family>|<addr>|<port>|", EXPFILL }},
        { &ei_ftp_epsv_args_invalid, { "ftp.epsv.args_invalid", PI_MALFORMED, PI_WARN, "EPSV arguments must have the form (|||<port>|)", EXPFILL }},
        { &ei_ftp_response_code_invalid, { "ftp.response.code.invalid", PI_MALFORMED, PI_ERROR, "Invalid response code", EXPFILL }},
        { &ei_ftp_pwd_response_invalid, { "ftp.response.pwd.invalid", PI_MALFORMED, PI_ERROR, "Invalid PWD response", EXPFILL }}
    };

    expert_module_t* expert_ftp;

    proto_ftp = proto_register_protocol("File Transfer Protocol (FTP)", "FTP", "ftp");

    ftp_handle = register_dissector("ftp", dissect_ftp, proto_ftp);
    proto_ftp_data = proto_register_protocol("FTP Data", "FTP-DATA", "ftp-data");
    ftpdata_handle = register_dissector("ftp-data", dissect_ftpdata, proto_ftp_data);
    proto_register_field_array(proto_ftp, hf, array_length(hf));
    proto_register_field_array(proto_ftp, data_hf, array_length(data_hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ftp = expert_register_protocol(proto_ftp);
    expert_register_field_array(expert_ftp, ei, array_length(ei));

    register_init_routine(&ftp_init_protocol);
    register_cleanup_routine(&ftp_cleanup_protocol);

    credentials_tap = register_tap("credentials");

    module_t *ftp_prefs_module = prefs_register_protocol(proto_ftp_data, NULL);
    prefs_register_uint_preference(ftp_prefs_module, "export.maxsize",
                             "Max file size (in MB) for export objects (use 0 for unlimited)", /* Title */
                             "Maximum file size (in megabytes) for export objects  (use 0 for unlimited).", /* Description */
                             10,
                             &pref_export_maxsize);
    ftp_eo_tap = register_export_object(proto_ftp_data, ftp_eo_packet, ftp_eo_cleanup);
}

void
proto_reg_handoff_ftp(void)
{
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_FTPDATA, ftpdata_handle);
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_FTP, ftp_handle);
    dissector_add_uint("acdr.tls_application", TLS_APP_FTP, ftp_handle);

    data_text_lines_handle = find_dissector_add_dependency("data-text-lines", proto_ftp_data);

    tls_handle = find_dissector( "tls" );
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
