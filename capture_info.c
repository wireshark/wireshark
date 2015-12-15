/* capture_info.c
 * capture info functions
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

#include <config.h>

#ifdef HAVE_LIBPCAP

#include <glib.h>

#include <epan/packet.h>
/* XXX - try to remove this later */
#include <epan/prefs.h>
/* XXX - try to remove this later */

#include <wiretap/wtap.h>

#include "capture_info.h"

#include <epan/capture_dissectors.h>

#include <wsutil/filesystem.h>

typedef struct _info_data {
    packet_counts     counts;     /* several packet type counters */
    struct wtap*      wtap;       /* current wtap file */
    capture_info      ui;         /* user interface data */
} info_data_t;


static info_data_t info_data;


/* open the info */
void capture_info_open(capture_session *cap_session)
{
    info_data.counts.total      = 0;
    info_data.counts.sctp       = 0;
    info_data.counts.tcp        = 0;
    info_data.counts.udp        = 0;
    info_data.counts.icmp       = 0;
    info_data.counts.ospf       = 0;
    info_data.counts.gre        = 0;
    info_data.counts.ipx        = 0;
    info_data.counts.netbios    = 0;
    info_data.counts.vines      = 0;
    info_data.counts.other      = 0;
    info_data.counts.arp        = 0;
    info_data.counts.i2c_event  = 0;
    info_data.counts.i2c_data   = 0;

    info_data.wtap = NULL;
    info_data.ui.counts = &info_data.counts;

    capture_info_ui_create(&info_data.ui, cap_session);
}


static const char *
cf_open_error_message(int err, gchar *err_info, gboolean for_writing,
                      int file_type)
{
    const char *errmsg;
    static char errmsg_errno[1024+1];

    if (err < 0) {
        /* Wiretap error. */
        switch (err) {

        case WTAP_ERR_NOT_REGULAR_FILE:
            errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
            break;

        case WTAP_ERR_FILE_UNKNOWN_FORMAT:
            /* Seen only when opening a capture file for reading. */
            errmsg = "The file \"%s\" isn't a capture file in a format Wireshark understands.";
            break;

        case WTAP_ERR_UNSUPPORTED:
            /* Seen only when opening a capture file for reading. */
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" contains record data that Wireshark doesn't support.\n"
                       "(%s)", err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            /* Seen only when opening a capture file for writing. */
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" is a pipe, and %s capture files can't be "
                       "written to a pipe.", wtap_file_type_subtype_string(file_type));
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_UNWRITABLE_FILE_TYPE:
            /* Seen only when opening a capture file for writing. */
            errmsg = "Wireshark doesn't support writing capture files in that format.";
            break;

        case WTAP_ERR_UNWRITABLE_ENCAP:
            /* Seen only when opening a capture file for writing. */
            errmsg = "Wireshark can't save this capture in that format.";
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            if (for_writing)
                errmsg = "Wireshark can't save this capture in that format.";
            else
                errmsg = "The file \"%s\" is a capture for a network type that Wireshark doesn't support.";
            break;

        case WTAP_ERR_BAD_FILE:
            /* Seen only when opening a capture file for reading. */
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" appears to be damaged or corrupt.\n"
                       "(%s)", err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        case WTAP_ERR_CANT_OPEN:
            if (for_writing)
                errmsg = "The file \"%s\" could not be created for some unknown reason.";
            else
                errmsg = "The file \"%s\" could not be opened for some unknown reason.";
            break;

        case WTAP_ERR_SHORT_READ:
            errmsg = "The file \"%s\" appears to have been cut short"
                " in the middle of a packet or other data.";
            break;

        case WTAP_ERR_SHORT_WRITE:
            errmsg = "A full header couldn't be written to the file \"%s\".";
            break;

        case WTAP_ERR_DECOMPRESS:
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The compressed file \"%%s\" appears to be damaged or corrupt.\n"
                       "(%s)", err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            errmsg = errmsg_errno;
            break;

        default:
            g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                       "The file \"%%s\" could not be %s: %s.",
                       for_writing ? "created" : "opened",
                       wtap_strerror(err));
            errmsg = errmsg_errno;
            break;
        }
    } else
        errmsg = file_open_error_message(err, for_writing);
    return errmsg;
}

/* new file arrived */
gboolean capture_info_new_file(const char *new_filename)
{
    int err;
    gchar *err_info;
    gchar *err_msg;


    if(info_data.wtap != NULL) {
        wtap_close(info_data.wtap);
    }

    info_data.wtap = wtap_open_offline(new_filename, WTAP_TYPE_AUTO, &err, &err_info, FALSE);
    if (!info_data.wtap) {
        err_msg = g_strdup_printf(cf_open_error_message(err, err_info, FALSE, WTAP_FILE_TYPE_SUBTYPE_UNKNOWN),
                                  new_filename);
        g_warning("capture_info_new_file: %d (%s)", err, err_msg);
        g_free (err_msg);
        return FALSE;
    } else
        return TRUE;
}

static void
capture_info_packet(packet_counts *counts, gint wtap_linktype, const guchar *pd, guint32 caplen, union wtap_pseudo_header *pseudo_header)
{
    capture_packet_info_t cpinfo;

    /* Setup the capture packet structure */
    cpinfo.counts = counts;

    counts->total++;
    if (!try_capture_dissector("wtap_encap", wtap_linktype, pd, 0, caplen, &cpinfo, pseudo_header))
        counts->other++;
}

/* new packets arrived */
void capture_info_new_packets(int to_read)
{
    int err;
    gchar *err_info;
    gint64 data_offset;
    struct wtap_pkthdr *phdr;
    union wtap_pseudo_header *pseudo_header;
    int wtap_linktype;
    const guchar *buf;


    info_data.ui.new_packets = to_read;

    /*g_warning("new packets: %u", to_read);*/

    while (to_read > 0) {
        wtap_cleareof(info_data.wtap);
        if (wtap_read(info_data.wtap, &err, &err_info, &data_offset)) {
            phdr = wtap_phdr(info_data.wtap);
            pseudo_header = &phdr->pseudo_header;
            wtap_linktype = phdr->pkt_encap;
            buf = wtap_buf_ptr(info_data.wtap);

            capture_info_packet(&info_data.counts, wtap_linktype, buf, phdr->caplen, pseudo_header);

            /*g_warning("new packet");*/
            to_read--;
        }
    }

    capture_info_ui_update(&info_data.ui);
}


/* close the info */
void capture_info_close(void)
{
    capture_info_ui_destroy(&info_data.ui);
    if(info_data.wtap)
        wtap_close(info_data.wtap);
}

#endif /* HAVE_LIBPCAP */

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
