/* capture_info.c
 * capture info functions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#ifdef HAVE_LIBPCAP

#include <glib.h>

#include <epan/packet.h>
#include <wiretap/wtap.h>

#include "capture_info.h"

#include <epan/capture_dissectors.h>

static void
capture_info_packet(info_data_t* cap_info, gint wtap_linktype, const guchar *pd, guint32 caplen, union wtap_pseudo_header *pseudo_header)
{
    capture_packet_info_t cpinfo;

    /* Setup the capture packet structure */
    cpinfo.counts = cap_info->counts.counts_hash;

    cap_info->counts.total++;
    if (!try_capture_dissector("wtap_encap", wtap_linktype, pd, 0, caplen, &cpinfo, pseudo_header))
        cap_info->counts.other++;
}

/* new packets arrived */
void capture_info_new_packets(int to_read, info_data_t* cap_info)
{
    int err;
    gchar *err_info;
    gint64 data_offset;
    wtap_rec *rec;
    union wtap_pseudo_header *pseudo_header;
    int wtap_linktype;
    const guchar *buf;


    cap_info->ui.new_packets = to_read;

    /*g_warning("new packets: %u", to_read);*/

    while (to_read > 0) {
        wtap_cleareof(cap_info->wtap);
        if (wtap_read(cap_info->wtap, &err, &err_info, &data_offset)) {
            rec = wtap_get_rec(cap_info->wtap);
            if (rec->rec_type == REC_TYPE_PACKET) {
                pseudo_header = &rec->rec_header.packet_header.pseudo_header;
                wtap_linktype = rec->rec_header.packet_header.pkt_encap;
                buf = wtap_get_buf_ptr(cap_info->wtap);

                capture_info_packet(cap_info, wtap_linktype, buf, rec->rec_header.packet_header.caplen, pseudo_header);

                /*g_warning("new packet");*/
                to_read--;
            }
        }
    }

    capture_info_ui_update(&cap_info->ui);
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
