/* follow_ssl.c
 * SSL specific routines for following traffic streams
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"
#include <stdio.h>
#include <string.h>


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>

#include <gtk/gtk.h>

#include <epan/follow.h>
#include <epan/dissectors/packet-ipv6.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/epan_dissect.h>
#include <wsutil/filesystem.h>
#include <epan/tap.h>

#include <ui/alert_box.h>
#include <ui/simple_dialog.h>
#include <ui/utf8_entities.h>
#include <ui/util.h>

#include "gtkglobals.h"
#include "ui/gtk/color_utils.h"
#include "ui/gtk/main.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/font_utils.h"
#include "ui/follow.h"
#include "ui/gtk/follow_ssl.h"
#include "ui/gtk/follow_stream.h"

#ifdef SSL_PLUGIN
#include "packet-ssl-utils.h"
#else
#include <epan/dissectors/packet-ssl-utils.h>
#endif

static int
ssl_queue_packet_data(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *ssl)
{
    follow_info_t *      follow_info = (follow_info_t*) tapdata;
    SslDecryptedRecord * rec = NULL;
    SslDataInfo *        appl_data = NULL;
    int                  proto_ssl = GPOINTER_TO_INT(ssl);
    SslPacketInfo *      pi = NULL;
    show_stream_t        from = FROM_CLIENT;

    /* Skip packets without decrypted payload data. */
    pi = (SslPacketInfo*) p_get_proto_data(wmem_file_scope(), pinfo, proto_ssl, 0);
    if (!pi || !pi->appl_data) return 0;

    /* Compute the packet's sender. */
    if (follow_info->client_port == 0) {
        follow_info->client_port = pinfo->srcport;
        COPY_ADDRESS(&follow_info->client_ip, &pinfo->src);
    }
    if (ADDRESSES_EQUAL(&follow_info->client_ip, &pinfo->src) &&
            follow_info->client_port == pinfo->srcport) {
        from = FROM_CLIENT;
    } else {
        from = FROM_SERVER;
    }

    for (appl_data = pi->appl_data; appl_data != NULL; appl_data = appl_data->next) {

        /* TCP segments that contain the end of two or more SSL PDUs will be
           queued to SSL taps for each of those PDUs. Therefore a single
           packet could be processed by this SSL tap listener multiple times.
           The following test handles that scenario by treating the
           follow_info->bytes_written[] values as the next expected
           appl_data->seq. Any appl_data instances that fall below that have
           already been processed and must be skipped. */
        if (appl_data->seq < follow_info->bytes_written[from]) continue;

        /* Allocate a SslDecryptedRecord to hold the current appl_data
           instance's decrypted data. Even though it would be possible to
           consolidate multiple appl_data instances into a single rec, it is
           beneficial to use a one-to-one mapping. This affords the Follow
           Stream dialog view modes (ASCII, EBCDIC, Hex Dump, C Arrays, Raw)
           the opportunity to accurately reflect SSL PDU boundaries. Currently
           the Hex Dump view does by starting a new line, and the C Arrays
           view does by starting a new array declaration. */
        rec = (SslDecryptedRecord*) g_malloc(sizeof(SslDecryptedRecord) + appl_data->plain_data.data_len);
        rec->is_from_server = from == FROM_SERVER;
        rec->data.data = (guchar*) (rec + 1);
        rec->data.data_len = appl_data->plain_data.data_len;
        memcpy(rec->data.data, appl_data->plain_data.data, appl_data->plain_data.data_len);

        /* Append the record to the follow_info structure. */
        follow_info->payload = g_list_append(follow_info->payload, rec);
        follow_info->bytes_written[from] += rec->data.data_len;
    }

    return 0;
}
/* Follow the SSL stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
follow_ssl_stream_cb(GtkWidget * w _U_, gpointer data _U_)
{
    GtkWidget *     filter_te;
    GtkWidget *     filter_cm;
    gchar *         follow_filter;
    const gchar *   previous_filter;
    int             filter_out_filter_len;
    int             previous_filter_len;
    const char *    hostname0;
    const char *    hostname1;
    const char *    port0;
    const char *    port1;
    const char *    client_hostname;
    const char *    server_hostname;
    const char *    client_port;
    const char *    server_port;
    gchar *         server_to_client_string = NULL;
    gchar *         client_to_server_string = NULL;
    gchar *         both_directions_string = NULL;
    const gchar *   single_direction_format = NULL;
    follow_stats_t  stats;
    follow_info_t * follow_info;
    GString *       msg;

    /* we got ssl so we can follow */
    if (!epan_dissect_packet_contains_field(cfile.edt, "ssl")) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Error following stream.  Please make\n"
                      "sure you have an SSL packet selected.");
        return;
    }

    follow_info = g_new0(follow_info_t, 1);
    follow_info->follow_type = FOLLOW_SSL;

    /* Create a new filter that matches all packets in the SSL stream,
       and set the display filter entry accordingly */
    reset_tcp_reassembly();
    follow_filter = build_follow_conv_filter(&cfile.edt->pi);
    if (!follow_filter)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Error creating filter for this stream.\n"
                      "A network layer header is needed");
        g_free(follow_info);
        return;
    }

    /* Set the display filter entry accordingly */
    filter_cm = (GtkWidget *)g_object_get_data(G_OBJECT(top_level), E_DFILTER_CM_KEY);
    filter_te = gtk_bin_get_child(GTK_BIN(filter_cm));

    /* needed in follow_filter_out_stream(), is there a better way? */
    follow_info->filter_te = filter_te;

    /* save previous filter, const since we're not supposed to alter */
    previous_filter =
        (const gchar *)gtk_entry_get_text(GTK_ENTRY(filter_te));

    /* allocate our new filter. API claims g_malloc terminates program on failure */
    /* my calc for max alloc needed is really +10 but when did a few extra bytes hurt ? */
    previous_filter_len = previous_filter?(int)strlen(previous_filter):0;
    filter_out_filter_len = (int)strlen(follow_filter) + previous_filter_len + 16;
    follow_info->filter_out_filter = (gchar *)g_malloc(filter_out_filter_len);

    /* append the negation */
    if(previous_filter_len) {
        g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
        "%s and !(%s)", previous_filter, follow_filter);
    } else {
        g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
        "!(%s)", follow_filter);
    }

    /* data will be passed via tap callback*/
    msg = register_tap_listener("ssl", follow_info, follow_filter, 0,
        NULL, ssl_queue_packet_data, NULL);
    if (msg)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Can't register ssl tap: %s\n",msg->str);
        g_free(follow_info->filter_out_filter);
        g_free(follow_info);
        g_free(follow_filter);
        return;
    }
    gtk_entry_set_text(GTK_ENTRY(filter_te), follow_filter);

    /* Run the display filter so it goes in effect - even if it's the
       same as the previous display filter. */
    main_filter_packets(&cfile, follow_filter, TRUE);

    /* Free the filter string, as we're done with it. */
    g_free(follow_filter);

    remove_tap_listener(follow_info);

    /* Stream to show */
    follow_stats(&stats);

    if (stats.is_ipv6) {
        struct e_in6_addr ipaddr;
        memcpy(&ipaddr, stats.ip_address[0], 16);
        hostname0 = get_hostname6(&ipaddr);
        memcpy(&ipaddr, stats.ip_address[1], 16);
        hostname1 = get_hostname6(&ipaddr);
    } else {
        guint32 ipaddr;
        memcpy(&ipaddr, stats.ip_address[0], 4);
        hostname0 = get_hostname(ipaddr);
        memcpy(&ipaddr, stats.ip_address[1], 4);
        hostname1 = get_hostname(ipaddr);
    }

    port0 = ep_tcp_port_to_display(stats.port[0]);
    port1 = ep_tcp_port_to_display(stats.port[1]);

    follow_info->is_ipv6 = stats.is_ipv6;

    /* Generate the strings for the follow stream dialog's combo box,
       starting with both directions... */
    both_directions_string = g_strdup_printf("Entire conversation (%u bytes)", follow_info->bytes_written[0] + follow_info->bytes_written[1]);

    /* ...and then the server-to-client and client-to-server directions. */
    if ((follow_info->client_port == stats.port[0]) &&
        ((stats.is_ipv6 && (memcmp(follow_info->client_ip.data, stats.ip_address[0], 16) == 0)) ||
         (!stats.is_ipv6 && (memcmp(follow_info->client_ip.data, stats.ip_address[0], 4) == 0)))) {
        server_hostname = hostname0;
        server_port = port0;
        client_hostname = hostname1;
        client_port = port1;
    } else {
        server_hostname = hostname1;
        server_port = port1;
        client_hostname = hostname0;
        client_port = port0;
    }

    single_direction_format = "%s:%s " UTF8_RIGHTWARDS_ARROW " %s:%s (%u bytes)";
    server_to_client_string = g_strdup_printf(single_direction_format,
        server_hostname, server_port,
        client_hostname, client_port,
        follow_info->bytes_written[0]);
    client_to_server_string = g_strdup_printf(single_direction_format,
        client_hostname, client_port,
        server_hostname, server_port,
        follow_info->bytes_written[1]);

    /* Invoke the dialog. */
    follow_stream("Follow SSL Stream", follow_info, both_directions_string,
                    server_to_client_string, client_to_server_string);

    g_free(both_directions_string);
    g_free(server_to_client_string);
    g_free(client_to_server_string);
}

#define FLT_BUF_SIZE 1024

/*
 * XXX - the routine pointed to by "print_line_fcn_p" doesn't get handed lines,
 * it gets handed bufferfuls.  That's fine for "follow_write_raw()"
 * and "follow_add_to_gtk_text()", but, as "follow_print_text()" calls
 * the "print_line()" routine from "print.c", and as that routine might
 * genuinely expect to be handed a line (if, for example, it's using
 * some OS or desktop environment's printing API, and that API expects
 * to be handed lines), "follow_print_text()" should probably accumulate
 * lines in a buffer and hand them "print_line()".  (If there's a
 * complete line in a buffer - i.e., there's nothing of the line in
 * the previous buffer or the next buffer - it can just hand that to
 * "print_line()" after filtering out non-printables, as an
 * optimization.)
 *
 * This might or might not be the reason why C arrays display
 * correctly but get extra blank lines very other line when printed.
 */
frs_return_t
follow_read_ssl_stream(follow_info_t *follow_info,
               gboolean (*print_line_fcn_p)(char *, size_t, gboolean, void *),
               void *arg)
{
    guint32      global_client_pos = 0, global_server_pos = 0;
    guint32      server_packet_count = 0;
    guint32      client_packet_count = 0;
    guint32 *    global_pos;
    GList *      cur;
    frs_return_t frs_return;

    for (cur = follow_info->payload; cur; cur = g_list_next(cur)) {
        SslDecryptedRecord * rec = (SslDecryptedRecord*) cur->data;
        gboolean             include_rec = FALSE;

        if (rec->is_from_server) {
            global_pos = &global_server_pos;
            include_rec = (follow_info->show_stream == BOTH_HOSTS) ||
                (follow_info->show_stream == FROM_SERVER);
        } else {
            global_pos = &global_client_pos;
            include_rec = (follow_info->show_stream == BOTH_HOSTS) ||
                (follow_info->show_stream == FROM_CLIENT);
        }

        if (include_rec) {
            size_t nchars = rec->data.data_len;
            gchar *buffer = (gchar *)g_memdup(rec->data.data, (guint) nchars);

            frs_return = follow_show(follow_info, print_line_fcn_p, buffer, nchars,
                rec->is_from_server, arg, global_pos,
                &server_packet_count, &client_packet_count);
            g_free(buffer);
            if (frs_return == FRS_PRINT_ERROR)
                return frs_return;
        }
    }

    return FRS_OK;
}

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
