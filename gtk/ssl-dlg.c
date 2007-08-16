/* ssl_dlg.c
 *
 * $Id$
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

#include "config.h"

#include <gtk/gtk.h>

#include <stdio.h>
#include <string.h>


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <ctype.h>

#include <color.h>
#include <gtk/colors.h>
#include <gtk/main.h>
#include <epan/follow.h>
#include <gtk/dlg_utils.h>
#include <gtk/file_dlg.h>
#include <gtk/keys.h>
#include <globals.h>
#include <alert_box.h>
#include <simple_dialog.h>
#include <epan/dissectors/packet-ipv6.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/charsets.h>
#include <util.h>
#include <gtk/gui_utils.h>
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include <gtk/compat_macros.h>
#include <epan/ipproto.h>
#include <gtk/font_utils.h>
#include <wiretap/file_util.h>
#include <epan/tap.h>

#ifdef SSL_PLUGIN
#include "packet-ssl-utils.h"
#else
#include <epan/dissectors/packet-ssl-utils.h>
#endif

#include "ssl-dlg.h"

#include "follow_stream.h"

static void follow_destroy_cb(GtkWidget * win, gpointer data);

typedef struct {
    gboolean is_server;
    StringInfo data;
} SslDecryptedRecord;

static int
ssl_queue_packet_data(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *ssl)
{
    follow_info_t* follow_info = tapdata;
    SslDecryptedRecord* rec;
    SslDataInfo* appl_data;
    gint total_len;
    guchar *p;
    int proto_ssl = (long) ssl;
    SslPacketInfo* pi = p_get_proto_data(pinfo->fd, proto_ssl);

    /* skip packet without decrypted data payload*/    
    if (!pi || !pi->appl_data)
        return 0;

    /* compute total length */
    total_len = 0;
    appl_data = pi->appl_data;
    do {
      total_len += appl_data->plain_data.data_len; 
      appl_data = appl_data->next;
    } while (appl_data);
    
    /* compute packet direction */
    rec = g_malloc(sizeof(SslDecryptedRecord) + total_len);

    if (follow_info->client_port == 0) {
        follow_info->client_port = pinfo->srcport;
        memcpy(follow_info->client_ip, pinfo->src.data, pinfo->src.len);
    }
    if (memcmp(follow_info->client_ip, pinfo->src.data, pinfo->src.len) == 0 &&
        follow_info->client_port == pinfo->srcport) {
        rec->is_server = 0;
    }
    else 
        rec->is_server = 1;

    /* update stream counter */
    follow_info->bytes_written[rec->is_server] += total_len;
    
    /* extract decrypted data and queue it locally */    
    rec->data.data = (guchar*)(rec + 1);
    rec->data.data_len = total_len;
    appl_data = pi->appl_data;
    p = rec->data.data;
    do {
      memcpy(p, appl_data->plain_data.data, appl_data->plain_data.data_len);
      p += appl_data->plain_data.data_len; 
      appl_data = appl_data->next;
    } while (appl_data);
    follow_info->ssl_decrypted_data = g_list_append(
        follow_info->ssl_decrypted_data,rec);

    return 0;
}

extern int 
packet_is_ssl(epan_dissect_t* edt);


/* Follow the SSL stream, if any, to which the last packet that we called
   a dissection routine on belongs (this might be the most recently
   selected packet, or it might be the last packet in the file). */
void
ssl_stream_cb(GtkWidget * w, gpointer data _U_)
{
    GtkWidget	*streamwindow, *vbox, *txt_scrollw, *text, *filter_te;
    GtkWidget	*hbox, *button_hbox, *button, *radio_bt;
    GtkWidget   *stream_fr, *stream_vb;
    GtkWidget	*stream_om, *stream_menu, *stream_mi;
    GtkTooltips *tooltips;
    gchar		*follow_filter;
    const gchar	*previous_filter;
    int		    filter_out_filter_len, previus_filter_len;
    const char	*hostname0, *hostname1;
    char		*port0, *port1;
    char		string[128];
    follow_tcp_stats_t stats;
    follow_info_t	*follow_info;
    GString* msg;

    /* we got ssl so we can follow */
    if (!packet_is_ssl(cfile.edt)) {
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
    follow_filter = build_follow_filter(&cfile.edt->pi);
    if (!follow_filter)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                      "Error creating filter for this stream.\n"
                      "A network layer header is needed");
        return;
    }

    /* Set the display filter entry accordingly */
    filter_te = OBJECT_GET_DATA(w, E_DFILTER_TE_KEY);

    /* needed in follow_filter_out_stream(), is there a better way? */
    follow_info->filter_te = filter_te;

    /* save previous filter, const since we're not supposed to alter */
    previous_filter =
        (const gchar *)gtk_entry_get_text(GTK_ENTRY(filter_te));

    /* allocate our new filter. API claims g_malloc terminates program on failure */
    /* my calc for max alloc needed is really +10 but when did a few extra bytes hurt ? */
    previus_filter_len = previous_filter?strlen(previous_filter):0;
    filter_out_filter_len = strlen(follow_filter) + previus_filter_len + 16;
    follow_info->filter_out_filter = (gchar *)g_malloc(filter_out_filter_len);

    /* append the negation */
    if(previus_filter_len) {
        g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
        "%s and !(%s)", previous_filter, follow_filter);
    } else {
        g_snprintf(follow_info->filter_out_filter, filter_out_filter_len,
        "!(%s)", follow_filter);
    }

    /* data will be passed via tap callback*/
    msg = register_tap_listener("ssl", follow_info, follow_filter,
	NULL, ssl_queue_packet_data, NULL);
    if (msg)
    {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
            "Can't register ssl tap: %s\n",msg->str);
        return;
    }
    gtk_entry_set_text(GTK_ENTRY(filter_te), follow_filter);

    /* Run the display filter so it goes in effect - even if it's the
       same as the previous display filter. */
    main_filter_packets(&cfile, follow_filter, TRUE);

    /* Free the filter string, as we're done with it. */
    g_free(follow_filter);

    /* The data_out_file should now be full of the streams information */
    remove_tap_listener(follow_info);

    /* The data_out_filename file now has all the text that was in the session */
    streamwindow = dlg_window_new("Follow SSL Stream");

    /* needed in follow_filter_out_stream(), is there a better way? */
    follow_info->streamwindow = streamwindow;

    gtk_widget_set_name(streamwindow, "SSL stream window");
    gtk_window_set_default_size(GTK_WINDOW(streamwindow), DEF_WIDTH, DEF_HEIGHT);
    gtk_container_border_width(GTK_CONTAINER(streamwindow), 6);

    /* setup the container */
    tooltips = gtk_tooltips_new ();

    vbox = gtk_vbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(streamwindow), vbox);

    /* content frame */
    if (incomplete_tcp_stream) {
            stream_fr = gtk_frame_new("Stream Content (incomplete)");
    } else {
            stream_fr = gtk_frame_new("Stream Content");
    }
    gtk_container_add(GTK_CONTAINER(vbox), stream_fr);
    gtk_widget_show(stream_fr);

    stream_vb = gtk_vbox_new(FALSE, 6);
    gtk_container_set_border_width( GTK_CONTAINER(stream_vb) , 6);
    gtk_container_add(GTK_CONTAINER(stream_fr), stream_vb);

    /* create a scrolled window for the text */
    txt_scrollw = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw),
                                        GTK_SHADOW_IN);
#endif
    gtk_box_pack_start(GTK_BOX(stream_vb), txt_scrollw, TRUE, TRUE, 0);

    /* create a text box */
#if GTK_MAJOR_VERSION < 2
    text = gtk_text_new(NULL, NULL);
    gtk_text_set_editable(GTK_TEXT(text), FALSE);
#else
    text = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
#endif
    gtk_container_add(GTK_CONTAINER(txt_scrollw), text);
    follow_info->text = text;


    /* stream hbox */
    hbox = gtk_hbox_new(FALSE, 1);
    gtk_box_pack_start(GTK_BOX(stream_vb), hbox, FALSE, FALSE, 0);

#if GTK_CHECK_VERSION(2,4,0)
	/* Create Find Button */
	button = BUTTON_NEW_FROM_STOCK(GTK_STOCK_FIND);
	SIGNAL_CONNECT(button, "clicked", follow_find_cb, follow_info);
	gtk_tooltips_set_tip (tooltips, button, "Find text in the displayed content", NULL);
	gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);
#endif

    /* Create Save As Button */
    button = BUTTON_NEW_FROM_STOCK(GTK_STOCK_SAVE_AS);
    SIGNAL_CONNECT(button, "clicked", follow_save_as_cmd_cb, follow_info);
    gtk_tooltips_set_tip (tooltips, button, "Save the content as currently displayed ", NULL);
    gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);

    /* Stream to show */
    follow_tcp_stats(&stats);

    if (stats.is_ipv6) {
      struct e_in6_addr ipaddr;
      memcpy(&ipaddr, stats.ip_address[0], 16);
      hostname0 = get_hostname6(&ipaddr);
      memcpy(&ipaddr, stats.ip_address[0], 16);
      hostname1 = get_hostname6(&ipaddr);
    } else {
      guint32 ipaddr;
      memcpy(&ipaddr, stats.ip_address[0], 4);
      hostname0 = get_hostname(ipaddr);
      memcpy(&ipaddr, stats.ip_address[1], 4);
      hostname1 = get_hostname(ipaddr);
    }

    port0 = get_tcp_port(stats.tcp_port[0]);
    port1 = get_tcp_port(stats.tcp_port[1]);

    follow_info->is_ipv6 = stats.is_ipv6;

    stream_om = gtk_option_menu_new();
    stream_menu = gtk_menu_new();

    /* Both Stream Directions */
    g_snprintf(string, sizeof(string),
             "Entire conversation (%u bytes)",
             follow_info->bytes_written[0] + follow_info->bytes_written[1]);
    stream_mi = gtk_menu_item_new_with_label(string);
    SIGNAL_CONNECT(stream_mi, "activate", follow_stream_om_both,
                   follow_info);
    gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
    gtk_widget_show(stream_mi);
    follow_info->show_stream = BOTH_HOSTS;

    /* Host 0 --> Host 1 */
    g_snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
             hostname0, port0, hostname1, port1,
             follow_info->bytes_written[0]);
    stream_mi = gtk_menu_item_new_with_label(string);
    SIGNAL_CONNECT(stream_mi, "activate", follow_stream_om_client,
                   follow_info);
    gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
    gtk_widget_show(stream_mi);

    /* Host 1 --> Host 0 */
    g_snprintf(string, sizeof(string), "%s:%s --> %s:%s (%u bytes)",
             hostname1, port1, hostname0, port0,
             follow_info->bytes_written[1]);
    stream_mi = gtk_menu_item_new_with_label(string);
    SIGNAL_CONNECT(stream_mi, "activate", follow_stream_om_server,
                   follow_info);
    gtk_menu_append(GTK_MENU(stream_menu), stream_mi);
    gtk_widget_show(stream_mi);

    gtk_option_menu_set_menu(GTK_OPTION_MENU(stream_om), stream_menu);
    /* Set history to 0th item, i.e., the first item. */
    gtk_option_menu_set_history(GTK_OPTION_MENU(stream_om), 0);
    gtk_tooltips_set_tip (tooltips, stream_om,
        "Select the stream direction to display", NULL);
    gtk_box_pack_start(GTK_BOX(hbox), stream_om, FALSE, FALSE, 0);

    /* ASCII radio button */
    radio_bt = gtk_radio_button_new_with_label(NULL, "ASCII");
    gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"ASCII\" format", NULL);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), TRUE);
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
    SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                   follow_info);
    follow_info->ascii_bt = radio_bt;
    follow_info->show_type = SHOW_ASCII;

    /* HEX DUMP radio button */
    radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
                                        (GTK_RADIO_BUTTON(radio_bt)),
                                        "Hex Dump");
    gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"Hexdump\" format", NULL);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
    SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                   follow_info);
    follow_info->hexdump_bt = radio_bt;

    /* C Array radio button */
    radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
                                        (GTK_RADIO_BUTTON(radio_bt)),
                                        "C Arrays");
    gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"C Array\" format", NULL);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
    SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                   follow_info);
    follow_info->carray_bt = radio_bt;

    /* Raw radio button */
    radio_bt = gtk_radio_button_new_with_label(gtk_radio_button_group
                                        (GTK_RADIO_BUTTON(radio_bt)),
                                        "Raw");
    gtk_tooltips_set_tip (tooltips, radio_bt, "Stream data output in \"Raw\" (binary) format. "
    "As this contains non printable characters, the screen output will be in ASCII format", NULL);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_bt), FALSE);
    gtk_box_pack_start(GTK_BOX(hbox), radio_bt, FALSE, FALSE, 0);
    SIGNAL_CONNECT(radio_bt, "toggled", follow_charset_toggle_cb,
                   follow_info);
    follow_info->raw_bt = radio_bt;

    /* button hbox */
    button_hbox = gtk_hbutton_box_new();
    gtk_box_pack_start(GTK_BOX(vbox), button_hbox, FALSE, FALSE, 0);
    gtk_button_box_set_layout (GTK_BUTTON_BOX(button_hbox), GTK_BUTTONBOX_END);
    gtk_button_box_set_spacing(GTK_BUTTON_BOX(button_hbox), 5);

    /* Create exclude stream button */
    button = gtk_button_new_with_label("Filter Out This Stream");
    SIGNAL_CONNECT(button, "clicked", follow_filter_out_stream, follow_info);
    gtk_tooltips_set_tip (tooltips, button,
    "Build a display filter which cuts this stream from the capture", NULL);
    gtk_box_pack_start(GTK_BOX(button_hbox), button, FALSE, FALSE, 0);

    /* Create Close Button */
    button = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
    gtk_tooltips_set_tip (tooltips, button,
        "Close the dialog and keep the current display filter", NULL);
    gtk_box_pack_start(GTK_BOX(button_hbox), button, FALSE, FALSE, 0);
    GTK_WIDGET_SET_FLAGS(button, GTK_CAN_DEFAULT);

    window_set_cancel_button(streamwindow, button, window_cancel_button_cb);

    /* Tuck away the follow_info object into the window */
    OBJECT_SET_DATA(streamwindow, E_FOLLOW_INFO_KEY, follow_info);

    follow_load_text(follow_info);
    remember_follow_info(follow_info);

    SIGNAL_CONNECT(streamwindow, "delete_event", window_delete_event_cb, NULL);
    SIGNAL_CONNECT(streamwindow, "destroy", follow_destroy_cb, NULL);

    /* Make sure this widget gets destroyed if we quit the main loop,
       so that if we exit, we clean up any temporary files we have
       for "Follow SSL Stream" windows. */
    gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(streamwindow));

    gtk_widget_show_all(streamwindow);
    window_present(streamwindow);
}

/* The destroy call back has the responsibility of
 * unlinking the temporary file
 * and freeing the filter_out_filter */
static void
follow_destroy_cb(GtkWidget *w, gpointer data _U_)
{
    GList* cur;
    follow_info_t	*follow_info;

    follow_info = OBJECT_GET_DATA(w, E_FOLLOW_INFO_KEY);
    g_free(follow_info->filter_out_filter);
    forget_follow_info(follow_info);

    /* free decrypted data list*/
    for (cur = follow_info->ssl_decrypted_data; cur; cur = g_list_next(cur))
        if (cur->data)
        {
            g_free(cur->data);
            cur->data = NULL;
        }
    g_list_free (follow_info->ssl_decrypted_data);
    g_free(follow_info);
}

#define FLT_BUF_SIZE 1024

/*
 * XXX - the routine pointed to by "print_line" doesn't get handed lines,
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
		       gboolean (*print_line)(char *, size_t, gboolean, void *),
		       void *arg)
{
    int			iplen;
    guint32		current_pos, global_client_pos = 0, global_server_pos = 0;
    guint32		*global_pos;
    gboolean		skip;
    gchar               initbuf[256];
    guint32             server_packet_count = 0;
    guint32             client_packet_count = 0;
    static const gchar	hexchars[16] = "0123456789abcdef";
    GList* cur;

    iplen = (follow_info->is_ipv6) ? 16 : 4;
    
    for (cur = follow_info->ssl_decrypted_data; cur; cur = g_list_next(cur)) {
        SslDecryptedRecord* rec = cur->data;
	skip = FALSE;
	if (!rec->is_server) {
	    global_pos = &global_client_pos;
	    if (follow_info->show_stream == FROM_SERVER) {
		skip = TRUE;
	    }
	}
	else {
	    global_pos = &global_server_pos;
	    if (follow_info->show_stream == FROM_CLIENT) {
		skip = TRUE;
	    }
	}

        if (!skip) {
            size_t nchars = rec->data.data_len;
            char* buffer = (char*) rec->data.data;
            
            switch (follow_info->show_type) {
    
	    case SHOW_EBCDIC:
		    /* Not yet implemented in show SSL stream */
		    break;

            case SHOW_ASCII:
                /* If our native arch is EBCDIC, call:
                 * ASCII_TO_EBCDIC(buffer, nchars);
                 */
                if (!(*print_line) (buffer, nchars, rec->is_server, arg))
                    goto print_error;
                break;
    
            case SHOW_RAW:
                /* Don't translate, no matter what the native arch
                 * is.
                 */
                if (!(*print_line) (buffer, nchars, rec->is_server, arg))
                    goto print_error;
                break;
    
            case SHOW_HEXDUMP:
                current_pos = 0;
                while (current_pos < nchars) {
                    gchar hexbuf[256];
                    int i;
                    gchar *cur = hexbuf, *ascii_start;
    
                    /* is_server indentation : put 78 spaces at the
                     * beginning of the string */
                    if (rec->is_server && follow_info->show_stream == BOTH_HOSTS) {
                        memset(cur, ' ', 78);
                        cur += 78;
                    }
                    cur += g_snprintf(cur, 20, "%08X  ", *global_pos);
                    /* 49 is space consumed by hex chars */
                    ascii_start = cur + 49;
                    for (i = 0; i < 16 && current_pos + i < nchars; i++) {
                        *cur++ =
                            hexchars[(buffer[current_pos + i] & 0xf0) >> 4];
                        *cur++ =
                            hexchars[buffer[current_pos + i] & 0x0f];
                        *cur++ = ' ';
                        if (i == 7)
                            *cur++ = ' ';
                    }
                    /* Fill it up if column isn't complete */
                    while (cur < ascii_start)  
                        *cur++ = ' ';
    
                    /* Now dump bytes as text */
                    for (i = 0; i < 16 && current_pos + i < nchars; i++) {
                        *cur++ =
                            (isprint((guchar)buffer[current_pos + i]) ?
                            buffer[current_pos + i] : '.' );
                        if (i == 7) {
                            *cur++ = ' ';
                        }
                    }
                    current_pos += i;
                    (*global_pos) += i;
                    *cur++ = '\n';
                    *cur = 0;
                    if (!(*print_line) (hexbuf, strlen(hexbuf), rec->is_server, arg))
                        goto print_error;
                }
                break;
    
            case SHOW_CARRAY:
                current_pos = 0;
                g_snprintf(initbuf, sizeof(initbuf), "char peer%d_%d[] = {\n", 
                        rec->is_server ? 1 : 0, 
                        rec->is_server ? server_packet_count++ : client_packet_count++);
                if (!(*print_line) (initbuf, strlen(initbuf), rec->is_server, arg))
                    goto print_error;
                while (current_pos < nchars) {
                    gchar hexbuf[256];
                    int i, cur;
    
                    cur = 0;
                    for (i = 0; i < 8 && current_pos + i < nchars; i++) {
                      /* Prepend entries with "0x" */
                      hexbuf[cur++] = '0';
                      hexbuf[cur++] = 'x';
                        hexbuf[cur++] =
                            hexchars[(buffer[current_pos + i] & 0xf0) >> 4];
                        hexbuf[cur++] =
                            hexchars[buffer[current_pos + i] & 0x0f];
    
                        /* Delimit array entries with a comma */
                        if (current_pos + i + 1 < nchars)
                          hexbuf[cur++] = ',';
    
                        hexbuf[cur++] = ' ';
                    }
    
                    /* Terminate the array if we are at the end */
                    if (current_pos + i == nchars) {
                        hexbuf[cur++] = '}';
                        hexbuf[cur++] = ';';
                    }
    
                    current_pos += i;
                    (*global_pos) += i;
                    hexbuf[cur++] = '\n';
                    hexbuf[cur] = 0;
                    if (!(*print_line) (hexbuf, strlen(hexbuf), rec->is_server, arg))
                        goto print_error;
                }
                break;
            }
        }
    }
    return FRS_OK;

print_error:
    return FRS_PRINT_ERROR;
}

