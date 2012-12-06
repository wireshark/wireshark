/* sip_stat.c
 * sip_stat   2004 Martin Mathieson
 *
 * $Id$
 * Copied from http_stat.c
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
#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet_info.h>
#include <epan/epan.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-sip.h>

#include "ui/simple_dialog.h"
#include "../globals.h"
#include "../stat_menu.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/tap_param_dlg.h"
#include "ui/gtk/main.h"

#include "ui/gtk/old-gtk-compat.h"

#define SUM_STR_MAX  1024

/* Ino about a table */
typedef struct {
    GtkWidget  *table;
    guint       row_count;
} tbl_info_t;

/* Used to keep track of the statistics for an entire program interface */
typedef struct _sip_stats_t {
    char        *filter;
    GtkWidget   *win;
    GHashTable  *hash_responses;
    GHashTable  *hash_requests;
    guint32      packets;               /* number of sip packets, including continuations */
    guint32      resent_packets;
    guint32      average_setup_time;
    guint32      max_setup_time;
    guint32      min_setup_time;
    guint32      no_of_completed_calls;
    guint64      total_setup_time;
    GtkWidget   *packets_label;
    GtkWidget   *resent_label;
    GtkWidget   *average_setup_time_label;

    GtkWidget   *request_box;    /* container for INVITE, ... */

    tbl_info_t   informational_table_info;   /* Status code between 100 and 199 */
    tbl_info_t   success_table_info;         /*   200 and 299 */
    tbl_info_t   redirection_table_info;     /*   300 and 399 */
    tbl_info_t   client_error_table_info;    /*   400 and 499 */
    tbl_info_t   server_errors_table_info;   /*   500 and 599 */
    tbl_info_t   global_failures_table_info; /*   600 and 699 */
} sipstat_t;

/* Used to keep track of the stats for a specific response code
 * for example it can be { 3, 404, "Not Found" ,...}
 * which means we captured 3 reply sip/1.1 404 Not Found */
typedef struct _sip_response_code_t {
    guint32      packets;               /* 3 */
    guint        response_code;         /* 404 */
    const gchar *name;                  /* "Not Found" */
    GtkWidget   *widget;                /* Label where we display it */
    tbl_info_t  *table_info;            /* Info about table in which we put it,
                                           e.g. client_error_table_info */
    sipstat_t   *sp;                    /* Pointer back to main struct */
} sip_response_code_t;

/* Used to keep track of the stats for a specific request string */
typedef struct _sip_request_method_t {
    gchar       *response;              /* eg. : INVITE */
    guint32      packets;
    GtkWidget   *widget;
    sipstat_t   *sp;                    /* Pointer back to main struct */
} sip_request_method_t;

/* TODO: extra codes to be added from SIP extensions? */
static const value_string vals_status_code[] = {
    { 100, "Trying"},
    { 180, "Ringing"},
    { 181, "Call Is Being Forwarded"},
    { 182, "Queued"},
    { 183, "Session Progress"},
    { 199, "Informational - Others" },

    { 200, "OK"},
    { 202, "Accepted"},
    { 204, "No Notification"},
    { 299, "Success - Others"}, /* used to keep track of other Success packets */

    { 300, "Multiple Choices"},
    { 301, "Moved Permanently"},
    { 302, "Moved Temporarily"},
    { 305, "Use Proxy"},
    { 380, "Alternative Service"},
    { 399, "Redirection - Others"},

    { 400, "Bad Request"},
    { 401, "Unauthorized"},
    { 402, "Payment Required"},
    { 403, "Forbidden"},
    { 404, "Not Found"},
    { 405, "Method Not Allowed"},
    { 406, "Not Acceptable"},
    { 407, "Proxy Authentication Required"},
    { 408, "Request Timeout"},
    { 410, "Gone"},
    { 412, "Conditional Request Failed"},
    { 413, "Request Entity Too Large"},
    { 414, "Request-URI Too Long"},
    { 415, "Unsupported Media Type"},
    { 416, "Unsupported URI Scheme"},
    { 420, "Bad Extension"},
    { 421, "Extension Required"},
    { 422, "Session Timer Too Small"},
    { 423, "Interval Too Brief"},
    { 428, "Use Identity Header"},
    { 429, "Provide Referrer Identity"},
    { 430, "Flow Failed"},
    { 433, "Anonymity Disallowed"},
    { 436, "Bad Identity-Info"},
    { 437, "Unsupported Certificate"},
    { 438, "Invalid Identity Header"},
    { 439, "First Hop Lacks Outbound Support"},
    { 440, "Max-Breadth Exceeded"},
    { 470, "Consent Needed"},
    { 480, "Temporarily Unavailable"},
    { 481, "Call/Transaction Does Not Exist"},
    { 482, "Loop Detected"},
    { 483, "Too Many Hops"},
    { 484, "Address Incomplete"},
    { 485, "Ambiguous"},
    { 486, "Busy Here"},
    { 487, "Request Terminated"},
    { 488, "Not Acceptable Here"},
    { 489, "Bad Event"},
    { 491, "Request Pending"},
    { 493, "Undecipherable"},
    { 494, "Security Agreement Required"},
    { 499, "Client Error - Others"},

    { 500, "Server Internal Error"},
    { 501, "Not Implemented"},
    { 502, "Bad Gateway"},
    { 503, "Service Unavailable"},
    { 504, "Server Time-out"},
    { 505, "Version Not Supported"},
    { 513, "Message Too Large"},
    { 599, "Server Error - Others"},

    { 600, "Busy Everywhere"},
    { 603, "Decline"},
    { 604, "Does Not Exist Anywhere"},
    { 606, "Not Acceptable"},
    { 699, "Global Failure - Others"},

    { 0, NULL}
};

void register_tap_listener_gtksipstat(void);


/* Create tables for responses and requests */
static void
sip_init_hash(sipstat_t *sp)
{
    int i;

    /* Create responses table */
    sp->hash_responses = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

    /* Add all response codes */
    for (i=0; vals_status_code[i].strptr; i++)
    {
        sip_response_code_t *sc  = g_malloc(sizeof(sip_response_code_t));

        sc->packets       = 0;
        sc->response_code = vals_status_code[i].value;
        sc->name          = vals_status_code[i].strptr;
        sc->widget        = NULL;
        sc->table_info    = NULL;
        sc->sp            = sp;
        g_hash_table_insert(sc->sp->hash_responses, GUINT_TO_POINTER(vals_status_code[i].value), sc);
    }

    /* Create empty requests table */
    sp->hash_requests = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

/* Draw the entry for an individual request message */
static void
sip_draw_hash_requests(gchar *key _U_, sip_request_method_t *data, gchar *unused _U_)
{
    gchar string_buff[SUM_STR_MAX];

    g_assert(data != NULL);

    if (data->packets == 0)
    {
        return;
    }

    /* Build string showing method and count */
    g_snprintf(string_buff, sizeof(string_buff),
               "     %-11s : %3d packets", data->response, data->packets);
    if (data->widget == NULL)
    {
        /* Create new label */
        data->widget = gtk_label_new(string_buff);
        gtk_misc_set_alignment(GTK_MISC(data->widget), 0.0f, 0.5f);
        gtk_box_pack_start(GTK_BOX(data->sp->request_box), data->widget, FALSE, FALSE, 0);
        gtk_widget_show(data->widget);
    }
    else
    {
        /* Update existing label */
         gtk_label_set_text(GTK_LABEL(data->widget), string_buff);
    }
}

/* Draw an individual response entry */
static void
sip_draw_hash_responses(gint *key _U_ , sip_response_code_t *data, gchar *unused _U_)
{
    gchar string_buff[SUM_STR_MAX];

    g_assert(data != NULL);

    if (data->packets == 0)
    {
        return;
    }

    /* Create an entry in the relevant box of the window */
    if (data->widget == NULL)
    {
        guint      x;
        GtkWidget *tmp;
        guint      i = data->response_code;

        /* Out of valid range - ignore */
        if ((i < 100) || (i >= 700))
        {
            return;
        }

        /* Find the table matching the code */
        if (i < 200)
        {
            data->table_info = &(data->sp->informational_table_info);
        }
        else if (i < 300)
        {
            data->table_info = &(data->sp->success_table_info);
        }
        else if (i < 400)
        {
            data->table_info = &(data->sp->redirection_table_info);
        }
        else if (i < 500)
        {
            data->table_info = &(data->sp->client_error_table_info);
        }
        else if (i < 600)
        {
            data->table_info = &(data->sp->server_errors_table_info);
        }
        else
        {
            data->table_info = &(data->sp->global_failures_table_info);
        }

        /* Get number of rows in table */
        x = data->table_info->row_count;

        /* Create a new label with this response, e.g. "SIP 180 Ringing" */
        g_snprintf(string_buff, sizeof(string_buff),
                   "SIP %3d %s ", data->response_code, data->name);
        tmp = gtk_label_new(string_buff);

        /* Insert the label in the correct place in the table */
        gtk_table_attach_defaults(GTK_TABLE(data->table_info->table), tmp,  0, 1, x, x+1);
        gtk_label_set_justify(GTK_LABEL(tmp), GTK_JUSTIFY_LEFT);
        gtk_widget_show(tmp);

        /* Show number of packets */
        g_snprintf(string_buff, sizeof(string_buff), "%9d", data->packets);
        data->widget = gtk_label_new(string_buff);

        /* Show this widget in the right place */
        gtk_table_attach_defaults(GTK_TABLE(data->table_info->table), data->widget, 1, 2, x, x+1);
        gtk_label_set_justify(GTK_LABEL(data->widget), GTK_JUSTIFY_RIGHT);
        gtk_widget_show(data->widget);

        data->table_info->row_count += 1;
    } else
    {
        /* Just update the existing label string */
        g_snprintf(string_buff, sizeof(string_buff), "%9d", data->packets);
        gtk_label_set_text(GTK_LABEL(data->widget), string_buff);
    }
}

static void
sip_reset_hash_responses(gchar *key _U_, sip_response_code_t *data, gpointer ptr _U_)
{
    data->packets = 0;
}

static void
sip_reset_hash_requests(gchar *key _U_ , sip_request_method_t *data, gpointer ptr _U_)
{
    data->packets = 0;
}

static void
sipstat_reset(void *psp)
{
    sipstat_t *sp = psp;
    if (sp)
    {
        sp->packets               = 0;
        sp->resent_packets        = 0;
        sp->average_setup_time    = 0;
        sp->max_setup_time        = 0;
        sp->max_setup_time        = 0;
        sp->no_of_completed_calls = 0;
        sp->total_setup_time      = 0;
        g_hash_table_foreach(sp->hash_responses, (GHFunc)sip_reset_hash_responses, NULL);
        g_hash_table_foreach(sp->hash_requests,  (GHFunc)sip_reset_hash_requests,  NULL);
    }
}

/* Main entry point to SIP tap */
static int
sipstat_packet(void *psp, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pri)
{
    const sip_info_value_t *value = pri;
    sipstat_t *sp = (sipstat_t *)psp;

    /* Total number of packets, including continuation packets */
    sp->packets++;

    /* Update resent count if flag set */
    if (value->resend)
    {
        sp->resent_packets++;
    }

    /* Calculate average setup time */
    if (value->setup_time)
    {
        sp->no_of_completed_calls++;
        /* Check if it's the first value */
        if ( sp->total_setup_time == 0 )
        {
            sp->average_setup_time = value->setup_time;
            sp->total_setup_time   = value->setup_time;
            sp->max_setup_time     = value->setup_time;
            sp->min_setup_time     = value->setup_time;
        } else
        {
            sp->total_setup_time = sp->total_setup_time + value->setup_time;
            if (sp->max_setup_time < value->setup_time)
            {
                sp->max_setup_time = value->setup_time;
            }
            if (sp->min_setup_time > value->setup_time)
            {
                sp->min_setup_time = value->setup_time;
            }
            /* Calculate average */
            sp->average_setup_time = (guint32)(sp->total_setup_time / sp->no_of_completed_calls);
        }
    }

    /* Looking at both requests and responses */
    if (value->response_code != 0)
    {
        /* Responses */
        sip_response_code_t *sc;

        /* Look up response code in hash table */
        sc = g_hash_table_lookup(sp->hash_responses, GUINT_TO_POINTER(value->response_code));
        if (sc == NULL)
        {
            /* Non-standard status code; we classify it as others
             * in the relevant category
             * (Informational, Success, Redirection, Client Error, Server Error, Global Failure)
             */
            guint key;
            guint i = value->response_code;


            if ((i < 100) || (i >= 700))
            {
                /* Forget about crazy values */
                return 0;
            }
            else if (i < 200)
            {
                key = 199;      /* Hopefully, this status code will never be used */
            }
            else if (i < 300)
            {
                key = 299;
            }
            else if (i < 400)
            {
                key = 399;
            }
            else if (i < 500)
            {
                key = 499;
            }
            else if (i < 600)
            {
                key = 599;
            }
            else
            {
                key = 699;
            }

            /* Now look up this fallback code to get its text description */
            sc = g_hash_table_lookup(sp->hash_responses, GUINT_TO_POINTER(key));
            if (sc == NULL)
            {
                return 0;
            }
        }
        sc->packets++;
    }
    else if (value->request_method)
    {
        /* Requests */
        sip_request_method_t *sc;

        /* Look up the request method in the table */
        sc = g_hash_table_lookup(sp->hash_requests, value->request_method);
        if (sc == NULL)
        {
            /* First of this type. Create structure and initialise */
            sc = g_malloc(sizeof(sip_request_method_t));
            sc->response = g_strdup(value->request_method);
            sc->packets  = 1;
            sc->widget   = NULL;
            sc->sp       = sp;
            /* Insert it into request table */
            g_hash_table_insert(sp->hash_requests, sc->response, sc);
        }
        else
        {
            /* Already existed, just update count for that method */
            sc->packets++;
        }
        /* g_free(value->request_method); */
    }
    else
    {
        /* No request method set. Just ignore */
        return 0;
    }

    return 1;
}

/* Redraw the whole stats window */
static void
sipstat_draw(void *psp)
{
    gchar      string_buff[SUM_STR_MAX];
    sipstat_t *sp = psp;

    /* Set summary label */
    g_snprintf(string_buff, sizeof(string_buff),
                "SIP stats (%d packets)", sp->packets);
    gtk_label_set_text(GTK_LABEL(sp->packets_label), string_buff);

    /* Set resend count label */
    g_snprintf(string_buff, sizeof(string_buff),
                "(%d resent packets)", sp->resent_packets);
    gtk_label_set_text(GTK_LABEL(sp->resent_label), string_buff);

    /* Draw responses and requests from their tables */
    g_hash_table_foreach(sp->hash_responses, (GHFunc)sip_draw_hash_responses, NULL);
    g_hash_table_foreach(sp->hash_requests,  (GHFunc)sip_draw_hash_requests,  NULL);

    /* Set resend count label */
    g_snprintf(string_buff, sizeof(string_buff),
               "Average setup time %d ms\n Min %d ms\n Max %d ms",
               sp->average_setup_time, sp->min_setup_time, sp->max_setup_time);
    gtk_label_set_text(GTK_LABEL(sp->average_setup_time_label), string_buff);

    gtk_widget_show_all(sp->win);
}

/* When window is destroyed, clean up */

static void
win_destroy_cb(GtkWindow *win _U_, gpointer data)
{
    sipstat_t *sp = (sipstat_t *)data;

    remove_tap_listener(sp);

    g_hash_table_destroy(sp->hash_responses);
    g_hash_table_destroy(sp->hash_requests);
    g_free(sp->filter);
    g_free(sp);
}


static void
init_table(GtkWidget *main_vb, gchar *title, tbl_info_t *tbl_info)
{
    GtkWidget *fr;

    fr = gtk_frame_new(title);
    gtk_box_pack_start(GTK_BOX(main_vb), fr, TRUE, TRUE, 0);

    /* table (within that frame) */
    (*tbl_info).table = gtk_table_new(0, 2, FALSE);
    gtk_container_add(GTK_CONTAINER(fr), (*tbl_info).table);
    (*tbl_info).row_count = 0;
}

/* Create a new instance of gtk_sipstat. */
static void
gtk_sipstat_init(const char *opt_arg, void *userdata _U_)
{
    sipstat_t  *sp;
    const char *filter;
    GString    *error_string;
    char       *title;
    GtkWidget  *main_vb, *separator, *request_fr;
    GtkWidget  *bt_close;
    GtkWidget  *bbox;


    if (strncmp(opt_arg, "sip,stat,", 9) == 0)
    {
        /* Skip those characters from filter to display */
        filter = opt_arg + 9;
    }
    else
    {
        /* No filter */
        filter = NULL;
    }

    /* Create sip stats window structure */
    sp = g_malloc(sizeof(sipstat_t));
    sp->win = dlg_window_new("sip-stat");  /* transient_for top_level */
    gtk_window_set_destroy_with_parent(GTK_WINDOW(sp->win), TRUE);

    /* Set title to include any filter given */
    if (filter)
    {
        sp->filter = g_strdup(filter);
        title = g_strdup_printf("SIP statistics with filter: %s", filter);
    }
    else
    {
        sp->filter = NULL;
        title = g_strdup("SIP statistics");
    }

    gtk_window_set_title(GTK_WINDOW(sp->win), title);
    g_free(title);


    /* Create container for all widgets */
    main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 12, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(main_vb), 12);
    gtk_container_add(GTK_CONTAINER(sp->win), main_vb);

    /* Initialise & show number of packets */
    sp->packets = 0;
    sp->packets_label = gtk_label_new("SIP stats (0 SIP packets)");
    gtk_box_pack_start(GTK_BOX(main_vb), sp->packets_label, TRUE, TRUE, 0);

    sp->resent_packets = 0;
    sp->resent_label = gtk_label_new("(0 resent packets)");
    gtk_box_pack_start(GTK_BOX(main_vb), sp->resent_label, TRUE, TRUE, 0);
    gtk_widget_show(sp->resent_label);

    init_table(main_vb, "Informational   SIP 1xx", &(sp->informational_table_info));
    init_table(main_vb, "Success         SIP 2xx", &(sp->success_table_info));
    init_table(main_vb, "Redirection     SIP 3xx", &(sp->redirection_table_info));
    init_table(main_vb, "Client errors   SIP 4xx", &(sp->client_error_table_info));
    init_table(main_vb, "Server errors   SIP 5xx", &(sp->server_errors_table_info));
    init_table(main_vb, "Global failures SIP 6xx", &(sp->global_failures_table_info));

    /* Separator between requests and responses */
    separator = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(main_vb), separator, TRUE, TRUE, 0);

    /* Request table and frame */
    request_fr = gtk_frame_new("List of request methods");
    gtk_box_pack_start(GTK_BOX(main_vb), request_fr, TRUE, TRUE, 0);
    gtk_container_set_border_width(GTK_CONTAINER(request_fr), 0);

    sp->request_box = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 10, FALSE);
    gtk_container_add(GTK_CONTAINER(request_fr), sp->request_box);

    sp->average_setup_time = 0;
    sp->max_setup_time =0;
    sp->min_setup_time =0;
    sp->average_setup_time_label = gtk_label_new("(Not calculated)");
    gtk_box_pack_start(GTK_BOX(main_vb), sp->average_setup_time_label, TRUE, TRUE, 0);
    gtk_widget_show(sp->average_setup_time_label);


    /* Register this tap listener now */
    error_string = register_tap_listener("sip",
                                         sp,
                                         filter,
                                         0,
                                         sipstat_reset,
                                         sipstat_packet,
                                         sipstat_draw);
    if (error_string)
    {
        /* Error.  We failed to attach to the tap. Clean up */
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
        g_free(sp->filter);
        g_free(sp);
        g_string_free(error_string, TRUE);
        return;
    }

    /* Button row. */
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
    gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

    bt_close = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
    window_set_cancel_button(sp->win, bt_close, window_cancel_button_cb);

    g_signal_connect(sp->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(sp->win, "destroy", G_CALLBACK(win_destroy_cb), sp);

    /* Display up-to-date contents */
    gtk_widget_show_all(sp->win);
    window_present(sp->win);

    sip_init_hash(sp);
    cf_retap_packets(&cfile);
    gdk_window_raise(gtk_widget_get_window(sp->win));
}

static tap_param sip_stat_params[] = {
    { PARAM_FILTER, "Filter", NULL }
};

static tap_param_dlg sip_stat_dlg = {
    "SIP Packet Counter",
    "sip,stat",
    gtk_sipstat_init,
    -1,
    G_N_ELEMENTS(sip_stat_params),
    sip_stat_params
};

/* Register this tap listener and add menu item. */
void
register_tap_listener_gtksipstat(void)
{
    register_dfilter_stat(&sip_stat_dlg, "_SIP", REGISTER_STAT_GROUP_TELEPHONY);
}

void
sipstat_cb(GtkAction *action, gpointer user_data _U_)
{
    tap_param_dlg_cb(action, &sip_stat_dlg);
}

