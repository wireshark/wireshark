/* rtp_stream_dlg.c
 * RTP streams summary addition for ethereal
 *
 * $Id: rtp_stream_dlg.c,v 1.2 2003/09/26 02:09:44 guy Exp $
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include "rtp_stream_dlg.h"
#include "rtp_stream.h"
#include "rtp_analysis.h"

#include "globals.h"
#include "epan/filesystem.h"

#include "menu.h"
#include "dlg_utils.h"
#include "ui_util.h"
#include "main.h"
#include "compat_macros.h"

#include <string.h>

extern GtkWidget *main_display_filter_widget;


/****************************************************************************/
/*
 * RTP Payload types
 * Table B.2 / H.225.0
 * Also RFC 1890, and
 *
 *	http://www.iana.org/assignments/rtp-parameters
 */
#define PT_PCMU		0	/* RFC 1890 */
#define PT_1016		1	/* RFC 1890 */
#define PT_G721		2	/* RFC 1890 */
#define PT_GSM		3	/* RFC 1890 */
#define PT_G723		4	/* From Vineet Kumar of Intel; see the Web page */
#define PT_DVI4_8000	5	/* RFC 1890 */
#define PT_DVI4_16000	6	/* RFC 1890 */
#define PT_LPC		7	/* RFC 1890 */
#define PT_PCMA		8	/* RFC 1890 */
#define PT_G722		9	/* RFC 1890 */
#define PT_L16_STEREO	10	/* RFC 1890 */
#define PT_L16_MONO	11	/* RFC 1890 */
#define PT_QCELP	12	/* Qualcomm Code Excited Linear Predictive coding? */
#define PT_CN		13	/* RFC 3389 */
#define PT_MPA		14	/* RFC 1890, RFC 2250 */
#define PT_G728		15	/* RFC 1890 */
#define PT_DVI4_11025	16	/* from Joseph Di Pol of Sun; see the Web page */
#define PT_DVI4_22050	17	/* from Joseph Di Pol of Sun; see the Web page */
#define PT_G729		18
#define PT_CELB		25	/* RFC 2029 */
#define PT_JPEG		26	/* RFC 2435 */
#define PT_NV		28	/* RFC 1890 */
#define PT_H261		31	/* RFC 2032 */
#define PT_MPV		32	/* RFC 2250 */
#define PT_MP2T		33	/* RFC 2250 */
#define PT_H263		34	/* from Chunrong Zhu of Intel; see the Web page */

static const value_string rtp_payload_type_vals[] =
{
	{ PT_PCMU,	"ITU-T G.711 PCMU" },
	{ PT_1016,	"USA Federal Standard FS-1016" },
	{ PT_G721,	"ITU-T G.721" },
	{ PT_GSM,	"GSM 06.10" },
	{ PT_G723,	"ITU-T G.723" },
	{ PT_DVI4_8000,	"DVI4 8000 samples/s" },
	{ PT_DVI4_16000, "DVI4 16000 samples/s" },
	{ PT_LPC,	"Experimental linear predictive encoding from Xerox PARC" },
	{ PT_PCMA,	"ITU-T G.711 PCMA" },
	{ PT_G722,	"ITU-T G.722" },
	{ PT_L16_STEREO, "16-bit uncompressed audio, stereo" },
	{ PT_L16_MONO,	"16-bit uncompressed audio, monaural" },
	{ PT_QCELP,	"Qualcomm Code Excited Linear Predictive coding" },
	{ PT_CN,	"Comfort noise" },
	{ PT_MPA,	"MPEG-I/II Audio"},
	{ PT_G728,	"ITU-T G.728" },
	{ PT_DVI4_11025, "DVI4 11025 samples/s" },
	{ PT_DVI4_22050, "DVI4 22050 samples/s" },
	{ PT_G729,	"ITU-T G.729" },
	{ PT_CELB,	"Sun CellB video encoding" },
	{ PT_JPEG,	"JPEG-compressed video" },
	{ PT_NV,	"'nv' program" },
	{ PT_H261,	"ITU-T H.261" },
	{ PT_MPV,	"MPEG-I/II Video"},
	{ PT_MP2T,	"MPEG-II transport streams"},
	{ PT_H263,	"ITU-T H.263" },
	{ 0,		NULL },
};


typedef const guint8 * ip_addr_p;

static const gchar FWD_LABEL_TEXT[] = "Select a forward stream with left mouse button";
static const gchar REV_LABEL_TEXT[] = "Select a reverse stream with SHIFT + left mouse button";

/****************************************************************************/
/* pointer to the one and only dialog window */
static GtkWidget *rtp_stream_dlg = NULL;

/* save as dialog box */
static GtkWidget *rtpstream_save_dlg = NULL;
static GtkWidget *clist = NULL;
static GtkWidget *label_fwd = NULL;
static GtkWidget *label_rev = NULL;

static rtp_stream_info_t* selected_stream_fwd = NULL;  /* current selection */
static rtp_stream_info_t* selected_stream_rev = NULL;  /* current selection for reversed */
static GList *last_list = NULL;


/****************************************************************************/
/* append a line to clist */
static void add_to_clist(rtp_stream_info_t* strinfo)
{
	gint added_row;
	gchar *data[8];
	gchar field[8][30];

	data[0]=&field[0][0];
	data[1]=&field[1][0];
	data[2]=&field[2][0];
	data[3]=&field[3][0];
	data[4]=&field[4][0];
	data[5]=&field[5][0];
	data[6]=&field[6][0];
	data[7]=&field[7][0];

	g_snprintf(field[0], 20, "%s", ip_to_str((const guint8*)&(strinfo->src_addr)));
	g_snprintf(field[1], 20, "%u", strinfo->src_port);
	g_snprintf(field[2], 20, "%s", ip_to_str((const guint8*)&(strinfo->dest_addr)));
	g_snprintf(field[3], 20, "%u", strinfo->dest_port);
	g_snprintf(field[4], 20, "%u", strinfo->ssrc);
	g_snprintf(field[5], 30, "%s", val_to_str(strinfo->pt, rtp_payload_type_vals,
		"Unknown (%u)"));
	g_snprintf(field[6], 20, "%u", strinfo->npackets);
	/* XXX: Comment field is not used for the moment */
/*	g_snprintf(field[7], 20, "%s", "");*/

	added_row = gtk_clist_append(GTK_CLIST(clist), data);

	/* set data pointer of last row to point to user data for that row */
	gtk_clist_set_row_data(GTK_CLIST(clist), added_row, strinfo);
}

/****************************************************************************/
static void save_stream_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
	/* Note that we no longer have a Save voice info dialog box. */
	rtpstream_save_dlg = NULL;
}

/****************************************************************************/
/* save in a file */
static void save_stream_ok_cb(GtkWidget *ok_bt _U_, gpointer user_data _U_)
{
	gchar *g_dest;

	if (!selected_stream_fwd)
		return;

	g_dest = g_strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION (rtpstream_save_dlg)));

	/* Perhaps the user specified a directory instead of a file.
	Check whether they did. */
	if (test_for_directory(g_dest) == EISDIR) {
		/* It's a directory - set the file selection box to display it. */
		set_last_open_dir(g_dest);
		g_free(g_dest);
		gtk_file_selection_set_filename(GTK_FILE_SELECTION(rtpstream_save_dlg), last_open_dir);
		return;
	}

	rtpstream_save(selected_stream_fwd, g_dest);

	gtk_widget_destroy(GTK_WIDGET(rtpstream_save_dlg));
}


/****************************************************************************/
/* CALLBACKS                                                                */
/****************************************************************************/
static void
rtpstream_on_destroy                      (GtkObject       *object _U_,
                                        gpointer         user_data _U_)
{
	/* Is there a save voice window open? */
	if (rtpstream_save_dlg != NULL)
		gtk_widget_destroy(rtpstream_save_dlg);

	/* Note that we no longer have a "RTP Analyse" dialog box. */
	rtp_stream_dlg = NULL;
}


/****************************************************************************/
static void
rtpstream_on_unselect                  (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	selected_stream_fwd = NULL;
	selected_stream_rev = NULL;
	gtk_clist_unselect_all(GTK_CLIST(clist));
	gtk_label_set_text(GTK_LABEL(label_fwd), FWD_LABEL_TEXT);
	gtk_label_set_text(GTK_LABEL(label_rev), REV_LABEL_TEXT);
}


/****************************************************************************/
/*
static void
rtpstream_on_goto                      (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	if (selected_stream_fwd)
	{
		goto_frame(&cfile, selected_stream_fwd->first_frame_num);
	}
}
*/


/****************************************************************************/
static void
rtpstream_on_save                      (GtkButton       *button _U_,
                                        gpointer         data _U_)
{
	rtpstream_tapinfo_t* tapinfo = data;

	GtkWidget *vertb;
	GtkWidget *ok_bt;

	if (!selected_stream_fwd)
		return;

	if (rtpstream_save_dlg != NULL) {
		/* There's already a Save dialog box; reactivate it. */
		reactivate_window(rtpstream_save_dlg);
		return;
	}

	rtpstream_save_dlg = gtk_file_selection_new("Ethereal: Save selected stream in rtpdump ('-F dump') format");
	gtk_signal_connect(GTK_OBJECT(rtpstream_save_dlg), "destroy",
		GTK_SIGNAL_FUNC(save_stream_destroy_cb), NULL);

	/* Container for each row of widgets */
	vertb = gtk_vbox_new(FALSE, 0);
	gtk_container_border_width(GTK_CONTAINER(vertb), 5);
	gtk_box_pack_start(GTK_BOX(GTK_FILE_SELECTION(rtpstream_save_dlg)->action_area),
		vertb, FALSE, FALSE, 0);
	gtk_widget_show (vertb);

	ok_bt = GTK_FILE_SELECTION(rtpstream_save_dlg)->ok_button;
/*	OBJECT_SET_DATA(ok_bt, "user_data", tapinfo);*/

	/* Connect the cancel_button to destroy the widget */
	SIGNAL_CONNECT_OBJECT(GTK_FILE_SELECTION(rtpstream_save_dlg)->cancel_button,
		"clicked", (GtkSignalFunc)gtk_widget_destroy,
		rtpstream_save_dlg);

	/* Catch the "key_press_event" signal in the window, so that we can catch
	the ESC key being pressed and act as if the "Cancel" button had
	been selected. */
	dlg_set_cancel(rtpstream_save_dlg, GTK_FILE_SELECTION(rtpstream_save_dlg)->cancel_button);

	gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
		GTK_SIGNAL_FUNC(save_stream_ok_cb), tapinfo);

	gtk_widget_show(rtpstream_save_dlg);
}


/****************************************************************************/
static void
rtpstream_on_mark                      (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	if (selected_stream_fwd==NULL && selected_stream_rev==NULL)
		return;
	rtpstream_mark(selected_stream_fwd, selected_stream_rev);
}


#define MAX_FILTER_LENGTH 320

/****************************************************************************/
static void
rtpstream_on_filter                    (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	gchar filter_string[MAX_FILTER_LENGTH] = "";
	gchar filter_string_rev[MAX_FILTER_LENGTH] = "";

	if (selected_stream_fwd==NULL && selected_stream_rev==NULL)
		return;

	if (selected_stream_fwd)
	{
		g_snprintf(filter_string, MAX_FILTER_LENGTH,
			"(ip.src==%s && udp.srcport==%u && ip.dst==%s && udp.dstport==%u && rtp.ssrc==%u)",
			ip_to_str((const guint8*)&(selected_stream_fwd->src_addr)),
			selected_stream_fwd->src_port,
			ip_to_str((const guint8*)&(selected_stream_fwd->dest_addr)),
			selected_stream_fwd->dest_port,
			selected_stream_fwd->ssrc);

		if (selected_stream_rev)
		{
			strcat(filter_string, " || ");
		}
	}

	if (selected_stream_rev)
	{
		g_snprintf(filter_string_rev, MAX_FILTER_LENGTH,
			"(ip.src==%s && udp.srcport==%u && ip.dst==%s && udp.dstport==%u && rtp.ssrc==%u)",
			ip_to_str((const guint8*)&(selected_stream_rev->src_addr)),
			selected_stream_rev->src_port,
			ip_to_str((const guint8*)&(selected_stream_rev->dest_addr)),
			selected_stream_rev->dest_port,
			selected_stream_rev->ssrc);
		strcat(filter_string, filter_string_rev);
	}

	gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), filter_string);
/*
	filter_packets(&cfile, filter_string);
	rtpstream_dlg_update(rtpstream_get_info()->strinfo_list);
*/
}


/****************************************************************************/
static void
rtpstream_on_close                     (GtkButton        *button _U_,
                                        gpointer         user_data _U_)
{
	gtk_grab_remove(rtp_stream_dlg);
	gtk_widget_destroy(rtp_stream_dlg);
}


/****************************************************************************/
static void
rtpstream_on_analyse                   (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	guint32 ip_src_fwd = 0;
	guint16 port_src_fwd = 0;
	guint32 ip_dst_fwd = 0;
	guint16 port_dst_fwd = 0;
	guint32 ssrc_fwd = 0;
	guint32 ip_src_rev = 0;
	guint16 port_src_rev = 0;
	guint32 ip_dst_rev = 0;
	guint16 port_dst_rev = 0;
	guint32 ssrc_rev = 0;

	if (selected_stream_fwd) {
		ip_src_fwd = selected_stream_fwd->src_addr;
		port_src_fwd = selected_stream_fwd->src_port;
		ip_dst_fwd = selected_stream_fwd->dest_addr;
		port_dst_fwd = selected_stream_fwd->dest_port;
		ssrc_fwd = selected_stream_fwd->ssrc;
	}

	if (selected_stream_rev) {
		ip_src_rev = selected_stream_rev->src_addr;
		port_src_rev = selected_stream_rev->src_port;
		ip_dst_rev = selected_stream_rev->dest_addr;
		port_dst_rev = selected_stream_rev->dest_port;
		ssrc_rev = selected_stream_rev->ssrc;
	}

	rtp_analysis(
		ip_src_fwd,
		port_src_fwd,
		ip_dst_fwd,
		port_dst_fwd,
		ssrc_fwd,
		ip_src_rev,
		port_src_rev,
		ip_dst_rev,
		port_dst_rev,
		ssrc_rev
		);
}


/****************************************************************************/
/* This should be the callback function called upon a user-defined
 * event "signal_rtpstream_update", but i didn't knoow how to do with GTK
static void
rtpstream_on_update                    (GtkButton       *button _U_,
                                        gpointer         user_data _U_)
{
	rtpstream_dlg_update(rtpstream_get_info()->strinfo_list);
}
*/

/****************************************************************************/
/* when the user selects a row in the stream list */
static void
rtpstream_on_select_row(GtkCList *clist,
                                            gint row _U_,
                                            gint column _U_,
                                            GdkEventButton *event _U_,
                                            gpointer user_data _U_)
{
	gchar label_text[80];

	/* update the labels */
	if (event->state & GDK_SHIFT_MASK) {
		selected_stream_rev = gtk_clist_get_row_data(GTK_CLIST(clist), row);
		g_snprintf(label_text, 80, "Reverse: %s:%u -> %s:%u, SSRC=%u",
			ip_to_str((ip_addr_p)&selected_stream_rev->src_addr),
			selected_stream_rev->src_port,
			ip_to_str((ip_addr_p)&selected_stream_rev->dest_addr),
			selected_stream_rev->dest_port,
			selected_stream_rev->ssrc
		);
		gtk_label_set_text(GTK_LABEL(label_rev), label_text);
	}
	else {
		selected_stream_fwd = gtk_clist_get_row_data(GTK_CLIST(clist), row);
		g_snprintf(label_text, 80, "Forward: %s:%u -> %s:%u, SSRC=%u",
			ip_to_str((ip_addr_p)&selected_stream_fwd->src_addr),
			selected_stream_fwd->src_port,
			ip_to_str((ip_addr_p)&selected_stream_fwd->dest_addr),
			selected_stream_fwd->dest_port,
			selected_stream_fwd->ssrc
		);
		gtk_label_set_text(GTK_LABEL(label_fwd), label_text);
	}

/*
	gtk_widget_set_sensitive(save_bt, TRUE);
	gtk_widget_set_sensitive(filter_bt, TRUE);
	gtk_widget_set_sensitive(mark_bt, TRUE);
*/
	/* TODO: activate other buttons when implemented */
}


/****************************************************************************/
/* INTERFACE                                                                */
/****************************************************************************/

static void rtpstream_dlg_create (void)
{
	/* these are global static now:
	GtkWidget *clist = NULL;
	GtkWidget *label_fwd = NULL;
	GtkWidget *label_rev = NULL;
	*/
	GtkWidget *rtpstream_dlg_w;
	GtkWidget *dialog_vbox1;
	GtkWidget *vbox1;
	GtkWidget *label10;
	GtkWidget *scrolledwindow1;
	GtkWidget *label2;
	GtkWidget *label3;
	GtkWidget *label4;
	GtkWidget *label5;
	GtkWidget *label6;
	GtkWidget *label7;
	GtkWidget *label8;
/*	GtkWidget *label9;*/
	GtkWidget *dialog_action_area1;
	GtkWidget *hbuttonbox2;
/*	GtkWidget *bt_goto;*/
	GtkWidget *bt_unselect;
	GtkWidget *bt_save;
	GtkWidget *bt_frames;
	GtkWidget *bt_filter;
	GtkWidget *bt_analyse;
	GtkWidget *bt_close;
	
	rtpstream_dlg_w = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title (GTK_WINDOW (rtpstream_dlg_w), "Ethereal: RTP Streams");
	
	dialog_vbox1 = GTK_DIALOG (rtpstream_dlg_w)->vbox;
	gtk_widget_show (dialog_vbox1);
	
	vbox1 = gtk_vbox_new (FALSE, 0);
	gtk_widget_ref (vbox1);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "vbox1", vbox1,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (vbox1);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), vbox1, TRUE, TRUE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (vbox1), 8);
	
	label10 = gtk_label_new ("Detected RTP streams. Choose one for forward and reverse direction for analysis");
	gtk_widget_ref (label10);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label10", label10,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label10);
	gtk_box_pack_start (GTK_BOX (vbox1), label10, FALSE, FALSE, 0);
	gtk_widget_set_usize (label10, -2, 32);
	
	scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
	gtk_widget_ref (scrolledwindow1);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "scrolledwindow1", scrolledwindow1,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (scrolledwindow1);
	gtk_box_pack_start (GTK_BOX (vbox1), scrolledwindow1, TRUE, TRUE, 0);
	
	clist = gtk_clist_new (7); /* defines number of columns */
	gtk_widget_ref (clist);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "clist", clist,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (clist);
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), clist);
	gtk_widget_set_usize (clist, 640, 200);
	gtk_clist_set_column_width (GTK_CLIST (clist), 0, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 1, 50);
	gtk_clist_set_column_width (GTK_CLIST (clist), 2, 100);
	gtk_clist_set_column_width (GTK_CLIST (clist), 3, 50);
	gtk_clist_set_column_width (GTK_CLIST (clist), 4, 80);
	gtk_clist_set_column_width (GTK_CLIST (clist), 5, 118);
	gtk_clist_set_column_width (GTK_CLIST (clist), 6, 60);
/*	gtk_clist_set_column_width (GTK_CLIST (clist), 7, 51);*/
	gtk_clist_column_titles_show (GTK_CLIST (clist));
	
	label2 = gtk_label_new ("Src IP addr");
	gtk_widget_ref (label2);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label2", label2,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label2);
	gtk_clist_set_column_widget (GTK_CLIST (clist), 0, label2);
	
	label3 = gtk_label_new ("Src port");
	gtk_widget_ref (label3);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label3", label3,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label3);
	gtk_clist_set_column_widget (GTK_CLIST (clist), 1, label3);
	
	label4 = gtk_label_new ("Dest IP addr");
	gtk_widget_ref (label4);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label4", label4,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label4);
	gtk_clist_set_column_widget (GTK_CLIST (clist), 2, label4);
	
	label5 = gtk_label_new ("Dest port");
	gtk_widget_ref (label5);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label5", label5,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label5);
	gtk_clist_set_column_widget (GTK_CLIST (clist), 3, label5);
	
	label6 = gtk_label_new ("SSRC");
	gtk_widget_ref (label6);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label6", label6,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label6);
	gtk_clist_set_column_widget (GTK_CLIST (clist), 4, label6);
	gtk_widget_set_usize (label6, 80, -2);
	
	label7 = gtk_label_new ("Payload");
	gtk_widget_ref (label7);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label7", label7,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label7);
	gtk_clist_set_column_widget (GTK_CLIST (clist), 5, label7);
	
	label8 = gtk_label_new ("Packets");
	gtk_widget_ref (label8);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label8", label8,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label8);
	gtk_clist_set_column_widget (GTK_CLIST (clist), 6, label8);
/*	
	label9 = gtk_label_new ("Comment");
	gtk_widget_ref (label9);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label9", label9,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label9);
	gtk_clist_set_column_widget (GTK_CLIST (clist), 7, label9);
*/	
	label_fwd = gtk_label_new (FWD_LABEL_TEXT);
	gtk_widget_ref (label_fwd);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label_fwd", label_fwd,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label_fwd);
	gtk_box_pack_start (GTK_BOX (vbox1), label_fwd, FALSE, FALSE, 0);
	gtk_label_set_justify (GTK_LABEL (label_fwd), GTK_JUSTIFY_LEFT);
	
	label_rev = gtk_label_new (REV_LABEL_TEXT);
	gtk_widget_ref (label_rev);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "label_rev", label_rev,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (label_rev);
	gtk_box_pack_start (GTK_BOX (vbox1), label_rev, FALSE, FALSE, 0);
	gtk_label_set_justify (GTK_LABEL (label_rev), GTK_JUSTIFY_LEFT);
	
	dialog_action_area1 = GTK_DIALOG (rtpstream_dlg_w)->action_area;
	gtk_widget_show (dialog_action_area1);
	gtk_container_set_border_width (GTK_CONTAINER (dialog_action_area1), 10);
	
	hbuttonbox2 = gtk_hbutton_box_new ();
	gtk_widget_ref (hbuttonbox2);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "hbuttonbox2", hbuttonbox2,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (hbuttonbox2);
	gtk_box_pack_start (GTK_BOX (dialog_action_area1), hbuttonbox2, FALSE, FALSE, 0);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox2), GTK_BUTTONBOX_END);
	gtk_button_box_set_spacing (GTK_BUTTON_BOX (hbuttonbox2), 0);
	
	bt_unselect = gtk_button_new_with_label ("Unselect");
	gtk_widget_ref (bt_unselect);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "bt_unselect", bt_unselect,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (bt_unselect);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_unselect);
	GTK_WIDGET_SET_FLAGS (bt_unselect, GTK_CAN_DEFAULT);
/*	
	bt_goto = gtk_button_new_with_label ("Go to Frame");
	gtk_widget_ref (bt_goto);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "bt_goto", bt_goto,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (bt_goto);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_goto);
	GTK_WIDGET_SET_FLAGS (bt_goto, GTK_CAN_DEFAULT);
*/	
	bt_save = gtk_button_new_with_label ("Save as...");
	gtk_widget_ref (bt_save);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "bt_save", bt_save,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (bt_save);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_save);
	GTK_WIDGET_SET_FLAGS (bt_save, GTK_CAN_DEFAULT);
	
	bt_frames = gtk_button_new_with_label ("Mark frames");
	gtk_widget_ref (bt_frames);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "bt_frames", bt_frames,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (bt_frames);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_frames);
	GTK_WIDGET_SET_FLAGS (bt_frames, GTK_CAN_DEFAULT);
	
	bt_filter = gtk_button_new_with_label ("Set filter");
	gtk_widget_ref (bt_filter);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "bt_filter", bt_filter,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (bt_filter);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_filter);
	GTK_WIDGET_SET_FLAGS (bt_filter, GTK_CAN_DEFAULT);
	
	bt_analyse = gtk_button_new_with_label ("Analyse");
	gtk_widget_ref (bt_analyse);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "bt_analyse", bt_analyse,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (bt_analyse);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_analyse);
	GTK_WIDGET_SET_FLAGS (bt_analyse, GTK_CAN_DEFAULT);
	
	bt_close = gtk_button_new_with_label ("Close");
	gtk_widget_ref (bt_close);
	gtk_object_set_data_full (GTK_OBJECT (rtpstream_dlg_w), "bt_close", bt_close,
		(GtkDestroyNotify) gtk_widget_unref);
	gtk_widget_show (bt_close);
	gtk_container_add (GTK_CONTAINER (hbuttonbox2), bt_close);
	GTK_WIDGET_SET_FLAGS (bt_close, GTK_CAN_DEFAULT);
	
	gtk_signal_connect (GTK_OBJECT (rtpstream_dlg_w), "destroy",
		GTK_SIGNAL_FUNC (rtpstream_on_destroy),
		NULL);
	gtk_signal_connect (GTK_OBJECT (clist), "select_row",
		GTK_SIGNAL_FUNC (rtpstream_on_select_row),
		NULL);
	gtk_signal_connect (GTK_OBJECT (bt_unselect), "clicked",
		GTK_SIGNAL_FUNC (rtpstream_on_unselect),
		NULL);
/*
	gtk_signal_connect (GTK_OBJECT (bt_goto), "clicked",
		GTK_SIGNAL_FUNC (rtpstream_on_goto),
		NULL);
*/
	gtk_signal_connect (GTK_OBJECT (bt_save), "clicked",
		GTK_SIGNAL_FUNC (rtpstream_on_save),
		NULL);
	gtk_signal_connect (GTK_OBJECT (bt_frames), "clicked",
		GTK_SIGNAL_FUNC (rtpstream_on_mark),
		NULL);
	gtk_signal_connect (GTK_OBJECT (bt_filter), "clicked",
		GTK_SIGNAL_FUNC (rtpstream_on_filter),
		NULL);
	gtk_signal_connect (GTK_OBJECT (bt_analyse), "clicked",
		GTK_SIGNAL_FUNC (rtpstream_on_analyse),
		NULL);
	gtk_signal_connect (GTK_OBJECT (bt_close), "clicked",
		GTK_SIGNAL_FUNC (rtpstream_on_close),
		NULL);
/* XXX: see rtpstream_on_update for comment
	gtk_signal_connect (GTK_OBJECT (top_level), "signal_rtpstream_update",
		GTK_SIGNAL_FUNC (rtpstream_on_update),
		NULL);
*/
	
	if (clist) {
		gtk_clist_set_column_justification(GTK_CLIST(clist), 0, GTK_JUSTIFY_CENTER);
		gtk_clist_set_column_justification(GTK_CLIST(clist), 1, GTK_JUSTIFY_CENTER);
		gtk_clist_set_column_justification(GTK_CLIST(clist), 2, GTK_JUSTIFY_CENTER);
		gtk_clist_set_column_justification(GTK_CLIST(clist), 3, GTK_JUSTIFY_CENTER);
		gtk_clist_set_column_justification(GTK_CLIST(clist), 4, GTK_JUSTIFY_CENTER);
		gtk_clist_set_column_justification(GTK_CLIST(clist), 5, GTK_JUSTIFY_LEFT);
		gtk_clist_set_column_justification(GTK_CLIST(clist), 6, GTK_JUSTIFY_RIGHT);
/*		gtk_clist_set_column_justification(GTK_CLIST(clist), 7, GTK_JUSTIFY_CENTER);*/
	}

	rtpstream_on_unselect(NULL, NULL);

	rtp_stream_dlg = rtpstream_dlg_w;
}


/****************************************************************************/
/* PUBLIC                                                                   */
/****************************************************************************/

/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of rtp_stream_info_t* */
void rtpstream_dlg_update(GList *list)
{
	if (rtp_stream_dlg != NULL) {
		gtk_clist_clear(GTK_CLIST(clist));

		list = g_list_first(list);
		while (list)
		{
			add_to_clist((rtp_stream_info_t*)(list->data));
			list = g_list_next(list);
		}

		rtpstream_on_unselect(NULL, NULL);
	}

	last_list = list;
}


/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of rtp_stream_info_t* */
void rtpstream_dlg_show(GList *list)
{
	if (rtp_stream_dlg != NULL) {
		/* There's already a dialog box; reactivate it. */
		reactivate_window(rtp_stream_dlg);
		/* Another list since last call? */
		if (list != last_list) {
			rtpstream_dlg_update(list);
		}
	}
	else {
		/* Create and show the dialog box */
		rtpstream_dlg_create();
		rtpstream_dlg_update(list);
		gtk_widget_show(rtp_stream_dlg);
	}
}


/****************************************************************************/
/* entry point when called via the GTK menu */
void rtpstream_launch(GtkWidget *w _U_, gpointer data _U_)
{
	/* Show the dialog box */
	rtpstream_dlg_show(rtpstream_get_info()->strinfo_list);
}

/****************************************************************************/
void
register_tap_menu_rtp_stream(void)
{
	register_tap_menu_item("Statistics/RTP Streams/Show All...",
	    rtpstream_launch, NULL, NULL);
}
