 /* rtp_player.c
 *
 * $Id$
 *
 *  Copyright 2006, Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/*
 * Here is a summary on how this works:
 *  - The VoipCalls will call add_rtp_packet() every time there is an RTP
 *    packet
 *  - add_rtp_packet() will add the RTP packet in a RTP stream struct, and
 *    create the RTP stream if it is the first RTP packet in the stream.
 *  - Each new RTP stream will be added to a list of RTP streams, called
 *    rtp_streams_list
 *  - When the user clicks "Player" in the VoipCall dialogue,
 *    rtp_player_init() is called.
 *  - rtp_player_init() creates the main dialog, and it calls:
 *    + mark_rtp_stream_to_play() to mark the RTP streams that needs to be
 *      displayed. These are the RTP streams that match the selected calls in
 *      the VoipCall dlg.
 *    + decode_rtp_stream() this will decode the RTP packets in each RTP
 *      stream, and will also create the RTP channels. An RTP channel is a
 *      group of RTP streams that have in common the source and destination
 *      IP and UDP ports. The RTP channels is what the user will listen in
 *      one of the two Audio channels.
 *      The RTP channels are stored in the hash table rtp_channels_hash
 *    + add_channel_to_window() will create and add the Audio graphic
 *      representation in the main window
 *  - When the user clicks the check box to listen one of the Audio channels,
 *    the structure rtp_channels is filled to play one or two RTP channels
 *    (a max of two channels can be listened at a given moment)
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBPORTAUDIO
#include <math.h>
#include <string.h>
#include "portaudio.h"

#include <gtk/gtk.h>

#include <epan/stats_tree.h>
#include <epan/addr_resolv.h>
#include <epan/dissectors/packet-rtp.h>
#include <epan/rtp_pt.h>
#include <epan/codecs.h>
#include <epan/prefs.h>

#include "../globals.h"
#include "ui/simple_dialog.h"
#include "../codecs/G711a/G711adecode.h"
#include "../codecs/G711u/G711udecode.h"

#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/graph_analysis.h"
#include "ui/gtk/voip_calls_dlg.h"
#include "ui/gtk/voip_calls.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/rtp_player.h"
#include "ui/gtk/stock_icons.h"

#include "ui/gtk/old-gtk-compat.h"

/*define this symbol to compile with G729 and G723 codecs*/
/*#define HAVE_G729_G723 1*/

#ifdef HAVE_G729_G723
#include "codecs/G729/G729decode.h"
#include "codecs/G723/G723decode.h"
#endif /* HAVE_G729_G723 */

static gboolean initialized = FALSE;

static voip_calls_tapinfo_t *voip_calls = NULL;

/* Hash table with all the RTP streams */
static GHashTable*  rtp_streams_hash = NULL;

/* List with all the RTP streams (this is used to decode them as it is sorted)*/
static GList*  rtp_streams_list = NULL;

/* the window */
static GtkWidget *rtp_player_dlg_w;
static GtkWidget *channels_vb;
static GtkWidget *main_scrolled_window = NULL;
static GtkWidget *jitter_spinner;
static GtkWidget *cb_use_rtp_timestamp;
static GtkWidget *cb_view_as_time_of_day;
static GtkWidget *bt_decode;
static GtkWidget *bt_play;
static GtkWidget *bt_pause;
static GtkWidget *bt_stop;
static GtkWidget *progress_bar;
static GtkWidget *info_bar;
static GtkWidget *stat_hbox;

static guint32 total_packets;
static guint32 total_frames;
static guint32 progbar_count;

static int new_jitter_buff;

/* a hash table with the RTP streams to play per audio channel */
static GHashTable *rtp_channels_hash = NULL;

/* Port Audio stuff */
#define SAMPLE_RATE  (8000)
#define NUM_CHANNELS    (2)

#define PA_SAMPLE_TYPE  paInt16
typedef gint16 SAMPLE;
#define SAMPLE_SILENCE  (0)
#define FRAMES_PER_BUFFER  (512)

typedef struct _sample_t {
	SAMPLE val;
	guint8 status;
} sample_t;

#define S_NORMAL 0
#define S_DROP_BY_JITT 1
#define S_WRONG_SEQ 2
#define S_WRONG_TIMESTAMP 3 /* The timestamp does not reflect the number of samples - samples have been dropped or silence inserted to match timestamp */
#define S_SILENCE 4 /* Silence inserted by Wireshark, rather than contained in a packet */

/* Display channels constants */
#define MULT 80
#define CHANNEL_WIDTH 500
#define CHANNEL_HEIGHT 100
#define MAX_TIME_LABEL 10
#define HEIGHT_TIME_LABEL 18
#define MAX_NUM_COL_CONV 10

#if PORTAUDIO_API_1
static PortAudioStream *pa_stream;
#else /* PORTAUDIO_API_1 */
static PaStream *pa_stream;
#endif /* PORTAUDIO_API_1 */

/* defines a RTP stream */
typedef struct _rtp_stream_info {
	address src_addr;
	guint16 src_port;
	address dest_addr;
	guint16 dest_port;
	guint32 ssrc;
	guint32 first_frame_number; /* first RTP frame for the stream */
	double start_time;			/* RTP stream start time in ms */
	nstime_t start_time_abs;
	gboolean play;
	guint16 call_num;
	GList*  rtp_packets_list; /* List of RTP packets in the stream */
	guint32 num_packets;
} rtp_stream_info_t;


/* defines the RTP streams to be played in an audio channel */
typedef struct _rtp_channel_info {
	double start_time;			/* RTP stream start time in ms */
	nstime_t start_time_abs;
	double end_time;			/* RTP stream end time in ms */
	GArray *samples;			/* the array with decoded audio */
	guint16 call_num;
	gboolean selected;
	guint32 frame_index;
	guint32 drop_by_jitter_buff;
	guint32 out_of_seq;
	guint32 wrong_timestamp;
	guint32 max_frame_index;
	GtkWidget *check_bt;
	GtkWidget *separator;
	GtkWidget *scroll_window;
	GtkWidget *draw_area;
#if GTK_CHECK_VERSION(2,22,0)
	cairo_surface_t *surface;
#else
	GdkPixmap *pixmap;
#endif
	GtkAdjustment *h_scrollbar_adjustment;
	GdkPixbuf* cursor_pixbuf;
#if PORTAUDIO_API_1
	PaTimestamp cursor_prev;
#else /* PORTAUDIO_API_1 */
	PaTime cursor_prev;
#endif /* PORTAUDIO_API_1 */
	GdkColor bg_color[MAX_NUM_COL_CONV+1];
	gboolean cursor_catch;
	rtp_stream_info_t *first_stream;	/* This is the first RTP stream in the channel */
	guint32 num_packets;
} rtp_channel_info_t;

/* defines a RTP packet */
typedef struct _rtp_packet {
	struct _rtp_info *info;	/* the RTP dissected info */
	double arrive_offset;	/* arrive offset time since the begining of the stream in ms */
	guint8* payload_data;
} rtp_packet_t;

/* defines the two RTP channels to be played */
typedef struct _rtp_play_channles {
	rtp_channel_info_t* rci[2]; /* Channels to be played */
	guint32 start_index[2];
	guint32 end_index[2];
	int channel;
	guint32 max_frame_index;
	guint32 frame_index;
	gboolean pause;
	gboolean stop;
	gint32 pause_duration;
#if PORTAUDIO_API_1
	PaTimestamp out_diff_time;
#else /* PORTAUDIO_API_1 */
	PaTime out_diff_time;
	PaTime pa_start_time;
#endif /* PORTAUDIO_API_1 */
} rtp_play_channels_t;

/* The two RTP channels to play */
static rtp_play_channels_t *rtp_channels = NULL;

typedef struct _rtp_decoder_t {
	codec_handle_t handle;
	void *context;
} rtp_decoder_t;


/****************************************************************************/
static void
rtp_key_destroy(gpointer key)
{
	g_free(key);
	key = NULL;
}

/****************************************************************************/
static void
rtp_channel_value_destroy(gpointer rci_arg)
{
	rtp_channel_info_t *rci = rci_arg;

	g_array_free(rci->samples, TRUE);
	g_free(rci);
	rci = NULL;
}

/****************************************************************************/
static void
rtp_stream_value_destroy(gpointer rsi_arg)
{
	rtp_stream_info_t *rsi = rsi_arg;
	GList*  rtp_packets_list;
	rtp_packet_t *rp;

	rtp_packets_list = g_list_first(rsi->rtp_packets_list);
	while (rtp_packets_list)
	{
		rp = rtp_packets_list->data;

		g_free(rp->info);
		g_free(rp->payload_data);
		g_free(rp);
		rp = NULL;

		rtp_packets_list = g_list_next(rtp_packets_list);
	}
	g_free((void *)(rsi->src_addr.data));
	g_free((void *)(rsi->dest_addr.data));
	g_free(rsi);
	rsi = NULL;
}

/****************************************************************************/
static void
rtp_decoder_value_destroy(gpointer dec_arg)
{
	rtp_decoder_t *dec = dec_arg;

	if (dec->handle)
		codec_release(dec->handle, dec->context);
	g_free(dec_arg);
}

/****************************************************************************/
static void
set_sensitive_check_bt(gchar *key _U_ , rtp_channel_info_t *rci, guint *stop _U_ )
{
	gtk_widget_set_sensitive(rci->check_bt, !(*stop));
}

/****************************************************************************/
static void
bt_state(gboolean decode, gboolean play, gboolean pause, gboolean stop)
{
	gboolean new_jitter_value = FALSE;
	gboolean false_val = FALSE;

	gtk_widget_set_sensitive(bt_decode, decode);
	gtk_widget_set_sensitive(cb_use_rtp_timestamp, decode);
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_use_rtp_timestamp))) {
		gtk_widget_set_sensitive(jitter_spinner, FALSE);
	} else {
		gtk_widget_set_sensitive(jitter_spinner, decode);
	}

	if (new_jitter_buff != (int) gtk_spin_button_get_value((GtkSpinButton * )jitter_spinner)) {
		new_jitter_value = TRUE;
	}

	/* set the sensitive state of play only if there is a channel selected */
	if ( play && (rtp_channels->rci[0] || rtp_channels->rci[1]) && !new_jitter_value) {
		gtk_widget_set_sensitive(bt_play, TRUE);
	} else {
		gtk_widget_set_sensitive(bt_play, FALSE);
	}

	if (!new_jitter_value) {
		gtk_widget_set_sensitive(bt_pause, pause);
		gtk_widget_set_sensitive(bt_stop, stop);

		/* Set sensitive to the check buttons based on the STOP state */
		if (rtp_channels_hash)
			g_hash_table_foreach( rtp_channels_hash, (GHFunc)set_sensitive_check_bt, &stop);
	} else {
		gtk_widget_set_sensitive(bt_pause, FALSE);
		gtk_widget_set_sensitive(bt_stop, FALSE);

		if (rtp_channels_hash)
			g_hash_table_foreach( rtp_channels_hash, (GHFunc)set_sensitive_check_bt, &false_val);
	}
}

/****************************************************************************/
void
add_rtp_packet(const struct _rtp_info *rtp_info, packet_info *pinfo)
{
	rtp_stream_info_t *stream_info = NULL;
	rtp_packet_t *new_rtp_packet;
	GString *key_str = NULL;

	/* create the streams hash if it doen't exist */
	if (!rtp_streams_hash)
		rtp_streams_hash = g_hash_table_new_full( g_str_hash, g_str_equal, rtp_key_destroy, rtp_stream_value_destroy);

	/* Create a hash key to lookup in the RTP streams hash table
	 * uses: src_ip:src_port dst_ip:dst_port ssrc
	 */
	key_str = g_string_new("");
	g_string_printf(key_str, "%s:%d %s:%d %d", get_addr_name(&(pinfo->src)),
		pinfo->srcport, get_addr_name(&(pinfo->dst)),
		pinfo->destport, rtp_info->info_sync_src );

	/* lookup for this RTP packet in the stream hash table */
	stream_info =  g_hash_table_lookup( rtp_streams_hash, key_str->str);

	/* if it is not in the hash table, create a new stream */
	if (stream_info==NULL) {
		stream_info = g_malloc(sizeof(rtp_stream_info_t));
		COPY_ADDRESS(&(stream_info->src_addr), &(pinfo->src));
		stream_info->src_port = pinfo->srcport;
		COPY_ADDRESS(&(stream_info->dest_addr), &(pinfo->dst));
		stream_info->dest_port = pinfo->destport;
		stream_info->ssrc = rtp_info->info_sync_src;
		stream_info->rtp_packets_list = NULL;
		stream_info->first_frame_number = pinfo->fd->num;
		stream_info->start_time = nstime_to_msec(&pinfo->fd->rel_ts);
		stream_info->start_time_abs = pinfo->fd->abs_ts;
		stream_info->call_num = 0;
		stream_info->play = FALSE;
		stream_info->num_packets = 0;

		g_hash_table_insert(rtp_streams_hash, g_strdup(key_str->str), stream_info);

		/* Add the element to the List too. The List is used to decode the packets because it is sorted */
		rtp_streams_list = g_list_append(rtp_streams_list, stream_info);
	}

	/* increment the number of packets in this stream, this is used for the progress bar and statistics */
	stream_info->num_packets++;

	/* Add the RTP packet to the list */
	new_rtp_packet = g_malloc(sizeof(rtp_packet_t));
	new_rtp_packet->info = g_malloc(sizeof(struct _rtp_info));

	memcpy(new_rtp_packet->info, rtp_info, sizeof(struct _rtp_info));
	new_rtp_packet->arrive_offset = nstime_to_msec(&pinfo->fd->rel_ts) - stream_info->start_time;
	/* copy the RTP payload to the rtp_packet to be decoded later */
	if (rtp_info->info_all_data_present && (rtp_info->info_payload_len != 0)) {
		new_rtp_packet->payload_data = g_malloc(rtp_info->info_payload_len);
		memcpy(new_rtp_packet->payload_data, &(rtp_info->info_data[rtp_info->info_payload_offset]), rtp_info->info_payload_len);
	} else {
		new_rtp_packet->payload_data = NULL;
	}

	stream_info->rtp_packets_list = g_list_append(stream_info->rtp_packets_list, new_rtp_packet);

	g_string_free(key_str, TRUE);
}

/****************************************************************************/
/* Mark the RTP stream to be played. Use the voip_calls graph to see if the
 * setup_frame is there and then if the associated voip_call is selected.
 */
static void
mark_rtp_stream_to_play(gchar *key _U_ , rtp_stream_info_t *rsi, gpointer ptr _U_)
{
	GList*  graph_list;
	graph_analysis_item_t *graph_item;
	GList*  voip_calls_list;
	voip_calls_info_t *tmp_voip_call;

	/* Reset the "to be play" value because the user can close and reopen the RTP Player window
	 * and the streams are not reset in that case
	 */
	rsi->play = FALSE;

	/* and associate the RTP stream with a call using the first RTP packet in the stream */
	graph_list = g_list_first(voip_calls->graph_analysis->list);
	while (graph_list)
	{
		graph_item = graph_list->data;
		if (rsi->first_frame_number == graph_item->fd->num) {
			rsi->call_num = graph_item->conv_num;
			/* if it is in the graph list, then check if the voip_call is selected */
			voip_calls_list = g_list_first(voip_calls->callsinfo_list);
			while (voip_calls_list)
			{
				tmp_voip_call = voip_calls_list->data;
				if ( (tmp_voip_call->call_num == rsi->call_num) && (tmp_voip_call->selected == TRUE) ) {
					rsi->play = TRUE;
					total_packets += rsi->num_packets;
					break;
				}
				voip_calls_list = g_list_next(voip_calls_list);
			}
			break;
		}
		graph_list = g_list_next(graph_list);
	}
}

/****************************************************************************/
/* Mark the ALL RTP stream to be played. This is called when calling the
 * RTP player from the "RTP Analysis" window
 */
static void
mark_all_rtp_stream_to_play(gchar *key _U_ , rtp_stream_info_t *rsi, gpointer ptr _U_)
{
	rsi->play = TRUE;
	total_packets += rsi->num_packets;
}

/****************************************************************************/
/* Decode a RTP packet
 * Return the number of decoded bytes
 */
static int
decode_rtp_packet(rtp_packet_t *rp, SAMPLE **out_buff, GHashTable *decoders_hash)
{
	unsigned int  payload_type;
	const gchar *p;
	rtp_decoder_t *decoder;
	SAMPLE *tmp_buff = NULL;
	int tmp_buff_len;
	int decoded_bytes = 0;

	if ((rp->payload_data == NULL) || (rp->info->info_payload_len == 0) ) {
		return 0;
	}

	payload_type = rp->info->info_payload_type;

	/* Look for registered codecs */
	decoder = g_hash_table_lookup(decoders_hash, GUINT_TO_POINTER(payload_type));
	if (!decoder) {  /* Put either valid or empty decoder into the hash table */
		decoder = g_malloc(sizeof(rtp_decoder_t));
		decoder->handle = NULL;
		decoder->context = NULL;
		p = match_strval_ext(payload_type, &rtp_payload_type_short_vals_ext);
		if (p) {
			decoder->handle = find_codec(p);
			if (decoder->handle)
				decoder->context = codec_init(decoder->handle);
		}
		g_hash_table_insert(decoders_hash, GUINT_TO_POINTER(payload_type), decoder);
	}
	if (decoder->handle) {  /* Decode with registered codec */
		tmp_buff_len = codec_decode(decoder->handle, decoder->context, rp->payload_data, rp->info->info_payload_len, NULL, NULL);
		tmp_buff = g_malloc(tmp_buff_len);
		decoded_bytes = codec_decode(decoder->handle, decoder->context, rp->payload_data, rp->info->info_payload_len, tmp_buff, &tmp_buff_len);
		*out_buff = tmp_buff;
		return decoded_bytes;
	}

	/* Try to decode with built-in codec */

	switch (payload_type) {

	case PT_PCMU:	/* G.711 u-law */
		tmp_buff = g_malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 1);
		decodeG711u(rp->payload_data, rp->info->info_payload_len,
			  tmp_buff, &decoded_bytes);
		break;

	case PT_PCMA:	/* G.711 A-law */
		tmp_buff = g_malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 1);
		decodeG711a(rp->payload_data, rp->info->info_payload_len,
			  tmp_buff, &decoded_bytes);
		break;

#ifdef HAVE_G729_G723
	case PT_G729:	/* G.729 */
		/* G729 8kbps => 64kbps/8kbps = 8  */
		/* Compensate for possible 2 octet SID frame (G.729B) */
		tmp_buff = g_malloc(sizeof(SAMPLE) * ((rp->info->info_payload_len + 8) / 10) * 80);
		decodeG729(rp->payload_data, rp->info->info_payload_len,
			  tmp_buff, &decoded_bytes);
		break;

	case PT_G723:	/* G.723 */
		if (rp->info->info_payload_len%24 == 0)	/* G723 High 6.4kbps */
			tmp_buff = g_malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 10); /* G723 High 64kbps/6.4kbps = 10  */
		else if (rp->info->info_payload_len%20 == 0)    /* G723 Low 5.3kbps */
			tmp_buff = g_malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 13); /* G723 High 64kbps/5.3kbps = 13  */
		else {
			return 0;
		}
		decodeG723(rp->payload_data, rp->info->info_payload_len,
			  tmp_buff, &decoded_bytes);
		break;
#endif /* HAVE_G729_G723 */

	default:
		/*
		 * XXX - return an error here, so the user gets told that
		 * we don't support this codec!
		 */
		break;
	}

	*out_buff = tmp_buff;
	return decoded_bytes;
}

/****************************************************************************/
static void
update_progress_bar(gfloat fraction)
{

	if GTK_IS_PROGRESS_BAR(progress_bar)
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), fraction);

	/* Force gtk to redraw the window before starting decoding the packet */
	while (gtk_events_pending())
		gtk_main_iteration();
}

/****************************************************************************/
/* Decode the RTP streams and add them to the RTP channels struct
 */
static void
decode_rtp_stream(rtp_stream_info_t *rsi, gpointer ptr _U_)
{
	GString *key_str = NULL;
	rtp_channel_info_t *rci;
	gboolean first = TRUE;
	GList*  rtp_packets_list;
	rtp_packet_t *rp;

	int i;
	double rtp_time;
	double rtp_time_prev;
	double arrive_time;
	double arrive_time_prev;
	double start_time;
	double start_rtp_time = 0;
	double diff;
	double pack_period;
#ifdef DEBUG /* ?? */
	double total_time;
	double total_time_prev;
#endif
	gint32 silence_frames;
	int seq;
	double delay;
	double prev_diff;
#ifdef DEBUG /* ?? */
	double mean_delay;
	double variation;
#endif
	int decoded_bytes;
	int decoded_bytes_prev;
	int jitter_buff;
	SAMPLE *out_buff = NULL;
	sample_t silence;
	sample_t sample;
	guint8 status;
	guint32 start_timestamp;
	GHashTable *decoders_hash = NULL;

	guint32 progbar_nextstep;
	int progbar_quantum;
	gfloat progbar_val;

	silence.val = 0;
	silence.status = S_NORMAL;

	/* skip it if we are not going to play it */
	if (rsi->play == FALSE) {
		return;
	}

	/* get the static jitter buffer from the spinner gui */
	jitter_buff = (int) gtk_spin_button_get_value((GtkSpinButton * )jitter_spinner);

	/* Create a hash key to lookup in the RTP channels hash
	 * uses: src_ip:src_port dst_ip:dst_port call_num
	 */
	key_str = g_string_new("");
	g_string_printf(key_str, "%s:%d %s:%d %d", get_addr_name(&(rsi->src_addr)),
		rsi->src_port, get_addr_name(&(rsi->dest_addr)),
		rsi->dest_port, rsi->call_num );

	/* create the rtp_channels_hash table if it doesn't exist */
	if (!rtp_channels_hash) {
		rtp_channels_hash = g_hash_table_new_full( g_str_hash, g_str_equal, rtp_key_destroy, rtp_channel_value_destroy);
	}

	/* lookup for this stream in the channel hash table */
	rci =  g_hash_table_lookup( rtp_channels_hash, key_str->str);

	/* ..if it is not in the hash, create an entry */
	if (rci == NULL) {
		rci = g_malloc(sizeof(rtp_channel_info_t));
		rci->call_num = rsi->call_num;
		rci->start_time = rsi->start_time;
		rci->start_time_abs = rsi->start_time_abs;
		rci->end_time = rsi->start_time;
		rci->selected = FALSE;
		rci->frame_index = 0;
		rci->drop_by_jitter_buff = 0;
		rci->out_of_seq = 0;
		rci->wrong_timestamp = 0;
		rci->max_frame_index = 0;
		rci->samples = g_array_new (FALSE, FALSE, sizeof(sample_t));
		rci->check_bt = NULL;
		rci->separator = NULL;
		rci->draw_area = NULL;
#if GTK_CHECK_VERSION(2,22,0)
		rci->surface = NULL;
#else
		rci->pixmap = NULL;
#endif
		rci->h_scrollbar_adjustment = NULL;
		rci->cursor_pixbuf = NULL;
		rci->cursor_prev = 0;
		rci->cursor_catch = FALSE;
		rci->first_stream = rsi;
		rci->num_packets = rsi->num_packets;
		g_hash_table_insert(rtp_channels_hash, g_strdup(key_str->str), rci);
	} else {
		/* Add silence between the two streams if needed */
		silence_frames = (gint32)( ((rsi->start_time - rci->end_time)/1000)*SAMPLE_RATE );
		for (i = 0; i< silence_frames; i++) {
			g_array_append_val(rci->samples, silence);
		}
		rci->num_packets += rsi->num_packets;
	}

	/* decode the RTP stream */
	first = TRUE;
	rtp_time = 0;
	rtp_time_prev = 0;
	decoded_bytes = 0;
	decoded_bytes_prev = 0;
	silence_frames = 0;
	arrive_time = start_time = 0;
	arrive_time_prev = 0;
	pack_period = 0;
#ifdef DEBUG /* ?? */
	total_time = 0;
	total_time_prev = 0;
#endif
	seq = 0;
	delay = 0;
	prev_diff = 0;
#ifdef DEBUG /* ?? */
	mean_delay = 0;
	variation = 0;
#endif
	start_timestamp = 0;
	decoders_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, rtp_decoder_value_destroy);

	/* we update the progress bar 100 times */

	/* Update the progress bar when it gets to this value. */
	progbar_nextstep = 0;
	/* When we reach the value that triggers a progress bar update,
	   bump that value by this amount. */
	progbar_quantum = total_packets/100;

	status = S_NORMAL;

	rtp_packets_list = g_list_first(rsi->rtp_packets_list);
	while (rtp_packets_list)
	{

		if (progbar_count >= progbar_nextstep) {
			g_assert(total_packets > 0);

			progbar_val = (gfloat) progbar_count / total_packets;

			update_progress_bar(progbar_val);

			progbar_nextstep += progbar_quantum;
		}


		rp = rtp_packets_list->data;
		if (first == TRUE) {
			start_timestamp = rp->info->info_timestamp; /* defined start_timestmp to avoid overflow in timestamp. TODO: handle the timestamp correctly */
			start_rtp_time = 0;
			rtp_time_prev = start_rtp_time;
			first = FALSE;
			seq = rp->info->info_seq_num - 1;
		}

		decoded_bytes = decode_rtp_packet(rp, &out_buff, decoders_hash);
		if (decoded_bytes == 0) {
			seq = rp->info->info_seq_num;
		}

		rtp_time = (double)(rp->info->info_timestamp-start_timestamp)/SAMPLE_RATE - start_rtp_time;

		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_use_rtp_timestamp))) {
			arrive_time = rtp_time;
		} else {
			arrive_time = (double)rp->arrive_offset/1000 - start_time;
		}

		if (rp->info->info_seq_num != seq+1){
			rci->out_of_seq++;
			status = S_WRONG_SEQ;
		}
		seq = rp->info->info_seq_num;

		diff = arrive_time - rtp_time;

		delay = diff - prev_diff;
		prev_diff = diff;
		if (delay<0) delay = -delay;

		if (diff<0) diff = -diff;

#ifdef DEBUG
		total_time = (double)rp->arrive_offset/1000;
		printf("seq = %d arr = %f abs_diff = %f index = %d tim = %f ji=%d jb=%f\n",rp->info->info_seq_num,
			total_time, diff, rci->samples->len, ((double)rci->samples->len/8000 - total_time)*1000, 0,
				(mean_delay + 4*variation)*1000);
		fflush(stdout);
#endif
		/* if the jitter buffer was exceeded */
		if ( diff*1000 > jitter_buff ) {
#ifdef DEBUG
			printf("Packet drop by jitter buffer exceeded\n");
#endif
			rci->drop_by_jitter_buff++;
			status = S_DROP_BY_JITT;

			/* if there was a silence period (more than two packetization period) resync the source */
			if ( (rtp_time - rtp_time_prev) > pack_period*2 ){
#ifdef DEBUG
				printf("Resync...\n");
#endif
				silence_frames = (gint32)((arrive_time - arrive_time_prev)*SAMPLE_RATE - decoded_bytes_prev/2);

				/* Fix for bug 4119/5902: don't insert too many silence frames.
				 * XXX - is there a better thing to do here?
				 */
#define MAX_SILENCE_FRAMES 240000
				if (silence_frames > MAX_SILENCE_FRAMES)
					silence_frames = MAX_SILENCE_FRAMES;

				for (i = 0; i< silence_frames; i++) {
					silence.status = status;
					g_array_append_val(rci->samples, silence);

					/* only mark the first in the silence that has the previous problem (S_DROP_BY_JITT or S_WRONG_SEQ) */
					status = S_NORMAL;
				}

				decoded_bytes_prev = 0;
				start_timestamp = rp->info->info_timestamp; /* defined start_timestamp to avoid overflow in timestamp. TODO: handle the timestamp correctly */
				start_rtp_time = 0;
				start_time = (double)rp->arrive_offset/1000;
				rtp_time_prev = 0;
			}
		} else {
			/* Add silence if it is necessary */
			silence_frames = (gint32)((rtp_time - rtp_time_prev)*SAMPLE_RATE - decoded_bytes_prev/2);
			if (silence_frames != 0) {
				rci->wrong_timestamp++;
				status = S_WRONG_TIMESTAMP;
			}

			/* Fix for bug 4119/5902: don't insert too many silence frames.
			 * XXX - is there a better thing to do here?
			 */
			if (silence_frames > MAX_SILENCE_FRAMES)
				silence_frames = MAX_SILENCE_FRAMES;

			for (i = 0; i< silence_frames; i++) {
				silence.status = status;
				g_array_append_val(rci->samples, silence);

				/* only mark the first in the silence that has the previous problem (S_DROP_BY_JITT or S_WRONG_SEQ) */
				status = S_NORMAL;
			}


			if (silence_frames > 0) {
				silence_frames = 0;
			}
			/* Add the audio */
			for (i = - silence_frames; i< (decoded_bytes/2); i++) {
				sample.val = out_buff[i];
				sample.status = status;
				g_array_append_val(rci->samples, sample);
				status = S_NORMAL;
			}

			rtp_time_prev = rtp_time;
			pack_period = (double)(decoded_bytes/2)/SAMPLE_RATE;
			decoded_bytes_prev = decoded_bytes;
			arrive_time_prev = arrive_time;
		}

		if (out_buff) {
			g_free(out_buff);
			out_buff = NULL;
		}
		rtp_packets_list = g_list_next (rtp_packets_list);
		progbar_count++;
	}
	rci->max_frame_index = rci->samples->len;
	rci->end_time = rci->start_time + ((double)rci->samples->len/SAMPLE_RATE)*1000;

	g_string_free(key_str, TRUE);
	g_hash_table_destroy(decoders_hash);
}

/****************************************************************************/
static gint
h_scrollbar_changed(GtkWidget *widget _U_, gpointer user_data)
{
	rtp_channel_info_t *rci = user_data;
	rci->cursor_catch = TRUE;
	return TRUE;
}

static gboolean draw_cursors(gpointer data);

/****************************************************************************/
static void
stop_channels(void)
{
	PaError err;
	GtkWidget *dialog;

	/* we should never be here if we are already in STOP */
	g_assert(rtp_channels->stop == FALSE);

	rtp_channels->stop = TRUE;
	/* force a draw_cursor to stop it */
	draw_cursors(NULL);

	err = Pa_StopStream(pa_stream);

	if( err != paNoError ) {
		dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
							  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
							  "Can not Stop Stream in PortAudio Library.\n Error: %s", Pa_GetErrorText( err ));
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		return;
	}

	err = Pa_CloseStream(pa_stream);
	if( err != paNoError ) {
		dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
							  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
							  "Can not Close Stream in PortAudio Library.\n Error: %s", Pa_GetErrorText( err ));
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		return;
	}
	pa_stream = NULL;	/* to catch errors better */

	rtp_channels->start_index[0] = 0;
	rtp_channels->start_index[1] = 0;
	rtp_channels->end_index[0] = 0;
	rtp_channels->end_index[1] = 0;
	rtp_channels->max_frame_index = 0;
	rtp_channels->frame_index = 0;
	rtp_channels->pause = FALSE;
	rtp_channels->pause_duration = 0;
	rtp_channels->stop = TRUE;
	rtp_channels->out_diff_time = 10000;

	if (rtp_channels->rci[0]) rtp_channels->rci[0]->frame_index = 0;
	if (rtp_channels->rci[1]) rtp_channels->rci[1]->frame_index = 0;

	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(TRUE, TRUE, FALSE, FALSE);

}

/****************************************************************************/
/* Draw a cursor in a channel graph
 */
static void
draw_channel_cursor(rtp_channel_info_t *rci, guint32 start_index)
{
#if PORTAUDIO_API_1
	PaTimestamp idx;
#else /* PORTAUDIO_API_1 */
	PaTime idx;
#endif /* PORTAUDIO_API_1 */
	int i;
	GtkAllocation widget_alloc;
	cairo_t *cr;

	if (!rci) return;

#if PORTAUDIO_API_1
	idx = Pa_StreamTime( pa_stream ) - rtp_channels->pause_duration - rtp_channels->out_diff_time - start_index;
#else  /* PORTAUDIO_API_1 */
	idx = ((guint32)(SAMPLE_RATE) * (Pa_GetStreamTime(pa_stream)-rtp_channels->pa_start_time))- rtp_channels->pause_duration - rtp_channels->out_diff_time - start_index;
#endif  /* PORTAUDIO_API_1 */


	/* If we finished playing both channels, then stop them */
	if ( (rtp_channels && (!rtp_channels->stop) && (!rtp_channels->pause)) && (idx > rtp_channels->max_frame_index) ) {
		stop_channels();
		return;
	}

	/* If only this channel finished, then return */
	if (idx > rci->max_frame_index) {
		return;
	}

	gtk_widget_get_allocation(rci->draw_area, &widget_alloc);
	/* draw the previous saved pixbuf line */
	if (rci->cursor_pixbuf && (rci->cursor_prev>=0)) {

#if GTK_CHECK_VERSION(2,22,0)
		cr = cairo_create (rci->surface);
#else
		cr = gdk_cairo_create (rci->pixmap);
#endif
		gdk_cairo_set_source_pixbuf (cr, rci->cursor_pixbuf, 0, 0);
		cairo_pattern_set_extend (cairo_get_source (cr), CAIRO_EXTEND_REPEAT);
		cairo_rectangle (cr, rci->cursor_prev/MULT, 0, -1, -1);
		cairo_fill (cr);

#if GTK_CHECK_VERSION(2,22,0)
		cairo_set_source_surface (cr, rci->surface, idx/MULT, 0); 
#else
		gdk_cairo_set_source_pixmap (cr, rci->pixmap,idx/MULT, 0);
#endif
		cairo_pattern_set_extend (cairo_get_source (cr), CAIRO_EXTEND_REPEAT);
		cairo_rectangle (cr, rci->cursor_prev/MULT, 0, 1, widget_alloc.height-HEIGHT_TIME_LABEL);
		cairo_fill (cr);
		cairo_destroy (cr);

		g_object_unref(rci->cursor_pixbuf);
		rci->cursor_pixbuf = NULL;
	}

	if (idx>0 && (rci->cursor_prev>=0)) {
#if GTK_CHECK_VERSION(2,22,0)
		rci->cursor_pixbuf = gdk_pixbuf_get_from_surface (rci->surface,0, 0, 1, widget_alloc.height-HEIGHT_TIME_LABEL);
		cr = cairo_create (rci->surface);
#else
		rci->cursor_pixbuf = gdk_pixbuf_get_from_drawable(NULL, rci->pixmap, NULL, (int) (idx/MULT), 0, 0, 0, 1, widget_alloc.height-HEIGHT_TIME_LABEL);
		cr = gdk_cairo_create (rci->pixmap);
#endif
		cairo_set_line_width (cr, 1.0);
		cairo_move_to(cr, idx/MULT, 0);
		cairo_line_to(cr, idx/MULT, widget_alloc.height-HEIGHT_TIME_LABEL);
		cairo_stroke(cr);
		cairo_destroy(cr);

		cr = gdk_cairo_create (gtk_widget_get_window(rci->draw_area));
#if GTK_CHECK_VERSION(2,22,0)
		cairo_set_source_surface (cr, rci->surface, idx/MULT, 0);
#else
		gdk_cairo_set_source_pixmap (cr, rci->pixmap, idx/MULT, 0);
#endif
		cairo_pattern_set_extend (cairo_get_source (cr), CAIRO_EXTEND_REPEAT);
		cairo_rectangle (cr, idx/MULT, 0, 1, widget_alloc.height-HEIGHT_TIME_LABEL);
		cairo_fill (cr);
		cairo_destroy (cr);
	}

	/* Disconnect the scroll bar "value" signal to not be called */
	g_signal_handlers_disconnect_by_func(rci->h_scrollbar_adjustment, h_scrollbar_changed, rci);

	/* Move the horizontal scroll bar */
#if 0
	if ( (rci->cursor_prev/MULT < (rci->h_scrollbar_adjustment->value+rci->h_scrollbar_adjustment->page_increment)) &&
		(idx/MULT >= (rci->h_scrollbar_adjustment->value+rci->h_scrollbar_adjustment->page_increment)) ){
		for (i=1; i<10; i++) {
			rci->h_scrollbar_adjustment->value += rci->h_scrollbar_adjustment->page_size/10;
			gtk_adjustment_value_changed(rci->h_scrollbar_adjustment);
		}
	}
#endif
	if (!rci->cursor_catch) {
		if (idx/MULT < gtk_adjustment_get_page_size(rci->h_scrollbar_adjustment)/2) {
			gtk_adjustment_set_value(rci->h_scrollbar_adjustment, gtk_adjustment_get_lower(rci->h_scrollbar_adjustment));
		} else if (idx/MULT > (gtk_adjustment_get_upper(rci->h_scrollbar_adjustment) - gtk_adjustment_get_page_size(rci->h_scrollbar_adjustment)/2)) {
			gtk_adjustment_set_value(rci->h_scrollbar_adjustment, gtk_adjustment_get_upper(rci->h_scrollbar_adjustment) - gtk_adjustment_get_page_size(rci->h_scrollbar_adjustment));
		} else {
			gtk_adjustment_set_value(rci->h_scrollbar_adjustment, idx/MULT - gtk_adjustment_get_page_size(rci->h_scrollbar_adjustment)/2);
		}

		gtk_adjustment_value_changed(rci->h_scrollbar_adjustment);
	} else if ( (rci->cursor_prev/MULT < gtk_adjustment_get_value(rci->h_scrollbar_adjustment)+gtk_adjustment_get_page_increment(rci->h_scrollbar_adjustment)) &&
		(idx/MULT >= gtk_adjustment_get_value(rci->h_scrollbar_adjustment) + gtk_adjustment_get_page_increment(rci->h_scrollbar_adjustment)) ){
		rci->cursor_catch = FALSE;
		for (i=1; i<10; i++) {
			gtk_adjustment_set_value(rci->h_scrollbar_adjustment, MIN(gtk_adjustment_get_upper(rci->h_scrollbar_adjustment)-gtk_adjustment_get_page_size(rci->h_scrollbar_adjustment), gtk_adjustment_get_value(rci->h_scrollbar_adjustment) + gtk_adjustment_get_page_size(rci->h_scrollbar_adjustment)/20));
			gtk_adjustment_value_changed(rci->h_scrollbar_adjustment);
		}
	}

	/* Connect back the "value" scroll signal */
	g_signal_connect(rci->h_scrollbar_adjustment, "value_changed", G_CALLBACK(h_scrollbar_changed), rci);

#if 0
	if (idx/MULT < rci->h_scrollbar_adjustment->page_increment) {
		rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->lower;
	} else if (idx/MULT > (rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size + rci->h_scrollbar_adjustment->page_increment)) {
		rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size;
	} else {
		if ( (idx/MULT < rci->h_scrollbar_adjustment->value) || (idx/MULT > (rci->h_scrollbar_adjustment->value+rci->h_scrollbar_adjustment->page_increment)) ){
			rci->h_scrollbar_adjustment->value = idx/MULT;
		}
	}
#endif

#if 0
	if (idx/MULT < rci->h_scrollbar_adjustment->page_size/2) {
		rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->lower;
	} else if (idx/MULT > (rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size/2)) {
		rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size;
	} else {
		rci->h_scrollbar_adjustment->value = idx/MULT - rci->h_scrollbar_adjustment->page_size/2;
	}
#endif

#if 0
	gtk_adjustment_value_changed(rci->h_scrollbar_adjustment);
#endif
	rci->cursor_prev = idx;
}

/****************************************************************************/
/* Move and draw the cursor in the graph
 */
static gboolean
draw_cursors(gpointer data _U_)
{
	if (!rtp_channels) return FALSE;

	/* Draw and move each of the two channels */
	draw_channel_cursor(rtp_channels->rci[0], rtp_channels->start_index[0]);
	draw_channel_cursor(rtp_channels->rci[1], rtp_channels->start_index[1]);

	if ((rtp_channels->stop) || (rtp_channels->pause)) return FALSE;

	return TRUE;
}

/****************************************************************************/
static void
init_rtp_channels_vals(void)
{
	rtp_play_channels_t *rpci = rtp_channels;

	/* if we only have one channel to play, we just use the info from that channel */
	if (rpci->rci[0] == NULL) {
		rpci->max_frame_index = rpci->rci[1]->max_frame_index;
		rpci->start_index[0] = rpci->max_frame_index;
		rpci->start_index[1] = 0;
		rpci->end_index[0] = rpci->max_frame_index;
		rpci->end_index[1] = rpci->max_frame_index;
	} else if (rpci->rci[1] == NULL) {
		rpci->max_frame_index = rpci->rci[0]->max_frame_index;
		rpci->start_index[1] = rpci->max_frame_index;
		rpci->start_index[0] = 0;
		rpci->end_index[0] = rpci->max_frame_index;
		rpci->end_index[1] = rpci->max_frame_index;

	/* if the two channels are to be played, then we need to sync both based on the start/end time of each one */
	} else {
		rpci->max_frame_index = (guint32)(SAMPLE_RATE/1000) * (guint32)(MAX(rpci->rci[0]->end_time, rpci->rci[1]->end_time) -
							(guint32)MIN(rpci->rci[0]->start_time, rpci->rci[1]->start_time));

		if (rpci->rci[0]->start_time < rpci->rci[1]->start_time) {
			rpci->start_index[0] = 0;
			rpci->start_index[1] = (guint32)(SAMPLE_RATE/1000) * (guint32)(rpci->rci[1]->start_time - rpci->rci[0]->start_time);
		} else {
			rpci->start_index[1] = 0;
			rpci->start_index[0] = (guint32)(SAMPLE_RATE/1000) * (guint32)(rpci->rci[0]->start_time - rpci->rci[1]->start_time);
		}

		if (rpci->rci[0]->end_time < rpci->rci[1]->end_time) {
			rpci->end_index[0] = rpci->max_frame_index - ((guint32)(SAMPLE_RATE/1000) * (guint32)(rpci->rci[1]->end_time - rpci->rci[0]->end_time));
			rpci->end_index[1] = rpci->max_frame_index;
		} else {
			rpci->end_index[1] = rpci->max_frame_index - ((guint32)(SAMPLE_RATE/1000) * (guint32)(rpci->rci[0]->end_time - rpci->rci[1]->end_time));
			rpci->end_index[0] = rpci->max_frame_index;
		}
	}
}


/****************************************************************************/
/* This routine will be called by the PortAudio engine when audio is needed.
 * It may called at interrupt level on some machines so don't do anything
 * that could mess up the system like calling malloc() or free().
 */
#if PORTAUDIO_API_1

static int paCallback(   void *inputBuffer, void *outputBuffer,
			 unsigned long framesPerBuffer,
			 PaTimestamp outTime, void *userData)
{
#else /* PORTAUDIO_API_1 */
static int paCallback( const void *inputBuffer, void *outputBuffer,
		       unsigned long framesPerBuffer,
		       const PaStreamCallbackTimeInfo* outTime,
		       PaStreamCallbackFlags statusFlags _U_,
		       void *userData)
{
#endif /* PORTAUDIO_API_1 */
	rtp_play_channels_t *rpci = (rtp_play_channels_t *)userData;
	SAMPLE *wptr = (SAMPLE*)outputBuffer;
	sample_t sample;
	unsigned int i;
	int finished;
	unsigned int framesLeft;
	int framesToPlay;

	/* if it is pasued, we keep the stream running but with silence only */
	if (rtp_channels->pause) {
		for(i=0; i<framesPerBuffer; i++ ) {
			*wptr++ = 0;
			*wptr++ = 0;
		}
		rtp_channels->pause_duration += framesPerBuffer;
		return 0;
	}

#if PORTAUDIO_API_1
	rpci->out_diff_time = outTime -  Pa_StreamTime(pa_stream) ;
#else /* PORTAUDIO_API_1 */
	rpci->out_diff_time = (guint32)(SAMPLE_RATE) * (outTime->outputBufferDacTime - Pa_GetStreamTime(pa_stream)) ;
#endif /* PORTAUDIO_API_1 */


	/* set the values if this is the first time */
	if (rpci->max_frame_index == 0) {
		init_rtp_channels_vals();

	}

	framesLeft = rpci->max_frame_index - rpci->frame_index;

	(void) inputBuffer; /* Prevent unused variable warnings. */
	(void) outTime;

	if( framesLeft < framesPerBuffer )
	{
		framesToPlay = framesLeft;
		finished = 1;
	}
	else
	{
		framesToPlay = framesPerBuffer;
		finished = 0;
	}

	for( i=0; i<(unsigned int)framesToPlay; i++ )
	{
		if (rpci->rci[0] && ( (rpci->frame_index >= rpci->start_index[0]) && (rpci->frame_index <= rpci->end_index[0]) )) {
			sample = g_array_index(rpci->rci[0]->samples, sample_t, rpci->rci[0]->frame_index++);
			*wptr++ = sample.val;
		} else {
			*wptr++ = 0;
		}

		if (rpci->rci[1] && ( (rpci->frame_index >= rpci->start_index[1]) && (rpci->frame_index <= rpci->end_index[1]) )) {
			sample = g_array_index(rpci->rci[1]->samples, sample_t, rpci->rci[1]->frame_index++);
			*wptr++ = sample.val;
		} else {
			*wptr++ = 0;
		}
	}
	for( ; i<framesPerBuffer; i++ )
	{
		*wptr++ = 0;
		*wptr++ = 0;
	}
	rpci->frame_index += framesToPlay;

	return finished;
}

/****************************************************************************/
static void
on_bt_check_clicked(GtkButton *button _U_, gpointer user_data)
{
	rtp_channel_info_t *rci = user_data;

	if (rci->selected) {
		if (rtp_channels->rci[0] == rci) {
			rtp_channels->rci[0] = NULL;
			rtp_channels->channel = 0;
		} else {
			rtp_channels->rci[1] = NULL;
			rtp_channels->channel = 1;
		}
	} else {
		/* if there are already both channels selected, unselect the old one */
		if (rtp_channels->rci[rtp_channels->channel]) {
			/* we disconnect the signal temporarly to avoid been called back */
			g_signal_handlers_disconnect_by_func(rtp_channels->rci[rtp_channels->channel]->check_bt, on_bt_check_clicked, rtp_channels->rci[rtp_channels->channel]);
			gtk_toggle_button_set_active((GtkToggleButton *)rtp_channels->rci[rtp_channels->channel]->check_bt, FALSE);
			g_signal_connect(rtp_channels->rci[rtp_channels->channel]->check_bt, "clicked", G_CALLBACK(on_bt_check_clicked), rtp_channels->rci[rtp_channels->channel]);
			rtp_channels->rci[rtp_channels->channel]->selected = FALSE;
		}

		rtp_channels->rci[rtp_channels->channel] = rci;
		rtp_channels->channel = !(rtp_channels->channel);
	}

	rci->selected = !(rci->selected);

	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(TRUE, TRUE, FALSE, FALSE);
}

/****************************************************************************/
static void channel_draw(rtp_channel_info_t* rci)
{
	int i, imax;
	int j;
	sample_t sample;
	SAMPLE min, max;
	PangoLayout  *small_layout;
	guint32 label_width, label_height;
	char label_string[MAX_TIME_LABEL];
	double offset;
	guint32 progbar_nextstep;
	int progbar_quantum;
	gfloat progbar_val;
	guint status;
	GdkColor red_color = {0, 65535, 0, 0};
	GdkColor amber_color = {0, 65535, 49152, 0};
	GdkColor white_color = {0, 65535, 65535, 65535};
	GdkColor black_color = {0, 0, 0, 0};

	GdkColor *draw_color_p;
	time_t seconds;
	struct tm *timestamp;
	GtkAllocation widget_alloc;
	cairo_t *cr;

#if GTK_CHECK_VERSION(2,22,0)
	gtk_widget_get_allocation(rci->draw_area, &widget_alloc);
	/* Clear out old plot */
	cr = cairo_create (rci->surface);
	gdk_cairo_set_source_color (cr, &rci->bg_color[1+rci->call_num%MAX_NUM_COL_CONV]);
	cairo_rectangle (cr, 0, 0, widget_alloc.width,widget_alloc.height);
	cairo_fill (cr);
	cairo_destroy (cr);
	cr = NULL;

	small_layout = gtk_widget_create_pango_layout(rci->draw_area, NULL);
	pango_layout_set_font_description(small_layout, pango_font_description_from_string("Helvetica,Sans,Bold 7"));

	/* calculated the pixel offset to display integer seconds */
	offset = ((double)rci->start_time/1000 - floor((double)rci->start_time/1000))*SAMPLE_RATE/MULT;

	cr = cairo_create (rci->surface);
	cairo_set_line_width (cr, 1.0);
	cairo_move_to(cr, 0, widget_alloc.height-HEIGHT_TIME_LABEL+0.5);
	cairo_line_to(cr, widget_alloc.width, widget_alloc.height-HEIGHT_TIME_LABEL+0.5);
	cairo_stroke(cr);
	cairo_destroy(cr);
	cr = NULL;

	imax = MIN(widget_alloc.width,(gint)(rci->samples->len/MULT));

	/* we update the progress bar 100 times */

	/* Update the progress bar when it gets to this value. */
	progbar_nextstep = 0;
	/* When we reach the value that triggers a progress bar update,
	   bump that value by this amount. */
	progbar_quantum = imax/100;

	for (i=0; i< imax; i++) {
		sample.val = 0;
		status = S_NORMAL;
		max=(SAMPLE)0xFFFF;
		min=(SAMPLE)0x7FFF;

		if (progbar_count >= progbar_nextstep) {
			g_assert(total_frames > 0);

			progbar_val = (gfloat) i / imax;

			update_progress_bar(progbar_val);

			progbar_nextstep += progbar_quantum;
		}

		for (j=0; j<MULT; j++) {
			sample = g_array_index(rci->samples, sample_t, i*MULT+j);
			max = MAX(max, sample.val);
			min = MIN(min, sample.val);
			if (sample.status == S_DROP_BY_JITT) status = S_DROP_BY_JITT;
			if (sample.status == S_WRONG_TIMESTAMP) status = S_WRONG_TIMESTAMP;
			if (sample.status == S_SILENCE) status = S_SILENCE;
		}

		/* Set the line color, default is black */
		if (status == S_DROP_BY_JITT) {
			draw_color_p = &red_color;
		} else if (status == S_WRONG_TIMESTAMP) {
			draw_color_p = &amber_color;
		} else if (status == S_SILENCE) {
			draw_color_p = &white_color;
		} else {
			draw_color_p = &black_color;				
		}

		/* if silence added by Wireshark, graphically show it with letter to indicate why */
		if ((status == S_DROP_BY_JITT) || (status == S_WRONG_TIMESTAMP) || (status == S_SILENCE)) {
			cr = cairo_create (rci->surface);
			cairo_set_line_width (cr, 1.0);
			gdk_cairo_set_source_color (cr, draw_color_p);
			cairo_move_to(cr, i+0.5, 0);
			cairo_line_to(cr, i+0.5, (widget_alloc.height-HEIGHT_TIME_LABEL)-1);
			cairo_stroke(cr);
			cairo_destroy(cr);
			cr=NULL;

			if (status == S_DROP_BY_JITT) g_snprintf(label_string, MAX_TIME_LABEL,"D");
			if (status == S_WRONG_TIMESTAMP) g_snprintf(label_string, MAX_TIME_LABEL, "W");
			if (status == S_SILENCE) g_snprintf(label_string, MAX_TIME_LABEL, "S");

			pango_layout_set_text(small_layout, label_string, -1);
			pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
			cr = cairo_create (rci->surface);
			gdk_cairo_set_source_color (cr, draw_color_p);
			cairo_move_to (cr, i, 0);
			pango_cairo_show_layout (cr, small_layout);
			cairo_destroy (cr);
			cr = NULL;
		} else {
			/* Draw a graphical representation of the sample */
			cr = cairo_create (rci->surface);
			cairo_set_line_width (cr, 1.0);
			gdk_cairo_set_source_color (cr, draw_color_p);
			cairo_move_to(cr, i+0.5, ( (0x7FFF+min) * (widget_alloc.height-HEIGHT_TIME_LABEL))/0xFFFF);
			cairo_line_to(cr, i+0.5, ( (0x7FFF+max) * (widget_alloc.height-HEIGHT_TIME_LABEL))/0xFFFF);
			cairo_stroke(cr);
			cairo_destroy(cr);
		}

		/* Draw the x-axis (seconds since beginning of packet flow for this call) */

		/* Draw tick mark and put a number for each whole second */
		if ( !((i*MULT)%(SAMPLE_RATE)) ) {
			cr = cairo_create (rci->surface);
			cairo_set_line_width (cr, 1.0);
			cairo_move_to(cr, i - offset+0.5, widget_alloc.height-HEIGHT_TIME_LABEL);
			cairo_line_to(cr, i+0.5, widget_alloc.height-HEIGHT_TIME_LABEL+4);
			cairo_stroke(cr);
			cairo_destroy(cr);
			cr=NULL;

			if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_view_as_time_of_day))) {
				seconds = rci->start_time_abs.secs + i * MULT / SAMPLE_RATE;
				timestamp = localtime(&seconds);
				g_snprintf(label_string, MAX_TIME_LABEL, "%02d:%02d:%02d", timestamp->tm_hour, timestamp->tm_min, timestamp->tm_sec);
			} else {
				g_snprintf(label_string, MAX_TIME_LABEL, "%.0f s", floor(rci->start_time/1000) + i*MULT/SAMPLE_RATE);
			}

			pango_layout_set_text(small_layout, label_string, -1);
			pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
			cr = cairo_create (rci->surface);
			cairo_move_to (cr, i - offset - label_width/2, widget_alloc.height - label_height);
			pango_cairo_show_layout (cr, small_layout);
			cairo_destroy (cr);
			cr = NULL;


		/* Draw only a tick mark for half second intervals */
		} else if ( !((i*MULT)%(SAMPLE_RATE/2)) ) {
			cr = cairo_create (rci->surface);
			cairo_set_line_width (cr, 1.0);
			cairo_move_to(cr,i - offset+0.5, widget_alloc.height-HEIGHT_TIME_LABEL);
			cairo_line_to(cr, (i - offset)+0.5, widget_alloc.height-HEIGHT_TIME_LABEL+2);
			cairo_stroke(cr);
			cairo_destroy(cr);
			cr=NULL;
		}

		progbar_count++;
	}
	g_object_unref(G_OBJECT(small_layout));
#else
	if (GDK_IS_DRAWABLE(rci->pixmap)) {
		gtk_widget_get_allocation(rci->draw_area, &widget_alloc);
		/* Clear out old plot */
		cr = gdk_cairo_create (rci->pixmap);
		gdk_cairo_set_source_color (cr, &rci->bg_color[1+rci->call_num%MAX_NUM_COL_CONV]);
		cairo_rectangle (cr, 0, 0, widget_alloc.width,widget_alloc.height);
		cairo_fill (cr);
		cairo_destroy (cr);
		cr = NULL;

		small_layout = gtk_widget_create_pango_layout(rci->draw_area, NULL);
		pango_layout_set_font_description(small_layout, pango_font_description_from_string("Helvetica,Sans,Bold 7"));

		/* calculated the pixel offset to display integer seconds */
		offset = ((double)rci->start_time/1000 - floor((double)rci->start_time/1000))*SAMPLE_RATE/MULT;

		cr = gdk_cairo_create (rci->pixmap);
		cairo_set_line_width (cr, 1.0);
		cairo_move_to(cr, 0, widget_alloc.height-HEIGHT_TIME_LABEL+0.5);
		cairo_line_to(cr, widget_alloc.width, widget_alloc.height-HEIGHT_TIME_LABEL+0.5);
		cairo_stroke(cr);
		cairo_destroy(cr);
		cr = NULL;

		imax = MIN(widget_alloc.width,(gint)(rci->samples->len/MULT));

		/* we update the progress bar 100 times */

		/* Update the progress bar when it gets to this value. */
		progbar_nextstep = 0;
		/* When we reach the value that triggers a progress bar update,
		   bump that value by this amount. */
		progbar_quantum = imax/100;

		for (i=0; i< imax; i++) {
			sample.val = 0;
			status = S_NORMAL;
			max=(SAMPLE)0xFFFF;
			min=(SAMPLE)0x7FFF;

			if (progbar_count >= progbar_nextstep) {
				g_assert(total_frames > 0);

				progbar_val = (gfloat) i / imax;

				update_progress_bar(progbar_val);

				progbar_nextstep += progbar_quantum;
			}

			for (j=0; j<MULT; j++) {
				sample = g_array_index(rci->samples, sample_t, i*MULT+j);
				max = MAX(max, sample.val);
				min = MIN(min, sample.val);
				if (sample.status == S_DROP_BY_JITT) status = S_DROP_BY_JITT;
				if (sample.status == S_WRONG_TIMESTAMP) status = S_WRONG_TIMESTAMP;
				if (sample.status == S_SILENCE) status = S_SILENCE;
			}

			/* Set the line color, default is black */
			if (status == S_DROP_BY_JITT) {
				draw_color_p = &red_color;
			} else if (status == S_WRONG_TIMESTAMP) {
				draw_color_p = &amber_color;
			} else if (status == S_SILENCE) {
				draw_color_p = &white_color;
			} else {
				draw_color_p = &black_color;				
			}

			/* if silence added by Wireshark, graphically show it with letter to indicate why */
			if ((status == S_DROP_BY_JITT) || (status == S_WRONG_TIMESTAMP) || (status == S_SILENCE)) {
				cr = gdk_cairo_create (rci->pixmap);
				cairo_set_line_width (cr, 1.0);
				gdk_cairo_set_source_color (cr, draw_color_p);
				cairo_move_to(cr, i+0.5, 0);
				cairo_line_to(cr, i+0.5, (widget_alloc.height-HEIGHT_TIME_LABEL)-1);
				cairo_stroke(cr);
				cairo_destroy(cr);
				cr=NULL;

				if (status == S_DROP_BY_JITT) g_snprintf(label_string, MAX_TIME_LABEL,"D");
				if (status == S_WRONG_TIMESTAMP) g_snprintf(label_string, MAX_TIME_LABEL, "W");
				if (status == S_SILENCE) g_snprintf(label_string, MAX_TIME_LABEL, "S");

				pango_layout_set_text(small_layout, label_string, -1);
				pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
				cr = gdk_cairo_create (rci->pixmap);
				gdk_cairo_set_source_color (cr, draw_color_p);
				cairo_move_to (cr, i, 0);
				pango_cairo_show_layout (cr, small_layout);
				cairo_destroy (cr);
				cr = NULL;
			} else {
				/* Draw a graphical representation of the sample */
				cr = gdk_cairo_create (rci->pixmap);
				cairo_set_line_width (cr, 1.0);
				gdk_cairo_set_source_color (cr, draw_color_p);
				cairo_move_to(cr, i+0.5, ( (0x7FFF+min) * (widget_alloc.height-HEIGHT_TIME_LABEL))/0xFFFF);
				cairo_line_to(cr, i+0.5, ( (0x7FFF+max) * (widget_alloc.height-HEIGHT_TIME_LABEL))/0xFFFF);
				cairo_stroke(cr);
				cairo_destroy(cr);
			}

			/* Draw the x-axis (seconds since beginning of packet flow for this call) */

			/* Draw tick mark and put a number for each whole second */
			if ( !((i*MULT)%(SAMPLE_RATE)) ) {
				cr = gdk_cairo_create (rci->pixmap);
				cairo_set_line_width (cr, 1.0);
				cairo_move_to(cr, i - offset+0.5, widget_alloc.height-HEIGHT_TIME_LABEL);
				cairo_line_to(cr, i+0.5, widget_alloc.height-HEIGHT_TIME_LABEL+4);
				cairo_stroke(cr);
				cairo_destroy(cr);
				cr=NULL;

				if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_view_as_time_of_day))) {
					seconds = rci->start_time_abs.secs + i * MULT / SAMPLE_RATE;
					timestamp = localtime(&seconds);
					g_snprintf(label_string, MAX_TIME_LABEL, "%02d:%02d:%02d", timestamp->tm_hour, timestamp->tm_min, timestamp->tm_sec);
				} else {
					g_snprintf(label_string, MAX_TIME_LABEL, "%.0f s", floor(rci->start_time/1000) + i*MULT/SAMPLE_RATE);
				}

				pango_layout_set_text(small_layout, label_string, -1);
				pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
				cr = gdk_cairo_create (rci->pixmap);
				cairo_move_to (cr, i - offset - label_width/2, widget_alloc.height - label_height);
				pango_cairo_show_layout (cr, small_layout);
				cairo_destroy (cr);
				cr = NULL;


			/* Draw only a tick mark for half second intervals */
			} else if ( !((i*MULT)%(SAMPLE_RATE/2)) ) {
				cr = gdk_cairo_create (rci->pixmap);
				cairo_set_line_width (cr, 1.0);
				cairo_move_to(cr,i - offset+0.5, widget_alloc.height-HEIGHT_TIME_LABEL);
				cairo_line_to(cr, (i - offset)+0.5, widget_alloc.height-HEIGHT_TIME_LABEL+2);
				cairo_stroke(cr);
				cairo_destroy(cr);
				cr=NULL;
			}

			progbar_count++;
		}
		g_object_unref(G_OBJECT(small_layout));
	}
#endif

}
/****************************************************************************/
static gboolean expose_event_channels(GtkWidget *widget, GdkEventExpose *event, gpointer user_data)
{
	rtp_channel_info_t *rci = user_data;
	cairo_t *cr;

	if (gtk_widget_is_drawable(widget)){
		cr = gdk_cairo_create (gtk_widget_get_window(widget));
#if GTK_CHECK_VERSION(2,22,0)
		cairo_set_source_surface (cr, rci->surface, 0, 0); 
#else
		gdk_cairo_set_source_pixmap (cr, rci->pixmap, event->area.x, event->area.y);
#endif
		cairo_rectangle (cr, event->area.x,event->area.y, event->area.width, event->area.height);
		cairo_fill (cr);
		cairo_destroy(cr);
		cr = NULL;
	}

	return FALSE;
}

/****************************************************************************/
static gboolean
configure_event_channels(GtkWidget *widget, GdkEventConfigure *event _U_, gpointer user_data)
{
	rtp_channel_info_t *rci = user_data;
	int i;
	GtkAllocation widget_alloc;
	cairo_t *cr;

	/* the first color is blue to highlight the selected item
	 * the other collors are the same as in the Voip Graph analysys
	 * to match the same calls
	 */
	static GdkColor col[MAX_NUM_COL_CONV+1] = {
		{0,	0x00FF, 0x00FF, 0xFFFF},
		{0,	0x90FF, 0xEEFF, 0x90FF},
		{0,	0xFFFF, 0xA0FF, 0x7AFF},
		{0,	0xFFFF, 0xB6FF, 0xC1FF},
		{0,	0xFAFF, 0xFAFF, 0xD2FF},
		{0,	0xFFFF, 0xFFFF, 0x33FF},
		{0,	0x66FF, 0xCDFF, 0xAAFF},
		{0,	0xE0FF, 0xFFFF, 0xFFFF},
		{0,	0xB0FF, 0xC4FF, 0xDEFF},
		{0,	0x87FF, 0xCEFF, 0xFAFF},
		{0,	0xD3FF, 0xD3FF, 0xD3FF}
	};

#if GTK_CHECK_VERSION(2,22,0)
	if(rci->surface){
		cairo_surface_destroy (rci->surface);
		rci->surface=NULL;
	}
	gtk_widget_get_allocation(widget, &widget_alloc);
	rci->surface = gdk_window_create_similar_surface (gtk_widget_get_window(widget),
			CAIRO_CONTENT_COLOR,
			widget_alloc.width,
			widget_alloc.height);

	cr = cairo_create (rci->surface);
	cairo_set_source_rgb (cr, 1, 1, 1);
	cairo_rectangle (cr, 0, 0, widget_alloc.width,widget_alloc.height);
	cairo_fill (cr);
	cairo_destroy (cr);
#else
	if(rci->pixmap){
		g_object_unref(rci->pixmap);
		rci->pixmap=NULL;
	}
	gtk_widget_get_allocation(widget, &widget_alloc);
	rci->pixmap = gdk_pixmap_new(gtk_widget_get_window(widget),
					widget_alloc.width,
					widget_alloc.height,
					-1);
	if ( GDK_IS_DRAWABLE(rci->pixmap) ){
		cr = gdk_cairo_create (rci->pixmap);
		cairo_set_source_rgb (cr, 1, 1, 1);
		cairo_rectangle (cr, 0, 0, widget_alloc.width,widget_alloc.height);
		cairo_fill (cr);
		cairo_destroy (cr);
	}
#endif

	/* create gc's for the background color of each channel */
	for (i=0; i<MAX_NUM_COL_CONV+1; i++){
		rci->bg_color[i].pixel=col[i].pixel;
		rci->bg_color[i].red=col[i].red;
		rci->bg_color[i].green=col[i].green;
		rci->bg_color[i].blue=col[i].blue;

	}

	channel_draw(rci);

	return TRUE;
}

/****************************************************************************/
static gboolean
button_press_event_channel(GtkWidget *widget _U_, GdkEventButton *event _U_, gpointer user_data)
{
	rtp_channel_info_t *rci = user_data;
	int this_channel;
	guint32 prev_index;

	if (!rci->selected) {

		/* only select a new channels if we are in STOP */
		if (!rtp_channels->stop) return 0;

		/* if there are already both channels selected, unselect the old one */
		if (rtp_channels->rci[rtp_channels->channel]) {
			/* we disconnect the signal temporarly to avoid been called back */
			g_signal_handlers_disconnect_by_func(rtp_channels->rci[rtp_channels->channel]->check_bt, on_bt_check_clicked, rtp_channels->rci[rtp_channels->channel]);
			gtk_toggle_button_set_active((GtkToggleButton *) rtp_channels->rci[rtp_channels->channel]->check_bt, FALSE);
			g_signal_connect(rtp_channels->rci[rtp_channels->channel]->check_bt, "clicked", G_CALLBACK(on_bt_check_clicked), rtp_channels->rci[rtp_channels->channel]);
			rtp_channels->rci[rtp_channels->channel]->selected = FALSE;
		}

		/* we disconnect the signal temporarly to avoid been called back */
		g_signal_handlers_disconnect_by_func(rci->check_bt, on_bt_check_clicked, rci);
		gtk_toggle_button_set_active((GtkToggleButton *) rci->check_bt, TRUE);
		g_signal_connect(rci->check_bt, "clicked", G_CALLBACK(on_bt_check_clicked), rci);

		rtp_channels->rci[rtp_channels->channel] = rci;
		rtp_channels->channel = !(rtp_channels->channel);
		rci->selected = TRUE;

		/* set the sensitive state of the buttons (decode, play, pause, stop) */
		bt_state(TRUE, TRUE, FALSE, FALSE);
	}

	if (rci == rtp_channels->rci[0]) {
		this_channel = 0;
	} else {
		this_channel = 1;
	}

	rci->frame_index = (unsigned int) (event->x * MULT);

	prev_index = rtp_channels->frame_index;
	rtp_channels->frame_index = rtp_channels->start_index[this_channel] + rci->frame_index;
	rtp_channels->pause_duration += prev_index - rtp_channels->frame_index;



	/* change the index in the other channel if selected, according with the index position */
	if (rtp_channels->rci[!this_channel]) {
		init_rtp_channels_vals();

		if (rtp_channels->frame_index < rtp_channels->start_index[!this_channel]) {
			rtp_channels->rci[!this_channel]->frame_index = 0;
		} else if (rtp_channels->frame_index > rtp_channels->end_index[!this_channel]) {
			rtp_channels->rci[!this_channel]->frame_index = rtp_channels->rci[!this_channel]->max_frame_index;
		} else {
			rtp_channels->rci[!this_channel]->frame_index = rtp_channels->frame_index - rtp_channels->start_index[!this_channel];
		}
	} else {
		init_rtp_channels_vals();
	}

	rtp_channels->out_diff_time = 0;

	rci->cursor_catch = TRUE;

	/* redraw the cusrsor */
	draw_cursors(NULL);

	return TRUE;
}

/****************************************************************************/
static void
add_channel_to_window(gchar *key _U_ , rtp_channel_info_t *rci, guint *counter _U_ )
{
	GString *label = NULL;
	GtkWidget *viewport;


	/* create the channel draw area */
	rci->draw_area=gtk_drawing_area_new();

	rci->scroll_window=gtk_scrolled_window_new(NULL, NULL);

	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (rci->scroll_window), GTK_POLICY_ALWAYS, GTK_POLICY_NEVER);
	rci->h_scrollbar_adjustment = gtk_scrolled_window_get_hadjustment(GTK_SCROLLED_WINDOW(rci->scroll_window));


	gtk_widget_set_size_request(rci->draw_area, (gint)(rci->samples->len/MULT), CHANNEL_HEIGHT);


	viewport = gtk_viewport_new(rci->h_scrollbar_adjustment, gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(rci->scroll_window)));
	gtk_container_add(GTK_CONTAINER(viewport), rci->draw_area);
	gtk_container_add(GTK_CONTAINER(rci->scroll_window), viewport);
	gtk_viewport_set_shadow_type(GTK_VIEWPORT(viewport), GTK_SHADOW_NONE);
	gtk_widget_add_events (rci->draw_area, GDK_BUTTON_PRESS_MASK);
#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_set_can_focus(rci->draw_area, TRUE);
#else
	GTK_WIDGET_SET_FLAGS(rci->draw_area, GTK_CAN_FOCUS);
#endif
	gtk_widget_grab_focus(rci->draw_area);

	gtk_box_pack_start(GTK_BOX (channels_vb), rci->scroll_window, FALSE, FALSE, 0);

	/* signals needed to handle backing pixmap */
	g_signal_connect(rci->draw_area, "expose_event", G_CALLBACK(expose_event_channels), rci);
	g_signal_connect(rci->draw_area, "configure_event", G_CALLBACK(configure_event_channels), rci);
	gtk_widget_add_events (rci->draw_area, GDK_BUTTON_PRESS_MASK);
	g_signal_connect(rci->draw_area, "button_press_event", G_CALLBACK(button_press_event_channel), rci);
	g_signal_connect(rci->h_scrollbar_adjustment, "value_changed", G_CALLBACK(h_scrollbar_changed), rci);


	label = g_string_new("");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cb_use_rtp_timestamp))) {
		g_string_printf(label, "From %s:%d to %s:%d   Duration:%.2f   Out of Seq: %d(%.1f%%)   Wrong Timestamp: %d(%.1f%%)",
		get_addr_name(&(rci->first_stream->src_addr)), rci->first_stream->src_port,
		get_addr_name(&(rci->first_stream->dest_addr)), rci->first_stream->dest_port,
		(double)rci->samples->len/SAMPLE_RATE,
		rci->out_of_seq, (double)rci->out_of_seq * 100 / (double)rci->num_packets,
		rci->wrong_timestamp, (double)rci->wrong_timestamp * 100 / (double)rci->num_packets);
	} else {
		g_string_printf(label, "From %s:%d to %s:%d   Duration:%.2f   Drop by Jitter Buff:%d(%.1f%%)   Out of Seq: %d(%.1f%%)   Wrong Timestamp: %d(%.1f%%)",
		get_addr_name(&(rci->first_stream->src_addr)), rci->first_stream->src_port,
		get_addr_name(&(rci->first_stream->dest_addr)), rci->first_stream->dest_port,
		(double)rci->samples->len/SAMPLE_RATE,
		rci->drop_by_jitter_buff, (double)rci->drop_by_jitter_buff * 100 / (double)rci->num_packets,
		rci->out_of_seq, (double)rci->out_of_seq * 100 / (double)rci->num_packets,
		rci->wrong_timestamp, (double)rci->wrong_timestamp * 100 / (double)rci->num_packets);
	}

	rci->check_bt = gtk_check_button_new_with_label(label->str);
	gtk_box_pack_start(GTK_BOX (channels_vb), rci->check_bt, FALSE, FALSE, 1);

	/* Create the Separator if it is not the last one */
	(*counter)++;
	if (*counter < g_hash_table_size(rtp_channels_hash)) {
	    rci->separator = gtk_hseparator_new();
		gtk_box_pack_start(GTK_BOX (channels_vb), rci->separator, FALSE, FALSE, 5);
	}

	g_signal_connect(rci->check_bt, "clicked", G_CALLBACK(on_bt_check_clicked), rci);

	g_string_free(label, TRUE);
}

/****************************************************************************/
static void
count_channel_frames(gchar *key _U_ , rtp_channel_info_t *rci, gpointer ptr _U_ )
{
	total_frames += rci->samples->len;
}

/****************************************************************************/
static void
play_channels(void)
{
	PaError err;
	GtkWidget *dialog;

	/* we should never be here if we are in PLAY and !PAUSE */
	g_assert(!rtp_channels->stop && !rtp_channels->pause);

	/* if we are in PAUSE change the state */
	if (rtp_channels->pause) {
		rtp_channels->pause = FALSE;
		/* set the sensitive state of the buttons (decode, play, pause, stop) */
		bt_state(FALSE, FALSE, TRUE, TRUE);

	/* if not PAUSE, then start to PLAY */
	} else {
#if PORTAUDIO_API_1
		err = Pa_OpenStream(
			  &pa_stream,
			  paNoDevice,     /* default input device */
			  0,              /* no input */
			  PA_SAMPLE_TYPE, /* 16 bit Integer input */
			  NULL,
			  Pa_GetDefaultOutputDeviceID(),
			  NUM_CHANNELS,   /* Stereo output */
			  PA_SAMPLE_TYPE, /* 16 bit Integer output */
			  NULL,
			  SAMPLE_RATE,    /* 8 kHz */
			  FRAMES_PER_BUFFER,
			  0,              /* number of buffers, if zero then use default minimum */
			  paClipOff,      /* we won't output out of range samples so don't bother clipping them */
			  paCallback,
			  rtp_channels );

		if( err != paNoError ) {
			const char *deviceName = "No Device";

			PaDeviceID device = Pa_GetDefaultOutputDeviceID();

			if (device != paNoDevice)
			{
				const PaDeviceInfo* deviceInfo = Pa_GetDeviceInfo( device );
				if (deviceInfo)
					deviceName = deviceInfo->name;
				else
					deviceName = "(No device info)";
			}

			dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
							  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
							  "Got this info from PortAudio Library:\n"
							  " Default deviceName: %s (%d)", deviceName, device);
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);

			dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
								  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
								  "Can not Open Stream in PortAudio Library.\n Error: %s", Pa_GetErrorText( err ));
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
			return;
		}
#else /* PORTAUDIO_API_1 */
		if (Pa_GetDefaultOutputDevice() != paNoDevice) {
			err = Pa_OpenDefaultStream(
				&pa_stream,
				0,
				NUM_CHANNELS,     /* Stereo output */
				PA_SAMPLE_TYPE,   /* 16 bit Integer output */
				SAMPLE_RATE,      /* 8 kHz */
				FRAMES_PER_BUFFER,
				paCallback,
				rtp_channels );
		} else {
			/* If the Default Host API doesn't even provide a device
			 * we might as well go look for another.
			 */
			PaHostApiIndex host_api_count = Pa_GetHostApiCount();
			PaHostApiIndex default_host_api_index = Pa_GetDefaultHostApi();

			PaHostApiIndex host_api_index;
			const PaHostApiInfo *host_api_info;

			for (host_api_index=0; host_api_index<host_api_count; host_api_index++)
			{
				/* Skip the default host API, that didn't work before */
				if (host_api_index == default_host_api_index)
					continue;

				/* If we find a host API with a device, then take it. */
				host_api_info = Pa_GetHostApiInfo(host_api_index);
				if (host_api_info->deviceCount > 0)
					break;
			}

			if (host_api_index<host_api_count)
			{
				PaStreamParameters stream_parameters;
				stream_parameters.device = host_api_info->defaultOutputDevice;
				stream_parameters.channelCount = NUM_CHANNELS;       /* Stereo output */
				stream_parameters.sampleFormat = PA_SAMPLE_TYPE;     /* 16 bit Integer output */
				stream_parameters.suggestedLatency = 0;
				stream_parameters.hostApiSpecificStreamInfo = NULL;
#ifdef DEBUG
				g_print("Trying Host API: %s\n", host_api_info->name);
#endif
				err = Pa_OpenStream(
					&pa_stream,
					NULL,           /* no input */
					&stream_parameters,
					SAMPLE_RATE,    /* 8 kHz */
					FRAMES_PER_BUFFER,
					paClipOff,      /* we won't output out of range samples so don't bother clipping them */
					paCallback,
					rtp_channels );
			}
			else
			{
				err = paNoDevice;
			}
		}

		if( err != paNoError ) {
			PaHostApiIndex hostApi = Pa_GetDefaultHostApi();
			if (hostApi < 0)
			{
				dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
								  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
								  "Can not even get the default host API from PortAudio Library.\n Error: %s",
								  Pa_GetErrorText( hostApi ));
				gtk_dialog_run (GTK_DIALOG (dialog));
				gtk_widget_destroy (dialog);
			}
			else
			{
				const PaHostApiInfo *hostApiInfo = Pa_GetHostApiInfo( hostApi );

				if ( !hostApiInfo )
				{
					dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
									  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
									  "Can not even get the host API info from PortAudio Library.");
					gtk_dialog_run (GTK_DIALOG (dialog));
					gtk_widget_destroy (dialog);
				}
				else
				{
					const char *hostApiName = hostApiInfo->name;
					const char *deviceName = "No Device";

					PaDeviceIndex device = hostApiInfo->defaultOutputDevice;

					if (device != paNoDevice)
					{
						const PaDeviceInfo* deviceInfo = Pa_GetDeviceInfo( device );
						if (deviceInfo)
							deviceName = deviceInfo->name;
						else
							deviceName = "(No device info)";
					}

					dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
									  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
									  "Got this info from PortAudio Library:\n"
									  " Default hostApiName: %s\n"
									  " Default deviceName: %s (%d)", hostApiName, deviceName, device);
					gtk_dialog_run (GTK_DIALOG (dialog));
					gtk_widget_destroy (dialog);
				}
			}

			dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
								  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
								  "Can not Open Stream in PortAudio Library.\n Error: %s", Pa_GetErrorText( err ));
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
			return;
		}
#endif

		err = Pa_StartStream( pa_stream );
		if( err != paNoError ) {
			dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
								  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
								  "Can not Start Stream in PortAudio Library.\n Error: %s", Pa_GetErrorText( err ));
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
			return;
		}
#if !PORTAUDIO_API_1
		rtp_channels->pa_start_time = Pa_GetStreamTime(pa_stream);
#endif /* PORTAUDIO_API_1 */

		rtp_channels->stop = FALSE;

		/* set the sensitive state of the buttons (decode, play, pause, stop) */
		bt_state(FALSE, FALSE, TRUE, TRUE);
	}

	/* Draw the cursor in the graph */
	g_timeout_add_full(G_PRIORITY_DEFAULT_IDLE, MULT*1000/SAMPLE_RATE, draw_cursors, NULL, NULL);

}

/****************************************************************************/
static void
pause_channels(void)
{
	rtp_channels->pause = !(rtp_channels->pause);

	/* reactivate the cusrosr display if no in pause */
	if (!rtp_channels->pause) {
		/* Draw the cursor in the graph */
		g_timeout_add_full(G_PRIORITY_DEFAULT_IDLE, MULT*1000/SAMPLE_RATE, draw_cursors, NULL, NULL);
	}

	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(FALSE, TRUE, FALSE, TRUE);
}

/****************************************************************************/
static void
reset_rtp_channels(void)
{
	rtp_channels->channel = 0;
	rtp_channels->rci[0] = NULL;
	rtp_channels->rci[1] = NULL;
	rtp_channels->start_index[0] = 0;
	rtp_channels->start_index[1] = 0;
	rtp_channels->end_index[0] = 0;
	rtp_channels->end_index[1] = 0;
	rtp_channels->max_frame_index = 0;
	rtp_channels->frame_index = 0;
	rtp_channels->pause = FALSE;
	rtp_channels->pause_duration = 0;
	rtp_channels->stop = TRUE;
	rtp_channels->out_diff_time = 10000;
}

/****************************************************************************/
static void
remove_channel_to_window(gchar *key _U_ , rtp_channel_info_t *rci, gpointer ptr _U_ )
{
#if GTK_CHECK_VERSION(2,22,0)
	if(rci->surface){
		 cairo_surface_destroy (rci->surface);
		rci->surface=NULL;
	}
#else
	g_object_unref(rci->pixmap);
#endif
	gtk_widget_destroy(rci->draw_area);
	gtk_widget_destroy(rci->scroll_window);
	gtk_widget_destroy(rci->check_bt);
	if (rci->separator)
		gtk_widget_destroy(rci->separator);
}

/****************************************************************************/
static void
reset_channels(void)
{

	if (rtp_channels_hash) {
		/* Remove the channels from the main window if there are there */
		g_hash_table_foreach( rtp_channels_hash, (GHFunc)remove_channel_to_window, NULL);


		/* destroy the rtp channels hash table */
		g_hash_table_destroy(rtp_channels_hash);
		rtp_channels_hash = NULL;
	}

	if (rtp_channels) {
		reset_rtp_channels();
	}
}

/****************************************************************************/
void
reset_rtp_player(void)
{
	/* Destroy the rtp channels */
	reset_channels();

	/* destroy the rtp streams hash table */
	if (rtp_streams_hash) {
		g_hash_table_destroy(rtp_streams_hash);
		rtp_streams_hash = NULL;
	}

	/* destroy the rtp streams list */
	if (rtp_streams_list) {
		g_list_free (rtp_streams_list);
		rtp_streams_list = NULL;
	}

}

/****************************************************************************/
static void
decode_streams(void)
{
	guint statusbar_context;
	guint counter;

	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(FALSE, FALSE, FALSE, FALSE);

	reset_channels();

	progress_bar = gtk_progress_bar_new();
	gtk_widget_set_size_request(progress_bar, 100, -1);
	gtk_box_pack_start(GTK_BOX (stat_hbox), progress_bar, FALSE, FALSE, 2);
	gtk_widget_show(progress_bar);
	statusbar_context = gtk_statusbar_get_context_id((GtkStatusbar *) info_bar, "main");
	gtk_statusbar_push((GtkStatusbar *) info_bar, statusbar_context, "  Decoding RTP packets...");

#if !GTK_CHECK_VERSION(3,0,0)
	gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(info_bar), FALSE);
#endif
	/* reset the number of packet to be decoded, this is used for the progress bar */
	total_packets = 0;
	/* reset the Progress Bar count */
	progbar_count = 0;

	/* Mark the RTP streams to be played using the selected VoipCalls. If voip_calls is NULL
	   then this was called from "RTP Analysis" so mark all strams */
	if (rtp_streams_hash) {
		if (voip_calls)
			g_hash_table_foreach( rtp_streams_hash, (GHFunc)mark_rtp_stream_to_play, NULL);
		else
			g_hash_table_foreach( rtp_streams_hash, (GHFunc)mark_all_rtp_stream_to_play, NULL);
	}

	/* Decode the RTP streams and add them to the RTP channels to be played */
	g_list_foreach( rtp_streams_list, (GFunc)decode_rtp_stream, NULL);

	/* reset the number of frames to be displayed, this is used for the progress bar */
	total_frames = 0;
	/* Count the frames in all the RTP channels */
	if (rtp_channels_hash)
		g_hash_table_foreach( rtp_channels_hash, (GHFunc)count_channel_frames, NULL);

	/* reset the Progress Bar count again for the progress of creating the channels view */
	progbar_count = 0;
	gtk_statusbar_pop((GtkStatusbar *) info_bar, statusbar_context);
	gtk_statusbar_push((GtkStatusbar *) info_bar, statusbar_context, "  Creating channels view...");

	/* Display the RTP channels in the window */
	counter = 0;
	if (rtp_channels_hash)
		g_hash_table_foreach( rtp_channels_hash, (GHFunc)add_channel_to_window, &counter);

	/* Resize the main scroll window to display no more than preferred (or default) max channels, scroll bar will be used if needed */

	if (prefs.rtp_player_max_visible < 1 || prefs.rtp_player_max_visible > 10)
		prefs.rtp_player_max_visible = RTP_PLAYER_DEFAULT_VISIBLE;

	gtk_widget_set_size_request(main_scrolled_window, CHANNEL_WIDTH,
		MIN(counter, prefs.rtp_player_max_visible) * (CHANNEL_HEIGHT+60));

	gtk_widget_show_all(main_scrolled_window);

	gtk_widget_destroy(progress_bar);
#if !GTK_CHECK_VERSION(3,0,0)
	gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(info_bar), TRUE);
#endif
	gtk_statusbar_pop((GtkStatusbar *) info_bar, statusbar_context);

	/* blank the status label */
	gtk_statusbar_pop((GtkStatusbar *) info_bar, statusbar_context);

	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(TRUE, FALSE, FALSE, FALSE);

	/* get the static jitter buffer from the spinner gui */
	new_jitter_buff = (int) gtk_spin_button_get_value((GtkSpinButton * )jitter_spinner);

}

/****************************************************************************/
static void
on_cb_view_as_time_of_day_clicked(GtkButton *button _U_, gpointer user_data _U_)
{
	/* Decode the streams again as if the decode button was pushed to update the time display */
	decode_streams();
}

/****************************************************************************/
static void
on_cb_use_rtp_clicked(GtkToggleButton  *button _U_, gpointer user_data _U_)
{
	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(TRUE, FALSE, FALSE, FALSE);
}

/****************************************************************************/
static void
on_bt_decode_clicked(GtkButton *button _U_, gpointer user_data _U_)
{
	decode_streams();
}

/****************************************************************************/
static void
on_bt_play_clicked(GtkButton *button _U_, gpointer user_data _U_)
{
	play_channels();
}

/****************************************************************************/
static void
on_bt_pause_clicked(GtkButton *button _U_, gpointer user_data _U_)
{
	pause_channels();
}

/****************************************************************************/
static void
on_bt_stop_clicked(GtkButton *button _U_, gpointer user_data _U_)
{
	stop_channels();
}

/****************************************************************************/
static void
rtp_player_on_destroy(GObject *object _U_, gpointer user_data _U_)
{
	PaError err;
	GtkWidget *dialog;

	/* Stop the channels if necesary */
	if(rtp_channels && (!rtp_channels->stop)){
		stop_channels();
	}

	/* Destroy the rtp channels */
	reset_channels();

	g_free(rtp_channels);
	rtp_channels = NULL;

	/* Terminate the use of PortAudio library */
	err = Pa_Terminate();
	initialized = FALSE;
	if( err != paNoError ) {
		dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
							  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
							  "Can not terminate the PortAudio Library.\n Error: %s", Pa_GetErrorText( err ));
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
	}

	gtk_widget_destroy(rtp_player_dlg_w);
	main_scrolled_window = NULL;
	rtp_player_dlg_w = NULL;
}

/****************************************************************************/
static void
jitter_spinner_value_changed (GtkSpinButton *spinner _U_, gpointer user_data _U_)
{
	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(TRUE, TRUE, FALSE, FALSE);
}

/****************************************************************************/
static void
rtp_player_dlg_create(void)
{
	GtkWidget *main_vb;
	GtkWidget *hbuttonbox;
	GtkWidget *timestamp_hb;
	GtkWidget *h_jitter_buttons_box;
	GtkWidget *bt_close;
	GtkAdjustment *jitter_spinner_adj;
	GtkWidget *label;
	const gchar *title_name_ptr;
	gchar   *win_name;

	title_name_ptr = cf_get_display_name(&cfile);
	win_name = g_strdup_printf("%s - VoIP - RTP Player", title_name_ptr);

	rtp_player_dlg_w = dlg_window_new(win_name);  /* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(rtp_player_dlg_w), TRUE);
	gtk_window_set_position(GTK_WINDOW(rtp_player_dlg_w), GTK_WIN_POS_NONE);

	gtk_window_set_default_size(GTK_WINDOW(rtp_player_dlg_w), 400, 50);

	main_vb = gtk_vbox_new (FALSE, 0);
	gtk_container_add(GTK_CONTAINER(rtp_player_dlg_w), main_vb);
	gtk_container_set_border_width (GTK_CONTAINER (main_vb), 2);

	main_scrolled_window=gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width (GTK_CONTAINER (main_scrolled_window), 4);
	gtk_widget_set_size_request(main_scrolled_window, CHANNEL_WIDTH, 0);

	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (main_scrolled_window), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(main_vb), main_scrolled_window);

	channels_vb = gtk_vbox_new (FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (channels_vb), 2);
	gtk_scrolled_window_add_with_viewport((GtkScrolledWindow *) main_scrolled_window, channels_vb);

	timestamp_hb = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(main_vb), timestamp_hb, FALSE, FALSE, 0);
	cb_view_as_time_of_day = gtk_check_button_new_with_label("View as time of day");
	gtk_box_pack_start(GTK_BOX(timestamp_hb), cb_view_as_time_of_day, TRUE, FALSE, 0); /* Centered */
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb_view_as_time_of_day), FALSE);
	gtk_widget_set_tooltip_text(cb_view_as_time_of_day, "View the timestamps as time of day instead of seconds since beginning of capture");
	g_signal_connect(cb_view_as_time_of_day, "toggled", G_CALLBACK(on_cb_view_as_time_of_day_clicked), NULL);

	h_jitter_buttons_box = gtk_hbox_new (FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (h_jitter_buttons_box), 10);
	gtk_box_pack_start (GTK_BOX(main_vb), h_jitter_buttons_box, FALSE, FALSE, 0);
	label = gtk_label_new("Jitter buffer [ms] ");
	gtk_box_pack_start(GTK_BOX(h_jitter_buttons_box), label, FALSE, FALSE, 0);

	jitter_spinner_adj = (GtkAdjustment *) gtk_adjustment_new (50, 0, 500, 5, 10, 0);
	jitter_spinner = gtk_spin_button_new (jitter_spinner_adj, 5, 0);
	gtk_box_pack_start(GTK_BOX(h_jitter_buttons_box), jitter_spinner, FALSE, FALSE, 0);
	gtk_widget_set_tooltip_text (jitter_spinner, "The simulated jitter buffer in [ms]");
	g_signal_connect(G_OBJECT (jitter_spinner_adj), "value_changed", G_CALLBACK(jitter_spinner_value_changed), NULL);

	cb_use_rtp_timestamp = gtk_check_button_new_with_label("Use RTP timestamp");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cb_use_rtp_timestamp), FALSE);
	gtk_box_pack_start(GTK_BOX(h_jitter_buttons_box), cb_use_rtp_timestamp, FALSE, FALSE, 10);
	g_signal_connect(cb_use_rtp_timestamp, "toggled", G_CALLBACK(on_cb_use_rtp_clicked), NULL);
	gtk_widget_set_tooltip_text (cb_use_rtp_timestamp, "Use RTP Timestamp instead of the arriving packet time. This will not reproduce the RTP stream as the user heard it, but is useful when the RTP is being tunneled and the original packet timing is missing");

	/* button row */
	hbuttonbox = gtk_hbutton_box_new ();
	gtk_box_pack_start (GTK_BOX (h_jitter_buttons_box), hbuttonbox, TRUE, TRUE, 0);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_SPREAD);
	gtk_box_set_spacing (GTK_BOX (hbuttonbox), 10);

	bt_decode = gtk_button_new_from_stock(WIRESHARK_STOCK_DECODE);
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_decode);
	g_signal_connect(bt_decode, "clicked", G_CALLBACK(on_bt_decode_clicked), NULL);
	gtk_widget_set_tooltip_text (bt_decode, "Decode the RTP stream(s)");

	bt_play = gtk_button_new_from_stock(GTK_STOCK_MEDIA_PLAY);
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_play);
	g_signal_connect(bt_play, "clicked", G_CALLBACK(on_bt_play_clicked), NULL);
	gtk_widget_set_tooltip_text (bt_play, "Play the RTP channel(s)");

	bt_pause = gtk_button_new_from_stock(GTK_STOCK_MEDIA_PAUSE);
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_pause);
	g_signal_connect(bt_pause, "clicked", G_CALLBACK(on_bt_pause_clicked), NULL);
	gtk_widget_set_tooltip_text (bt_pause, "Pause the RTP channel(s)");

	bt_stop = gtk_button_new_from_stock(GTK_STOCK_MEDIA_STOP);
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_stop);
	g_signal_connect(bt_stop, "clicked", G_CALLBACK(on_bt_stop_clicked), NULL);
	gtk_widget_set_tooltip_text (bt_stop, "Stop the RTP channel(s)");

	bt_close = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_close);
#if GTK_CHECK_VERSION(2,18,0)
	gtk_widget_set_can_default(bt_close, TRUE);
#else
	GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);
#endif
	gtk_widget_set_tooltip_text (bt_close, "Close this dialog");
	window_set_cancel_button(rtp_player_dlg_w, bt_close, window_cancel_button_cb);

	g_signal_connect(rtp_player_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(rtp_player_dlg_w, "destroy", G_CALLBACK(rtp_player_on_destroy), NULL);

	/* button row */
	hbuttonbox = gtk_hbutton_box_new ();

	/* Filter/status hbox */
	stat_hbox = gtk_hbox_new(FALSE, 1);
	gtk_container_set_border_width(GTK_CONTAINER(stat_hbox), 0);

	/* statusbar */
	info_bar = gtk_statusbar_new();
#if !GTK_CHECK_VERSION(3,0,0)
	gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(info_bar), TRUE);
#endif
	gtk_box_pack_start(GTK_BOX(stat_hbox), info_bar, TRUE, TRUE, 0);

	/* statusbar hbox */
	gtk_box_pack_start(GTK_BOX(main_vb), stat_hbox, FALSE, TRUE, 0);

	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(TRUE, FALSE, FALSE, FALSE);

	gtk_widget_show_all(rtp_player_dlg_w);

	/* Force gtk to redraw the window before starting decoding the packet */
	while (g_main_context_iteration(NULL, FALSE));

	g_free(win_name);
}

/****************************************************************************/
void
rtp_player_init(voip_calls_tapinfo_t *voip_calls_tap)
{
	PaError err;
	GtkWidget *dialog;

	if (initialized) return;
	initialized = TRUE;

	voip_calls = voip_calls_tap;
	err = Pa_Initialize();
	if( err != paNoError ) {
		dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
						 GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
						 "Can not Initialize the PortAudio Library.\n Error: %s", Pa_GetErrorText( err ));
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		initialized = FALSE;
		return;
	}

	new_jitter_buff = -1;

#ifdef HAVE_G729_G723
	/* Initialize the G729 and G723 decoders */
	initG723();
	initG729();
#endif /* HAVE_G729_G723 */

	if (!rtp_channels) {
		rtp_channels = g_malloc(sizeof(rtp_play_channels_t));
	}

	reset_rtp_channels();

#ifdef DEBUG
	g_print("Pa_GetHostApiCount() = %d\n", Pa_GetHostApiCount());
	g_print("Pa_GetDefaultHostApi() = %d\n", Pa_GetDefaultHostApi());

	if ((Pa_GetHostApiCount() >= 0) && (Pa_GetDefaultHostApi() >= 0))
	{
		unsigned int i;
		PaHostApiIndex api_index;
		const PaHostApiInfo *api_info = Pa_GetHostApiInfo( (unsigned int)Pa_GetDefaultHostApi() );
		g_print("Default PaHostApiInfo.type = %d (%s)\n", api_info->type, api_info->name);

		for (i=0; i<(unsigned int)Pa_GetHostApiCount(); i++)
		{
			api_info = Pa_GetHostApiInfo( i );
			g_print("PaHostApiInfo[%u].type = %d (%s)\n", i, api_info->type, api_info->name);
		}

		api_index = Pa_HostApiTypeIdToHostApiIndex( paALSA );
		if (api_index < 0)
		{
			g_print("api_index for paALSA not found (%d)\n", api_index);
		}
		else
		{
			api_info = Pa_GetHostApiInfo( (unsigned int)api_index );
			g_print("This should be ALSA: %s\n", api_info->name);
		}
	}
#endif

	/* create the dialog window */
	rtp_player_dlg_create();

}

#endif /* HAVE_LIBPORTAUDIO */
