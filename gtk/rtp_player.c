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
 *    create the RTP stream if it is the  first RTP in the stream.
 *  - Each new RTP stream will be added to a list of RTP stream, called
 *    rtp_streams_list
 *  - When the user clicks "Player" in the VoipCall dialogue,
 *    rtp_player_init() is called.
 *  - rtp_player_init() create the main dialog, and it calls:
 *    + mark_rtp_stream_to_play() to mark the RTP streams that needs to be
 *      displayed. These are the RTP stream that match the selected calls in
 *      the VoipCall dlg.
 *    + decode_rtp_stream() this will decode the RTP packets in each RTP
 *      stream, and will also create  the RTP channles. An RTP channel is a
 *      group of RTP stream that have in common the source and destination
 *      IP and UPD ports. The RTP channels is what the user will listen in
 *      one of the two Audio channles. 
 *      The RTP channels are stored in the hash table rtp_channels_hash
 *    + add_channel_to_window() will create and add the Audio graphic
 *      representation in the main window
 *  - When the user click the check box to listen one of the Audio channels,
 *    the structure rtp_channels is filled  to play one or two RTP channels
 *    (a max of two channels can be listened at a given moment)
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBPORTAUDIO

#include <epan/stats_tree.h>
#include <epan/addr_resolv.h>
#include <string.h>
#include <glib.h>
#include <gtk/gtk.h>
#include "globals.h"
#include "portaudio.h"
#include "simple_dialog.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "compat_macros.h"

#include "graph_analysis.h"
#include "voip_calls_dlg.h"
#include "voip_calls.h"
#include "gtkglobals.h"


#include <epan/dissectors/packet-rtp.h>

#include "rtp_player.h"
#include "codecs/G711a/G711adecode.h"
#include "codecs/G711u/G711udecode.h"
#include <math.h>

#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif

/*define this symbol to compile with G729 and G723 codecs*/
/*#define HAVE_G729_G723 1*/

#ifdef HAVE_G729_G723
#include "codecs/G729/G729decode.h"
#include "codecs/G723/G723decode.h"
#endif /* HAVE_G729_G723 */

static gboolean initialized = FALSE;

voip_calls_tapinfo_t *voip_calls = NULL;

/* Hash table with all the RTP streams */
static GHashTable*  rtp_streams_hash = NULL;

/* List with all the RTP streams (this is used to decode them as it is sorted)*/
static GList*  rtp_streams_list = NULL;

/* the window */
static GtkWidget *rtp_player_dlg_w;
static GtkWidget *channels_vb;
static GtkWidget *main_scrolled_window = NULL;
static GtkWidget *jitter_spinner;
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

/* Port Audio staff */
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

/* Display channels constants */
#define MULT 80
#define CHANNEL_WIDTH 500
#define CHANNEL_HEIGHT 100
#define MAX_TIME_LABEL 10
#define HEIGHT_TIME_LABEL 18
#define MAX_NUM_COL_CONV 10

#if PORTAUDIO_API_1
PortAudioStream *pa_stream;
#else /* PORTAUDIO_API_1 */
PaStream *pa_stream;
#endif /* PORTAUDIO_API_1 */

/* TODO: The RTP Player it is only supported for GTK >=2 */
#if GTK_MAJOR_VERSION >= 2

/* defines a RTP stream */
typedef struct _rtp_stream_info {
	address src_addr;
	guint16 src_port;
	address dest_addr;
	guint16 dest_port;
	guint32 ssrc;
	guint32 first_frame_number; /* first RTP frame for the stream */
	double start_time;			/* RTP stream start time in ms */
	gboolean play;
	guint16 call_num;
	GList*  rtp_packets_list; /* List of RTP packets in the stream */
	guint32 num_packets;
} rtp_stream_info_t;


/* defines the RTP streams to be played in an audio channel */
typedef struct _rtp_channel_info {
	double start_time;			/* RTP stream start time in ms */
	double end_time;			/* RTP stream end time in ms */
	GArray *samples;			/* the array with decoded audio */
	guint16 call_num;
	gboolean selected;
	guint32 frame_index;
	guint32 drop_by_jitter_buff;
	guint32 out_of_seq;
	guint32 max_frame_index;
	GtkWidget *check_bt;
	GtkWidget *separator;
	GtkWidget *scroll_window;
	GtkWidget *draw_area;
	GdkPixmap *pixmap;
	GtkAdjustment *h_scrollbar_adjustment;
	GdkPixbuf* cursor_pixbuf;
#if PORTAUDIO_API_1
	PaTimestamp cursor_prev;
#else /* PORTAUDIO_API_1 */
	PaTime cursor_prev;
#endif /* PORTAUDIO_API_1 */
	GdkGC *bg_gc[MAX_NUM_COL_CONV+1];
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
} rtp_play_channles_t;

/* The two RTP channles to play */
static rtp_play_channles_t *rtp_channels = NULL;


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
	g_free(rsi);
	rsi = NULL;
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
	gtk_widget_set_sensitive(jitter_spinner, decode);
		
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

	/* create the the streams hash if it doen't exist */
	if (!rtp_streams_hash)
		rtp_streams_hash = g_hash_table_new_full( g_str_hash, g_str_equal, rtp_key_destroy, rtp_stream_value_destroy);

	/* Create a hash key to lookup in the RTP streams hash table
	 * uses: src_ip:src_port dst_ip:dst_port ssrc
	 */
	key_str = g_string_new("");
	g_string_printf(key_str, "%s:%d %s:%d %d", get_addr_name(&(pinfo->src)),
		pinfo->srcport, get_addr_name(&(pinfo->dst)),
		pinfo->destport, rtp_info->info_sync_src );

	/* lookup for this rtp packet in the stream hash table*/
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
		stream_info->call_num = 0;
		stream_info->play = FALSE;
		stream_info->num_packets = 0;

		g_hash_table_insert(rtp_streams_hash, g_strdup(key_str->str), stream_info);

		/* Add the element to the List too. The List is used to decode the packets because it is sordted */
		rtp_streams_list = g_list_append(rtp_streams_list, stream_info);
	}

	/* increment the number of packets in this stream, this is used for the progress bar and statistics*/
	stream_info->num_packets++;

	/* Add the RTP packet to the list */
	new_rtp_packet = g_malloc(sizeof(rtp_packet_t));
	new_rtp_packet->info = g_malloc(sizeof(struct _rtp_info));

	memcpy(new_rtp_packet->info, rtp_info, sizeof(struct _rtp_info));
	new_rtp_packet->arrive_offset = nstime_to_msec(&pinfo->fd->rel_ts) - stream_info->start_time;
	/* copy the RTP payload to the rtp_packet to be decoded later */
	if (rtp_info->info_payload_len) {
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
	 * and the streams are nor reset in that case
	 */
	rsi->play = FALSE;

	/* and associate the RTP stream with a call using the first RTP in the stream*/
	graph_list = g_list_first(voip_calls->graph_analysis->list);
	while (graph_list)
	{
		graph_item = graph_list->data;
		if (rsi->first_frame_number == graph_item->frame_num) {
			rsi->call_num = graph_item->conv_num;
			/* if it is in the graph list, then check if the voip_call is selected */
			voip_calls_list = g_list_first(voip_calls->strinfo_list);
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
/* Decode a RTP packet 
 * Return the number of decoded bytes
 */
static int 
decode_rtp_packet(rtp_packet_t *rp, rtp_channel_info_t *rci, SAMPLE **out_buff)
{
	unsigned int  payload_type;
	SAMPLE *tmp_buff = NULL;
	int decoded_bytes = 0;

	if ((rp->payload_data == NULL) || (rp->info->info_payload_len == 0) ) {
		return 0;
	}

	payload_type = rp->info->info_payload_type;
	switch (payload_type) {
	case 0:	/* G711 Ulaw */
		tmp_buff = malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 1);
		decodeG711u(rp->payload_data, rp->info->info_payload_len,
			  tmp_buff, &decoded_bytes);
		break; 
	case 8:	/* G711 Alaw */
		tmp_buff = malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 1);
		decodeG711a(rp->payload_data, rp->info->info_payload_len,
			  tmp_buff, &decoded_bytes);
		break; 
#ifdef HAVE_G729_G723
	case 18:	/* G729 */
		tmp_buff = malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 8); /* G729 8kbps => 64kbps/8kbps = 8  */
		decodeG729(rp->payload_data, rp->info->info_payload_len,
			  tmp_buff, &decoded_bytes);
		break; 
	case 4:	/* G723 */

		if (rp->info->info_payload_len%24 == 0)	/* G723 High 6.4kbps */
			tmp_buff = malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 10); /* G723 High 64kbps/6.4kbps = 10  */	
		else if (rp->info->info_payload_len%20 == 0)    /* G723 Low 5.3kbps */
			tmp_buff = malloc(sizeof(SAMPLE) * rp->info->info_payload_len * 13); /* G723 High 64kbps/5.3kbps = 13  */	
		else {
		  return 0;
		}
		decodeG723(rp->payload_data, rp->info->info_payload_len,
			  tmp_buff, &decoded_bytes);
		break;
#endif /* HAVE_G729_G723 */
	} 

	*out_buff = tmp_buff;
	return decoded_bytes;
}

/****************************************************************************/
static void
update_progress_bar(gfloat percentage)
{

	gtk_progress_bar_update(GTK_PROGRESS_BAR(progress_bar), percentage);

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
	double start_rtp_time;
	double diff;
	double pack_period;
	double total_time;
	double total_time_prev;
	gint32 silence_frames;
	int seq;
	double delay;
	double prev_diff;
	double mean_delay;
	double variation;
	int decoded_bytes;
	int decoded_bytes_prev;
	int jitter_buff;
	SAMPLE *out_buff = NULL;
	sample_t silence;
	sample_t sample;
	guint8 status;
	guint32 start_timestamp; 

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
		rci = malloc(sizeof(rtp_channel_info_t));
		rci->call_num = rsi->call_num;
		rci->start_time = rsi->start_time;
		rci->end_time = rsi->start_time;		
		rci->selected = FALSE;
		rci->frame_index = 0;
		rci->drop_by_jitter_buff = 0;
		rci->out_of_seq = 0;
		rci->max_frame_index = 0;
		rci->samples = g_array_new (FALSE, FALSE, sizeof(sample_t));
		rci->check_bt = NULL;
		rci->separator = NULL;
		rci->draw_area = NULL;
		rci->pixmap = NULL;
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
	decoded_bytes = 0;
	decoded_bytes_prev = 0;
	silence_frames = 0;
	arrive_time = start_time = 0;
	arrive_time_prev = 0;
	pack_period = 0;
	total_time = 0;
	total_time_prev = 0;
	seq = 0;
	delay = 0;
	prev_diff = 0;
	mean_delay = 0;
	variation = 0;
	start_timestamp = 0;

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

		decoded_bytes = decode_rtp_packet(rp, rci, &out_buff);
		if (decoded_bytes == 0) {
			seq = rp->info->info_seq_num;
		}

		rtp_time = (double)(rp->info->info_timestamp-start_timestamp)/SAMPLE_RATE - start_rtp_time;
		arrive_time = (double)rp->arrive_offset/1000 - start_time;

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
  
		total_time = (double)rp->arrive_offset/1000;
		
		printf("seq = %d arr = %f abs_diff = %f index = %d tim = %f ji=%d jb=%f\n",rp->info->info_seq_num, 
			total_time, diff, rci->samples->len, ((double)rci->samples->len/8000 - total_time)*1000, 0,
				(mean_delay + 4*variation)*1000);
		fflush(stdout);

		/* if the jitter buffer was exceeded */	
		if ( diff*1000 > jitter_buff ) {
			printf("Packet drop by jitter buffer exceeded\n");
			rci->drop_by_jitter_buff++;
			status = S_DROP_BY_JITT;

			/* if there was a silence period (more than two packetization period) resync the source */
			if ( (rtp_time - rtp_time_prev) > pack_period*2 ){
				printf("Resync...\n");

				silence_frames = (gint32)((arrive_time - arrive_time_prev)*SAMPLE_RATE - decoded_bytes_prev/2);
				for (i = 0; i< silence_frames; i++) {
					silence.status = status;
					g_array_append_val(rci->samples, silence);

					/* only mark the fisrt in the silence that has the previos problem (S_DROP_BY_JITT  or S_WRONG_SEQ ) */
					status = S_NORMAL;
				}

				decoded_bytes_prev = 0;
				start_timestamp = rp->info->info_timestamp; /* defined start_timestmp to avoid overflow in timestamp. TODO: handle the timestamp correctly */
				start_rtp_time = 0;
				start_time = (double)rp->arrive_offset/1000;
				rtp_time_prev = 0;
			}
		} else {
			/* Add silence if it is necessary */
			silence_frames = (gint32)((rtp_time - rtp_time_prev)*SAMPLE_RATE - decoded_bytes_prev/2);
			for (i = 0; i< silence_frames; i++) {
				silence.status = status;
				g_array_append_val(rci->samples, silence);

				/* only mark the fisrt in the silence that has the previos problem (S_DROP_BY_JITT  or S_WRONG_SEQ ) */
				status = S_NORMAL;
			}

			status = S_NORMAL;

			/* Add the audio */
			for (i = 0; i< (decoded_bytes/2); i++) {
				sample.val = out_buff[i];
				sample.status = status;
				g_array_append_val(rci->samples, sample);
			}
	
			rtp_time_prev = rtp_time;
			pack_period = (double)(decoded_bytes/2)/SAMPLE_RATE;
			decoded_bytes_prev = decoded_bytes;
			arrive_time_prev = arrive_time;

		}

		rtp_packets_list = g_list_next (rtp_packets_list);
		progbar_count++;
	}
	rci->max_frame_index = rci->samples->len;
	rci->end_time = rci->start_time + ((double)rci->samples->len/SAMPLE_RATE)*1000;

	g_string_free(key_str, TRUE);
}

/****************************************************************************/
static gint 
h_scrollbar_changed(GtkWidget *widget _U_, gpointer user_data)
{
	rtp_channel_info_t *rci = (rtp_channel_info_t *)user_data;
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
	if(rtp_channels->stop){
		exit(10);
	}

	rtp_channels->stop = TRUE;
	/* force a draw_cursor to stop it */
	draw_cursors(NULL);

	err = Pa_StopStream(pa_stream);

	if( err != paNoError ) {
		dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
							  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
							  "Can not Stop Stream in PortAduio Library.\n Error: %s", Pa_GetErrorText( err ));
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		return;
	}

	err = Pa_CloseStream(pa_stream);
	if( err != paNoError ) {
		dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
							  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
							  "Can not Close Stream in PortAduio Library.\n Error: %s", Pa_GetErrorText( err ));
		gtk_dialog_run (GTK_DIALOG (dialog));
		gtk_widget_destroy (dialog);
		return;
	}

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
	PaTimestamp index;
#else /* PORTAUDIO_API_1 */
	PaTime index;
#endif /* PORTAUDIO_API_1 */
	int i;

	if (!rci) return;

#if PORTAUDIO_API_1
	index = Pa_StreamTime( pa_stream ) - rtp_channels->pause_duration - rtp_channels->out_diff_time - start_index;
#else  /* PORTAUDIO_API_1 */
	index = ((guint32)(SAMPLE_RATE) * (Pa_GetStreamTime(pa_stream)-rtp_channels->pa_start_time))- rtp_channels->pause_duration - rtp_channels->out_diff_time - start_index;
#endif  /* PORTAUDIO_API_1 */


	/* If we finished playing both channels, then stop them */
	if ( (rtp_channels && (!rtp_channels->stop) && (!rtp_channels->pause)) && (index > rtp_channels->max_frame_index) ) {
		stop_channels();
		return;
	}

	/* If only this channel finished, then return */
	if (index > rci->max_frame_index) {
		return;
	}

	/* draw the previous saved pixbuf line */
	if (rci->cursor_pixbuf && (rci->cursor_prev>=0)) {

		gdk_draw_pixbuf(rci->pixmap, NULL, rci->cursor_pixbuf, 0, 0, (int) (rci->cursor_prev/MULT), 0, -1, -1, GDK_RGB_DITHER_NONE, 0 ,0);

		gdk_draw_drawable(rci->draw_area->window,
			rci->draw_area->style->fg_gc[GTK_WIDGET_STATE(rci->draw_area)],
			rci->pixmap,
			(int) (rci->cursor_prev/MULT), 0,
			(int) (rci->cursor_prev/MULT), 0,
			1, rci->draw_area->allocation.height-HEIGHT_TIME_LABEL);

		g_object_unref(rci->cursor_pixbuf);
	}

	if (index>0 && (rci->cursor_prev>=0)) {
		rci->cursor_pixbuf = gdk_pixbuf_get_from_drawable(NULL, rci->pixmap, NULL, (int) (index/MULT), 0, 0, 0, 1, rci->draw_area->allocation.height-HEIGHT_TIME_LABEL);

		gdk_draw_line(rci->pixmap, rci->draw_area->style->black_gc,
			(int) (index/MULT),
			0,
			(int) (index/MULT),
			rci->draw_area->allocation.height-HEIGHT_TIME_LABEL);

		gdk_draw_drawable(rci->draw_area->window,
			rci->draw_area->style->fg_gc[GTK_WIDGET_STATE(rci->draw_area)],	
			rci->pixmap,
			(int) (index/MULT), 0,
			(int) (index/MULT), 0,
			1, rci->draw_area->allocation.height-HEIGHT_TIME_LABEL);
	}

	/* Disconnect the scroll bar "value" signal to not be called */
	SIGNAL_DISCONNECT_BY_FUNC(rci->h_scrollbar_adjustment, h_scrollbar_changed, rci);

	/* Move the horizontal scroll bar */
/*	if ( (rci->cursor_prev/MULT < (rci->h_scrollbar_adjustment->value+rci->h_scrollbar_adjustment->page_increment)) && 
		(index/MULT >= (rci->h_scrollbar_adjustment->value+rci->h_scrollbar_adjustment->page_increment)) ){		
		for (i=1; i<10; i++) {
			rci->h_scrollbar_adjustment->value += rci->h_scrollbar_adjustment->page_size/10;
			gtk_adjustment_value_changed(rci->h_scrollbar_adjustment);
		}

	}
 */
	if (!rci->cursor_catch) {
		if (index/MULT < rci->h_scrollbar_adjustment->page_size/2) {
			rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->lower;
		} else if (index/MULT > (rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size/2)) {
			rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size;
		} else {
			rci->h_scrollbar_adjustment->value = index/MULT - rci->h_scrollbar_adjustment->page_size/2;
		}

		gtk_adjustment_value_changed(rci->h_scrollbar_adjustment);
	} else if ( (rci->cursor_prev/MULT < (rci->h_scrollbar_adjustment->value+rci->h_scrollbar_adjustment->page_increment)) && 
		(index/MULT >= (rci->h_scrollbar_adjustment->value+rci->h_scrollbar_adjustment->page_increment)) ){	
		rci->cursor_catch = FALSE;
		for (i=1; i<10; i++) {
			rci->h_scrollbar_adjustment->value = min(rci->h_scrollbar_adjustment->upper-rci->h_scrollbar_adjustment->page_size, rci->h_scrollbar_adjustment->value + (rci->h_scrollbar_adjustment->page_size/20));
			gtk_adjustment_value_changed(rci->h_scrollbar_adjustment);
		}

	}


	/* Connect back the "value" scroll signal */
	SIGNAL_CONNECT(rci->h_scrollbar_adjustment, "value_changed", h_scrollbar_changed, rci);


/*	if (index/MULT < rci->h_scrollbar_adjustment->page_increment) {
		rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->lower;
	} else if (index/MULT > (rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size + rci->h_scrollbar_adjustment->page_increment)) {
		rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size;
	} else {
		if ( (index/MULT < rci->h_scrollbar_adjustment->value) || (index/MULT > (rci->h_scrollbar_adjustment->value+rci->h_scrollbar_adjustment->page_increment)) ){
			rci->h_scrollbar_adjustment->value = index/MULT;
		}
	}
 */

/*	if (index/MULT < rci->h_scrollbar_adjustment->page_size/2) {
		rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->lower;
	} else if (index/MULT > (rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size/2)) {
		rci->h_scrollbar_adjustment->value = rci->h_scrollbar_adjustment->upper - rci->h_scrollbar_adjustment->page_size;
	} else {
		rci->h_scrollbar_adjustment->value = index/MULT - rci->h_scrollbar_adjustment->page_size/2;
	}
 */
/*	gtk_adjustment_value_changed(rci->h_scrollbar_adjustment);
 */
	rci->cursor_prev = index;
}

/****************************************************************************/
/* Move and draw the cursor in the graph 
 */
static gboolean 
draw_cursors(gpointer data)
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
	rtp_play_channles_t *rpci = rtp_channels; 
	
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
		rpci->max_frame_index = (guint32)(SAMPLE_RATE/1000) * (guint32)(max(rpci->rci[0]->end_time, rpci->rci[1]->end_time) -
							(guint32)min(rpci->rci[0]->start_time, rpci->rci[1]->start_time));

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
static int paCallback( void *inputBuffer, void *outputBuffer,
                             unsigned long framesPerBuffer,
							 const PaStreamCallbackTimeInfo* outTime,
							 PaStreamCallbackFlags statusFlags,
                             void *userData)
{
/*	(void) statusFlags;*/
#endif /* PORTAUDIO_API_1 */
    rtp_play_channles_t *rpci = (rtp_play_channles_t*)userData;
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
on_bt_check_clicked(GtkButton *button _U_, gpointer user_data _U_)
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
			SIGNAL_DISCONNECT_BY_FUNC(rtp_channels->rci[rtp_channels->channel]->check_bt, on_bt_check_clicked, rtp_channels->rci[rtp_channels->channel]);
			gtk_toggle_button_set_active((GtkToggleButton *)rtp_channels->rci[rtp_channels->channel]->check_bt, FALSE);
			SIGNAL_CONNECT(rtp_channels->rci[rtp_channels->channel]->check_bt, "clicked", on_bt_check_clicked, rtp_channels->rci[rtp_channels->channel]);
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
	GdkGC *gc;
	GdkGC *red_gc;
	GdkColor red_color = {0, 65535, 0, 0};
	
	if (GDK_IS_DRAWABLE(rci->pixmap)) {
		/* Clear out old plot */
		gdk_draw_rectangle(rci->pixmap,
			rci->bg_gc[1+rci->call_num%MAX_NUM_COL_CONV],
			TRUE,
			0, 0,
			rci->draw_area->allocation.width,
			rci->draw_area->allocation.height);

		small_layout = gtk_widget_create_pango_layout(rci->draw_area, NULL);
		pango_layout_set_font_description(small_layout, pango_font_description_from_string("Helvetica,Sans,Bold 7"));

		/* calculated the pixel offset to display integer seconds */
		offset = ((double)rci->start_time/1000 - floor((double)rci->start_time/1000))*SAMPLE_RATE/MULT;

		gdk_draw_line(rci->pixmap, rci->draw_area->style->black_gc,
				0,
				rci->draw_area->allocation.height-HEIGHT_TIME_LABEL,
				rci->draw_area->allocation.width,
				rci->draw_area->allocation.height-HEIGHT_TIME_LABEL);

		imax = min(rci->draw_area->allocation.width,(gint)(rci->samples->len/MULT));

		/* we update the progress bar 100 times */

		/* Update the progress bar when it gets to this value. */
		progbar_nextstep = 0;
		/* When we reach the value that triggers a progress bar update,
		   bump that value by this amount. */
		progbar_quantum = imax/100;

		red_gc = gdk_gc_new(rci->draw_area->window);
		gdk_gc_set_rgb_fg_color(red_gc, &red_color);

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
				max = max(max, sample.val);
				min = min(min, sample.val);
				if (sample.status == S_DROP_BY_JITT) status = S_DROP_BY_JITT;
			}

			if (status == S_DROP_BY_JITT) {
				gc = red_gc;
			} else {
				gc = rci->draw_area->style->black_gc;
			}

			gdk_draw_line(rci->pixmap, gc,
				i,
				(gint)(( (0x7FFF+min) * (rci->draw_area->allocation.height-HEIGHT_TIME_LABEL))/0xFFFF),
				i,
				(gint)(( (0x7FFF+max) * (rci->draw_area->allocation.height-HEIGHT_TIME_LABEL))/0xFFFF));

			/*draw the time label and grid */
			if ( !((i*MULT)%(SAMPLE_RATE)) ) {
				gdk_draw_line(rci->pixmap, rci->draw_area->style->black_gc,
					(int) (i - offset),
					rci->draw_area->allocation.height-HEIGHT_TIME_LABEL,
					(int) (i - offset),
					rci->draw_area->allocation.height-HEIGHT_TIME_LABEL+4);

				g_snprintf(label_string, MAX_TIME_LABEL, "%.0f", floor(rci->start_time/1000) + i*MULT/SAMPLE_RATE);

				pango_layout_set_text(small_layout, label_string, -1);
				pango_layout_get_pixel_size(small_layout, &label_width, &label_height);
				gdk_draw_layout(rci->pixmap,
					rci->draw_area->style->black_gc,
					(int) (i - offset - label_width/2),
					rci->draw_area->allocation.height - label_height,
					small_layout);
			/* draw the 1/2 sec grid */
			} else if ( !((i*MULT)%(SAMPLE_RATE/2)) ) {
				gdk_draw_line(rci->pixmap, rci->draw_area->style->black_gc,
					(int) (i - offset),
					rci->draw_area->allocation.height-HEIGHT_TIME_LABEL,
					(int) (i - offset),
					rci->draw_area->allocation.height-HEIGHT_TIME_LABEL+2);

			}

			progbar_count++;
		}
	}

}
/****************************************************************************/
static gint expose_event_channels(GtkWidget *widget, GdkEventExpose *event)
{
	rtp_channel_info_t *rci;

	rci=(rtp_channel_info_t *)OBJECT_GET_DATA(widget, "rtp_channel_info_t");
	if(!rci){
		exit(10);
	}

	if (GDK_IS_DRAWABLE(widget->window))
		gdk_draw_drawable(widget->window,
			widget->style->fg_gc[GTK_WIDGET_STATE(widget)],
			rci->pixmap,
			event->area.x, event->area.y,
			event->area.x, event->area.y,
			event->area.width, event->area.height);

	return FALSE;
}

/****************************************************************************/
static gint 
configure_event_channels(GtkWidget *widget, GdkEventConfigure *event _U_)
{
	rtp_channel_info_t *rci;
	int i;

	/* the first calor is blue to highlight the selected item 
	 * the other collors are the same as in the Voip Graph analysys
	 * to match the same calls 
	 */
	static GdkColor col[MAX_NUM_COL_CONV+1] = {
		{0,     0x00FF, 0x00FF, 0xFFFF},
		{0,     0x33FF, 0xFFFF, 0x33FF},
		{0,     0x00FF, 0xCCFF, 0xCCFF},
		{0,     0x66FF, 0xFFFF, 0xFFFF},
		{0,     0x99FF, 0x66FF, 0xFFFF},
		{0,     0xFFFF, 0xFFFF, 0x33FF},
		{0,     0xCCFF, 0x99FF, 0xFFFF},
		{0,     0xCCFF, 0xFFFF, 0x33FF},
		{0,     0xFFFF, 0xCCFF, 0xCCFF},
		{0,     0xFFFF, 0x99FF, 0x66FF},
		{0,     0xFFFF, 0xFFFF, 0x99FF}
	};

	rci=(rtp_channel_info_t *)OBJECT_GET_DATA(widget, "rtp_channel_info_t");
	if(!rci){
		exit(10);
	}

	if(rci->pixmap){
		g_object_unref(rci->pixmap);
		rci->pixmap=NULL;
	}

	rci->pixmap = gdk_pixmap_new(widget->window,
					widget->allocation.width,
					widget->allocation.height,
					-1);

	if ( GDK_IS_DRAWABLE(rci->pixmap) )
		gdk_draw_rectangle(rci->pixmap,
			widget->style->white_gc,
			TRUE,
			0, 0,
			widget->allocation.width,
			widget->allocation.height);

	/* create gcs for the background color of each channel */
	for (i=0; i<MAX_NUM_COL_CONV+1; i++){
		rci->bg_gc[i]=gdk_gc_new(rci->pixmap);
		gdk_gc_set_rgb_fg_color(rci->bg_gc[i], &col[i]);
	}

	channel_draw(rci);

	return TRUE;
}

/****************************************************************************/
static gint 
button_press_event_channel(GtkWidget *widget, GdkEventButton *event _U_)
{
	rtp_channel_info_t *rci;
	int this_channel;
	guint32 prev_index;

	rci=(rtp_channel_info_t *)OBJECT_GET_DATA(widget, "rtp_channel_info_t");
	if(!rci){
		exit(10);
	}

	if (!rci->selected) {

		/* only select a new channels if we are in STOP */
		if (!rtp_channels->stop) return 0;

		/* if there are already both channels selected, unselect the old one */
		if (rtp_channels->rci[rtp_channels->channel]) {
			/* we disconnect the signal temporarly to avoid been called back */
			SIGNAL_DISCONNECT_BY_FUNC(rtp_channels->rci[rtp_channels->channel]->check_bt, on_bt_check_clicked, rtp_channels->rci[rtp_channels->channel]);
			gtk_toggle_button_set_active((GtkToggleButton *) rtp_channels->rci[rtp_channels->channel]->check_bt, FALSE);
			SIGNAL_CONNECT(rtp_channels->rci[rtp_channels->channel]->check_bt, "clicked", on_bt_check_clicked, rtp_channels->rci[rtp_channels->channel]);
			rtp_channels->rci[rtp_channels->channel]->selected = FALSE;
		}

		/* we disconnect the signal temporarly to avoid been called back */
		SIGNAL_DISCONNECT_BY_FUNC(rci->check_bt, on_bt_check_clicked, rci);
		gtk_toggle_button_set_active((GtkToggleButton *) rci->check_bt, TRUE);
		SIGNAL_CONNECT(rci->check_bt, "clicked", on_bt_check_clicked, rci);

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
	OBJECT_SET_DATA(rci->draw_area, "rtp_channel_info_t", rci);
	gtk_widget_add_events (rci->draw_area, GDK_BUTTON_PRESS_MASK);
	GTK_WIDGET_SET_FLAGS(rci->draw_area, GTK_CAN_FOCUS);
	gtk_widget_grab_focus(rci->draw_area);

	gtk_box_pack_start(GTK_BOX (channels_vb), rci->scroll_window, FALSE, FALSE, 0);

	/* signals needed to handle backing pixmap */
	SIGNAL_CONNECT(rci->draw_area, "expose_event", expose_event_channels, NULL);
	SIGNAL_CONNECT(rci->draw_area, "configure_event", configure_event_channels, rci);
	gtk_widget_add_events (rci->draw_area, GDK_BUTTON_PRESS_MASK);
	SIGNAL_CONNECT(rci->draw_area, "button_press_event", button_press_event_channel, rci);
	SIGNAL_CONNECT(rci->h_scrollbar_adjustment, "value_changed", h_scrollbar_changed, rci);


	label = g_string_new("");
	g_string_printf(label, "From %s:%d to %s:%d   Duration:%.2f   Drop by Jitter Buff:%d(%.1f%%)   Out of Seq: %d(%.1f%%)", get_addr_name(&(rci->first_stream->src_addr)), 
		rci->first_stream->src_port, get_addr_name(&(rci->first_stream->dest_addr)), rci->first_stream->dest_port, 
		(double)rci->samples->len/SAMPLE_RATE, rci->drop_by_jitter_buff, (double)rci->drop_by_jitter_buff * 100 / (double)rci->num_packets
		, rci->out_of_seq, (double)rci->out_of_seq * 100 / (double)rci->num_packets);

	rci->check_bt = gtk_check_button_new_with_label(label->str);
	gtk_box_pack_start(GTK_BOX (channels_vb), rci->check_bt, FALSE, FALSE, 1);
	
	/* Create the Separator if it is not the last one */
	(*counter)++;
	if (*counter < g_hash_table_size(rtp_channels_hash)) {
	    rci->separator = gtk_hseparator_new();
		gtk_box_pack_start(GTK_BOX (channels_vb), rci->separator, FALSE, FALSE, 5);
	}

	SIGNAL_CONNECT(rci->check_bt, "clicked", on_bt_check_clicked, rci);

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
	if(!rtp_channels->stop && !rtp_channels->pause){
		exit(10);
	}

	/* if we are in PAUSE change the sate */
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
			  SAMPLE_RATE,
			  FRAMES_PER_BUFFER,
			  0,              /* number of buffers, if zero then use default minimum */
			  paClipOff,      /* we won't output out of range samples so don't bother clipping them */
			  paCallback,
			  rtp_channels );
#else /* PORTAUDIO_API_1 */
		err = Pa_OpenDefaultStream( 
				&pa_stream,
                0,
                NUM_CHANNELS,
                PA_SAMPLE_TYPE,
                SAMPLE_RATE,
                FRAMES_PER_BUFFER,
                paCallback,
                rtp_channels );
#endif /* PORTAUDIO_API_1 */

		if( err != paNoError ) {
			dialog = gtk_message_dialog_new ((GtkWindow *) rtp_player_dlg_w,
								  GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,GTK_BUTTONS_CLOSE,
								  "Can not Open Stream in PortAduio Library.\n Error: %s", Pa_GetErrorText( err ));
			gtk_dialog_run (GTK_DIALOG (dialog));
			gtk_widget_destroy (dialog);
			return;
		}

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
	g_object_unref(rci->pixmap);
	gtk_widget_destroy(rci->draw_area);
	gtk_widget_destroy(rci->scroll_window);
	gtk_widget_destroy(rci->check_bt);
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
	WIDGET_SET_SIZE(progress_bar, 100, -1);
	gtk_box_pack_start(GTK_BOX (stat_hbox), progress_bar, FALSE, FALSE, 2);
	gtk_widget_show(progress_bar);
	statusbar_context = gtk_statusbar_get_context_id((GtkStatusbar *) info_bar, "main");
	gtk_statusbar_push((GtkStatusbar *) info_bar, statusbar_context, "  Decoding RTP packets...");

	gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(info_bar), FALSE);

	/* reset the number of packet to be decoded, this is used for the progress bar */
	total_packets = 0;
	/* reset the Progress Bar count */
	progbar_count = 0;

	/* Mark the RTP streams to be played using the selected VoipCalls*/
	if (rtp_streams_hash)
		g_hash_table_foreach( rtp_streams_hash, (GHFunc)mark_rtp_stream_to_play, NULL);

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

	/* Resize the main scroll window to display no more than 5 channels, otherwise the scroll bar need to be used */
	WIDGET_SET_SIZE(main_scrolled_window, CHANNEL_WIDTH, 
		min(counter, 5) * (CHANNEL_HEIGHT+60));

	gtk_widget_show_all(main_scrolled_window);

	gtk_widget_destroy(progress_bar);
	gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(info_bar), TRUE);
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
rtp_player_on_destroy(GtkObject *object _U_, gpointer user_data _U_)
{
	/* Stop the channels if necesary */
	if(rtp_channels && (!rtp_channels->stop)){
		stop_channels();
	}

	/* Destroy the rtp channels */
	reset_channels();

	g_free(rtp_channels);
	rtp_channels = NULL;

	initialized = FALSE;

	gtk_widget_destroy(rtp_player_dlg_w);
	main_scrolled_window = NULL;
	rtp_player_dlg_w = NULL;
}

/****************************************************************************/
static void
jitter_spinner_value_changed (GtkSpinButton *spinner, gpointer user_data _U_)
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
	GtkWidget *h_jitter_buttons_box;
	GtkWidget *bt_close;
	GtkAdjustment *jitter_spinner_adj;
	GtkWidget *label;

	GtkTooltips *tooltips = gtk_tooltips_new();

	rtp_player_dlg_w=gtk_window_new(GTK_WINDOW_TOPLEVEL);
	
	gtk_window_set_title(GTK_WINDOW(rtp_player_dlg_w), "Wireshark: RTP Player");
	gtk_window_set_position(GTK_WINDOW(rtp_player_dlg_w), GTK_WIN_POS_NONE);

	gtk_window_set_default_size(GTK_WINDOW(rtp_player_dlg_w), 400, 50);

	main_vb = gtk_vbox_new (FALSE, 0);
	gtk_container_add(GTK_CONTAINER(rtp_player_dlg_w), main_vb);
	gtk_container_set_border_width (GTK_CONTAINER (main_vb), 2);
	
	main_scrolled_window=gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width (GTK_CONTAINER (main_scrolled_window), 4);
	WIDGET_SET_SIZE(main_scrolled_window, CHANNEL_WIDTH, 0);

	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (main_scrolled_window), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(main_vb), main_scrolled_window);

	channels_vb = gtk_vbox_new (FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (channels_vb), 2);
	gtk_scrolled_window_add_with_viewport((GtkScrolledWindow *) main_scrolled_window, channels_vb);

	h_jitter_buttons_box = gtk_hbox_new (FALSE, 0);
	gtk_container_set_border_width (GTK_CONTAINER (h_jitter_buttons_box), 10);
	gtk_box_pack_start (GTK_BOX(main_vb), h_jitter_buttons_box, FALSE, FALSE, 0);
	label = gtk_label_new("Jitter buffer [ms] ");
	gtk_box_pack_start(GTK_BOX(h_jitter_buttons_box), label, FALSE, FALSE, 0);
	
	jitter_spinner_adj = (GtkAdjustment *) gtk_adjustment_new (50, 0, 500, 5, 10, 10);
	jitter_spinner = gtk_spin_button_new (jitter_spinner_adj, 5, 0);
	gtk_box_pack_start(GTK_BOX(h_jitter_buttons_box), jitter_spinner, FALSE, FALSE, 0);
	gtk_tooltips_set_tip (tooltips, jitter_spinner, "The simulated jitter buffer in [ms]", NULL);
	SIGNAL_CONNECT(GTK_OBJECT (jitter_spinner_adj), "value_changed", (GtkSignalFunc) jitter_spinner_value_changed, NULL);

	/* button row */
	hbuttonbox = gtk_hbutton_box_new ();
	gtk_box_pack_start (GTK_BOX (h_jitter_buttons_box), hbuttonbox, TRUE, TRUE, 0);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_SPREAD);
	gtk_button_box_set_spacing (GTK_BUTTON_BOX (hbuttonbox), 30);

	bt_decode = gtk_button_new_with_label("Decode");
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_decode);
	SIGNAL_CONNECT(bt_decode, "clicked", on_bt_decode_clicked, NULL);
	gtk_tooltips_set_tip (tooltips, bt_decode, "Decode the RTP stream(s)", NULL);

	bt_play = gtk_button_new_with_label("Play");
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_play);
	SIGNAL_CONNECT(bt_play, "clicked", on_bt_play_clicked, NULL);
	gtk_tooltips_set_tip (tooltips, bt_play, "Play the RTP channel(s)", NULL);

	bt_pause = gtk_button_new_with_label("Pause");
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_pause);
	SIGNAL_CONNECT(bt_pause, "clicked", on_bt_pause_clicked, NULL);
	gtk_tooltips_set_tip (tooltips, bt_pause, "Pause the RTP channel(s)", NULL);

	bt_stop = gtk_button_new_with_label("Stop");
	gtk_container_add(GTK_CONTAINER(hbuttonbox), bt_stop);
	SIGNAL_CONNECT(bt_stop, "clicked", on_bt_stop_clicked, NULL);
	gtk_tooltips_set_tip (tooltips, bt_stop, "Stop the RTP channel(s)", NULL);

	bt_close = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_close);
	GTK_WIDGET_SET_FLAGS(bt_close, GTK_CAN_DEFAULT);
	gtk_tooltips_set_tip (tooltips, bt_close, "Close this dialog", NULL);

	SIGNAL_CONNECT(bt_close, "clicked", rtp_player_on_destroy, NULL);
	SIGNAL_CONNECT(rtp_player_dlg_w, "destroy", rtp_player_on_destroy, NULL);

	/* button row */
	hbuttonbox = gtk_hbutton_box_new ();

	/* Filter/status hbox */
	stat_hbox = gtk_hbox_new(FALSE, 1);
	gtk_container_border_width(GTK_CONTAINER(stat_hbox), 0);

	/* statusbar */
	info_bar = gtk_statusbar_new();
	gtk_statusbar_set_has_resize_grip(GTK_STATUSBAR(info_bar), TRUE);

	gtk_box_pack_start(GTK_BOX(stat_hbox), info_bar, TRUE, TRUE, 0);

	/* statusbar hbox */
	gtk_box_pack_start(GTK_BOX(main_vb), stat_hbox, FALSE, TRUE, 0);

	/* set the sensitive state of the buttons (decode, play, pause, stop) */
	bt_state(TRUE, FALSE, FALSE, FALSE);
	
	gtk_widget_show_all(rtp_player_dlg_w);

	/* Force gtk to redraw the window before starting decoding the packet */
	while (g_main_context_iteration(NULL, FALSE));
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
                                  "Can not Initialize the PortAduio Library.\n Error: %s", Pa_GetErrorText( err ));
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
		rtp_channels = g_malloc(sizeof(rtp_play_channles_t));
	}

	reset_rtp_channels();

	/* create the dialog window */
	rtp_player_dlg_create();
	
}

#endif /* GTK_MAJOR_VERSION >= 2 */
 
#endif /* HAVE_LIBPORTAUDIO */
