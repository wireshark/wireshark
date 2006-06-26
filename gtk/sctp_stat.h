/* 
 * Copyright 2004, Irene Ruengeler <i.ruengeler [AT] fh-muenster.de>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
 
#include <epan/dissectors/packet-sctp.h>
#include <epan/address.h>
#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#define SCTP_DATA_CHUNK_ID               0
#define SCTP_INIT_CHUNK_ID               1
#define SCTP_INIT_ACK_CHUNK_ID           2
#define SCTP_SACK_CHUNK_ID               3
#define SCTP_HEARTBEAT_CHUNK_ID          4
#define SCTP_HEARTBEAT_ACK_CHUNK_ID      5
#define SCTP_ABORT_CHUNK_ID              6
#define SCTP_SHUTDOWN_CHUNK_ID           7
#define SCTP_SHUTDOWN_ACK_CHUNK_ID       8
#define SCTP_ERROR_CHUNK_ID              9
#define SCTP_COOKIE_ECHO_CHUNK_ID       10
#define SCTP_COOKIE_ACK_CHUNK_ID        11

#define CHUNK_TYPE_LENGTH             1
#define CHUNK_FLAGS_LENGTH            1
#define CHUNK_LENGTH_LENGTH           2

#define CHUNK_HEADER_OFFSET           0
#define CHUNK_TYPE_OFFSET             CHUNK_HEADER_OFFSET
#define CHUNK_FLAGS_OFFSET            (CHUNK_TYPE_OFFSET + CHUNK_TYPE_LENGTH)
#define CHUNK_LENGTH_OFFSET           (CHUNK_FLAGS_OFFSET + CHUNK_FLAGS_LENGTH)
#define CHUNK_VALUE_OFFSET            (CHUNK_LENGTH_OFFSET + CHUNK_LENGTH_LENGTH)

#define INIT_CHUNK_INITIATE_TAG_LENGTH               4
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH      4
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH 2
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH  2


#define INIT_CHUNK_INITIATE_TAG_OFFSET               CHUNK_VALUE_OFFSET
#define INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET      (INIT_CHUNK_INITIATE_TAG_OFFSET + \
                                                      INIT_CHUNK_INITIATE_TAG_LENGTH )
#define INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET (INIT_CHUNK_ADV_REC_WINDOW_CREDIT_OFFSET + \
                                                      INIT_CHUNK_ADV_REC_WINDOW_CREDIT_LENGTH )
#define INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET  (INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_OFFSET + \
                                                      INIT_CHUNK_NUMBER_OF_OUTBOUND_STREAMS_LENGTH )
#define INIT_CHUNK_INITIAL_TSN_OFFSET                (INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_OFFSET + \
                                                      INIT_CHUNK_NUMBER_OF_INBOUND_STREAMS_LENGTH )

#define DATA_CHUNK_TSN_LENGTH         4
#define DATA_CHUNK_TSN_OFFSET         (CHUNK_VALUE_OFFSET + 0)
#define DATA_CHUNK_STREAM_ID_OFFSET   (DATA_CHUNK_TSN_OFFSET + DATA_CHUNK_TSN_LENGTH)
#define DATA_CHUNK_STREAM_ID_LENGTH   2
#define DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH 2
#define DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH 4
#define DATA_CHUNK_HEADER_LENGTH      (CHUNK_HEADER_LENGTH + \
                                       DATA_CHUNK_TSN_LENGTH + \
                                       DATA_CHUNK_STREAM_ID_LENGTH + \
                                       DATA_CHUNK_STREAM_SEQ_NUMBER_LENGTH + \
                                       DATA_CHUNK_PAYLOAD_PROTOCOL_ID_LENGTH)
#define MAX_ADDRESS_LEN                47
#define NUM_CHUNKS                     13


typedef struct _tsn {
	guint32 frame_number;
	guint32 secs;    /* Absolute seconds */
	guint32 usecs;
	address src;
	address dst;
	GList   *tsns;
} tsn_t;

typedef struct _sctp_tmp_info {
	address src;
	address dst;
	guint16 port1;
	guint16 port2;
	guint32 verification_tag1;
	guint32 verification_tag2;
	guint32 n_tvbs;
} sctp_tmp_info_t;

typedef struct _sctp_min_max {
	guint32 tmp_min_secs;
	guint32 tmp_min_usecs;
	guint32 tmp_max_secs;
	guint32 tmp_max_usecs;
	guint32 tmp_min_tsn1;
	guint32 tmp_min_tsn2;
	guint32 tmp_max_tsn1;
	guint32 tmp_max_tsn2;
	gint    tmp_secs;
} sctp_min_max_t;

struct tsn_sort{
	guint32 tsnumber;
	guint32 secs;
	guint32 usecs;
	guint32 offset;
	guint32 length;
};

typedef struct _sctp_addr_chunk {
	guint32  direction;
	address* addr;
	guint32  addr_count[13];
} sctp_addr_chunk;

typedef struct _sctp_assoc_info {
	address   src;
	address   dst;
	guint16   port1;
	guint16   port2;
	guint32   verification_tag1;
	guint32   verification_tag2;
	guint32   n_tvbs;
	GList     *addr1;
	GList     *addr2;
	guint16   instream1;
	guint16   outstream1;
	guint16   instream2;
	guint16   outstream2;
	guint32   n_adler32_calculated;
	guint32   n_adler32_correct;
	guint32   n_crc32c_calculated;
	guint32   n_crc32c_correct;
	gchar     checksum_type[8];
	guint32   n_checksum_errors;
	guint32   n_bundling_errors;
	guint32   n_padding_errors;
	guint32   n_length_errors;
	guint32   n_value_errors;
	guint32   n_data_chunks;
	guint32   n_data_bytes;
	guint32   n_packets;
	guint32   n_data_chunks_ep1;
	guint32   n_data_bytes_ep1;
	guint32   n_data_chunks_ep2;
	guint32   n_data_bytes_ep2;
	guint32   n_sack_chunks_ep1;
	guint32   n_sack_chunks_ep2;
	guint32   n_array_tsn1;
	guint32   n_array_tsn2;
	guint32   max_window1;
	guint32   max_window2;
	gboolean  init;
	gboolean  initack;
	guint8    initack_dir;
	guint8    direction;
	guint32   min_secs;
	guint32   min_usecs;
	guint32   max_secs;
	guint32   max_usecs;
	guint32   min_tsn1;
	guint32   min_tsn2;
	guint32   max_tsn1;
	guint32   max_tsn2;
	guint32   max_bytes1;
	guint32   max_bytes2;
	GSList    *min_max;
	GList     *frame_numbers;
	GList     *tsn1;
	GPtrArray *sort_tsn1;
	GPtrArray *sort_sack1;
	GList     *sack1;
	GList     *tsn2;
	GPtrArray *sort_tsn2;
	GPtrArray *sort_sack2;
	GList     *sack2;
	gboolean  check_address;
	GList*    error_info_list;
	guint32   chunk_count[NUM_CHUNKS];
	guint32   ep1_chunk_count[NUM_CHUNKS];
	guint32   ep2_chunk_count[NUM_CHUNKS];
	GList*    addr_chunk_count;
} sctp_assoc_info_t;

typedef struct _sctp_error_info {
	guint32 frame_number;
	gchar   chunk_info[200];
	const gchar  *info_text;
} sctp_error_info_t;


typedef struct _sctp_allassocs_info {
	guint32  sum_tvbs;
	GList*   assoc_info_list;
	gboolean is_registered;
	GList*   children;
} sctp_allassocs_info_t;



struct notes {
	GtkWidget   *checktype;
	GtkWidget   *checksum;
	GtkWidget   *bundling;
	GtkWidget   *padding;
	GtkWidget   *length;
	GtkWidget   *value;
	GtkWidget   *chunks_ep1;
	GtkWidget   *bytes_ep1;
	GtkWidget   *chunks_ep2;
	GtkWidget   *bytes_ep2;
	struct page *page2;
	struct page *page3;
};

struct page {
	GtkWidget *addr_frame;
	GtkWidget *scrolled_window;
	GtkWidget *clist;
	GtkWidget *port;
	GtkWidget *veritag;
	GtkWidget *max_in;
	GtkWidget *min_in;
	GtkWidget *max_out;
	GtkWidget *min_out;
};

struct sctp_analyse {
	sctp_assoc_info_t *assoc;
	GtkWidget*        window;
	struct notes      *analyse_nb;
	GList             *children;
	guint16           num_children;
};

typedef struct _sctp_graph_t {
	gboolean  needs_redraw;
	gfloat    x_interval;
	gfloat    y_interval;
	GtkWidget *window;
	GtkWidget *draw_area;
	GdkPixmap *pixmap;
	gint      pixmap_width;
	gint      pixmap_height;
	gint      graph_type;
	gdouble   x_old;
	gdouble   y_old;
	gdouble   x_new;
	gdouble   y_new;
	guint16   offset;
	guint16   length;
	gboolean  tmp;
	gboolean  rectangle;
	gboolean  rectangle_present;
	guint32   rect_x_min;
	guint32   rect_x_max;
	guint32   rect_y_min;
	guint32   rect_y_max;
	guint32   x1_tmp_sec;
	guint32   x2_tmp_sec;
	guint32   x1_tmp_usec;
	guint32   x2_tmp_usec;
	guint32   x1_akt_sec;
	guint32   x2_akt_sec;
	guint32   x1_akt_usec;
	guint32   x2_akt_usec;
	guint32   tmp_width;
	guint32   axis_width;
	guint32   y1_tmp;
	guint32   y2_tmp;
	guint32   tmp_min_tsn1;
	guint32   tmp_max_tsn1;
	guint32   tmp_min_tsn2;
	guint32   tmp_max_tsn2;
	guint32   min_x;
	guint32   max_x;
	guint32   min_y;
	guint32   max_y;
	gboolean  uoff;
} sctp_graph_t;



struct sctp_udata {
	sctp_assoc_info_t   *assoc;
	sctp_graph_t        *io;
	struct sctp_analyse *parent;
	guint16             dir;
};


void register_tap_listener_sctp_stat(void);

const sctp_allassocs_info_t* sctp_stat_get_info(void);

void sctp_stat_scan(void);

void remove_tap_listener_sctp_stat(void);

void assoc_analyse(sctp_assoc_info_t* assoc);

const sctp_assoc_info_t* get_selected_assoc(void);

void create_graph(guint16 dir, struct sctp_analyse* u_data);

void create_byte_graph(guint16 dir, struct sctp_analyse* u_data);

void sctp_error_dlg_show(sctp_assoc_info_t* assoc);

void sctp_stat_dlg_update(void);

void sctp_chunk_stat_dlg_update(struct sctp_udata* udata, unsigned int direction);

void sctp_chunk_dlg_show(struct sctp_analyse* userdata);

void sctp_chunk_stat_dlg_show(unsigned int direction, struct sctp_analyse* userdata);

GtkWidget *get_stat_dlg(void);

GtkWidget *get_chunk_stat_dlg(void);

void update_analyse_dlg(struct sctp_analyse* u_data);

void sctp_analyse_start(GtkWidget *w _U_, gpointer data _U_);

void increase_childcount(struct sctp_analyse *parent);

void decrease_childcount(struct sctp_analyse *parent);

void set_child(struct sctp_udata *child, struct sctp_analyse *parent);

void remove_child(struct sctp_udata *child, struct sctp_analyse *parent);

void decrease_analyse_childcount(void);

void increase_analyse_childcount(void);

void set_analyse_child(struct sctp_analyse *child);

void remove_analyse_child(struct sctp_analyse *child);

void sctp_set_assoc_filter();