/* pppdump.c
 *
 * $Id$
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap-int.h"
#include "buffer.h"
#include "pppdump.h"
#include "file_wrappers.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/*
pppdump records
Daniel Thompson (STMicroelectronics) <daniel.thompson@st.com>

+------+
| 0x07 |                              Reset time
+------+------+------+------+
|  t3  |  t2  |  t1  |  t0  |         t = time_t
+------+------+------+------+

+------+
| 0x06 |                              Time step (short)
+------+
|  ts  |                              ts = time step (tenths of seconds)
+------+

+------+
| 0x05 |                              Time step (long)
+------+------+------+------+
| ts3  | ts2  | ts1  | ts0  |         ts = time step (tenths of seconds)
+------+------+------+------+

+------+
| 0x04 |                              Receive deliminator (not seen in practice)
+------+

+------+
| 0x03 |                              Send deliminator (not seen in practice)
+------+

+------+
| 0x02 |                              Received data
+------+------+
|  n1  |  n0  |                       n = number of bytes following
+------+------+
|    data     |
|             |

+------+
| 0x01 |                              Sent data
+------+------+
|  n1  |  n0  |                       n = number of bytes following
+------+------+
|    data     |
|             |
*/

#define PPPD_SENT_DATA		0x01
#define PPPD_RECV_DATA		0x02
#define PPPD_SEND_DELIM		0x03
#define PPPD_RECV_DELIM		0x04
#define PPPD_TIME_STEP_LONG	0x05
#define PPPD_TIME_STEP_SHORT	0x06
#define PPPD_RESET_TIME		0x07

/* this buffer must be at least (2*PPPD_MTU) + sizeof(ppp_header) +
 * sizeof(lcp_header) + sizeof(ipcp_header).  PPPD_MTU is *very* rarely
 * larger than 1500 so this value is fine.
 */
#define PPPD_BUF_SIZE		8192

typedef enum {
	DIRECTION_SENT,
	DIRECTION_RECV
} direction_enum;

static gboolean pppdump_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);
static gboolean pppdump_seek_read(wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info);

/*
 * Information saved about a packet, during the initial sequential pass
 * through the file, to allow us to later re-read it when randomly
 * reading packets.
 *
 * "offset" is the offset in the file of the first data chunk containing data
 * from that packet; note that it may also contain data from previous
 * packets.
 *
 * "num_bytes_to_skip" is the number of bytes from previous packets in that
 * first data chunk.
 *
 * "dir" is the direction of the packet.
 */
typedef struct {
	long		offset;
	int		num_bytes_to_skip;
	direction_enum	dir;
} pkt_id;

/*
 * Information about a packet currently being processed.  There is one of
 * these for the sent packet being processed and one of these for the
 * received packet being processed, as we could be in the middle of
 * processing both a received packet and a sent packet.
 *
 * "dir" is the direction of the packet.
 *
 * "cnt" is the number of bytes of packet data we've accumulated.
 *
 * "esc" is TRUE if the next byte we see is escaped (and thus must be XORed
 * with 0x20 before saving it), FALSE otherwise.
 *
 * "buf" is a buffer containing the packet data we've accumulated.
 *
 * "id_offset" is the offset in the file of the first data chunk
 * containing data from the packet we're processing.
 *
 * "sd_offset" is the offset in the file of the first data byte from
 * the packet we're processing - which isn't necessarily right after
 * the header of the first data chunk, as we may already have assembled
 * packets from that chunk.
 *
 * "cd_offset" is the offset in the file of the current data chunk we're
 * processing.
 */
typedef struct {
	direction_enum	dir;
	int		cnt;
	gboolean	esc;
	guint8		buf[PPPD_BUF_SIZE];
	long		id_offset;
	long		sd_offset;
	long		cd_offset;
} pkt_t;

/*
 * This keeps state used while processing records.
 *
 * "timestamp" is the seconds portion of the current time stamp value,
 * as updated from PPPD_RESET_TIME, PPPD_TIME_STEP_LONG, and
 * PPPD_TIME_STEP_SHORT records.  "tenths" is the tenths-of-seconds
 * portion.
 *
 * "spkt" and "rpkt" are "pkt_t" structures for the sent and received
 * packets we're currently working on.
 *
 * "offset" is the current offset in the file.
 *
 * "num_bytes" and "pkt" are information saved when we finish accumulating
 * the data for a packet, if the data chunk we're working on still has more
 * data in it:
 *
 *	"num_bytes" is the number of bytes of additional data remaining
 *	in the chunk after we've finished accumulating the data for the
 *	packet.
 *
 *	"pkt" is the "pkt_t" for the type of packet the data chunk is for
 *	(sent or received packet).
 *
 * "seek_state" is another state structure used while processing records
 * when doing a seek-and-read.  (That structure doesn't itself have a
 * "seek_state" structure.)
 *
 * "pids" is a GPtrArray of pointers to "pkt_id" structures for all the
 * packets we've seen during the initial sequential pass, to allow us to
 * later retrieve them with random accesses.
 *
 * "pkt_cnt" is the number of packets we've seen up to this point in the
 * sequential pass.
 */
typedef struct _pppdump_t {
	time_t			timestamp;
	guint			tenths;
	pkt_t			spkt;
	pkt_t			rpkt;
	long			offset;
	int			num_bytes;
	pkt_t			*pkt;
	struct _pppdump_t	*seek_state;
	GPtrArray		*pids;
	guint			pkt_cnt;
} pppdump_t;

static int
process_data(pppdump_t *state, FILE_T fh, pkt_t *pkt, int n, guint8 *pd,
    int *err, pkt_id *pid);

static gboolean
collate(pppdump_t*, FILE_T fh, int *err, gchar **err_info, guint8 *pd,
		int *num_bytes, direction_enum *direction, pkt_id *pid,
		int num_bytes_to_skip);

static void
pppdump_close(wtap *wth);

static void
init_state(pppdump_t *state)
{

	state->num_bytes = 0;
	state->pkt = NULL;

	state->spkt.dir = DIRECTION_SENT;
	state->spkt.cnt = 0;
	state->spkt.esc = FALSE;
	state->spkt.id_offset = 0;
	state->spkt.sd_offset = 0;
	state->spkt.cd_offset = 0;

	state->rpkt.dir = DIRECTION_RECV;
	state->rpkt.cnt = 0;
	state->rpkt.esc = FALSE;
	state->rpkt.id_offset = 0;
	state->rpkt.sd_offset = 0;
	state->rpkt.cd_offset = 0;

	state->seek_state = NULL;
	state->offset = 0x100000; /* to detect errors during development */
}


int
pppdump_open(wtap *wth, int *err, gchar **err_info _U_)
{
	guint8		buffer[6];	/* Looking for: 0x07 t3 t2 t1 t0 ID */
	pppdump_t	*state;

	/* There is no file header, only packet records. Fortunately for us,
	* timestamp records are separated from packet records, so we should
	* find an "initial time stamp" (i.e., a "reset time" record, or
	* record type 0x07) at the beginning of the file. We'll check for
	* that, plus a valid record following the 0x07 and the four bytes
	* representing the timestamp.
	*/

	wtap_file_read_unknown_bytes(buffer, sizeof(buffer), wth->fh, err);

	if (buffer[0] == PPPD_RESET_TIME &&
			(buffer[5] == PPPD_SENT_DATA ||
			 buffer[5] == PPPD_RECV_DATA ||
			 buffer[5] == PPPD_TIME_STEP_LONG ||
			 buffer[5] == PPPD_TIME_STEP_SHORT ||
			 buffer[5] == PPPD_RESET_TIME)) {

		goto my_file_type;
	}
	else {
		return 0;
	}

  my_file_type:

	if (file_seek(wth->fh, 5, SEEK_SET, err) == -1)
		return -1;

	state = wth->capture.generic = g_malloc(sizeof(pppdump_t));
	state->timestamp = pntohl(&buffer[1]);
	state->tenths = 0;

	init_state(state);

	state->offset = 5;
	wth->file_encap = WTAP_ENCAP_PPP_WITH_PHDR;
	wth->file_type = WTAP_FILE_PPPDUMP;

	wth->snapshot_length = PPPD_BUF_SIZE; /* just guessing */
	wth->subtype_read = pppdump_read;
	wth->subtype_seek_read = pppdump_seek_read;
	wth->subtype_close = pppdump_close;
	wth->tsprecision = WTAP_FILE_TSPREC_DSEC;

	state->seek_state = g_malloc(sizeof(pppdump_t));

	/* If we have a random stream open, we're going to be reading
	   the file randomly; set up a GPtrArray of pointers to
	   information about how to retrieve the data for each packet. */
	if (wth->random_fh != NULL)
		state->pids = g_ptr_array_new();
	else
		state->pids = NULL;
	state->pkt_cnt = 0;

	return 1;
}

/* Find the next packet and parse it; called from wtap_read(). */
static gboolean
pppdump_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	int		num_bytes;
	direction_enum	direction;
	guint8		*buf;
	pppdump_t	*state;
	pkt_id		*pid;

	buffer_assure_space(wth->frame_buffer, PPPD_BUF_SIZE);
	buf = buffer_start_ptr(wth->frame_buffer);

	state = wth->capture.generic;

	/* If we have a random stream open, allocate a structure to hold
	   the information needed to read this packet's data again. */
	if (wth->random_fh != NULL) {
		pid = g_new(pkt_id, 1);
		if (!pid) {
			*err = errno;	/* assume a malloc failed and set "errno" */
			return FALSE;
		}
		pid->offset = 0;
	} else
		pid = NULL;	/* sequential only */

	if (!collate(state, wth->fh, err, err_info, buf, &num_bytes, &direction,
	    pid, 0)) {
	    	if (pid != NULL)
			g_free(pid);
		return FALSE;
	}

	if (pid != NULL)
		pid->dir = direction;

	if (pid != NULL)
		g_ptr_array_add(state->pids, pid);
	/* The user's data_offset is not really an offset, but a packet number. */
	*data_offset = state->pkt_cnt;
	state->pkt_cnt++;

	wth->phdr.len		= num_bytes;
	wth->phdr.caplen	= num_bytes;
	wth->phdr.ts.secs	= state->timestamp;
	wth->phdr.ts.nsecs	= state->tenths * 100000000;
	wth->phdr.pkt_encap	= WTAP_ENCAP_PPP_WITH_PHDR;

	wth->pseudo_header.p2p.sent = (direction == DIRECTION_SENT ? TRUE : FALSE);

	return TRUE;
}

/* Returns number of bytes copied for record, -1 if failure.
 *
 * This is modeled after pppdump.c, the utility to parse pppd log files; it
 * comes with the ppp distribution.
 */
static int
process_data(pppdump_t *state, FILE_T fh, pkt_t *pkt, int n, guint8 *pd,
    int *err, pkt_id *pid)
{
	int	c;
	int	num_bytes = n;
	int	num_written;

	for (; num_bytes > 0; --num_bytes) {
		c = file_getc(fh);
		if (c == EOF) {
			*err = file_error(fh);
			if (*err == 0) {
				*err = WTAP_ERR_SHORT_READ;
			}
			return -1;
		}
		state->offset++;
		switch (c) {
			case 0x7e:
				/*
				 * Flag Sequence for RFC 1662 HDLC-like
				 * framing.
				 *
				 * As this is a raw trace of octets going
				 * over the wire, and that might include
				 * the login sequence, there is no
				 * guarantee that *only* PPP traffic
				 * appears in this file, so there is no
				 * guarantee that the first 0x7e we see is
				 * a start flag sequence, and therefore we
				 * cannot safely ignore all characters up
				 * to the first 0x7e, and therefore we
				 * might end up with some bogus PPP
				 * packets.
				 */
				if (pkt->cnt > 0) {
					/*
					 * We've seen stuff before this,
					 * so this is the end of a frame.
					 * Make a frame out of that stuff.
					 */
					pkt->esc = FALSE;

					num_written = pkt->cnt;
					pkt->cnt = 0;
					if (num_written <= 0) {
						return 0;
					}

					if (num_written > PPPD_BUF_SIZE) {
						*err = WTAP_ERR_UNC_OVERFLOW;
						return -1;
					}

					memcpy(pd, pkt->buf, num_written);

					/*
					 * Remember the offset of the
					 * first record containing data
					 * for this packet, and how far
					 * into that record to skip to
					 * get to the beginning of the
					 * data for this packet; the number
					 * of bytes to skip into that record
					 * is the file offset of the first
					 * byte of this packet minus the
					 * file offset of the first byte of
					 * this record, minus 3 bytes for the
					 * header of this record (which, if
					 * we re-read this record, we will
					 * process, not skip).
					 */
					if (pid) {
						pid->offset = pkt->id_offset;
						pid->num_bytes_to_skip =
						    pkt->sd_offset - pkt->id_offset - 3;
						g_assert(pid->num_bytes_to_skip >= 0);
					}

					num_bytes--;
					if (num_bytes > 0) {
						/*
						 * There's more data in this
						 * record.
						 * Set the initial data offset
						 * for the next packet.
						 */
						pkt->id_offset = pkt->cd_offset;
						pkt->sd_offset = state->offset;
					} else {
						/*
						 * There is no more data in
						 * this record.
						 * Thus, we don't have the
						 * initial data offset for
						 * the next packet.
						 */
						pkt->id_offset = 0;
						pkt->sd_offset = 0;
					}
					state->num_bytes = num_bytes;
					state->pkt = pkt;
					return num_written;
				}
				break;

			case 0x7d:
				/*
				 * Control Escape octet for octet-stuffed
				 * RFC 1662 HDLC-like framing.
				 */
				if (!pkt->esc) {
					/*
					 * Control Escape not preceded by
					 * Control Escape; discard it
					 * but XOR the next octet with
					 * 0x20.
					 */
					pkt->esc = TRUE;
					break;
				}
				/*
				 * Control Escape preceded by Control Escape;
				 * treat it as an ordinary character,
				 * by falling through.
				 */

			default:
				if (pkt->esc) {
					/*
					 * This character was preceded by
					 * Control Escape, so XOR it with
					 * 0x20, as per RFC 1662's octet-
					 * stuffed framing, and clear
					 * the flag saying that the
					 * character should be escaped.
					 */
					c ^= 0x20;
					pkt->esc = FALSE;
				}

				pkt->buf[pkt->cnt++] = c;
				if (pkt->cnt > PPPD_BUF_SIZE) {
					*err = WTAP_ERR_UNC_OVERFLOW;
					return -1;
				}
				break;
		}
	}

	/* we could have run out of bytes to read */
	return 0;
}

/* Returns TRUE if packet data copied, FALSE if error occurred or EOF (no more records). */
static gboolean
collate(pppdump_t* state, FILE_T fh, int *err, gchar **err_info, guint8 *pd,
		int *num_bytes, direction_enum *direction, pkt_id *pid,
		int num_bytes_to_skip)
{
	int		id;
	pkt_t		*pkt = NULL;
	int		byte0, byte1;
	int		n, num_written = 0;
	long		start_offset;
	guint32		time_long;
	guint8		time_short;

	/*
	 * Process any data left over in the current record when doing
	 * sequential processing.
	 */
	if (state->num_bytes > 0) {
		g_assert(num_bytes_to_skip == 0);
		pkt = state->pkt;
		num_written = process_data(state, fh, pkt, state->num_bytes,
		    pd, err, pid);

		if (num_written < 0) {
			return FALSE;
		}
		else if (num_written > 0) {
			*num_bytes = num_written;
			*direction = pkt->dir;
			return TRUE;
		}
		/* if 0 bytes written, keep processing */
	} else {
		/*
		 * We didn't have any data left over, so the packet will
		 * start at the beginning of a record.
		 */
		if (pid)
			pid->num_bytes_to_skip = 0;
	}

	/*
	 * That didn't get all the data for this packet, so process
	 * subsequent records.
	 */
	start_offset = state->offset;
	while ((id = file_getc(fh)) != EOF) {
		state->offset++;
		switch (id) {
			case PPPD_SENT_DATA:
			case PPPD_RECV_DATA:
				pkt = id == PPPD_SENT_DATA ? &state->spkt : &state->rpkt;

				/*
				 * Save the offset of the beginning of
				 * the current record.
				 */
				pkt->cd_offset = state->offset - 1;

				/*
				 * Get the length of the record.
				 */
				byte0 = file_getc(fh);
				if (byte0 == EOF)
					goto done;
				state->offset++;
				byte1 = file_getc(fh);
				if (byte1 == EOF)
					goto done;
				state->offset++;
				n = (byte0 << 8) | byte1;

				if (pkt->id_offset == 0) {
					/*
					 * We don't have the initial data
					 * offset for this packet, which
					 * means this is the first
					 * data record for that packet.
					 * Save the offset of the
					 * beginning of that record and
					 * the offset of the first data
					 * byte in the packet, which is
					 * the first data byte in the
					 * record.
					 */
					pkt->id_offset = pkt->cd_offset;
					pkt->sd_offset = state->offset;
				}

				g_assert(num_bytes_to_skip < n);
				while (num_bytes_to_skip) {
					if (file_getc(fh) == EOF)
						goto done;
					state->offset++;
					num_bytes_to_skip--;
					n--;
				}
				num_written = process_data(state, fh, pkt, n,
				    pd, err, pid);

				if (num_written < 0) {
					return FALSE;
				}
				else if (num_written > 0) {
					*num_bytes = num_written;
					*direction = pkt->dir;
					return TRUE;
				}
				/* if 0 bytes written, keep looping */
				break;

			case PPPD_SEND_DELIM:
			case PPPD_RECV_DELIM:
				/* What can we do? */
				break;

			case PPPD_RESET_TIME:
				wtap_file_read_unknown_bytes(&time_long, sizeof(guint32), fh, err);
				state->offset += sizeof(guint32);
				state->timestamp = pntohl(&time_long);
				state->tenths = 0;
				break;

			case PPPD_TIME_STEP_LONG:
				wtap_file_read_unknown_bytes(&time_long, sizeof(guint32), fh, err);
				state->offset += sizeof(guint32);
				state->tenths += pntohl(&time_long);

				if (state->tenths >= 10) {
					state->timestamp += state->tenths / 10;
					state->tenths = state->tenths % 10;
				}

				break;

			case PPPD_TIME_STEP_SHORT:
				wtap_file_read_unknown_bytes(&time_short, sizeof(guint8), fh, err);
				state->offset += sizeof(guint8);
				state->tenths += time_short;

				if (state->tenths >= 10) {
					state->timestamp += state->tenths / 10;
					state->tenths = state->tenths % 10;
				}

				break;

			default:
				/* XXX - bad file */
				*err = WTAP_ERR_BAD_RECORD;
				*err_info = g_strdup_printf("pppdump: bad ID byte 0x%02x", id);
				return FALSE;
		}

	}

done:
	*err = file_error(fh);
	if (*err == 0) {
		if (state->offset != start_offset) {
			/*
			 * We read at least one byte, so we were working
			 * on a record; an EOF means that record was
			 * cut short.
			 */
			*err = WTAP_ERR_SHORT_READ;
		}
	}
	return FALSE;
}



/* Used to read packets in random-access fashion */
static gboolean
pppdump_seek_read(wtap *wth,
		 gint64 seek_off,
		 union wtap_pseudo_header *pseudo_header,
		 guint8 *pd,
		 int len,
		 int *err,
		 gchar **err_info)
{
	int		num_bytes;
	direction_enum	direction;
	pppdump_t	*state;
	pkt_id		*pid;
	int		num_bytes_to_skip;

	state = wth->capture.generic;

	pid = g_ptr_array_index(state->pids, seek_off);
	if (!pid) {
		*err = WTAP_ERR_BAD_RECORD;	/* XXX - better error? */
		*err_info = g_strdup("pppdump: PID not found for record");
		return FALSE;
	}

	if (file_seek(wth->random_fh, pid->offset, SEEK_SET, err) == -1)
		return FALSE;

	init_state(state->seek_state);
	state->seek_state->offset = pid->offset;

	/*
	 * We'll start reading at the first record containing data from
	 * this packet; however, that doesn't mean "collate()" will
	 * stop only when we've read that packet, as there might be
	 * data for packets going in the other direction as well, and
	 * we might finish processing one of those packets before we
	 * finish processing the packet we're reading.
	 *
	 * Therefore, we keep reading until we get a packet that's
	 * going in the direction we want.
	 */
	num_bytes_to_skip = pid->num_bytes_to_skip;
	do {
		if (!collate(state->seek_state, wth->random_fh, err, err_info,
		    pd, &num_bytes, &direction, NULL, num_bytes_to_skip))
			return FALSE;
		num_bytes_to_skip = 0;
	} while (direction != pid->dir);

	if (len != num_bytes) {
		*err = WTAP_ERR_BAD_RECORD;	/* XXX - better error? */
		*err_info = g_strdup_printf("pppdump: requested length %d doesn't match record length %d",
		    len, num_bytes);
		return FALSE;
	}

	pseudo_header->p2p.sent = (pid->dir == DIRECTION_SENT ? TRUE : FALSE);

	return TRUE;
}

static void
pppdump_close(wtap *wth)
{
	pppdump_t	*state;

	state = wth->capture.generic;

	if (state->seek_state) { /* should always be TRUE */
		g_free(state->seek_state);
	}

	if (state->pids) {
		unsigned int i;
		for (i = 0; i < g_ptr_array_len(state->pids); i++) {
			g_free(g_ptr_array_index(state->pids, i));
		}
		g_ptr_array_free(state->pids, TRUE);
	}

	g_free(state);

}
