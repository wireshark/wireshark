/* pppdump.c
 *
 * $Id: pppdump.c,v 1.1 2000/09/19 17:22:10 gram Exp $
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@xiexie.org>
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
 *
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

/*#define DEBUG 1 */

#ifdef DEBUG
#define dbg_print(...)		g_print(##args)
#else
#define dbg_print(...)		;
#endif

/*
pppdump records
Daniel Thompson (STMicroelectronics) <daniel.thompson@st.com>

+------+
| 0x07 +------+------+------+         Reset time
|  t3  |  t2  |  t1  |  t0  |         t = time_t
+------+------+------+------+

+------+
| 0x06 |                              Time step (short)
|  ts  |                              ts = time step (tenths)
+------+

+------+
| 0x05 +------+------+------+         Time step (long)
| ts3  | ts2  | ts1  | ts0  |         ts = time step (tenths)
+------+------+------+------+

+------+
| 0x04 |                              Receive deliminator (not seen in practice)
+------+

+------+
| 0x03 |                              Send deliminator (not seen in practice)
+------+

+------+
| 0x02 +------+                       Received data
|  n1  |  n0  |                       n = number of bytes following
|    data     |
|             |

+------+
| 0x01 +------+                       Sent data
|  n1  |  n0  |                       n = number of bytes following
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

#define PPPD_NULL		0x00	/* For my own use */

typedef enum {
	DIRECTION_SENT,
	DIRECTION_RECV
} direction_enum;

static gboolean pppdump_read(wtap *wth, int *err, int *data_offset);
static int pppdump_seek_read(wtap *wth, int seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len);

typedef struct {
	long		offset;
	int		num_saved_states;
	direction_enum	dir;
} pkt_id;

typedef struct {
	direction_enum	dir;
	int		cnt;
	gboolean	esc;
	guint8		buf[8192];
	long		id_offset;
} pkt_t;

/* Partial-record state */
typedef struct {
	int		num_bytes;
	pkt_t		*pkt;
} prec_state;

struct _pppdump_t;

typedef struct _pppdump_t {
	time_t			timestamp;
	guint			tenths;
	pkt_t			spkt;
	pkt_t			rpkt;
	long			offset;
	GList			*precs;
	struct _pppdump_t	*seek_state;
	GPtrArray		*pids;
	guint			pkt_cnt;
	int			num_saved_states;
} pppdump_t;

static int
process_data(pppdump_t *state, FILE_T fh, pkt_t *pkt, int n, guint8 *pd, int *err,
		gboolean *state_saved);

static gboolean
collate(pppdump_t*, FILE_T fh, int *err, guint8 *pd, int *num_bytes,
		direction_enum *direction, pkt_id *pid);

static void
pppdump_close(wtap *wth);

static void
init_state(pppdump_t *state)
{

	dbg_print("INITIALIZING STATE 0x%08x\n", (unsigned int) state);
	state->precs = NULL;

	state->spkt.dir = DIRECTION_SENT;
	state->spkt.cnt = 0;
	state->spkt.esc = FALSE;
	state->spkt.id_offset = 0;

	state->rpkt.dir = DIRECTION_RECV;
	state->rpkt.cnt = 0;
	state->rpkt.esc = FALSE;
	state->rpkt.id_offset = 0;

	state->seek_state = NULL;
	state->offset = 0x100000; /* to detect errors during development */
}

#ifdef DEBUG
static
void print_hex_data_text(const u_char *cp, unsigned int length)
{
        register int ad, i, j, k;
        u_char c;
        u_char line[60];
	static u_char binhex[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        memset (line, ' ', sizeof line);
        line[sizeof (line)-1] = 0;
        for (ad=i=j=k=0; i<length; i++) {
                c = *cp++;
                line[j++] = binhex[c>>4];
                line[j++] = binhex[c&0xf];
                if (i&1) j++;
                line[42+k++] = c >= ' ' && c < 0x7f ? c : '.';
                if ((i & 15) == 15) {
                        printf ("\n%4x  %s", ad, line);
                        /*if (i==15) printf (" %d", length);*/
                        memset (line, ' ', sizeof line);
                        line[sizeof (line)-1] = j = k = 0;
                        ad += 16;
                }
        }

        if (line[0] != ' ') printf ("\n%4x  %s", ad, line);
        printf("\n");
        return;

}
#endif


	
int
pppdump_open(wtap *wth, int *err)
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

	file_seek(wth->fh, 0, SEEK_SET); 
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

	state = wth->capture.generic = g_malloc(sizeof(pppdump_t));
	state->timestamp = pntohl(&buffer[1]);
	state->tenths = 0;
	dbg_print("pppdump time is %lu\n", state->start_time);

	init_state(state);

	state->offset = 5; 
	file_seek(wth->fh, 5, SEEK_SET); 
	wth->file_encap = WTAP_ENCAP_PPP; 
	wth->file_type = WTAP_FILE_PPPDUMP; 

	wth->snapshot_length = 8192; /* just guessing */ 
	wth->subtype_read = pppdump_read; 
	wth->subtype_seek_read = pppdump_seek_read; 
	wth->subtype_close = pppdump_close;

	state->seek_state = g_malloc(sizeof(pppdump_t));

	state->pids = g_ptr_array_new();
	state->pkt_cnt = 0;
	state->num_saved_states = 0;

	return 1;
}

/* Find the next packet and parse it; called from wtap_loop(). */
static gboolean
pppdump_read(wtap *wth, int *err, int *data_offset)
{
	gboolean	retval;
	int		num_bytes;
	direction_enum	direction;
	guint8		*buf;
	pppdump_t	*state;
	pkt_id		*pid;

	dbg_print("======================================================\n");

	buffer_assure_space(wth->frame_buffer, 8192);
	buf = buffer_start_ptr(wth->frame_buffer);

	state = wth->capture.generic;
	pid = g_new(pkt_id, 1);
	if (!pid) {
		return FALSE;
	}
	pid->offset = 0;
	pid->num_saved_states = 0;

	retval = collate(state, wth->fh, err, buf, &num_bytes, &direction, pid);

	dbg_print("Record %u ended with pid offset = 0x%lx num_ss = %d\n", 
			state->pkt_cnt, pid->offset, pid->num_saved_states);

	if (!retval) {
		g_free(pid);
		return FALSE;
	}

	pid->dir = direction;

	g_ptr_array_add(state->pids, pid);
	/* The user's data_offset is not really an offset, but a packet number. */
	*data_offset = state->pkt_cnt;
	state->pkt_cnt++;

	wth->phdr.len		= num_bytes;
	wth->phdr.caplen	= num_bytes;
	wth->phdr.ts.tv_sec	= state->timestamp;
	wth->phdr.ts.tv_usec	= state->tenths * 100000;
	wth->phdr.pkt_encap	= WTAP_ENCAP_PPP;

	return TRUE;
}

#define PKT(x)	(x)->dir == DIRECTION_SENT ? "SENT" : "RECV"

static gboolean
save_prec_state(pppdump_t *state, int num_bytes, pkt_t *pkt)
{
	prec_state	*prec;

	prec = g_new(prec_state, 1);
	if (!prec) {
		return FALSE;
	}
	prec->num_bytes = num_bytes;
	prec->pkt = pkt;

	dbg_print("saved state of num_bytes=%d pkt=0x%08x (%s) pkt->cnt=%d\n",
			num_bytes, (unsigned int) pkt, PKT(pkt), pkt->cnt);
	state->precs = g_list_append(state->precs, prec);
	return TRUE;
}

static int
process_data_from_prec_state(pppdump_t *state, FILE_T fh, guint8* pd, int *err,
		gboolean *state_saved, pkt_t **ppkt)
{
	prec_state	*prec;

	prec = state->precs->data;

	state->precs = g_list_remove(state->precs, prec);

	dbg_print("retrieved state of num_bytes=%d ", prec->num_bytes);
	*ppkt = prec->pkt;
	dbg_print("pkt=0x%08x (%s) pkt->cnt = %d\n", (unsigned int) prec->pkt, PKT(prec->pkt), prec->pkt->cnt);

	return process_data(state, fh, prec->pkt, prec->num_bytes, pd, err, state_saved);
}
	


/* Returns number of bytes copied for record, -1 if failure.
 *
 * This is modeled after pppdump.c, the utility to parse pppd log files; it comes with the ppp
 * distribution.
 */
static int
process_data(pppdump_t *state, FILE_T fh, pkt_t *pkt, int n, guint8 *pd, int *err,
		gboolean *state_saved)
{
	int	c;
	int	num_bytes = n;
	int	num_written;

	*state_saved = FALSE;
	for (; num_bytes > 0; --num_bytes) {
		c = file_getc(fh);
		dbg_print("PD At offset 0x%lx got %c (0x%02x)\n", state->offset, c, c);
		state->offset++;
		switch (c) {
			case EOF:
				dbg_print("Unexpected EOF\n");
				if (*err == 0) {
					*err = WTAP_ERR_SHORT_READ;
				}
				return -1;
				break;

			case '~':
				if (pkt->cnt > 0) {
					pkt->esc = FALSE;

					num_written = pkt->cnt - 2;
					pkt->cnt = 0;
					if (num_written <= 0) {
						return 0;
					}

					memcpy(pd, pkt->buf, num_written);
					dbg_print("\n%s:\n", PKT(pkt));
#ifdef DEBUG
					print_hex_data_text(pd, num_written);
#endif

					num_bytes--;
					if (num_bytes > 0) {
						if (!save_prec_state(state, num_bytes, pkt)) {
							return -1;
						}
						*state_saved = TRUE;
					}
					dbg_print("returning with num_bytes   = %d\n", num_bytes);
					dbg_print("returning with num_written = %d\n", num_written);
					return num_written;
				}
				break;

			case '}':
				if (!pkt->esc) {
					pkt->esc = TRUE;
					break;
				}
				/* else fall through */

			default:
				if (pkt->esc) {
					c ^= 0x20;
					dbg_print("Changed  0x%02x\t%c\n", c, c);
					pkt->esc = FALSE;
				}
		
				pkt->buf[pkt->cnt++] = c;
				break;
		}
	}

	dbg_print("PD returning 0; no out bytes. pkt=0x%08x (%s) pkt->cnt=%d\n",
			(unsigned int) pkt, PKT(pkt), pkt->cnt);
	/* we could have run out of bytes to read */
	return 0;

}




/* Returns TRUE if packet data copied, FALSE if error occurred or EOF (no more records). */
static gboolean
collate(pppdump_t* state, FILE_T fh, int *err, guint8 *pd, int *num_bytes,
		direction_enum *direction, pkt_id *pid)
{
	int		id;
	pkt_t		*pkt = NULL;
	int		n, num_written = 0;
	gboolean	ss = FALSE;
	guint32		time_long;
	guint8		time_short;

	if (!state->precs) {
		state->num_saved_states = 0;
	}
	if (pid) {
		pid->num_saved_states = state->num_saved_states;
	}


	while (state->precs) {
		dbg_print("I see a saved state.\n");
		num_written = process_data_from_prec_state(state, fh, pd, err, &ss, &pkt);
		state->num_saved_states++;
		if (pid) {
			pid->num_saved_states++;
		}

		if (num_written < 0) {
			return FALSE;
		}
		else if (num_written > 0) {
			*num_bytes = num_written;
			*direction = pkt->dir;
			if (pid) {
				pid->offset = pkt->id_offset;
			}
			if (!ss) {
				pkt->id_offset = 0;
			}
			dbg_print("Returning, state->offset = 0x%lx\n", state->offset);
			return TRUE;
		}
		/* if 0 bytes written, keep processing */
	}
	dbg_print("No saved states.\n");

	while ((id = file_getc(fh)) != EOF) {
		dbg_print("CL At offset 0x%lx got %c (0x%02x)\n", state->offset, id, id);
		state->offset++;
		switch (id) {
			case PPPD_SENT_DATA:
			case PPPD_RECV_DATA:
				pkt = id == PPPD_SENT_DATA ? &state->spkt : &state->rpkt;

				if (pkt->id_offset == 0) {
					pkt->id_offset = state->offset - 1;
				}

				n = file_getc(fh);
				n = (n << 8) + file_getc(fh);
				state->offset += 2;

				dbg_print("ID: Going to read %d bytes for pkt=0x%08x (%s)\n", n,
						(unsigned int) pkt, PKT(pkt));

				num_written = process_data(state, fh, pkt, n, pd, err, &ss);

				if (num_written < 0) {
					return FALSE;
				}
				else if (num_written > 0) {
					*num_bytes = num_written;
					*direction = pkt->dir;
					if (pid) {
						pid->offset = pkt->id_offset;
					}
					if (!ss) {
						pkt->id_offset = 0;
					}
					dbg_print("Returning, state->offset = 0x%lx\n", state->offset);
					return TRUE;
				}
				/* if 0 bytes written, keep looping */
				
				break;

			case PPPD_SEND_DELIM:
			case PPPD_RECV_DELIM:
				/* What can we do? */
				dbg_print("GOT *_DELIM\n");
				break;

			case PPPD_TIME_STEP_LONG:
				dbg_print("GOT *_TIME 32\n");
				wtap_file_read_unknown_bytes(&time_long, sizeof(guint32), fh, err);
				state->offset += sizeof(guint32);
				state->timestamp = time_long;
				state->tenths = 0;
				break;

			case PPPD_RESET_TIME:
				dbg_print("GOT *_TIME 32\n");
				wtap_file_read_unknown_bytes(&time_long, sizeof(guint32), fh, err);
				state->offset += sizeof(guint32);
				state->tenths += time_long;

				if (state->tenths >= 10) {
					state->timestamp += state->tenths / 10;
					state->tenths = state->tenths % 10;
				}

				break;

			case PPPD_TIME_STEP_SHORT:
				dbg_print("GOT *_TIME 8\n");
				wtap_file_read_unknown_bytes(&time_short, sizeof(guint8), fh, err);
				state->offset += sizeof(guint8);
				state->tenths += time_short;

				if (state->tenths >= 10) {
					state->timestamp += state->tenths / 10;
					state->tenths = state->tenths % 10;
				}

				break;

			default:
				dbg_print("BAD ID: 0x%02x\n", id);
				/* XXX - bad file */
				g_assert_not_reached();
		}

	}

	return FALSE;
}



/* Used to read packets in random-access fashion */
static int
pppdump_seek_read (wtap *wth,
		 int seek_off,
		 union wtap_pseudo_header *pseudo_header,
		 guint8 *pd,
		 int len)
{
	int		err = 0;
	int		num_bytes;
	direction_enum	direction;
	gboolean	retval;
	pppdump_t	*state;
	pkt_id		*pid;
	int		i;


	dbg_print(">>>>>>>>>>>> SEEKING to packet # %d\n", seek_off);
	state = wth->capture.generic;

	pid = g_ptr_array_index(state->pids, seek_off);
	if (!pid) {
		return -1;
	}

	dbg_print(">>>>>>>>>>>> SEEKING to offset %ld (0x%lx), num_ss=%d\n",
			pid->offset, pid->offset, pid->num_saved_states);
	file_seek(wth->random_fh, pid->offset, SEEK_SET);

	init_state(state->seek_state);

	for (i = 0 ; i <= pid->num_saved_states; i++) {
		dbg_print("Loop=%d\n", i);
	  again:
		retval = collate(state->seek_state, wth->random_fh, &err, pd, &num_bytes,
				&direction, NULL);

		if (!retval) {
			return -1;
		}

		if (direction != pid->dir) {
			dbg_print("Looping because wrong direction.\n");
			goto again;
		}
		dbg_print("Got right direction.\n");
	}

	if (len != num_bytes) {
		return -1;
	}


	dbg_print(">>>>>>>>>>>> COPIED %d bytes\n", num_bytes);

	return 0;
}

static void
simple_g_free(gpointer data, gpointer junk)
{
	if (data)
		g_free(data);
}

static void
pppdump_close(wtap *wth)
{
	pppdump_t	*state;

	state = wth->capture.generic;

	if (state->precs) {
		g_list_foreach(state->precs, simple_g_free, NULL);
		g_list_free(state->precs);
	}

	if (state->seek_state) { /* should always be TRUE */
		g_free(state->seek_state);
	}

	if (state->pids) { /* should always be TRUE */
		g_ptr_array_free(state->pids, TRUE); /* free data, too */
	}

	g_free(state);

}
