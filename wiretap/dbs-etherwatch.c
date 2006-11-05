/* dbs-etherwatch.c
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 2001 by Marc Milgram <ethereal@mmilgram.NOSPAMmail.net>
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
#include "dbs-etherwatch.h"
#include "file_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* This module reads the text output of the 'DBS-ETHERTRACE' command in VMS
 * It was initially based on vms.c.
 */

/*
   Example 'ETHERWATCH' output data:
ETHERWATCH  X5-008
42 names and addresses were loaded
Reading recorded data from PERSISTENCE
------------------------------------------------------------------------------
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   60 byte buffer at 10-OCT-2001 10:20:45.16
  [E..<8.....Ò.....]-    0-[45 00 00 3C 38 93 00 00 1D 06 D2 12 80 93 11 1A]
  [...Ö.Ò...(¤.....]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 90 00 00 00 00]
  [.....½.....´....]-   32-[A0 02 FF FF 95 BD 00 00 02 04 05 B4 03 03 04 01]
  [......å.....    ]-   48-[01 01 08 0A 90 90 E5 14 00 00 00 00]
------------------------------------------------------------------------------
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   50 byte buffer at 10-OCT-2001 10:20:45.17
  [E..(8.....Ò%....]-    0-[45 00 00 28 38 94 00 00 1D 06 D2 25 80 93 11 1A]
  [...Ö.Ò...(¤.Z.4w]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 91 5A 1C 34 77]
  [P.#(Ás.....´....]-   32-[50 10 23 28 C1 73 00 00 02 04 05 B4 03 03 00 00]
  [..              ]-   48-[02 04]


Alternative HEX only output, slightly more efficient and all wireshark needs:
------------------------------------------------------------------------------
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   50 byte buffer at 10-OCT-2001 10:20:45.17
     0-[45 00 00 28 38 9B 00 00 1D 06 D2 1E 80 93 11 1A 80 93 80 D6]
    20-[02 D2 02 03 00 28 A4 BF 5A 1C 34 79 50 10 23 28 C1 43 00 00]
    40-[03 30 30 30 30 30 00 00 03 30]
 */

/* Magic text to check for DBS-ETHERWATCH-ness of file */
static const char dbs_etherwatch_hdr_magic[]  =
{ 'E', 'T', 'H', 'E', 'R', 'W', 'A', 'T', 'C', 'H', ' ', ' '};
#define DBS_ETHERWATCH_HDR_MAGIC_SIZE  \
        (sizeof dbs_etherwatch_hdr_magic  / sizeof dbs_etherwatch_hdr_magic[0])

/* Magic text for start of packet */
static const char dbs_etherwatch_rec_magic[]  =
{'F', 'r', 'o', 'm', ' '};
#define DBS_ETHERWATCH_REC_MAGIC_SIZE \
	(sizeof dbs_etherwatch_rec_magic  / sizeof dbs_etherwatch_rec_magic[0])

/*
 * XXX - is this the biggest packet we can get?
 */
#define DBS_ETHERWATCH_MAX_PACKET_LEN	16384

static gboolean dbs_etherwatch_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);
static gboolean dbs_etherwatch_seek_read(wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
	int *err, gchar **err_info);
static int parse_dbs_etherwatch_packet(wtap *wth, FILE_T fh, guint8* buf,
	int *err, gchar **err_info);
static guint parse_single_hex_dump_line(char* rec, guint8 *buf,
	int byte_offset);
static guint parse_hex_dump(char* dump, guint8 *buf, char seperator, char end);

/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure, and sets "*err" to the error. */
static gint64 dbs_etherwatch_seek_next_packet(wtap *wth, int *err)
{
  int byte;
  unsigned int level = 0;
  gint64 cur_off;

  while ((byte = file_getc(wth->fh)) != EOF) {
    if (byte == dbs_etherwatch_rec_magic[level]) {
      level++;
      if (level >= DBS_ETHERWATCH_REC_MAGIC_SIZE) {
        /* note: we're leaving file pointer right after the magic characters */
        cur_off = file_tell(wth->fh);
        if (cur_off == -1) {
          /* Error. */
          *err = file_error(wth->fh);
          return -1;
        }
        return cur_off + 1;
      }
    } else {
      level = 0;
    }
  }
  if (file_eof(wth->fh)) {
    /* We got an EOF. */
    *err = 0;
  } else {
    /* We (presumably) got an error (there's no equivalent to "ferror()"
       in zlib, alas, so we don't have a wrapper to check for an error). */
    *err = file_error(wth->fh);
  }
  return -1;
}

#define DBS_ETHERWATCH_HEADER_LINES_TO_CHECK	200
#define DBS_ETHERWATCH_LINE_LENGTH		240

/* Look through the first part of a file to see if this is
 * a DBS Ethertrace text trace file.
 *
 * Returns TRUE if it is, FALSE if it isn't or if we get an I/O error;
 * if we get an I/O error, "*err" will be set to a non-zero value.
 */
static gboolean dbs_etherwatch_check_file_type(wtap *wth, int *err)
{
	char	buf[DBS_ETHERWATCH_LINE_LENGTH];
	int	line, byte;
	unsigned int reclen, i, level;

	buf[DBS_ETHERWATCH_LINE_LENGTH-1] = 0;

	for (line = 0; line < DBS_ETHERWATCH_HEADER_LINES_TO_CHECK; line++) {
		if (file_gets(buf, DBS_ETHERWATCH_LINE_LENGTH, wth->fh)!=NULL){

			reclen = strlen(buf);
			if (reclen < DBS_ETHERWATCH_HDR_MAGIC_SIZE)
				continue;

			level = 0;
			for (i = 0; i < reclen; i++) {
				byte = buf[i];
				if (byte == dbs_etherwatch_hdr_magic[level]) {
					level++;
					if (level >=
					      DBS_ETHERWATCH_HDR_MAGIC_SIZE) {
						return TRUE;
					}
				}
				else
					level = 0;
			}
		}
		else {
			/* EOF or error. */
			if (file_eof(wth->fh))
				*err = 0;
			else
				*err = file_error(wth->fh);
			return FALSE;
		}
	}
	*err = 0;
	return FALSE;
}


int dbs_etherwatch_open(wtap *wth, int *err, gchar **err_info _U_)
{
	/* Look for DBS ETHERWATCH header */
	if (!dbs_etherwatch_check_file_type(wth, err)) {
		if (*err == 0)
			return 0;
		else
			return -1;
	}

	wth->data_offset = 0;
	wth->file_encap = WTAP_ENCAP_ETHERNET;
	wth->file_type = WTAP_FILE_DBS_ETHERWATCH;
	wth->snapshot_length = 0;	/* not known */
	wth->subtype_read = dbs_etherwatch_read;
	wth->subtype_seek_read = dbs_etherwatch_seek_read;
	wth->tsprecision = WTAP_FILE_TSPREC_CSEC;

	return 1;
}

/* Find the next packet and parse it; called from wtap_read(). */
static gboolean dbs_etherwatch_read(wtap *wth, int *err, gchar **err_info,
    gint64 *data_offset)
{
	gint64	offset;
	guint8	*buf;
	int	pkt_len;

	/* Find the next packet */
	offset = dbs_etherwatch_seek_next_packet(wth, err);
	if (offset < 1)
		return FALSE;

	/* Make sure we have enough room for the packet */
	buffer_assure_space(wth->frame_buffer, DBS_ETHERWATCH_MAX_PACKET_LEN);
	buf = buffer_start_ptr(wth->frame_buffer);

	/* Parse the packet */
	pkt_len = parse_dbs_etherwatch_packet(wth, wth->fh, buf, err, err_info);
	if (pkt_len == -1)
		return FALSE;

	/*
	 * We don't have an FCS in this frame.
	 */
	wth->pseudo_header.eth.fcs_len = 0;

	wth->data_offset = offset;
	*data_offset = offset;
	return TRUE;
}

/* Used to read packets in random-access fashion */
static gboolean
dbs_etherwatch_seek_read (wtap *wth, gint64 seek_off,
	union wtap_pseudo_header *pseudo_header _U_,
	guint8 *pd, int len, int *err, gchar **err_info)
{
	int	pkt_len;

	if (file_seek(wth->random_fh, seek_off - 1, SEEK_SET, err) == -1)
		return FALSE;

	pkt_len = parse_dbs_etherwatch_packet(NULL, wth->random_fh, pd, err,
	    err_info);

	if (pkt_len != len) {
		if (pkt_len != -1) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup_printf("dbs_etherwatch: packet length %d doesn't match requested length %d",
			    pkt_len, len);
		}
		return FALSE;
	}

	/*
	 * We don't have an FCS in this frame.
	 */
	pseudo_header->eth.fcs_len = 0;

	return TRUE;
}

/* Parse a packet */
/*
Packet header:
          1         2         3         4
0123456789012345678901234567890123456789012345
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   50 byte buffer at 10-OCT-2001 10:20:45.17
*/
#define MAC_ADDR_LENGTH		6			/* Length MAC address */
#define DEST_MAC_PREFIX		"] to "		/* Prefix to the dest. MAC address */
#define PROTOCOL_LENGTH		2			/* Length protocol */
#define PROTOCOL_POS		9			/* Position protocol */
#define SAP_LENGTH			2			/* Length DSAP+SSAP */
#define SAP_POS				9			/* Position DSAP+SSAP */
#define CTL_UNNUMB_LENGTH	1			/* Length unnumbered control field */
#define CTL_NUMB_LENGTH		2			/* Length numbered control field */
#define CTL_POS				15			/* Position control field */
#define PID_LENGTH			5			/* Length PID */
#define PID_POS				18			/* Position PID */
#define LENGTH_POS			33			/* Position length */
#define HEX_HDR_SPR			'-'			/* Seperator char header hex values */
#define HEX_HDR_END			' '			/* End char hdr. hex val. except PID */
#define HEX_PID_END			','			/* End char PID hex value */
#define IEEE802_LEN_LEN		2			/* Length of the IEEE 802 len. field */
/*
To check whether it is Ethernet II or IEEE 802 we check the values of the
control field and PID, when they are all 0's we assume it is Ethernet II
else IEEE 802. In IEEE 802 the DSAP and SSAP are behind protocol, the
length in the IEEE data we have to construct.
*/
#define ETH_II_CHECK_POS    15
#define ETH_II_CHECK_STR    "00 00-00-00-00-00,"
/*
To check whether it IEEE 802.3 with SNAP we check that both the DSAP & SSAP
values are 0xAA and the control field 0x03.
*/
#define SNAP_CHECK_POS		9
#define SNAP_CHECK_STR		"AA-AA 03"
/*
To check whether the control field is 1 or two octets we check if it is
unnumbered. Unnumbered has length 1, numbered 2.
*/
#define CTL_UNNUMB_MASK		0x03
#define CTL_UNNUMB_VALUE	0x03
static int
parse_dbs_etherwatch_packet(wtap *wth, FILE_T fh, guint8* buf, int *err,
    gchar **err_info)
{
	char	line[DBS_ETHERWATCH_LINE_LENGTH];
	int	num_items_scanned;
	int	eth_hdr_len, pkt_len, csec;
	int length_pos, length_from, length;
	struct tm tm;
	char mon[4];
	gchar *p;
	static gchar months[] = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC";
	int	count, line_count;

	eth_hdr_len = 0;
	/* Our file pointer should be on the first line containing the
	 * summary information for a packet. Read in that line and
	 * extract the useful information
	 */
	if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
		*err = file_error(fh);
		if (*err == 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	/* Get the destination address */
	p = strstr(line, DEST_MAC_PREFIX);
	if(!p) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup("dbs_etherwatch: destination address not found");
		return -1;
	}
	p += strlen(DEST_MAC_PREFIX);
	if(parse_hex_dump(p, &buf[eth_hdr_len], HEX_HDR_SPR, HEX_HDR_END)
				!= MAC_ADDR_LENGTH) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup("dbs_etherwatch: destination address not valid");
		return -1;
	}
	eth_hdr_len += MAC_ADDR_LENGTH;

	/* Get the source address */
	/*
	 * Since the first part of the line is already skipped in order to find
	 * the start of the record we cannot index, just look for the first
	 * 'HEX' character
	 */
	p = line;
	while(!isxdigit((guchar)*p)) {
		p++;
	}
	if(parse_hex_dump(p, &buf[eth_hdr_len], HEX_HDR_SPR,
		HEX_HDR_END) != MAC_ADDR_LENGTH) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup("dbs_etherwatch: source address not valid");
		return -1;
	}
	eth_hdr_len += MAC_ADDR_LENGTH;

	/* Read the next line of the record header */
	if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
		*err = file_error(fh);
		if (*err == 0) {
			*err = WTAP_ERR_SHORT_READ;
		}
		return -1;
	}

	/* Check the lines is as least as long as the length position */
	if(strlen(line) < LENGTH_POS) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup("dbs_etherwatch: line too short");
		return -1;
	}

	num_items_scanned = sscanf(line + LENGTH_POS,
				"%d byte buffer at %d-%3s-%d %d:%d:%d.%d",
				&pkt_len,
				&tm.tm_mday, mon,
				&tm.tm_year, &tm.tm_hour, &tm.tm_min,
				&tm.tm_sec, &csec);

	if (num_items_scanned != 8) {
		*err = WTAP_ERR_BAD_RECORD;
		*err_info = g_strdup("dbs_etherwatch: header line not valid");
		return -1;
	}
	
	/* Determine whether it is Ethernet II or IEEE 802 */
	if(strncmp(&line[ETH_II_CHECK_POS], ETH_II_CHECK_STR,
		strlen(ETH_II_CHECK_STR)) == 0) {
		/* Ethernet II */
		/* Get the Protocol */
		if(parse_hex_dump(&line[PROTOCOL_POS], &buf[eth_hdr_len], HEX_HDR_SPR,
					HEX_HDR_END) != PROTOCOL_LENGTH) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup("dbs_etherwatch: Ethernet II protocol value not valid");
			return -1;
		}
		eth_hdr_len += PROTOCOL_LENGTH;
	} else {
		/* IEEE 802 */
		/* Remember where to put the length in the header */
		length_pos = eth_hdr_len;
		/* Leave room in the header for the length */
		eth_hdr_len += IEEE802_LEN_LEN;
		/* Remember how much of the header should not be added to the length */
		length_from = eth_hdr_len;
		/* Get the DSAP + SSAP */
		if(parse_hex_dump(&line[SAP_POS], &buf[eth_hdr_len], HEX_HDR_SPR,
					HEX_HDR_END) != SAP_LENGTH) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup("dbs_etherwatch: 802.2 DSAP+SSAP value not valid");
			return -1;
		}
		eth_hdr_len += SAP_LENGTH;
		/* Get the (first part of the) control field */
		if(parse_hex_dump(&line[CTL_POS], &buf[eth_hdr_len], HEX_HDR_SPR,
					HEX_HDR_END) != CTL_UNNUMB_LENGTH) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup("dbs_etherwatch: 802.2 control field first part not valid");
			return -1;
		}
		/* Determine whether the control is numbered, and thus longer */
		if((buf[eth_hdr_len] & CTL_UNNUMB_MASK) != CTL_UNNUMB_VALUE) {
			/* Get the rest of the control field, the first octet in the PID */
			if(parse_hex_dump(&line[PID_POS],
						&buf[eth_hdr_len + CTL_UNNUMB_LENGTH], HEX_HDR_END,
						HEX_HDR_SPR) != CTL_NUMB_LENGTH - CTL_UNNUMB_LENGTH) {
				*err = WTAP_ERR_BAD_RECORD;
				*err_info = g_strdup("dbs_etherwatch: 802.2 control field second part value not valid");
				return -1;
			}
			eth_hdr_len += CTL_NUMB_LENGTH;
		} else {
			eth_hdr_len += CTL_UNNUMB_LENGTH;
		}
		/* Determine whether it is SNAP */
		if(strncmp(&line[SNAP_CHECK_POS], SNAP_CHECK_STR,
				strlen(SNAP_CHECK_STR)) == 0) {
			/* Get the PID */
			if(parse_hex_dump(&line[PID_POS], &buf[eth_hdr_len], HEX_HDR_SPR,
						HEX_PID_END) != PID_LENGTH) {
				*err = WTAP_ERR_BAD_RECORD;
				*err_info = g_strdup("dbs_etherwatch: 802.2 PID value not valid");
				return -1;
			}
			eth_hdr_len += PID_LENGTH;
		}
		/* Write the length in the header */
		length = eth_hdr_len - length_from + pkt_len;
		buf[length_pos] = (length) >> 8;
		buf[length_pos+1] = (length) & 0xFF;
	}

	if (wth) {
		p = strstr(months, mon);
		if (p)
			tm.tm_mon = (p - months) / 3;
		tm.tm_year -= 1900;

		tm.tm_isdst = -1;
		wth->phdr.ts.secs = mktime(&tm);
		wth->phdr.ts.nsecs = csec * 10000000;
		wth->phdr.caplen = eth_hdr_len + pkt_len;
		wth->phdr.len = eth_hdr_len + pkt_len;
	}

	/* Parse the hex dump */
	count = 0;
	while (count < pkt_len) {
		if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
			*err = file_error(fh);
			if (*err == 0) {
				*err = WTAP_ERR_SHORT_READ;
			}
			return -1;
		}
		if (!(line_count = parse_single_hex_dump_line(line,
				&buf[eth_hdr_len + count], count))) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup("dbs_etherwatch: packet data value not valid");
			return -1;
		}
		count += line_count;
		if (count > pkt_len) {
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup("dbs_etherwatch: packet data value has too many bytes");
			return -1;
		}
	}
	return eth_hdr_len + pkt_len;
}

/* Parse a hex dump line */
/*
/DISPLAY=BOTH output:

          1         2         3         4
0123456789012345678901234567890123456789012345
  [E..(8.....Ò.....]-    0-[45 00 00 28 38 9B 00 00 1D 06 D2 1E 80 93 11 1A]
  [...Ö.Ò...(¤¿Z.4y]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 BF 5A 1C 34 79]
  [P.#(ÁC...00000..]-   32-[50 10 23 28 C1 43 00 00 03 30 30 30 30 30 00 00]
  [.0              ]-   48-[03 30]

/DISPLAY=HEXADECIMAL output:

          1         2         3         4
0123456789012345678901234567890123456789012345
     0-[45 00 00 28 38 9B 00 00 1D 06 D2 1E 80 93 11 1A 80 93 80 D6]
    20-[02 D2 02 03 00 28 A4 BF 5A 1C 34 79 50 10 23 28 C1 43 00 00]
    40-[03 30 30 30 30 30 00 00 03 30]

*/

#define TYPE_CHECK_POS		2	/* Position to check the type of hex dump */
#define TYPE_CHECK_BOTH		'['	/* Value at pos. that indicates BOTH type */
#define COUNT_POS_BOTH		21	/* Count position BOTH type */
#define COUNT_POS_HEX		1	/* Count position HEX type */
#define COUNT_SIZE         	5	/* Length counter */
#define HEX_DUMP_START		'['	/* Start char */
#define HEX_DUMP_SPR		' ' /* Seperator char */
#define HEX_DUMP_END		']' /* End char */

/* Take a string representing one line from a hex dump and converts the
 * text to binary data. We check the printed offset with the offset
 * we are passed to validate the record. We place the bytes in the buffer
 * at the specified offset.
 *
 * Returns length parsed if a good hex dump, 0 if bad.
 */
static guint
parse_single_hex_dump_line(char* rec, guint8 *buf, int byte_offset) {

	int		pos, i;
	int		value;


	/* Check that the record is as least as long as the check offset */
	for(i = 0; i < TYPE_CHECK_POS; i++)
	{
		if(rec[i] == '\0') {
			return 0;
		}
	}
	/* determine the format and thus the counter offset and hex dump length */
	if(rec[TYPE_CHECK_POS] == TYPE_CHECK_BOTH)
	{
		pos = COUNT_POS_BOTH;
	}
	else
	{
		pos = COUNT_POS_HEX;
	}	

	/* Check that the record is as least as long as the start position */
	while(i < pos)
	{
		if(rec[i] == '\0') {
			return 0;
		}
		i++;
	}

	/* Get the byte_offset directly from the record */
	value = 0;
	for(i = 0; i < COUNT_SIZE; i++) {
		if(!isspace((guchar)rec[pos])) {
			if(isdigit((guchar)rec[pos])) {
				value *= 10;
				value += rec[pos] - '0';
			} else {
				return 0;
			}
		}
		pos++;
	}

	if (value != byte_offset) {
		return 0;
	}

	/* find the start of the hex dump */
	while(rec[pos] != HEX_DUMP_START) {
		if(rec[pos] == '\0') {
			return 0;
		}
		pos++;
	}
	pos++;
	return parse_hex_dump(&rec[pos], buf, HEX_DUMP_SPR, HEX_DUMP_END);
}

/* Parse a hex dump */
static guint
parse_hex_dump(char* dump, guint8 *buf, char seperator, char end) {
	int		pos, count;

	/* Parse the hex dump */
	pos = 0;
	count = 0;
	while(dump[pos] != end) {
		/* Check the hex value */
		if(!(isxdigit((guchar)dump[pos]) &&
		    isxdigit((guchar)dump[pos + 1]))) {
			return 0;
		}
		/* Get the hex value value */
		if(isdigit((guchar)dump[pos])) {
			buf[count] = (dump[pos] - '0') << 4;
		} else {
			buf[count] = (toupper(dump[pos]) - 'A' + 10) << 4;
		}
		pos++;
		if(isdigit((guchar)dump[pos])) {
			buf[count] += dump[pos] - '0';
		} else {
			buf[count] += toupper(dump[pos]) - 'A' + 10;
		}
		pos++;
		count++;
		/* Skip the seperator characters */
		while(dump[pos] == seperator) {
			pos++;
		}
	}
	return count;
}
