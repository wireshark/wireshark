/* iseries.c
 *
 * $Id$
 *
 * Wiretap Library
 * Copyright (c) 2011 by Martin Warnes <Martin_Warnes@uk.ibm.com>
 *
 * Based on toshiba.c and vms.c
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
 * This module will read the contents of the iSeries (OS/400) Communication trace
 * Both ASCII & Unicode formatted traces are supported.
 *
 * iSeries Comms traces consist of a header page and a subsequent number of packet records
 *
 * The header page contains details on the options set during running of the trace,
 * currently the following options are a requirement for this module:
 *
 * 1. Object protocol = ETHERNET (Default)
 * 2. ASCII or UNICODE file formats.
 *
 * The above can be acheived by passing option ASCII(*YES) with the trace command
 *
 */

/* iSeries header page

 COMMUNICATIONS TRACE       Title: OS400 - OS400 trace               10/28/05  11:44:50                           Page:       1
   Trace Description  . . . . . :   OS400 - OS400 trace
   Configuration object . . . . :   ETH0
   Type . . . . . . . . . . . . :   1            1=Line, 2=Network Interface
                                                 3=Network server
   Object protocol  . . . . . . :   ETHERNET
   Start date/Time  . . . . . . :   10/28/05  11:43:00.341
   End date/Time  . . . . . . . :   10/28/05  11:44:22.148
   Bytes collected  . . . . . . :   11999
   Buffer size  . . . . . . . . :   2048         kilobytes
   Data direction . . . . . . . :   3            1=Sent, 2=Received, 3=Both
   Stop on buffer full  . . . . :   Y            Y=Yes, N=No
   Number of bytes to trace
     Beginning bytes  . . . . . :   *MAX         Value, *CALC, *MAX
     Ending bytes   . . . . . . :   *CALC        Value, *CALC
   Controller name  . . . . . . :   *ALL         *ALL, name
   Data representation  . . . . :   1            1=ASCII, 2=EBCDIC, 3=*CALC
   Format SNA data only . . . . :   N            Y=Yes, N=No
   Format RR, RNR commands  . . :   N            Y=Yes, N=No
   Format TCP/IP data only  . . :   Y            Y=Yes, N=No
     IP address . . . . . . . . :   *ALL             *ALL, address
     IP address . . . . . . . . :   *ALL             *ALL, address
     IP port  . . . . . . . . . :   *ALL             *ALL, IP port
   Format UI data only  . . . . :   N            Y=Yes, N=No
   Select Ethernet data . . . . :   3            1=802.3, 2=ETHV2, 3=Both
   Format Broadcast data  . . . :   Y            Y=Yes, N=No
*/

/* iSeries IPv4 formatted packet records consist of a header line identifying the packet number,direction,size,
 * timestamp,source/destination MAC addresses and packet type.
 *
 * Thereafter there will be a formated display of the IP and TCP headers as well as a hex string dump
 * of the headers themselves displayed in the the "IP Header" and "TCP header" fields.
 *
 * If the packet contains data this is displayed as 4 groups of 16 hex digits followed by an ASCII
 * representaion of the data line.
 *
 * Information from the header line, IP header, TCP header and if available data lines are extracted
 * by the module for displaying.
 *
 *
 Record       Data    Record           Controller  Destination   Source        Frame
 Number  S/R  Length  Timer            Name        MAC Address   MAC Address   Format
 ------  ---  ------  ---------------  ----------  ------------  ------------  ------
      8   S      145  11:43:59.82956               0006299C14AE  0006299C14FE   ETHV2   Type: 0800
                      Frame Type :  IP          DSCP: 0   ECN: 00-NECT  Length:   145   Protocol: TCP         Datagram ID: 388B
                                    Src Addr: 10.20.144.150       Dest Addr: 10.20.144.151       Fragment Flags: DON'T,LAST
                      IP Header  :  45000091388B40004006CC860A1490960A149097
                      IP Options :  NONE
                      TCP  . . . :  Src Port:  6006,Unassigned    Dest Port: 35366,Unassigned
                                    SEQ Number:  2666470699 ('9EEF1D2B'X)  ACK Number: 2142147535 ('7FAE93CF'X)
                                    Code Bits: ACK PSH                  Window: 32648  TCP Option: NO OP
                      TCP Header :  17768A269EEF1D2B7FAE93CF80187F885B5600000101080A0517E0F805166DE0
         Data . . . . . :  5443503200020010 0000004980000000  B800000080470103 01001E0000002000   *TCP2.......I*...*...*G........ .*
                           002F010080000004 0300800700C00600  4002008000000304 00800000060FB067   *./..*.....*..*..@..*.....*....*G*
                           FC276228786B3EB0 EF34F5F1D27EF8DF  20926820E7B322AA 739F1FB20D         **'B(XK>**4***.** *H **"*S*.*.   *
*/

/* iSeries IPv6 formatted traces are similar to the IPv4 version above but data is no longer output as 4 hex sections
*

Record       Data      Record                       Destination   Source        Frame
Number  S/R  Length    Timer                        MAC Address   MAC Address   Format
------  ---  ------    ------------                 ------------  ------------  ------
   218   S     1488    15:01:14.389                 0011BC358680  00096B6BD918   ETHV2  Type: 86DD
                      IPv6   Data:  Ver: 06                      Traffic Class: 00            Flow Label: 000000
                                    Payload Length:  1448        Next Header: 06,TCP          Hop Limit:    64
                                    Src Addr:   fd00:0:0:20f2::122
                                    Dest Addr:  fd00:0:0:20a0::155
                      IPv6 Header:  6000000005A80640FD000000000020F20000000000000122FD000000000020A0
                                    0000000000000155
                      TCP  . . . :  Src Port: 21246,Unassigned    Dest Port: 13601,Unassigned
                                    SEQ Number:  2282300877 ('880925CD'X)  ACK Number: 3259003715 ('C2407343'X)
                                    Code Bits: ACK                      Window: 65535  TCP Option: NO OP
                      TCP Header :  52FE3521880925CDC24073438010FFFFCFBB00000101080A0E15127000237A08
         Data . . . . . :  54435032000200140000061880000000ECBEB867F0000000004CE640E6C1D9D5       *TCP2........*...***g*....L*@*****
                           C9D5C740E3C8C9E240C9E240E3C8C540E6C1D9D5C9D5C740C6C9C5D3C4404040       ****@****@**@***@*******@*****@@@*
                           4040404040404040404040404040404040404040404040404040404040404040       *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*
*/

/* iSeries unformatted packet record consist of the same header record as the formatted trace but all
 * other records are simply unformatted data containing IP, TCP and packet data combined.
 *
 Record       Data    Record           Controller  Destination   Source        Frame            Number  Number    Poll/
 Number  S/R  Length  Timer            Name        MAC Address   MAC Address   Format  Command  Sent    Received  Final  DSAP  SSAP
 ------  ---  ------  ---------------  ----------  ------------  ------------  ------  -------  ------  --------  -----  ----  ----
      1   R       64  12:19:29.97108               000629ECF48E  0006D78E23C2   ETHV2   Type: 0800
         Data . . . . . :  4500003C27954000 3A06CE3D9797440F  0A5964EAC4F50554 58C9915500000000   *E..<'*@.:.*=**D..YD***.TX**U....*
                           A00216D06A200000 020405B40402080A  1104B6C000000000 010303000B443BF1   **..*J .....*......**.........D;**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "wtap-int.h"
#include "buffer.h"
#include "iseries.h"
#include "file_wrappers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <wsutil/str_util.h>

#define ISERIES_HDR_MAGIC_STR	"COMMUNICATIONS TRACE"
#define ISERIES_HDR_MAGIC_LEN   20
#define ISERIES_UNICODE_HDR_MAGIC_LEN 17
#define ISERIES_PKT_MAGIC_STR   "ETHV2"
#define ISERIES_PKT_MAGIC_LEN   5
#define ISERIES_LINE_LENGTH     270
#define ISERIES_HDR_LINES_TO_CHECK  100
#define ISERIES_PKT_LINES_TO_CHECK  4
#define ISERIES_MAX_PACKET_LEN  16384
#define ISERIES_MAX_TRACE_LEN   99999999
#define ISERIES_PKT_ALLOC_SIZE (cap_len*2)+1
#define ISERIES_FORMAT_ASCII    1
#define ISERIES_FORMAT_UNICODE  2

typedef struct {
  gboolean have_date;     /* TRUE if we found a capture start date */
  int year, month, day;   /* The start date */
  gboolean tcp_formatted; /* TCP/IP data formated Y/N */
  gboolean ipv6_trace;    /* IPv4 or IPv6  */   
  int format;             /* Trace format type        */
} iseries_t;

static gboolean iseries_read (wtap * wth, int *err, gchar ** err_info,
			      gint64 *data_offset);
static gboolean iseries_seek_read (wtap * wth, gint64 seek_off,
				   union wtap_pseudo_header *pseudo_header,
				   guint8 * pd, int len, int *err,
				   gchar ** err_info);
static gboolean iseries_check_file_type (wtap * wth, int *err, gchar **err_info,
					 int format);
static gint64 iseries_seek_next_packet (wtap * wth, int *err, gchar **err_info);
static int iseries_parse_packet (wtap * wth, FILE_T fh,
				 union wtap_pseudo_header *pseudo_header,
				 guint8 * pd, int *err, gchar ** err_info);
static int iseries_UNICODE_to_ASCII (guint8 * buf, guint bytes);
static gboolean iseries_parse_hex_string (const char * ascii, guint8 * buf,
					  int len);

int
iseries_open (wtap * wth, int *err, gchar ** err_info)
{
  int bytes_read;
  gint offset;
  char magic[ISERIES_LINE_LENGTH];
  char unicodemagic[ISERIES_UNICODE_HDR_MAGIC_LEN] =
    { '\x43', '\x00', '\x4F', '\x00', '\x4D',
    '\x00', '\x4D', '\x00', '\x55', '\x00', '\x4E', '\x00', '\x49', '\x00',
    '\x43', '\x00', '\x41'
  };

  /*
   * Check that file starts with a valid iSeries COMMS TRACE header
   * by scanning for it in the first line
   */
  errno = WTAP_ERR_CANT_READ;
  bytes_read = file_read (&magic, sizeof magic, wth->fh);
  if (bytes_read != sizeof magic)
    {
      *err = file_error (wth->fh, err_info);
      if (*err != 0)
	return -1;
      return 0;
    }

  /* 
   * Check if this is a UNICODE formatted file by scanning for the magic string
   */
  offset=0;
  while (offset < ISERIES_LINE_LENGTH - ISERIES_UNICODE_HDR_MAGIC_LEN)
  {
	  if (memcmp (magic + offset, unicodemagic, ISERIES_UNICODE_HDR_MAGIC_LEN) == 0) {
		  if (file_seek (wth->fh, 0, SEEK_SET, err) == -1)
		  {
			  return 0;
		  }
		  /*
		  * Do some basic sanity checking to ensure we can handle the
		  * contents of this trace
		  */
		  if (!iseries_check_file_type (wth, err, err_info, ISERIES_FORMAT_UNICODE))
		  {
			  if (*err == 0)
				  return 0;
			  else
				  return -1;
		  }
		  wth->data_offset = 0;
		  wth->file_encap = WTAP_ENCAP_ETHERNET;
		  wth->file_type = WTAP_FILE_ISERIES;
		  wth->snapshot_length = 0;
		  wth->subtype_read = iseries_read;
		  wth->subtype_seek_read = iseries_seek_read;
		  wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		  if (file_seek (wth->fh, 0, SEEK_SET, err) == -1)
		  {
			  return 0;
		  }
		  return 1;
	  }
	  offset += 1;
  }

    /* 
   * Check if this is a ASCII formatted file by scanning for the magic string
   */
  offset=0;
  while (offset < ISERIES_LINE_LENGTH - ISERIES_HDR_MAGIC_LEN)
  {
	  if (memcmp (magic + offset, ISERIES_HDR_MAGIC_STR, ISERIES_HDR_MAGIC_LEN) == 0) {

		  if (file_seek (wth->fh, 0, SEEK_SET, err) == -1)
		  {
			  return 0;
		  }
		  /*
		  * Do some basic sanity checking to ensure we can handle the
		  * contents of this trace
		  */
		  if (!iseries_check_file_type (wth, err, err_info, ISERIES_FORMAT_ASCII))
		  {
			  if (*err == 0)
				  return 0;
			  else
				  return -1;
		  }
		  wth->data_offset = 0;
		  wth->file_encap = WTAP_ENCAP_ETHERNET;
		  wth->file_type = WTAP_FILE_ISERIES;
		  wth->snapshot_length = 0;
		  wth->subtype_read = iseries_read;
		  wth->subtype_seek_read = iseries_seek_read;
		  wth->tsprecision = WTAP_FILE_TSPREC_USEC;
		  if (file_seek (wth->fh, 0, SEEK_SET, err) == -1)
		  {
			  return 0;
		  }
		  return 1;
	  }
	  offset += 1;
  }

  /* Neither ASCII or UNICODE so not supported */
  return 0;
}

/*
 * Do some basic sanity checking to ensure we can handle the
 * contents of this trace by checking the header page for
 * requisit requirements and additional information.
 */
static gboolean
iseries_check_file_type (wtap * wth, int *err, gchar **err_info, int format)
{
  guint line;
  int num_items_scanned;
  char buf[ISERIES_LINE_LENGTH], protocol[9], type[5], work[2] = "";
  iseries_t *iseries;

  /* Save trace format for passing between packets */
  iseries = (iseries_t *) g_malloc (sizeof (iseries_t));
  wth->priv = (void *)iseries;
  iseries->have_date = FALSE;
  iseries->format = format;
  iseries->tcp_formatted = FALSE;
  iseries->ipv6_trace = FALSE;

  for (line = 0; line < ISERIES_HDR_LINES_TO_CHECK; line++)
    {
      if (file_gets (buf, ISERIES_LINE_LENGTH, wth->fh) != NULL)
	{
	  /*
	   * Check that we are dealing with an ETHERNET trace
	   */
	  if (iseries->format == ISERIES_FORMAT_UNICODE)
	    {	
            iseries_UNICODE_to_ASCII ((guint8 *)buf, ISERIES_LINE_LENGTH);
	    }
	  ascii_strup_inplace(buf);
	  num_items_scanned = sscanf (buf,
		  "%*[ \n\t]OBJECT PROTOCOL%*[ .:\n\t]%8s",
				      protocol);
	  if (num_items_scanned == 1)
	    {
	      if (memcmp (protocol, "ETHERNET", 8) != 0)
		return FALSE;
	    }

	  /*
	   * The header is the only place where the date part of the timestamp is held, so
	   * extract it here and store for all packets to access
	   */
	  num_items_scanned = sscanf (buf,
				      "%*[ \n\t]START DATE/TIME%*[ .:\n\t]%2d/%2d/%2d",
				      &iseries->month, &iseries->day,
				      &iseries->year);
	  if (num_items_scanned == 3)
	    {
	      iseries->have_date = TRUE;
	    }


	 /*
	  * Determine if this is a IPv4 or IPv6 trace
	  */
	  num_items_scanned =
		  sscanf (buf+78,
		  "%*[ \n\t]ETHV2%*[ .:\n\t]TYPE%*[ .:\n\t]%4s",type);
	  if (num_items_scanned == 1)
	  {
		  if (strncmp (type, "0800", 1) == 0) 
		  {
			iseries->ipv6_trace = FALSE;
		  }
		  if (strncmp (type, "86DD", 1) == 0) 
		  {
			iseries->ipv6_trace = TRUE;
		  }
	  }

	  /*
	  * Determine if the data has been formatted
	  */
	  /* IPv6 formatted */ 
	  num_items_scanned = sscanf (buf,
		  "%*[ \n\t]IPV6 HEADER%1s",
		  work);
	  if (num_items_scanned == 1)
	  {
		  iseries->tcp_formatted = TRUE;
		  return TRUE;
	  }	
	  /* IPv4 formatted */
	  num_items_scanned = sscanf (buf,
		  "%*[ \n\t]IP HEADER  %1s",
		  work);
	  if (num_items_scanned == 1)
	  {
		  iseries->tcp_formatted = TRUE;
		  return TRUE;
	  }

}
      else
	{
	  /* EOF or error. */
	  if (file_eof (wth->fh))
	    *err = 0;
	  else 
	    *err = file_error (wth->fh, err_info);
	  return FALSE;
	}
    }
  *err = 0;
  return TRUE;
}

/*
 * Find the next packet and parse it; called from wtap_read().
 */
static gboolean
iseries_read (wtap * wth, int *err, gchar ** err_info, gint64 *data_offset)
{
  gint64 offset;
  int pkt_len;

  /*
   * Locate the next packet
   */
  offset = iseries_seek_next_packet (wth, err, err_info);
  if (offset < 1)
    return FALSE;

  /*
   * Parse the packet and extract the various fields
   */
  pkt_len =
    iseries_parse_packet (wth, wth->fh, &wth->pseudo_header, NULL, err,
			  err_info);
  if (pkt_len == -1)
    return FALSE;

  wth->data_offset = offset;
  *data_offset = offset;
  return TRUE;
}

/*
 * Seeks to the beginning of the next packet, and returns the
 * byte offset.  Returns -1 on failure, and sets "*err" to the error
 * and "*err_info" to null or an additional error string.
 */
static gint64
iseries_seek_next_packet (wtap * wth, int *err, gchar **err_info)
{
  iseries_t *iseries = (iseries_t *)wth->priv;
  char buf[ISERIES_LINE_LENGTH],type[5];
  int line, num_items_scanned;
  gint64 cur_off;
  long buflen;

  /*
   * Seeks to the beginning of the next packet, and returns the
   * byte offset.  Returns -1 on failure, and sets "*err" to the error
   * and "*err_info" to null or an additional error string.
   */
  for (line = 0; line < ISERIES_MAX_TRACE_LEN; line++)
    {
      if (file_gets (buf, ISERIES_LINE_LENGTH, wth->fh) != NULL)
	{

	  /* Convert UNICODE to ASCII if required and determine    */
	  /* the number of bytes to rewind to beginning of record. */
	  if (iseries->format == ISERIES_FORMAT_UNICODE)
	    {
	      /* buflen is #bytes to 1st 0x0A */
             buflen = iseries_UNICODE_to_ASCII ((guint8 *)buf, ISERIES_LINE_LENGTH);
	    }
	  else
	    {
	      /* Else buflen is just length of the ASCII string */
	      buflen = (long) strlen (buf);
	    }
	  ascii_strup_inplace(buf);
	  /* If packet header found return the offset */
	  num_items_scanned =
		  sscanf (buf+78,
		  "%*[ \n\t]ETHV2%*[ .:\n\t]TYPE%*[ .:\n\t]%4s",type);
	  if (num_items_scanned == 1)
	    {
	      /* Rewind to beginning of line */
	      cur_off = file_tell (wth->fh);
	      if (cur_off == -1)
		{
		  *err = file_error (wth->fh, err_info);
		  return -1;
		}
	      if (file_seek (wth->fh, cur_off - buflen, SEEK_SET, err) == -1)
		{
		  return -1;
		}
	      return cur_off - buflen;
	    }
	}
      /* Otherwise we got an error or reached EOF */
      else
	{
	  if (file_eof (wth->fh))
	    {
	      /* We got an EOF. */
	      *err = 0;
	    }
	  else
	    {
	      /* We got an error. */
	      *err = file_error (wth->fh, err_info);
	    }
	  return -1;
	}
    }

  return -1;
}

/*
 * Read packets in random-access fashion
 */
static gboolean
iseries_seek_read (wtap * wth, gint64 seek_off,
		   union wtap_pseudo_header *pseudo_header, guint8 * pd,
		   int len, int *err, gchar ** err_info)
{
  int pkt_len;

  /* seek to packet location */
  if (file_seek (wth->random_fh, seek_off - 1, SEEK_SET, err) == -1)
    return FALSE;

  /*
   * Parse the packet and extract the various fields
   */
  pkt_len = iseries_parse_packet (wth, wth->random_fh, pseudo_header, pd,
				  err, err_info);

  if (pkt_len != len)
    {
      if (pkt_len != -1)
	{
	  *err = WTAP_ERR_BAD_RECORD;
	  *err_info =
	    g_strdup_printf
	    ("iseries: requested length %d doesn't match record length %d",
	     len, pkt_len);
	}
      return FALSE;
    }
  return TRUE;
}

/* Parses a packet. */
static int
iseries_parse_packet (wtap * wth, FILE_T fh,
		      union wtap_pseudo_header *pseudo_header, guint8 * pd,
		      int *err, gchar ** err_info)
{
  iseries_t *iseries = (iseries_t *)wth->priv;
  gint64 cur_off;
  gboolean isValid, isCurrentPacket, IPread, TCPread, isDATA, isDataFormatted, isDataHandled;
  int num_items_scanned, line, pktline, buflen;
  guint32 pkt_len;
  int cap_len, pktnum, hr, min, sec, csec;
  char direction[2], destmac[13], srcmac[13], type[5], ipheader[41],
    tcpheader[81];
  char hex1[17], hex2[17], hex3[17], hex4[17];
  char data[ISERIES_LINE_LENGTH * 2];
  guint8 *buf;
  char   *tcpdatabuf, *workbuf, *asciibuf;
  struct tm tm;

  /*
   * Check for packet headers in first 3 lines this should handle page breaks
   * situations and the header lines output at each page throw and ensure we
   * read both the captured and packet lengths.
   */
  isValid = FALSE;
  for (line = 1; line < ISERIES_PKT_LINES_TO_CHECK; line++)
    {
      cur_off = file_tell (fh);
      if (file_gets (data, ISERIES_LINE_LENGTH, fh) == NULL)
	{
	  *err = file_error (fh, err_info);
	  if (*err == 0)
	    {
	      *err = WTAP_ERR_SHORT_READ;
	    }
	  return -1;
	}
      /* Convert UNICODE data to ASCII */
      if (iseries->format == ISERIES_FORMAT_UNICODE)
	{
         iseries_UNICODE_to_ASCII ((guint8 *)data, ISERIES_LINE_LENGTH);
	}
	  ascii_strup_inplace(data);
      num_items_scanned =
	sscanf (data,
		"%*[ \n\t]%6d%*[ *\n\t]%1s%*[ \n\t]%6d%*[ \n\t]%2d:%2d:%2d.%9d%*[ \n\t]%12s%*[ \n\t]%12s%*[ \n\t]ETHV2%*[ \n\t]TYPE:%*[ \n\t]%4s",
		&pktnum, direction, &cap_len, &hr, &min, &sec, &csec, destmac,
		srcmac, type);
      if (num_items_scanned == 10)
	{
	  /* OK! We found the packet header line */
	  isValid = TRUE;
	  /*
	   * XXX - The Capture length returned by the iSeries trace doesn't seem to include the src/dest MAC
	   * addresses or the packet type. So we add them here.
	   */
	  cap_len += 14;
	  break;
	}
    }

  /*
   * If no packet header found we exit at this point and inform the user.
   */
  if (!isValid)
    {
      *err = WTAP_ERR_BAD_RECORD;
      *err_info = g_strdup ("iseries: packet header isn't valid");
      return -1;
    }

  /*
   * If we have Wiretap Header then populate it here
   *
   * XXX - Timer resolution on the iSeries is hardware dependant; the value for csec may be
   * different on other platforms though all the traces I've seen seem to show resolution
   * to Milliseconds (i.e HH:MM:SS.nnnnn) or Nanoseconds (i.e HH:MM:SS.nnnnnn)
   */
  if (iseries->have_date)
    {
      tm.tm_year = 100 + iseries->year;
      tm.tm_mon = iseries->month - 1;
      tm.tm_mday = iseries->day;
      tm.tm_hour = hr;
      tm.tm_min = min;
      tm.tm_sec = sec;
      tm.tm_isdst = -1;
      wth->phdr.ts.secs = mktime (&tm);
      /* Handle Millisecond precision for timer */
      if (csec > 99999)
	{
	  wth->phdr.ts.nsecs = csec * 1000;
	}
      /* Handle Nanosecond precision for timer */
      else
	{
	  wth->phdr.ts.nsecs = csec * 10000;
	}
    }

    wth->phdr.caplen = cap_len;
    wth->phdr.pkt_encap = WTAP_ENCAP_ETHERNET;
    pseudo_header->eth.fcs_len = -1;

  /*
   * Start Reading packet contents
   */
  isCurrentPacket = TRUE;
  IPread = FALSE;
  TCPread = FALSE;
  isDATA = FALSE;
  isDataFormatted = TRUE;
  /*
   * Allocate 2 work buffers to handle concatentation of the hex data block
   */
  tcpdatabuf = g_malloc (ISERIES_PKT_ALLOC_SIZE);
  g_snprintf (tcpdatabuf, 1, "%s", "");
  workbuf = g_malloc (ISERIES_PKT_ALLOC_SIZE);
  g_snprintf (workbuf, 1, "%s", "");
  /* loop through packet lines and breakout when the next packet header is read */
  pktline = 0;
  while (isCurrentPacket)
    {
      pktline++;
      /* Read the next line */
      if (file_gets (data, ISERIES_LINE_LENGTH, fh) == NULL)
	{
	  if (file_eof (fh))
	    {
	      break;
	    }
	  else
	    {
	      *err = file_error (fh, err_info);
	      if (*err == 0)
		{
		  *err = WTAP_ERR_SHORT_READ;
		}
	      return -1;
	    }
	}

      /* Convert UNICODE data to ASCII and determine line length */
      if (iseries->format == ISERIES_FORMAT_UNICODE)
	{
         buflen = iseries_UNICODE_to_ASCII ((guint8 *)data, ISERIES_LINE_LENGTH);
	}
      else
	{
	  /* Else bytes to rewind is just length of ASCII string */
	  buflen = (int) strlen (data);
	}

	  /*                      
	  * Decode data for IPv4 traces and unformatted IPv6 traces 
	  */
	  if ((!iseries->ipv6_trace) || ((iseries->ipv6_trace) && (!iseries->tcp_formatted)))
	  {
		  /* If this is a IP header hex string then set flag */
		  num_items_scanned = sscanf (data + 22, "IP Header%*[ .:\n\t]%40s", ipheader);
		  if (num_items_scanned == 1)
		  {
			  IPread = TRUE;
		  }

		  /* If this is TCP header hex string then set flag */
		  num_items_scanned = sscanf (data + 22, "TCP Header%*[ .:\n\t]%80s", tcpheader);
		  if (num_items_scanned == 1)
		  {
			  TCPread = TRUE;
		  }

		  /*
		  * If there is data in the packet handle it here.
		  *
		  * The data header line will have the "Data . . " identifier, subsequent lines don't
		  */
		  num_items_scanned =
			  sscanf (data + 27, "%16[A-F0-9] %16[A-F0-9] %16[A-F0-9] %16[A-F0-9]",
			  hex1, hex2, hex3, hex4);
		  if (num_items_scanned > 0)
		  {
			  isDATA = TRUE;
			  /*
			  * Scan the data line for data blocks, depending on the number of blocks scanned
			  * add them along with current tcpdata buffer to the work buffer and then copy
			  * work buffer to tcpdata buffer to continue building up tcpdata buffer to contain
			  * a single hex string.
			  */
			  switch (num_items_scanned)
			  {
			  case 1:
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s", tcpdatabuf,
					  hex1);
				  break;
			  case 2:
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s",
					  tcpdatabuf, hex1, hex2);
				  break;
			  case 3:
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s",
					  tcpdatabuf, hex1, hex2, hex3);
				  break;
			  default:
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s%s",
					  tcpdatabuf, hex1, hex2, hex3, hex4);
			  }
			  memcpy (tcpdatabuf, workbuf, ISERIES_PKT_ALLOC_SIZE);
		  }
	  }
      
	  /*
	   * Decode data for IPv6 formatted traces
	   */
	  if ((iseries->ipv6_trace) && (iseries->tcp_formatted))
	  {
		  /*
		  * If there are IPv6 headers in the packet handle it here.
		  *
		  * iSeries IPv6 headers are aligned after column 36 and appears as a single hex string  
		  * of 16,32,48 or 64 bytes
		  */
		  isDataHandled=FALSE;
		  num_items_scanned =
			  sscanf (data + 35, "%*[ \n\t]%16[A-F0-9]%16[A-F0-9]%16[A-F0-9]%16[A-F0-9]",
			  hex1, hex2, hex3, hex4);
		  if (num_items_scanned > 0)
		  {
			  isDATA = TRUE;
			  /*
			  * Scan the data line for data blocks, depending on the number of blocks scanned
			  * add them along with current tcpdata buffer to the work buffer and then copy
			  * work buffer to tcpdata buffer to continue building up tcpdata buffer to contain
			  * a single hex string.
			  */
			  switch (num_items_scanned)
			  {
			  case 1:
				  if (strlen(hex1)==16) 
				  {
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s", tcpdatabuf,
					  hex1);
					isDataHandled=TRUE;
				  }
				  break;
			  case 2:
				  if ((strlen(hex1)==16) && (strlen(hex2)==16)) 
				  {
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s",
					  tcpdatabuf, hex1, hex2);
				    isDataHandled=TRUE;
				  }
				  break;
			  case 3:
				  if ((strlen(hex1)==16) && (strlen(hex2)==16) && (strlen(hex3)==16)) 
				  {
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s",
					  tcpdatabuf, hex1, hex2, hex3);
			        isDataHandled=TRUE;
				  }
				  break;
			  default:
				  if ((strlen(hex1)==16) && (strlen(hex2)==16) && (strlen(hex3)==16) && (strlen(hex4)==16)) 
				  {
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s%s",
					  tcpdatabuf, hex1, hex2, hex3, hex4);
			        isDataHandled=TRUE;
				  }
			  }
			  memcpy (tcpdatabuf, workbuf, ISERIES_PKT_ALLOC_SIZE);
		  }
		  /*
		  * If there is data in the packet handle it here.
		  *
		  * The data header line will have the "Data . . " identifier, subsequent lines don't
		  * Check to ensure we haven't already captured and used this data block already above
		  */
		  num_items_scanned =
			  sscanf (data + 26, "%*[ \n\t]%16[A-F0-9]%16[A-F0-9]%16[A-F0-9]%16[A-F0-9]",
			  hex1, hex2, hex3, hex4);
		  if ((num_items_scanned > 0) && (isDataHandled==FALSE))
		  {
			  isDATA = TRUE;
			  /*
			  * Scan the data line for data blocks, depending on the number of blocks scanned
			  * add them along with current tcpdata buffer to the work buffer and then copy
			  * work buffer to tcpdata buffer to continue building up tcpdata buffer to contain
			  * a single hex string.
			  */
			  switch (num_items_scanned)
			  {
			  case 1:
				  if (strlen(hex1)==16)
				  {
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s", tcpdatabuf,
					  hex1);
				  }
				  break;
			  case 2:
				  if ((strlen(hex1)==16) && (strlen(hex2)==16)) 
				  {
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s",
					  tcpdatabuf, hex1, hex2);
				  }
				  break;
			  case 3:
				  if ((strlen(hex1)==16) && (strlen(hex2)==16) && (strlen(hex3)==16)) 
				  {
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s",
					  tcpdatabuf, hex1, hex2, hex3);
				  }	
				  break;
			  default:
				  if ((strlen(hex1)==16) && (strlen(hex2)==16) && (strlen(hex3)==16) && (strlen(hex4)==16)) 
				  {
				  g_snprintf (workbuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s%s",
					  tcpdatabuf, hex1, hex2, hex3, hex4);
				  }
			  }
			  memcpy (tcpdatabuf, workbuf, ISERIES_PKT_ALLOC_SIZE);
		  }
	  }

      /*
       * If we see the identifier for the next packet then rewind and set
       * isCurrentPacket FALSE
       */
	  ascii_strup_inplace(data);
	  /* If packet header found return the offset */
	  num_items_scanned =
		  sscanf (data+78,
		  "%*[ \n\t]ETHV2%*[ .:\n\t]TYPE%*[ .:\n\t]%4s",type);
      if ((num_items_scanned == 1) && pktline > 1)
	{
	  isCurrentPacket = FALSE;
	  cur_off = file_tell (fh);
	  if (cur_off == -1)
	    {
	      /* Error. */
	      *err = file_error (fh, err_info);
	      return -1;
	    }
	  if (file_seek (fh, cur_off - buflen, SEEK_SET, err) == -1)
	    {
	      return -1;
	    }
	}
    }

	/*
	* For a IPV4 formated trace ensure we have read at least the IP and TCP headers otherwise
	* exit and pass error message to user.
	*/
	if ((iseries->tcp_formatted) && (iseries->ipv6_trace == FALSE))
	{
		if (!IPread)
		{
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup ("iseries: IP header isn't valid");
			return -1;
		}
		if (!TCPread)
		{
			*err = WTAP_ERR_BAD_RECORD;
			*err_info = g_strdup ("iseries: TCP header isn't valid");
			return -1;
		}
	}

  /*
   * Create a buffer to hold all the ASCII Hex data and populate with all the
   * extracted data.
   */
  asciibuf = g_malloc (ISERIES_PKT_ALLOC_SIZE);
  if (isDATA)
    {
      /* packet contained data */
      if ((iseries->tcp_formatted) && (iseries->ipv6_trace == FALSE))
	{
	  /* build string for formatted fields */
	  g_snprintf (asciibuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s%s%s",
		      destmac, srcmac, type, ipheader, tcpheader, tcpdatabuf);
	}
      else
	{
	  /* build string for unformatted data fields and IPV6 data*/
	  g_snprintf (asciibuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s", destmac,
		      srcmac, type, tcpdatabuf);
	}
    }
  else
    {
      /* No data in the packet */
      g_snprintf (asciibuf, ISERIES_PKT_ALLOC_SIZE, "%s%s%s%s%s", destmac,
		  srcmac, type, ipheader, tcpheader);
    }

  /*
   * Note: iSeries comms traces pad data blocks out with zeros
   * Extract the packet length from the actual IP header; this may
   * differ from the capture length reported by the formatted trace.
   * IPv4 and IPv6 headers contain the length at different offsets so
   * read from the correct location.
   */
  if (!iseries->ipv6_trace) 
  {
  num_items_scanned = sscanf (asciibuf + 32, "%4x", &pkt_len);
  wth->phdr.len = pkt_len + 14;
  }
  else
  {
  num_items_scanned = sscanf (asciibuf + 36, "%4x", &pkt_len);
    wth->phdr.len = pkt_len + 14;
  }
  if (wth->phdr.caplen > wth->phdr.len)
    wth->phdr.len = wth->phdr.caplen;

  /* Make sure we have enough room for the packet, only create buffer if none supplied */
  if (pd == NULL)
    {
      buffer_assure_space (wth->frame_buffer, ISERIES_MAX_PACKET_LEN);
      buf = buffer_start_ptr (wth->frame_buffer);
      /* Convert ascii data to binary and return in the frame buffer */
      iseries_parse_hex_string (asciibuf, buf, (int) strlen (asciibuf));
    }
  else
    {
      /* Convert ascii data to binary and return in the frame buffer */
      iseries_parse_hex_string (asciibuf, pd, (int) strlen (asciibuf));
    }

  /* free buffers allocs and return */
  *err = 0;
  g_free (asciibuf);
  g_free (tcpdatabuf);
  g_free (workbuf);
  return wth->phdr.len;
}

/*
 * Simple routine to convert an UNICODE buffer to ASCII
 *
 * XXX - This may be possible with iconv or similar
 */
static int
iseries_UNICODE_to_ASCII (guint8 * buf, guint bytes)
{
  guint i;
  guint8 *bufptr;
  bufptr = buf;

  for (i = 0; i < bytes; i++)
    {
      switch (buf[i])
	{
	case 0xFE:
	case 0xFF:
	case 0x00:
	  break;
	default:
	  *bufptr = buf[i];
	  bufptr++;
	}
      if (buf[i] == 0x0A)
	return i;
    }
  return i;
}

/*
 * Simple routine to convert an ASCII hex string to binary data
 * Requires ASCII hex data and buffer to populate with binary data
 */
static gboolean
iseries_parse_hex_string (const char * ascii, guint8 * buf, int len)
{
  int i, byte;
  gint hexvalue;
  guint8 bytevalue;

  byte = 0;
  i = 0;
  for (;;)
    {
      if (i >= len)
        break;
      hexvalue = g_ascii_xdigit_value(ascii[i]);
      i++;
      if (hexvalue == -1)
        return FALSE;	/* not a valid hex digit */
      bytevalue = (guint8)(hexvalue << 4);
      if (i >= len)
        return FALSE;	/* only one hex digit of the byte is present */
      hexvalue = g_ascii_xdigit_value(ascii[i]);
      i++;
      if (hexvalue == -1)
        return FALSE;	/* not a valid hex digit */
      bytevalue |= (guint8) hexvalue;
      buf[byte] = bytevalue;
      byte++;
    }
  return TRUE;
}
