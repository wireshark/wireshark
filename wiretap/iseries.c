/* iseries.c
 *
 * Wiretap Library
 * Copyright (c) 2005 by Martin Warnes <Martin_Warnes@Stercomm.com>
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

/* iSeries formatted packet records consist of a header line identifying the packet number,direction,size,
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

#define ISERIES_HDR_MAGIC_STR	" COMMUNICATIONS TRACE"
#define ISERIES_HDR_MAGIC_LEN   21
#define ISERIES_PKT_MAGIC_STR   "ETHV2"
#define ISERIES_PKT_MAGIC_LEN   5
#define ISERIES_LINE_LENGTH     135
#define ISERIES_HDR_LINES_TO_CHECK  50
#define ISERIES_PKT_LINES_TO_CHECK  4
#define ISERIES_MAX_PACKET_LEN  16384
#define ISERIES_MAX_TRACE_LEN   99999999
#define ISERIES_PKT_ALLOC_SIZE (cap_len*2)+1
#define ISERIES_FORMAT_ASCII    1
#define ISERIES_FORMAT_UNICODE  2

static gboolean iseries_read(wtap *wth, int *err, gchar **err_info,
			     long *data_offset);
static gboolean iseries_seek_read(wtap *wth, long seek_off,
				  union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
				  int *err, gchar **err_info);
static gboolean iseries_check_file_type(wtap *wth, int *err, int format);
static long iseries_seek_next_packet(wtap *wth, int *err);
static int iseries_parse_packet(wtap *wth, FILE_T fh,
				union wtap_pseudo_header *pseudo_header, guint8 *pd, int *err, gchar **err_info);
static int iseries_bytes_to_read(wtap *wth);
static void iseries_UNICODE_to_ASCII(guint8 *buf, guint bytes);
static gboolean iseries_parse_hex_string(guint8 *ascii, guint8 *buf, int len);
      
int iseries_open(wtap *wth, int *err, gchar **err_info _U_)
{
  int	bytes_read;
  char	magic[ISERIES_HDR_MAGIC_LEN];
  /* UNICODE identification */ 
  char  unicodemagic[ISERIES_HDR_MAGIC_LEN]=
    { '\xFF', '\xFE', '\x20', '\x00', '\x43', '\x00', '\x4F', '\x00', '\x4D', '\x00', 
      '\x4D', '\x00', '\x55', '\x00', '\x4E', '\x00', '\x49', '\x00', '\x43', '\x00', '\x41' };  
  /*
   * Check that file starts with a valid iSeries COMMS TRACE header 
   */
  errno = WTAP_ERR_CANT_READ;
  bytes_read = file_read(&magic, 1, sizeof magic, wth->fh);
  if (bytes_read != sizeof magic) {
    *err = file_error(wth->fh);
    if (*err != 0)
      return -1;
    return 0;
  }

  /* Check if this is an ASCII formatted file */
  if (memcmp(magic, ISERIES_HDR_MAGIC_STR, ISERIES_HDR_MAGIC_LEN) == 0) {
    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
      return 0;
    }
    /*
     * Do some basic sanity checking to ensure we can handle the 
     * contents of this trace                                    
     */
    if (!iseries_check_file_type(wth, err, ISERIES_FORMAT_ASCII)) {
      if (*err == 0)
	return 0;
      else
	return -1;
    }
    wth->data_offset = 0;
    wth->file_encap = WTAP_ENCAP_PER_PACKET;
    wth->file_type = WTAP_FILE_ISERIES;
    wth->snapshot_length = 0; 
    wth->subtype_read = iseries_read;
    wth->subtype_seek_read = iseries_seek_read;
    wth->tsprecision = WTAP_FILE_TSPREC_USEC;
    return 1;
  }

  /* Check if this is a UNICODE formatted file */
  if (memcmp(magic, unicodemagic, ISERIES_HDR_MAGIC_LEN) == 0) {
    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
      return 0;
    }
    /*
     * Do some basic sanity checking to ensure we can handle the 
     * contents of this trace                                    
     */
    if (!iseries_check_file_type(wth, err, ISERIES_FORMAT_UNICODE)) {
      if (*err == 0)
	return 0;
      else
	return -1;
    }
    wth->data_offset = 0;
    wth->file_encap = WTAP_ENCAP_PER_PACKET;
    wth->file_type = WTAP_FILE_ISERIES_UNICODE;
    wth->snapshot_length = 0; 
    wth->subtype_read = iseries_read;
    wth->subtype_seek_read = iseries_seek_read;
    wth->tsprecision = WTAP_FILE_TSPREC_USEC;
    return 1;
  }
  
  /* Neither ASCII or UNICODE so not supported */
  return 0;
}

/*
 * Do some basic sanity checking to ensure we can handle the 
 * contents of this trace by checking the header page for
 * requisit requirements and additional information.                                    
 */
static gboolean iseries_check_file_type(wtap *wth, int *err, int format)
{
  guint	line;
  int bytes_to_read, num_items_scanned;
  char buf[ISERIES_LINE_LENGTH*2], protocol[8], tcpformat[1];
  guint8 *sdate;

  /* Save trace format for passing between packets */
  sdate = g_malloc(10);
  wth->capture.iseries = g_malloc(sizeof(iseries_t));
  wth->capture.iseries->format = format;

  for (line = 0; line < ISERIES_HDR_LINES_TO_CHECK; line++) {
    /* Determine bytes to read based on format type */
    bytes_to_read = iseries_bytes_to_read(wth);
    if (bytes_to_read == -1) {
      return -1;
    }
    if (file_gets(buf, bytes_to_read, wth->fh) != NULL) {
      /* 
       * Check that we are dealing with an ETHERNET trace 
       */
      if (wth->capture.iseries->format == ISERIES_FORMAT_UNICODE) {
	iseries_UNICODE_to_ASCII(buf,bytes_to_read);
      }
      num_items_scanned = sscanf(buf,  
				 "   Object protocol  . . . . . . :  %8s",
				 protocol);
      if (num_items_scanned == 1) {
	if (memcmp(protocol, "ETHERNET", 8) != 0) 
	  return FALSE;
      }
      
      /* 
       * Determine if the data has been formatted or not
       */
      num_items_scanned = sscanf(buf,  
				 "   Format TCP/IP data only  . . :  %1s",
				 tcpformat);
      if (num_items_scanned == 1) {
	if (strncmp(tcpformat,"Y",1) == 0) {
	  wth->capture.iseries->tcp_formatted = TRUE;
	}
	else {
	  wth->capture.iseries->tcp_formatted = FALSE;
	}
      }     

      /* 
       * The header is the only place where the date part of the timestamp is held, so
       * extract it here and store for all packets to access
       */
      num_items_scanned = sscanf(buf,  
				 "   Start date/Time  . . . . . . :  %8s",
				 sdate);
      if (num_items_scanned == 1) {
        wth->capture.iseries->sdate = sdate;
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
  return TRUE;
}

/* 
 * Find the next packet and parse it; called from wtap_read(). 
 */
static gboolean iseries_read(wtap *wth, int *err, gchar **err_info,
			     long *data_offset)
{
  long	offset;
  int	pkt_len;
  
  /* 
   * Locate the next packet 
   */
  offset = iseries_seek_next_packet(wth, err);
  if (offset < 1)
    return FALSE;
  
  /* 
   * Parse the packet and extract the various fields  
   */
  pkt_len = iseries_parse_packet(wth, wth->fh, &wth->pseudo_header, NULL, err,
  				 err_info);
  if (pkt_len == -1)
    return FALSE;
  
  wth->data_offset = offset;
  *data_offset = offset;
  return TRUE;
}

/* 
 * Seeks to the beginning of the next packet, and returns the
 * byte offset.  Returns -1 on failure, and sets "*err" to the error. 
 */
static long iseries_seek_next_packet(wtap *wth, int *err)
{
  char	buf[ISERIES_LINE_LENGTH*2];
  int line, bytes_to_read;
  long cur_off;

  /* 
   * Seeks to the beginning of the next packet, and returns the
   * byte offset.  Returns -1 on failure, and sets "*err" to the error. 
   */
  for (line = 0; line < ISERIES_MAX_TRACE_LEN ; line++) {
    /* Determine bytes to read based on format type */
    bytes_to_read = iseries_bytes_to_read(wth);
    if (bytes_to_read == -1) {
      return -1;
    }
    if (file_gets(buf, bytes_to_read, wth->fh) != NULL) {
      /* Convert UNICODE to ASCII if requiredd.*/
      if (wth->capture.iseries->format == ISERIES_FORMAT_UNICODE) {
	iseries_UNICODE_to_ASCII(buf,bytes_to_read);
      }
      /* If packet header found return the offset */
      if(strncmp(buf+80,ISERIES_PKT_MAGIC_STR,ISERIES_PKT_MAGIC_LEN) == 0) {
	cur_off = file_tell(wth->fh);
	if (cur_off == -1) {
	  *err = file_error(wth->fh);
	  return -1;
	}
	return cur_off;
      }
    }
    /* Otherwise we got an error or reached EOF */
    else {
      if (file_eof(wth->fh)) {
	*err = 0;
      } 
      else {
	/* We (presumably) got an error (there's no equivalent to "ferror()"
	   in zlib, alas, so we don't have a wrapper to check for an error). */
	*err = file_error(wth->fh);
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
iseries_seek_read (wtap *wth, long seek_off,
		   union wtap_pseudo_header *pseudo_header, guint8 *pd, int len,
		   int *err, gchar **err_info)
{
  int	pkt_len;
  
  /* seek to packet location */
  if (file_seek(wth->random_fh, seek_off - 1, SEEK_SET, err) == -1)
    return FALSE;
  
  /* 
   * Parse the packet and extract the various fields  
   */
  pkt_len = iseries_parse_packet(wth, wth->random_fh, pseudo_header, pd,
				 err, err_info);
  
  if (pkt_len != len) {
    if (pkt_len != -1) {
      *err = WTAP_ERR_BAD_RECORD;
      *err_info = g_strdup_printf("iseries: requested length %d doesn't match record length %d",
				  len, pkt_len);
    }
    return FALSE;
  }
  return TRUE;
}

/* Parses a packet. */
static int
iseries_parse_packet(wtap *wth, FILE_T fh,
		     union wtap_pseudo_header *pseudo_header, guint8 *pd, int *err, gchar **err_info)
{
  long cur_off;
  gboolean isValid,isCurrentPacket,IPread,TCPread,isDATA;
  int	num_items_scanned, line, bytes_to_read, pktline;
  int	pkt_len,cap_len, pktnum, month, day, year, hr, min, sec, csec;
  char	direction[2],destmac[13],srcmac[13],type[5],ipheader[41],tcpheader[81];
  char  hex1[17],hex2[17],hex3[17],hex4[17];
  char	data[ISERIES_LINE_LENGTH*2];
  guint8 *buf,*asciibuf,*tcpdatabuf,*workbuf;
  struct tm tm;

  /* 
   * Rewind 1 line to ensure we find beginning of packet
   */
  cur_off = file_tell(fh);
  if (cur_off == -1) {
    /* Error. */
    *err = file_error(fh);
    return -1;
  }
  /* If the format is UNICODE we need to rewind a little further */
  if (wth->capture.iseries->format == ISERIES_FORMAT_UNICODE) {
    bytes_to_read = ISERIES_LINE_LENGTH*2;
  }
  else {
    bytes_to_read = ISERIES_LINE_LENGTH;
  }
  if (file_seek(fh,cur_off-bytes_to_read, SEEK_SET, err) == -1) {
    return -1;
  }

  /* 
   * Check for packet headers in first 3 lines this should handle page breaks 
   * situations and the header lines output at each page throw and ensure we
   * read both the captured and packet lengths.
   */
  isValid = FALSE;
  for (line = 1; line < ISERIES_PKT_LINES_TO_CHECK; line++) {
    /* Determine bytes to read based on format type */
    bytes_to_read = iseries_bytes_to_read(wth);
    if (bytes_to_read == -1) {
      return -1;
    }
    if (file_gets(data, bytes_to_read, fh) == NULL) {
      *err = file_error(fh);
      if (*err == 0) {
	*err = WTAP_ERR_SHORT_READ;
      }
      return -1;
    }
    /* Convert UNICODE data to ASCII */
    if (wth->capture.iseries->format == ISERIES_FORMAT_UNICODE) {
      iseries_UNICODE_to_ASCII(data,bytes_to_read);
    }
    /* look for packet header */
    num_items_scanned = sscanf(data, "%6d   %1s   %6d  %d:%d:%d.%d               %12s  %12s  ETHV2   Type: %s",
  			       &pktnum, direction, &cap_len, &hr, &min, &sec, &csec, destmac, srcmac, type );
    if (num_items_scanned == 10) {
      /* OK! We found the packet header line */
      isValid = TRUE;
      /* 
       * XXX - The Capture length returned by the iSeries trace doesn't seem to include the src/dest MAC
       * addresses or the packet type. So we add them here.
       */
      cap_len +=14;
    }
  }

  /* 
   * If no packet header found we exit at this point and inform the user.
   */ 
  if (!isValid) {
    *err = WTAP_ERR_BAD_RECORD;
    *err_info = g_strdup("iseries: packet header isn't valid");
    return -1;
  }
  
  /* 
   * If we have Wiretap Header then populate it here
   *
   * XXX - Timer resolution on the iSeries is hardware dependant, the value for csec may be 
   * different on other platforms though all the traces I've seen seem so show resolution
   * to 5 digits (i.e HH:MM:SS.nnnnn) so hopefully this will not require special handling
   */
  if (wth) {
    num_items_scanned = sscanf(wth->capture.iseries->sdate,"%d/%d/%d",&month,&day,&year);
    tm.tm_year = 100 + year;
    tm.tm_mon = month -1;
    tm.tm_mday = day;
    tm.tm_hour = hr;
    tm.tm_min = min;
    tm.tm_sec = sec;
    tm.tm_isdst = -1;
    wth->phdr.ts.secs = mktime(&tm);
    wth->phdr.ts.nsecs = csec * 10000;
    wth->phdr.caplen = cap_len;
    wth->phdr.pkt_encap = WTAP_ENCAP_ETHERNET;
    pseudo_header->eth.fcs_len = -1;
  }

  /* 
   * Start Reading packet contents
   */ 
  isCurrentPacket = TRUE;
  IPread=FALSE;
  TCPread=FALSE;
  isDATA=FALSE;
  /*
   * Allocate 2 work buffers to handle concatentation of the hex data block
   */
  tcpdatabuf = g_malloc(ISERIES_PKT_ALLOC_SIZE);
  g_snprintf(tcpdatabuf,1,"%s","");
  workbuf = g_malloc(ISERIES_PKT_ALLOC_SIZE);
  g_snprintf(workbuf,1,"%s","");
  /* loop through packet lines and breakout when the next packet header is read */
  pktline=0;
  while (isCurrentPacket) {
    pktline++;
    /* Determine bytes to read based on format type */
    bytes_to_read = iseries_bytes_to_read(wth);
    if (bytes_to_read == -1) {
      return -1;
    }
    /* Read the next line */
    if (file_gets(data, bytes_to_read, fh) == NULL) {
      if (file_eof(fh)) {
	break;
      }
      else {
	*err = file_error(fh);
	if (*err == 0) {
	  *err = WTAP_ERR_SHORT_READ;
	}
	return -1;
      }
    }

    /* Convert UNICODE data to ASCII */
    if (wth->capture.iseries->format == ISERIES_FORMAT_UNICODE) {
      iseries_UNICODE_to_ASCII(data,bytes_to_read);
    }
    /* If this is a IP header hex string then set flag */ 
    num_items_scanned = sscanf(data+22, "IP Header  : %40s",
  			       ipheader );
    if (num_items_scanned == 1) {
      IPread = TRUE;
    }

    /* If this is TCP header hex string then set flag */ 
    num_items_scanned = sscanf(data+22, "TCP Header : %80s",
  			       tcpheader );
    if (num_items_scanned == 1) {
      TCPread = TRUE;
    }

    /* 
     * If there is data in the packet handle it here.
     *
     * The data header line will have the "Data . . " identifier, subsequent lines don't
    */
    num_items_scanned = sscanf(data+27, "%16[A-Z0-9] %16[A-Z0-9] %16[A-Z0-9] %16[A-Z0-9]",
    		       hex1, hex2, hex3, hex4 );
    if (num_items_scanned > 0) {
      isDATA = TRUE;
      /*
       * Scan the data line for data blocks, depending on the number of blocks scanned
       * add them along with current tcpdata buffer to the work buffer and then copy
       * work buffer to tcpdata buffer to continue building up tcpdata buffer to contain
       * a single hex string. 
       */
      switch (num_items_scanned) {
      case 1:
	g_snprintf(workbuf,ISERIES_PKT_ALLOC_SIZE,"%s%s",tcpdatabuf,hex1);
	break;
      case 2:
	g_snprintf(workbuf,ISERIES_PKT_ALLOC_SIZE,"%s%s%s",tcpdatabuf,hex1,hex2);
	break;
      case 3:
	g_snprintf(workbuf,ISERIES_PKT_ALLOC_SIZE,"%s%s%s%s",tcpdatabuf,hex1,hex2,hex3);
	break;
      default:
	g_snprintf(workbuf,ISERIES_PKT_ALLOC_SIZE,"%s%s%s%s%s",tcpdatabuf,hex1,hex2,hex3,hex4);
      }
      memcpy(tcpdatabuf,workbuf,ISERIES_PKT_ALLOC_SIZE);
    }
  
    /* 
     * If we see the identifier for the next packet then rewind and set 
     * isCurrentPacket FALSE 
     */
    if((strncmp(data+80,ISERIES_PKT_MAGIC_STR,ISERIES_PKT_MAGIC_LEN) == 0) && pktline>1) {
      isCurrentPacket=FALSE;
      cur_off = file_tell(fh);
      if (cur_off == -1) {
	/* Error. */
	*err = file_error(fh);
	return -1;
      }
      /* If the format is UNICODE we need to rewind a little further */
      if (wth->capture.iseries->format == ISERIES_FORMAT_UNICODE) {
	bytes_to_read = ISERIES_LINE_LENGTH*2;
      }
      else {
	bytes_to_read = ISERIES_LINE_LENGTH;
      }
      if (file_seek(fh,cur_off-bytes_to_read, SEEK_SET, err) == -1) {
	return -1;
      }
    }
  }
  
  /*
   * For a formated trace ensure we have read at least the IP and TCP headers otherwise 
   * exit and pass error message to user.
   */
  if (wth->capture.iseries->tcp_formatted) {
    if (!IPread) {
      *err = WTAP_ERR_BAD_RECORD;
      *err_info = g_strdup("iseries: IP header isn't valid");
      return -1;
    }
    if (!TCPread) {
      *err = WTAP_ERR_BAD_RECORD;
      *err_info = g_strdup("iseries: TCP header isn't valid");
      return -1;
    }
  }

  /* 
   * Create a buffer to hold all the ASCII Hex data and populate with all the
   * extracted data.
   */ 
  asciibuf = g_malloc(ISERIES_PKT_ALLOC_SIZE);
  if (isDATA) {
    /* packet contained data */
    if (wth->capture.iseries->tcp_formatted) {
      /* build string for formatted fields */
      g_snprintf(asciibuf,ISERIES_PKT_ALLOC_SIZE,"%s%s%s%s%s%s",destmac,srcmac,type,ipheader,tcpheader,tcpdatabuf);
    }
    else {
      /* build string for unformatted data fields */
      g_snprintf(asciibuf,ISERIES_PKT_ALLOC_SIZE,"%s%s%s%s",destmac,srcmac,type,tcpdatabuf);
    }
  }
  else {
    /* No data in the packet */
    g_snprintf(asciibuf,ISERIES_PKT_ALLOC_SIZE,"%s%s%s%s%s",destmac,srcmac,type,ipheader,tcpheader);
  }

  /* 
   * Extract the packet length from the actual IP header, this may differ from the capture length 
   * reported by the formatted trace
   */
  num_items_scanned = sscanf(asciibuf+32,"%4x",&pkt_len);
  wth->phdr.len = pkt_len+14;

  /* Make sure we have enough room for the packet, only create buffer if none supplied */
  if (pd == NULL) {
    buffer_assure_space(wth->frame_buffer, ISERIES_MAX_PACKET_LEN);
    buf = buffer_start_ptr(wth->frame_buffer);
    /* Convert ascii data to binary and return in the frame buffer */
    iseries_parse_hex_string(asciibuf,buf,strlen(asciibuf));
  }
  else {
    /* Convert ascii data to binary and return in the frame buffer */
    iseries_parse_hex_string(asciibuf,pd,strlen(asciibuf));
  }

  /* free buffers allocs and return */  
  *err=0;
  free(asciibuf);
  free(tcpdatabuf);
  free(workbuf);
  return wth->phdr.len;
}

/*
 * Return number of bytes to read from file based on Trace type
 * 
 */
static int
iseries_bytes_to_read(wtap *wth) {
  int bytes_to_read=0;
  /* Determine number of bytes to read from file based on trace format */
  switch (wth->capture.iseries->format) {
    /* Standard line length for read */ 
  case ISERIES_FORMAT_ASCII:
    bytes_to_read = ISERIES_LINE_LENGTH;
    break;
    /* UNICODE line length twice as long */ 
  case ISERIES_FORMAT_UNICODE:
    bytes_to_read = ISERIES_LINE_LENGTH*2;
    break;
  }
  return bytes_to_read;
}

/*
 * Simple routine to convert an UNICODE buffer to ASCII
 * 
 * XXX - This may be possible with iconv or similar
 */
static void
iseries_UNICODE_to_ASCII(guint8 *buf, guint bytes)
{
  guint	i;
  guint8	*bufptr;
  bufptr = buf;
  
  for (i = 0; i < bytes; i++) {
    switch (buf[i]) {
    case 0xFE:
    case 0xFF:
    case 0x00:
      break;
    default:
      *bufptr = buf[i];
      bufptr++;
    }
  }
}

/*
 * Simple routine to convert an ASCII hex string to binary data
 * Requires ASCII hex data and buffer to populate with binary data
 */
static gboolean 
iseries_parse_hex_string(guint8 *ascii, guint8 *buf, int len) {
  int i,byte;
  char hexvalue[3] = {0,0,0};

  byte=0;
  for (i=0; i < len; i++) {
    hexvalue[0]=ascii[i];
    i++;
    hexvalue[1]=ascii[i];
    buf[byte] = (guint8)strtoul(hexvalue, NULL, 16);
    byte++;
  }
  return TRUE;
}


