/*
 *
 * Copyright (c) 2003 Endace Technology Ltd, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This software and documentation has been developed by Endace Technology Ltd.
 * along with the DAG PCI network capture cards. For further information please
 * visit http://www.endace.com/.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 *  3. The name of Endace Technology Ltd may not be used to endorse or promote
 *  products derived from this software without specific prior written
 *  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY ENDACE TECHNOLOGY LTD ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL ENDACE TECHNOLOGY LTD BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

/*
 * erf - Endace ERF (Extensible Record Format)
 *
 * See
 *
 *	http://www.endace.com/support/EndaceRecordFormat.pdf
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "buffer.h"
#include "atm.h"
#include "erf.h"


static int erf_read_header(FILE_T fh,
			   struct wtap_pkthdr *phdr,
			   union wtap_pseudo_header *pseudo_header,
			   erf_header_t *erf_header,
			   int *err,
			   gchar **err_info,
			   guint32 *bytes_read,
			   guint32 *packet_size);
static gboolean erf_read(wtap *wth, int *err, gchar **err_info,
			 gint64 *data_offset);
static gboolean erf_seek_read(wtap *wth, gint64 seek_off,
			      union wtap_pseudo_header *pseudo_header, guchar *pd,
			      int length, int *err, gchar **err_info);

extern int erf_open(wtap *wth, int *err, gchar **err_info)
{
  int i, n, records_for_erf_check = RECORDS_FOR_ERF_CHECK;
  int valid_prev = 0;
  char *s;
  erf_timestamp_t prevts,ts; 
  erf_header_t header;
  guint32 mc_hdr;
  guint16 eth_hdr;
  guint32 packet_size;
  guint16 rlen;
  guint64 erf_ext_header;
  guint8 type;
  size_t r;
  gchar * buffer;

  memset(&prevts, 0, sizeof(prevts));

  /* number of records to scan before deciding if this really is ERF */
  if ((s = getenv("ERF_RECORDS_TO_CHECK")) != NULL) {
    if ((n = atoi(s)) > 0 && n < 101) {
      records_for_erf_check = n;
    }
  }

  /*
   * ERF is a little hard because there's no magic number; we look at
   * the first few records and see if they look enough like ERF
   * records.
   */

  for (i = 0; i < records_for_erf_check; i++) {  /* records_for_erf_check */

    r = file_read(&header,sizeof(header),wth->fh);

    if (r == 0 ) break;
    if (r != sizeof(header)) {
      if ((*err = file_error(wth->fh, err_info)) != 0) {
	return -1;
      } else {
	/* ERF header too short accept the file,
	   only if the very first records have been successfully checked */
	if (i < MIN_RECORDS_FOR_ERF_CHECK) {
	  return 0;
	} else {
	  /* BREAK, the last record is too short, and will be ignored */
	  break;
	}
      }
    }

    rlen=g_ntohs(header.rlen);

    /* fail on invalid record type, invalid rlen, timestamps decreasing, or incrementing too far */
    
    /* Test valid rlen >= 16 */
    if (rlen < 16) {
      return 0;
    }
    
    packet_size = rlen - (guint32)sizeof(header);
    if (packet_size > WTAP_MAX_PACKET_SIZE) {
      /*
       * Probably a corrupt capture file or a file that's not an ERF file
       * but that passed earlier tests; don't blow up trying
       * to allocate space for an immensely-large packet.
       */
      return 0;
    }

    /* Skip PAD records, timestamps may not be set */
    if ((header.type & 0x7F) == ERF_TYPE_PAD) {
      if (file_seek(wth->fh, packet_size, SEEK_CUR, err) == -1) {
	return -1;
      }
      continue;
    }

    /* fail on invalid record type, decreasing timestamps or non-zero pad-bits */
    /* Not all types within this range are decoded, but it is a first filter */
    if ((header.type & 0x7F) == 0 || (header.type & 0x7F) > ERF_TYPE_MAX ) {
      return 0;
    }
    
    /* The ERF_TYPE_MAX is the PAD record, but the last used type is ERF_TYPE_INFINIBAND_LINK */
    if ((header.type & 0x7F) > ERF_TYPE_INFINIBAND_LINK) {
      return 0;
    }
    
    if ((ts = pletohll(&header.ts)) < prevts) {
      /* reassembled AALx records may not be in time order, also records are not in strict time order between physical interfaces, so allow 1 sec fudge */
      if ( ((prevts-ts)>>32) > 1 ) {
	return 0;
      }
    }
    
    /* Check to see if timestamp increment is > 1 week */
    if ( (valid_prev) && (ts > prevts) && (((ts-prevts)>>32) > 3600*24*7) ) {
      return 0;
    }
    
    memcpy(&prevts, &ts, sizeof(prevts));

    /* Read over the extension headers */
    type = header.type;
    while (type & 0x80){
	    if (file_read(&erf_ext_header, sizeof(erf_ext_header),wth->fh) != sizeof(erf_ext_header)) {
		    *err = file_error(wth->fh, err_info);
		    return -1;
	    }
	    packet_size -= (guint32)sizeof(erf_ext_header);
	    memcpy(&type, &erf_ext_header, sizeof(type));
    }
    

    /* Read over MC or ETH subheader */
    switch(header.type & 0x7F) {
    case ERF_TYPE_MC_HDLC:
    case ERF_TYPE_MC_RAW:
    case ERF_TYPE_MC_ATM:
    case ERF_TYPE_MC_RAW_CHANNEL:
    case ERF_TYPE_MC_AAL5:
    case ERF_TYPE_MC_AAL2:
    case ERF_TYPE_COLOR_MC_HDLC_POS:
    case ERF_TYPE_AAL2: /* not an MC type but has a similar 'AAL2 ext' header */
      if (file_read(&mc_hdr,sizeof(mc_hdr),wth->fh) != sizeof(mc_hdr)) {
	*err = file_error(wth->fh, err_info);
	return -1;
      }
      packet_size -= (guint32)sizeof(mc_hdr);
      break;
    case ERF_TYPE_ETH:
    case ERF_TYPE_COLOR_ETH:
    case ERF_TYPE_DSM_COLOR_ETH:
      if (file_read(&eth_hdr,sizeof(eth_hdr),wth->fh) != sizeof(eth_hdr)) {
	*err = file_error(wth->fh, err_info);
	return -1;
      }
      packet_size -= (guint32)sizeof(eth_hdr);
      break;
    default:
      break;
    }

    /* The file_seek function do not return an error if the end of file
       is reached whereas the record is truncated */
    if (packet_size > WTAP_MAX_PACKET_SIZE) {
      /*
       * Probably a corrupt capture file; don't blow up trying
       * to allocate space for an immensely-large packet.
       */
      return 0;
    }
    buffer=g_malloc(packet_size);
    r = file_read(buffer, packet_size, wth->fh);
    g_free(buffer);

    if (r != packet_size) { 
      /* ERF record too short, accept the file,
	 only if the very first records have been successfully checked */
      if (i < MIN_RECORDS_FOR_ERF_CHECK) {
	return 0;
      }
    }

    valid_prev = 1;

  } /* records_for_erf_check */

  if (file_seek(wth->fh, 0L, SEEK_SET, err) == -1) {	/* rewind */
    return -1;
  }

  wth->data_offset = 0;

  /* This is an ERF file */
  wth->file_type = WTAP_FILE_ERF;
  wth->snapshot_length = 0;	/* not available in header, only in frame */

  /*
   * Use the encapsulation for ERF records.
   */
  wth->file_encap = WTAP_ENCAP_ERF;

  wth->subtype_read = erf_read;
  wth->subtype_seek_read = erf_seek_read;
  wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

  return 1;
}

/* Read the next packet */
static gboolean erf_read(wtap *wth, int *err, gchar **err_info,
			 gint64 *data_offset)
{
  erf_header_t erf_header;
  guint32 packet_size, bytes_read;

  *data_offset = wth->data_offset;

  do {
    if (!erf_read_header(wth->fh,
			 &wth->phdr, &wth->pseudo_header, &erf_header,
			 err, err_info, &bytes_read, &packet_size)) {
      return FALSE;
    }
    wth->data_offset += bytes_read;

    buffer_assure_space(wth->frame_buffer, packet_size);
    
    wtap_file_read_expected_bytes(buffer_start_ptr(wth->frame_buffer),
				(gint32)(packet_size), wth->fh, err, err_info);
    wth->data_offset += packet_size;

  } while ( erf_header.type == ERF_TYPE_PAD );

  return TRUE;
}

static gboolean erf_seek_read(wtap *wth, gint64 seek_off,
			      union wtap_pseudo_header *pseudo_header, guchar *pd,
			      int length _U_, int *err, gchar **err_info)
{
  erf_header_t erf_header;
  guint32 packet_size;

  if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    return FALSE;

  do {
    if (!erf_read_header(wth->random_fh, NULL, pseudo_header, &erf_header,
			 err, err_info, NULL, &packet_size))
      return FALSE;
  } while ( erf_header.type == ERF_TYPE_PAD );

  wtap_file_read_expected_bytes(pd, (int)packet_size, wth->random_fh, err,
                                err_info);

  return TRUE;
}

static int erf_read_header(FILE_T fh,
			   struct wtap_pkthdr *phdr,
			   union wtap_pseudo_header *pseudo_header,
			   erf_header_t *erf_header,
			   int *err,
			   gchar **err_info,
			   guint32 *bytes_read,
			   guint32 *packet_size)
{
  guint32 mc_hdr;
  guint8 erf_exhdr[8];
  guint64 erf_exhdr_sw;
  guint8 type = 0;
  guint16 eth_hdr;
  guint32 skiplen=0;
  int i = 0 , max = sizeof(pseudo_header->erf.ehdr_list)/sizeof(struct erf_ehdr);

  wtap_file_read_expected_bytes(erf_header, sizeof(*erf_header), fh, err,
                                err_info);
  if (bytes_read != NULL) {
    *bytes_read = sizeof(*erf_header);
  }

  *packet_size =  g_ntohs(erf_header->rlen) - (guint32)sizeof(*erf_header);

  if (*packet_size > WTAP_MAX_PACKET_SIZE) {
    /*
     * Probably a corrupt capture file; don't blow up trying
     * to allocate space for an immensely-large packet.
     */
    *err = WTAP_ERR_BAD_RECORD;
    *err_info = g_strdup_printf("erf: File has %u-byte packet, bigger than maximum of %u",
				*packet_size, WTAP_MAX_PACKET_SIZE);
    return FALSE;
  }

  if (phdr != NULL) {
    guint64 ts = pletohll(&erf_header->ts);

    phdr->ts.secs = (long) (ts >> 32);
    ts = ((ts & 0xffffffff) * 1000 * 1000 * 1000);
    ts += (ts & 0x80000000) << 1; /* rounding */
    phdr->ts.nsecs = ((int) (ts >> 32));
    if (phdr->ts.nsecs >= 1000000000) {
      phdr->ts.nsecs -= 1000000000;
      phdr->ts.secs += 1;
    }
  }

  /* Copy the ERF pseudo header */
  memset(&pseudo_header->erf, 0, sizeof(pseudo_header->erf));
  pseudo_header->erf.phdr.ts = pletohll(&erf_header->ts);
  pseudo_header->erf.phdr.type = erf_header->type;
  pseudo_header->erf.phdr.flags = erf_header->flags;
  pseudo_header->erf.phdr.rlen = g_ntohs(erf_header->rlen);
  pseudo_header->erf.phdr.lctr = g_ntohs(erf_header->lctr);
  pseudo_header->erf.phdr.wlen = g_ntohs(erf_header->wlen);

  /* Copy the ERF extension header into the pseudo header */
  type = erf_header->type;
  while (type & 0x80){
	  wtap_file_read_expected_bytes(&erf_exhdr, sizeof(erf_exhdr), fh, err,
	                                err_info);
	  if (bytes_read != NULL)
		  *bytes_read += (guint32)sizeof(erf_exhdr);
	  *packet_size -=  (guint32)sizeof(erf_exhdr);
	  skiplen += (guint32)sizeof(erf_exhdr);
	  erf_exhdr_sw = pntohll(erf_exhdr);
	  if (i < max)
	    memcpy(&pseudo_header->erf.ehdr_list[i].ehdr, &erf_exhdr_sw, sizeof(erf_exhdr_sw));
	  type = erf_exhdr[0];
	  i++;
  }

  switch (erf_header->type & 0x7F) {
  case ERF_TYPE_IPV4:
  case ERF_TYPE_IPV6:
  case ERF_TYPE_RAW_LINK:
  case ERF_TYPE_INFINIBAND:
  case ERF_TYPE_INFINIBAND_LINK:
    /***
    if (phdr != NULL) {
      phdr->len =  g_htons(erf_header->wlen);
      phdr->caplen = g_htons(erf_header->wlen); 
    }  
    return TRUE;
    ***/
    break;
  case ERF_TYPE_PAD:
  case ERF_TYPE_HDLC_POS:
  case ERF_TYPE_COLOR_HDLC_POS:
  case ERF_TYPE_DSM_COLOR_HDLC_POS:
  case ERF_TYPE_ATM:
  case ERF_TYPE_AAL5:
    break;

  case ERF_TYPE_ETH:
  case ERF_TYPE_COLOR_ETH:
  case ERF_TYPE_DSM_COLOR_ETH:
    wtap_file_read_expected_bytes(&eth_hdr, sizeof(eth_hdr), fh, err,
                                  err_info);
    if (bytes_read != NULL)
      *bytes_read += (guint32)sizeof(eth_hdr);
    *packet_size -=  (guint32)sizeof(eth_hdr);
    skiplen += (guint32)sizeof(eth_hdr);
    pseudo_header->erf.subhdr.eth_hdr = g_htons(eth_hdr);
    break;

  case ERF_TYPE_MC_HDLC:
  case ERF_TYPE_MC_RAW:
  case ERF_TYPE_MC_ATM:
  case ERF_TYPE_MC_RAW_CHANNEL:
  case ERF_TYPE_MC_AAL5:
  case ERF_TYPE_MC_AAL2:
  case ERF_TYPE_COLOR_MC_HDLC_POS:
  case ERF_TYPE_AAL2: /* not an MC type but has a similar 'AAL2 ext' header */
    wtap_file_read_expected_bytes(&mc_hdr, sizeof(mc_hdr), fh, err,
                                  err_info);
    if (bytes_read != NULL)
      *bytes_read += (guint32)sizeof(mc_hdr);
    *packet_size -=  (guint32)sizeof(mc_hdr);
    skiplen += (guint32)sizeof(mc_hdr);
    pseudo_header->erf.subhdr.mc_hdr = g_htonl(mc_hdr);
    break;

  case ERF_TYPE_IP_COUNTER:
  case ERF_TYPE_TCP_FLOW_COUNTER:
    /* unsupported, continue with default: */
  default:
    *err = WTAP_ERR_UNSUPPORTED_ENCAP;
    *err_info = g_strdup_printf("erf: unknown record encapsulation %u",
				erf_header->type);
    return FALSE;
  }

  if (phdr != NULL) {
    phdr->len = g_htons(erf_header->wlen);
    phdr->caplen = MIN( g_htons(erf_header->wlen),
			g_htons(erf_header->rlen) - (guint32)sizeof(*erf_header) - skiplen );
  }
  return TRUE;
}
