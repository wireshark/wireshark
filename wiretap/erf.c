/*
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

#include <wsutil/crc32.c>

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
			      union wtap_pseudo_header *pseudo_header, guint8 *pd,
			      int length, int *err, gchar **err_info);

static const struct {
  int erf_encap_value;
  int wtap_encap_value;
} erf_to_wtap_map[] = {
  { ERF_TYPE_HDLC_POS,  WTAP_ENCAP_CHDLC },
  { ERF_TYPE_HDLC_POS,  WTAP_ENCAP_HHDLC },
  { ERF_TYPE_HDLC_POS,  WTAP_ENCAP_CHDLC_WITH_PHDR },
  { ERF_TYPE_HDLC_POS,  WTAP_ENCAP_PPP },
  { ERF_TYPE_HDLC_POS,  WTAP_ENCAP_FRELAY },
  { ERF_TYPE_HDLC_POS,  WTAP_ENCAP_MTP2 },
  { ERF_TYPE_ETH,       WTAP_ENCAP_ETHERNET },
  { 99,       WTAP_ENCAP_ERF }, /*this type added so WTAP_ENCAP_ERF will work and then be treated at ERF->ERF*/
};

#define NUM_ERF_ENCAPS (sizeof erf_to_wtap_map / sizeof erf_to_wtap_map[0])

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
			      union wtap_pseudo_header *pseudo_header, guint8 *pd,
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
    *err = WTAP_ERR_BAD_FILE;
    *err_info = g_strdup_printf("erf: File has %u-byte packet, bigger than maximum of %u",
				*packet_size, WTAP_MAX_PACKET_SIZE);
    return FALSE;
  }

  if (*packet_size == 0) {
    /* Again a corrupt packet, bail out */
   *err = WTAP_ERR_BAD_FILE;
   *err_info = g_strdup_printf("erf: File has 0 byte packet");

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

  if (*packet_size > WTAP_MAX_PACKET_SIZE) {
    /*
     * Probably a corrupt capture file; don't blow up trying
     * to allocate space for an immensely-large packet.
     */
    *err = WTAP_ERR_BAD_FILE;
    *err_info = g_strdup_printf("erf: File has %u-byte packet, bigger than maximum of %u",
                                *packet_size, WTAP_MAX_PACKET_SIZE);
    return FALSE;
  }

  return TRUE;
}

static int wtap_wtap_encap_to_erf_encap(int encap)
{
  unsigned int i;
  for(i = 0; i < NUM_ERF_ENCAPS; i++){
    if(erf_to_wtap_map[i].wtap_encap_value == encap)
      return erf_to_wtap_map[i].erf_encap_value;
  }
  return -1;
}

static gboolean erf_write_phdr(wtap_dumper *wdh, int encap, const union wtap_pseudo_header *pseudo_header, int * err)
{
  guint8 erf_hdr[sizeof(struct erf_mc_phdr)];
  guint8 erf_subhdr[((sizeof(struct erf_mc_hdr) > sizeof(struct erf_eth_hdr))?
    sizeof(struct erf_mc_hdr) : sizeof(struct erf_eth_hdr))];
  guint8 ehdr[8*MAX_ERF_EHDR];
  size_t size = 0;
  size_t subhdr_size = 0;
  int i = 0;

  switch(encap){
    case WTAP_ENCAP_ERF:
      memset(&erf_hdr, 0, sizeof(erf_hdr));
      phtolell(&erf_hdr[0], pseudo_header->erf.phdr.ts);
      erf_hdr[8] = pseudo_header->erf.phdr.type;
      erf_hdr[9] = pseudo_header->erf.phdr.flags;
      phtons(&erf_hdr[10], pseudo_header->erf.phdr.rlen);
      phtons(&erf_hdr[12], pseudo_header->erf.phdr.lctr);
      phtons(&erf_hdr[14], pseudo_header->erf.phdr.wlen);
      size = sizeof(struct erf_phdr);

      switch(pseudo_header->erf.phdr.type & 0x7F) {
        case ERF_TYPE_MC_HDLC:
        case ERF_TYPE_MC_RAW:
        case ERF_TYPE_MC_ATM:
        case ERF_TYPE_MC_RAW_CHANNEL:
        case ERF_TYPE_MC_AAL5:
        case ERF_TYPE_MC_AAL2:
        case ERF_TYPE_COLOR_MC_HDLC_POS:
          phtonl(&erf_subhdr[0], pseudo_header->erf.subhdr.mc_hdr);
          subhdr_size += (int)sizeof(struct erf_mc_hdr);
          break;
        case ERF_TYPE_ETH:
        case ERF_TYPE_COLOR_ETH:
        case ERF_TYPE_DSM_COLOR_ETH:
          phtons(&erf_subhdr[0], pseudo_header->erf.subhdr.eth_hdr);
          subhdr_size += (int)sizeof(struct erf_eth_hdr);
          break;
        default:
          break;
      }
      break;
    default:
      return FALSE;

  }
  if (!wtap_dump_file_write(wdh, erf_hdr, size, err))
    return FALSE;
  wdh->bytes_dumped += size;

  /*write out up to MAX_ERF_EHDR extension headers*/
  if((pseudo_header->erf.phdr.type & 0x80) != 0){  /*we have extension headers*/
    do{
      phtonll(ehdr+(i*8), pseudo_header->erf.ehdr_list[i].ehdr);
      if(i == MAX_ERF_EHDR-1) ehdr[i*8] = ehdr[i*8] & 0x7F;
      i++;
    }while((ehdr[0] & 0x80) != 0 && i < MAX_ERF_EHDR);
    if (!wtap_dump_file_write(wdh, ehdr, MAX_ERF_EHDR*i, err))
      return FALSE;
    wdh->bytes_dumped += MAX_ERF_EHDR*i;
  }

  if(!wtap_dump_file_write(wdh, erf_subhdr, subhdr_size, err))
    return FALSE;
  wdh->bytes_dumped += subhdr_size;

  return TRUE;
}

static gboolean erf_dump(
    wtap_dumper *wdh,
    const struct wtap_pkthdr *phdr,
    const union wtap_pseudo_header *pseudo_header,
    const guint8 *pd,
    int *err)
{
  union wtap_pseudo_header other_phdr;
  int encap;
  gint64 alignbytes = 0;
  int i;
  int round_down = 0;
  gboolean must_add_crc = FALSE;
  guint32 crc32 = 0x00000000;

  if(wdh->encap == WTAP_ENCAP_PER_PACKET){
    encap = phdr->pkt_encap;
  }else{
    encap = wdh->encap;
  }

  switch(encap){
    case WTAP_ENCAP_ERF:
      alignbytes = wdh->bytes_dumped + pseudo_header->erf.phdr.rlen;

      if(!erf_write_phdr(wdh, encap, pseudo_header, err)) return FALSE;

      if(!wtap_dump_file_write(wdh, pd, phdr->caplen, err)) return FALSE;
      wdh->bytes_dumped += phdr->caplen;

      while(wdh->bytes_dumped < alignbytes){
        if(!wtap_dump_file_write(wdh, "", 1, err)) return FALSE;
        wdh->bytes_dumped++;
      }
      must_add_crc = TRUE; /* XXX - not if this came from an ERF file with an FCS! */
      break;
    default:  /*deal with generic wtap format*/
      /*generate a fake header in other_phdr using data that we know*/
      /*covert time erf timestamp format*/
      other_phdr.erf.phdr.ts = ((guint64) phdr->ts.secs << 32) + (((guint64) phdr->ts.nsecs <<32) / 1000 / 1000 / 1000);
      other_phdr.erf.phdr.type = wtap_wtap_encap_to_erf_encap(encap);
      other_phdr.erf.phdr.flags = 0x4;  /*vlen flag set because we're creating variable length records*/
      other_phdr.erf.phdr.lctr = 0;
      /*now we work out rlen, accounting for all the different headers and missing fcs(eth)*/
      other_phdr.erf.phdr.rlen = phdr->caplen+16;
      other_phdr.erf.phdr.wlen = phdr->len;
      switch(other_phdr.erf.phdr.type){
        case ERF_TYPE_ETH:
          other_phdr.erf.phdr.rlen += 2;  /*2 bytes for erf eth_type*/
          if (pseudo_header->eth.fcs_len != 4) {
            /* Either this packet doesn't include the FCS
               (pseudo_header->eth.fcs_len = 0), or we don't
               know whether it has an FCS (= -1).  We have to
               synthesize an FCS.*/

            if(!(phdr->caplen < phdr->len)){ /*don't add FCS if packet has been snapped off*/
              crc32 = crc32_ccitt_seed(pd, phdr->caplen, 0xFFFFFFFF);
              other_phdr.erf.phdr.rlen += 4;  /*4 bytes for added checksum*/
              other_phdr.erf.phdr.wlen += 4;
              must_add_crc = TRUE;
            }
          }
          break;
        case ERF_TYPE_HDLC_POS:
          /*we assume that it's missing a FCS checksum, make one up*/
          if(!(phdr->caplen < phdr->len)){  /*unless of course, the packet has been snapped off*/
            crc32 = crc32_ccitt_seed(pd, phdr->caplen, 0xFFFFFFFF);
            other_phdr.erf.phdr.rlen += 4;  /*4 bytes for added checksum*/
            other_phdr.erf.phdr.wlen += 4;
            must_add_crc = TRUE; /* XXX - these never have an FCS? */
          }
          break;
        default:
          break;
      }

      alignbytes = (8 - (other_phdr.erf.phdr.rlen % 8)) % 8;  /*calculate how much padding will be required */
      if(phdr->caplen < phdr->len){ /*if packet has been snapped, we need to round down what we output*/
        round_down = (8 - alignbytes) % 8;
        other_phdr.erf.phdr.rlen -= round_down;
      }else{
        other_phdr.erf.phdr.rlen += (gint16)alignbytes;
      }

      if(!erf_write_phdr(wdh, WTAP_ENCAP_ERF, &other_phdr, err)) return FALSE;
      if(!wtap_dump_file_write(wdh, pd, phdr->caplen - round_down, err)) return FALSE;
      wdh->bytes_dumped += phdr->caplen - round_down;

      /*add the 4 byte CRC if necessary*/
      if(must_add_crc){
        if(!wtap_dump_file_write(wdh, &crc32, 4, err)) return FALSE;
        wdh->bytes_dumped += 4;
      }
      /*records should be 8byte aligned, so we add padding*/
      if(round_down == 0){
        for(i = (gint16)alignbytes; i > 0; i--){
          if(!wtap_dump_file_write(wdh, "", 1, err)) return FALSE;
          wdh->bytes_dumped++;
        }
      }

      break;
  }

  return TRUE;
}

int erf_dump_can_write_encap(int encap)
{

  if(encap == WTAP_ENCAP_PER_PACKET)
    return 0;

  if (wtap_wtap_encap_to_erf_encap(encap) == -1)
    return WTAP_ERR_UNSUPPORTED_ENCAP;

  return 0;
}

int erf_dump_open(wtap_dumper *wdh, int *err)
{
  wdh->subtype_write = erf_dump;
  wdh->subtype_close = NULL;

  switch(wdh->file_type){
    case WTAP_FILE_ERF:
      wdh->tsprecision = WTAP_FILE_TSPREC_NSEC;
      break;
    default:
      *err = WTAP_ERR_UNSUPPORTED_FILE_TYPE;
      return FALSE;
      break;
  }

  return TRUE;
}
