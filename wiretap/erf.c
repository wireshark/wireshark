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
 */

/*
 * erf - Endace ERF (Extensible Record Format)
 *
 * See
 *
 *      http://www.endace.com/support/EndaceRecordFormat.pdf
 *      (mirror: https://bugs.wireshark.org/bugzilla/attachment.cgi?id=4333) (bug #4484)
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <wsutil/crc32.h>

#include "wtap-int.h"
#include "file_wrappers.h"
#include "pcap-encap.h"
#include "pcapng.h"
#include "erf.h"

static gboolean erf_read_header(wtap *wth, FILE_T fh,
                                struct wtap_pkthdr *phdr,
                                erf_header_t *erf_header,
                                int *err,
                                gchar **err_info,
                                guint32 *bytes_read,
                                guint32 *packet_size);
static gboolean erf_read(wtap *wth, int *err, gchar **err_info,
                         gint64 *data_offset);
static gboolean erf_seek_read(wtap *wth, gint64 seek_off,
                              struct wtap_pkthdr *phdr, Buffer *buf,
                              int *err, gchar **err_info);
static void erf_close(wtap *wth);
static int populate_summary_info(erf_t *erf_priv, wtap *wth, union wtap_pseudo_header *pseudo_header, guint32 packet_size);

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

#define ERF_META_TAG_HEADERLEN 4
#define ERF_META_TAG_ALIGNED_LENGTH(taglength)  ((((guint32)taglength + 0x3U) & ~0x3U) + ERF_META_TAG_HEADERLEN)

struct erf_if_info {
  int if_index;
  gchar *name;
  gchar *descr;
  int stream_num;
  struct {
    guint filter:1;
    guint fcs_len:1;
    guint snaplen:1;
  } set_flags;
};

struct erf_if_mapping {
  guint64 host_id;
  guint8 source_id;
  struct erf_if_info interfaces[4];

  gchar *module_filter_str;
  gint8 module_fcs_len;
  guint32 module_snaplen;
  int interface_metadata;
  gboolean module_metadata;
};

struct erf_meta_tag {
  guint16 type;
  guint16 length;
  guint8 *value;
};

struct erf_meta_read_state {
  guint8 *tag_ptr;
  guint32 remaining_len;

  struct erf_if_mapping *if_map;

  guint16 sectiontype;
  guint16 sectionid;
  guint16 parentsectiontype;
  guint16 parentsectionid;

  int interface_metadata;
};

static gboolean erf_if_mapping_equal(gconstpointer a, gconstpointer b)
{
  const struct erf_if_mapping *if_map_a = (const struct erf_if_mapping*) a;
  const struct erf_if_mapping *if_map_b = (const struct erf_if_mapping*) b;

  return if_map_a->source_id == if_map_b->source_id && if_map_a->host_id == if_map_b->host_id;
}

static guint erf_if_mapping_hash(gconstpointer key)
{
  const struct erf_if_mapping *if_map = (const struct erf_if_mapping*) key;

  return (((guint) if_map->host_id) << 16) | if_map->source_id;
}

static void erf_if_mapping_destroy(gpointer key)
{
  int i = 0;
  struct erf_if_mapping *if_map = (struct erf_if_mapping*) key;

  for (i = 0; i < 4; i++) {
    g_free(if_map->interfaces[i].name);
    g_free(if_map->interfaces[i].descr);
  }

  g_free(if_map->module_filter_str);
  g_free(if_map);
}

static struct erf_if_mapping* erf_if_mapping_create(guint64 host_id, guint8 source_id)
{
  int i = 0;
  struct erf_if_mapping *if_map = NULL;

  if_map = (struct erf_if_mapping*) g_malloc(sizeof(struct erf_if_mapping));
  memset(if_map, 0, sizeof(struct erf_if_mapping));

  if_map->host_id = host_id;
  if_map->source_id = source_id;

  for (i = 0; i < 4; i++) {
    if_map->interfaces[i].if_index = -1;
    if_map->interfaces[i].stream_num = -1;
  }

  if_map->module_fcs_len = -1;
  if_map->module_snaplen = (guint32) -1;
  /* everything else 0 by memset */

  return if_map;
}

erf_t *erf_priv_create(void)
{
  erf_t *erf_priv;

  erf_priv = (erf_t*) g_malloc(sizeof(erf_t));
  erf_priv->if_map = g_hash_table_new_full(erf_if_mapping_hash, erf_if_mapping_equal, erf_if_mapping_destroy, NULL);
  erf_priv->implicit_host_id = ERF_META_HOST_ID_IMPLICIT;
  erf_priv->capture_metadata = FALSE;
  erf_priv->host_metadata = FALSE;

  return erf_priv;
}

erf_t* erf_priv_free(erf_t* erf_priv)
{
  if (erf_priv)
  {
    g_hash_table_destroy(erf_priv->if_map);
    g_free(erf_priv);
  }

  return NULL;
}

static void
erf_free_data(gpointer data, gpointer user_data _U_)
{
    g_free(data);
}


extern wtap_open_return_val erf_open(wtap *wth, int *err, gchar **err_info)
{
  int              i, n, records_for_erf_check = RECORDS_FOR_ERF_CHECK;
  int              valid_prev                  = 0;
  char            *s;
  erf_timestamp_t  prevts,ts;
  erf_header_t     header;
  guint32          mc_hdr;
  struct erf_eth_hdr eth_hdr;
  guint32          packet_size;
  guint16          rlen;
  guint64          erf_ext_header;
  guint8           type;
  gboolean         r;
  gchar *          buffer;

  memset(&prevts, 0, sizeof(prevts));

  /* number of records to scan before deciding if this really is ERF */
  if ((s = getenv("ERF_RECORDS_TO_CHECK")) != NULL) {
    if ((n = atoi(s)) >= 0 && n < 101) {
      records_for_erf_check = n;
    }
  }

  /*
   * ERF is a little hard because there's no magic number; we look at
   * the first few records and see if they look enough like ERF
   * records.
   */

  for (i = 0; i < records_for_erf_check; i++) {  /* records_for_erf_check */

    if (!wtap_read_bytes_or_eof(wth->fh,&header,sizeof(header),err,err_info)) {
      if (*err == 0) {
        /* EOF - all records have been successfully checked, accept the file */
        break;
      }
      if (*err == WTAP_ERR_SHORT_READ) {
        /* ERF header too short accept the file,
           only if the very first records have been successfully checked */
        if (i < MIN_RECORDS_FOR_ERF_CHECK) {
          return WTAP_OPEN_NOT_MINE;
        } else {
          /* BREAK, the last record is too short, and will be ignored */
          break;
        }
      } else {
        return WTAP_OPEN_ERROR;
      }
    }

    rlen=g_ntohs(header.rlen);

    /* fail on invalid record type, invalid rlen, timestamps decreasing, or incrementing too far */

    /* Test valid rlen >= 16 */
    if (rlen < 16) {
      return WTAP_OPEN_NOT_MINE;
    }

    packet_size = rlen - (guint32)sizeof(header);
    if (packet_size > WTAP_MAX_PACKET_SIZE) {
      /*
       * Probably a corrupt capture file or a file that's not an ERF file
       * but that passed earlier tests.
       */
      return WTAP_OPEN_NOT_MINE;
    }

    /* Skip PAD records, timestamps may not be set */
    if ((header.type & 0x7F) == ERF_TYPE_PAD) {
      if (file_seek(wth->fh, packet_size, SEEK_CUR, err) == -1) {
        return WTAP_OPEN_ERROR;
      }
      continue;
    }

    /* ERF Type 0 is reserved for ancient legacy records which are not supported, probably not ERF */
    if ((header.type & 0x7F) == 0) {
      return WTAP_OPEN_NOT_MINE;
    }

    /* fail on decreasing timestamps */
    if ((ts = pletoh64(&header.ts)) < prevts) {
      /* reassembled AALx records may not be in time order, also records are not in strict time order between physical interfaces, so allow 1 sec fudge */
      if ( ((prevts-ts)>>32) > 1 ) {
        return WTAP_OPEN_NOT_MINE;
      }
    }

    /* Check to see if timestamp increment is > 1 week */
    if ( (valid_prev) && (ts > prevts) && (((ts-prevts)>>32) > 3600*24*7) ) {
      return WTAP_OPEN_NOT_MINE;
    }

    memcpy(&prevts, &ts, sizeof(prevts));

    /* Read over the extension headers */
    type = header.type;
    while (type & 0x80){
      if (!wtap_read_bytes(wth->fh,&erf_ext_header,sizeof(erf_ext_header),err,err_info)) {
        if (*err == WTAP_ERR_SHORT_READ) {
          /* Extension header missing, not an ERF file */
          return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
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
        if (!wtap_read_bytes(wth->fh,&mc_hdr,sizeof(mc_hdr),err,err_info)) {
          if (*err == WTAP_ERR_SHORT_READ) {
            /* Subheader missing, not an ERF file */
            return WTAP_OPEN_NOT_MINE;
          }
          return WTAP_OPEN_ERROR;
        }
        packet_size -= (guint32)sizeof(mc_hdr);
        break;
      case ERF_TYPE_ETH:
      case ERF_TYPE_COLOR_ETH:
      case ERF_TYPE_DSM_COLOR_ETH:
      case ERF_TYPE_COLOR_HASH_ETH:
        if (!wtap_read_bytes(wth->fh,&eth_hdr,sizeof(eth_hdr),err,err_info)) {
          if (*err == WTAP_ERR_SHORT_READ) {
            /* Subheader missing, not an ERF file */
            return WTAP_OPEN_NOT_MINE;
          }
          return WTAP_OPEN_ERROR;
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
       * Probably a corrupt capture file or a file that's not an ERF file
       * but that passed earlier tests.
       */
      return WTAP_OPEN_NOT_MINE;
    }
    buffer=(gchar *)g_malloc(packet_size);
    r = wtap_read_bytes(wth->fh, buffer, packet_size, err, err_info);
    g_free(buffer);

    if (!r) {
      if (*err != WTAP_ERR_SHORT_READ) {
        /* A real error */
        return WTAP_OPEN_ERROR;
      }
      /* ERF record too short, accept the file,
         only if the very first records have been successfully checked */
      if (i < MIN_RECORDS_FOR_ERF_CHECK) {
        return WTAP_OPEN_NOT_MINE;
      }
    }

    valid_prev = 1;

  } /* records_for_erf_check */

  if (file_seek(wth->fh, 0L, SEEK_SET, err) == -1) {   /* rewind */
    return WTAP_OPEN_ERROR;
  }

  /* This is an ERF file */
  wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_ERF;
  wth->snapshot_length = 0;     /* not available in header, only in frame */

  /*
   * Use the encapsulation for ERF records.
   */
  wth->file_encap = WTAP_ENCAP_ERF;

  wth->subtype_read = erf_read;
  wth->subtype_seek_read = erf_seek_read;
  wth->subtype_close = erf_close;
  wth->file_tsprec = WTAP_TSPREC_NSEC;

  wth->priv = erf_priv_create();

  return WTAP_OPEN_MINE;
}

/* Read the next packet */
static gboolean erf_read(wtap *wth, int *err, gchar **err_info,
                         gint64 *data_offset)
{
  erf_header_t erf_header;
  guint32      packet_size, bytes_read;

  *data_offset = file_tell(wth->fh);

  do {
    if (!erf_read_header(wth, wth->fh,
                         &wth->phdr, &erf_header,
                         err, err_info, &bytes_read, &packet_size)) {
      return FALSE;
    }

    if (!wtap_read_packet_bytes(wth->fh, wth->frame_buffer, packet_size,
                                err, err_info))
      return FALSE;

    /*
     * If MetaERF, frame buffer could hold the meta erf tags. Only look until
     * we have seen a description of every interface.
     */
    if ((erf_header.type & 0x7F) == ERF_TYPE_META && packet_size > 0)
    {
      populate_summary_info((erf_t*) wth->priv, wth, &wth->phdr.pseudo_header, packet_size);
    }

  } while ( erf_header.type == ERF_TYPE_PAD );

  return TRUE;
}

static gboolean erf_seek_read(wtap *wth, gint64 seek_off,
                              struct wtap_pkthdr *phdr, Buffer *buf,
                              int *err, gchar **err_info)
{
  erf_header_t erf_header;
  guint32      packet_size;

  if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
    return FALSE;

  do {
    if (!erf_read_header(wth, wth->random_fh, phdr, &erf_header,
                         err, err_info, NULL, &packet_size))
      return FALSE;
  } while ( erf_header.type == ERF_TYPE_PAD );

  return wtap_read_packet_bytes(wth->random_fh, buf, packet_size,
                                err, err_info);
}

static gboolean erf_read_header(wtap *wth, FILE_T fh,
                                struct wtap_pkthdr *phdr,
                                erf_header_t *erf_header,
                                int *err,
                                gchar **err_info,
                                guint32 *bytes_read,
                                guint32 *packet_size)
{
  union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
  guint8  erf_exhdr[8];
  guint64 erf_exhdr_sw;
  guint8  type    = 0;
  guint32 mc_hdr;
  guint32 aal2_hdr;
  struct wtap_erf_eth_hdr eth_hdr;
  guint32 skiplen = 0;
  int     i       = 0;
  int     max     = sizeof(pseudo_header->erf.ehdr_list)/sizeof(struct erf_ehdr);

  guint64 host_id  = ERF_META_HOST_ID_IMPLICIT;
  guint8 source_id = 0;
  guint8 if_num    = 0;
  gboolean host_id_found = FALSE;

  if (!wtap_read_bytes_or_eof(fh, erf_header, sizeof(*erf_header), err, err_info)) {
    return FALSE;
  }
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
    /* If this isn't a pad record, it's a corrupt packet; bail out */
    if ((erf_header->type & 0x7F) != ERF_TYPE_PAD) {
      *err = WTAP_ERR_BAD_FILE;
      *err_info = g_strdup("erf: File has 0 byte packet");

      return FALSE;
    }
  }

  {
    guint64 ts = pletoh64(&erf_header->ts);

    /*if ((erf_header->type & 0x7f) != ERF_TYPE_META || wth->file_type_subtype != WTAP_FILE_TYPE_SUBTYPE_ERF) {*/
      phdr->rec_type = REC_TYPE_PACKET;
    /*
     * XXX: ERF_TYPE_META records should ideally be FT_SPECIFIC for display
     * purposes, but currently ft_specific_record_phdr clashes with erf_mc_phdr
     * and the PCAP-NG dumper assumes it is a PCAP-NG block type. Ideally we
     * would register a block handler with PCAP-NG and write out the closest
     * PCAP-NG block, or a custom block/MetaERF record.
     *
     */
#if 0
    } else {
      /*
       * TODO: how to identify, distinguish and timestamp events?
       * What to do about ENCAP_ERF in PCAP/PCAP-NG? Filetype dissector is
       * chosen by wth->file_type_subtype?
       */
      /* For now just treat all MetaERF records as reports */
      phdr->rec_type = REC_TYPE_FT_SPECIFIC_REPORT;
      /* XXX: phdr ft_specific_record_phdr? */
    }
#endif
    phdr->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN|WTAP_HAS_INTERFACE_ID;
    phdr->ts.secs = (long) (ts >> 32);
    ts  = ((ts & 0xffffffff) * 1000 * 1000 * 1000);
    ts += (ts & 0x80000000) << 1; /* rounding */
    phdr->ts.nsecs = ((int) (ts >> 32));
    if (phdr->ts.nsecs >= 1000000000) {
      phdr->ts.nsecs -= 1000000000;
      phdr->ts.secs += 1;
    }

    if_num = erf_header->flags & 0x03;
  }

  /* Copy the ERF pseudo header */
  memset(&pseudo_header->erf, 0, sizeof(pseudo_header->erf));
  pseudo_header->erf.phdr.ts = pletoh64(&erf_header->ts);
  pseudo_header->erf.phdr.type = erf_header->type;
  pseudo_header->erf.phdr.flags = erf_header->flags;
  pseudo_header->erf.phdr.rlen = g_ntohs(erf_header->rlen);
  pseudo_header->erf.phdr.lctr = g_ntohs(erf_header->lctr);
  pseudo_header->erf.phdr.wlen = g_ntohs(erf_header->wlen);

  /* Copy the ERF extension header into the pseudo header */
  type = erf_header->type;
  while (type & 0x80){
    if (!wtap_read_bytes(fh, &erf_exhdr, sizeof(erf_exhdr),
                         err, err_info))
      return FALSE;
    if (bytes_read != NULL)
      *bytes_read += (guint32)sizeof(erf_exhdr);
    *packet_size -=  (guint32)sizeof(erf_exhdr);
    skiplen += (guint32)sizeof(erf_exhdr);
    erf_exhdr_sw = pntoh64(erf_exhdr);
    if (i < max)
      memcpy(&pseudo_header->erf.ehdr_list[i].ehdr, &erf_exhdr_sw, sizeof(erf_exhdr_sw));
    type = erf_exhdr[0];

    /*
     * XXX: Only want first Source ID and Host ID, and want to preserve HID n SID 0 (see
     * erf_populate_interface)
     */
    switch (type & 0x7f) {
      case ERF_EXT_HDR_TYPE_HOST_ID:
        if (!host_id_found)
          host_id = erf_exhdr_sw & ERF_EHDR_HOST_ID_MASK;

        host_id_found = TRUE;
        /* Fall through */
      case ERF_EXT_HDR_TYPE_FLOW_ID:
        if (!source_id)
          source_id = (erf_exhdr_sw >> 48) & 0xff;
        break;
    }

    i++;
  }

  /* XXX: erf_priv pointer needs to change if used as common function for other dissectors! */
  phdr->interface_id = (guint) erf_populate_interface((erf_t*) wth->priv, wth, pseudo_header, host_id, source_id, if_num);

  switch (erf_header->type & 0x7F) {
    case ERF_TYPE_IPV4:
    case ERF_TYPE_IPV6:
    case ERF_TYPE_RAW_LINK:
    case ERF_TYPE_INFINIBAND:
    case ERF_TYPE_INFINIBAND_LINK:
    case ERF_TYPE_META:
    case ERF_TYPE_OPA_SNC:
    case ERF_TYPE_OPA_9B:
#if 0
      {
        phdr->len =  g_htons(erf_header->wlen);
        phdr->caplen = g_htons(erf_header->wlen);
      }
      return TRUE;
#endif
      break;
    case ERF_TYPE_PAD:
    case ERF_TYPE_HDLC_POS:
    case ERF_TYPE_COLOR_HDLC_POS:
    case ERF_TYPE_DSM_COLOR_HDLC_POS:
    case ERF_TYPE_COLOR_HASH_POS:
    case ERF_TYPE_ATM:
    case ERF_TYPE_AAL5:
      break;

    case ERF_TYPE_ETH:
    case ERF_TYPE_COLOR_ETH:
    case ERF_TYPE_DSM_COLOR_ETH:
    case ERF_TYPE_COLOR_HASH_ETH:
      if (!wtap_read_bytes(fh, &eth_hdr, sizeof(eth_hdr), err, err_info))
        return FALSE;
      if (bytes_read != NULL)
        *bytes_read += (guint32)sizeof(eth_hdr);
      *packet_size -=  (guint32)sizeof(eth_hdr);
      skiplen += (guint32)sizeof(eth_hdr);
      pseudo_header->erf.subhdr.eth_hdr = eth_hdr;
      break;

    case ERF_TYPE_MC_HDLC:
    case ERF_TYPE_MC_RAW:
    case ERF_TYPE_MC_ATM:
    case ERF_TYPE_MC_RAW_CHANNEL:
    case ERF_TYPE_MC_AAL5:
    case ERF_TYPE_MC_AAL2:
    case ERF_TYPE_COLOR_MC_HDLC_POS:
      if (!wtap_read_bytes(fh, &mc_hdr, sizeof(mc_hdr), err, err_info))
        return FALSE;
      if (bytes_read != NULL)
        *bytes_read += (guint32)sizeof(mc_hdr);
      *packet_size -=  (guint32)sizeof(mc_hdr);
      skiplen += (guint32)sizeof(mc_hdr);
      pseudo_header->erf.subhdr.mc_hdr = g_ntohl(mc_hdr);
      break;

    case ERF_TYPE_AAL2:
      if (!wtap_read_bytes(fh, &aal2_hdr, sizeof(aal2_hdr), err, err_info))
        return FALSE;
      if (bytes_read != NULL)
        *bytes_read += (guint32)sizeof(aal2_hdr);
      *packet_size -=  (guint32)sizeof(aal2_hdr);
      skiplen += (guint32)sizeof(aal2_hdr);
      pseudo_header->erf.subhdr.aal2_hdr = g_ntohl(aal2_hdr);
      break;

    case ERF_TYPE_IP_COUNTER:
    case ERF_TYPE_TCP_FLOW_COUNTER:
      /* unsupported, continue with default: */
    default:
      /* let the dissector dissect as unknown record type for forwards compatibility */
      break;
  }

  {
    phdr->len = g_ntohs(erf_header->wlen);
    phdr->caplen = MIN( g_ntohs(erf_header->wlen),
                        g_ntohs(erf_header->rlen) - (guint32)sizeof(*erf_header) - skiplen );
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
  guint8 erf_subhdr[sizeof(union erf_subhdr)];
  guint8 ehdr[8*MAX_ERF_EHDR];
  size_t size        = 0;
  size_t subhdr_size = 0;
  int    i           = 0;
  guint8 has_more    = 0;

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
        case ERF_TYPE_AAL2:
          phtonl(&erf_subhdr[0], pseudo_header->erf.subhdr.aal2_hdr);
          subhdr_size += (int)sizeof(struct erf_aal2_hdr);
          break;
        case ERF_TYPE_ETH:
        case ERF_TYPE_COLOR_ETH:
        case ERF_TYPE_DSM_COLOR_ETH:
        case ERF_TYPE_COLOR_HASH_ETH:
          memcpy(&erf_subhdr[0], &pseudo_header->erf.subhdr.eth_hdr, sizeof pseudo_header->erf.subhdr.eth_hdr);
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
  has_more = pseudo_header->erf.phdr.type & 0x80;
  if(has_more){  /*we have extension headers*/
    do{
      phtonll(ehdr+(i*8), pseudo_header->erf.ehdr_list[i].ehdr);
      if(i == MAX_ERF_EHDR-1) ehdr[i*8] = ehdr[i*8] & 0x7F;
      has_more = ehdr[i*8] & 0x80;
      i++;
    }while(has_more && i < MAX_ERF_EHDR);
    if (!wtap_dump_file_write(wdh, ehdr, 8*i, err))
      return FALSE;
    wdh->bytes_dumped += 8*i;
  }

  if(!wtap_dump_file_write(wdh, erf_subhdr, subhdr_size, err))
    return FALSE;
  wdh->bytes_dumped += subhdr_size;

  return TRUE;
}

static gboolean erf_dump(
    wtap_dumper                    *wdh,
    const struct wtap_pkthdr       *phdr,
    const guint8                   *pd,
    int                            *err,
    gchar                          **err_info _U_)
{
  const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
  union wtap_pseudo_header other_phdr;
  int      encap;
  gint64   alignbytes   = 0;
  int      i;
  int      round_down   = 0;
  gboolean must_add_crc = FALSE;
  guint32  crc32        = 0x00000000;

  /* Don't write anything bigger than we're willing to read. */
  if(phdr->caplen > WTAP_MAX_PACKET_SIZE) {
    *err = WTAP_ERR_PACKET_TOO_LARGE;
    return FALSE;
  }

  if(wdh->encap == WTAP_ENCAP_PER_PACKET){
    encap = phdr->pkt_encap;
  }else{
    encap = wdh->encap;
  }

  if(encap == WTAP_ENCAP_ERF){
    /* We've been handed an ERF record, so there's not much to do here. */
    alignbytes = wdh->bytes_dumped + pseudo_header->erf.phdr.rlen;

    if(!erf_write_phdr(wdh, encap, pseudo_header, err)) return FALSE;

    if(!wtap_dump_file_write(wdh, pd, phdr->caplen, err)) return FALSE;
    wdh->bytes_dumped += phdr->caplen;

    /*XXX: this pads the record to its original length, which is fine in most
     * cases. However with >MAX_ERF_EHDR unnecessary padding will be added, and
     * if the record was truncated this will be incorrectly treated as payload.
     * More than 8 extension headers is unusual though, only the first 8 are
     * written out anyway and fixing properly would require major refactor.*/
    while(wdh->bytes_dumped < alignbytes){
      if(!wtap_dump_file_write(wdh, "", 1, err)) return FALSE;
      wdh->bytes_dumped++;
    }
    return TRUE;
  }

  /* We can only convert packet records. */
  if (phdr->rec_type != REC_TYPE_PACKET) {
    *err = WTAP_ERR_UNWRITABLE_REC_TYPE;
    return FALSE;
  }

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
    round_down = (8 - (guint)alignbytes) % 8;
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

  return TRUE;
}

int erf_dump_can_write_encap(int encap)
{

  if(encap == WTAP_ENCAP_PER_PACKET)
    return 0;

  if (wtap_wtap_encap_to_erf_encap(encap) == -1)
    return WTAP_ERR_UNWRITABLE_ENCAP;

  return 0;
}

int erf_dump_open(wtap_dumper *wdh, int *err)
{
  wdh->subtype_write = erf_dump;

  switch(wdh->file_type_subtype){
    case WTAP_FILE_TYPE_SUBTYPE_ERF:
      wdh->tsprecision = WTAP_TSPREC_NSEC;
      break;
    default:
      *err = WTAP_ERR_UNWRITABLE_FILE_TYPE;
      return FALSE;
      break;
  }

  return TRUE;
}

/*
 * TODO: Replace uses in pcapng and pcap with
 * erf_read_header() and/or erf_populate_interface_from_header() and delete.
 */
int erf_populate_interfaces(wtap *wth)
{
  wtap_block_t int_data;
  wtapng_if_descr_mandatory_t* int_data_mand;
  int i;

  if (!wth)
    return -1;

  /* Preemptively create interface entries for 4 interfaces, since this is the max number in ERF */
  for (i=0; i<4; i++) {

    int_data = wtap_block_create(WTAP_BLOCK_IF_DESCR);
    int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);

    int_data_mand->wtap_encap = WTAP_ENCAP_ERF;
    /* int_data.time_units_per_second = (1LL<<32);  ERF format resolution is 2^-32, capture resolution is unknown */
    int_data_mand->time_units_per_second = 1000000000; /* XXX Since Wireshark only supports down to nanosecond resolution we have to dilute to this */
    int_data_mand->link_type = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_ERF);
    int_data_mand->snap_len = 65535; /* ERF max length */

    /* XXX: if_IPv4addr opt 4  Interface network address and netmask.*/
    /* XXX: if_IPv6addr opt 5  Interface network address and prefix length (stored in the last byte).*/
    /* XXX: if_MACaddr  opt 6  Interface Hardware MAC address (48 bits).*/
    /* XXX: if_EUIaddr  opt 7  Interface Hardware EUI address (64 bits)*/
    /* XXX: if_speed    opt 8  Interface speed (in bits per second)*/
    /* int_data.if_tsresol = 0xa0;  ERF format resolution is 2^-32 = 0xa0, capture resolution is unknown */
    wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 0x09); /* XXX Since Wireshark only supports down to nanosecond resolution we have to dilute to this */

    /* XXX: if_tzone      10  Time zone for GMT support (TODO: specify better). */

    /* XXX if_tsoffset; opt 14  A 64 bits integer value that specifies an offset (in seconds)...*/
    /* Interface statistics */
    int_data_mand->num_stat_entries = 0;
    int_data_mand->interface_statistics = NULL;

    wtap_block_add_string_option_format(int_data, OPT_IDB_NAME, "Port %c", 'A'+i);
    wtap_block_add_string_option_format(int_data, OPT_IDB_DESCR, "ERF Interface Id %d (Port %c)", i, 'A'+i);

    g_array_append_val(wth->interface_data, int_data);
  }

  return 0;
}

int erf_get_source_from_header(union wtap_pseudo_header *pseudo_header, guint64 *host_id, guint8 *source_id)
{
  guint8   type;
  guint8   has_more;
  guint64  hdr;
  int      i             = 0;
  gboolean host_id_found = FALSE;

  if (!pseudo_header || !host_id || !source_id)
      return -1;

  *host_id = ERF_META_HOST_ID_IMPLICIT;
  *source_id = 0;

  has_more = pseudo_header->erf.phdr.type & 0x80;

  while (has_more && (i < MAX_ERF_EHDR)) {
    hdr = pseudo_header->erf.ehdr_list[i].ehdr;
    type = (guint8) (hdr >> 56);

    /*
     * XXX: Only want first Source ID and Host ID, and want to preserve HID n SID 0 (see
     * erf_populate_interface)
     */
    switch (type & 0x7f) {
      case ERF_EXT_HDR_TYPE_HOST_ID:
        if (!host_id_found)
          *host_id = hdr & ERF_EHDR_HOST_ID_MASK;

        host_id_found = TRUE;
        /* Fall through */
      case ERF_EXT_HDR_TYPE_FLOW_ID:
        if (*source_id == 0)
          *source_id = (hdr >> 48) & 0xff;
        break;
    }

    if (host_id_found)
      break;

    has_more = type & 0x80;
    i += 1;
  }

  return 0;
}

int erf_populate_interface_from_header(erf_t *erf_priv, wtap *wth, union wtap_pseudo_header *pseudo_header)
{
  guint64 host_id;
  guint8 source_id;
  guint8 if_num;

  if (!pseudo_header)
    return -1;

  if_num = pseudo_header->erf.phdr.flags & 0x03;

  erf_get_source_from_header(pseudo_header, &host_id, &source_id);

  return erf_populate_interface(erf_priv, wth, pseudo_header, host_id, source_id, if_num);
}

static struct erf_if_mapping* erf_find_interface_mapping(erf_t *erf_priv, guint64 host_id, guint8 source_id)
{
  struct erf_if_mapping if_map_lookup;

  if (!erf_priv)
    return NULL;

  if_map_lookup.host_id = host_id;
  if_map_lookup.source_id = source_id;

  return (struct erf_if_mapping*) g_hash_table_lookup(erf_priv->if_map, &if_map_lookup);
}

static void erf_set_interface_descr(wtap_block_t block, guint option_id, guint64 host_id, guint8 source_id, guint8 if_num, const gchar *descr)
{
  /* Source XXX,*/
  char sourceid_buf[16];
  /* Host XXXXXXXXXXXX,*/
  char hostid_buf[24];

  sourceid_buf[0] = '\0';
  hostid_buf[0] = '\0';

  /* Implicit Host ID defaults to 0 */
  if (host_id == ERF_META_HOST_ID_IMPLICIT) {
    host_id = 0;
  }

  if (host_id > 0) {
    g_snprintf(hostid_buf, sizeof(hostid_buf), " Host %012" G_GINT64_MODIFIER "x,", host_id);
  }

  if (source_id > 0) {
    g_snprintf(sourceid_buf, sizeof(sourceid_buf), " Source %u,", source_id);
  }

  if (descr) {
    wtap_block_set_string_option_value_format(block, option_id, "%s (ERF%s%s Interface %d)", descr, hostid_buf, sourceid_buf, if_num);
  } else {
    wtap_block_set_string_option_value_format(block, option_id, "Port %c (ERF%s%s Interface %d)", 'A'+if_num, hostid_buf, sourceid_buf, if_num);
  }
}

static int erf_update_implicit_host_id(erf_t *erf_priv, wtap *wth, guint64 implicit_host_id)
{
  GHashTableIter iter;
  gpointer iter_value;
  GList* implicit_list = NULL;
  GList* item = NULL;
  wtap_block_t int_data;
  struct erf_if_mapping* if_map = NULL;
  struct erf_if_mapping* if_map_other = NULL;
  struct erf_if_info* if_info = NULL;
  gchar *oldstr = NULL;
  char portstr_buf[16];
  int i;

  if (!erf_priv)
    return -1;

  erf_priv->implicit_host_id = implicit_host_id;

  /*
   * We need to update the descriptions of all the interfaces with no Host
   * ID to the correct Host ID.
   */
  g_hash_table_iter_init(&iter, erf_priv->if_map);

  /* Remove the implicit mappings from the mapping table */
  while (g_hash_table_iter_next(&iter, &iter_value, NULL)) {
    if_map = (struct erf_if_mapping*) iter_value;

    if (if_map->host_id == ERF_META_HOST_ID_IMPLICIT) {
      /* Check we don't have an existing interface that matches */
      if_map_other = erf_find_interface_mapping(erf_priv, implicit_host_id, if_map->source_id);

      if (!if_map_other) {
        /* Pull mapping for update */
        /* XXX: Can't add while iterating hash table so use list instead */
        g_hash_table_iter_steal(&iter);
        implicit_list = g_list_append(implicit_list, if_map);
      } else {
        /*
         * XXX: We have duplicate interfaces in this case, but not much else we
         * can do since we have already dissected the earlier packets. Expected
         * to be unusual as it reqires a mix of explicit and implicit Host ID
         * (e.g. FlowID extension header only) packets with the same effective
         * Host ID before the first ERF_TYPE_META record.
         */

        /*
         * Update the description of the ERF_META_HOST_ID_IMPLICIT interface(s)
         * for the first records in one pass mode. In 2 pass mode (Wireshark
         * initial open, TShark in 2 pass mode) we will update the interface
         * mapping for the frames on the second pass. Relatively consistent
         * with the dissector behaviour.
         *
         * TODO: Can we delete this interface on the second (or even first)
         * pass? Should we try to merge in other metadata?
         * Needs a wtap_block_copy() that supports overwriting and/or expose
         * custom option copy and do with wtap_block_foreach_option().
         */
        for (i = 0; i < 4; i++) {
          if_info = &if_map->interfaces[i];

          if (if_info->if_index >= 0) {
            /* XXX: this is a pointer! */
            int_data = g_array_index(wth->interface_data, wtap_block_t, if_info->if_index);

            g_snprintf(portstr_buf, sizeof(portstr_buf), "Port %c", 'A'+i);

            oldstr = if_info->name;
            if_info->name = g_strconcat(oldstr ? oldstr : portstr_buf, " [unmatched implicit]", NULL);
            g_free(oldstr); /* probably null, but g_free doesn't care */

            oldstr = if_info->descr;
            if_info->descr = g_strconcat(oldstr ? oldstr : portstr_buf, " [unmatched implicit]", NULL);
            g_free(oldstr);

            erf_set_interface_descr(int_data, OPT_IDB_NAME, implicit_host_id, if_map->source_id, (guint8) i, if_info->name);
            erf_set_interface_descr(int_data, OPT_IDB_DESCR, implicit_host_id, if_map->source_id, (guint8) i, if_info->descr);
          }
        }
      }
    }
  }

  /* Re-add the non-clashing items under the real implicit Host ID */
  if (implicit_list) {
    item = implicit_list;
    do {
      if_map = (struct erf_if_mapping*) item->data;

      for (i = 0; i < 4; i++) {
        if_info = &if_map->interfaces[i];

        if (if_info->if_index >= 0) {
          /* XXX: this is a pointer! */
          int_data = g_array_index(wth->interface_data, wtap_block_t, if_info->if_index);
          erf_set_interface_descr(int_data, OPT_IDB_NAME, implicit_host_id, if_map->source_id, (guint8) i, if_info->name);
          erf_set_interface_descr(int_data, OPT_IDB_DESCR, implicit_host_id, if_map->source_id, (guint8) i, if_info->descr);
        }
      }

      if_map->host_id = implicit_host_id;
      /* g_hash_table_add() only exists since 2.32. */
      g_hash_table_replace(erf_priv->if_map, if_map, if_map);
    } while ((item = g_list_next(item)));

    g_list_free(implicit_list);
  }

  return 0;
}

int erf_populate_interface(erf_t *erf_priv, wtap *wth, union wtap_pseudo_header *pseudo_header, guint64 host_id, guint8 source_id, guint8 if_num)
{
  wtap_block_t int_data;
  wtapng_if_descr_mandatory_t* int_data_mand;
  struct erf_if_mapping* if_map = NULL;

  if (!wth || !pseudo_header || !erf_priv || if_num > 3)
    return -1;

  if (host_id == ERF_META_HOST_ID_IMPLICIT) {
    /* Defaults to ERF_META_HOST_ID_IMPLICIT so we can update mapping later */
    host_id = erf_priv->implicit_host_id;
  } else if ((pseudo_header->erf.phdr.type & 0x7f) == ERF_TYPE_META) {
    /*
     * XXX: We assume there is only one Implicit Host ID. As a special case a first
     * Host ID extension header with Source ID 0 on a record does not change
     * the implicit Host ID. We respect this even though we support only one
     * Implicit Host ID.
     */
    if (erf_priv->implicit_host_id == ERF_META_HOST_ID_IMPLICIT && source_id > 0) {
      erf_update_implicit_host_id(erf_priv, wth, host_id);
    }
  }

  if_map = erf_find_interface_mapping(erf_priv, host_id, source_id);

  if (!if_map) {
    if_map = erf_if_mapping_create(host_id, source_id);
    /* g_hash_table_add() only exists since 2.32. */
    g_hash_table_replace(erf_priv->if_map, if_map, if_map);

  }

  /* Return the existing interface if we have it */
  if (if_map->interfaces[if_num].if_index >= 0) {
    return if_map->interfaces[if_num].if_index;
  }

  int_data = wtap_block_create(WTAP_BLOCK_IF_DESCR);
  int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);

  int_data_mand->wtap_encap = WTAP_ENCAP_ERF;
  /* int_data.time_units_per_second = (1LL<<32);  ERF format resolution is 2^-32, capture resolution is unknown */
  int_data_mand->time_units_per_second = 1000000000; /* XXX Since Wireshark only supports down to nanosecond resolution we have to dilute to this */
  int_data_mand->link_type = wtap_wtap_encap_to_pcap_encap(WTAP_ENCAP_ERF);
  int_data_mand->snap_len = 65535; /* ERF max length */

  /* XXX: if_IPv4addr opt 4  Interface network address and netmask.*/
  /* XXX: if_IPv6addr opt 5  Interface network address and prefix length (stored in the last byte).*/
  /* XXX: if_MACaddr  opt 6  Interface Hardware MAC address (48 bits).*/
  /* XXX: if_EUIaddr  opt 7  Interface Hardware EUI address (64 bits)*/
  /* XXX: if_speed    opt 8  Interface speed (in bits per second)*/
  /* int_data.if_tsresol = 0xa0;  ERF format resolution is 2^-32 = 0xa0, capture resolution is unknown */
  wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 0x09); /* XXX Since Wireshark only supports down to nanosecond resolution we have to dilute to this */
  /* XXX: if_tzone      10  Time zone for GMT support (TODO: specify better). */
  /* XXX if_tsoffset; opt 14  A 64 bits integer value that specifies an offset (in seconds)...*/
  /* Interface statistics */
  int_data_mand->num_stat_entries = 0;
  int_data_mand->interface_statistics = NULL;

  erf_set_interface_descr(int_data, OPT_IDB_NAME, host_id, source_id, if_num, NULL);
  erf_set_interface_descr(int_data, OPT_IDB_DESCR, host_id, source_id, if_num, NULL);

  if_map->interfaces[if_num].if_index = (int) wth->interface_data->len;
  g_array_append_val(wth->interface_data, int_data);

  return if_map->interfaces[if_num].if_index;
}

static guint32 erf_meta_read_tag(struct erf_meta_tag* tag, guint8 *tag_ptr, guint32 remaining_len)
{
  guint16 tagtype;
  guint16 taglength;
  guint32 tagtotallength;

  if (!tag_ptr || !tag || remaining_len < ERF_META_TAG_HEADERLEN)
    return 0;

  /* tagtype (2 bytes) */
  tagtype = pntoh16(&tag_ptr[0]);

  /* length (2 bytes) */
  taglength = pntoh16(&tag_ptr[2]);

  tagtotallength = ERF_META_TAG_ALIGNED_LENGTH(taglength);

  if (remaining_len < tagtotallength) {
    return 0;
  }

  tag->type = tagtype;
  tag->length = taglength;
  tag->value = &tag_ptr[4];

  return tagtotallength;
}

static int populate_capture_host_info(erf_t *erf_priv, wtap *wth, union wtap_pseudo_header *pseudo_header _U_, struct erf_meta_read_state *state)
{
  struct erf_meta_tag tag = {0, 0, NULL};

  wtap_block_t shb_hdr;
  char* tmp;
  gchar* app_name    = NULL;
  gchar* app_version = NULL;
  gchar* model       = NULL;
  gchar* descr       = NULL;
  gchar* cpu         = NULL;
  gchar* modelcpu    = NULL;
  guint32 tagtotallength;

  if (!wth || !state || !wth->shb_hdrs || (wth->shb_hdrs->len == 0))
    return -1;

  /* XXX: wth->shb_hdr is already created by different layer, using directly for now. */
  /* XXX: Only one section header is supported at this time */
  shb_hdr = g_array_index(wth->shb_hdrs, wtap_block_t, 0);

  while ((tagtotallength = erf_meta_read_tag(&tag, state->tag_ptr, state->remaining_len)) && !ERF_META_IS_SECTION(tag.type)) {
    switch (state->sectiontype) {
      case ERF_META_SECTION_CAPTURE:
      {
        if (erf_priv->capture_metadata == TRUE) {
          return 0;
        }

        switch (tag.type) {
          case ERF_META_TAG_comment:
            wtap_block_add_string_option(shb_hdr, OPT_COMMENT, tag.value, tag.length);
            break;
        }
        /* Fall through */
      }
      case ERF_META_SECTION_HOST:
      {
        if (erf_priv->host_metadata == TRUE) {
          return 0;
        }

        switch (tag.type) {
          case ERF_META_TAG_model:
            g_free(model);
            model = g_strndup((gchar*) tag.value, tag.length);
            break;
          case ERF_META_TAG_cpu:
            g_free(cpu);
            cpu = g_strndup((gchar*) tag.value, tag.length);
            break;
          case ERF_META_TAG_descr:
            g_free(descr);
            descr = g_strndup((gchar*) tag.value, tag.length);
            break;
          case ERF_META_TAG_os:
            wtap_block_set_string_option_value(shb_hdr, OPT_SHB_OS, tag.value, tag.length);
            break;
          case ERF_META_TAG_app_name:
            g_free(app_name);
            app_name = g_strndup((gchar*) tag.value, tag.length);
            break;
          case ERF_META_TAG_app_version:
            g_free(app_version);
            app_version = g_strndup((gchar*) tag.value, tag.length);
            break;
            /* TODO: dag_version? */
            /* TODO: could concatenate comment(s)? */
          default:
            break;
        }
      }
      break;
    }

    state->tag_ptr += tagtotallength;
    state->remaining_len -= tagtotallength;
  }

  /* Post processing */

  if (app_name) {
    /* If no app_version will just use app_name */

    tmp = g_strjoin(" ", app_name, app_version, NULL);
    wtap_block_set_string_option_value(shb_hdr, OPT_SHB_USERAPPL, tmp, strlen(tmp));
    g_free(tmp);

    g_free(app_name);
    g_free(app_version);
    app_name = NULL;
    app_version = NULL;
  }

  /* For the hardware field show description followed by (model; cpu) */
  /* Build "Model; CPU" part */
  if (model || cpu) {
    /* g_strjoin() would be nice to use here if the API didn't stop on the first NULL... */
    if (model && cpu) {
      modelcpu = g_strconcat(model, "; ", cpu, NULL);
    } else if (cpu) {
      modelcpu = cpu;
      /* avoid double-free */
      cpu = NULL;
    } else {
      modelcpu = model;
      /* avoid double-free */
      model = NULL;
    }
  }

  /* Combine into "Description (Model; CPU)" */
  if (state->sectiontype == ERF_META_SECTION_HOST && descr) {
    if (modelcpu) {
      wtap_block_set_string_option_value_format(shb_hdr, OPT_SHB_HARDWARE, "%s (%s)", descr, modelcpu);
    } else {
      wtap_block_set_string_option_value(shb_hdr, OPT_SHB_HARDWARE, descr, strlen(descr));
      /*descr = NULL;*/
    }
  } else if (modelcpu) {
    wtap_block_set_string_option_value(shb_hdr, OPT_SHB_HARDWARE, modelcpu, strlen(modelcpu));
    /*modelcpu = NULL;*/
  }

  /* Free the fields we didn't end up using */
  g_free(modelcpu);
  g_free(model);
  g_free(descr);
  g_free(cpu);

  if (state->sectiontype == ERF_META_SECTION_CAPTURE) {
    erf_priv->capture_metadata = TRUE;
  } else {
    erf_priv->host_metadata = TRUE;
  }

  return 1;
}

static int populate_module_info(erf_t *erf_priv _U_, wtap *wth, union wtap_pseudo_header *pseudo_header _U_, struct erf_meta_read_state *state)
{
  struct erf_meta_tag tag = {0, 0, NULL};

  guint32 tagtotallength;

  if (!wth || !state)
    return -1;

  if (state->if_map->module_metadata == TRUE) {
    return 0;
  }

  while ((tagtotallength = erf_meta_read_tag(&tag, state->tag_ptr, state->remaining_len)) && !ERF_META_IS_SECTION(tag.type)) {
      switch (tag.type) {
        case ERF_META_TAG_fcs_len:
          if (tag.length >= 4) {
            state->if_map->module_fcs_len = (gint8) pntoh32(tag.value);
          }
          break;
        case ERF_META_TAG_snaplen:
          /* XXX: this is generally per stream */
          if (tag.length >= 4) {
            state->if_map->module_snaplen = pntoh32(tag.value);
          }
          break;
        case ERF_META_TAG_filter:
          g_free(state->if_map->module_filter_str);
          state->if_map->module_filter_str = g_strndup((gchar*) tag.value, tag.length);
          break;
      }

    state->tag_ptr += tagtotallength;
    state->remaining_len -= tagtotallength;
  }

  state->if_map->module_metadata = TRUE;

  return 1;
}

static int populate_interface_info(erf_t *erf_priv, wtap *wth, union wtap_pseudo_header *pseudo_header, struct erf_meta_read_state *state)
{
  struct erf_meta_tag tag = {0, 0, NULL};
  guint32 tagtotallength;
  int interface_index = -1;
  wtap_block_t int_data = NULL;
  wtapng_if_descr_mandatory_t* int_data_mand = NULL;
  wtapng_if_descr_filter_t if_filter;
  guint32 if_num = 0;
  struct erf_if_info* if_info = NULL;

  memset(&if_filter, 0, sizeof(if_filter));

  if (!wth || !state || !pseudo_header || !state->if_map)
    return -1;

  /* Section ID of interface is defined to match ERF interface id. */
  if_num = state->sectionid - 1;
  /*
   * Get or create the interface (there can be multiple interfaces in
   * a MetaERF record).
   */
  if (if_num < 4) { /* Note: -1u > 4*/
    if_info = &state->if_map->interfaces[if_num];
    interface_index = if_info->if_index;

    /* Check if the interface information is still uninitialized */
    if (interface_index == -1) {
      guint8 *tag_ptr_tmp = state->tag_ptr;
      guint32 remaining_len_tmp = state->remaining_len;

      /* First iterate tags, checking we aren't looking at a timing port */
      /*
       * XXX: we deliberately only do this logic here rather than the per-packet
       * population function so that if somehow we do see packets for an
       * 'invalid' port the interface will be created at that time.
       */
      while ((tagtotallength = erf_meta_read_tag(&tag, tag_ptr_tmp, remaining_len_tmp)) && !ERF_META_IS_SECTION(tag.type)) {
        if (tag.type == ERF_META_TAG_if_port_type) {
          if (tag.length >= 4 && pntoh32(tag.value) == 2) {
            /* This is a timing port, skip it from now on */
            /* XXX: should we skip all non-capture ports instead? */

            if_info->if_index = -2;
            interface_index = -2;
          }
        } else if (tag.type == ERF_META_TAG_stream_num) {
          if (tag.length >= 4) {
            if_info->stream_num = (gint32) pntoh32(tag.value);
          }
        }

        tag_ptr_tmp += tagtotallength;
        remaining_len_tmp -= tagtotallength;
      }

      /* If the interface is valid but uninitialized, create it */
      if (interface_index == -1) {
        interface_index = erf_populate_interface(erf_priv, wth, pseudo_header, state->if_map->host_id, state->if_map->source_id, (guint8) if_num);
      }
    }

    /* Get the wiretap interface metadata */
    if (interface_index >= 0) {
      int_data = g_array_index(wth->interface_data, wtap_block_t, interface_index);
      int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
    } else if (interface_index == -2) {
      /* timing/unknown port */
      return 0;
    } else {
      return -1;
    }
  }

  /*
   * Bail if already have interface metadata or no interface to associate with.
   * We also don't support metadata for >4 interfaces per Host + Source
   * as we only use interface ID.
   */
  if (!int_data || state->if_map->interface_metadata & (1 << if_num))
    return 0;

  while ((tagtotallength = erf_meta_read_tag(&tag, state->tag_ptr, state->remaining_len)) && !ERF_META_IS_SECTION(tag.type)) {
    switch (tag.type) {
      case ERF_META_TAG_name:
        /* TODO: fall back to module "dev_name Port N"? */
        if (!if_info->name) {
          if_info->name = g_strndup((gchar*) tag.value, tag.length);
          erf_set_interface_descr(int_data, OPT_IDB_NAME, state->if_map->host_id, state->if_map->source_id, (guint8) if_num, if_info->name);

          /* If we have no description, also copy to wtap if_description */
          if (!if_info->descr) {
            erf_set_interface_descr(int_data, OPT_IDB_DESCR, state->if_map->host_id, state->if_map->source_id, (guint8) if_num, if_info->name);
          }
        }
        break;
      case ERF_META_TAG_descr:
        if (!if_info->descr) {
          if_info->descr = g_strndup((gchar*) tag.value, tag.length);
          erf_set_interface_descr(int_data, OPT_IDB_DESCR, state->if_map->host_id, state->if_map->source_id, (guint8) if_num, if_info->descr);

          /* If we have no name, also copy to wtap if_name */
          if (!if_info->name) {
            erf_set_interface_descr(int_data, OPT_IDB_NAME, state->if_map->host_id, state->if_map->source_id, (guint8) if_num, if_info->descr);
          }
        }
        break;
      case ERF_META_TAG_if_speed:
        if (tag.length >= 8)
          wtap_block_add_uint64_option(int_data, OPT_IDB_SPEED, pntoh64(tag.value));
        break;
      case ERF_META_TAG_if_num:
        /*
         * XXX: We ignore this as Section ID must match the ERF ifid and
         * that is all we care about/have space for at the moment. if_num
         * is only really useful with >4 interfaces.
         */
        /* TODO: might want to put this number in description */
        break;
      case ERF_META_TAG_fcs_len:
        if (tag.length >= 4) {
          wtap_block_add_uint8_option(int_data, OPT_IDB_FCSLEN, (guint8) pntoh32(tag.value));
          if_info->set_flags.fcs_len = 1;
        }
        break;
      case ERF_META_TAG_snaplen:
        /* XXX: this generally per stream */
        if (tag.length >= 4) {
          int_data_mand->snap_len = pntoh32(tag.value);
          if_info->set_flags.snaplen = 1;
        }
        break;
      case ERF_META_TAG_comment:
        wtap_block_add_string_option(int_data, OPT_COMMENT, tag.value, tag.length);
        break;
      case ERF_META_TAG_filter:
        if_filter.if_filter_str = g_strndup((gchar*) tag.value, tag.length);
        wtap_block_add_custom_option(int_data, OPT_IDB_FILTER, &if_filter, sizeof if_filter);
        g_free(if_filter.if_filter_str);
        if_info->set_flags.filter = 1;
        break;
      default:
        break;
    }

    state->tag_ptr += tagtotallength;
    state->remaining_len -= tagtotallength;
  }

  /* Post processing */
  /*
   * XXX: Assumes module defined first. It is higher in hierarchy so only set
   * if not already.
   */

  /*
   * XXX: Missing exposed existence/type-check. No way currently to check if
   * been set in the optionblock.
   */
  if (state->if_map->module_filter_str && !if_info->set_flags.filter) {
    /* Duplicate because might use with multiple interfaces */
    if_filter.if_filter_str = state->if_map->module_filter_str;
    wtap_block_add_custom_option(int_data, OPT_IDB_FILTER, &if_filter, sizeof if_filter);
    /*
     * Don't set flag because stream is more specific than module. Interface
     * metadata bit is set so we don't look at the filter again regardless.
     */
  }

  if (state->if_map->module_fcs_len != -1 && !if_info->set_flags.fcs_len) {
    wtap_block_add_uint8_option(int_data, OPT_IDB_FCSLEN, (guint8) state->if_map->module_fcs_len);
    if_info->set_flags.fcs_len = 1;
  }

  if (state->if_map->module_snaplen != (guint32) -1 && !if_info->set_flags.snaplen) {
    int_data_mand->snap_len = pntoh32(tag.value);
    if_info->set_flags.snaplen = 1;
  }

  state->interface_metadata |= 1 << if_num;

  return 1;
}

static int populate_stream_info(erf_t *erf_priv _U_, wtap *wth, union wtap_pseudo_header *pseudo_header, struct erf_meta_read_state *state)
{
  struct erf_meta_tag tag = {0, 0, NULL};
  guint32 tagtotallength;
  int interface_index = -1;
  wtap_block_t int_data = NULL;
  wtapng_if_descr_mandatory_t* int_data_mand = NULL;
  wtapng_if_descr_filter_t if_filter;
  guint32 if_num = 0;
  gint32 stream_num = -1;
  guint8 *tag_ptr_tmp;
  guint32 remaining_len_tmp;
  struct erf_if_info* if_info = NULL;

  memset(&if_filter, 0, sizeof(if_filter));

  if (!wth || !pseudo_header || !state || !state->if_map)
    return -1;

  tag_ptr_tmp = state->tag_ptr;
  remaining_len_tmp = state->remaining_len;

  /*
   * XXX: We ignore parent section ID because it doesn't represent the
   * many-to-many relationship of interfaces and streams very well. The stream is
   * associated with all interfaces in the record that don't have a stream_num
   * that says otherwise.
   */

  if (state->sectionid > 0 && state->sectionid != 0x7fff) {
    /* Section ID of stream is supposed to match stream_num. */
    stream_num = state->sectionid - 1;
  } else {
    /* First iterate tags, looking for the stream number interfaces might associate with. */
    while ((tagtotallength = erf_meta_read_tag(&tag, tag_ptr_tmp, remaining_len_tmp)) && !ERF_META_IS_SECTION(tag.type)) {
      if (tag.type == ERF_META_TAG_stream_num) {
        if (tag.length >= 4) {
          stream_num = (gint32) pntoh32(tag.value);
        }
      }

      tag_ptr_tmp += tagtotallength;
      remaining_len_tmp -= tagtotallength;
    }
  }
  /* Otherwise assume the stream applies to all interfaces in the record */

  for (if_num = 0; if_num < 4; if_num++) {
    tag_ptr_tmp = state->tag_ptr;
    remaining_len_tmp = state->remaining_len;
    if_info = &state->if_map->interfaces[if_num];

    /* Check if we should be handling this interface */
    /* XXX: currently skips interfaces that are not in the record. */
    if (state->if_map->interface_metadata & (1 << if_num)
        || !(state->interface_metadata & (1 << if_num))) {
      continue;
    }

    if (if_info->stream_num != -1
        && if_info->stream_num != stream_num) {
      continue;
    }

    interface_index = if_info->if_index;
    /* Get the wiretap interface metadata */
    if (interface_index >= 0) {
        int_data = g_array_index(wth->interface_data, wtap_block_t, interface_index);
        int_data_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);
    }

    if (!int_data) {
      continue;
    }

    while ((tagtotallength = erf_meta_read_tag(&tag, tag_ptr_tmp, remaining_len_tmp)) && !ERF_META_IS_SECTION(tag.type)) {
      switch (tag.type) {
        case ERF_META_TAG_fcs_len:
          if (tag.length >= 4) {
            /* Use the largest fcslen of matching streams */
            gint8 fcs_len = (gint8) pntoh32(tag.value);
            guint8 old_fcs_len = 0;

            switch (wtap_block_get_uint8_option_value(int_data, OPT_IDB_FCSLEN, &old_fcs_len)) {

              case WTAP_OPTTYPE_SUCCESS:
                /* We already have an FCS length option; update it. */
                if (fcs_len > old_fcs_len || !if_info->set_flags.fcs_len) {
                  wtap_block_set_uint8_option_value(int_data, OPT_IDB_FCSLEN, (guint8) pntoh32(tag.value));
                  if_info->set_flags.fcs_len = 1;
                }
                break;

              case WTAP_OPTTYPE_NOT_FOUND:
                /* We don't have an FCS length option; add it. */
                wtap_block_add_uint8_option(int_data, OPT_IDB_FCSLEN, (guint8) pntoh32(tag.value));
                if_info->set_flags.fcs_len = 1;
                break;

              default:
                /* "shouldn't happen" */
                break;
            }
          }
          break;
        case ERF_META_TAG_snaplen:
          if (tag.length >= 4) {
            /* Use the largest snaplen of matching streams */
            guint32 snaplen = pntoh32(tag.value);

            if (snaplen > int_data_mand->snap_len || !if_info->set_flags.snaplen) {
              int_data_mand->snap_len = pntoh32(tag.value);
              if_info->set_flags.snaplen = 1;
            }
          }
          break;
        case ERF_META_TAG_filter:
          /* Override only if not set */
          if (!if_info->set_flags.filter) {
            if_filter.if_filter_str = g_strndup((gchar*) tag.value, tag.length);
            wtap_block_add_custom_option(int_data, OPT_IDB_FILTER, &if_filter, sizeof if_filter);
            g_free(if_filter.if_filter_str);
            if_info->set_flags.filter = 1;
          }
          break;
        default:
          break;
      }

      tag_ptr_tmp += tagtotallength;
      remaining_len_tmp -= tagtotallength;
    }
  }
  state->tag_ptr = tag_ptr_tmp;
  state->remaining_len = remaining_len_tmp;

  return 1;
}

/* Populates the capture and interface information for display on the Capture File Properties */
static int populate_summary_info(erf_t *erf_priv, wtap *wth, union wtap_pseudo_header *pseudo_header, guint32 packet_size)
{
  struct erf_meta_read_state state;
  struct erf_meta_read_state *state_post = NULL;
  guint64 host_id;
  guint8 source_id;
  GList *post_list = NULL;
  GList *item = NULL;

  struct erf_meta_tag tag = {0, 0, NULL};
  guint32 tagtotallength;

  if (!erf_priv || !wth || !pseudo_header)
    return -1;

  memset(&state, 0, sizeof(struct erf_meta_read_state));

  erf_get_source_from_header(pseudo_header, &host_id, &source_id);

  if (host_id == 0) {
    host_id = erf_priv->implicit_host_id;
  }

  state.if_map = erf_find_interface_mapping(erf_priv, host_id, source_id);

  if (!state.if_map) {
    state.if_map = erf_if_mapping_create(host_id, source_id);
    /* g_hash_table_add() only exists since 2.32. */
    g_hash_table_replace(erf_priv->if_map, state.if_map, state.if_map);

  }

  /*
   * Skip the record if we already have enough metadata (seen one section for
   * each type for the source).
   */
  if ((state.if_map->interface_metadata & 0x03)
      && erf_priv->host_metadata && erf_priv->capture_metadata) {
    return 0;
  }

  state.tag_ptr = wth->frame_buffer->data;
  state.remaining_len = packet_size;

  /* Read until see next section tag */
  while ((tagtotallength = erf_meta_read_tag(&tag, state.tag_ptr, state.remaining_len))) {
    /*
     * Skip until we get to the next section tag (which could be the current tag
     * after an empty section or successful parsing).
     */
    if (!ERF_META_IS_SECTION(tag.type)) {
      /* adjust offset */
      state.tag_ptr += tagtotallength;
      state.remaining_len -= tagtotallength;
      continue;
    }

    /*
     * We are now looking at the next section (and would have exited the loop
     * if we reached the end).
     */

    /* Update parent section. Implicit grouping is by a change in section except Interface and Stream. */
    if (tag.type != state.sectiontype) {
      if ((tag.type == ERF_META_SECTION_STREAM && state.sectiontype == ERF_META_SECTION_INTERFACE) ||
        (tag.type == ERF_META_SECTION_INTERFACE && state.sectiontype == ERF_META_SECTION_STREAM)) {
        /* do nothing */
      } else {
        state.parentsectiontype = state.sectiontype;
        state.parentsectionid = state.sectionid;
      }
    }

    /* Update with new sectiontype */
    state.sectiontype = tag.type;
    if (tag.length >= 4) {
      state.sectionid = pntoh16(tag.value);
    } else {
      state.sectionid = 0;
    }

    /* Adjust offset to that of first tag in section */
    state.tag_ptr += tagtotallength;
    state.remaining_len -= tagtotallength;

    if ((tagtotallength = erf_meta_read_tag(&tag, state.tag_ptr, state.remaining_len))) {
      /*
       * Process parent section tag if present (which must be the first tag in
       * the section).
       */
      if (tag.type == ERF_META_TAG_parent_section && tag.length >= 4) {
        state.parentsectiontype = pntoh16(tag.value);
        state.parentsectionid = pntoh16(&tag.value[2]);
      }
    }

    /* Skip empty sections (includes if above read fails) */
    if (ERF_META_IS_SECTION(tag.type)) {
      continue;
    }

    /*
     * Skip sections that don't apply to the general set of records
     * (extension point for per-packet/event metadata).
     */
    if (state.sectionid & 0x8000) {
      continue;
    }

    /*
     * Start at first tag in section, makes loop
     * simpler in called functions too. Also makes iterating after failure
     * much simpler.
     */
    switch (state.sectiontype) {
      case ERF_META_SECTION_CAPTURE:
      case ERF_META_SECTION_HOST:
        /* TODO: use return code */
        populate_capture_host_info(erf_priv, wth, pseudo_header, &state);
        break;
      case ERF_META_SECTION_MODULE:
        populate_module_info(erf_priv, wth, pseudo_header, &state);
        break;
      case ERF_META_SECTION_INTERFACE:
        populate_interface_info(erf_priv, wth, pseudo_header, &state);
        break;
      case ERF_META_SECTION_STREAM:
        /*
         * XXX: Treat streams specially in case the stream information appears
         * before the interface information, as we associate them to interface
         * data.
         */
        post_list = g_list_append(post_list, g_memdup(&state, sizeof(struct erf_meta_read_state)));
        break;
      case ERF_META_SECTION_SOURCE:
      case ERF_META_SECTION_DNS:
      default:
        /* TODO: Not yet implemented */
        break;
    }
  }

  /* Process streams last */
  if (post_list) {
    item = post_list;
    do {
      state_post = (struct erf_meta_read_state*) item->data;
      switch (state_post->sectiontype) {
        case ERF_META_SECTION_STREAM:
          populate_stream_info(erf_priv, wth, pseudo_header, state_post);
          break;
      }
    } while ((item = g_list_next(item)));
    /* g_list_free_full() only exists since 2.28. */
    g_list_foreach(post_list, erf_free_data, NULL);
    g_list_free(post_list);
  }

  /*
   * Update known metadata so we only examine the first set of metadata. Need to
   * do this here so can have interface and stream in same record.
   */
  state.if_map->interface_metadata |= state.interface_metadata;

  return 0;
}

static void erf_close(wtap *wth)
{
  erf_t* erf_priv = (erf_t*)wth->priv;

  erf_priv_free(erf_priv);
  /* XXX: Prevent double free by wtap_close() */
  wth->priv = NULL;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
