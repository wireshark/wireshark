/* file.c
 * File I/O routines
 *
 * $Id: file.c,v 1.13 1998/11/17 04:28:46 gerald Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
# include "config.h"
#endif

#include <gtk/gtk.h>

#ifdef WITH_WIRETAP
#include <pcap.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "menu.h"
#include "ethereal.h"
#include "packet.h"
#include "file.h"
#include "util.h"

extern GtkWidget *packet_list, *prog_bar, *info_bar, *byte_view, *tree_view;
extern guint      file_ctx;

static guint32 ssec, susec;
static guint32 lastsec, lastusec;

#ifdef WITH_WIRETAP
static void wtap_dispatch_cb(u_char *, const struct wtap_pkthdr *, int,
    const u_char *);
#else
static void pcap_dispatch_cb(u_char *, const struct pcap_pkthdr *,
    const u_char *);
#endif

int
open_cap_file(char *fname, capture_file *cf) {
#ifndef WITH_WIRETAP
  guint32     magic[2];
  char        err_str[PCAP_ERRBUF_SIZE];
#endif
  struct stat cf_stat;

  /* First, make sure the file is valid */
  if (stat(fname, &cf_stat)) {
    simple_dialog(ESD_TYPE_WARN, NULL, "File does not exist.");
    return 1;
  }
  if (! S_ISREG(cf_stat.st_mode) && ! S_ISFIFO(cf_stat.st_mode)) {
    simple_dialog(ESD_TYPE_WARN, NULL, "The file you have chosen is invalid.");
    return 1;
  }

  /* Next, try to open the file */
  cf->fh = fopen(fname, "r");
  if (cf->fh == NULL)
    return (errno);

  fseek(cf->fh, 0L, SEEK_END);
  cf->f_len = ftell(cf->fh);
#ifndef WITH_WIRETAP
  fseek(cf->fh, 0L, SEEK_SET);
  fread(magic, sizeof(guint32), 2, cf->fh);
  fseek(cf->fh, 0L, SEEK_SET);
#endif
  fclose(cf->fh);
  cf->fh = NULL;
  /* set the file name beacuse we need it to set the follow stream filter */
  cf->filename = g_strdup( fname );

  /* Next, find out what type of file we're dealing with */
#ifdef WITH_WIRETAP 
  cf->cd_t  = WTAP_FILE_UNKNOWN;
  cf->lnk_t = WTAP_ENCAP_NONE;
#else
  cf->cd_t  = CD_UNKNOWN;
  cf->lnk_t = DLT_NULL;
#endif
  cf->swap  = 0;
  cf->count = 0;
  cf->drops = 0;
  cf->esec  = 0;
  cf->eusec = 0;
  cf->snap  = 0;
  if (cf->plist == NULL) {
    cf->plist       = g_list_alloc();
    cf->plist->data = (frame_data *) g_malloc(sizeof(frame_data));
  } else {
    cf->plist = g_list_first(cf->plist);
  }
  ssec = 0, susec = 0;
  lastsec = 0, lastusec = 0;
 
#ifndef WITH_WIRETAP
  if (magic[0] == PCAP_MAGIC || magic[0] == SWAP32(PCAP_MAGIC)) {

    /* Pcap/Tcpdump file */
    cf->pfh = pcap_open_offline(fname, err_str);
    if (cf->pfh == NULL) {
#else
	cf->wth = wtap_open_offline(fname, WTAP_FILE_UNKNOWN);
	if (cf->wth == NULL) {
#endif

      simple_dialog(ESD_TYPE_WARN, NULL, "Could not open file.");
      return 1;
    }

#ifndef WITH_WIRETAP
    if (cf->dfilter) {
      if (pcap_compile(cf->pfh, &cf->fcode, cf->dfilter, 1, 0) < 0) {
        simple_dialog(ESD_TYPE_WARN, NULL, "Unable to parse filter string "
          "\"%s\".", cf->dfilter);
      } else if (pcap_setfilter(cf->pfh, &cf->fcode) < 0) {
        simple_dialog(ESD_TYPE_WARN, NULL, "Can't install filter.");
      }
    }

    cf->fh   = pcap_file(cf->pfh);
    cf->swap = pcap_is_swapped(cf->pfh);    
    if ((cf->swap && BYTE_ORDER == BIG_ENDIAN) ||
      (!cf->swap && BYTE_ORDER == LITTLE_ENDIAN)) {
      /* Data is big-endian */
      cf->cd_t = CD_PCAP_BE;
    } else {
      cf->cd_t = CD_PCAP_LE;
    }
    cf->vers  = ( ((pcap_major_version(cf->pfh) & 0x0000ffff) << 16) |
                  pcap_minor_version(cf->pfh) );
    cf->snap  = pcap_snapshot(cf->pfh);
    cf->lnk_t = pcap_datalink(cf->pfh);
  } else if (ntohl(magic[0]) == SNOOP_MAGIC_1 && ntohl(magic[1]) == SNOOP_MAGIC_2) {
    /* Snoop file */
    simple_dialog(ESD_TYPE_WARN, NULL, "The snoop format is not yet supported.");
    return 1;
    /*
    fread(&sfh, sizeof(snoop_file_hdr), 1, cf->fh);
    cf->cd_t = CD_SNOOP;
    cf->vers = ntohl(sfh.vers);
    if (cf->vers < SNOOP_MIN_VERSION || cf->vers > SNOOP_MAX_VERSION) {
      g_warning("ethereal:open_cap_file:%s:bad snoop file version(%d)",
        fname, cf->vers);
      return 1;
    }
    switch (ntohl(sfh.s_lnk_t)) {
      case 4:
        cf->lnk_t = DLT_EN10MB;
        break;
    }
    */
  }
  
  if (cf->cd_t == CD_UNKNOWN) {
    simple_dialog(ESD_TYPE_WARN, NULL, "Can't determine file type.");
    return 1;
  }
#else
  cf->fh = wtap_file(cf->wth);
  cf->cd_t = wtap_file_type(cf->wth);
  cf->snap = wtap_snapshot_length(cf->wth);
  cf->lnk_t = wtap_encapsulation(cf->wth);
#endif

  return 0;
}

/* Reset everything to a pristine state */
void
close_cap_file(capture_file *cf, GtkWidget *w, guint context) {
  if (cf->fh) {
    fclose(cf->fh);
    cf->fh = NULL;
  }
#ifdef WITH_WIRETAP
  if (cf->wth) {
	  wtap_close(cf->wth);
	  cf->wth = NULL;
	}
#else
  if (cf->pfh) {
    pcap_close(cf->pfh);
    cf->pfh = NULL;
  }
#endif
  gtk_text_freeze(GTK_TEXT(byte_view));
  gtk_text_set_point(GTK_TEXT(byte_view), 0);
  gtk_text_forward_delete(GTK_TEXT(byte_view),
    gtk_text_get_length(GTK_TEXT(byte_view)));
  gtk_text_thaw(GTK_TEXT(byte_view));
  gtk_tree_clear_items(GTK_TREE(tree_view), 0,
    g_list_length(GTK_TREE(tree_view)->children));

  gtk_clist_freeze(GTK_CLIST(packet_list));
  gtk_clist_clear(GTK_CLIST(packet_list));
  gtk_clist_thaw(GTK_CLIST(packet_list));
  gtk_statusbar_pop(GTK_STATUSBAR(w), context);
}

int
load_cap_file(char *fname, capture_file *cf) {
  gchar  *name_ptr, *load_msg, *load_fmt = " Loading: %s...";
  gchar  *done_fmt = " File: %s  Drops: %d";
  gchar  *err_fmt  = " Error: Could not load '%s'";
  gint    timeout;
  size_t  msg_len;
  int     err;

  close_cap_file(cf, info_bar, file_ctx);
  
  if ((name_ptr = (gchar *) strrchr(fname, '/')) == NULL)
    name_ptr = fname;
  else
    name_ptr++;
  load_msg = g_malloc(strlen(name_ptr) + strlen(load_fmt) + 2);
  sprintf(load_msg, load_fmt, name_ptr);
  gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
  
  timeout = gtk_timeout_add(250, file_progress_cb, (gpointer) &cf);
  
  err = open_cap_file(fname, cf);
#ifdef WITH_WIRETAP
  if ((err == 0) && (cf->cd_t != WTAP_FILE_UNKNOWN)) {
#else
  if ((err == 0) && (cf->cd_t != CD_UNKNOWN)) {
#endif
    gtk_clist_freeze(GTK_CLIST(packet_list));
#ifdef WITH_WIRETAP
    wtap_loop(cf->wth, 0, wtap_dispatch_cb, (u_char *) cf);
    wtap_close(cf->wth);
    cf->wth = NULL;
#else
    pcap_loop(cf->pfh, 0, pcap_dispatch_cb, (u_char *) cf);
    pcap_close(cf->pfh);
    cf->pfh = NULL;
#endif
    cf->plist = g_list_first(cf->plist);
    cf->fh = fopen(fname, "r");
    gtk_clist_thaw(GTK_CLIST(packet_list));
  }
  
  gtk_timeout_remove(timeout);
  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar), 0);

  gtk_statusbar_pop(GTK_STATUSBAR(info_bar), file_ctx);

  if (err == 0) {
    msg_len = strlen(name_ptr) + strlen(done_fmt) + 64;
    load_msg = g_realloc(load_msg, msg_len);
    snprintf(load_msg, msg_len, done_fmt, name_ptr, cf->drops);
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
    g_free(load_msg);

    name_ptr[-1] = '\0';
    set_menu_sensitivity("<Main>/File/Close", TRUE);
    set_menu_sensitivity("<Main>/File/Reload", TRUE);
  } else {
    msg_len = strlen(name_ptr) + strlen(err_fmt) + 2;
    load_msg = g_realloc(load_msg, msg_len);
    snprintf(load_msg, msg_len, err_fmt, name_ptr);
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
    g_free(load_msg);
    set_menu_sensitivity("<Main>/File/Close", FALSE);
    set_menu_sensitivity("<Main>/File/Reload", FALSE);
  }

  return err;
}

static void
#ifdef WITH_WIRETAP
wtap_dispatch_cb(u_char *user, const struct wtap_pkthdr *phdr, int offset,
#else
pcap_dispatch_cb(u_char *user, const struct pcap_pkthdr *phdr,
#endif
  const u_char *buf) {
  frame_data   *fdata;
  gint          i, row;
  capture_file *cf = (capture_file *) user;
  guint32 tssecs, tsusecs;
  
  while (gtk_events_pending())
    gtk_main_iteration();

  fdata   = cf->plist->data;
  cf->cur = fdata;
  cf->count++;

  fdata->pkt_len  = phdr->len;
  fdata->cap_len  = phdr->caplen;
#ifdef WITH_WIRETAP
  fdata->file_off = offset;
#else
  fdata->file_off = ftell(cf->fh) - phdr->caplen;
#endif
  fdata->secs     = phdr->ts.tv_sec;
  fdata->usecs    = phdr->ts.tv_usec;

  /* If we don't have the time stamp of the first packet, it's because this
     is the first packet.  Save the time stamp of this packet as the time
     stamp of the first packet. */
  if (!ssec && !susec) {
    ssec  = fdata->secs;
    susec = fdata->usecs;
  }

  /* Do the same for the time stamp of the previous packet. */
  if (!lastsec && !lastusec) {
    lastsec  = fdata->secs;
    lastusec = fdata->usecs;
  }

  /* Get the time elapsed between the first packet and this packet. */
  cf->esec = fdata->secs - ssec;
  if (susec <= fdata->usecs) {
    cf->eusec = fdata->usecs - susec;
  } else {
    cf->eusec = (fdata->usecs + 1000000) - susec;
    cf->esec--;
  }

  /* Compute the time stamp. */
  switch (timestamp_type) {
    case RELATIVE:	/* Relative to the first packet */
      tssecs = cf->esec;
      tsusecs = cf->eusec;
      break;
    case DELTA:		/* Relative to the previous packet */
      tssecs = fdata->secs - lastsec;
      if (lastusec <= fdata->usecs) {
	tsusecs = fdata->usecs - lastusec;
      } else {
	tsusecs = (fdata->usecs + 1000000) - lastusec;
	tssecs--;
      }
      break;
    default:		/* Absolute time, or bogus timestamp_type value */
      tssecs = 0;	/* Not used */
      tsusecs = 0;
      break;
  }
  fdata->cinfo = &cf->cinfo;
  for (i = 0; i < fdata->cinfo->num_cols; i++) {
    fdata->cinfo->col_data[i][0] = '\0';
  }
  if (check_col(fdata, COL_NUMBER))
    col_add_fstr(fdata, COL_NUMBER, "%d", cf->count);
  dissect_packet(buf, tssecs, tsusecs, fdata, NULL);
  row = gtk_clist_append(GTK_CLIST(packet_list), fdata->cinfo->col_data);
  fdata->cinfo = NULL;

  /* Make sure we always have an available list entry */
  if (cf->plist->next == NULL) {
    fdata = (frame_data *) g_malloc(sizeof(frame_data));
    g_list_append(cf->plist, (gpointer) fdata);
  }
  cf->plist = cf->plist->next;
}

/* Uncomment when we handle snoop files again.

size_t
read_frame_header(capture_file *cf) {
  snoop_frame_hdr  shdr;
  pcap_frame_hdr   phdr;
  gint16           pkt_len, cap_len;
  guint32          secs, usecs;
  frame_data      *fdata;
  size_t           err;

  if ((cf->cd_t == CD_PCAP_BE) || (cf->cd_t == CD_PCAP_LE)) {
    err = fread((char *)&phdr, sizeof(pcap_frame_hdr), 1, cf->fh);
    if (!err) { return err; }
    fdata = (frame_data *) g_malloc(sizeof(frame_data));
    if (cf->swap) {
      pkt_len = SWAP32(phdr.pkt_len);
      cap_len = SWAP32(phdr.cap_len);
      secs    = SWAP32(phdr.tm.tv_sec);
      usecs   = SWAP32(phdr.tm.tv_usec);
    } else {
      pkt_len = phdr.pkt_len;
      cap_len = phdr.cap_len;
      secs    = phdr.tm.tv_sec;
      usecs   = phdr.tm.tv_usec;
    }
  } else if (cf->cd_t == CD_SNOOP) {
    err = fread(&shdr, sizeof(snoop_frame_hdr), 1, cf->fh);
    fdata = (frame_data *) g_malloc(sizeof(frame_data));
    if (!err) { return err; }
    pkt_len = ntohl(shdr.inc_len);
    cap_len = ntohl(shdr.pr_len) - 24;
    secs    = ntohl(shdr.secs);
    usecs   = ntohl(shdr.usecs);
    shdr.drops  = ntohl(shdr.drops);
    if (!ssec && !susec) { ssec = secs; susec = usecs; }
    cf->drops = shdr.drops;
    cf->esec = secs - ssec;
    if (susec < shdr.usecs) {
      cf->eusec = usecs - susec;
    } else {
      cf->eusec = susec - usecs;
      cf->esec--;
    }
  }
  cf->cur = fdata;
  fdata->pkt_len = pkt_len;
  fdata->cap_len = cap_len;
  fdata->secs    = secs;
  fdata->usecs   = usecs;
  g_list_append(cf->plist, (gpointer) fdata);
  if (!ssec && !susec) {
    ssec  = secs;
    susec = usecs;
  }
  cf->esec = secs - ssec;
  if (susec < usecs) {
    cf->eusec = usecs - susec;
  } else {
    cf->eusec = susec - usecs;
    cf->esec--;
  }
  return err;
}
*/
