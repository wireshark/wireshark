/* file.c
 * File I/O routines
 *
 * $Id: file.c,v 1.2 1998/09/16 03:21:57 gerald Exp $
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
#include <pcap.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif


#include "packet.h"
#include "file.h"
#include "ethereal.h"
#include "util.h"

extern GtkWidget *packet_list, *prog_bar, *info_bar, *byte_view, *tree_view;
extern guint      file_ctx;

guint32 ssec, susec;

int
open_cap_file(char *fname, capture_file *cf) {
  guint32     magic[2];
  char        err_str[PCAP_ERRBUF_SIZE];
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
  fseek(cf->fh, 0L, SEEK_SET);
  fread(magic, sizeof(guint32), 2, cf->fh);
  fseek(cf->fh, 0L, SEEK_SET);
  fclose(cf->fh);
  cf->fh = NULL;

  /* Next, find out what type of file we're dealing with */
  
  cf->cd_t  = CD_UNKNOWN;
  cf->lnk_t = DLT_NULL;
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
  
  if (magic[0] == PCAP_MAGIC || magic[0] == SWAP32(PCAP_MAGIC)) {

    /* Pcap/Tcpdump file */
    cf->pfh = pcap_open_offline(fname, err_str);
    if (cf->pfh == NULL) {
      simple_dialog(ESD_TYPE_WARN, NULL, "Could not open file.");
      return 1;
    }

    if (cf->filter) {
      if (pcap_compile(cf->pfh, &cf->fcode, cf->filter, 1, 0) < 0) {
        simple_dialog(ESD_TYPE_WARN, NULL, "Unable to parse filter string.");
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
  return 0;
}

/* Reset everything to a pristine state */
void
close_cap_file(capture_file *cf, GtkWidget *w, guint context) {
  if (cf->fh) {
    fclose(cf->fh);
    cf->fh = NULL;
  }
  if (cf->pfh) {
    pcap_close(cf->pfh);
    cf->pfh = NULL;
  }
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
  gchar  *done_fmt = " File: %s  Packets: %d  Drops: %d  Elapsed: %d.%06ds";
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
  if ((err == 0) && (cf->cd_t != CD_UNKNOWN)) {
    gtk_clist_freeze(GTK_CLIST(packet_list));
    pcap_loop(cf->pfh, 0, pcap_dispatch_cb, (u_char *) cf);
    pcap_close(cf->pfh);
    cf->pfh = NULL;
    cf->plist = g_list_first(cf->plist);
    cf->fh = fopen(fname, "r");
    gtk_clist_thaw(GTK_CLIST(packet_list));
  }
  
  gtk_timeout_remove(timeout);
  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar), 0);

  gtk_statusbar_pop(GTK_STATUSBAR(info_bar), file_ctx);

  if (err == 0) {
    msg_len = strlen(name_ptr) + strlen(load_fmt) + 64;
    load_msg = g_realloc(load_msg, msg_len);
    snprintf(load_msg, msg_len, done_fmt, name_ptr, cf->count, cf->drops,
      cf->esec, cf->eusec);
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
    g_free(load_msg);

    name_ptr[-1] = '\0';
    set_menu_sensitivity("<Main>/File/Close", TRUE);
  } else {
    msg_len = strlen(name_ptr) + strlen(err_fmt) + 2;
    load_msg = g_realloc(load_msg, msg_len);
    snprintf(load_msg, msg_len, err_fmt, name_ptr);
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
    g_free(load_msg);
    set_menu_sensitivity("<Main>/File/Close", FALSE);
  }

  return err;
}

void
pcap_dispatch_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *buf) {
  frame_data   *fdata;
  /* To do: make sure this is big enough. */
  gchar         p_info[5][256];
  gint          i, row;
  capture_file *cf = (capture_file *) user;
  
  while (gtk_events_pending())
    gtk_main_iteration();

  fdata   = cf->plist->data;
  cf->cur = fdata;
  cf->count++;

  fdata->pkt_len  = phdr->len;
  fdata->cap_len  = phdr->caplen;
  fdata->file_off = ftell(cf->fh) - phdr->caplen;
  fdata->secs     = phdr->ts.tv_sec;
  fdata->usecs    = phdr->ts.tv_usec;

  for (i = 0; i < 5; i++) { fdata->win_info[i] = &p_info[i][0]; }
  sprintf(fdata->win_info[0], "%d", cf->count);
  dissect_packet(buf, fdata, NULL);
  row = gtk_clist_append(GTK_CLIST(packet_list), fdata->win_info);
  for (i = 0; i < 5; i++) { fdata->win_info[i] = NULL; }

  if (!ssec && !susec) {
    ssec  = fdata->secs;
    susec = fdata->usecs;
  }
  cf->esec = fdata->secs - ssec;
  if (susec < fdata->usecs) {
    cf->eusec = fdata->usecs - susec;
  } else {
    cf->eusec = susec - fdata->usecs;
    cf->esec--;
  }

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
