/* file.c
 * File I/O routines
 *
 * $Id: file.c,v 1.66 1999/08/14 04:23:21 guy Exp $
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

#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include "ethereal.h"
#include "column.h"
#include "menu.h"
#include "packet.h"
#include "print.h"
#include "file.h"
#include "util.h"
#include "gtkpacket.h"
#include "dfilter.h"
#include "timestamp.h"

#include "packet-ncp.h"

extern GtkWidget *packet_list, *prog_bar, *info_bar, *byte_view, *tree_view;
extern guint      file_ctx;
extern int	  sync_mode;
extern int        sync_pipe[];

guint cap_input_id;

static guint32 firstsec, firstusec;
static guint32 prevsec, prevusec;

static dfilter *rfcode = NULL; 

static void wtap_dispatch_cb(u_char *, const struct wtap_pkthdr *, int,
    const u_char *);

static void freeze_clist(capture_file *cf);
static void thaw_clist(capture_file *cf);

static gint dfilter_progress_cb(gpointer p);

int
open_cap_file(char *fname, capture_file *cf) {
  struct stat cf_stat;

  /* First, make sure the file is valid */
  if (stat(fname, &cf_stat))
    return (errno);
#ifndef WIN32
  if (! S_ISREG(cf_stat.st_mode) && ! S_ISFIFO(cf_stat.st_mode))
    return (OPEN_CAP_FILE_NOT_REGULAR);
#endif

  /* Next, try to open the file */
  cf->fh = fopen(fname, "r");
  if (cf->fh == NULL)
    return (errno);

  fseek(cf->fh, 0L, SEEK_END);
  cf->f_len = ftell(cf->fh);
  fclose(cf->fh);
  cf->fh = NULL;
  /* set the file name beacuse we need it to set the follow stream filter */
  cf->filename = g_strdup( fname );

  /* Next, find out what type of file we're dealing with */
  cf->cd_t      = WTAP_FILE_UNKNOWN;
  cf->cd_t_desc = "unknown";
  cf->count     = 0;
  cf->drops     = 0;
  cf->esec      = 0;
  cf->eusec     = 0;
  cf->snap      = 0;
  firstsec = 0, firstusec = 0;
  prevsec = 0, prevusec = 0;
 
  cf->wth = wtap_open_offline(fname);
  if (cf->wth == NULL) {

    /* XXX - we assume that, because we were able to open it above,
       this must have failed because it's not a capture file in
       a format we can read. */
    return (OPEN_CAP_FILE_UNKNOWN_FORMAT);
  }

  cf->fh = wtap_file(cf->wth);
  cf->cd_t = wtap_file_type(cf->wth);
  cf->cd_t_desc = wtap_file_type_string(cf->wth);
  cf->snap = wtap_snapshot_length(cf->wth);
  return (0);
}

/* Reset everything to a pristine state */
void
close_cap_file(capture_file *cf, void *w, guint context) {
  frame_data *fd, *fd_next;

  if (cf->fh) {
    fclose(cf->fh);
    cf->fh = NULL;
  }
  if (cf->wth) {
    wtap_close(cf->wth);
    cf->wth = NULL;
  }
  for (fd = cf->plist; fd != NULL; fd = fd_next) {
    fd_next = fd->next;
    g_free(fd);
  }
  cf->plist = NULL;
  cf->plist_end = NULL;
  unselect_packet(cf);	/* nothing to select */

  gtk_clist_freeze(GTK_CLIST(packet_list));
  gtk_clist_clear(GTK_CLIST(packet_list));
  gtk_clist_thaw(GTK_CLIST(packet_list));
  gtk_statusbar_pop(GTK_STATUSBAR(w), context);

  /* Disable all menu items that make sense only if you have a capture. */
  set_menu_sensitivity("/File/Save", FALSE);
  set_menu_sensitivity("/File/Save As...", FALSE);
  set_menu_sensitivity("/File/Close", FALSE);
  set_menu_sensitivity("/File/Reload", FALSE);
  set_menu_sensitivity("/File/Print...", FALSE);
  set_menu_sensitivity("/Display/Options...", FALSE);
  set_menu_sensitivity("/Tools/Summary", FALSE);
}

int
load_cap_file(char *fname, char *rfilter, capture_file *cf) {
  gchar  *name_ptr, *load_msg, *load_fmt = " Loading: %s...";
  gchar  *done_fmt = " File: %s  Drops: %d";
  gchar  *err_fmt  = " Error: Could not load '%s'";
  gint    timeout;
  size_t  msg_len;
  int     err;

  close_cap_file(cf, info_bar, file_ctx);

  /* Initialize protocol-specific variables */
  ncp_init_protocol();

  if ((name_ptr = (gchar *) strrchr(fname, '/')) == NULL)
    name_ptr = fname;
  else
    name_ptr++;

  if (rfilter) {
    rfcode = dfilter_new();
    if (dfilter_compile(rfcode, rfilter) != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
        "Unable to parse filter string \"%s\".", rfilter);
      goto fail;
    }
  }

  err = open_cap_file(fname, cf);
  if (err != 0) {
    simple_dialog(ESD_TYPE_WARN, NULL,
			file_open_error_message(err, FALSE), fname);
    goto fail;
  }

  load_msg = g_malloc(strlen(name_ptr) + strlen(load_fmt) + 2);
  sprintf(load_msg, load_fmt, name_ptr);
  gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
  
  timeout = gtk_timeout_add(250, file_progress_cb, (gpointer) cf);

  freeze_clist(cf);
  wtap_loop(cf->wth, 0, wtap_dispatch_cb, (u_char *) cf);
  wtap_close(cf->wth);
  cf->wth = NULL;
  cf->fh = fopen(fname, "r");
  thaw_clist(cf);
  
  gtk_timeout_remove(timeout);
  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar), 0);

  gtk_statusbar_pop(GTK_STATUSBAR(info_bar), file_ctx);

  msg_len = strlen(name_ptr) + strlen(done_fmt) + 64;
  load_msg = g_realloc(load_msg, msg_len);

  if (cf->user_saved || !cf->save_file)
    snprintf(load_msg, msg_len, done_fmt, name_ptr, cf->drops);
  else
    snprintf(load_msg, msg_len, done_fmt, "<none>", cf->drops);

  gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
  g_free(load_msg);

/*  name_ptr[-1] = '\0';  Why is this here? It causes problems with capture files */

  /* Remember the new read filter string. */
  if (cf->rfilter != NULL)
    g_free(cf->rfilter);
  cf->rfilter = rfilter;

  /* Enable menu items that make sense if you have a capture. */
  set_menu_sensitivity("/File/Close", TRUE);
  set_menu_sensitivity("/File/Reload", TRUE);
  set_menu_sensitivity("/File/Print...", TRUE);
  set_menu_sensitivity("/Display/Options...", TRUE);
  set_menu_sensitivity("/Tools/Summary", TRUE);
  return 0;

fail:
  msg_len = strlen(name_ptr) + strlen(err_fmt) + 2;
  load_msg = g_malloc(msg_len);
  snprintf(load_msg, msg_len, err_fmt, name_ptr);
  gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
  g_free(load_msg);
  if (rfilter != NULL)
    g_free(rfilter);	/* assumed to be "g_strdup()"ed, if not null */
  return -1;
}

#ifdef HAVE_LIBPCAP
void 
cap_file_input_cb (gpointer data, gint source, GdkInputCondition condition) {
  
  capture_file *cf = (capture_file *)data;
  char buffer[256], *p = buffer, *q = buffer;
  int  nread;
  int  to_read = 0;
  gboolean exit_loop = FALSE;

  /* avoid reentrancy problems and stack overflow */
  gtk_input_remove(cap_input_id);

  if ((nread = read(sync_pipe[0], buffer, 256)) <= 0) {

    /* The child has closed the sync pipe, meaning it's not going to be
       capturing any more packets.  Read what remains of the capture file,
       and stop capture (restore menu items) */
    gtk_clist_freeze(GTK_CLIST(packet_list));

    wtap_loop(cf->wth, 0, wtap_dispatch_cb, (u_char *) cf);      

    thaw_clist(cf);

    wtap_close(cf->wth);
    cf->wth = NULL;
    set_menu_sensitivity("/File/Open...", TRUE);
    set_menu_sensitivity("/File/Close", TRUE);
    set_menu_sensitivity("/File/Save As...", TRUE);
    set_menu_sensitivity("/File/Print...", TRUE);
    set_menu_sensitivity("/File/Reload", TRUE);
#ifdef HAVE_LIBPCAP
    set_menu_sensitivity("/Capture/Start...", TRUE);
#endif
    set_menu_sensitivity("/Tools/Summary", TRUE);
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, " File: <none>");
    return;
  }

  buffer[nread] = '\0';

  while(!exit_loop) {
    /* look for (possibly multiple) '*' */
    switch (*q) {
    case '*' :
      to_read += atoi(p);
      p = q + 1; 
      q++;
      break;
    case '\0' :
      /* XXX should handle the case of a pipe full (i.e. no star found) */
      exit_loop = TRUE;
      break;
    default :
      q++;
      break;
    } 
  }

  gtk_clist_freeze(GTK_CLIST(packet_list));
  wtap_loop(cf->wth, to_read, wtap_dispatch_cb, (u_char *) cf);      
  gtk_clist_thaw(GTK_CLIST(packet_list));

  /* restore pipe handler */
  cap_input_id = gtk_input_add_full (sync_pipe[0],
				     GDK_INPUT_READ,
				     cap_file_input_cb,
				     NULL,
				     (gpointer) cf,
				     NULL);
}

int
tail_cap_file(char *fname, capture_file *cf) {
  int     err;
  int     i;

  close_cap_file(cf, info_bar, file_ctx);

  /* Initialize protocol-specific variables */
  ncp_init_protocol();

  err = open_cap_file(fname, cf);
  if ((err == 0) && (cf->cd_t != WTAP_FILE_UNKNOWN)) {

    set_menu_sensitivity("/File/Open...", FALSE);
    set_menu_sensitivity("/Display/Options...", TRUE);
#ifdef HAVE_LIBPCAP
    set_menu_sensitivity("/Capture/Start...", FALSE);
#endif

    for (i = 0; i < cf->cinfo.num_cols; i++) {
      if (get_column_resize_type(cf->cinfo.col_fmt[i]) == RESIZE_LIVE)
        gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, TRUE);
      else {
        gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, FALSE);
        gtk_clist_set_column_width(GTK_CLIST(packet_list), i,
				cf->cinfo.col_width[i]);
        gtk_clist_set_column_resizeable(GTK_CLIST(packet_list), i, TRUE);
      }
    }

    cf->fh = fopen(fname, "r");

    cap_input_id = gtk_input_add_full (sync_pipe[0],
				       GDK_INPUT_READ,
				       cap_file_input_cb,
				       NULL,
				       (gpointer) cf,
				       NULL);
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, 
		       " <live capture in progress>");
  }
  else {
    close(sync_pipe[0]);
  }
  return err;
}
#endif

/* To do: Add check_col checks to the col_add* routines */

static void
col_add_abs_time(frame_data *fd, gint el)
{
  struct tm *tmp;
  time_t then;

  then = fd->abs_secs;
  tmp = localtime(&then);
  col_add_fstr(fd, el, "%02d:%02d:%02d.%04ld",
    tmp->tm_hour,
    tmp->tm_min,
    tmp->tm_sec,
    (long)fd->abs_usecs/100);
}

static void
col_add_rel_time(frame_data *fd, gint el)
{
  col_add_fstr(fd, el, "%d.%06d", fd->rel_secs, fd->rel_usecs);
}

static void
col_add_delta_time(frame_data *fd, gint el)
{
  col_add_fstr(fd, el, "%d.%06d", fd->del_secs, fd->del_usecs);
}

/* Add "command-line-specified" time. */
static void
col_add_cls_time(frame_data *fd)
{
  switch (timestamp_type) {
    case ABSOLUTE:
      col_add_abs_time(fd, COL_CLS_TIME);
      break;

    case RELATIVE:
      col_add_rel_time(fd, COL_CLS_TIME);
      break;

    case DELTA:
      col_add_delta_time(fd, COL_CLS_TIME);
      break;
  }
}

static void
add_packet_to_packet_list(frame_data *fdata, capture_file *cf, const u_char *buf)
{
  gint          i, row;
  proto_tree   *protocol_tree;

  /* If we don't have the time stamp of the first packet in the
     capture, it's because this is the first packet.  Save the time
     stamp of this packet as the time stamp of the first packet. */
  if (!firstsec && !firstusec) {
    firstsec  = fdata->abs_secs;
    firstusec = fdata->abs_usecs;
  }

  /* Get the time elapsed between the first packet and this packet. */
  cf->esec = fdata->abs_secs - firstsec;
  if (firstusec <= fdata->abs_usecs) {
    cf->eusec = fdata->abs_usecs - firstusec;
  } else {
    cf->eusec = (fdata->abs_usecs + 1000000) - firstusec;
    cf->esec--;
  }

  fdata->cinfo = &cf->cinfo;
  for (i = 0; i < fdata->cinfo->num_cols; i++) {
    fdata->cinfo->col_data[i][0] = '\0';
  }

  /* Apply the display filter */
  if (DFILTER_CONTAINS_FILTER(cf->dfcode)) {
	protocol_tree = proto_tree_create_root();
	dissect_packet(buf, fdata, protocol_tree);
	fdata->passed_dfilter = dfilter_apply(cf->dfcode, protocol_tree, cf->pd);
	proto_tree_free(protocol_tree);
  }
  else {
	dissect_packet(buf, fdata, NULL);
	fdata->passed_dfilter = TRUE;
  }
  if (fdata->passed_dfilter) {
    if (check_col(fdata, COL_NUMBER))
      col_add_fstr(fdata, COL_NUMBER, "%d", cf->count);

    /* If we don't have the time stamp of the previous displayed packet,
       it's because this is the first displayed packet.  Save the time
       stamp of this packet as the time stamp of the previous displayed
       packet. */
    if (!prevsec && !prevusec) {
      prevsec  = fdata->abs_secs;
      prevusec = fdata->abs_usecs;
    }

    /* Get the time elapsed between the first packet and this packet. */
    fdata->rel_secs = cf->esec;
    fdata->rel_usecs = cf->eusec;
  
    /* Get the time elapsed between the previous displayed packet and
       this packet. */
    fdata->del_secs = fdata->abs_secs - prevsec;
    if (prevusec <= fdata->abs_usecs) {
      fdata->del_usecs = fdata->abs_usecs - prevusec;
    } else {
      fdata->del_usecs = (fdata->abs_usecs + 1000000) - prevusec;
      fdata->del_secs--;
    }
    prevsec = fdata->abs_secs;
    prevusec = fdata->abs_usecs;

    /* Set any time stamp columns. */
    if (check_col(fdata, COL_CLS_TIME))
      col_add_cls_time(fdata);
    if (check_col(fdata, COL_ABS_TIME))
      col_add_abs_time(fdata, COL_ABS_TIME);
    if (check_col(fdata, COL_REL_TIME))
      col_add_rel_time(fdata, COL_REL_TIME);
    if (check_col(fdata, COL_DELTA_TIME))
      col_add_delta_time(fdata, COL_DELTA_TIME);

    if (check_col(fdata, COL_PACKET_LENGTH))
      col_add_fstr(fdata, COL_PACKET_LENGTH, "%d", fdata->pkt_len);

    row = gtk_clist_append(GTK_CLIST(packet_list), fdata->cinfo->col_data);
    fdata->row = row;

    /* If this was the selected packet, remember the row it's in, so
       we can re-select it.  ("selected_packet" is 0-origin, as it's
       a GList index; "count", however, is 1-origin.) */
    if (cf->selected_packet == cf->count - 1)
      cf->selected_row = row;
  } else
    fdata->row = -1;	/* not in the display */
  fdata->cinfo = NULL;
}

static void
wtap_dispatch_cb(u_char *user, const struct wtap_pkthdr *phdr, int offset,
  const u_char *buf) {
  frame_data   *fdata;
  capture_file *cf = (capture_file *) user;
  int           passed;
  proto_tree   *protocol_tree;
  frame_data   *plist_end;

  while (gtk_events_pending())
    gtk_main_iteration();

  /* Allocate the next list entry, and add it to the list. */
  fdata = (frame_data *) g_malloc(sizeof(frame_data));

  fdata->next = NULL;
  fdata->pkt_len  = phdr->len;
  fdata->cap_len  = phdr->caplen;
  fdata->file_off = offset;
  fdata->lnk_t = phdr->pkt_encap;
  fdata->abs_secs  = phdr->ts.tv_sec;
  fdata->abs_usecs = phdr->ts.tv_usec;
  fdata->flags = phdr->flags;
  fdata->cinfo = NULL;

  passed = TRUE;
  if (rfcode) {
    protocol_tree = proto_tree_create_root();
    dissect_packet(buf, fdata, protocol_tree);
    passed = dfilter_apply(rfcode, protocol_tree, cf->pd);
    proto_tree_free(protocol_tree);
  }
  if (passed) {
    plist_end = cf->plist_end;
    if (plist_end != NULL)
      plist_end->next = fdata;
    else
      cf->plist = fdata;
    cf->plist_end = fdata;

    cf->count++;
    add_packet_to_packet_list(fdata, cf, buf);
  } else
    g_free(fdata);
}

void
filter_packets(capture_file *cf)
{
/*  gint timeout;*/
  frame_data *fd;

  if (cf->dfilter == NULL) {
	dfilter_clear_filter(cf->dfcode);
  }
  else {
    /*
     * Compile the filter.
     */
    if (dfilter_compile(cf->dfcode, cf->dfilter) != 0) {
      simple_dialog(ESD_TYPE_WARN, NULL,
      "Unable to parse filter string \"%s\".", cf->dfilter);
      return;
    }
  }

  /* Freeze the packet list while we redo it, so we don't get any
     screen updates while it happens. */
  gtk_clist_freeze(GTK_CLIST(packet_list));

  /* Clear it out. */
  gtk_clist_clear(GTK_CLIST(packet_list));

  /* If a packet was selected, we don't know yet what row, if any, it'll
     get. */
  cf->selected_row = -1;

  /* Iterate through the list of packets, calling a routine
     to run the filter on the packet, see if it matches, and
     put it in the display list if so.  */
  firstsec = 0;
  firstusec = 0;
  prevsec = 0;
  prevusec = 0;
  cf->unfiltered_count = cf->count;
  cf->count = 0;

/*  timeout = gtk_timeout_add(250, dfilter_progress_cb, cf);*/
  for (fd = cf->plist; fd != NULL; fd = fd->next) {
    cf->count++;

    fseek(cf->fh, fd->file_off, SEEK_SET);
    fread(cf->pd, sizeof(guint8), fd->cap_len, cf->fh);

    add_packet_to_packet_list(fd, cf, cf->pd);

    if (cf->count % 20 == 0) {
      dfilter_progress_cb(cf);
    }
  }
/*  gtk_timeout_remove(timeout);*/
 
  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar), 0);

  if (cf->selected_row != -1) {
    /* We had a selected packet and it passed the filter. */
    gtk_clist_select_row(GTK_CLIST(packet_list), cf->selected_row, -1);
  } else {
    /* If we had one, it didn't pass the filter. */
    unselect_packet(cf);
  }

  /* Unfreeze the packet list. */
  gtk_clist_thaw(GTK_CLIST(packet_list));
}

/* Update the progress bar */
static gint
dfilter_progress_cb(gpointer p) {
  capture_file *cf = (capture_file*)p;

  /* let's not divide by zero. I should never be started
   * with unfiltered_count == 0, so let's assert that
   */
  g_assert(cf->unfiltered_count > 0);

  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar),
    (gfloat) cf->count / cf->unfiltered_count);

  /* Have GTK+ repaint what is pending */
  while (gtk_events_pending ()) {
	  gtk_main_iteration();
  }
  return TRUE;
}


int
print_packets(capture_file *cf, int to_file, const char *dest)
{
  frame_data *fd;
  proto_tree *protocol_tree;

  cf->print_fh = open_print_dest(to_file, dest);
  if (cf->print_fh == NULL)
    return FALSE;	/* attempt to open destination failed */

  /* XXX - printing multiple frames in PostScript looks as if it's
     tricky - you have to deal with page boundaries, I think -
     and I'll have to spend some time learning enough about
     PostScript to figure it out, so, for now, we only print
     multiple frames as text. */
#if 0
  print_preamble(cf->print_fh);
#endif

  /* Iterate through the list of packets, printing each of them.  */
  cf->count = 0;
  for (fd = cf->plist; fd != NULL; fd = fd->next) {
    cf->count++;

    fseek(cf->fh, fd->file_off, SEEK_SET);
    fread(cf->pd, sizeof(guint8), fd->cap_len, cf->fh);

    /* create the logical protocol tree */
    protocol_tree = proto_tree_create_root();
    dissect_packet(cf->pd, fd, protocol_tree);

    /* Print the packet */
    proto_tree_print(cf->count, (GNode *)protocol_tree, cf->pd, fd, cf->print_fh);

    proto_tree_free(protocol_tree);
  }

#if 0
  print_finale(cf->print_fh);
#endif

  close_print_dest(to_file, cf->print_fh);
  cf->print_fh = NULL;
  return TRUE;
}

/* Scan through the packet list and change all columns that use the
   "command-line-specified" time stamp format to use the current
   value of that format. */
void
change_time_formats(capture_file *cf)
{
  frame_data *fd;
  int i;
  GtkStyle  *pl_style;

  /* Freeze the packet list while we redo it, so we don't get any
     screen updates while it happens. */
  freeze_clist(cf);

  /* Iterate through the list of packets, checking whether the packet
     is in a row of the summary list and, if so, whether there are
     any columns that show the time in the "command-line-specified"
     format and, if so, update that row. */
  for (fd = cf->plist; fd != NULL; fd = fd->next) {
    if (fd->row != -1) {
      /* This packet is in the summary list, on row "fd->row". */

      /* XXX - there really should be a way of checking "cf->cinfo" for this;
         the answer isn't going to change from packet to packet, so we should
         simply skip all the "change_time_formats()" work if we're not
         changing anything. */
      fd->cinfo = &cf->cinfo;
      if (check_col(fd, COL_CLS_TIME)) {
        /* There are columns that show the time in the "command-line-specified"
           format; update them. */
        for (i = 0; i < cf->cinfo.num_cols; i++) {
          cf->cinfo.col_data[i][0] = '\0';
        }
        col_add_cls_time(fd);
        for (i = 0; i < cf->cinfo.num_cols; i++) {
          if (cf->cinfo.fmt_matx[i][COL_CLS_TIME]) {
            /* This is one of the columns that shows the time in
               "command-line-specified" format; update it. */
            gtk_clist_set_text(GTK_CLIST(packet_list), fd->row, i,
			  cf->cinfo.col_data[i]);
	  }
        }
      }
    }
  }

  /* Set the column widths of those columns that show the time in
     "command-line-specified" format. */
  pl_style = gtk_widget_get_style(packet_list);
  for (i = 0; i < cf->cinfo.num_cols; i++) {
    if (cf->cinfo.fmt_matx[i][COL_CLS_TIME]) {
      gtk_clist_set_column_width(GTK_CLIST(packet_list), i,
        get_column_width(COL_CLS_TIME, pl_style->font));
    }
  }

  /* Unfreeze the packet list. */
  thaw_clist(cf);
}

static void
clear_tree_and_hex_views(void)
{
  /* Clear the hex dump. */
  gtk_text_freeze(GTK_TEXT(byte_view));
  gtk_text_set_point(GTK_TEXT(byte_view), 0);
  gtk_text_forward_delete(GTK_TEXT(byte_view),
    gtk_text_get_length(GTK_TEXT(byte_view)));
  gtk_text_thaw(GTK_TEXT(byte_view));

  /* Clear the protocol tree view. */
  gtk_tree_clear_items(GTK_TREE(tree_view), 0,
    g_list_length(GTK_TREE(tree_view)->children));
}

/* Select the packet on a given row. */
void
select_packet(capture_file *cf, int row)
{
  frame_data *fd;
  int i;

  /* Clear out whatever's currently in the hex dump. */
  gtk_text_freeze(GTK_TEXT(byte_view));
  gtk_text_set_point(GTK_TEXT(byte_view), 0);
  gtk_text_forward_delete(GTK_TEXT(byte_view),
    gtk_text_get_length(GTK_TEXT(byte_view)));

  /* Search through the list of frames to see which one is in
     this row. */
  for (fd = cf->plist, i = 0; fd != NULL; fd = fd->next, i++) {
    if (fd->row == row)
      break;
  }
  cf->fd = fd;

  /* Remember the ordinal number of that frame. */
  cf->selected_packet = i;

  /* Get the data in that frame. */
  fseek(cf->fh, cf->fd->file_off, SEEK_SET);
  fread(cf->pd, sizeof(guint8), cf->fd->cap_len, cf->fh);

  /* Create the logical protocol tree. */
  if (cf->protocol_tree)
      proto_tree_free(cf->protocol_tree);
  cf->protocol_tree = proto_tree_create_root();
  dissect_packet(cf->pd, cf->fd, cf->protocol_tree);

  /* Display the GUI protocol tree and hex dump. */
  clear_tree_and_hex_views();
  proto_tree_draw(cf->protocol_tree, tree_view);
  packet_hex_print(GTK_TEXT(byte_view), cf->pd, cf->fd->cap_len, -1, -1);
  gtk_text_thaw(GTK_TEXT(byte_view));

  /* A packet is selected, so "File/Print Packet" has something to print. */
  set_menu_sensitivity("/File/Print Packet", TRUE);
}

/* Unselect the selected packet, if any. */
void
unselect_packet(capture_file *cf)
{
  cf->selected_packet = -1;	/* nothing there to be selected */
  cf->selected_row = -1;

  /* Destroy the protocol tree for that packet. */
  if (cf->protocol_tree != NULL) {
    proto_tree_free(cf->protocol_tree);
    cf->protocol_tree = NULL;
  }

  /* Clear out the display of that packet. */
  clear_tree_and_hex_views();

  /* No packet is selected, so "File/Print Packet" has nothing to print. */
  set_menu_sensitivity("/File/Print Packet", FALSE);
}

static void
freeze_clist(capture_file *cf)
{
  int i;

  /* Make the column sizes static, so they don't adjust while
     we're reading the capture file (freezing the clist doesn't
     seem to suffice). */
  for (i = 0; i < cf->cinfo.num_cols; i++)
    gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, FALSE);
  gtk_clist_freeze(GTK_CLIST(packet_list));
}

static void
thaw_clist(capture_file *cf)
{
  int i;

  for (i = 0; i < cf->cinfo.num_cols; i++) {
    if (get_column_resize_type(cf->cinfo.col_fmt[i]) == RESIZE_MANUAL) {
      /* Set this column's width to the appropriate value. */
      gtk_clist_set_column_width(GTK_CLIST(packet_list), i,
				cf->cinfo.col_width[i]);
    } else {
      /* Make this column's size dynamic, so that it adjusts to the
         appropriate size. */
      gtk_clist_set_column_auto_resize(GTK_CLIST(packet_list), i, TRUE);
    }
  }
  gtk_clist_thaw(GTK_CLIST(packet_list));

  /* Hopefully, the columns have now gotten their appropriate sizes;
     make them resizeable - a column that auto-resizes cannot be
     resized by the user, and *vice versa*. */
  for (i = 0; i < cf->cinfo.num_cols; i++)
    gtk_clist_set_column_resizeable(GTK_CLIST(packet_list), i, TRUE);
}

/* Tries to mv a file. If unsuccessful, tries to cp the file.
 * Returns 0 on failure to do either, 1 on success of either
 */
int
file_mv(char *from, char *to)
{

#define COPY_BUFFER_SIZE	8192

	int retval;

#ifndef WIN32
	/* try a hard link */
	retval = link(from, to);

	/* or try a copy */
	if (retval < 0) {
#endif
		retval = file_cp(from, to);
		if (!retval) {
			return 0;
		}
#ifndef WIN32
	}
#endif

	unlink(from);
	return 1;
}

/* Copies a file.
 * Returns 0 on failure to do either, 1 on success of either
 */
int
file_cp(char *from, char *to)
{

#define COPY_BUFFER_SIZE	8192

	int from_fd, to_fd, nread, nwritten;
	char *buffer;

	buffer = g_malloc(COPY_BUFFER_SIZE);

	from_fd = open(from, O_RDONLY);
	if (from_fd < 0) {
		simple_dialog(ESD_TYPE_WARN, NULL,
			file_open_error_message(errno, TRUE), from);
		return 0;
	}

	to_fd = creat(to, 0644);
	if (to_fd < 0) {
		simple_dialog(ESD_TYPE_WARN, NULL,
			file_open_error_message(errno, TRUE), to);
		close(from_fd);
		return 0;
	}

	while( (nread = read(from_fd, buffer, COPY_BUFFER_SIZE)) > 0) {
		nwritten = write(to_fd, buffer, nread);
		if (nwritten < nread) {
			if (nwritten < 0) {
				simple_dialog(ESD_TYPE_WARN, NULL,
					file_write_error_message(errno), to);
			} else {
				simple_dialog(ESD_TYPE_WARN, NULL,
"The file \"%s\" could not be saved: tried writing %d, wrote %d.\n",
					to, nread, nwritten);
			}
			close(from_fd);
			close(to_fd);
			return 0;
		}
	}
	if (nread < 0) {
		simple_dialog(ESD_TYPE_WARN, NULL,
			file_read_error_message(errno), from);
		close(from_fd);
		close(to_fd);
		return 0;
	}
	close(from_fd);
	close(to_fd);

	return 1;
}

char *
file_open_error_message(int err, int for_writing)
{
  char *errmsg;
  static char errmsg_errno[1024+1];

  switch (err) {

  case OPEN_CAP_FILE_NOT_REGULAR:
    errmsg = "The file \"%s\" is invalid.";
    break;

  case OPEN_CAP_FILE_UNKNOWN_FORMAT:
    errmsg = "The file \"%s\" is not a capture file in a format Ethereal understands.";
    break;

  case ENOENT:
    if (for_writing)
      errmsg = "The path to the file \"%s\" does not exist.";
    else
      errmsg = "The file \"%s\" does not exist.";
    break;

  case EACCES:
    if (for_writing)
      errmsg = "You do not have permission to create or write to the file \"%s\".";
    else
      errmsg = "You do not have permission to open the file \"%s\".";
    break;

  default:
    sprintf(errmsg_errno, "The file \"%%s\" could not be opened: %s.", strerror(err));
    errmsg = errmsg_errno;
    break;
  }
  return errmsg;
}

char *
file_read_error_message(int err)
{
  static char errmsg_errno[1024+1];

  sprintf(errmsg_errno, "An error occurred while reading from the file \"%%s\": %s.", strerror(err));
  return errmsg_errno;
}

char *
file_write_error_message(int err)
{
  char *errmsg;
  static char errmsg_errno[1024+1];

  switch (err) {

  case ENOSPC:
    errmsg = "The file \"%s\" could not be saved because there is no space left on the file system.";
    break;

#ifdef EDQUOT
  case EDQUOT:
    errmsg = "The file \"%s\" could not be saved because you are too close to, or over, your disk quota.";
    break;
#endif

  default:
    sprintf(errmsg_errno, "An error occurred while writing to the file \"%%s\": %s.", strerror(err));
    errmsg = errmsg_errno;
    break;
  }
  return errmsg;
}
