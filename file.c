/* file.c
 * File I/O routines
 *
 * $Id: file.c,v 1.34 1999/07/07 22:51:38 gram Exp $
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
#include "file.h"
#include "util.h"
#include "dfilter.h"

#include "packet-ncp.h"

#define TAIL_TIMEOUT	2000  /* msec */

extern GtkWidget *packet_list, *prog_bar, *info_bar, *byte_view, *tree_view;
extern GtkStyle  *pl_style;
extern guint      file_ctx;
extern int	  sync_mode;
extern int        sync_pipe[];

guint cap_input_id, tail_timeout_id;

static guint32 firstsec, firstusec;
static guint32 lastsec, lastusec;

/* Used when applying a display filter */
static proto_tree *dfilter_proto_tree = NULL;

static void wtap_dispatch_cb(u_char *, const struct wtap_pkthdr *, int,
    const u_char *);

static void init_col_widths(capture_file *);
static void set_col_widths(capture_file *);

static gint tail_timeout_cb(gpointer);

int
open_cap_file(char *fname, capture_file *cf) {
  struct stat cf_stat;

  /* First, make sure the file is valid */
  if (stat(fname, &cf_stat))
    return (errno);
  if (! S_ISREG(cf_stat.st_mode) && ! S_ISFIFO(cf_stat.st_mode))
    return (OPEN_CAP_FILE_NOT_REGULAR);

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
  cf->cd_t  = WTAP_FILE_UNKNOWN;
  cf->count = 0;
  cf->drops = 0;
  cf->esec  = 0;
  cf->eusec = 0;
  cf->snap  = 0;
  firstsec = 0, firstusec = 0;
  lastsec = 0, lastusec = 0;
 
	cf->wth = wtap_open_offline(fname);
	if (cf->wth == NULL) {

      /* XXX - we assume that, because we were able to open it above,
         this must have failed because it's not a capture file in
	 a format we can read. */
      return (OPEN_CAP_FILE_UNKNOWN_FORMAT);
    }

    if (cf->dfilter) {
	dfilter_compile(cf->dfilter, &cf->dfcode);
/*      if (wtap_offline_filter(cf->wth, cf->dfilter) < 0) {
        simple_dialog(ESD_TYPE_WARN, NULL, "Unable to parse filter string "
          "\"%s\".", cf->dfilter);
      }*/
    }
  cf->fh = wtap_file(cf->wth);
  cf->cd_t = wtap_file_type(cf->wth);
  cf->snap = wtap_snapshot_length(cf->wth);
  return (0);
}

static void
free_packets_cb(gpointer data, gpointer user_data)
{
  g_free(data);
}

/* Reset everything to a pristine state */
void
close_cap_file(capture_file *cf, void *w, guint context) {
  if (cf->fh) {
    fclose(cf->fh);
    cf->fh = NULL;
  }
  if (cf->wth) {
    wtap_close(cf->wth);
    cf->wth = NULL;
  }
  if (cf->plist) {
    g_list_foreach(cf->plist, free_packets_cb, NULL);
    g_list_free(cf->plist);
    cf->plist = NULL;
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
  gchar  *done_fmt = " File: %s  Drops: %d";
  gchar  *err_fmt  = " Error: Could not load '%s'";
  gint    timeout;
  size_t  msg_len;
  int     err;

  close_cap_file(cf, info_bar, file_ctx);

  /* Initialize protocol-speficic variables */
  ncp_init_protocol();

  if ((name_ptr = (gchar *) strrchr(fname, '/')) == NULL)
    name_ptr = fname;
  else
    name_ptr++;
  load_msg = g_malloc(strlen(name_ptr) + strlen(load_fmt) + 2);
  sprintf(load_msg, load_fmt, name_ptr);
  gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
  
  timeout = gtk_timeout_add(250, file_progress_cb, (gpointer) &cf);
  
  err = open_cap_file(fname, cf);
  if ((err == 0) && (cf->cd_t != WTAP_FILE_UNKNOWN)) {

    if (dfilter_proto_tree)

    gtk_clist_freeze(GTK_CLIST(packet_list));
    init_col_widths(cf);
    wtap_loop(cf->wth, 0, wtap_dispatch_cb, (u_char *) cf);
    wtap_close(cf->wth);
    cf->wth = NULL;
    cf->fh = fopen(fname, "r");

    set_col_widths(cf);
    gtk_clist_thaw(GTK_CLIST(packet_list));
  }
  
  gtk_timeout_remove(timeout);
  gtk_progress_bar_update(GTK_PROGRESS_BAR(prog_bar), 0);

  gtk_statusbar_pop(GTK_STATUSBAR(info_bar), file_ctx);

  if (err == 0) {
    msg_len = strlen(name_ptr) + strlen(done_fmt) + 64;
    load_msg = g_realloc(load_msg, msg_len);

    if (cf->user_saved || !cf->save_file)
	    snprintf(load_msg, msg_len, done_fmt, name_ptr, cf->drops);
    else
	    snprintf(load_msg, msg_len, done_fmt, "<none>", cf->drops);

    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
    g_free(load_msg);

/*    name_ptr[-1] = '\0';  Why is this here? It causes problems with capture files */
#ifdef USE_ITEM
    set_menu_sensitivity("/File/Close", TRUE);
    set_menu_sensitivity("/File/Reload", TRUE);
    set_menu_sensitivity("/Tools/Summary", TRUE);
#else
    set_menu_sensitivity("<Main>/File/Close", TRUE);
    set_menu_sensitivity("<Main>/File/Reload", TRUE);
    set_menu_sensitivity("<Main>/Tools/Summary", TRUE);
#endif
  } else {
    msg_len = strlen(name_ptr) + strlen(err_fmt) + 2;
    load_msg = g_realloc(load_msg, msg_len);
    snprintf(load_msg, msg_len, err_fmt, name_ptr);
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, load_msg);
    g_free(load_msg);
#ifdef USE_ITEM
    set_menu_sensitivity("/File/Close", FALSE);
    set_menu_sensitivity("/File/Save", FALSE);
    set_menu_sensitivity("/File/Save As...", FALSE);
    set_menu_sensitivity("/File/Reload", FALSE);
    set_menu_sensitivity("/Tools/Summary", FALSE);

#else
    set_menu_sensitivity("<Main>/File/Close", FALSE);
    set_menu_sensitivity("<Main>/File/Save", FALSE);
    set_menu_sensitivity("<Main>/File/Save As...", FALSE);
    set_menu_sensitivity("<Main>/File/Reload", FALSE);
    set_menu_sensitivity("<Main>/Tools/Summary", FALSE);
#endif
  }
  return err;
}

void 
cap_file_input_cb (gpointer data, gint source, GdkInputCondition condition) {
  
  capture_file *cf = (capture_file *)data;
  char buffer[256];

  /* avoid reentrancy problems and stack overflow */
  gtk_input_remove(cap_input_id);
  if (tail_timeout_id != -1) gtk_timeout_remove(tail_timeout_id);

  if (read(sync_pipe[0], buffer, 256) <= 0) {

    /* process data until end of file and stop capture (restore menu items) */
    gtk_clist_freeze(GTK_CLIST(packet_list));
    init_col_widths(cf);
    wtap_loop(cf->wth, 0, wtap_dispatch_cb, (u_char *) cf);      

    set_col_widths(cf);
    gtk_clist_thaw(GTK_CLIST(packet_list));

    wtap_close(cf->wth);
    cf->wth = NULL;
#ifdef USE_ITEM
    set_menu_sensitivity("/File/Open...", TRUE);
    set_menu_sensitivity("/File/Close", TRUE);
    set_menu_sensitivity("/File/Save As...", TRUE);
    set_menu_sensitivity("/File/Reload", TRUE);
    set_menu_sensitivity("/Capture/Start...", TRUE);
    set_menu_sensitivity("/Tools/Capture...", TRUE);
    set_menu_sensitivity("/Tools/Summary", TRUE);

#else
    set_menu_sensitivity("<Main>/File/Open...", TRUE);
    set_menu_sensitivity("<Main>/File/Close", TRUE);
    set_menu_sensitivity("<Main>/File/Save As...", TRUE);
    set_menu_sensitivity("<Main>/File/Reload", TRUE);
    set_menu_sensitivity("<Main>/Capture/Start...", TRUE);
    set_menu_sensitivity("<Main>/Tools/Capture...", TRUE);
    set_menu_sensitivity("<Main>/Tools/Summary", TRUE);
#endif
    gtk_statusbar_push(GTK_STATUSBAR(info_bar), file_ctx, " File: <none>");
    return;
  }

  gtk_clist_freeze(GTK_CLIST(packet_list));
  init_col_widths(cf);
  wtap_loop(cf->wth, 0, wtap_dispatch_cb, (u_char *) cf);      

  set_col_widths(cf);
  gtk_clist_thaw(GTK_CLIST(packet_list));

  /* restore pipe handler */
  cap_input_id = gtk_input_add_full (sync_pipe[0],
				     GDK_INPUT_READ,
				     cap_file_input_cb,
				     NULL,
				     (gpointer) cf,
				     NULL);

  /* only useful in case of low amount of captured data */
  tail_timeout_id = gtk_timeout_add(TAIL_TIMEOUT, tail_timeout_cb, (gpointer) cf);

}

gint
tail_timeout_cb(gpointer data) {

  capture_file *cf = (capture_file *)data;

  /* avoid reentrancy problems and stack overflow */
  gtk_input_remove(cap_input_id);

  gtk_clist_freeze(GTK_CLIST(packet_list));
  init_col_widths(cf);
  wtap_loop(cf->wth, 0, wtap_dispatch_cb, (u_char *) cf);      

  set_col_widths(cf);
  gtk_clist_thaw(GTK_CLIST(packet_list));

  cap_input_id = gtk_input_add_full (sync_pipe[0],
				     GDK_INPUT_READ,
				     cap_file_input_cb,
				     NULL,
				     (gpointer) cf,
				     NULL);

  return TRUE;
}

int
tail_cap_file(char *fname, capture_file *cf) {
  int     err;

  close_cap_file(cf, info_bar, file_ctx);

  /* Initialize protocol-speficic variables */
  ncp_init_protocol();

  err = open_cap_file(fname, cf);
  if ((err == 0) && (cf->cd_t != WTAP_FILE_UNKNOWN)) {

#ifdef USE_ITEM
    set_menu_sensitivity("/File/Open...", FALSE);
    set_menu_sensitivity("/File/Close", FALSE);
    set_menu_sensitivity("/File/Reload", FALSE);
    set_menu_sensitivity("/Capture/Start...", FALSE);
    set_menu_sensitivity("/Tools/Capture...", FALSE);
    set_menu_sensitivity("/Tools/Summary", FALSE);

#else
    set_menu_sensitivity("<Main>/File/Open...", FALSE);
    set_menu_sensitivity("<Main>/File/Close", FALSE);
    set_menu_sensitivity("<Main>/File/Reload", FALSE);
    set_menu_sensitivity("<Main>/Capture/Start...", FALSE);
    set_menu_sensitivity("<Main>/Tools/Capture...", FALSE);
    set_menu_sensitivity("<Main>/Tools/Summary", FALSE);

#endif
    cf->fh = fopen(fname, "r");
    tail_timeout_id = -1;
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
#ifdef USE_ITEM
    set_menu_sensitivity("/File/Close", FALSE);
    set_menu_sensitivity("/File/Save", FALSE);
    set_menu_sensitivity("/File/Save As...", FALSE);
    set_menu_sensitivity("/File/Reload", FALSE);
    set_menu_sensitivity("/Tools/Summary", FALSE);
#else
    set_menu_sensitivity("<Main>/File/Close", FALSE);
    set_menu_sensitivity("<Main>/File/Save", FALSE);
    set_menu_sensitivity("<Main>/File/Save As...", FALSE);
    set_menu_sensitivity("<Main>/File/Reload", FALSE);
    set_menu_sensitivity("<Main>/Tools/Summary", FALSE);
#endif
    close(sync_pipe[0]);
  }
  return err;
}

static void
compute_time_stamps(frame_data *fdata, capture_file *cf)
{
  /* If we don't have the time stamp of the first packet, it's because this
     is the first packet.  Save the time stamp of this packet as the time
     stamp of the first packet. */
  if (!firstsec && !firstusec) {
    firstsec  = fdata->abs_secs;
    firstusec = fdata->abs_usecs;
  }

  /* Do the same for the time stamp of the previous packet. */
  if (!lastsec && !lastusec) {
    lastsec  = fdata->abs_secs;
    lastusec = fdata->abs_usecs;
  }

  /* Get the time elapsed between the first packet and this packet. */
  cf->esec = fdata->abs_secs - firstsec;
  if (firstusec <= fdata->abs_usecs) {
    cf->eusec = fdata->abs_usecs - firstusec;
  } else {
    cf->eusec = (fdata->abs_usecs + 1000000) - firstusec;
    cf->esec--;
  }
  fdata->rel_secs = cf->esec;
  fdata->rel_usecs = cf->eusec;
  
  /* Do the same for the previous packet */
  fdata->del_secs = fdata->abs_secs - lastsec;
  if (lastusec <= fdata->abs_usecs) {
    fdata->del_usecs = fdata->abs_usecs - lastusec;
  } else {
    fdata->del_usecs = (fdata->abs_usecs + 1000000) - lastusec;
    fdata->del_secs--;
  }
  lastsec = fdata->abs_secs;
  lastusec = fdata->abs_usecs;
}

static void
change_time_format_in_packet_list(frame_data *fdata, capture_file *cf)
{
  gint          i, col_width;

  /* XXX - there really should be a way of checking "cf->cinfo" for this;
     the answer isn't going to change from packet to packet, so we should
     simply skip all the "change_time_formats()" work if we're not
     changing anything. */
  fdata->cinfo = &cf->cinfo;
  if (!check_col(fdata, COL_CLS_TIME)) {
    /* There are no columns that show the time in the "command-line-specified"
       format, so there's nothing we need to do. */
    return;
  }

  compute_time_stamps(fdata, cf);

  for (i = 0; i < fdata->cinfo->num_cols; i++) {
    fdata->cinfo->col_data[i][0] = '\0';
  }
  col_add_cls_time(fdata);
  for (i = 0; i < fdata->cinfo->num_cols; i++) {
    if (fdata->cinfo->fmt_matx[i][COL_CLS_TIME]) {
      /* This is one of the columns that shows the time in
         "command-line-specified" format; update it. */
      col_width = gdk_string_width(pl_style->font, fdata->cinfo->col_data[i]);
      if (col_width > fdata->cinfo->col_width[i])
        fdata->cinfo->col_width[i] = col_width;
      gtk_clist_set_text(GTK_CLIST(packet_list), cf->count - 1, i,
			  fdata->cinfo->col_data[i]);
    }
  }
  fdata->cinfo = NULL;
}

static void
add_packet_to_packet_list(frame_data *fdata, capture_file *cf, const u_char *buf)
{
  gint          i, col_width, row;

  compute_time_stamps(fdata, cf);

  fdata->cinfo = &cf->cinfo;
  for (i = 0; i < fdata->cinfo->num_cols; i++) {
    fdata->cinfo->col_data[i][0] = '\0';
  }
  if (check_col(fdata, COL_NUMBER))
    col_add_fstr(fdata, COL_NUMBER, "%d", cf->count);
  dissect_packet(buf, fdata, NULL);
  for (i = 0; i < fdata->cinfo->num_cols; i++) {
    col_width = gdk_string_width(pl_style->font, fdata->cinfo->col_data[i]);
    if (col_width > fdata->cinfo->col_width[i])
      fdata->cinfo->col_width[i] = col_width;
  }
  if (fdata->passed_dfilter) {
	row = gtk_clist_append(GTK_CLIST(packet_list), fdata->cinfo->col_data);
	gtk_clist_set_row_data(GTK_CLIST(packet_list), row, fdata);
  }
  fdata->cinfo = NULL;
}

static void
wtap_dispatch_cb(u_char *user, const struct wtap_pkthdr *phdr, int offset,
  const u_char *buf) {
  frame_data   *fdata;
  capture_file *cf = (capture_file *) user;
  proto_tree *protocol_tree = NULL;

  while (gtk_events_pending())
    gtk_main_iteration();

  /* Allocate the next list entry, and add it to the list. */
  fdata = (frame_data *) g_malloc(sizeof(frame_data));
  cf->plist = g_list_append(cf->plist, (gpointer) fdata);

  cf->cur = fdata;
  cf->count++;

  fdata->pkt_len  = phdr->len;
  fdata->cap_len  = phdr->caplen;
  fdata->file_off = offset;
  fdata->lnk_t = phdr->pkt_encap;
  fdata->abs_secs  = phdr->ts.tv_sec;
  fdata->abs_usecs = phdr->ts.tv_usec;
  fdata->cinfo = NULL;

  /* Apply the display filter */
  if (cf->dfcode) {
	protocol_tree = proto_tree_create_root();
	dissect_packet(buf, fdata, protocol_tree);
	fdata->passed_dfilter = dfilter_apply(cf->dfcode, protocol_tree, buf);
  }
  else {
	fdata->passed_dfilter = TRUE;
  }

  add_packet_to_packet_list(fdata, cf, buf);
}

static void
change_time_formats_cb(gpointer data, gpointer user_data)
{
  frame_data *fd = data;
  capture_file *cf = user_data;

  cf->cur = fd;
  cf->count++;

  change_time_format_in_packet_list(fd, cf);
}

/* Scan through the packet list and change all columns that use the
   "command-line-specified" time stamp format to use the current
   value of that format. */
void
change_time_formats(capture_file *cf)
{
  int i;

  /* Freeze the packet list while we redo it, so we don't get any
     screen updates while it happens. */
  gtk_clist_freeze(GTK_CLIST(packet_list));

  /* Zero out the column widths. */
  init_col_widths(cf);

  /*
   * Iterate through the list of packets, calling a routine
   * to run the filter on the packet, see if it matches, and
   * put it in the display list if so.
   */
  firstsec = 0;
  firstusec = 0;
  lastsec = 0;
  lastusec = 0;
  cf->count = 0;
  g_list_foreach(cf->plist, change_time_formats_cb, cf);

  /* Set the column widths of those columns that show the time in
     "command-line-specified" format. */
  for (i = 0; i < cf->cinfo.num_cols; i++) {
    if (cf->cinfo.fmt_matx[i][COL_CLS_TIME]) {
      gtk_clist_set_column_width(GTK_CLIST(packet_list), i,
        cf->cinfo.col_width[i]);
    }
  }

  /* Unfreeze the packet list. */
  gtk_clist_thaw(GTK_CLIST(packet_list));
}

/* Initialize the maximum widths of the columns to the widths of their
   titles. */
static void
init_col_widths(capture_file *cf)
{
  int i;

  /* XXX - this should use the column *title* font, not the font for
     the items in the list.

     Unfortunately, it's not clear how to get that font - it'd be
     the font used for buttons; there doesn't seem to be a way to get
     that from a clist, or to get one of the buttons in that clist from
     the clist in order to get its font. */
  for (i = 0; i < cf->cinfo.num_cols; i++)
    cf->cinfo.col_width[i] = gdk_string_width(pl_style->font,
                                               cf->cinfo.col_title[i]);
}

/* Set the widths of the columns to the maximum widths we found. */
static void
set_col_widths(capture_file *cf)
{
  int i;

  for (i = 0; i < cf->cinfo.num_cols; i++) {
    gtk_clist_set_column_width(GTK_CLIST(packet_list), i,
      cf->cinfo.col_width[i]);
  }
}

/* Tries to mv a file. If unsuccessful, tries to cp the file.
 * Returns 0 on failure to do either, 1 on success of either
 */
int
file_mv(char *from, char *to)
{

#define COPY_BUFFER_SIZE	8192

	int retval;

	/* try a hard link */
	retval = link(from, to);

	/* or try a copy */
	if (retval < 0) {
		retval = file_cp(from, to);
		if (!retval) {
			return 0;
		}
	}

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
	gint dialogue_button = ESD_BTN_OK;

	buffer = g_malloc(COPY_BUFFER_SIZE);

	from_fd = open(from, O_RDONLY);
	if (from_fd < 0) {
		simple_dialog(ESD_TYPE_WARN, &dialogue_button,
			file_open_error_message(errno, TRUE), from);
		return 0;
	}

	to_fd = creat(to, 0644);
	if (to_fd < 0) {
		simple_dialog(ESD_TYPE_WARN, &dialogue_button,
			file_open_error_message(errno, TRUE), to);
		close(from_fd);
		return 0;
	}

	while( (nread = read(from_fd, buffer, COPY_BUFFER_SIZE)) > 0) {
		nwritten = write(to_fd, buffer, nread);
		if (nwritten < nread) {
			if (nwritten < 0) {
				simple_dialog(ESD_TYPE_WARN, &dialogue_button,
					file_write_error_message(errno), to);
			} else {
				simple_dialog(ESD_TYPE_WARN, &dialogue_button,
"The file \"%s\" could not be saved: tried writing %d, wrote %d.\n",
					to, nread, nwritten);
			}
			close(from_fd);
			close(to_fd);
			return 0;
		}
	}
	if (nread < 0) {
		simple_dialog(ESD_TYPE_WARN, &dialogue_button,
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
