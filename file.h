/* file.h
 * Definitions for file structures and routines
 *
 * $Id: file.h,v 1.111 2004/01/20 18:47:21 ulfl Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
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

#ifndef __FILE_H__
#define __FILE_H__

#include "range.h"
#include "wiretap/wtap.h"
#include <epan/dfilter/dfilter.h>
#include "print.h"
#include <errno.h>
#include <epan/epan.h>

#include "cfile.h"

/* Return values from "cf_read()", "cf_continue_tail()", and
   "cf_finish_tail()". */
typedef enum {
	READ_SUCCESS,	/* read succeeded */
	READ_ERROR,	/* read got an error */
	READ_ABORTED	/* read aborted by user */
} read_status_t;

int  cf_open(char *, gboolean, capture_file *);
void cf_close(capture_file *);
read_status_t cf_read(capture_file *, int *);
int  cf_start_tail(char *, gboolean, capture_file *);
read_status_t cf_continue_tail(capture_file *, int, int *);
read_status_t cf_finish_tail(capture_file *, int *);
/* size_t read_frame_header(capture_file *); */
gboolean cf_save(char *fname, capture_file * cf, packet_range_t *range, guint save_format);
gchar *cf_get_display_name(capture_file *);

int filter_packets(capture_file *cf, gchar *dfilter);
void reftime_packets(capture_file *);
void colorize_packets(capture_file *);
void redissect_packets(capture_file *cf);
int retap_packets(capture_file *cf);
int print_packets(capture_file *cf, print_args_t *print_args);
void change_time_formats(capture_file *);

gboolean find_packet_protocol_tree(capture_file *cf, const char *string);
gboolean find_packet_summary_line(capture_file *cf, const char *string);
gboolean find_packet_data(capture_file *cf, const guint8 *string,
			  size_t string_size);
gboolean find_packet_dfilter(capture_file *cf, dfilter_t *sfcode);

guint8 get_int_value(char char_val);
gboolean find_ascii(capture_file *cf, char *ascii_text, gboolean ascii_search, char *ftype, gboolean case_type);
gboolean find_in_gtk_data(capture_file *cf, gpointer *data, char *ascii_text, gboolean case_type, gboolean search_type);
gboolean goto_frame(capture_file *cf, guint fnumber);
gboolean goto_bottom_frame(capture_file *cf);
gboolean goto_top_frame(capture_file *cf);


void select_packet(capture_file *, int);
void unselect_packet(capture_file *);

void unselect_field(capture_file *);

/*
 * Mark a particular frame in a particular capture.
 */
void mark_frame(capture_file *, frame_data *);

/*
 * Unmark a particular frame in a particular capture.
 */
void unmark_frame(capture_file *, frame_data *);

/* Moves or copies a file. Returns 0 on failure, 1 on success */
int file_mv(char *from, char *to);

/* Copies a file. Returns 0 on failure, 1 on success */
int file_cp(char *from, char *to);

char *file_open_error_message(int, gboolean, int);
char *file_read_error_message(int);
char *file_write_error_message(int);

#endif /* file.h */
