/* file.h
 * Definitions for file structures and routines
 *
 * $Id: file.h,v 1.105 2003/09/12 02:48:20 sahlberg Exp $
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

#include "wiretap/wtap.h"
#include <epan/dfilter/dfilter.h>
#include "print.h"
#include <errno.h>
#include <epan/epan.h>

#include "cfile.h"

/* Return values from "read_cap_file()", "continue_tail_cap_file()",
   and "finish_tail_cap_file()". */
typedef enum {
	READ_SUCCESS,	/* read succeeded */
	READ_ERROR,	/* read got an error */
	READ_ABORTED	/* read aborted by user */
} read_status_t;

int  open_cap_file(char *, gboolean, capture_file *);
void close_cap_file(capture_file *);
read_status_t read_cap_file(capture_file *, int *);
int  start_tail_cap_file(char *, gboolean, capture_file *);
read_status_t continue_tail_cap_file(capture_file *, int, int *);
read_status_t finish_tail_cap_file(capture_file *, int *);
/* size_t read_frame_header(capture_file *); */
gboolean save_cap_file(char *, capture_file *, gboolean, gboolean, guint);

int filter_packets(capture_file *cf, gchar *dfilter);
void reftime_packets(capture_file *);
void colorize_packets(capture_file *);
void redissect_packets(capture_file *cf);
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

void select_packet(capture_file *, int);
void unselect_packet(capture_file *);

void unselect_field(void);

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
