/* merge.h
 * Definitions for menu routines with toolkit-independent APIs but
 * toolkit-dependent implementations.
 *
 * $Id$
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

#ifndef __MERGE_H__
#define __MERGE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Structures to manage our input files.
 */
typedef struct merge_in_file_s {
  const char *filename;
  wtap       *wth;
  int         err;
  gchar      *err_info;
  long        data_offset;
  gboolean    ok;
} merge_in_file_t;

/**
 * Structures to manage our output file.
 */
typedef struct merge_out_file_s {
  int          fd;
  wtap_dumper *pdh;
  int          file_type;
  int          frame_type;
  unsigned int snaplen;
  int          count;
} merge_out_file_t;

/** Verbosity levels. */
typedef enum {
    VERBOSE_NONE,
    VERBOSE_ERRORS,
    VERBOSE_ALL
} verbose_e;

/** Current verbosity level, default is VERBOSE_NONE. */
extern int merge_verbose;

/** Open a number of input files to merge.
 * 
 * @param in_file_count number of entries in in_file_names and in_files
 * @param in_file_names filenames of the input files
 * @param in_files input file array to be filled (>= sizeof(merge_in_file_t) * in_file_count)
 * @param err wiretap error, if failed
 * @return number of opened input files
 */
extern int
merge_open_in_files(int in_file_count, char *in_file_names[], merge_in_file_t *in_files[], int *err);

/** Close the input files again.
 * 
 * @param in_file_count number of entries in in_files
 * @param in_files input file array to be closed
 */
extern void
merge_close_in_files(int in_file_count, merge_in_file_t in_files[]);

/** Open the output file.
 * 
 * @param out_file the prefilled output file array
 * @param snapshot_len the snapshot length of the output file
 * @param err wiretap error, if failed
 * @return TRUE, if the output file could be opened
 */
extern gboolean
merge_open_outfile(merge_out_file_t *out_file, int snapshot_len, int *err);

/** Close the output file again.
 * 
 * @param out_file the output file array
 */
extern void
merge_close_outfile(merge_out_file_t *out_file);

/** Try to get the frame type from the input files.
 * 
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @return the frame type
 */
extern int
merge_select_frame_type(int in_file_count, merge_in_file_t in_files[]);

/** Try to get the snapshot length from the input files.
 * 
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @return the snapshot length
 */
extern int
merge_max_snapshot_length(int in_file_count, merge_in_file_t in_files[]);

/** Merge the packets from the input files into the output file sorted chronologically.
 * 
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @param out_file the output file array
 * @param err wiretap error, if failed
 * @return TRUE if function succeeded
 */
extern gboolean
merge_files(int in_file_count, merge_in_file_t in_files[], merge_out_file_t *out_file, int *err);

/** Append the packets from the input files into the output file.
 * 
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @param out_file the output file array
 * @param err wiretap error, if failed
 * @return TRUE if function succeeded
 */
extern gboolean
merge_append_files(int in_file_count, merge_in_file_t in_files[], merge_out_file_t *out_file, int *err);


/*
 * Convenience function: merge any number of input files into one.
 *
 * @param out_filename the output filename
 * @param in_file_count number of input files
 * @param in_filenames array of input filenames
 * @param do_append TRUE to append, FALSE to merge chronologically
 * @param err wiretap error, if failed
 * @return TRUE if function succeeded
 */
extern gboolean
merge_n_files(int out_fd, int in_file_count, char **in_filenames, int filetype, gboolean do_append, int *err);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MERGE_H__ */

