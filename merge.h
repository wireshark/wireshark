/* merge.h
 * Definitions for routines for merging files.
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
  wtap_dumper *pdh;
  unsigned int snaplen;
  int          count;
} merge_out_file_t;

/** Open a number of input files to merge.
 * 
 * @param in_file_count number of entries in in_file_names and in_files
 * @param in_file_names filenames of the input files
 * @param in_files input file array to be filled (>= sizeof(merge_in_file_t) * in_file_count)
 * @param err wiretap error, if failed
 * @param err_info wiretap error string, if failed
 * @param err_fileno file on which open failed, if failed
 * @return TRUE if all files could be opened, FALSE otherwise
 */
extern gboolean
merge_open_in_files(int in_file_count, char *const *in_file_names,
                    merge_in_file_t **in_files, int *err, gchar **err_info,
                    int *err_fileno);

/** Close the input files again.
 * 
 * @param in_file_count number of entries in in_files
 * @param in_files input file array to be closed
 */
extern void
merge_close_in_files(int in_file_count, merge_in_file_t in_files[]);

/** Open the output file.
 * 
 * @param out_file the output file array, which we fill in
 * @param fd the file descriptor to use for the output file
 * @param file_type the file type to write
 * @param frame_type the frame type to write
 * @param snapshot_len the snapshot length of the output file
 * @param err wiretap error, if failed
 * @return TRUE, if the output file could be opened, and FALSE otherwise
 */
extern gboolean
merge_open_outfile(merge_out_file_t *out_file, int fd, int file_type,
                   int frame_type, int snapshot_len, int *err);

/** Close the output file again.
 * 
 * @param out_file the output file array
 * @param err wiretap error, if failed
 * @return TRUE if the close succeeded, FALSE otherwise
 */
extern gboolean
merge_close_outfile(merge_out_file_t *out_file, int *err);

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

/*
 * Status from the merge-files routines.
 */
typedef enum {
	MERGE_SUCCESS,
	MERGE_READ_ERROR,
	MERGE_WRITE_ERROR
} merge_status_e;

/** Merge the packets from the input files into the output file sorted chronologically.
 * 
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @param out_file the output file array
 * @param err wiretap error, if failed
 * @return MERGE_SUCCESS on success, MERGE_READ_ERROR on read error,
 *         MERGE_WRITE_ERROR on write error
 */
extern merge_status_e
merge_files(int in_file_count, merge_in_file_t in_files[], merge_out_file_t *out_file, int *err);

/** Append the packets from the input files into the output file.
 * 
 * @param in_file_count number of entries in in_files
 * @param in_files input file array
 * @param out_file the output file array
 * @param err wiretap error, if failed
 * @return MERGE_SUCCESS on success, MERGE_READ_ERROR on read error,
 *         MERGE_WRITE_ERROR on write error
 */
extern merge_status_e
merge_append_files(int in_file_count, merge_in_file_t in_files[],
                   merge_out_file_t *out_file, int *err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __MERGE_H__ */

