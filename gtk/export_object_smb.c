/* export_object_smb.c
 * Routines for tracking & saving objects (files) found in SMB streams
 * See also: export_object.c / export_object.h for common code
 * Initial file, prototypes and general structure initially copied
 * from export_object_http.c
 *
 * Copyright 2010, David Perez & Jose Pico from TADDONG S.L.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-smb.h>
#include <epan/tap.h>

#include "gtk/export_object.h"


/* These flags show what kind of data the object contains
   (designed to be or'ed) */
#define SMB_EO_CONTAINS_NOTHING		0x00
#define SMB_EO_CONTAINS_READS		0x01
#define SMB_EO_CONTAINS_WRITES		0x02
#define SMB_EO_CONTAINS_READSANDWRITES	0x03
#define LEGAL_FILENAME_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVXYZ1234567890_."

static const value_string smb_eo_contains_string[]={
	{SMB_EO_CONTAINS_NOTHING,     		""},
	{SMB_EO_CONTAINS_READS,     		"R"},
	{SMB_EO_CONTAINS_WRITES,     		"W"},
	{SMB_EO_CONTAINS_READSANDWRITES,     	"R&W"},
	{0, NULL}
	};


/* This struct contains the relationship between
   the row# in the export_object window and the file being captured;
   the row# in this GSList will match the row# in the entry list */

typedef struct _active_file {
        guint16         tid,uid,fid;
        guint64         file_length;    /* The last free reported offset */
                                        /* We treat it as the file length */
        guint64         data_gathered;  /* The actual total of data gathered */
        guint8          flag_contains;  /* What kind of data it contains */
        GSList          *free_chunk_list;
					/* A list of virtual "holes" in the */
					/* file stream stored in memory */
	gboolean	is_out_of_memory;
					/* TRUE if we cannot allocate memory */
					/* memory for this file */
        } active_file ;

/* This is the GSList that will contain all the files that we are tracking */
static GSList	*GSL_active_files = NULL;

/* We define a free chunk in a file as an start offset and end offset
   Consider a free chunk as a "hole" in a file that we are capturing */
typedef struct _free_chunk {
        guint64         start_offset;
        guint64         end_offset;
} free_chunk;

/* insert_chunk function will recalculate the free_chunk_list, the data_size,
   the end_of_file, and the data_gathered as appropriate.
   It will also insert the data chunk that is coming in the right
   place of the file in memory.
   HINTS:
   file->data_gathered 	contains the real data gathered independently
	 		from the file length
   file->file_length 	contains the length of the file in memory, i.e.,
			the last offset captured. In most cases, the real
			file length would be different.
*/
static void
insert_chunk(active_file   *file, export_object_entry_t *entry, const smb_eo_t *eo_info)
{
        guint           nfreechunks = g_slist_length(file->free_chunk_list);
	guint		i;
        free_chunk      *current_free_chunk;
        free_chunk      *new_free_chunk;
	guint64 	chunk_offset=eo_info->smb_file_offset;
	guint64 	chunk_length=eo_info->payload_len;
        guint64         chunk_end_offset = chunk_offset+chunk_length-1;
	/* Size of file in memory */
        guint64         calculated_size = chunk_offset+chunk_length;
	gpointer	dest_memory_addr;

	/* Let's recalculate the file length and data gathered */
	if (file->data_gathered==0 && nfreechunks==0) {
		/* If this is the first entry for this file, we first
		   create an initial free chunk */
                new_free_chunk=g_malloc(sizeof(free_chunk));
                new_free_chunk->start_offset=0;
		new_free_chunk->end_offset=MAX(file->file_length,chunk_end_offset+1)-1;
		file->free_chunk_list=NULL;
		file->free_chunk_list=g_slist_append(file->free_chunk_list,new_free_chunk);
		nfreechunks+=1;
	} else {
		if (chunk_end_offset > file->file_length-1) {
                	new_free_chunk=g_malloc(sizeof(free_chunk));
                	new_free_chunk->start_offset=file->file_length;
			new_free_chunk->end_offset=chunk_end_offset;
			file->free_chunk_list=g_slist_append(file->free_chunk_list,new_free_chunk);
			nfreechunks+=1;
			}
	}
	file->file_length = MAX(file->file_length,chunk_end_offset+1);

        for (i=0;i<nfreechunks;i++) {
                current_free_chunk = g_slist_nth_data(file->free_chunk_list,i);
                if (chunk_offset <= current_free_chunk->start_offset ) {
                        if (chunk_end_offset >= current_free_chunk->start_offset) {
                                if (chunk_end_offset < current_free_chunk->end_offset) {
                                        file->data_gathered+=
                                                (chunk_end_offset-current_free_chunk->start_offset+1);
                                        current_free_chunk->start_offset=chunk_end_offset+1;
                                } else {
                                        file->data_gathered+=
                                                (current_free_chunk->end_offset-current_free_chunk->start_offset+1);
                                        file->free_chunk_list =
                                                g_slist_remove(file->free_chunk_list,current_free_chunk);
					nfreechunks-=1;
					if (nfreechunks==0) { /* The free chunk list is empty */
						g_slist_free(file->free_chunk_list);
						file->free_chunk_list=NULL;
						break;
					}
                                }
                        } else {
                                break;
                        }
                } else {
			if (chunk_offset <= current_free_chunk->end_offset) {
                                if (chunk_end_offset < current_free_chunk->end_offset) {
                                        new_free_chunk=g_malloc(sizeof(free_chunk));
                                        new_free_chunk->start_offset=chunk_end_offset+1;
                                        new_free_chunk->end_offset=current_free_chunk->end_offset;
                                        current_free_chunk->end_offset=chunk_offset-1;
                                        file->free_chunk_list =
                                                g_slist_insert(file->free_chunk_list,new_free_chunk,i+1);
                                        file->data_gathered+=chunk_length;
                                } else {
                                        file->data_gathered+=current_free_chunk->end_offset-chunk_offset+1;
                                        current_free_chunk->end_offset=chunk_offset-1;
                                }
                        }
                }
        }

	/* Now, let's insert the data chunk into memory
	   ...first, we shall be able to allocate the memory */
	if (!entry->payload_data) {
		/* This is a New file */
		if (calculated_size > G_MAXSIZE) {
			/*
			 * The argument to g_try_malloc() is
			 * a gsize, the maximum value of which is
			 * G_MAXSIZE.  If the calculated size is
			 * bigger than that, we just say the attempt
			 * to allocate memory failed.
			 */
			entry->payload_data=NULL;
		} else {
			entry->payload_data = g_try_malloc((gsize)calculated_size);
			entry->payload_len=calculated_size;
		}
		if (!entry->payload_data) {
			/* Memory error */
			file->is_out_of_memory=TRUE;
		}
	} else {
		/* This is an existing file in memory */
		if (calculated_size > (guint64) entry->payload_len &&
		    !file->is_out_of_memory) {
			/* We need more memory */
			if (calculated_size > G_MAXSIZE) {
				/*
				 * As for g_try_malloc(), so for
				 * g_try_realloc().
				 */
				dest_memory_addr=NULL;
			} else {
				dest_memory_addr=g_try_realloc(
					entry->payload_data,
					(gsize)calculated_size);
			}
			if(!dest_memory_addr) {
				/* Memory error */
				file->is_out_of_memory=TRUE;
				/* We don't have memory for this file.
				   Free the current file content from memory */
				g_free(entry->payload_data);
				entry->payload_data=NULL;
				entry->payload_len=0;
			} else {
				entry->payload_data=dest_memory_addr;
				entry->payload_len=calculated_size;
			}
		}
	}
	/* ...then, put the chunk of the file in the right place */
	if(!file->is_out_of_memory) {
		dest_memory_addr=entry->payload_data+chunk_offset;
		g_memmove(dest_memory_addr,eo_info->payload_data,eo_info->payload_len);
	}
}

/* We use this function to obtain the index in the GSL of a given file */
static int
find_incoming_file(GSList *GSL_active_files,active_file *incoming_file)
{
	int 	i,row,last;
	active_file	*in_list_file;

	row=-1;
	last=g_slist_length(GSL_active_files)-1;

	/* We lookup in reverse order because it is more likely that the file
	   is one of the latest */
	for (i=last;i>=0;i--) {
		in_list_file=g_slist_nth_data(GSL_active_files, i);
		/* The best-working criteria of two identical files is that the file
  		   that is the same of the file that we are analyzing is the last one
		   in the list that has the same tid and the same fid */
		/* note that we have excluded in_list_file->uid == incoming_file->uid
		   from the comparison, because a file can be opened by different
		   SMB users and it is still the same file */
		if (in_list_file->tid == incoming_file->tid &&
				in_list_file->fid == incoming_file->fid) {
			row=i;
			break;
		}
	}

	return row;
}

#if !GLIB_CHECK_VERSION(2,6,0)
/**
 * g_strv_length:
 * @str_array: a %NULL-terminated array of strings.
 *
 * Returns the length of the given %NULL-terminated
 * string array @str_array.
 *
 * Return value: length of @str_array.
 *
 * Since: 2.6
 **/
static guint
g_strv_length (gchar **str_array)
{
	guint i = 0;

	g_return_val_if_fail (str_array != NULL, 0);

	while (str_array[i])
		++i;

	return i;
}
#endif

/* This is the function answering to the registered tap listener call */
static gboolean
eo_smb_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt _U_, const void *data)
{
	export_object_list_t *object_list = tapdata;
	const smb_eo_t *eo_info = data;

	export_object_entry_t 	*entry;
	export_object_entry_t 	*current_entry;
	active_file		incoming_file;
	gint			active_row;
	active_file		*new_file;
	active_file		*current_file;
	guint8			contains;
	gboolean		is_supported_filetype;
	gfloat			percent;

	gchar			**aux_string_v;

	/* Is this an eo_smb supported file_type? (right now we only support FILE */
	is_supported_filetype = (eo_info->fid_type==SMB_FID_TYPE_FILE);

	/* What kind of data this packet contains? */
	switch(eo_info->cmd) {
	case SMB_COM_READ_ANDX:
		contains=SMB_EO_CONTAINS_READS;
		break;
	case SMB_COM_WRITE_ANDX:
		contains=SMB_EO_CONTAINS_WRITES;
		break;
	default:
		contains=SMB_EO_CONTAINS_NOTHING;
		break;
	}

	/* Is this data from an already tracked file or not? */
	incoming_file.tid=eo_info->tid;
	incoming_file.uid=eo_info->uid;
	incoming_file.fid=eo_info->fid;
	active_row=find_incoming_file(GSL_active_files, &incoming_file);

	if (active_row==-1) { /* This is a new-tracked file */
		/* Construct the entry in the list of active files */
		entry = g_malloc(sizeof(export_object_entry_t));
		entry->payload_data=NULL;
		entry->payload_len=0;
		new_file = g_malloc(sizeof(active_file));
		new_file->tid=incoming_file.tid;
		new_file->uid=incoming_file.uid;
		new_file->fid=incoming_file.fid;
		new_file->file_length = eo_info->end_of_file;
		new_file->flag_contains=contains;
		new_file->free_chunk_list=NULL;
		new_file->data_gathered=0;
		new_file->is_out_of_memory=FALSE;
		entry->pkt_num = pinfo->fd->num;
		entry->hostname = g_strdup(eo_info->hostname);
		if (g_str_has_prefix(eo_info->filename,"\\")) {
			aux_string_v = g_strsplit(eo_info->filename, "\\", -1);
			entry->filename = g_strdup(aux_string_v[g_strv_length(aux_string_v)-1]);
			g_strfreev(aux_string_v);
		} else {
			entry->filename = g_strdup(eo_info->filename);
		}

		/* Insert the first chunk in the chunk list of this file */
		if (is_supported_filetype) {
			insert_chunk(new_file, entry, eo_info);
		}

		if(new_file->is_out_of_memory) {
			entry->content_type =
				g_strdup_printf("%s (%"G_GUINT64_FORMAT"?/%"G_GUINT64_FORMAT") %s [mem!!]",
						match_strval(eo_info->fid_type, smb_fid_types),
						new_file->data_gathered,
						new_file->file_length,
						match_strval(contains, smb_eo_contains_string));
		} else {
			if (new_file->file_length > 0) {
				percent=(gfloat) 100*new_file->data_gathered/new_file->file_length;
			} else {
				percent = 0.0;
			}

			entry->content_type =
				g_strdup_printf("%s (%"G_GUINT64_FORMAT"/%"G_GUINT64_FORMAT") %s [%5.2f%%]",
						match_strval(eo_info->fid_type, smb_fid_types),
						new_file->data_gathered,
						new_file->file_length,
						match_strval(contains, smb_eo_contains_string),
						percent);
		}

		object_list->entries =
			g_slist_append(object_list->entries, entry);
		GSL_active_files =
			g_slist_append(GSL_active_files, new_file);
	}
	else if (is_supported_filetype) {
		current_file=g_slist_nth_data(GSL_active_files,active_row);
		/* Recalculate the current file flags */
		current_file->flag_contains=current_file->flag_contains|contains;
		current_entry=g_slist_nth_data(object_list->entries,active_row);

		insert_chunk(current_file, current_entry, eo_info);

		/* Modify the current_entry object_type string */
		if(current_file->is_out_of_memory) {
			current_entry->content_type =
				g_strdup_printf("%s (%"G_GUINT64_FORMAT"?/%"G_GUINT64_FORMAT") %s [mem!!]",
						match_strval(eo_info->fid_type, smb_fid_types),
						current_file->data_gathered,
						current_file->file_length,
						match_strval(current_file->flag_contains, smb_eo_contains_string));
		} else {
			percent=(gfloat) 100*current_file->data_gathered/current_file->file_length;
			current_entry->content_type =
				g_strdup_printf("%s (%"G_GUINT64_FORMAT"/%"G_GUINT64_FORMAT") %s [%5.2f%%]",
						match_strval(eo_info->fid_type, smb_fid_types),
						current_file->data_gathered,
						current_file->file_length,
						match_strval(current_file->flag_contains, smb_eo_contains_string),
						percent);
		}
	}

	return TRUE; /* State changed - window should be redrawn */
}
/* This is the eo_protocoldata_reset function that is used in the export_object module
   to cleanup any previous private data of the export object functionality before perform
   the eo_reset function or when the window closes */
static void
eo_smb_cleanup(void)
{
	int 	         i,last;
	active_file	*in_list_file;

	/* Free any previous data structures used in previous invocation to the
	   export_object_smb function */
	last=g_slist_length(GSL_active_files);
	if (GSL_active_files) {
		for (i=last-1;i>=0;i--) {
			in_list_file=g_slist_nth_data(GSL_active_files, i);
			if (in_list_file->free_chunk_list) {
				g_slist_free(in_list_file->free_chunk_list);
                        	in_list_file->free_chunk_list=NULL;
				}
			g_free(in_list_file);
			}
		g_slist_free(GSL_active_files);
		GSL_active_files=NULL;
	}
}

void
eo_smb_cb(GtkWidget *widget _U_, gpointer data _U_)
{
	/* Call the export_object window */
	export_object_window("smb_eo", "SMB", eo_smb_packet, eo_smb_cleanup);
}
