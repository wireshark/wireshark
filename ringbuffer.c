/* ringbuffer.c
 * Routines for packet capture windows
 *
 * $Id: ringbuffer.c,v 1.1 2001/12/04 08:45:04 guy Exp $
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#ifdef HAVE_IO_H
#include <io.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef NEED_SNPRINTF_H
#include "snprintf.h"
#endif

#include "wiretap/wtap.h"
#include "ringbuffer.h"

/* Win32 needs the O_BINARY flag for open() */
#ifndef O_BINARY
#define O_BINARY	0
#endif

/* Ringbuffer file structure */
typedef struct _rb_file {
  gchar*        name;
  int           fd;
  time_t        creation_time;
  gboolean      is_new;
  guint16       number;
  wtap_dumper*  pdh;
  long          start_pos;
} rb_file;

/* Ringbuffer data structure */
typedef struct _ringbuf_data {
  rb_file*      files;
  guint         num_files;      /* Number of ringbuffer files */
  guint         curr_file_num;  /* Number of the current file */
  gchar*        fprefix;        /* Filename prefix */
  gchar*        fsuffix;        /* Filename suffix */
} ringbuf_data; 

/* Create the ringbuffer data structure */
static ringbuf_data rb_data;

/* 
 * Initialize the ringbuffer data structure
 */
int 
ringbuf_init(const char *capfile_name, guint num_files)
{
  int          save_file_fd;
  unsigned int i;
  char        *pfx;
  gchar       *save_file;
  char         save_file_num[3+1];

  /* just to be sure ... */
  if (num_files <= RINGBUFFER_MAX_NUM_FILES) {
    rb_data.num_files = num_files;
  } else {
    rb_data.num_files = RINGBUFFER_MAX_NUM_FILES;
  }

  /* Check file name */
  if (capfile_name == NULL) {
    /* ringbuffer does not work with temporary files! */
    return -1;
  }

  /* Open the initial file */
  save_file_fd = open(capfile_name, O_RDWR|O_BINARY|O_TRUNC|O_CREAT, 0600);
  if (save_file_fd == -1) {
    /* open failed */
    return -1;
  }
 
  /* allocate memory */
  rb_data.files = (rb_file *)calloc(num_files, sizeof(rb_file));
  if (rb_data.files == NULL) {
    /* could not allocate memory */
    return -1;
  }

  /* initialize */
  rb_data.fprefix = NULL;
  rb_data.fsuffix = NULL;
  for (i=0; i<rb_data.num_files; i++) {
    rb_data.files[i].name = NULL;
    rb_data.files[i].fd = -1;
  }

  /* get file name prefix/suffix */
  save_file = g_strdup(capfile_name);
  pfx = strrchr(save_file,'.');
  if (pfx != NULL) {
    pfx[0] = '\0';
    rb_data.fprefix = g_strdup(save_file);
    pfx[0] = '.'; /* restore capfile_name */
    rb_data.fsuffix = g_strdup(pfx);
  } else {
    rb_data.fprefix = g_strdup(save_file);
    rb_data.fsuffix = NULL;
  }
  g_free(save_file);
  save_file = NULL;

#ifdef _WIN32
  _tzset();
#endif
  /* save the initial file parameters */
  rb_data.files[0].name = g_strdup(capfile_name);
  rb_data.files[0].fd = save_file_fd;
  rb_data.files[0].creation_time = time(NULL);
  rb_data.files[0].number = 0;
  rb_data.files[0].is_new = TRUE;

  /* create the other files */
  for (i=1; i<rb_data.num_files; i++) {
    /* create a file name */
    snprintf(save_file_num,3+1,"%03d",i);
    save_file = g_strconcat(capfile_name, ".", save_file_num, NULL);
    /* open the file */
    save_file_fd = open(save_file, O_RDWR|O_BINARY|O_TRUNC|O_CREAT, 0600);
    if (save_file_fd != -1) {
      rb_data.files[i].name = save_file;
      rb_data.files[i].fd = save_file_fd;
      rb_data.files[i].creation_time = time(NULL);
      rb_data.files[i].number = i;
      rb_data.files[i].is_new = TRUE;
    } else {
      /* could not open a file  */
      ringbuf_error_cleanup();
      return -1;
    }
  }
  
  /* done */
  rb_data.curr_file_num = 0;
  return rb_data.files[0].fd;
}

/* 
 * Calls wtap_dump_fdopen() for all ringbuffer files
 */
wtap_dumper* 
ringbuf_init_wtap_dump_fdopen(int filetype, int linktype, 
  int snaplen, int *err)
{
  unsigned int  i;
  FILE         *fh;

  for (i=0; i<rb_data.num_files; i++) {
    rb_data.files[i].pdh = wtap_dump_fdopen(rb_data.files[i].fd, filetype,
      linktype, snaplen, err);
    if (rb_data.files[i].pdh == NULL) {
      /* could not open file */
      return NULL;
    } else {
      /*
       * XXX - this relies on Wiretap writing out data sequentially,
       * and writing the entire capture file header when the file
       * is created.  That happens to be true for libpcap files,
       * which are Ethereal's native capture files, and which are
       * therefore the capture file types we're writing, but is not
       * true for all the capture file types Wiretap can write.
       */
      fh = wtap_dump_file(rb_data.files[i].pdh);
      fflush(fh);
      rb_data.files[i].start_pos = ftell(fh);
      clearerr(fh);
    }
  }
  /* done */
  rb_data.files[0].is_new = FALSE;
  return rb_data.files[0].pdh;
}

/* 
 * Switches to the next ringbuffer file
 */
gboolean
ringbuf_switch_file(capture_file *cf, wtap_dumper **pdh, int *err)
{
  int   next_file_num;
  FILE *fh;

  /* flush the current file */
  fh = wtap_dump_file(rb_data.files[rb_data.curr_file_num].pdh);
  clearerr(fh);
  fflush(fh);
  /* get the next file number */
  next_file_num = (rb_data.curr_file_num + 1) % rb_data.num_files;
  /* prepare the file if it was already used */
  if (!rb_data.files[next_file_num].is_new) {
    /* rewind to the position after the file header */
    fh = wtap_dump_file(rb_data.files[next_file_num].pdh);
    fseek(fh, rb_data.files[next_file_num].start_pos, SEEK_SET);
    wtap_set_bytes_dumped(rb_data.files[next_file_num].pdh,
      rb_data.files[next_file_num].start_pos);
    /* set the absolute file number */
    rb_data.files[next_file_num].number += rb_data.num_files;
  }
#ifdef _WIN32
  _tzset();
#endif
  rb_data.files[next_file_num].creation_time = time(NULL);
  /* switch to the new file */
  cf->save_file = rb_data.files[next_file_num].name;
  cf->save_file_fd = rb_data.files[next_file_num].fd;
  (*pdh) = rb_data.files[next_file_num].pdh;
  /* mark the file as used */
  rb_data.files[next_file_num].is_new = FALSE;
  /* finally set the current file number */
  rb_data.curr_file_num = next_file_num;

  return TRUE;
}

/* 
 * Calls wtap_dump_close() for all ringbuffer files
 */
gboolean
ringbuf_wtap_dump_close(capture_file *cf, int *err)
{
  gboolean     ret_val;
  unsigned int i;
  gchar       *new_name;
  char         filenum[5+1];
  char         timestr[14+1];
  FILE        *fh;

  /* assume success */
  ret_val = TRUE;
  /* close all files */
  for (i=0; i<rb_data.num_files; i++) {
    fh = wtap_dump_file(rb_data.files[i].pdh);
    clearerr(fh);
    /* Flush the file */
    fflush(fh);
    /* Truncate the file to the current size. This must be done in order
       to get rid of the 'garbage' packets at the end of the file from
       previous usage */
    if (!rb_data.files[i].is_new) {
      if (ftruncate(rb_data.files[i].fd,ftell(fh)) != 0) {
        /* could not truncate the file */
        if (err != NULL) {
          *err = errno;
        }
        ret_val = FALSE;
        /* remove the file since it contains garbage at the end */
        close(rb_data.files[i].fd);
        unlink(rb_data.files[i].name);
        continue;
      }
    }
    /* close the file */
    if (!wtap_dump_close(rb_data.files[i].pdh, err)) {
      /* error only if it is a used file */
      if (!rb_data.files[i].is_new) {
        ret_val = FALSE;
      }
    }
    if (!rb_data.files[i].is_new) {
      /* rename the file */
      snprintf(filenum,5+1,"%05d",rb_data.files[i].number);
      strftime(timestr,14+1,"%Y%m%d%H%M%S", 
        localtime(&(rb_data.files[i].creation_time)));
      new_name = g_strconcat(rb_data.fprefix,"_", filenum, "_", timestr, 
        rb_data.fsuffix, NULL);
      if (rename(rb_data.files[i].name, new_name) != 0) {
        /* save the latest error */
        if (err != NULL) {
          *err = errno;
        }
        ret_val = FALSE;
        g_free(new_name);
      } else {
        g_free(rb_data.files[i].name);
        rb_data.files[i].name = new_name;
      }
    } else {
      /* this file has never been used - remove it */
      unlink(rb_data.files[i].name);
    }
  }
  /* make the current file the save file */
  cf->save_file = rb_data.files[rb_data.curr_file_num].name;
  return ret_val;
}

/* 
 * Frees all memory allocated by the ringbuffer
 */
void
ringbuf_free()
{ 
  unsigned int i;
  
  if (rb_data.files != NULL) {
    for (i=0; i < rb_data.num_files; i++) {
      g_free(rb_data.files[i].name);
      rb_data.files[i].name = NULL;
    }
    free(rb_data.files);
    rb_data.files = NULL;
  }
  g_free(rb_data.fprefix);
  g_free(rb_data.fsuffix);
}

/* 
 * Frees all memory allocated by the ringbuffer
 */
void 
ringbuf_error_cleanup()
{
  unsigned int i;
  int err;
  
  if (rb_data.files == NULL) {
    ringbuf_free();
    return;
  }

  for (i=0; i<rb_data.num_files; i++) {
    /* try to close via wtap */
    if (rb_data.files[i].pdh != NULL) {
      if (wtap_dump_close(rb_data.files[i].pdh, &err) == TRUE) {
        /* done */
        rb_data.files[i].fd = -1;
      }
    }
    /* close directly if still open */
    if (rb_data.files[i].fd != -1) {
      close(rb_data.files[i].fd);
    }
    /* remove the other files, the initial file will be handled
       by the calling funtion */
    if (rb_data.files[i].name != NULL) {
      unlink(rb_data.files[i].name);
    }
  }
  /* free the memory */  
  ringbuf_free();
}

#endif /* HAVE_LIBPCAP */
