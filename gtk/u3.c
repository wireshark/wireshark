/* u3.c
 * u3   2006 Graeme Lunt
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * Indentation logic: 2-space
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef _WIN32
#include <process.h>    /* getpid */
#endif

#include <wiretap/file_util.h>
#include <epan/filesystem.h>

#include <gtk/u3.h>

#define U3_DEVICE_PATH_VAR   "$U3_DEVICE_PATH"

static char *pid_file = NULL;
static char *u3devicepath = (char*)-1;
static gchar *newpath = NULL;

static char *u3_change_path(char *path, const char *old, const char *new);

gboolean u3_active() 
{

  return (
#ifdef _WIN32
      getenv_utf8
#else
      getenv
#endif 
      ("U3_HOST_EXEC_PATH") != NULL);

}

void u3_register_pid()
{
  int	pid;
  int   pid_fd;
  char *u3hostexecpath;
  int   pf_size;
    
  if((u3hostexecpath = 
#ifdef _WIN32
      getenv_utf8
#else
      getenv
#endif 
      ("U3_HOST_EXEC_PATH")) != NULL) {

    pid = getpid();

    pf_size = strlen(u3hostexecpath) + 32;
    pid_file = g_malloc(pf_size);

    g_snprintf(pid_file, pf_size, "%s\\%d.pid", u3hostexecpath, pid);

    pid_fd = eth_open(pid_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);

    if(pid_fd != -1)
      eth_close(pid_fd);
    else {
      g_free(pid_file);
      pid_file = NULL;
    }
  }
}


void u3_deregister_pid()
{
  if(pid_file) {
    /* we don't care if we succeed or fail - u3utils may have deleted the file */
    eth_unlink(pid_file);
    
    g_free(pid_file);

    pid_file = NULL;

  }
}

char *u3_expand_device_path(char *path)
{
  return u3_change_path(path, U3_DEVICE_PATH_VAR, NULL);
}


char *u3_contract_device_path(char *path)
{
  return u3_change_path(path, NULL, U3_DEVICE_PATH_VAR);
}

static char *u3_change_path(char *path, const char *old, const char *new) 
{

  if(u3devicepath == (char*)-1) {
    /* cache the device path */
    u3devicepath = 
#ifdef _WIN32
      getenv_utf8
#else
      getenv
#endif 
      ("U3_DEVICE_PATH");
  }
  
  if(new == NULL)
    new = u3devicepath;
  if(old == NULL)
    old = u3devicepath;

  if(newpath != NULL) {
    g_free(newpath);
    newpath = NULL;
  }

  if((path != NULL) && (u3devicepath != NULL) && (strncmp(path, old, strlen(old)) == 0)) {
    
    newpath = g_strconcat(new, path + strlen(old), NULL);

    return newpath;

  }

  return path;

}
