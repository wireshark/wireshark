/* u3.c
 * u3   2006 Graeme Lunt
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * Indentation logic: 2-space
 */


#include "config.h"

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

#include <wsutil/file_util.h>

#include "u3.h"


#define U3_DEVICE_PATH_VAR   "$U3_DEVICE_PATH"

static char *pid_file = NULL;
static char *u3devicepath = (char*)-1;
static gchar *newpath = NULL;

static const char *u3_change_path(const char *path, const char *old, const char *new_u3devicepath);

gboolean u3_active(void)
{

  return (
#ifdef _WIN32
      getenv_utf8
#else
      getenv
#endif
      ("U3_HOST_EXEC_PATH") != NULL);

}

void u3_runtime_info(GString *str)
{

  char *u3devicepath_lcl = NULL;
  char *u3deviceproduct = NULL;

  if((u3deviceproduct =
#ifdef _WIN32
      getenv_utf8
#else
      getenv
#endif
      ("U3_DEVICE_PRODUCT")) != NULL) {
    g_string_append(str, " from the ");
    g_string_append(str, u3deviceproduct);
  } else {
    g_string_append(str, " from a ");
  }

  g_string_append(str, " U3 device");

  if((u3devicepath_lcl =
#ifdef _WIN32
      getenv_utf8
#else
      getenv
#endif
      ("U3_DEVICE_PATH")) != NULL) {
    g_string_append(str, " in drive ");
    g_string_append(str, u3devicepath_lcl);
  }

}

void u3_register_pid(void)
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

    pf_size = (int) strlen(u3hostexecpath) + 32;
    pid_file = (char *)g_malloc(pf_size);

    g_snprintf(pid_file, pf_size, "%s\\%d.pid", u3hostexecpath, pid);

    pid_fd = ws_open(pid_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);

    if(pid_fd != -1)
      ws_close(pid_fd);
    else {
      g_free(pid_file);
      pid_file = NULL;
    }
  }
}


void u3_deregister_pid(void)
{
  if(pid_file) {
    /* we don't care if we succeed or fail - u3utils may have deleted the file */
    ws_unlink(pid_file);

    g_free(pid_file);

    pid_file = NULL;

  }
}

const char *u3_expand_device_path(const char *path)
{
  return u3_change_path(path, U3_DEVICE_PATH_VAR, NULL);
}


const char *u3_contract_device_path(char *path)
{
  return u3_change_path(path, NULL, U3_DEVICE_PATH_VAR);
}

static const char *u3_change_path(const char *path, const char *old, const char *new_u3devicepath)
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

  if(new_u3devicepath == NULL)
    new_u3devicepath = u3devicepath;
  if(old == NULL)
    old = u3devicepath;

  if(newpath != NULL) {
    g_free(newpath);
    newpath = NULL;
  }

  if((path != NULL) && (u3devicepath != NULL) && (strncmp(path, old, strlen(old)) == 0)) {

    newpath = g_strconcat(new_u3devicepath, path + strlen(old), NULL);

    return newpath;

  }

  return path;

}
