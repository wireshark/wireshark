/* prefs.c
 * Routines for handling preferences
 *
 * $Id: prefs.c,v 1.29 2000/01/03 06:29:32 guy Exp $
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/stat.h>

#include "globals.h"
#include "packet.h"
#include "file.h"
#include "prefs.h"
#include "column.h"
#include "print.h"

/* Internal functions */
static int    set_pref(gchar*, gchar*);
static GList *get_string_list(gchar *);
static void   clear_string_list(GList *);

#define PF_NAME "preferences"

static int init_prefs = 1;
static gchar *pf_path = NULL;

e_prefs prefs;

gchar	*gui_ptree_line_style_text[] =
	{ "NONE", "SOLID", "DOTTED", "TABBED", NULL };

gchar	*gui_ptree_expander_style_text[] =
	{ "NONE", "SQUARE", "TRIANGLE", "CIRCULAR", NULL };


/* Parse through a list of comma-separated, quoted strings.  Return a
   list of the string data */
static GList *
get_string_list(gchar *str) {
  enum { PRE_QUOT, IN_QUOT, POST_QUOT };

  gint      state = PRE_QUOT, i = 0, j = 0;
  gboolean  backslash = FALSE;
  gchar     cur_c, *slstr = NULL;
  GList    *sl = NULL;
  
  while ((cur_c = str[i]) != '\0') {
    if (cur_c == '"' && ! backslash) {
      switch (state) {
        case PRE_QUOT:
          state = IN_QUOT;
          slstr = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
          j = 0;
          break;
        case IN_QUOT:
          state  = POST_QUOT;
          slstr[j] = '\0';
          sl = g_list_append(sl, slstr);
          break;
        case POST_QUOT:
          clear_string_list(sl);
          return NULL;
          break;
        default:
          break;
      }
    } else if (cur_c == '\\' && ! backslash) {
      backslash = TRUE;
    } else if (cur_c == ',' && state == POST_QUOT) {
      state = PRE_QUOT;
    } else if (state == IN_QUOT && j < COL_MAX_LEN) {
      slstr[j] = str[i];
      j++;
    }
    i++;
  }
  if (state != POST_QUOT) {
    clear_string_list(sl);
  }
  return(sl);
}

void
clear_string_list(GList *sl) {
  GList *l = sl;
  
  while (l) {
    g_free(l->data);
    l = g_list_remove_link(l, l);
  }
}

/* Takes an string and a pointer to an array of strings, and a default int value.
 * The array must be terminated by a NULL string. If the string is found in the array
 * of strings, the index of that string in the array is returned. Otherwise, the
 * default value that was passed as the third argument is returned.
 */
static int
find_index_from_string_array(char *needle, char **haystack, int default_value)
{
	int i = 0;

	while (haystack[i] != NULL) {
		if (strcmp(needle, haystack[i]) == 0) {
			return i;
		}
		i++;	
	}
	return default_value;
}

/* Preferences file format:
 * - Configuration directives start at the beginning of the line, and 
 *   are terminated with a colon.
 * - Directives can be continued on the next line by preceding them with
 *   whitespace.
 *
 * Example:

# This is a comment line
print.command: lpr
print.file: /a/very/long/path/
	to/ethereal-out.ps
 *
 */

#define MAX_VAR_LEN    48
#define MAX_VAL_LEN  1024

#define DEF_NUM_COLS    6
e_prefs *
read_prefs(char **pf_path_return) {
  enum { START, IN_VAR, PRE_VAL, IN_VAL, IN_SKIP };
  FILE     *pf;
  gchar     cur_var[MAX_VAR_LEN], cur_val[MAX_VAL_LEN];
  int       got_c, state = START, i;
  gint      var_len = 0, val_len = 0, fline = 1, pline = 1;
  gboolean  got_val = FALSE;
  fmt_data *cfmt;
  gchar    *col_fmt[] = {"No.",      "%m", "Time",        "%t",
                         "Source",   "%s", "Destination", "%d",
                         "Protocol", "%p", "Info",        "%i"};

  
  /* Initialize preferences.  With any luck, these values will be
     overwritten below. */
  if (init_prefs) {
    init_prefs       = 0;
    prefs.pr_format  = PR_FMT_TEXT;
    prefs.pr_dest    = PR_DEST_CMD;
    prefs.pr_file    = g_strdup("ethereal.out");
    prefs.pr_cmd     = g_strdup("lpr");
    prefs.col_list = NULL;
    for (i = 0; i < DEF_NUM_COLS; i++) {
      cfmt = (fmt_data *) g_malloc(sizeof(fmt_data));
      cfmt->title = g_strdup(col_fmt[i * 2]);
      cfmt->fmt   = g_strdup(col_fmt[(i * 2) + 1]);
      prefs.col_list = g_list_append(prefs.col_list, cfmt);
    }
    prefs.num_cols  = DEF_NUM_COLS;
    prefs.st_client_fg.pixel =     0;
    prefs.st_client_fg.red   = 32767;
    prefs.st_client_fg.green =     0;
    prefs.st_client_fg.blue  =     0;
    prefs.st_client_bg.pixel = 65535;
    prefs.st_client_bg.red   = 65535;
    prefs.st_client_bg.green = 65535;
    prefs.st_client_bg.blue  = 65535;
    prefs.st_server_fg.pixel =     0;
    prefs.st_server_fg.red   =     0;
    prefs.st_server_fg.green =     0;
    prefs.st_server_fg.blue  = 32767;
    prefs.st_server_bg.pixel = 65535;
    prefs.st_server_bg.red   = 65535;
    prefs.st_server_bg.green = 65535;
    prefs.st_server_bg.blue  = 65535;
    prefs.gui_scrollbar_on_right = TRUE;
    prefs.gui_plist_sel_browse = FALSE;
    prefs.gui_ptree_sel_browse = FALSE;
    prefs.gui_ptree_line_style = 0;
    prefs.gui_ptree_expander_style = 1;
  }

  if (! pf_path) {
    pf_path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(PF_DIR) +
      strlen(PF_NAME) + 4);
    sprintf(pf_path, "%s/%s/%s", getenv("HOME"), PF_DIR, PF_NAME);
  }
    
  *pf_path_return = NULL;
  if ((pf = fopen(pf_path, "r")) == NULL) {
    if (errno != ENOENT)
      *pf_path_return = pf_path;
    return &prefs;
  }
    
  while ((got_c = getc(pf)) != EOF) {
    if (got_c == '\n') {
      state = START;
      fline++;
      continue;
    }
    if (var_len >= MAX_VAR_LEN) {
      g_warning ("%s line %d: Variable too long", pf_path, fline);
      state = IN_SKIP;
      var_len = 0;
      continue;
    }
    if (val_len >= MAX_VAL_LEN) {
      g_warning ("%s line %d: Value too long", pf_path, fline);
      state = IN_SKIP;
      var_len = 0;
      continue;
    }
    
    switch (state) {
      case START:
        if (isalnum(got_c)) {
          if (var_len > 0) {
            if (got_val) {
              cur_var[var_len] = '\0';
              cur_val[val_len] = '\0';
              if (! set_pref(cur_var, cur_val))
                g_warning ("%s line %d: Bogus preference", pf_path, pline);
            } else {
              g_warning ("%s line %d: Incomplete preference", pf_path, pline);
            }
          }
          state      = IN_VAR;
          got_val    = FALSE;
          cur_var[0] = got_c;
          var_len    = 1;
          pline = fline;
        } else if (isspace(got_c) && var_len > 0 && got_val) {
          state = PRE_VAL;
        } else if (got_c == '#') {
          state = IN_SKIP;
        } else {
          g_warning ("%s line %d: Malformed line", pf_path, fline);
        }
        break;
      case IN_VAR:
        if (got_c != ':') {
          cur_var[var_len] = got_c;
          var_len++;
        } else {
          state   = PRE_VAL;
          val_len = 0;
          got_val = TRUE;
        }
        break;
      case PRE_VAL:
        if (!isspace(got_c)) {
          state = IN_VAL;
          cur_val[val_len] = got_c;
          val_len++;
        }
        break;
      case IN_VAL:
        if (got_c != '#')  {
          cur_val[val_len] = got_c;
          val_len++;
        } else {
          while (isspace(cur_val[val_len]) && val_len > 0)
            val_len--;
          state = IN_SKIP;
        }
        break;
    }
  }
  if (var_len > 0) {
    if (got_val) {
      cur_var[var_len] = '\0';
      cur_val[val_len] = '\0';
      if (! set_pref(cur_var, cur_val))
        g_warning ("%s line %d: Bogus preference", pf_path, pline);
    } else {
      g_warning ("%s line %d: Incomplete preference", pf_path, pline);
    }
  }
  fclose(pf);
  
  return &prefs;
}

#define PRS_PRINT_FMT    "print.format"
#define PRS_PRINT_DEST   "print.destination"
#define PRS_PRINT_FILE   "print.file"
#define PRS_PRINT_CMD    "print.command"
#define PRS_COL_FMT      "column.format"
#define PRS_STREAM_CL_FG "stream.client.fg"
#define PRS_STREAM_CL_BG "stream.client.bg"
#define PRS_STREAM_SR_FG "stream.server.fg"
#define PRS_STREAM_SR_BG "stream.server.bg"
#define PRS_GUI_SCROLLBAR_ON_RIGHT "gui.scrollbar_on_right"
#define PRS_GUI_PLIST_SEL_BROWSE "gui.packet_list_sel_browse"
#define PRS_GUI_PTREE_SEL_BROWSE "gui.protocol_tree_sel_browse"
#define PRS_GUI_PTREE_LINE_STYLE "gui.protocol_tree_line_style"
#define PRS_GUI_PTREE_EXPANDER_STYLE "gui.protocol_tree_expander_style"

#define RED_COMPONENT(x)   ((((x) >> 16) & 0xff) * 65535 / 255)
#define GREEN_COMPONENT(x) ((((x) >>  8) & 0xff) * 65535 / 255)
#define BLUE_COMPONENT(x)   (((x)        & 0xff) * 65535 / 255)

static gchar *pr_formats[] = { "text", "postscript" };
static gchar *pr_dests[]   = { "command", "file" };

int
set_pref(gchar *pref, gchar *value) {
  GList    *col_l;
  gint      llen;
  fmt_data *cfmt;
  unsigned long int cval;

  if (strcmp(pref, PRS_PRINT_FMT) == 0) {
    if (strcmp(value, pr_formats[PR_FMT_TEXT]) == 0) {
      prefs.pr_format = PR_FMT_TEXT;
    } else if (strcmp(value, pr_formats[PR_FMT_PS]) == 0) {
      prefs.pr_format = PR_FMT_PS;
    } else {
      return 0;
    }
  } else if (strcmp(pref, PRS_PRINT_DEST) == 0) {
    if (strcmp(value, pr_dests[PR_DEST_CMD]) == 0) {
      prefs.pr_dest = PR_DEST_CMD;
    } else if (strcmp(value, pr_dests[PR_DEST_FILE]) == 0) {
      prefs.pr_dest = PR_DEST_FILE;
    } else {
      return 0;
    }
  } else if (strcmp(pref, PRS_PRINT_FILE) == 0) {
    if (prefs.pr_file) g_free(prefs.pr_file);
    prefs.pr_file = g_strdup(value);
  } else if (strcmp(pref, PRS_PRINT_CMD) == 0) {
    if (prefs.pr_cmd) g_free(prefs.pr_cmd);
    prefs.pr_cmd = g_strdup(value);
  } else if (strcmp(pref, PRS_COL_FMT) == 0) {
    if ((col_l = get_string_list(value)) && (g_list_length(col_l) % 2) == 0) {
      while (prefs.col_list) {
        cfmt = prefs.col_list->data;
        g_free(cfmt->title);
        g_free(cfmt->fmt);
        g_free(cfmt);
        prefs.col_list = g_list_remove_link(prefs.col_list, prefs.col_list);
      }
      llen             = g_list_length(col_l);
      prefs.num_cols   = llen / 2;
      col_l = g_list_first(col_l);
      while(col_l) {
        cfmt = (fmt_data *) g_malloc(sizeof(fmt_data));
        cfmt->title    = g_strdup(col_l->data);
        col_l          = col_l->next;
        cfmt->fmt      = g_strdup(col_l->data);
        col_l          = col_l->next;
        prefs.col_list = g_list_append(prefs.col_list, cfmt);
      }
      /* To do: else print some sort of error? */
    }
    clear_string_list(col_l);
  } else if (strcmp(pref, PRS_STREAM_CL_FG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.st_client_fg.pixel = 0;
    prefs.st_client_fg.red   = RED_COMPONENT(cval);
    prefs.st_client_fg.green = GREEN_COMPONENT(cval);
    prefs.st_client_fg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref, PRS_STREAM_CL_BG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.st_client_bg.pixel = 0;
    prefs.st_client_bg.red   = RED_COMPONENT(cval);
    prefs.st_client_bg.green = GREEN_COMPONENT(cval);
    prefs.st_client_bg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref, PRS_STREAM_SR_FG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.st_server_fg.pixel = 0;
    prefs.st_server_fg.red   = RED_COMPONENT(cval);
    prefs.st_server_fg.green = GREEN_COMPONENT(cval);
    prefs.st_server_fg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref, PRS_STREAM_SR_BG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.st_server_bg.pixel = 0;
    prefs.st_server_bg.red   = RED_COMPONENT(cval);
    prefs.st_server_bg.green = GREEN_COMPONENT(cval);
    prefs.st_server_bg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref, PRS_GUI_SCROLLBAR_ON_RIGHT) == 0) {
    if (strcmp(value, "TRUE") == 0) {
	    prefs.gui_scrollbar_on_right = TRUE;
    }
    else {
	    prefs.gui_scrollbar_on_right = FALSE;
    }
  } else if (strcmp(pref, PRS_GUI_PLIST_SEL_BROWSE) == 0) {
    if (strcmp(value, "TRUE") == 0) {
	    prefs.gui_plist_sel_browse = TRUE;
    }
    else {
	    prefs.gui_plist_sel_browse = FALSE;
    }
  } else if (strcmp(pref, PRS_GUI_PTREE_SEL_BROWSE) == 0) {
    if (strcmp(value, "TRUE") == 0) {
	    prefs.gui_ptree_sel_browse = TRUE;
    }
    else {
	    prefs.gui_ptree_sel_browse = FALSE;
    }
  } else if (strcmp(pref, PRS_GUI_PTREE_LINE_STYLE) == 0) {
	  prefs.gui_ptree_line_style =
		  find_index_from_string_array(value, gui_ptree_line_style_text, 0);
  } else if (strcmp(pref, PRS_GUI_PTREE_EXPANDER_STYLE) == 0) {
	  prefs.gui_ptree_expander_style =
		  find_index_from_string_array(value, gui_ptree_expander_style_text, 1);
  } else {
    return 0;
  }
  
  return 1;
}

int
write_prefs(char **pf_path_return) {
  FILE        *pf;
  struct stat  s_buf;
  
  /* To do:
   * - Split output lines longer than MAX_VAL_LEN
   * - Create a function for the preference directory check/creation
   *   so that duplication can be avoided with filter.c
   */

  if (! pf_path) {
    pf_path = (gchar *) g_malloc(strlen(getenv("HOME")) + strlen(PF_DIR) +
      strlen(PF_NAME) + 4);
  }

  sprintf(pf_path, "%s/%s", getenv("HOME"), PF_DIR);
  if (stat(pf_path, &s_buf) != 0)
#ifdef WIN32
    mkdir(pf_path);
#else
    mkdir(pf_path, 0755);
#endif

  sprintf(pf_path, "%s/%s/%s", getenv("HOME"), PF_DIR, PF_NAME);
  if ((pf = fopen(pf_path, "w")) == NULL) {
    *pf_path_return = pf_path;
    return errno;
  }
    
  fputs("# Configuration file for Ethereal " VERSION ".\n"
    "#\n"
    "# This file is regenerated each time preferences are saved within\n"
    "# Ethereal.  Making manual changes should be safe, however.\n"
    "\n"
    "######## Printing ########\n"
    "\n", pf);

  fprintf (pf, "# Can be one of \"text\" or \"postscript\".\n"
    "print.format: %s\n\n", pr_formats[prefs.pr_format]);

  fprintf (pf, "# Can be one of \"command\" or \"file\".\n"
    "print.destination: %s\n\n", pr_dests[prefs.pr_dest]);

  fprintf (pf, "# This is the file that gets written to when the "
    "destination is set to \"file\"\n"
    "%s: %s\n\n", PRS_PRINT_FILE, prefs.pr_file);

  fprintf (pf, "# Output gets piped to this command when the destination "
    "is set to \"command\"\n"
    "%s: %s\n\n", PRS_PRINT_CMD, prefs.pr_cmd);

  fprintf (pf, "# Packet list column format.  Each pair of strings consists "
    "of a column title \n# and its format.\n"
    "%s: %s\n\n", PRS_COL_FMT, col_format_to_pref_str());

  fprintf (pf, "# TCP stream window color preferences.  Each value is a six "
    "digit hexadecimal value in the form rrggbb.\n");
  fprintf (pf, "%s: %02x%02x%02x\n", PRS_STREAM_CL_FG,
    (prefs.st_client_fg.red * 255 / 65535),
    (prefs.st_client_fg.green * 255 / 65535),
    (prefs.st_client_fg.blue * 255 / 65535));
  fprintf (pf, "%s: %02x%02x%02x\n", PRS_STREAM_CL_BG,
    (prefs.st_client_bg.red * 255 / 65535),
    (prefs.st_client_bg.green * 255 / 65535),
    (prefs.st_client_bg.blue * 255 / 65535));
  fprintf (pf, "%s: %02x%02x%02x\n", PRS_STREAM_SR_FG,
    (prefs.st_server_fg.red * 255 / 65535),
    (prefs.st_server_fg.green * 255 / 65535),
    (prefs.st_server_fg.blue * 255 / 65535));
  fprintf (pf, "%s: %02x%02x%02x\n", PRS_STREAM_SR_BG,
    (prefs.st_server_bg.red * 255 / 65535),
    (prefs.st_server_bg.green * 255 / 65535),
    (prefs.st_server_bg.blue * 255 / 65535));

  fprintf(pf, "\n# Vertical scrollbars should be on right side? TRUE/FALSE\n");
  fprintf(pf, PRS_GUI_SCROLLBAR_ON_RIGHT ": %s\n",
		  prefs.gui_scrollbar_on_right == TRUE ? "TRUE" : "FALSE");

  fprintf(pf, "\n# Packet-list selection bar can be used to browse w/o selecting? TRUE/FALSE\n");
  fprintf(pf, PRS_GUI_PLIST_SEL_BROWSE ": %s\n",
		  prefs.gui_plist_sel_browse == TRUE ? "TRUE" : "FALSE");

  fprintf(pf, "\n# Protocol-tree selection bar can be used to browse w/o selecting? TRUE/FALSE\n");
  fprintf(pf, PRS_GUI_PTREE_SEL_BROWSE ": %s\n",
		  prefs.gui_ptree_sel_browse == TRUE ? "TRUE" : "FALSE");

  fprintf(pf, "\n# Protocol-tree line style. One of: NONE, SOLID, DOTTED, TABBED\n");
  fprintf(pf, PRS_GUI_PTREE_LINE_STYLE ": %s\n",
		  gui_ptree_line_style_text[prefs.gui_ptree_line_style]);

  fprintf(pf, "\n# Protocol-tree expander style. One of: NONE, SQUARE, TRIANGLE, CIRCULAR\n");
  fprintf(pf, PRS_GUI_PTREE_EXPANDER_STYLE ": %s\n",
		  gui_ptree_expander_style_text[prefs.gui_ptree_expander_style]);

  fclose(pf);

  /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
     an error indication, or maybe write to a new preferences file and
     rename that file on top of the old one only if there are not I/O
     errors. */
  return 0;
}
