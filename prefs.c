/* prefs.c
 * Routines for handling preferences
 *
 * $Id: prefs.c,v 1.45 2001/01/03 06:55:35 guy Exp $
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
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <epan.h>
#include "globals.h"
#include "packet.h"
#include "file.h"
#include "prefs.h"
#include "column.h"
#include "print.h"
#include "util.h"

#include "prefs-int.h"

/* Internal functions */
static int    set_pref(gchar*, gchar*);
static GList *get_string_list(gchar *);
static void   clear_string_list(GList *);
static void   free_col_info(e_prefs *);

#define PF_NAME "preferences"

#define GPF_PATH	DATAFILE_DIR "/ethereal.conf"

static gboolean init_prefs = TRUE;
static gchar *pf_path = NULL;

e_prefs prefs;

gchar	*gui_ptree_line_style_text[] =
	{ "NONE", "SOLID", "DOTTED", "TABBED", NULL };

gchar	*gui_ptree_expander_style_text[] =
	{ "NONE", "SQUARE", "TRIANGLE", "CIRCULAR", NULL };

gchar	*gui_hex_dump_highlight_style_text[] =
	{ "BOLD", "INVERSE", NULL };

/*
 * List of modules with preference settings.
 */
static GList *modules;

/*
 * Register a module that will have preferences.
 * Specify the name used for the module in the preferences file, the
 * title used in the tab for it in a preferences dialog box, and a
 * routine to call back when we apply the preferences.
 */
module_t *
prefs_register_module(const char *name, const char *title,
    void (*apply_cb)(void))
{
	module_t *module;

	module = g_malloc(sizeof (module_t));
	module->name = name;
	module->title = title;
	module->apply_cb = apply_cb;
	module->prefs = NULL;	/* no preferences, to start */
	module->numprefs = 0;
	module->prefs_changed = FALSE;

	modules = g_list_append(modules, module);

	return module;
}

/*
 * Find a module, given its name.
 */
static gint
module_match(gconstpointer a, gconstpointer b)
{
	const module_t *module = a;
	const char *name = b;

	return strcmp(name, module->name);
}

static module_t *
find_module(char *name)
{
	GList *list_entry;

	list_entry = g_list_find_custom(modules, name, module_match);
	if (list_entry == NULL)
		return NULL;	/* no such module */
	return (module_t *) list_entry->data;
}

typedef struct {
	module_cb callback;
	gpointer user_data;
} module_cb_arg_t;

static void
do_module_callback(gpointer data, gpointer user_data)
{
	module_t *module = data;
	module_cb_arg_t *arg = user_data;

	(*arg->callback)(module, arg->user_data);
}

/*
 * Call a callback function, with a specified argument, for each module.
 */
void
prefs_module_foreach(module_cb callback, gpointer user_data)
{
	module_cb_arg_t arg;

	arg.callback = callback;
	arg.user_data = user_data;
	g_list_foreach(modules, do_module_callback, &arg);
}

static void
call_apply_cb(gpointer data, gpointer user_data)
{
	module_t *module = data;

	if (module->prefs_changed) {
		if (module->apply_cb != NULL)
			(*module->apply_cb)();
		module->prefs_changed = FALSE;
	}
}

/*
 * Call the "apply" callback function for each module if any of its
 * preferences have changed, and then clear the flag saying its
 * preferences have changed, as the module has been notified of that
 * fact.
 */
void
prefs_apply_all(void)
{
	g_list_foreach(modules, call_apply_cb, NULL);
}

/*
 * Register a preference in a module's list of preferences.
 */
static pref_t *
register_preference(module_t *module, const char *name, const char *title,
    const char *description)
{
	pref_t *preference;

	preference = g_malloc(sizeof (pref_t));
	preference->name = name;
	preference->title = title;
	preference->description = description;
	preference->ordinal = module->numprefs;

	module->prefs = g_list_append(module->prefs, preference);
	module->numprefs++;

	return preference;
}

/*
 * Find a preference in a module's list of preferences, given the module
 * and the preference's name.
 */
static gint
preference_match(gconstpointer a, gconstpointer b)
{
	const pref_t *pref = a;
	const char *name = b;

	return strcmp(name, pref->name);
}

static struct preference *
find_preference(module_t *module, char *name)
{
	GList *list_entry;

	list_entry = g_list_find_custom(module->prefs, name, preference_match);
	if (list_entry == NULL)
		return NULL;	/* no such preference */
	return (struct preference *) list_entry->data;
}

/*
 * Returns TRUE if the given protocol has registered preferences
 */
gboolean
prefs_is_registered_protocol(char *name)
{
	return (find_module(name) != NULL);
}

/*
 * Returns the module title of a registered protocol
 */
const char *
prefs_get_title_by_name(char *name)
{
	module_t *m = find_module(name);
	return  (m) ? m->title : NULL;
}

/*
 * Register a preference with an unsigned integral value.
 */
void
prefs_register_uint_preference(module_t *module, const char *name,
    const char *title, const char *description, guint base, guint *var)
{
	pref_t *preference;

	preference = register_preference(module, name, title, description);
	preference->type = PREF_UINT;
	preference->varp.uint = var;
	preference->info.base = base;
}

/*
 * Register a preference with an Boolean value.
 */
void
prefs_register_bool_preference(module_t *module, const char *name,
    const char *title, const char *description, gboolean *var)
{
	pref_t *preference;

	preference = register_preference(module, name, title, description);
	preference->type = PREF_BOOL;
	preference->varp.bool = var;
}

/*
 * Register a preference with an enumerated value.
 */
void
prefs_register_enum_preference(module_t *module, const char *name,
    const char *title, const char *description, gint *var,
    const enum_val_t *enumvals, gboolean radio_buttons)
{
	pref_t *preference;

	preference = register_preference(module, name, title, description);
	preference->type = PREF_ENUM;
	preference->varp.enump = var;
	preference->info.enum_info.enumvals = enumvals;
	preference->info.enum_info.radio_buttons = radio_buttons;
}

/*
 * Register a preference with a character-string value.
 */
void
prefs_register_string_preference(module_t *module, const char *name,
    const char *title, const char *description, char **var)
{
	pref_t *preference;

	preference = register_preference(module, name, title, description);
	preference->type = PREF_STRING;
	preference->varp.string = var;
	preference->saved_val.string = NULL;
}

typedef struct {
	pref_cb callback;
	gpointer user_data;
} pref_cb_arg_t;

static void
do_pref_callback(gpointer data, gpointer user_data)
{
	pref_t *pref = data;
	pref_cb_arg_t *arg = user_data;

	(*arg->callback)(pref, arg->user_data);
}

/*
 * Call a callback function, with a specified argument, for each preference
 * in a given module.
 */
void
prefs_pref_foreach(module_t *module, pref_cb callback, gpointer user_data)
{
	pref_cb_arg_t arg;

	arg.callback = callback;
	arg.user_data = user_data;
	g_list_foreach(module->prefs, do_pref_callback, &arg);
}

/*
 * Register all non-dissector modules' preferences.
 */
void
prefs_register_modules(void)
{
}

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

/*
 * Takes a string, a pointer to an array of "enum_val_t"s, and a default gint
 * value.
 * The array must be terminated by an entry with a null "name" string.
 * If the string matches a "name" strings in an entry, the value from that
 * entry is returned. Otherwise, the default value that was passed as the
 * third argument is returned.
 */
gint
find_val_for_string(const char *needle, const enum_val_t *haystack,
    gint default_value)
{
	int i = 0;

	while (haystack[i].name != NULL) {
		if (strcasecmp(needle, haystack[i].name) == 0) {
			return haystack[i].value;
		}
		i++;	
	}
	return default_value;
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

static void read_prefs_file(const char *pf_path, FILE *pf);

/* Read the preferences file, fill in "prefs", and return a pointer to it.

   If we got an error (other than "it doesn't exist") trying to read
   the global preferences file, stuff the errno into "*gpf_errno_return"
   and a pointer to the path of the file into "*gpf_path_return", and
   return NULL.

   If we got an error (other than "it doesn't exist") trying to read
   the user's preferences file, stuff the errno into "*pf_errno_return"
   and a pointer to the path of the file into "*pf_path_return", and
   return NULL. */
e_prefs *
read_prefs(int *gpf_errno_return, char **gpf_path_return,
	   int *pf_errno_return, char **pf_path_return)
{
  int       i;
  FILE     *pf;
  fmt_data *cfmt;
  gchar    *col_fmt[] = {"No.",      "%m", "Time",        "%t",
                         "Source",   "%s", "Destination", "%d",
                         "Protocol", "%p", "Info",        "%i"};

  
  if (init_prefs) {
    /* Initialize preferences to wired-in default values.
       They may be overridded by the global preferences file or the
       user's preferences file. */
    init_prefs       = FALSE;
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
    prefs.gui_hex_dump_highlight_style = 1;
#ifdef WIN32
    prefs.gui_font_name = g_strdup("-*-lucida console-medium-r-*-*-*-100-*-*-*-*-*-*");
#else
    /*
     * XXX - for now, we make the initial font name a pattern that matches
     * only ISO 8859/1 fonts, so that we don't match 2-byte fonts such
     * as ISO 10646 fonts.
     *
     * Users in locales using other one-byte fonts will have to choose
     * a different font from the preferences dialog - or put the font
     * selection in the global preferences file to make that font the
     * default for all users who don't explicitly specify a different
     * font.
     *
     * Making this a font set rather than a font has two problems:
     *
     *	1) as far as I know, you can't select font sets with the
     *	   font selection dialog;
     *
     *  2) if you use a font set, the text to be drawn must be a
     *	   multi-byte string in the appropriate locale, but
     *	   Ethereal does *NOT* guarantee that's the case - in
     *	   the hex-dump window, each character in the text portion
     *	   of the display must be a *single* byte, and in the
     *	   packet-list and protocol-tree windows, text extracted
     *	   from the packet is not necessarily in the right format.
     *
     * "Doing this right" may, for the packet-list and protocol-tree
     * windows, require that dissectors know what the locale is
     * *AND* know what locale and text representation is used in
     * the packets they're dissecting, and may be impossible in
     * the hex-dump window (except by punting and displaying only
     * ASCII characters).
     *
     * GTK+ 2.0 may simplify part of the problem, as it will, as I
     * understand it, use UTF-8-encoded Unicode as its internal
     * character set; however, we'd still have to know whatever
     * character set and encoding is used in the packet (which
     * may differ for different protocols, e.g. SMB might use
     * PC code pages for some strings and Unicode for others, whilst
     * NFS might use some UNIX character set encoding, e.g. ISO 8859/x,
     * or one of the EUC character sets for Asian languages, or one
     * of the other multi-byte character sets, or UTF-8, or...).
     *
     * I.e., as far as I can tell, "internationalizing" the packet-list,
     * protocol-tree, and hex-dump windows involves a lot more than, say,
     * just using font sets rather than fonts.
     */
    prefs.gui_font_name = g_strdup("-*-fixed-medium-r-semicondensed-*-*-120-*-*-*-*-iso8859-1");
#endif
    prefs.gui_marked_fg.pixel = 65535;
    prefs.gui_marked_fg.red   = 65535;
    prefs.gui_marked_fg.green = 65535;
    prefs.gui_marked_fg.blue  = 65535;
    prefs.gui_marked_bg.pixel =     0;
    prefs.gui_marked_bg.red   =     0;
    prefs.gui_marked_bg.green =     0;
    prefs.gui_marked_bg.blue  =     0;

  }

  /* Read the global preferences file, if it exists. */
  *gpf_path_return = NULL;
  if ((pf = fopen(GPF_PATH, "r")) != NULL) {
    /* We succeeded in opening it; read it. */
    read_prefs_file(GPF_PATH, pf);
    fclose(pf);
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *gpf_errno_return = errno;
      *gpf_path_return = GPF_PATH;
    }
  }

  /* Construct the pathname of the user's preferences file. */
  if (! pf_path) {
    pf_path = (gchar *) g_malloc(strlen(get_home_dir()) + strlen(PF_DIR) +
      strlen(PF_NAME) + 4);
    sprintf(pf_path, "%s/%s/%s", get_home_dir(), PF_DIR, PF_NAME);
  }
    
  /* Read the user's preferences file, if it exists. */
  *pf_path_return = NULL;
  if ((pf = fopen(pf_path, "r")) != NULL) {
    /* We succeeded in opening it; read it. */
    read_prefs_file(pf_path, pf);
    fclose(pf);
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *pf_errno_return = errno;
      *pf_path_return = pf_path;
    }
  }
  
  return &prefs;
}

static void
read_prefs_file(const char *pf_path, FILE *pf)
{
  enum { START, IN_VAR, PRE_VAL, IN_VAL, IN_SKIP };
  gchar     cur_var[MAX_VAR_LEN], cur_val[MAX_VAL_LEN];
  int       got_c, state = START;
  gboolean  got_val = FALSE;
  gint      var_len = 0, val_len = 0, fline = 1, pline = 1;

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
              switch (set_pref(cur_var, cur_val)) {

	      case PREFS_SET_SYNTAX_ERR:
                g_warning ("%s line %d: Syntax error", pf_path, pline);
                break;

	      case PREFS_SET_NO_SUCH_PREF:
                g_warning ("%s line %d: No such preference \"%s\"", pf_path,
				pline, cur_var);
                break;
              }
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
          while (isspace((guchar)cur_val[val_len]) && val_len > 0)
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
      switch (set_pref(cur_var, cur_val)) {

      case PREFS_SET_SYNTAX_ERR:
        g_warning ("%s line %d: Syntax error", pf_path, pline);
        break;

      case PREFS_SET_NO_SUCH_PREF:
        g_warning ("%s line %d: No such preference \"%s\"", pf_path,
			pline, cur_var);
        break;
      }
    } else {
      g_warning ("%s line %d: Incomplete preference", pf_path, pline);
    }
  }
}

/*
 * Given a string of the form "<pref name>:<pref value>", as might appear
 * as an argument to a "-o" option, parse it and set the preference in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
int
prefs_set_pref(char *prefarg)
{
	u_char *p, *colonp;
	int ret;

	colonp = strchr(prefarg, ':');
	if (colonp == NULL)
		return PREFS_SET_SYNTAX_ERR;

	p = colonp;
	*p++ = '\0';

	/*
	 * Skip over any white space (there probably won't be any, but
	 * as we allow it in the preferences file, we might as well
	 * allow it here).
	 */
	while (isspace(*p))
		p++;
	if (*p == '\0') {
		/*
		 * Put the colon back, so if our caller uses, in an
		 * error message, the string they passed us, the message
		 * looks correct.
		 */
		*colonp = ':';
		return PREFS_SET_SYNTAX_ERR;
	}

	ret = set_pref(prefarg, p);
	*colonp = ':';	/* put the colon back */
	return ret;
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
#define PRS_GUI_HEX_DUMP_HIGHLIGHT_STYLE "gui.hex_dump_highlight_style"
#define PRS_GUI_FONT_NAME "gui.font_name"
#define PRS_GUI_MARKED_FG "gui.marked_frame.fg"
#define PRS_GUI_MARKED_BG "gui.marked_frame.bg"

#define RED_COMPONENT(x)   ((((x) >> 16) & 0xff) * 65535 / 255)
#define GREEN_COMPONENT(x) ((((x) >>  8) & 0xff) * 65535 / 255)
#define BLUE_COMPONENT(x)   (((x)        & 0xff) * 65535 / 255)

static gchar *pr_formats[] = { "text", "postscript" };
static gchar *pr_dests[]   = { "command", "file" };

static int
set_pref(gchar *pref_name, gchar *value)
{
  GList    *col_l;
  gint      llen;
  fmt_data *cfmt;
  unsigned long int cval;
  guint    uval;
  gboolean bval;
  gint     enum_val;
  char     *p;
  gchar    *dotp;
  module_t *module;
  pref_t   *pref;

  if (strcmp(pref_name, PRS_PRINT_FMT) == 0) {
    if (strcmp(value, pr_formats[PR_FMT_TEXT]) == 0) {
      prefs.pr_format = PR_FMT_TEXT;
    } else if (strcmp(value, pr_formats[PR_FMT_PS]) == 0) {
      prefs.pr_format = PR_FMT_PS;
    } else {
      return PREFS_SET_SYNTAX_ERR;
    }
  } else if (strcmp(pref_name, PRS_PRINT_DEST) == 0) {
    if (strcmp(value, pr_dests[PR_DEST_CMD]) == 0) {
      prefs.pr_dest = PR_DEST_CMD;
    } else if (strcmp(value, pr_dests[PR_DEST_FILE]) == 0) {
      prefs.pr_dest = PR_DEST_FILE;
    } else {
      return PREFS_SET_SYNTAX_ERR;
    }
  } else if (strcmp(pref_name, PRS_PRINT_FILE) == 0) {
    if (prefs.pr_file) g_free(prefs.pr_file);
    prefs.pr_file = g_strdup(value);
  } else if (strcmp(pref_name, PRS_PRINT_CMD) == 0) {
    if (prefs.pr_cmd) g_free(prefs.pr_cmd);
    prefs.pr_cmd = g_strdup(value);
  } else if (strcmp(pref_name, PRS_COL_FMT) == 0) {
    if ((col_l = get_string_list(value)) && (g_list_length(col_l) % 2) == 0) {
      free_col_info(&prefs);
      prefs.col_list = NULL;
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
  } else if (strcmp(pref_name, PRS_STREAM_CL_FG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.st_client_fg.pixel = 0;
    prefs.st_client_fg.red   = RED_COMPONENT(cval);
    prefs.st_client_fg.green = GREEN_COMPONENT(cval);
    prefs.st_client_fg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref_name, PRS_STREAM_CL_BG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.st_client_bg.pixel = 0;
    prefs.st_client_bg.red   = RED_COMPONENT(cval);
    prefs.st_client_bg.green = GREEN_COMPONENT(cval);
    prefs.st_client_bg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref_name, PRS_STREAM_SR_FG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.st_server_fg.pixel = 0;
    prefs.st_server_fg.red   = RED_COMPONENT(cval);
    prefs.st_server_fg.green = GREEN_COMPONENT(cval);
    prefs.st_server_fg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref_name, PRS_STREAM_SR_BG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.st_server_bg.pixel = 0;
    prefs.st_server_bg.red   = RED_COMPONENT(cval);
    prefs.st_server_bg.green = GREEN_COMPONENT(cval);
    prefs.st_server_bg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref_name, PRS_GUI_SCROLLBAR_ON_RIGHT) == 0) {
    if (strcmp(value, "TRUE") == 0) {
	    prefs.gui_scrollbar_on_right = TRUE;
    }
    else {
	    prefs.gui_scrollbar_on_right = FALSE;
    }
  } else if (strcmp(pref_name, PRS_GUI_PLIST_SEL_BROWSE) == 0) {
    if (strcmp(value, "TRUE") == 0) {
	    prefs.gui_plist_sel_browse = TRUE;
    }
    else {
	    prefs.gui_plist_sel_browse = FALSE;
    }
  } else if (strcmp(pref_name, PRS_GUI_PTREE_SEL_BROWSE) == 0) {
    if (strcmp(value, "TRUE") == 0) {
	    prefs.gui_ptree_sel_browse = TRUE;
    }
    else {
	    prefs.gui_ptree_sel_browse = FALSE;
    }
  } else if (strcmp(pref_name, PRS_GUI_PTREE_LINE_STYLE) == 0) {
	  prefs.gui_ptree_line_style =
		  find_index_from_string_array(value, gui_ptree_line_style_text, 0);
  } else if (strcmp(pref_name, PRS_GUI_PTREE_EXPANDER_STYLE) == 0) {
	  prefs.gui_ptree_expander_style =
		  find_index_from_string_array(value, gui_ptree_expander_style_text, 1);
  } else if (strcmp(pref_name, PRS_GUI_HEX_DUMP_HIGHLIGHT_STYLE) == 0) {
	  prefs.gui_hex_dump_highlight_style =
		  find_index_from_string_array(value, gui_hex_dump_highlight_style_text, 1);
  } else if (strcmp(pref_name, PRS_GUI_FONT_NAME) == 0) {
	  if (prefs.gui_font_name != NULL)
		g_free(prefs.gui_font_name);
	  prefs.gui_font_name = g_strdup(value);
  } else if (strcmp(pref_name, PRS_GUI_MARKED_FG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.gui_marked_fg.pixel = 0;
    prefs.gui_marked_fg.red   = RED_COMPONENT(cval);
    prefs.gui_marked_fg.green = GREEN_COMPONENT(cval);
    prefs.gui_marked_fg.blue  = BLUE_COMPONENT(cval);
  } else if (strcmp(pref_name, PRS_GUI_MARKED_BG) == 0) {
    cval = strtoul(value, NULL, 16);
    prefs.gui_marked_bg.pixel = 0;
    prefs.gui_marked_bg.red   = RED_COMPONENT(cval);
    prefs.gui_marked_bg.green = GREEN_COMPONENT(cval);
    prefs.gui_marked_bg.blue  = BLUE_COMPONENT(cval);
  } else {
    /* To which module does this preference belong? */
    dotp = strchr(pref_name, '.');
    if (dotp == NULL)
      return PREFS_SET_SYNTAX_ERR;	/* no ".", so no module/name separator */
    *dotp = '\0';		/* separate module and preference name */
    module = find_module(pref_name);

    /*
     * XXX - "Diameter" rather than "diameter" was used in earlier
     * versions of Ethereal; if we didn't find the module, and its name
     * was "Diameter", look for "diameter" instead.
     */
    if (module == NULL && strcmp(pref_name, "Diameter") == 0)
      module = find_module("diameter");
    *dotp = '.';		/* put the preference string back */
    if (module == NULL)
      return PREFS_SET_NO_SUCH_PREF;	/* no such module */
    dotp++;			/* skip past separator to preference name */
    pref = find_preference(module, dotp);
    if (pref == NULL)
      return PREFS_SET_NO_SUCH_PREF;	/* no such preference */

    switch (pref->type) {

    case PREF_UINT:
      uval = strtoul(value, &p, pref->info.base);
      if (p == value || *p != '\0')
        return PREFS_SET_SYNTAX_ERR;	/* number was bad */
      if (*pref->varp.uint != uval) {
        module->prefs_changed = TRUE;
        *pref->varp.uint = uval;
      }
      break;

    case PREF_BOOL:
      /* XXX - give an error if it's neither "true" nor "false"? */
      if (strcasecmp(value, "true") == 0)
        bval = TRUE;
      else
        bval = FALSE;
      if (*pref->varp.bool != bval) {
      	module->prefs_changed = TRUE;
      	*pref->varp.bool = bval;
      }
      break;

    case PREF_ENUM:
      /* XXX - give an error if it doesn't match? */
      enum_val = find_val_for_string(value,
					pref->info.enum_info.enumvals, 1);
      if (*pref->varp.enump != enum_val) {
      	module->prefs_changed = TRUE;
      	*pref->varp.enump = enum_val;
      }
      break;

    case PREF_STRING:
      if (*pref->varp.string == NULL || strcmp(*pref->varp.string, value) != 0) {
        module->prefs_changed = TRUE;
        if (*pref->varp.string != NULL)
          g_free(*pref->varp.string);
        *pref->varp.string = g_strdup(value);
      }
      break;
    }
  }
  
  return PREFS_SET_OK;
}

typedef struct {
	module_t *module;
	FILE	*pf;
} write_pref_arg_t;

/*
 * Write out a single preference.
 */
static void
write_pref(gpointer data, gpointer user_data)
{
	pref_t *pref = data;
	write_pref_arg_t *arg = user_data;
	const enum_val_t *enum_valp;
	const char *val_string;

	fprintf(arg->pf, "\n# %s\n", pref->description);

	switch (pref->type) {

	case PREF_UINT:
		switch (pref->info.base) {

		case 10:
			fprintf(arg->pf, "# A decimal number.\n");
			fprintf(arg->pf, "%s.%s: %u\n", arg->module->name,
			    pref->name, *pref->varp.uint);
			break;

		case 8:
			fprintf(arg->pf, "# An octal number.\n");
			fprintf(arg->pf, "%s.%s: %#o\n", arg->module->name,
			    pref->name, *pref->varp.uint);
			break;

		case 16:
			fprintf(arg->pf, "# A hexadecimal number.\n");
			fprintf(arg->pf, "%s.%s: %#x\n", arg->module->name,
			    pref->name, *pref->varp.uint);
			break;
		}
		break;

	case PREF_BOOL:
		fprintf(arg->pf, "# TRUE or FALSE (case-insensitive).\n");
		fprintf(arg->pf, "%s.%s: %s\n", arg->module->name, pref->name,
		    *pref->varp.bool ? "TRUE" : "FALSE");
		break;

	case PREF_ENUM:
		fprintf(arg->pf, "# One of: ");
		enum_valp = pref->info.enum_info.enumvals;
		val_string = NULL;
		while (enum_valp->name != NULL) {
			if (enum_valp->value == *pref->varp.enump)
				val_string = enum_valp->name;
			fprintf(arg->pf, "%s", enum_valp->name);
			enum_valp++;
			if (enum_valp->name == NULL)
				fprintf(arg->pf, "\n");
			else
				fprintf(arg->pf, ", ");
		}
		fprintf(arg->pf, "# (case-insensitive).\n");
		fprintf(arg->pf, "%s.%s: %s\n", arg->module->name, pref->name,
		    val_string);
		break;

	case PREF_STRING:
		fprintf(arg->pf, "# A string.\n");
		fprintf(arg->pf, "%s.%s: %s\n", arg->module->name, pref->name,
		    *pref->varp.string);
		break;
	}
}

static void
write_module_prefs(gpointer data, gpointer user_data)
{
	write_pref_arg_t arg;

	arg.module = data;
	arg.pf = user_data;
	g_list_foreach(arg.module->prefs, write_pref, &arg);
}

/* Write out "prefs" to the user's preferences file, and return 0.

   If we got an error, stuff a pointer to the path of the preferences file
   into "*pf_path_return", and return the errno. */
int
write_prefs(char **pf_path_return)
{
  FILE        *pf;
  struct stat  s_buf;
  
  /* To do:
   * - Split output lines longer than MAX_VAL_LEN
   * - Create a function for the preference directory check/creation
   *   so that duplication can be avoided with filter.c
   */

  if (! pf_path) {
    pf_path = (gchar *) g_malloc(strlen(get_home_dir()) + strlen(PF_DIR) +
      strlen(PF_NAME) + 4);
  }

  sprintf(pf_path, "%s/%s", get_home_dir(), PF_DIR);
  if (stat(pf_path, &s_buf) != 0)
#ifdef WIN32
    mkdir(pf_path);
#else
    mkdir(pf_path, 0755);
#endif

  sprintf(pf_path, "%s/%s/%s", get_home_dir(), PF_DIR, PF_NAME);
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

  fprintf(pf, "\n# Hex dump highlight style. One of: BOLD, INVERSE\n");
  fprintf(pf, PRS_GUI_HEX_DUMP_HIGHLIGHT_STYLE ": %s\n",
		  gui_hex_dump_highlight_style_text[prefs.gui_hex_dump_highlight_style]);

  fprintf(pf, "\n# Font name for packet list, protocol tree, and hex dump panes.\n");
  fprintf(pf, PRS_GUI_FONT_NAME ": %s\n", prefs.gui_font_name);

  fprintf (pf, "\n# Color preferences for a marked frame.  Each value is a six "
    "digit hexadecimal value in the form rrggbb.\n");
  fprintf (pf, "%s: %02x%02x%02x\n", PRS_GUI_MARKED_FG,
    (prefs.gui_marked_fg.red * 255 / 65535),
    (prefs.gui_marked_fg.green * 255 / 65535),
    (prefs.gui_marked_fg.blue * 255 / 65535));
  fprintf (pf, "%s: %02x%02x%02x\n", PRS_GUI_MARKED_BG,
    (prefs.gui_marked_bg.red * 255 / 65535),
    (prefs.gui_marked_bg.green * 255 / 65535),
    (prefs.gui_marked_bg.blue * 255 / 65535));

  g_list_foreach(modules, write_module_prefs, pf);

  fclose(pf);

  /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
     an error indication, or maybe write to a new preferences file and
     rename that file on top of the old one only if there are not I/O
     errors. */
  return 0;
}

/* Copy a set of preferences. */
void
copy_prefs(e_prefs *dest, e_prefs *src)
{
  fmt_data *src_cfmt, *dest_cfmt;
  GList *entry;

  dest->pr_format = src->pr_format;
  dest->pr_dest = src->pr_dest;
  dest->pr_file = g_strdup(src->pr_file);
  dest->pr_cmd = g_strdup(src->pr_cmd);
  dest->col_list = NULL;
  for (entry = src->col_list; entry != NULL; entry = g_list_next(entry)) {
    src_cfmt = entry->data;
    dest_cfmt = (fmt_data *) g_malloc(sizeof(fmt_data));
    dest_cfmt->title = g_strdup(src_cfmt->title);
    dest_cfmt->fmt = g_strdup(src_cfmt->fmt);
    dest->col_list = g_list_append(dest->col_list, dest_cfmt);
  }
  dest->num_cols = src->num_cols;
  dest->st_client_fg = src->st_client_fg;
  dest->st_client_bg = src->st_client_bg;
  dest->st_server_fg = src->st_server_fg;
  dest->st_server_bg = src->st_server_bg;
  dest->gui_scrollbar_on_right = src->gui_scrollbar_on_right;
  dest->gui_plist_sel_browse = src->gui_plist_sel_browse;
  dest->gui_ptree_sel_browse = src->gui_ptree_sel_browse;
  dest->gui_ptree_line_style = src->gui_ptree_line_style;
  dest->gui_ptree_expander_style = src->gui_ptree_expander_style;
  dest->gui_hex_dump_highlight_style = src->gui_hex_dump_highlight_style;
  dest->gui_font_name = g_strdup(src->gui_font_name);
  dest->gui_marked_fg = src->gui_marked_fg;
  dest->gui_marked_bg = src->gui_marked_bg;
}

/* Free a set of preferences. */
void
free_prefs(e_prefs *pr)
{
  if (pr->pr_file != NULL) {
    g_free(pr->pr_file);
    pr->pr_file = NULL;
  }
  if (pr->pr_cmd != NULL) {
    g_free(pr->pr_cmd);
    pr->pr_cmd = NULL;
  }
  free_col_info(pr);
  if (pr->gui_font_name != NULL) {
    g_free(pr->gui_font_name);
    pr->gui_font_name = NULL;
  }
}

static void
free_col_info(e_prefs *pr)
{
  fmt_data *cfmt;

  while (pr->col_list != NULL) {
    cfmt = pr->col_list->data;
    g_free(cfmt->title);
    g_free(cfmt->fmt);
    g_free(cfmt);
    pr->col_list = g_list_remove_link(pr->col_list, pr->col_list);
  }
  g_list_free(pr->col_list);
  pr->col_list = NULL;
}
