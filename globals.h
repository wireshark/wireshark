#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#ifndef _STDIO_H_
#include <stdio.h>
#endif

#ifndef __PACKET_H__
#include "packet.h"
#endif

#ifndef __GTK_H__
#include <gtk/gtk.h>
#endif

#ifndef __FILE_H__
#include "file.h"
#endif

#ifndef __TIMESTAMP_H__
#include "timestamp.h"
#endif

extern FILE        *data_out_file;
extern packet_info  pi;
extern capture_file cf;
extern GtkWidget   *file_sel, *packet_list, *tree_view, *byte_view, *prog_bar,
            *info_bar;
extern GdkFont     *m_r_font, *m_b_font;
extern guint        main_ctx, file_ctx;
extern gint         start_capture;
extern gchar        comp_info_str[256];
extern gchar       *ethereal_path;
extern gchar       *medium_font;
extern gchar       *bold_font;
extern gchar       *last_open_dir;

extern ts_type timestamp_type;

extern GtkStyle *item_style;

#ifdef HAVE_LIBPCAP
extern int sync_mode;	/* allow sync */
extern int sync_pipe[2]; /* used to sync father */
extern int fork_mode;	/* fork a child to do the capture */
extern int sigusr2_received;
extern int quit_after_cap; /* Makes a "capture only mode". Implies -k */
#endif

#define PF_DIR ".ethereal"

#endif
