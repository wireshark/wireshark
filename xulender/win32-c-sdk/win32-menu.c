#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"

#include "menu.h"

/* Routines defined in menu.h */

/* Add a new recent capture filename to the "Recent Files" submenu
   (duplicates will be ignored) */
void add_menu_recent_capture_file(gchar *file) {
}

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading. */
void set_menus_for_capture_file(gboolean have_capture_file) {
}

/* Enable or disable menu items based on whether you have an unsaved
   capture file you've finished reading. */
void set_menus_for_unsaved_capture_file(gboolean have_unsaved_capture_file) {
}

/* Enable or disable menu items based on whether there's a capture in
   progress. */
void set_menus_for_capture_in_progress(gboolean capture_in_progress) {
}

/* Enable or disable menu items based on whether you have some captured
   packets. */
void set_menus_for_captured_packets(gboolean have_captured_packets) {
}

/* Enable or disable menu items based on whether a packet is selected. */
void set_menus_for_selected_packet(capture_file *cf) {
}

/* Enable or disable menu items based on whether a tree row is selected
   and and on whether a "Match Selected" can be done. */
void set_menus_for_selected_tree_row(capture_file *cf) {
}
