#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"

#include "statusbar.h"

#include "win32-c-sdk.h"

static gchar *packets_str = NULL;

/* Routines defined in statusbar.h */
/*
 * Push a message referring to file access onto the statusbar.
 */
void
statusbar_push_file_msg(gchar *msg) {
    win32_element_t *statusbarpanel = win32_identifier_get_str("main-info-bar");

    win32_element_assert(statusbarpanel);

    win32_statusbarpanel_push(statusbarpanel, msg);
}

/*
 * Pop a message referring to file access off the statusbar.
 */
void
statusbar_pop_file_msg(void) {
    win32_element_t *statusbarpanel = win32_identifier_get_str("main-info-bar");

    win32_element_assert(statusbarpanel);

    win32_statusbarpanel_pop(statusbarpanel);
}

/*
 * Push a message referring to the currently-selected field onto the statusbar.
 */
void
statusbar_push_field_msg(gchar *msg) {
    statusbar_push_file_msg(msg);
}

/*
 * Pop a message referring to the currently-selected field off the statusbar.
 */
void
statusbar_pop_field_msg(void) {
    statusbar_pop_file_msg();
}

/*
 * Update the packets statusbar to the current values
 */
void
packets_bar_update(void) {
    win32_element_t *statusbarpanel = win32_identifier_get_str("main-packets-bar");

    win32_element_assert(statusbarpanel);

    /* remove old status */
    if(packets_str) {
	g_free(packets_str);
	win32_statusbarpanel_pop(statusbarpanel);
    }

    /* do we have any packets? */
    if(cfile.count) {
	packets_str = g_strdup_printf(" P: %u D: %u M: %u",
	    cfile.count, cfile.displayed_count, cfile.marked_count);
    } else {
	packets_str = g_strdup(" No Packets");
    }
    win32_statusbarpanel_push(statusbarpanel, packets_str);
}