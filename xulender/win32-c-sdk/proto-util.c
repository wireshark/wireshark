
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "simple_dialog.h"
#include "disabled_protos.h"
#include <epan/filesystem.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"
#include "proto-util.h"

#include "enabled-protocols-dialog.h"


static void show_proto_selection(win32_element_t *listbox);
static void enabled_protocols_dlg_destroy(win32_element_t *dlg, gboolean destroy_window);
static gboolean set_proto_selection(void);
static gboolean revert_proto_selection(void);

/* list of protocols */
static GSList *protocol_list = NULL;

typedef struct protocol_data {
    char     *name;
    char     *abbrev;
    int       hfinfo_index;
    gboolean  enabled;
    gboolean  was_enabled;
    gint      row;
} protocol_data_t;

#define DISABLED "Disabled"
#define STATUS_TXT(x) ((x) ? "" : DISABLED)


win32_element_t *
enabled_protocols_dialog_init(HWND hw_mainwin) {
    win32_element_t *proto_dlg = win32_identifier_get_str("enabled-protocols-dialog");
    win32_element_t *listbox;
    HWND             hw_proto;
    SIZE             sz;

    if (! proto_dlg) {
	hw_proto = enabled_protocols_dialog_dialog_create(hw_mainwin);
	proto_dlg = (win32_element_t *) GetWindowLong(hw_proto, GWL_USERDATA);
    }

    listbox = win32_identifier_get_str("enabled-protocols.protolist");
    win32_element_assert(listbox);

    win32_get_text_size(listbox->h_wnd, "A very long protocol name", &sz);
    listbox->minwidth = sz.cx * 3;
    listbox->minheight = sz.cy * 25;

    win32_listbox_enable_checkboxes(listbox, TRUE);

    show_proto_selection(listbox);

    proto_dlg->destroy = enabled_protocols_dlg_destroy;

    enabled_protocols_dialog_dialog_show(proto_dlg->h_wnd);

    return proto_dlg;
}

BOOL CALLBACK
enabled_protocols_dialog_dlg_proc(HWND hw_proto, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch(msg) {
	case WM_INITDIALOG:
	    enabled_protocols_dialog_handle_wm_initdialog(hw_proto);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_proto, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    enabled_protocols_dialog_dialog_hide(hw_proto);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}


/* oncommand procedures */

/* Command sent by <listbox> id "enabled-protocols.protolist" */
void enabled_protocols_dialog_status_toggled (win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    protocol_data_t *p;
    gint             row;

    win32_element_assert(listbox);

    if (nmlv == NULL)
	return;

    row = nmlv->iItem;

    p = win32_listbox_get_row_data(listbox, row);
    if (p) {
	p->enabled = win32_listbox_get_row_checked(listbox, row);
    }
}

/* Command sent by <listbox> id "enabled-protocols.protolist" */
void enabled_protocols_dialog_status_dclick (win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    protocol_data_t *p;
    gint             row;

    win32_element_assert(listbox);

    if (nmlv == NULL)
	return;

    row = nmlv->iItem;

    p = win32_listbox_get_row_data(listbox, row);
    if (p) {
	if (win32_listbox_get_row_checked(listbox, row))
	    p->enabled = FALSE;
	else
	    p->enabled = TRUE;
	win32_listbox_set_row_checked(listbox, row, p->enabled);
    }
}

/* Command sent by element type <button>, id "enabled-protocols.invert" */
void
enabled_protocols_dialog_invert (win32_element_t *btn_el) {
    win32_element_t *listbox = win32_element_find_in_window(btn_el, "enabled-protocols.protolist");
    GSList *entry;

    win32_element_assert(listbox);

    for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
	protocol_data_t *p = entry->data;

	if (p->enabled)
	    p->enabled = FALSE;
	else
	    p->enabled = TRUE;

	win32_listbox_set_row_checked(listbox, p->row, p->enabled);
    }
}

/* Enable/Disable All Helper */
static void
set_active_all(win32_element_t *el, gboolean new_state)
{
    win32_element_t *listbox = win32_element_find_in_window(el, "enabled-protocols.protolist");
    GSList *entry;

    win32_element_assert(listbox);

    for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
	protocol_data_t *p = entry->data;

	p->enabled = new_state;
	win32_listbox_set_row_checked(listbox, p->row, p->enabled);
    }
}

/* Command sent by element type <button>, id "enabled-protocols.enable-all" */
void enabled_protocols_dialog_enable_all (win32_element_t *btn_el) {
    set_active_all(btn_el, TRUE);
}

/* Command sent by element type <button>, id "enabled-protocols.disable-all" */
void enabled_protocols_dialog_disable_all (win32_element_t *btn_el) {
    set_active_all(btn_el, FALSE);
}

/* Command sent by element type <button>, id "enabled-protocols.ok" */
void enabled_protocols_ok (win32_element_t *btn_el) {
    win32_element_t *proto_dlg = win32_identifier_get_str("enabled-protocols-dialog");
    gboolean redissect;

    win32_element_assert(proto_dlg);

    redissect = set_proto_selection();
    win32_element_destroy(proto_dlg, TRUE);
    if (redissect)
	redissect_packets(&cfile);
}

/* Command sent by element type <button>, id "enabled-protocols.apply" */
void enabled_protocols_apply (win32_element_t *btn_el) {
    if (set_proto_selection())
	redissect_packets(&cfile);
}

/* Command sent by element type <button>, id "enabled-protocols.save" */
void enabled_protocols_save (win32_element_t *btn_el) {
    gboolean must_redissect = FALSE;
    char *pf_dir_path;
    char *pf_path;
    int pf_save_errno;

    /* Create the directory that holds personal configuration files, if
       necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Can't create directory\n\"%s\"\nfor disabled protocols file: %s.",
		pf_dir_path, strerror(errno));
	 g_free(pf_dir_path);
    } else {
	/*
	 * make disabled/enabled protocol settings current
	 */
	must_redissect = set_proto_selection();

	save_disabled_protos_list(&pf_path, &pf_save_errno);
	if (pf_path != NULL) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Could not save to your disabled protocols file\n\"%s\": %s.",
		pf_path, strerror(pf_save_errno));
	    g_free(pf_path);
	}
    }

    if (must_redissect) {
	/* Redissect all the packets, and re-evaluate the display filter. */
	redissect_packets(&cfile);
    }
}

/* Command sent by element type <button>, id "enabled-protocols.cancel" */
void enabled_protocols_cancel (win32_element_t *btn_el) {
    win32_element_t *proto_dlg = win32_identifier_get_str("enabled-protocols-dialog");
    gboolean redissect;

    win32_element_assert(proto_dlg);

    redissect = revert_proto_selection();
    win32_element_destroy(proto_dlg, TRUE);
    if (redissect)
	redissect_packets(&cfile);
}


/*
 * Private functions
 */

gint
protocol_data_compare(gconstpointer a, gconstpointer b)
{
    const protocol_data_t *ap = (const protocol_data_t *)a;
    const protocol_data_t *bp = (const protocol_data_t *)b;

    return strcmp(ap->abbrev, bp->abbrev);
}

static void
show_proto_selection(win32_element_t *listbox) {
    GSList *entry;
    gint i;
    void *cookie;
    protocol_t *protocol;
    protocol_data_t *p;

    /* Iterate over all the protocols */
    for (i = proto_get_first_protocol(&cookie); i != -1;
	    i = proto_get_next_protocol(&cookie)) {
	if (proto_can_toggle_protocol(i)) {
	    p = g_malloc(sizeof(protocol_data_t));
	    protocol = find_protocol_by_id(i);
	    p->name = proto_get_protocol_name(i);
	    p->abbrev = proto_get_protocol_short_name(protocol);
	    p->hfinfo_index = i;
	    p->enabled = proto_is_protocol_enabled(protocol);
	    p->was_enabled = p->enabled;
	    protocol_list = g_slist_insert_sorted(protocol_list,
		    p, protocol_data_compare);
	}
    }

    for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
	p = entry->data;


	/* XXX - The preferred way to do this would be to have a check box
	 * in the first column.  GtkClists don't let us put arbitrary widgets
	 * in a cell, so we use the word "Disabled" instead.  We should be
	 * able to use check boxes in Gtk2, however.
	 */
	p->row = win32_listbox_add_item(listbox, -1, NULL, "");
	win32_listbox_set_row_checked(listbox, p->row, p->enabled);
	win32_listbox_add_cell(listbox, NULL, p->abbrev);
	win32_listbox_add_cell(listbox, NULL, p->name);
	win32_listbox_set_row_data(listbox, p->row, p);
    }

} /* show_proto_selection */

static void
enabled_protocols_dlg_destroy(win32_element_t *dlg, gboolean destroy_window) {
    GSList *entry;

    win32_element_assert(dlg);

    /* remove protocol list */
    if (protocol_list) {
	for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
	    g_free(entry->data);
	}
	g_slist_free(protocol_list);
	protocol_list = NULL;
    }
}

static gboolean
set_proto_selection() {
    GSList *entry;
    gboolean need_redissect = FALSE;

    for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
	protocol_data_t *p = entry->data;
	protocol_t *protocol;

	protocol = find_protocol_by_id(p->hfinfo_index);
	if (proto_is_protocol_enabled(protocol) != p->enabled) {
	    proto_set_decoding(p->hfinfo_index, p->enabled);
	    need_redissect = TRUE;
	}
    }

    return need_redissect;

} /* set_proto_selection */

static gboolean
revert_proto_selection(void) {
    GSList *entry;
    gboolean need_redissect = FALSE;

    /*
     * Undo all the changes we've made to protocol enable flags.
     */
    for (entry = protocol_list; entry != NULL; entry = g_slist_next(entry)) {
	protocol_data_t *p = entry->data;
	protocol_t *protocol;

	protocol = find_protocol_by_id(p->hfinfo_index);
	if (proto_is_protocol_enabled(protocol) != p->was_enabled) {
	    proto_set_decoding(p->hfinfo_index, p->was_enabled);
	    need_redissect = TRUE;
	}
    }

    return need_redissect;

} /* revert_proto_selection */