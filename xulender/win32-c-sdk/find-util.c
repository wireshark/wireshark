
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>

#include "alert_box.h"
#include "epan/strutil.h"

#include "simple_dialog.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"
#include "find-util.h"

#include "find-packet-dialog.h"

static gboolean case_sensitive = FALSE;
static gboolean summary_data = FALSE;
static gboolean decode_data = FALSE;

win32_element_t *
find_dialog_init() {
    win32_element_t *find_dlg = win32_identifier_get_str("find-packet-dialog");
    HWND             hw_find;
    win32_element_t *cur_el;

    if (! find_dlg) {
	hw_find = find_packet_dialog_dialog_create(g_hw_mainwin);
	find_dlg = (win32_element_t *) GetWindowLong(hw_find, GWL_USERDATA);
    }

    /* "Find by" buttons */

    if (!cfile.hex && !cfile.string) {
	cur_el = win32_identifier_get_str("find-packet.by.display-filter");
    } else if (cfile.hex) {
	cur_el = win32_identifier_get_str("find-packet.by.hex-value");
    } else {
	cur_el = win32_identifier_get_str("find-packet.by.string");
    }
    win32_element_assert(cur_el);
    win32_radio_set_state(cur_el, TRUE);

    /* Filter text / search string */
    cur_el = win32_identifier_get_str("find-packet.find-string");
    win32_element_assert(cur_el);
    win32_textbox_set_text(cur_el, cfile.sfilter);

    /* "Search in" buttons */
    if (summary_data) {
	cur_el = win32_identifier_get_str("find-packet.search-in.packet-list");
    } else if (decode_data) {
	cur_el = win32_identifier_get_str("find-packet.search-in.packet-details");
    } else {
	cur_el = win32_identifier_get_str("find-packet.search-in.packet-bytes");
    }
    win32_element_assert(cur_el);
    win32_radio_set_state(cur_el, TRUE);

    /* String options */
    cur_el = win32_identifier_get_str("find-packet.string-options.case-sensitive");
    win32_element_assert(cur_el);
    win32_checkbox_attach_data(cur_el, &case_sensitive);

    cur_el = win32_identifier_get_str("find-packet.string-options.char-set");
    win32_element_assert(cur_el);
    win32_menulist_set_selection(cur_el, 0);

    /* "Direction" buttons */
    if (cfile.sbackward) {
	cur_el = win32_identifier_get_str("find-packet.direction.up");
    } else {
	cur_el = win32_identifier_get_str("find-packet.direction.down");
    }
    win32_element_assert(cur_el);
    win32_radio_set_state(cur_el, TRUE);

    /* Trigger the filter and string callbacks manually */
    find_dlg_by_toggle(NULL);

    find_packet_dialog_dialog_show(find_dlg->h_wnd);

    return find_dlg;
}

BOOL CALLBACK
find_packet_dialog_dlg_proc(HWND hw_find, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch(msg) {
	case WM_INITDIALOG:
	    find_packet_dialog_handle_wm_initdialog(hw_find);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_find, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    find_packet_dialog_dialog_hide(hw_find);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}


/* oncommand procedures */

/* Command sent by element type <button>, id "find-packet.find" */
void
find_dlg_find (win32_element_t *find_btn) {
    win32_element_t *find_dlg = win32_identifier_get_str("find-packet-dialog");
    win32_element_t *cur_el, *hex_rb, *string_rb;
    gchar           *filter_text;
    int              string_type;
    search_charset_t scs_type = SCS_ASCII_AND_UNICODE;
    guint8          *bytes = NULL;
    size_t           nbytes;
    char            *string = NULL;
    dfilter_t       *sfcode;
    gboolean         found_packet;

    find_dlg = find_dialog_init();

    win32_element_assert(find_dlg);

    cur_el = win32_identifier_get_str("find-packet.find-string");
    win32_element_assert(cur_el);
    filter_text = win32_textbox_get_text(cur_el);

    cur_el = win32_identifier_get_str("find-packet.string-options.char-set");
    win32_element_assert(cur_el);
    string_type = win32_menulist_get_selection(cur_el);

    cur_el = win32_identifier_get_str("find-packet.search-in.packet-list");
    win32_element_assert(cur_el);
    summary_data = win32_radio_get_state(cur_el);

    cur_el = win32_identifier_get_str("find-packet.search-in.packet-details");
    win32_element_assert(cur_el);
    decode_data = win32_radio_get_state(cur_el);

    hex_rb = win32_identifier_get_str("find-packet.by.hex-value");
    win32_element_assert(cur_el);

    string_rb = win32_identifier_get_str("find-packet.by.string");
    win32_element_assert(cur_el);

    if (win32_radio_get_state(hex_rb)) {
	/*
	 * Hex search - scan the search string to make sure it's valid hex
	 * and to find out how many bytes there are.
	 */
	bytes = convert_string_to_hex(filter_text, &nbytes);
	if (bytes == NULL) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"You didn't specify a valid hex string.");
	    return;
	}
    } else if (win32_radio_get_state(string_rb)) {
	/*
	 * String search.
	 * Make sure we're searching for something, first.
	 */
	if (strcmp(filter_text, "") == 0) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"You didn't specify any text for which to search.");
	    return;
	}

	/*
	 * We are - get the character set type.
	 */
	switch (string_type) {
	    case 0:
		scs_type = SCS_ASCII_AND_UNICODE;
		break;
	    case 1:
		scs_type = SCS_ASCII;
		break;
	    case 2:
		scs_type = SCS_UNICODE;
		break;
	    default:
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "You didn't choose a valid character set.");
		return;
	}
	string = convert_string_case(filter_text, ! case_sensitive);
    } else {
	/*
	 * Display filter search - try to compile the filter.
	 */
	if (!dfilter_compile(filter_text, &sfcode)) {
	    /* The attempt failed; report an error. */
	    bad_dfilter_alert_box(filter_text);
	    return;
	}

	/* Was it empty? */
	if (sfcode == NULL) {
	    /* Yes - complain. */
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"You specified a filter that doesn't test anything.");
	    return;
	}
    }

    /*
     * Remember the search parameters.
     */
    if (cfile.sfilter)
	g_free(cfile.sfilter);
    cfile.sfilter = filter_text;

    cur_el = win32_identifier_get_str("find-packet.direction.up");
    win32_element_assert(cur_el);
    cfile.sbackward = win32_radio_get_state(cur_el);

    cur_el = win32_identifier_get_str("find-packet.by.hex-value");
    win32_element_assert(cur_el);
    cfile.hex = win32_radio_get_state(cur_el);

    cur_el = win32_identifier_get_str("find-packet.by.string");
    win32_element_assert(cur_el);
    cfile.string = win32_radio_get_state(cur_el);

    cfile.scs_type = scs_type;
    cfile.case_type = ! case_sensitive;
    cfile.decode_data = decode_data;
    cfile.summary_data = summary_data;

    if (cfile.hex) {
	found_packet = find_packet_data(&cfile, bytes, nbytes);
	g_free(bytes);
	if (!found_packet) {
	    /* We didn't find a packet */
	    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
		"%sFound no match!%s\n\n"
		"No packet contained those bytes.",
		simple_dialog_primary_start(), simple_dialog_primary_end());
	    g_free(bytes);
	    return;
	}
    } else if (cfile.string) {
	/* OK, what are we searching? */
	if (cfile.decode_data) {
	    /* The text in the protocol tree */
	    found_packet = find_packet_protocol_tree(&cfile, string);
	    g_free(string);
	    if (!found_packet) {
		/* We didn't find the packet. */
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
		    "%sFound no match!%s\n\n"
		    "No packet contained that string in its dissected display.",
		    simple_dialog_primary_start(), simple_dialog_primary_end());
		return;
	    }
	} else if (cfile.summary_data) {
	    /* The text in the summary line */
	    found_packet = find_packet_summary_line(&cfile, string);
	    g_free(string);
	    if (!found_packet) {
		/* We didn't find the packet. */
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
		    "%sFound no match!%s\n\n"
		    "No packet contained that string in its Info column.",
		    simple_dialog_primary_start(), simple_dialog_primary_end());
		return;
	    }
	} else {
	    /* The raw packet data */
	    found_packet = find_packet_data(&cfile, string, strlen(string));
	    g_free(string);
	    if (!found_packet) {
		/* We didn't find the packet. */
		simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
		    "%sFound no match!%s\n\n"
		    "No packet contained that string in its data.",
		    simple_dialog_primary_start(), simple_dialog_primary_end());
		return;
	    }
	}
    } else {
	found_packet = find_packet_dfilter(&cfile, sfcode);
	dfilter_free(sfcode);
	if (!found_packet) {
	    /* We didn't find a packet */
	    simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK,
		"%sFound no match!%s\n\n"
		"No packet matched that filter.",
		simple_dialog_primary_start(), simple_dialog_primary_end());
	    g_free(bytes);
	    return;
	}
    }

    find_packet_dialog_dialog_hide(find_dlg->h_wnd);
}

/* Command sent by element type <button>, id "find-packet.cancel" */
void
find_dlg_cancel (win32_element_t *find_btn) {
    win32_element_t *find_dlg = win32_identifier_get_str("find-packet-dialog");

    win32_element_assert(find_dlg);

    find_packet_dialog_dialog_hide(find_dlg->h_wnd);
}

/* Command sent by element type <button>, id "find-packet.filter" */
void
find_dlg_filter (win32_element_t *find_btn) {
}


/* Disable/enable filter and string option elements as needed */
/* Command sent by element type <radio>, id "find-packet.by.display-filter" */
/* Command sent by element type <radio>, id "find-packet.by.hex-value" */
/* Command sent by element type <radio>, id "find-packet.by.string" */
void
find_dlg_by_toggle (win32_element_t *btn_el) {
    win32_element_t *cur_el;
    gboolean         enable_filter = FALSE, enable_string = FALSE;

    cur_el = win32_identifier_get_str("find-packet.by.display-filter");
    win32_element_assert(cur_el);
    enable_filter = win32_radio_get_state(cur_el);

    cur_el = win32_identifier_get_str("find-packet.by.string");
    win32_element_assert(cur_el);
    enable_string = win32_radio_get_state(cur_el);

    /* Enable/disable filter button */
    cur_el = win32_identifier_get_str("find-packet.filter");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_filter);

    /* Enable/disable string elements */
    cur_el = win32_identifier_get_str("find-packet.search-in.packet-list");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_string);
    cur_el = win32_identifier_get_str("find-packet.search-in.packet-details");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_string);
    cur_el = win32_identifier_get_str("find-packet.search-in.packet-bytes");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_string);
    cur_el = win32_identifier_get_str("find-packet.string-options.case-sensitive");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_string);
    cur_el = win32_identifier_get_str("find-packet.string-options.char-set");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_string);
}


/* Opens the find frame dialogue with the given filter string */
void
find_frame_with_filter(HWND hw_parent, char *filter) {
    win32_element_t *cur_el;

    find_dialog_init();

    cur_el = win32_identifier_get_str("find-packet.find-string");
    win32_element_assert(cur_el);
    win32_textbox_set_text(cur_el, filter);

}

void
find_previous_next(gboolean sens) {
    guint8    *bytes;
    size_t     nbytes;
    char      *string;
    dfilter_t *sfcode;

    if (cfile.sfilter) {
	cfile.sbackward = sens;
	if (cfile.hex) {
	    bytes = convert_string_to_hex(cfile.sfilter, &nbytes);
	    if (bytes == NULL) {
		/*
		 * XXX - this shouldn't happen, as we've already successfully
		 * translated the string once.
		 */
		return;
	    }
	    find_packet_data(&cfile, bytes, nbytes);
	    g_free(bytes);
	} else if (cfile.string) {
	    string = convert_string_case(cfile.sfilter, cfile.case_type);
	    /* OK, what are we searching? */
	    if (cfile.decode_data) {
		/* The text in the protocol tree */
		find_packet_protocol_tree(&cfile, string);
	    } else if (cfile.summary_data) {
		/* The text in the summary line */
		find_packet_summary_line(&cfile, string);
	    } else {
		/* The raw packet data */
		find_packet_data(&cfile, string, strlen(string));
	    }
	    g_free(string);
	} else {
	    if (!dfilter_compile(cfile.sfilter, &sfcode)) {
		/*
		 * XXX - this shouldn't happen, as we've already successfully
		 * translated the string once.
		 */
		return;
	    }
	    if (sfcode == NULL) {
		/*
		 * XXX - this shouldn't happen, as we've already found that the
		 * string wasn't null.
		 */
		return;
	    }
	    find_packet_dfilter(&cfile, sfcode);
	    dfilter_free(sfcode);
	}
    } else
	find_dlg_find(NULL);
}

/* this function jumps to the next packet matching the filter */
void
find_previous_next_frame_with_filter(char *filter, gboolean backwards)
{
    dfilter_t *sfcode;
    gboolean sbackwards_saved;

    /* temporarily set the direction we want to search */
    sbackwards_saved = cfile.sbackward;
    cfile.sbackward = backwards;

    if (!dfilter_compile(filter, &sfcode)) {
	 /*
	  * XXX - this shouldn't happen, as the filter string is machine
	  * generated
	  */
	return;
    }
    if (sfcode == NULL) {
	/*
	 * XXX - this shouldn't happen, as the filter string is machine
	 * generated.
	 */
	return;
    }
    find_packet_dfilter(&cfile, sfcode);
    dfilter_free(sfcode);
    cfile.sbackward=sbackwards_saved;
}

// XXX - Implement find_filter_te_syntax_check_cb()



/*
 * Private functions
 */
