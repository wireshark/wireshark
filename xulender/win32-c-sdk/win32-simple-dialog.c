#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <stdio.h>

#include <epan/strutil.h>

#include <windows.h>

#include "win32-globals.h"

#include "simple_dialog.h"

/* Derived from gtk/simple_dialog.c */

/*
 * Queue for messages requested before we have a main window.
 */
typedef struct {
	gint	type;
	gint	btn_mask;
	char	*message;
} queued_message_t;

static GSList *message_queue;

static int
display_simple_dialog(gint type, gint btn_mask, char *message)
{
    UINT flags = 0;;


    switch (type) {
	case ESD_TYPE_WARN:
	    flags |= MB_ICONERROR;
	break;
	case ESD_TYPE_CONFIRMATION:
	    flags |= MB_ICONQUESTION;
	break;
	case ESD_TYPE_ERROR:
	    flags |= MB_ICONWARNING;
	break;
	case ESD_TYPE_INFO:
	default:
	    flags |= MB_ICONINFORMATION;
	break;
    }

    if (type)
	flags |= MB_TASKMODAL;

    switch(btn_mask) {
	case (ESD_BTN_OK):
	    flags |= MB_OK;
	    break;
	case (ESD_BTN_CLEAR | ESD_BTN_CANCEL):
	    flags |= MB_OKCANCEL;
	    break;
	case (ESD_BTNS_YES_NO_CANCEL):
	    flags |= MB_YESNOCANCEL;
	    break;
	default:
	    g_assert_not_reached();
	    break;
    }

    return MessageBox(NULL, message, "Ethereal", flags);
}

void
display_queued_messages(void)
{
  queued_message_t *queued_message;

  while (message_queue != NULL) {
    queued_message = message_queue->data;
    message_queue = g_slist_remove(message_queue, queued_message);

    display_simple_dialog(queued_message->type, queued_message->btn_mask,
                          queued_message->message);

    g_free(queued_message->message);
    g_free(queued_message);
  }
}

/* Simple dialog function - Displays a dialog box with the supplied message
 * text.
 *
 * Args:
 * type       : One of ESD_TYPE_*.
 * btn_mask   : The value passed in determines which buttons are displayed.
 * msg_format : Sprintf-style format of the text displayed in the dialog.
 * ...        : Argument list for msg_format
 */

gpointer
vsimple_dialog(ESD_TYPE_E type, gint btn_mask, const gchar *msg_format, va_list ap)
{
    gchar            *message;
    queued_message_t *queued_message;
    int               ret;

    /* Format the message. */
    message = g_strdup_vprintf(msg_format, ap);


    /* If we don't yet have a main window, queue up the message for later
       display. */
    if (g_hw_mainwin == NULL) {
	queued_message = g_malloc(sizeof (queued_message_t));
	queued_message->type = type;
	queued_message->btn_mask = btn_mask;
	queued_message->message = message;
	message_queue = g_slist_append(message_queue, queued_message);
	return NULL;
    }

    /*
     * Do we have any queued up messages?  If so, pop them up.
     */
    display_queued_messages();

    ret = display_simple_dialog(type, btn_mask, message);

    g_free(message);

    return (gpointer) ret;
}

gpointer
simple_dialog(ESD_TYPE_E type, gint btn_mask, const gchar *msg_format, ...)
{
    va_list ap;
    gpointer ret;

    va_start(ap, msg_format);
    ret = vsimple_dialog(type, btn_mask, msg_format, ap);
    va_end(ap);
    return ret;
}

extern char *simple_dialog_primary_start(void) {
    return "";
}

extern char *simple_dialog_format_message(const char *msg) {
    char *str;

    if (msg) {
        str = xml_escape(msg);
    } else {
        str = NULL;
    }
    return str;
}

extern char *simple_dialog_primary_end(void) {
    return "";
}
