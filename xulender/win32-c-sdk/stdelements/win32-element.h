#ifndef __WIN32_TYPES_H__
#define __WIN32_TYPES_H__

/* Corresponds to the "align" element attribute.  BOX_STRETCH is the default. */
typedef enum {
    BOX_ALIGN_START,
    BOX_ALIGN_CENTER,
    BOX_ALIGN_END,
    BOX_ALIGN_BASELINE,
    BOX_ALIGN_STRETCH
} win32_box_align_t;

/* Corresponds to the "crop" attribute.  BOX_CROP_NONE is the default. */
typedef enum {
    BOX_CROP_LEFT,
    BOX_CROP_RIGHT,
    BOX_CROP_CENTER,
    BOX_CROP_NONE
} win32_box_crop_t;

/* Corresponds to the "dir" element attribute.  BOX_DIR_LTR is the default. */
typedef enum {
    BOX_DIR_LTR,	/* Left-to-right / top-to-bottom */
    BOX_DIR_RTL	/* Right-to-left / bottom-to-top */
} win32_box_dir_t;

/* Corresponds to the "orient" attribute.  BOX_ORIENT_HORIZONTAL is the default. */
typedef enum {
    BOX_ORIENT_HORIZONTAL,
    BOX_ORIENT_VERTICAL
    /* XXX - Implement 'inherit' */
} win32_box_orient_t;

/* Corresponds to the "pack" box attribute.  BOX_PACK_START is the default. */
typedef enum {
    BOX_PACK_START,
    BOX_PACK_CENTER,
    BOX_PACK_END
} win32_box_pack_t;

/* Corresponds to the "sortdirection" element attribute.  EL_SORT_NATURAL is the default. */
typedef enum {
    EL_SORT_ASCENDING,
    EL_SORT_DESCENDING,
    EL_SORT_NATURAL
} win32_el_sortdirection_t;


/* Boxes can contain other boxes, windows (controls) and splitters.
 * Splitters are special-purpose empty windows.  Under this scheme
 * element adjacent to a splitter must have a 3-D inset or it will
 * look funny.
 */
/* XXX - This is too simplistic.  Things other than boxes (e.g. frames)
   can hold other objects.  We need something more like an is_container
   flag. */
typedef enum {
    BOX_BOX,
    BOX_WINDOW,
    BOX_SPLITTER,
    BOX_GRID,
    BOX_DECK,
    BOX_GROUPBOX
} win32_box_element_type_t;

/*
 * CSS text-align style
 */

typedef enum {
    CSS_TEXT_ALIGN_LEFT,
    CSS_TEXT_ALIGN_RIGHT,
    CSS_TEXT_ALIGN_CENTER,
    CSS_TEXT_ALIGN_JUSTIFY,
} win32_css_text_align_t;

/* Used to register callback functions for a box element */
/* Callbacks should have the form
 * LRESULT CALLBACK
 * callback_proc (
 * 	HWND hwnd,	// Element/control's HWND
 * 	UINT u_msg,	// Message identifier
 * 	WPARAM w_param,	// First message parameter
 * 	LPARAM l_param	// Second message parameter
 * );
 */

typedef struct _win32_element_t win32_element_t;

/* XXX - Should this be a full-blown GObject? */
typedef struct _win32_element_t {
    win32_box_element_type_t type;
    GList *contents;	/* Null for non-boxes */
    GData *object_data;
    void (*destroy)();

    /* Data specific to various elements.  If we ever use actual objects,
     * these should become members of their respective objects. */
    GPtrArray *rows, *columns; /* Specific to <grid> */

    /* Windows SDK attributes */
    HWND h_wnd;

    /* XUL element attributes */
    gchar *id;
    win32_box_dir_t dir;
    win32_box_crop_t crop;
    gfloat flex;
    gint flexgroup;

    win32_box_orient_t orient;
    win32_box_align_t align;
    win32_box_pack_t pack;
    win32_el_sortdirection_t sortdirection;

    /* CSS attributes */

    /* Margin dimensions - the space around elements */
    gint margin_top;
    gint margin_bottom;
    gint margin_left;
    gint margin_right;

    /* Padding dimensions - the distance from the inner edge of a box
     * to the outer edge of the box contents.
     */
    gint padding_top;
    gint padding_bottom;
    gint padding_left;
    gint padding_right;

    win32_css_text_align_t text_align;

    /* h_wnd has current height/width */

    /* Max height/width */
    gint maxheight;
    gint maxwidth;

    /* Absolute minimum height/width */
    gint minheight;
    gint minwidth;

    /* XUL element methods */
    void (*onchange)();
    void (*oncommand)();
    void (*oninput)();
} win32_element_t;

#define BOX_DEF_SIZE 50

/*
 * Initialize the identifier list.
 */
void win32_identifier_init(void);

/*
 * Associates a given data pointer to an ID.
 */
void win32_identifier_set_str(const gchar*, gpointer);

/*
 * Given an ID, return its data pointer or NULL if not found.
 */
gpointer win32_identifier_get_str(const gchar *);

/*
 * Removes a data identifier
 */
void win32_identifier_remove_str(const gchar *);

/*
 * Allocates an element and initializes its variables.
 */
win32_element_t * win32_element_new(HWND hw_el);

/*
 * Destroys an element, and optionally destroys its HWND.
 */
void win32_element_destroy(win32_element_t *el, gboolean destroy_window);

/*
 * Checks that an element is valid, and throws an assertion if it isn't.
 */
void win32_element_assert(win32_element_t *el);

/*
 * Checks that an HWND has an associated element, and that it is valid.
 */
void win32_element_hwnd_assert(HWND hwnd);

/*
 * Copies the string "id" and associates it with the given element.
 */
void win32_element_set_id(win32_element_t *el, gchar *id);

/*
 * Given an element, return the width of its h_wnd.
 */
LONG win32_element_get_width(win32_element_t *el);

/*
 * Given an element's hwnd, return its width.
 */
LONG win32_element_hwnd_get_width(HWND hwnd);

/*
 * Given an element, return the height of its h_wnd.
 */
LONG win32_element_get_height(win32_element_t *el);

/*
 * Given an element's hwnd, return its height.
 */
LONG win32_element_hwnd_get_height(HWND hwnd);

/*
 * Given an element, set the width of its h_wnd.
 */
void win32_element_set_width(win32_element_t *el, int width);

/*
 * Set the width of an element's h_wnd
 */
void win32_element_hwnd_set_width(HWND hwnd, int width);

/*
 * Given an element, set the height of its h_wnd.
 */
void win32_element_set_height(win32_element_t *el, int height);

/*
 * Set the height of an element's h_wnd
 */
void win32_element_hwnd_set_height(HWND hwnd, int height);

/*
 * Calculate the intrinsic (minimum) width or height of an element.
 */
gint win32_element_intrinsic_width(win32_element_t *el);
gint win32_element_intrinsic_height(win32_element_t *el);


/*
 * Associates the pointer to "data" to "el", keyed by "id".  NOTE: IDs
 * beginning with an underscore ("_") are reserved for private use.
 */
void win32_element_set_data(win32_element_t *el, gchar *id, gpointer data);

/*
 * Associates the pointer to "data" to "hwnd"'s element data, keyed by "id".
 */
void win32_element_hwnd_set_data(HWND hwnd, gchar *id, gpointer data);

/*
 * Fetch the data associated with "el" keyed by "id"
 */
gpointer win32_element_get_data(win32_element_t *el, gchar *id);

/*
 * Fetch the data associated with "hwnd"'s element data, keyed by "id"
 */
gpointer win32_element_hwnd_get_data(HWND hwnd, gchar *id);

/*
 * Fetch the active (! disabled) state of an element (true if active).
 * Disabled elements are shown grayed out and don't respond to events.
 */
gboolean win32_element_get_enabled(win32_element_t *el);

/*
 * Set the active state of an element (false if disabled).
 */
/*
 * XXX - Setting WS_DISABLED on a window only affects that window, and
 * not its children.  As a result, this isn't very useful in its present
 * form for compound elements.
 */
void win32_element_set_enabled(win32_element_t *el, gboolean active);

/** Find a child element, given its identifier.
 *
 * @param el The top-level element to search
 * @param id The desired element identifier
 * @return A pointer to the element if found, NULL otherwise
 */
win32_element_t *win32_element_find_child(win32_element_t *el, gchar *id);

/** Find an element in the same window, given its identifier.
 *
 * @param el An element contained by the window to search
 * @param id The desired element identifier
 * @return A pointer to the element if found, NULL otherwise
 */
win32_element_t *win32_element_find_in_window(win32_element_t *el, gchar *id);

/** Check to see if an element's HWND is visible.
 *
 * @param el The element in question.
 * @return TRUE if visible, FALSE otherwise.
 */
gboolean win32_element_is_visible(win32_element_t *el);

/*
 * Handle WM_COMMAND for various elements.
 */

void win32_element_handle_wm_command(UINT msg, WPARAM w_param, LPARAM l_param);

#endif /* win32-element.h */

