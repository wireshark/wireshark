/* filter-util.h */

#ifndef FILTER_UTIL_H
#define FILTER_UTIL_H


/**
 * Structure giving properties of the filter editing dialog box to be
 * created.
 */
typedef struct {
    gchar    *title;                /**< title of dialog box */
    gboolean wants_apply_button;    /**< dialog should have an Apply button */
    gboolean activate_on_ok;        /**< if parent text widget should be
                                        activated on "Ok" or "Apply" */
} construct_args_t;

void capture_filter_construct(win32_element_t *btn_el, win32_element_t *parent_filter_tb);
void display_filter_construct(win32_element_t *btn_el, win32_element_t *parent_filter_tb, gpointer construct_args_ptr);

void cfilter_dialog();
void dfilter_dialog();

void filter_tb_syntax_check(HWND hwnd, gchar *filter_text);

#define E_FILT_BT_PTR_KEY "filter_bt_ptr"

#endif /* filter-util.h */
