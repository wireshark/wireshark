#ifndef __ETHEREAL_SPINNER_H__
#define __ETHEREAL_SPINNER_H__


win32_element_t *ethereal_spinner_new(HWND hw_parent);
void ethereal_spinner_set_range(win32_element_t *spinner, int low, int high);
void ethereal_spinner_set_pos(win32_element_t *spinner, int pos);
int ethereal_spinner_get_pos(win32_element_t *spinner);

#define ID_SPINNER 5004

#endif /* ethereal-spinner.h */
