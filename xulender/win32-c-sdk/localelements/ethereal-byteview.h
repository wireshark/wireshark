
#ifndef __ETHEREAL_BYTEVIEW_H__
#define __ETHEREAL_BYTEVIEW_H__

#define ID_BYTE_VIEW 5002

win32_element_t * ethereal_byteview_new(HWND hw_parent);
void ethereal_byteview_add(epan_dissect_t *edt, win32_element_t *byteview, win32_element_t *treeview);
void ethereal_byteview_clear(win32_element_t *byteview);
const guint8 * get_byteview_data_and_length(win32_element_t *byteview, guint *data_len);
void set_notebook_page(win32_element_t *byteview, tvbuff_t *tvb);
void packet_hex_print(win32_element_t *byteview, const guint8 *pd, frame_data *fd, field_info *finfo, guint len);

#endif /* ethereal-byteview.h */
