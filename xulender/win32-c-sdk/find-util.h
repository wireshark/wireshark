/* find-util.h */

#ifndef FIND_UTIL_H
#define FIND_UTIL_H

void find_dialog_init(HWND hw_parent);
void find_frame_with_filter(HWND hw_parent, char *filter);
void find_previous_next(gboolean sens);
void find_previous_next_frame_with_filter(char *filter, gboolean backwards);

#endif /* find-util.h */
