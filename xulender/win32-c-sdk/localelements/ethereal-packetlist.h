#ifndef __ETHEREAL_PACKETLIST_H__
#define __ETHEREAL_PACKETLIST_H__


#define ID_PACKET_LIST 5000

win32_element_t * ethereal_packetlist_new(HWND hw_parent);
void ethereal_packetlist_resize(HWND hw_packetlist, HWND hw_parent);
void ethereal_packetlist_delete(HWND hw_packetlist);
void ethereal_packetlist_init(capture_file *cfile);
void mark_current_frame();
void mark_all_frames(gboolean set);
void update_marked_frames(void);

#endif /* ethereal-packetlist.h */
