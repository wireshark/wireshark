/* toolbar-util.h */

#ifndef TOOLBAR_UTIL_H
#define TOOLBAR_UTIL_H

void toolbar_new();

/** We have (or don't have) a capture file now.
 *
 * @param have_capture_file TRUE, if we have a capture file
 */
void set_toolbar_for_capture_file(gboolean have_capture_file);

/** We have (or don't have) an unsaved capture file now.
 *
 * @param have_unsaved_capture_file TRUE, if we have an unsaved capture file
 */
void set_toolbar_for_unsaved_capture_file(gboolean have_unsaved_capture_file);

/** We have (or don't have) a capture in progress now.
 *
 * @param have_capture_file TRUE, if we have a capture in progress file
 */
void set_toolbar_for_capture_in_progress(gboolean have_capture_file);

/** We have (or don't have) captured packets now.
 *
 * @param have_captured_packets TRUE, if we have captured packets
 */
void set_toolbar_for_captured_packets(gboolean have_captured_packets);


#endif /* toolbar-util.h */
