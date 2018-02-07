/* capture_stop_conditions.h
 * Implementation for 'stop condition handler'.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

void init_capture_stop_conditions(void);
void cleanup_capture_stop_conditions(void);

extern const char *CND_CLASS_TIMEOUT;
extern const char *CND_CLASS_CAPTURESIZE;
extern const char *CND_CLASS_INTERVAL;

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
