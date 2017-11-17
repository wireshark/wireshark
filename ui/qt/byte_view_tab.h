/* byte_view_tab.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef BYTE_VIEW_TAB_H
#define BYTE_VIEW_TAB_H

#include <config.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

#include <ui/qt/utils/field_information.h>

#include "cfile.h"

#include <QTabWidget>


#include <ui/qt/widgets/byte_view_text.h>

class ByteViewTab : public QTabWidget
{
    Q_OBJECT

public:
    explicit ByteViewTab(QWidget *parent = 0);

public slots:
    /* Set the capture file */
    void setCaptureFile(capture_file *cf);
    /* Creates the tabs and data, depends on an dissection which has already run */
    void selectedFrameChanged(int);
    /* Selects or marks a field */
    void selectedFieldChanged(FieldInformation *);

signals:
    void fieldSelected(FieldInformation *);
    void fieldHighlight(FieldInformation *);

private:
    capture_file *cap_file_;

    FieldInformation * curSelected;

    void setTabsVisible();

    ByteViewText * findByteViewTextForTvb(tvbuff_t * search, int * idx = 0);

    void addTab(const char *name = "", tvbuff_t *tvb = NULL);

protected:
    void tabInserted(int);
    void tabRemoved(int);

private slots:
    void byteViewTextHovered(int);
    void byteViewTextMarked(int);

    void connectToMainWindow();

    void captureActive(int);
};

#endif // BYTE_VIEW_TAB_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
