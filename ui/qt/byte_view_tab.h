/* byte_view_tab.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
    explicit ByteViewTab(QWidget *parent = 0, epan_dissect_t *edt_fixed = 0);

public slots:
    /* Set the capture file */
    void setCaptureFile(capture_file *cf);
    /* Creates the tabs and data, depends on an dissection which has already run */
    void selectedFrameChanged(QList<int>);
    /* Selects or marks a field */
    void selectedFieldChanged(FieldInformation *);
    /* Highlights field */
    void highlightedFieldChanged(FieldInformation *);

signals:
    void fieldSelected(FieldInformation *);
    void fieldHighlight(FieldInformation *);
    void byteViewSettingsChanged(void);

private:
    capture_file *cap_file_;
    bool is_fixed_packet_;  /* true if this byte view is related to a single
                               packet in the packet dialog and false if the
                               packet dissection context can change. */
    epan_dissect_t *edt_;   /* Packet dissection result for the currently selected packet. */

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
