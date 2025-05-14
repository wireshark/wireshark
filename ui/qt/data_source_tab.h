/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <config.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

#include <ui/qt/utils/field_information.h>

#include "cfile.h"

#include <QTabWidget>


#include <ui/qt/widgets/base_data_source_view.h>

class DataSourceTab : public QTabWidget
{
    Q_OBJECT

public:
    explicit DataSourceTab(QWidget *parent = 0, epan_dissect_t *edt_fixed = 0);

public slots:
    /* Set the capture file */
    void setCaptureFile(capture_file *cf);
    /* Creates the tabs and data, depends on an dissection which has already run */
    void selectedFrameChanged(QList<int>);
    /* Selects or marks a field */
    void selectedFieldChanged(FieldInformation *);
    /* Highlights field */
    void highlightedFieldChanged(FieldInformation *);
    void captureFileClosing(void);

signals:
    void fieldSelected(FieldInformation *);
    void fieldHighlight(FieldInformation *);
    void byteViewSettingsChanged(void);
    void byteViewUnmarkField(void);
    void detachData(void);

private:
    capture_file *cap_file_;
    bool is_fixed_packet_;  /* true if this byte view is related to a single
                               packet in the packet dialog and false if the
                               packet dissection context can change. */
    epan_dissect_t *edt_;   /* Packet dissection result for the currently selected packet. */
    bool disable_hover_;

    void setTabsVisible();
    BaseDataSourceView * findDataSourceViewForTvb(tvbuff_t * search, int * idx = 0);
    void addTab(const char *name = "", const struct data_source *source = nullptr);

protected:
    void tabInserted(int);
    void tabRemoved(int);

private slots:
    void byteViewTextHovered(int);
    void byteViewTextMarked(int);

    void connectToMainWindow();

    void captureActive(int);
};
