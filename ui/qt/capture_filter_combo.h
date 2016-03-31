/* capture_filter_combo.h
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

#ifndef CAPTURE_FILTER_COMBO_H
#define CAPTURE_FILTER_COMBO_H

#include "capture_filter_edit.h"

#include <QComboBox>
#include <QList>

class CaptureFilterCombo : public QComboBox
{
    Q_OBJECT
public:
    explicit CaptureFilterCombo(QWidget *parent = 0, bool plain = false);
    bool addRecentCapture(const char *filter);
    void writeRecent(FILE *rf);
    void setConflict(bool conflict = false) { cf_edit_->setConflict(conflict); }

signals:
    void interfacesChanged();
    void pushFilterSyntaxStatus(const QString&);
    void popFilterSyntaxStatus();
    void captureFilterSyntaxChanged(bool valid);
    void startCapture();

public slots:

private:
    CaptureFilterEdit *cf_edit_;

private slots:
    void saveAndRebuildFilterList();
    void rebuildFilterList();
};

#endif // CAPTURE_FILTER_COMBO_H

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
