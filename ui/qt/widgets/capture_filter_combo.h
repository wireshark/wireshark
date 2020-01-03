/* capture_filter_combo.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_COMBO_H
#define CAPTURE_FILTER_COMBO_H

#include <ui/qt/widgets/capture_filter_edit.h>

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
    void captureFilterSyntaxChanged(bool valid);
    void startCapture();

protected:
    virtual bool event(QEvent *event);

private:
    void updateStyleSheet();
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
