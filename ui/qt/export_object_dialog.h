/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef EXPORT_OBJECT_DIALOG_H
#define EXPORT_OBJECT_DIALOG_H

#include <config.h>

#include <file.h>

#include <ui/qt/models/export_objects_model.h>
#include <ui/qt/widgets/export_objects_view.h>

#include "wireshark_dialog.h"

#include <QKeyEvent>

class QTreeWidgetItem;
class QAbstractButton;
class QToolButton;

namespace Ui {
class ExportObjectDialog;
}

class ExportObjectDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ExportObjectDialog(QWidget &parent, CaptureFile &cf, register_eo_t* eo);
    ~ExportObjectDialog();

public slots:
    void show();

protected:
    virtual void keyPressEvent(QKeyEvent *evt);

private slots:
    void accept();
    void captureEvent(CaptureEvent e);
    void on_buttonBox_helpRequested();
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_cmbContentType_currentIndexChanged(int index);

    void modelDataChanged(const QModelIndex &topLeft, int from, int to);
    void modelRowsReset();

    void currentHasChanged(const QModelIndex &current);
    void selectionHasChanged(const QItemSelection&);

private:
    bool mimeTypeIsPreviewable(QString mime_type);
    void saveEntry(const QModelIndex &proxyIndex, QString *tempFile = nullptr);
    void saveEntries(const QModelIndexList &proxyIndices);
    void saveCurrentEntry(QString *tempFile = Q_NULLPTR);
    void saveSelectedEntries();
    void saveDisplayedEntries();
    void saveAllEntries();

    Ui::ExportObjectDialog *eo_ui_;

    QPushButton *save_bt_;
    QToolButton *save_all_bt_;
    ExportObjectModel model_;
    ExportObjectProxyModel proxyModel_;

    QStringList contentTypes;

    void updateContentTypes();
};

#endif // EXPORT_OBJECT_DIALOG_H
