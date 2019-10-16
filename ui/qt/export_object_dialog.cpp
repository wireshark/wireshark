/* export_object_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "export_object_dialog.h"
#include <ui_export_object_dialog.h>

#include <ui/alert_box.h>
#include <wsutil/utf8_entities.h>

#include "wireshark_application.h"
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QDialogButtonBox>
#include <QMessageBox>
#include <QPushButton>


ExportObjectDialog::ExportObjectDialog(QWidget &parent, CaptureFile &cf, register_eo_t* eo) :
    WiresharkDialog(parent, cf),
    eo_ui_(new Ui::ExportObjectDialog),
    save_bt_(NULL),
    save_all_bt_(NULL),
    model_(eo, this),
    proxyModel_(this)
{
    QPushButton *close_bt;

    eo_ui_->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

    proxyModel_.setSourceModel(&model_);
    eo_ui_->objectTree->setModel(&proxyModel_);

    proxyModel_.setFilterFixedString("");
    proxyModel_.setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyModel_.setFilterKeyColumn(-1);

#if defined(Q_OS_MAC)
    eo_ui_->progressLabel->setAttribute(Qt::WA_MacSmallSize, true);
    eo_ui_->progressBar->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    connect(&model_, SIGNAL(rowsInserted(QModelIndex,int,int)),
            this, SLOT(modelDataChanged(QModelIndex)));
    connect(&model_, SIGNAL(modelReset()), this, SLOT(modelRowsReset()));
    connect(eo_ui_->filterLine, &QLineEdit::textChanged,
            &proxyModel_, &QSortFilterProxyModel::setFilterFixedString);


    save_bt_ = eo_ui_->buttonBox->button(QDialogButtonBox::Save);
    save_all_bt_ = eo_ui_->buttonBox->button(QDialogButtonBox::SaveAll);
    close_bt = eo_ui_->buttonBox->button(QDialogButtonBox::Close);

    setWindowTitle(wsApp->windowTitleString(QStringList() << tr("Export") << tr("%1 object list").arg(proto_get_protocol_short_name(find_protocol_by_id(get_eo_proto_id(eo))))));

    if (save_bt_) save_bt_->setEnabled(false);
    if (save_all_bt_) save_all_bt_->setEnabled(false);
    if (close_bt) close_bt->setDefault(true);

    connect(&cap_file_, SIGNAL(captureEvent(CaptureEvent)),
            this, SLOT(captureEvent(CaptureEvent)));

    show();
    raise();
    activateWindow();
}

ExportObjectDialog::~ExportObjectDialog()
{
    delete eo_ui_;
    model_.removeTap();
    removeTapListeners();
}

ExportObjectsTreeView* ExportObjectDialog::getExportObjectView()
{
    return eo_ui_->objectTree;
}

void ExportObjectDialog::modelDataChanged(const QModelIndex&)
{
    bool enabled = (model_.rowCount() > 0);
    if (save_bt_) save_bt_->setEnabled(enabled);
    if (save_all_bt_) save_all_bt_->setEnabled(enabled);
}

void ExportObjectDialog::modelRowsReset()
{
    if (save_bt_) save_bt_->setEnabled(false);
    if (save_all_bt_) save_all_bt_->setEnabled(false);
}

void ExportObjectDialog::show()
{
    /* Data will be gathered via a tap callback */
    if (!registerTapListener(model_.getTapListenerName(), model_.getTapData(), NULL, 0,
                             ExportObjectModel::resetTap,
                             model_.getTapPacketFunc(),
                             NULL)) {
        return;
    }

    QDialog::show();
    cap_file_.retapPackets();
    eo_ui_->progressFrame->hide();
    for (int i = 0; i < eo_ui_->objectTree->model()->columnCount(); i++)
        eo_ui_->objectTree->resizeColumnToContents(i);

    eo_ui_->objectTree->sortByColumn(ExportObjectModel::colPacket, Qt::AscendingOrder);
}

void ExportObjectDialog::accept()
{
    // Don't close the dialog.
}

void ExportObjectDialog::captureEvent(CaptureEvent e)
{
    if ((e.captureContext() == CaptureEvent::File) &&
            (e.eventType() == CaptureEvent::Closing))
    {
        close();
    }
}

void ExportObjectDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_EXPORT_OBJECT_LIST);
}

void ExportObjectDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    switch (eo_ui_->buttonBox->standardButton(button)) {
    case QDialogButtonBox::Save:
        saveCurrentEntry();
        break;
    case QDialogButtonBox::SaveAll:
        saveAllEntries();
        break;
    default: // Help, Cancel
        break;
    }
}

void ExportObjectDialog::saveCurrentEntry()
{
    QDir path(wsApp->lastOpenDir());

    QModelIndex proxyIndex = eo_ui_->objectTree->currentIndex();
    if (!proxyIndex.isValid())
        return;

    QModelIndex current = proxyModel_.mapToSource(proxyIndex);
    if (!current.isValid())
        return;

    QString entry_filename = model_.data(model_.index(current.row(), ExportObjectModel::colFilename), Qt::DisplayRole).toString();
    if (entry_filename.isEmpty())
        return;

    GString *safe_filename = eo_massage_str(entry_filename.toUtf8().constData(), EXPORT_OBJECT_MAXFILELEN, 0);
    QString file_name = WiresharkFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Object As" UTF8_HORIZONTAL_ELLIPSIS)),
                                             safe_filename->str);
    g_string_free(safe_filename, TRUE);

    model_.saveEntry(current, file_name);
}

void ExportObjectDialog::saveAllEntries()
{
    QDir save_in_dir(wsApp->lastOpenDir());
    QString save_in_path;

    //
    // We want the user to be able to specify a directory in which
    // to drop files for all the objects, not a file name.
    //
    // XXX - what we *really* want is something that asks the user
    // for an existing directory *but* lets them create a new
    // directory in the process.  That's what we get on macOS,
    // as the native dialog is used, and it supports that; does
    // that also work on Windows and with Qt's own dialog?
    //
    save_in_path = WiresharkFileDialog::getExistingDirectory(this, wsApp->windowTitleString(tr("Save All Objects In" UTF8_HORIZONTAL_ELLIPSIS)),
                                                     save_in_dir.canonicalPath(),
                                                     QFileDialog::ShowDirsOnly);

    if (save_in_path.length() < 1)
        return;

    model_.saveAllEntries(save_in_path);
}

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
