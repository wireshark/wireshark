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
#include <ui/qt/widgets/export_objects_view.h>
#include <ui/qt/models/export_objects_model.h>

#include <QDialogButtonBox>
#include <QMessageBox>
#include <QPushButton>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDesktopServices>

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
            this, SLOT(modelDataChanged(QModelIndex, int, int)));
    connect(&model_, SIGNAL(modelReset()), this, SLOT(modelRowsReset()));
    connect(eo_ui_->filterLine, &QLineEdit::textChanged, &proxyModel_, &ExportObjectProxyModel::setTextFilterString);
    connect(eo_ui_->objectTree, &ExportObjectsTreeView::currentIndexChanged, this, &ExportObjectDialog::currentHasChanged);

    save_bt_ = eo_ui_->buttonBox->button(QDialogButtonBox::Save);
    save_all_bt_ = eo_ui_->buttonBox->button(QDialogButtonBox::SaveAll);
    close_bt = eo_ui_->buttonBox->button(QDialogButtonBox::Close);
    if (eo_ui_->buttonBox->button(QDialogButtonBox::Open))
    {
        QPushButton * open = eo_ui_->buttonBox->button(QDialogButtonBox::Open);
        open->setText(tr("Preview"));
        open->setEnabled(false);
    }

    contentTypes << tr("All Content-Types");
    eo_ui_->cmbContentType->addItems(contentTypes);

    setWindowTitle(wsApp->windowTitleString(QStringList() << tr("Export") << tr("%1 object list").arg(proto_get_protocol_short_name(find_protocol_by_id(get_eo_proto_id(eo))))));

    if (save_bt_) save_bt_->setEnabled(false);
    if (save_all_bt_) save_all_bt_->setEnabled(false);
    if (close_bt) close_bt->setDefault(true);

    connect(&cap_file_, SIGNAL(captureEvent(CaptureEvent)),
            this, SLOT(captureEvent(CaptureEvent)));
}

ExportObjectDialog::~ExportObjectDialog()
{
    delete eo_ui_;
    model_.removeTap();
    removeTapListeners();
}

void ExportObjectDialog::currentHasChanged(QModelIndex current)
{
    if (current.isValid())
    {
        QModelIndex sibl = current.sibling(current.row(), ExportObjectModel::colPacket);
        if (eo_ui_->buttonBox->button(QDialogButtonBox::Open))
        {
            QString cont = sibl.sibling(current.row(), ExportObjectModel::colContent).data().toString();
            /* For security reasons application and unknown are disabled */
            eo_ui_->buttonBox->button(QDialogButtonBox::Open)->setEnabled(! cont.startsWith("application/") && ! cont.startsWith("unknown/"));
        }
        wsApp->gotoFrame(sibl.data().toInt());
    }
}

void ExportObjectDialog::modelDataChanged(const QModelIndex&, int from, int to)
{
    bool enabled = (model_.rowCount() > 0);
    if (save_bt_) save_bt_->setEnabled(enabled);
    if (save_all_bt_) save_all_bt_->setEnabled(enabled);

    for (int row = from; row <= to; row++)
    {
        QModelIndex idx = model_.index(row, ExportObjectModel::colContent);
        if (idx.isValid())
        {
            QString dataType = idx.data().toString();
            if (dataType.length() > 0 && ! contentTypes.contains(dataType))
            {
                contentTypes << dataType;
                contentTypes.sort(Qt::CaseInsensitive);
                QString selType = eo_ui_->cmbContentType->currentText();
                eo_ui_->cmbContentType->clear();
                eo_ui_->cmbContentType->addItems(contentTypes);
                if (contentTypes.contains(selType) )
                    eo_ui_->cmbContentType->setCurrentText(selType);
            }
        }
    }
}

void ExportObjectDialog::modelRowsReset()
{
    contentTypes.clear();
    contentTypes << tr("All Content-Types");
    eo_ui_->cmbContentType->clear();
    eo_ui_->cmbContentType->addItems(contentTypes);

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

void ExportObjectDialog::keyPressEvent(QKeyEvent *evt)
{
    if(evt->key() == Qt::Key_Enter || evt->key() == Qt::Key_Return)
        return;
    QDialog::keyPressEvent(evt);
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
    case QDialogButtonBox::Open:
    {
        QString temp;
        saveCurrentEntry(&temp);

        if (temp.length() > 0)
            QDesktopServices::openUrl(QUrl(QString("file:///").append(temp), QUrl::TolerantMode));
        break;
    }
    default: // Help, Cancel
        break;
    }
}

void ExportObjectDialog::on_cmbContentType_currentIndexChanged(int index)
{
    QString filterString = index <= 0 ? "" : eo_ui_->cmbContentType->currentText();
    proxyModel_.setContentFilterString(filterString);

}

void ExportObjectDialog::saveCurrentEntry(QString *tempFile)
{
    QDir path(wsApp->lastOpenDir());

    QModelIndex proxyIndex = eo_ui_->objectTree->currentIndex();
    if (!proxyIndex.isValid())
        return;

    QModelIndex current = proxyModel_.mapToSource(proxyIndex);
    if (!current.isValid())
        return;

    QString entry_filename = current.sibling(current.row(), ExportObjectModel::colFilename).data().toString();
    if (entry_filename.isEmpty())
        return;

    QString file_name;
    if (!tempFile)
    {
        GString *safe_filename = eo_massage_str(entry_filename.toUtf8().constData(), EXPORT_OBJECT_MAXFILELEN, 0);
        file_name = WiresharkFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Object As" UTF8_HORIZONTAL_ELLIPSIS)),
                                                safe_filename->str);
        g_string_free(safe_filename, TRUE);
    } else {
        QString path = QDir::tempPath().append("/").append(entry_filename);
        /* This means, the system must remove the file! */
        file_name = path;
        if (QFileInfo::exists(path))
            QFile::remove(path);
        *tempFile = path;
    }

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
