/* export_object_dialog.cpp
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

#include "export_object_dialog.h"
#include <ui_export_object_dialog.h>

#include <ui/alert_box.h>
#include <wsutil/utf8_entities.h>

#include <wsutil/filesystem.h>
#include <wsutil/str_util.h>

#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QDialogButtonBox>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>

extern "C" {

// object_list_add_entry and object_list_get_entry are defined in ui/export_object.h

void object_list_add_entry(export_object_list_t *object_list, export_object_entry_t *entry) {
    if (object_list && object_list->eod) object_list->eod->addObjectEntry(entry);
}

export_object_entry_t *object_list_get_entry(export_object_list_t *object_list, int row) {
    if (object_list && object_list->eod) return object_list->eod->objectEntry(row);
    return NULL;
}

// Called by taps

/* Runs at the beginning of tapping only */
static void
eo_reset(void *tapdata)
{
    export_object_list_t *object_list = (export_object_list_t *) tapdata;
    if (object_list && object_list->eod) object_list->eod->resetObjects();
}

} // extern "C"

enum {
    COL_PACKET,
    COL_HOSTNAME,
    COL_CONTENT_TYPE,
    COL_SIZE,
    COL_FILENAME
};

enum {
    export_object_row_type_ = 1000
};

class ExportObjectTreeWidgetItem : public QTreeWidgetItem
{
public:
    ExportObjectTreeWidgetItem(QTreeWidget *parent, export_object_entry_t *entry) :
        QTreeWidgetItem (parent, export_object_row_type_),
        entry_(entry)
    {
        // Not perfect but better than nothing.
        setTextAlignment(COL_SIZE, Qt::AlignRight);
    }
    ~ExportObjectTreeWidgetItem() {
        eo_free_entry(entry_);
    }

    export_object_entry_t *entry() { return entry_; }

    virtual QVariant data(int column, int role) const {
        if (!entry_ || role != Qt::DisplayRole) {
            return QTreeWidgetItem::data(column, role);
        }

        switch (column) {
        case COL_PACKET:
            return QString::number(entry_->pkt_num);
        case COL_HOSTNAME:
            return entry_->hostname;
        case COL_CONTENT_TYPE:
            return entry_->content_type;
        case COL_SIZE:
            return file_size_to_qstring(entry_->payload_len);
        case COL_FILENAME:
            return entry_->filename;
        default:
            break;
        }
        return QTreeWidgetItem::data(column, role);
    }

    bool operator< (const QTreeWidgetItem &other) const
    {
        if (!entry_ || other.type() != export_object_row_type_) {
            return QTreeWidgetItem::operator< (other);
        }

        const ExportObjectTreeWidgetItem *other_row = static_cast<const ExportObjectTreeWidgetItem *>(&other);

        switch (treeWidget()->sortColumn()) {
        case COL_PACKET:
            return entry_->pkt_num < other_row->entry_->pkt_num;
        case COL_SIZE:
            return entry_->payload_len < other_row->entry_->payload_len;
        default:
            break;
        }

        return QTreeWidgetItem::operator< (other);
    }

private:
    export_object_entry_t *entry_;
};

ExportObjectDialog::ExportObjectDialog(QWidget &parent, CaptureFile &cf, ObjectType object_type) :
    WiresharkDialog(parent, cf),
    eo_ui_(new Ui::ExportObjectDialog),
    save_bt_(NULL),
    save_all_bt_(NULL),
    tap_name_(NULL),
    name_(NULL),
    tap_packet_(NULL),
    eo_protocoldata_resetfn_(NULL)
{
    QPushButton *close_bt;

    eo_ui_->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

#if defined(Q_OS_MAC)
    eo_ui_->progressLabel->setAttribute(Qt::WA_MacSmallSize, true);
    eo_ui_->progressBar->setAttribute(Qt::WA_MacSmallSize, true);
#endif

    export_object_list_.eod = this;

    switch (object_type) {
    case Dicom:
        tap_name_ = "dicom_eo";
        name_ = "DICOM";
        tap_packet_ = eo_dicom_packet;
        break;
    case Http:
        tap_name_ = "http_eo";
        name_ = "HTTP";
        tap_packet_ = eo_http_packet;
        break;
    case Smb:
        tap_name_ = "smb_eo";
        name_ = "SMB";
        tap_packet_ = eo_smb_packet;
        eo_protocoldata_resetfn_ = eo_smb_cleanup;
        break;
    case Tftp:
        tap_name_ = "tftp_eo";
        name_ = "TFTP";
        tap_packet_ = eo_tftp_packet;
        break;
    }

    save_bt_ = eo_ui_->buttonBox->button(QDialogButtonBox::Save);
    save_all_bt_ = eo_ui_->buttonBox->button(QDialogButtonBox::SaveAll);
    close_bt = eo_ui_->buttonBox->button(QDialogButtonBox::Close);

    setWindowTitle(wsApp->windowTitleString(QStringList() << tr("Export") << tr("%1 object list").arg(name_)));

    if (save_bt_) save_bt_->setEnabled(false);
    if (save_all_bt_) save_all_bt_->setEnabled(false);
    if (close_bt) close_bt->setDefault(true);

    connect(&cap_file_, SIGNAL(captureFileClosing()), this, SLOT(captureFileClosing()));

    show();
    raise();
    activateWindow();
}

ExportObjectDialog::~ExportObjectDialog()
{
    delete eo_ui_;
    export_object_list_.eod = NULL;
    removeTapListeners();
}

void ExportObjectDialog::addObjectEntry(export_object_entry_t *entry)
{
    if (!entry) return;

    new ExportObjectTreeWidgetItem(eo_ui_->objectTree, entry);

    if (save_all_bt_) save_all_bt_->setEnabled(true);
}

export_object_entry_t *ExportObjectDialog::objectEntry(int row)
{
    QTreeWidgetItem *cur_ti = eo_ui_->objectTree->topLevelItem(row);
    ExportObjectTreeWidgetItem *eo_ti = dynamic_cast<ExportObjectTreeWidgetItem *>(cur_ti);

    if (eo_ti) {
        return eo_ti->entry();
    }

    return NULL;
}

void ExportObjectDialog::resetObjects()
{
    eo_ui_->objectTree->clear();
    if (eo_protocoldata_resetfn_) eo_protocoldata_resetfn_();
    if (save_bt_) save_bt_->setEnabled(false);
    if (save_all_bt_) save_all_bt_->setEnabled(false);
}

void ExportObjectDialog::show()
{
    /* Data will be gathered via a tap callback */
    if (!registerTapListener(tap_name_, &export_object_list_, NULL, 0,
                             eo_reset,
                             tap_packet_,
                             NULL)) {
        return;
    }

    QDialog::show();
    cap_file_.retapPackets();
    eo_ui_->progressFrame->hide();
    for (int i = 0; i < eo_ui_->objectTree->columnCount(); i++)
        eo_ui_->objectTree->resizeColumnToContents(i);

    eo_ui_->objectTree->setSortingEnabled(true);
    eo_ui_->objectTree->sortByColumn(COL_PACKET, Qt::AscendingOrder);

}

void ExportObjectDialog::accept()
{
    // Don't close the dialog.
}

void ExportObjectDialog::captureFileClosing()
{
    close();
}

void ExportObjectDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_EXPORT_OBJECT_LIST);
}

void ExportObjectDialog::on_objectTree_currentItemChanged(QTreeWidgetItem *item, QTreeWidgetItem *)
{
    if (!item) {
        if (save_bt_) save_bt_->setEnabled(false);
        return;
    }

    if (save_bt_) save_bt_->setEnabled(true);

    ExportObjectTreeWidgetItem *eo_ti = dynamic_cast<ExportObjectTreeWidgetItem *>(item);

    if (!eo_ti) {
        return;
    }

    export_object_entry_t *entry = eo_ti->entry();
    if (entry && !file_closed_) {
        cf_goto_frame(cap_file_.capFile(), entry->pkt_num);
    }
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
    QTreeWidgetItem *item = eo_ui_->objectTree->currentItem();
    export_object_entry_t *entry;
    QDir path(wsApp->lastOpenDir());
    QString file_name;

    ExportObjectTreeWidgetItem *eo_ti = dynamic_cast<ExportObjectTreeWidgetItem *>(item);
    if (!eo_ti) {
        return;
    }

    entry = eo_ti->entry();
    if (!entry) {
        return;
    }

    file_name = QFileDialog::getSaveFileName(this, wsApp->windowTitleString(tr("Save Object As" UTF8_HORIZONTAL_ELLIPSIS)),
                                             path.filePath(entry->filename));

    if (file_name.length() > 0) {
        eo_save_entry(file_name.toUtf8().constData(), entry, TRUE);
    }
}

#define MAXFILELEN  255
void ExportObjectDialog::saveAllEntries()
{
    int i;
    QTreeWidgetItem *item;
    QDir save_in_dir(wsApp->lastOpenDir());
    QString save_in_path;
    bool all_saved = true;

    //
    // We want the user to be able to specify a directory in which
    // to drop files for all the objects, not a file name.
    //
    // XXX - what we *really* want is something that asks the user
    // for an existing directory *but* lets them create a new
    // directory in the process.  That's what we get on OS X,
    // as the native dialog is used, and it supports that; does
    // that also work on Windows and with Qt's own dialog?
    //
    save_in_path = QFileDialog::getExistingDirectory(this, wsApp->windowTitleString(tr("Save All Objects In" UTF8_HORIZONTAL_ELLIPSIS)),
                                                     save_in_dir.canonicalPath(),
                                                     QFileDialog::ShowDirsOnly);

    if (save_in_path.length() < 1 || save_in_path.length() > MAXFILELEN) return;

    for (i = 0; (item = eo_ui_->objectTree->topLevelItem(i)) != NULL; i++) {
        int count = 0;
        gchar *save_as_fullpath = NULL;

        ExportObjectTreeWidgetItem *eo_ti = dynamic_cast<ExportObjectTreeWidgetItem *>(item);
        if (!eo_ti) {
            continue;
        }

        export_object_entry_t *entry = eo_ti->entry();
        if (!entry) continue;

        do {
            GString *safe_filename;

            g_free(save_as_fullpath);
            if (entry->filename)
                safe_filename = eo_massage_str(entry->filename,
                    MAXFILELEN - save_in_path.length(), count);
            else {
                char generic_name[256];
                const char *ext;
                ext = ct2ext(entry->content_type);
                g_snprintf(generic_name, sizeof(generic_name),
                    "object%u%s%s", entry->pkt_num, ext ? "." : "",
                    ext ? ext : "");
                safe_filename = eo_massage_str(generic_name,
                    MAXFILELEN - save_in_path.length(), count);
            }
            save_as_fullpath = g_build_filename(save_in_path.toUtf8().constData(),
                                                safe_filename->str, NULL);
            g_string_free(safe_filename, TRUE);
        } while (g_file_test(save_as_fullpath, G_FILE_TEST_EXISTS) && ++count < 1000);
        if (!eo_save_entry(save_as_fullpath, entry, FALSE))
            all_saved = false;
        g_free(save_as_fullpath);
        save_as_fullpath = NULL;
    }
    if (!all_saved) {
        QMessageBox::warning(
                    this,
                    tr("Object Export"),
                    tr("Some files could not be saved."),
                    QMessageBox::Ok
                    );
    }
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
