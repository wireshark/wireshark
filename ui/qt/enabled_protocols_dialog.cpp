/* enabled_protocols_dialog.cpp
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

#include "enabled_protocols_dialog.h"
#include <ui_enabled_protocols_dialog.h>

#include <errno.h>

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/disabled_protos.h>
#include <wsutil/filesystem.h>

#include "wireshark_application.h"
#include "ui/simple_dialog.h"

enum
{
    PROTOCOL_COLUMN,
    DESCRIPTION_COLUMN
};

enum
{
    enable_type_ = 1000,
    protocol_type_ = 1001,
    heuristic_type_ = 1002
};

#include <QDebug>
class EnableProtocolTreeWidgetItem : public QTreeWidgetItem
{
public:
    EnableProtocolTreeWidgetItem(QTreeWidgetItem *parent, QString proto_name, QString short_name, bool enable, int type = enable_type_) :
        QTreeWidgetItem (parent, type),
        short_name_(short_name),
        proto_name_(proto_name),
        enable_(enable)
    {
        setCheckState(PROTOCOL_COLUMN, enable_ ? Qt::Checked : Qt::Unchecked);
        setText(PROTOCOL_COLUMN, short_name_);
        setText(DESCRIPTION_COLUMN, proto_name_);
    }

    virtual bool applyValue(bool value)
    {
        bool change = (value != enable_);
        enable_ = value;
        applyValuePrivate(value);
        return change;
    }

    // Useful if we ever add "save as" / "copy as".
//    QList<QVariant> rowData() {
//        return QList<QVariant>() << short_name_ << proto_name_ << enable_;
//    }

protected:
    virtual void applyValuePrivate(gboolean value) = 0;

private:
    QString short_name_;
    QString proto_name_;
    bool enable_;
};

class ProtocolTreeWidgetItem : public EnableProtocolTreeWidgetItem
{
public:
    ProtocolTreeWidgetItem(QTreeWidgetItem *parent, const protocol_t *protocol) :
        EnableProtocolTreeWidgetItem (parent, proto_get_protocol_long_name(protocol), proto_get_protocol_short_name(protocol), proto_is_protocol_enabled(protocol), protocol_type_),
        protocol_(protocol)
    {
    }
    const protocol_t *protocol() { return protocol_; }

protected:
    virtual void applyValuePrivate(gboolean value)
    {
        proto_set_decoding(proto_get_id(protocol_), value);
    }

private:
    const protocol_t *protocol_;
};

class HeuristicTreeWidgetItem : public EnableProtocolTreeWidgetItem
{
public:
    HeuristicTreeWidgetItem(QTreeWidgetItem *parent, heur_dtbl_entry_t *heuristic) :
        EnableProtocolTreeWidgetItem (parent, heuristic->display_name, heuristic->short_name, heuristic->enabled, heuristic_type_),
        heuristic_(heuristic)
    {
    }

protected:
    virtual void applyValuePrivate(gboolean value)
    {
        heuristic_->enabled = value;
    }

private:
    heur_dtbl_entry_t *heuristic_;
};

EnabledProtocolsDialog::EnabledProtocolsDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::EnabledProtocolsDialog)
{
    ui->setupUi(this);
    loadGeometry();
    setWindowTitle(wsApp->windowTitleString(tr("Enabled Protocols")));

    void *cookie;
    protocol_t *protocol;

    //Remove "original" item
    ui->protocol_tree_->takeTopLevelItem(0);

    // Iterate over all the protocols
    for (gint i = proto_get_first_protocol(&cookie);
         i != -1;
         i = proto_get_next_protocol(&cookie))
    {
        if (proto_can_toggle_protocol(i))
        {
            protocol = find_protocol_by_id(i);
            ProtocolTreeWidgetItem* protocol_row = new ProtocolTreeWidgetItem(ui->protocol_tree_->invisibleRootItem(), protocol);

            proto_heuristic_dissector_foreach(protocol, addHeuristicItem, protocol_row);
        }
    }

    ui->protocol_tree_->expandAll();

    //make sortable
    ui->protocol_tree_->setSortingEnabled(true);
    ui->protocol_tree_->sortByColumn(PROTOCOL_COLUMN, Qt::AscendingOrder);

    // Some protocols have excessively long names. Instead of calling
    // resizeColumnToContents, pick a reasonable-ish em width and apply it.
    int one_em = ui->protocol_tree_->fontMetrics().height();
    ui->protocol_tree_->setColumnWidth(PROTOCOL_COLUMN, one_em * 18);

    //"Remove" Save button
    if (!prefs.gui_use_pref_save)
        ui->buttonBox->button(QDialogButtonBox::Save)->setHidden(true);
}

EnabledProtocolsDialog::~EnabledProtocolsDialog()
{
    delete ui;
}

void EnabledProtocolsDialog::selectProtocol(_protocol *protocol)
{
    QTreeWidgetItemIterator it(ui->protocol_tree_->invisibleRootItem());
    while (*it)
    {
        if ((*it)->type() == protocol_type_)
        {
            ProtocolTreeWidgetItem* protocol_item = dynamic_cast<ProtocolTreeWidgetItem*>((ProtocolTreeWidgetItem*)(*it));
            if (protocol_item && protocol_item->protocol() == protocol) {
                protocol_item->setSelected(true);
                ui->protocol_tree_->scrollToItem((*it));
                return;
            }
        }

        ++it;
    }
}

void EnabledProtocolsDialog::addHeuristicItem(gpointer data, gpointer user_data)
{
    heur_dtbl_entry_t* heur = (heur_dtbl_entry_t*)data;
    ProtocolTreeWidgetItem* protocol_item = (ProtocolTreeWidgetItem*)user_data;

    new HeuristicTreeWidgetItem(protocol_item, heur);
}

void EnabledProtocolsDialog::on_invert_button__clicked()
{
    QTreeWidgetItemIterator it(ui->protocol_tree_->invisibleRootItem());
    while (*it)
    {
        if ((*it)->checkState(PROTOCOL_COLUMN) == Qt::Unchecked)
        {
            (*it)->setCheckState(PROTOCOL_COLUMN, Qt::Checked);
        }
        else
        {
            (*it)->setCheckState(PROTOCOL_COLUMN, Qt::Unchecked);
        }

        ++it;
    }
}

void EnabledProtocolsDialog::on_enable_all_button__clicked()
{
    QTreeWidgetItemIterator it(ui->protocol_tree_->invisibleRootItem());
    while (*it)
    {
       (*it)->setCheckState(PROTOCOL_COLUMN, Qt::Checked);
        ++it;
    }
}

void EnabledProtocolsDialog::on_disable_all_button__clicked()
{
    QTreeWidgetItemIterator it(ui->protocol_tree_->invisibleRootItem());
    while (*it)
    {
       (*it)->setCheckState(PROTOCOL_COLUMN, Qt::Unchecked);
        ++it;
    }
}

bool EnabledProtocolsDialog::applyChanges()
{
    bool redissect = false;

    QTreeWidgetItemIterator it(ui->protocol_tree_);
    while (*it)
    {
        EnableProtocolTreeWidgetItem* it_cast = dynamic_cast<EnableProtocolTreeWidgetItem *>(*it);

        if ((*it)->checkState(PROTOCOL_COLUMN) == Qt::Checked)
        {
            redissect |= it_cast->applyValue(true);
        }
        else
        {
            redissect |= it_cast->applyValue(false);
        }
        ++it;
    }

    return redissect;
}

void EnabledProtocolsDialog::writeChanges()
{
    char *pf_dir_path;
    char *pf_path;
    int pf_save_errno;

    /* Create the directory that holds personal configuration files, if necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                  "Can't create directory\n\"%s\"\nfor disabled protocols file: %s.", pf_dir_path,
                  g_strerror(errno));
        g_free(pf_dir_path);
    }
    else
    {
        save_disabled_protos_list(&pf_path, &pf_save_errno);
        if (pf_path != NULL)
        {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                        "Could not save to your disabled protocols file\n\"%s\": %s.",
                        pf_path, g_strerror(pf_save_errno));
            g_free(pf_path);
        }

        save_disabled_heur_dissector_list(&pf_path, &pf_save_errno);
        if (pf_path != NULL)
        {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                        "Could not save to your disabled heuristic protocol file\n\"%s\": %s.",
                        pf_path, g_strerror(pf_save_errno));
            g_free(pf_path);
        }
    }
}

void EnabledProtocolsDialog::on_search_line_edit__textChanged(const QString &search_re)
{
    QTreeWidgetItemIterator it(ui->protocol_tree_);
    QRegExp regex(search_re, Qt::CaseInsensitive);
    while (*it) {
        bool hidden = true;
        if (search_re.isEmpty() || (*it)->text(PROTOCOL_COLUMN).contains(regex) || (*it)->text(DESCRIPTION_COLUMN).contains(regex)) {
            hidden = false;
        }
        (*it)->setHidden(hidden);
        ++it;
    }
}

void EnabledProtocolsDialog::on_buttonBox_accepted()
{
    if (applyChanges())
    {
        writeChanges();
        wsApp->queueAppSignal(WiresharkApplication::PacketDissectionChanged);
    }
}

#if 0
// If we ever find and fix the bug behind queueAppSignal we can re-enable
// this.
void EnabledProtocolsDialog::on_buttonBox_clicked(QAbstractButton *button)
{
    if (button == ui->buttonBox->button(QDialogButtonBox::Apply))
    {
        if (applyChanges())
        {
            // if we don't have a Save button, just save the settings now
            if (!prefs.gui_use_pref_save)
                writeChanges();

            wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
        }
    }
}
#endif

void EnabledProtocolsDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_ENABLED_PROTOCOLS_DIALOG);
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
