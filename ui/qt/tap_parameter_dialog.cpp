/* tap_parameter_dialog.cpp
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

/*
 * @file Tap parameter dialog class
 *
 * Base class for statistics dialogs. Subclasses must implement:
 * - fillTree. Called when the dialog is first displayed and when a display
 *   filter is applied. In most cases the subclass should clear the tree and
 *   retap packets here.
 * - getTreeAsString.
 */

#include "tap_parameter_dialog.h"
#include "ui_tap_parameter_dialog.h"

#include <errno.h>

#include "ui/last_open_dir.h"
#include "ui/utf8_entities.h"

#include "wsutil/file_util.h"

#include "wireshark_application.h"

#include <QClipboard>
#include <QMessageBox>
#include <QFileDialog>

// The GTK+ counterpart uses tap_param_dlg, which we don't use. If we
// need tap parameters we should probably create a TapParameterDialog
// class based on WiresharkDialog and subclass it here.

// To do:
// - Add help
// - Update to match bug 9452 / r53657

const int expand_all_threshold_ = 100; // Arbitrary

TapParameterDialog::TapParameterDialog(QWidget &parent, CaptureFile &cf, int help_topic) :
    WiresharkDialog(parent, cf),
    ui(new Ui::TapParameterDialog),
    help_topic_(help_topic)
{
    ui->setupUi(this);

    // XXX Use recent settings instead
    resize(parent.width(), parent.height() * 3 / 4);

    ui->statsTreeWidget->addAction(ui->actionCopyToClipboard);
    ui->statsTreeWidget->addAction(ui->actionSaveAs);
    ui->statsTreeWidget->setContextMenuPolicy(Qt::ActionsContextMenu);

    QPushButton *button;
    button = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    connect(button, SIGNAL(clicked()), this, SLOT(on_actionCopyToClipboard_triggered()));

    button = ui->buttonBox->addButton(tr("Save as..."), QDialogButtonBox::ActionRole);
    connect(button, SIGNAL(clicked()), this, SLOT(on_actionSaveAs_triggered()));

    if (help_topic_ < 1) {
        ui->buttonBox->button(QDialogButtonBox::Help)->hide();
    }
}

TapParameterDialog::~TapParameterDialog()
{
    delete ui;
}

QTreeWidget *TapParameterDialog::statsTreeWidget()
{
    return ui->statsTreeWidget;
}

const char *TapParameterDialog::displayFilter()
{
    return ui->displayFilterLineEdit->text().toUtf8().constData();
}

//QByteArray TapParameterDialog::getTreeAsString(st_format_type format)
//{
//    // XXX Iterate over the tree and build a QByteArray
//}

void TapParameterDialog::drawTreeItems()
{
    if (ui->statsTreeWidget->model()->rowCount() < expand_all_threshold_) {
        ui->statsTreeWidget->expandAll();
    }

    for (int col = 0; col < ui->statsTreeWidget->columnCount(); col++) {
        ui->statsTreeWidget->resizeColumnToContents(col);
    }
}

void TapParameterDialog::showEvent(QShowEvent *)
{
    fillTree();
}

void TapParameterDialog::updateWidgets()
{
    if (file_closed_) {
        ui->displayFilterLineEdit->setEnabled(false);
        ui->applyFilterButton->setEnabled(false);
    }
}

void TapParameterDialog::on_applyFilterButton_clicked()
{
    fillTree();
}

void TapParameterDialog::on_actionCopyToClipboard_triggered()
{
    wsApp->clipboard()->setText(getTreeAsString(ST_FORMAT_PLAIN));
}

void TapParameterDialog::on_actionSaveAs_triggered()
{
    QString selectedFilter;
    st_format_type format;
    const char *file_ext;
    FILE *f;
    bool success = false;
    int last_errno;

    QFileDialog SaveAsDialog(this, wsApp->windowTitleString(tr("Save Statistics As" UTF8_HORIZONTAL_ELLIPSIS)),
                                                            get_last_open_dir());
    SaveAsDialog.setNameFilter(tr("Plain text file (*.txt);;"
                                    "Comma separated values (*.csv);;"
                                    "XML document (*.xml);;"
                                    "YAML document (*.yaml)"));
    SaveAsDialog.selectNameFilter(tr("Plain text file (*.txt)"));
    SaveAsDialog.setAcceptMode(QFileDialog::AcceptSave);
    if (!SaveAsDialog.exec()) {
        return;
    }
    selectedFilter= SaveAsDialog.selectedNameFilter();
    if (selectedFilter.contains("*.yaml", Qt::CaseInsensitive)) {
        format = ST_FORMAT_YAML;
        file_ext = ".yaml";
    }
    else if (selectedFilter.contains("*.xml", Qt::CaseInsensitive)) {
        format = ST_FORMAT_XML;
        file_ext = ".xml";
    }
    else if (selectedFilter.contains("*.csv", Qt::CaseInsensitive)) {
        format = ST_FORMAT_CSV;
        file_ext = ".csv";
    }
    else {
        format = ST_FORMAT_PLAIN;
        file_ext = ".txt";
    }

    // Get selected filename and add extension of necessary
    QString file_name = SaveAsDialog.selectedFiles()[0];
    if (!file_name.endsWith(file_ext, Qt::CaseInsensitive)) {
        file_name.append(file_ext);
    }

    QByteArray tree_as_ba = getTreeAsString(format);

    // actually save the file
    f = ws_fopen (file_name.toUtf8().constData(),"w");
    last_errno= errno;
    if (f) {
        if (fputs(tree_as_ba.data(), f)!=EOF) {
            success= true;
        }
        last_errno= errno;
        fclose(f);
    }
    if (!success) {
        QMessageBox::warning(this, tr("Error saving file %1").arg(file_name),
                             g_strerror (last_errno));
    }
}

void TapParameterDialog::on_buttonBox_helpRequested()
{
    if (help_topic_ > 0) {
        wsApp->helpTopicAction((topic_action_e) help_topic_);
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
