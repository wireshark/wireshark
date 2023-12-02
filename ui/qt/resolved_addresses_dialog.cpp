/* resolved_addresses_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "resolved_addresses_dialog.h"
#include <ui_resolved_addresses_dialog.h>

#include "config.h"

#include <glib.h>

#include "file.h"

#include "epan/addr_resolv.h"
#include <wiretap/wtap.h>

#include <QMenu>
#include <QPushButton>
#include <QTextCursor>
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QTextStream>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>

#include "capture_file.h"
#include "main_application.h"
#include <ui/util.h>

#include <ui/qt/models/astringlist_list_model.h>
#include <ui/qt/models/resolved_addresses_models.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>

const QString no_entries_ = QObject::tr("No entries.");
const QString entry_count_ = QObject::tr("%1 entries.");

ResolvedAddressesDialog::ResolvedAddressesDialog(QWidget *parent, QString captureFile, wtap* wth) :
    GeometryStateDialog(parent),
    ui(new Ui::ResolvedAddressesDialog),
    file_name_(tr("[no file]"))
{
    ui->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

    QStringList title_parts = QStringList() << tr("Resolved Addresses");

    QPushButton *button;
    button = ui->buttonBox->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
    button->setMenu(createCopyMenu(button));
    //connect(button, &QPushButton::clicked, this, &ResolvedAddressesDialog::copyToClipboard);

    button = ui->buttonBox->addButton(tr("Save as…"), QDialogButtonBox::ActionRole);
    connect(button, &QPushButton::clicked, this, &ResolvedAddressesDialog::saveAs);

    if (!captureFile.isEmpty()) {
        file_name_ = captureFile;
        title_parts << file_name_;
    }
    setWindowTitle(mainApp->windowTitleString(title_parts));

    ui->plainTextEdit->setFont(mainApp->monospaceFont());
    ui->plainTextEdit->setReadOnly(true);
    ui->plainTextEdit->setWordWrapMode(QTextOption::NoWrap);

    if (wth) {
        // might return null
        wtap_block_t nrb_hdr;

        /*
            * XXX - support multiple NRBs.
            */
        nrb_hdr = wtap_file_get_nrb(wth);
        if (nrb_hdr != NULL) {
            char *str;

            /*
                * XXX - support multiple comments.
                */
            if (wtap_block_get_nth_string_option_value(nrb_hdr, OPT_COMMENT, 0, &str) == WTAP_OPTTYPE_SUCCESS) {
                comment_ = str;
            }
        }
    }

    fillBlocks();

    ethSortModel = new AStringListListSortFilterProxyModel(this);
    ethTypeModel = new AStringListListSortFilterProxyModel(this);
    EthernetAddressModel * ethModel = new EthernetAddressModel(this);
    ethSortModel->setSourceModel(ethModel);
    ethSortModel->setColumnsToFilter(QList<int>() << 1 << 2);
    ethSortModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    ethTypeModel->setSourceModel(ethSortModel);
    ethTypeModel->setColumnToFilter(0);
    ethTypeModel->setColumnToHide(0);
    ui->tblAddresses->setModel(ethTypeModel);
    ui->tblAddresses->resizeColumnsToContents();
    ui->tblAddresses->horizontalHeader()->setStretchLastSection(true);
    ui->tblAddresses->sortByColumn(1, Qt::AscendingOrder);
    ui->cmbDataType->addItems(ethModel->filterValues());

    portSortModel = new AStringListListSortFilterProxyModel(this);
    portTypeModel = new AStringListListSortFilterProxyModel(this);
    PortsModel * portModel = new PortsModel(this);
    portSortModel->setSourceModel(portModel);
    portSortModel->setColumnAsNumeric(PORTS_COL_PORT);
    portSortModel->setColumnsToFilter(QList<int>() << PORTS_COL_NAME << PORTS_COL_PROTOCOL);
    portSortModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    portTypeModel->setSourceModel(portSortModel);
    portTypeModel->setColumnToFilter(PORTS_COL_PROTOCOL);
    portTypeModel->setColumnAsNumeric(PORTS_COL_PORT);
    ui->tblPorts->setModel(portTypeModel);
    ui->tblPorts->resizeColumnsToContents();
    ui->tblPorts->horizontalHeader()->setStretchLastSection(true);
    ui->tblPorts->sortByColumn(PORTS_COL_PORT, Qt::AscendingOrder);
    ui->cmbPortFilterType->addItems(portModel->filterValues());

    connect(ui->tabWidget, &QTabWidget::currentChanged, this, &ResolvedAddressesDialog::tabChanged);
}

ResolvedAddressesDialog::~ResolvedAddressesDialog()
{
    delete ui;
}

void ResolvedAddressesDialog::tabChanged(int index)
{
    bool enable_save = true;
    QWidget *currentTab = ui->tabWidget->widget(index);
    if (currentTab == nullptr || currentTab->findChild<QTableView*>() == nullptr) {
        // Saving the NRB comments tab is not supported yet.
        // Note it has a context menu anyway that allows copying,
        // and no one ever uses NRB comments (and this dialog only
        // shows the first in the first NRB) anyway.
        enable_save = false;
    }
    foreach (QAbstractButton *button, ui->buttonBox->buttons()) {
        if (ui->buttonBox->buttonRole(button) == QDialogButtonBox::ActionRole) {
            button->setEnabled(enable_save);
        }
    }
}

void ResolvedAddressesDialog::on_cmbDataType_currentIndexChanged(int index)
{
    if (! ethSortModel)
        return;

    QString filter = ui->cmbDataType->itemText(index);
    if (index == 0)
    {
        filter.clear();
        ethTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterNone, 0);
    }
    else
        ethTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterByEquivalent, 0);
    ethTypeModel->setFilter(filter);
}

void ResolvedAddressesDialog::on_txtSearchFilter_textChanged(QString)
{
    QString filter = ui->txtSearchFilter->text();
    if (!ethSortModel || (!filter.isEmpty() && filter.length() < 3))
        return;

    ethSortModel->setFilter(filter);
}

void ResolvedAddressesDialog::on_cmbPortFilterType_currentIndexChanged(int index)
{
    if (! portSortModel)
        return;

    QString filter = ui->cmbPortFilterType->itemText(index);
    if (index == 0)
    {
        filter.clear();
        portTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterNone, PORTS_COL_PROTOCOL);
    }
    else
        portTypeModel->setFilterType(AStringListListSortFilterProxyModel::FilterByEquivalent, PORTS_COL_PROTOCOL);
    portTypeModel->setFilter(filter);
}

void ResolvedAddressesDialog::on_txtPortFilter_textChanged(QString val)
{
    if (! portSortModel)
        return;

    portSortModel->setFilter(val);
}

void ResolvedAddressesDialog::changeEvent(QEvent *event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            ui->retranslateUi(this);
            fillBlocks();
            break;
        default:
            break;
        }
    }
    QDialog::changeEvent(event);
}

void ResolvedAddressesDialog::fillBlocks()
{
    setUpdatesEnabled(false);
    ui->plainTextEdit->clear();

    QString lines;
    ui->plainTextEdit->appendPlainText(tr("# Resolved addresses found in %1").arg(file_name_));

    if (ui->actionComment->isChecked()) {
        lines = "\n";
        lines.append(tr("# Comments\n#\n# "));
        if (!comment_.isEmpty()) {
            lines.append("\n\n");
            lines.append(comment_);
            lines.append("\n");
        } else {
            lines.append(no_entries_);
        }
        ui->plainTextEdit->appendPlainText(lines);
    }

    ui->plainTextEdit->moveCursor(QTextCursor::Start);
    setUpdatesEnabled(true);
}

QMenu* ResolvedAddressesDialog::createCopyMenu(QWidget *parent)
{
    QMenu *copy_menu = new QMenu(tr("Copy table"), parent);
    QAction *ca;
    ca = copy_menu->addAction(tr("as Plain Text"));
    ca->setProperty("copy_as", ResolvedAddressesDialog::EXPORT_TEXT);
    connect(ca, &QAction::triggered, this, &ResolvedAddressesDialog::clipboardAction);
    ca = copy_menu->addAction(tr("as CSV"));
    ca->setProperty("copy_as", ResolvedAddressesDialog::EXPORT_CSV);
    connect(ca, &QAction::triggered, this, &ResolvedAddressesDialog::clipboardAction);
    ca = copy_menu->addAction(tr("as JSON"));
    ca->setProperty("copy_as", ResolvedAddressesDialog::EXPORT_JSON);
    connect(ca, &QAction::triggered, this, &ResolvedAddressesDialog::clipboardAction);

    return copy_menu;
}

void ResolvedAddressesDialog::clipboardAction()
{
    QAction *ca = qobject_cast<QAction *>(sender());
    if (ca && ca->property("copy_as").isValid())
        copyToClipboard(static_cast<eResolvedAddressesExport>(ca->property("copy_as").toInt()));
}

void ResolvedAddressesDialog::copyToClipboard(eResolvedAddressesExport format)
{
    QString clipText;
    QTextStream stream(&clipText, QIODevice::Text);
    toTextStream(stream, format);
    mainApp->clipboard()->setText(stream.readAll());
}

void ResolvedAddressesDialog::saveAs()
{
    QString caption(mainApp->windowTitleString(tr("Save Resolved Addresses As…")));
    QString txtFilter = tr("Plain text (*.txt)");
    QString csvFilter = tr("CSV Document (*.csv)");
    QString jsonFilter = tr("JSON Document (*.json)");
    QString selectedFilter;
    QString fileName = WiresharkFileDialog::getSaveFileName(this, caption,
        mainApp->openDialogInitialDir().canonicalPath(),
        QString("%1;;%2;;%3").arg(txtFilter).arg(csvFilter).arg(jsonFilter),
        &selectedFilter);
    if (fileName.isEmpty()) {
        return;
    }

    eResolvedAddressesExport format(EXPORT_TEXT);
    if (selectedFilter.compare(csvFilter) == 0) {
        format = EXPORT_CSV;
    } else if (selectedFilter.compare(jsonFilter)) {
        format = EXPORT_JSON;
    }

    // macOS and Windows use the native file dialog, which enforces file
    // extensions. UN*X dialogs generally don't. That's ok here, at
    // least for the text format, because hosts and ethers and services
    // files don't have an extension.
    QFile saveFile(fileName);
    if (saveFile.open(QFile::WriteOnly | QFile::Text)) {
        QTextStream stream(&saveFile);
        toTextStream(stream, format);
        saveFile.close();
    } else {
        QMessageBox::warning(this, tr("Warning").arg(saveFile.fileName()),
                             tr("Unable to save %1: %2").arg(saveFile.fileName().arg(saveFile.errorString())));
    }
}

void ResolvedAddressesDialog::toTextStream(QTextStream& stream, eResolvedAddressesExport format) const
{
    QWidget *currentTab = ui->tabWidget->currentWidget();
    if (currentTab == nullptr) {
        return;
    }
    QTableView *currentTable = currentTab->findChild<QTableView*>();
    if (currentTable == nullptr) {
        return;
    }
    QAbstractItemModel *model = currentTable->model();
    if (model == nullptr) {
        return;
    }

    // XXX: TrafficTree and TapParameterDialog have similar "export a
    // "QAbstractItemModel to a QTextStream in TEXT, CSV or JSON"
    // functions that could be made into common code.
    QStringList rowText;
    if (format == EXPORT_TEXT) {
        if (currentTable == ui->tblPorts) {
            // Format of services(5)
            stream << "# service-name\tport/protocol\n";
            for (int row = 0; row < model->rowCount(); row++) {
                rowText.clear();
                rowText << model->data(model->index(row, PORTS_COL_NAME)).toString();
                rowText << QString("%1/%2")
                                  .arg(model->data(model->index(row, PORTS_COL_PORT)).toString())
                                  .arg(model->data(model->index(row, PORTS_COL_PROTOCOL)).toString());
                stream << rowText.join("\t") << "\n";
            }
        } else {
            // Format as hosts(5) and ethers(5)
            for (int col = 0; col < model->columnCount(); col++) {
                rowText << model->headerData(col, Qt::Horizontal).toString();
            }
            stream << "# " << rowText.join("\t") << "\n";
            for (int row = 0; row < model->rowCount(); row++) {
                rowText.clear();
                for (int col = 0; col < model->columnCount(); col++) {
                    rowText << model->data(model->index(row, col)).toString();
                }
                stream << rowText.join("\t") << "\n";
            }
        }
    } else if (format == EXPORT_CSV) {
        for (int col = 0; col < model->columnCount(); col++) {
            rowText << model->headerData(col, Qt::Horizontal).toString();
        }
        stream << rowText.join(",") << "\n";
        for (int row = 0; row < model->rowCount(); row++) {
            rowText.clear();
            for (int col = 0; col < model->columnCount(); col++) {
                QVariant v = model->data(model->index(row, col));
                if (!v.isValid()) {
                    rowText << QStringLiteral("\"\"");
                } else if (v.userType() == QMetaType::QString) {
                    rowText << QString("\"%1\"").arg(v.toString().replace('\"', "\"\""));
                } else {
                    rowText << v.toString();
                }
            }
            stream << rowText.join(",") << "\n";
        }
    } else if (format == EXPORT_JSON) {
        QMap<int, QString> headers;
        for (int col = 0; col < model->columnCount(); col++)
            headers.insert(col, model->headerData(col, Qt::Horizontal, Qt::DisplayRole).toString());

        QJsonArray records;

        for (int row = 0; row < model->rowCount(); row++) {
            QJsonObject rowData;
            foreach(int col, headers.keys()) {
                QModelIndex idx = model->index(row, col);
                rowData.insert(headers[col], model->data(idx).toString());
            }
            records.push_back(rowData);
        }

        QJsonDocument json;
        json.setArray(records);
        stream << json.toJson();
    }
}
