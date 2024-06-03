/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_QTUI

#include <ui/qt/widgets/resolved_addresses_view.h>
#include <ui/qt/models/resolved_addresses_models.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>

#include <QHeaderView>
#include <QMessageBox>
#include <QClipboard>
#include <QTextStream>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonDocument>
#include <QContextMenuEvent>

#include "main_application.h"

#include <wsutil/wslog.h>

ResolvedAddressesView::ResolvedAddressesView(QWidget *parent) : QTableView(parent)
{
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    setSortingEnabled(true);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    horizontalHeader()->setStretchLastSection(true);
    verticalHeader()->setVisible(false);

    // creating this action is mostly to override the default Ctrl-C handling
    // (which could also be done by overriding KeyPressEvent) and to make the
    // keyboard shortcut show up in the context menu.
#if QT_VERSION < QT_VERSION_CHECK(6, 3, 0)
    clip_action_ = new QAction(tr("as Plain Text"), this);
    clip_action_->setShortcut(QKeySequence(QKeySequence::Copy));
    connect(clip_action_, &QAction::triggered, this, &ResolvedAddressesView::clipboardAction);
    addAction(clip_action_);
#else
    clip_action_ = addAction(tr("as Plain Text"), QKeySequence(QKeySequence::Copy), this, &ResolvedAddressesView::clipboardAction);
#endif
    clip_action_->setProperty("copy_as", ResolvedAddressesView::EXPORT_TEXT);
    clip_action_->setProperty("selected", true);
}

QMenu* ResolvedAddressesView::createCopyMenu(bool selected, QWidget *parent)
{
    QMenu *copy_menu;
    if (selected) {
        copy_menu = new QMenu(tr("Copy selected rows"), parent);
    } else {
        copy_menu = new QMenu(tr("Copy table"), parent);
    }
    copy_menu->setIcon(QIcon::fromTheme(QStringLiteral("edit-copy")));
    QAction *ca;
    if (selected) {
        copy_menu->addAction(clip_action_);
    } else {
        ca = copy_menu->addAction(tr("as Plain Text"), this, &ResolvedAddressesView::clipboardAction);
        ca->setProperty("copy_as", ResolvedAddressesView::EXPORT_TEXT);
        ca->setProperty("selected", selected);
    }
    ca = copy_menu->addAction(tr("as CSV"), this, &ResolvedAddressesView::clipboardAction);
    ca->setProperty("copy_as", ResolvedAddressesView::EXPORT_CSV);
    ca->setProperty("selected", selected);
    ca = copy_menu->addAction(tr("as JSON"), this, &ResolvedAddressesView::clipboardAction);
    ca->setProperty("copy_as", ResolvedAddressesView::EXPORT_JSON);
    ca->setProperty("selected", selected);

    return copy_menu;
}

void ResolvedAddressesView::contextMenuEvent(QContextMenuEvent *e)
{
    if (!e)
        return;

    QMenu *ctxMenu = new QMenu(this);
    ctxMenu->setAttribute(Qt::WA_DeleteOnClose);
    ctxMenu->addMenu(createCopyMenu(true, ctxMenu));
    QAction *act = ctxMenu->addAction(tr("Save selected rows as…"));
    act->setIcon(QIcon::fromTheme(QStringLiteral("document-save-as")));
    act->setProperty("selected", true);
    connect(act, &QAction::triggered, this, &ResolvedAddressesView::saveAs);
    ctxMenu->addSeparator();
    ctxMenu->addMenu(createCopyMenu(false, ctxMenu));
    act = ctxMenu->addAction(QIcon::fromTheme(QStringLiteral("document-save-as")), tr("Save table as…"), this, &ResolvedAddressesView::saveAs);
    act->setProperty("selected", false);

    ctxMenu->popup(e->globalPos());
}

AStringListListModel* ResolvedAddressesView::dataModel() const
{
    QSortFilterProxyModel *proxy = qobject_cast<QSortFilterProxyModel *>(model());

    if (proxy) {
        QAbstractItemModel *source = proxy->sourceModel();
        while (qobject_cast<QSortFilterProxyModel *>(source) != nullptr) {
            proxy = qobject_cast<QSortFilterProxyModel *>(source);
            source = proxy->sourceModel();
        }
        return qobject_cast<AStringListListModel *>(source);
    }
    return nullptr;
}

void ResolvedAddressesView::clipboardAction()
{
    QAction *ca = qobject_cast<QAction *>(sender());
    if (ca && ca->property("copy_as").isValid()) {
        copyToClipboard(static_cast<eResolvedAddressesExport>(ca->property("copy_as").toInt()),
            ca->property("selected").toBool());
    }
}

void ResolvedAddressesView::copyToClipboard(eResolvedAddressesExport format, bool selected)
{
    QString clipText;
    QTextStream stream(&clipText, QIODevice::Text);
    toTextStream(stream, format, selected);
    mainApp->clipboard()->setText(stream.readAll());
}

void ResolvedAddressesView::saveAs()
{
    bool selected = false;
    QAction *ca = qobject_cast<QAction *>(sender());
    if (ca && ca->property("selected").isValid()) {
        selected = true;
    }
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
    } else if (selectedFilter.compare(jsonFilter) == 0) {
        format = EXPORT_JSON;
    }

    // macOS and Windows use the native file dialog, which enforces file
    // extensions. UN*X dialogs generally don't. That's ok here, at
    // least for the text format, because hosts and ethers and services
    // files don't have an extension.
    QFile saveFile(fileName);
    if (saveFile.open(QFile::WriteOnly | QFile::Text)) {
        QTextStream stream(&saveFile);
        toTextStream(stream, format, selected);
        saveFile.close();
    } else {
        QMessageBox::warning(this, tr("Warning").arg(saveFile.fileName()),
                             tr("Unable to save %1: %2").arg(saveFile.fileName().arg(saveFile.errorString())));
    }
}


void ResolvedAddressesView::toTextStream(QTextStream& stream,
    eResolvedAddressesExport format, bool selected) const
{
    if (model() == nullptr) {
        return;
    }

    // XXX: TrafficTree and TapParameterDialog have similar
    // "export a QAbstractItemModel to a QTextStream in TEXT, CSV or JSON"
    // functions that could be made into common code.
    QStringList rowText;
    if (format == EXPORT_TEXT) {
        if (qobject_cast<PortsModel*>(dataModel()) != nullptr) {
            // Format of services(5)
            if (!selected) {
                stream << "# service-name\tport/protocol\n";
            }
            for (int row = 0; row < model()->rowCount(); row++) {
                if (selected && !selectionModel()->isRowSelected(row, QModelIndex())) continue;
                rowText.clear();
                rowText << model()->data(model()->index(row, PORTS_COL_NAME)).toString();
                rowText << QString("%1/%2")
                                  .arg(model()->data(model()->index(row, PORTS_COL_PORT)).toString())
                                  .arg(model()->data(model()->index(row, PORTS_COL_PROTOCOL)).toString());
                stream << rowText.join("\t") << "\n";
            }
        } else {
            // Format as hosts(5) and ethers(5)
            if (!selected) {
                for (int col = 0; col < model()->columnCount(); col++) {
                    rowText << model()->headerData(col, Qt::Horizontal).toString();
                }
                stream << "# " << rowText.join("\t") << "\n";
            }
            for (int row = 0; row < model()->rowCount(); row++) {
                if (selected && !selectionModel()->isRowSelected(row, QModelIndex())) continue;
                rowText.clear();
                for (int col = 0; col < model()->columnCount(); col++) {
                    rowText << model()->data(model()->index(row, col)).toString();
                }
                stream << rowText.join("\t") << "\n";
            }
        }
    } else if (format == EXPORT_CSV) {
        for (int col = 0; col < model()->columnCount(); col++) {
            rowText << model()->headerData(col, Qt::Horizontal).toString();
        }
        if (!selected) {
            stream << rowText.join(",") << "\n";
        }
        for (int row = 0; row < model()->rowCount(); row++) {
            if (selected && !selectionModel()->isRowSelected(row, QModelIndex())) continue;
            rowText.clear();
            for (int col = 0; col < model()->columnCount(); col++) {
                QVariant v = model()->data(model()->index(row, col));
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
        for (int col = 0; col < model()->columnCount(); col++)
            headers.insert(col, model()->headerData(col, Qt::Horizontal, Qt::DisplayRole).toString());

        QJsonArray records;

        for (int row = 0; row < model()->rowCount(); row++) {
            if (selected && !selectionModel()->isRowSelected(row, QModelIndex())) continue;
            QJsonObject rowData;
            foreach(int col, headers.keys()) {
                QModelIndex idx = model()->index(row, col);
                rowData.insert(headers[col], model()->data(idx).toString());
            }
            records.push_back(rowData);
        }

        QJsonDocument json;
        json.setArray(records);
        stream << json.toJson();
    }
}
