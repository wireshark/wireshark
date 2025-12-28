/* keyboard_shortcuts_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "keyboard_shortcuts_dialog.h"
#include <ui_keyboard_shortcuts_dialog.h>

#include <QAction>
#include <QAbstractItemModel>
#include <QApplication>
#include <QClipboard>
#include <QItemSelectionModel>
#include <QKeySequence>
#include <QLineEdit>
#include <QMap>
#include <QMenu>
#include <QPair>
#ifndef QT_NO_PRINTER
#include <QPrintDialog>
#include <QPrinter>
#include <QTextDocument>
#endif
#include <QShowEvent>
#include <QTreeView>
#include <QWidget>
#include <QMainWindow>

#include <main_window.h>
#include <main_application.h>

#include <app/application_flavor.h>

ShortcutListModel::ShortcutListModel(QObject *parent) :
    AStringListListModel(parent)
{
    QMap<QString, QPair<QString, QString> > shortcuts; // name -> (shortcut, description)
    
    foreach (const QWidget *child, ((QMainWindow *)(mainApp->mainWindow()))->findChildren<QWidget *>()) {
        // Recent items look funny here.
        if (child->objectName().compare("menuOpenRecentCaptureFile") == 0) continue;
        foreach (const QAction *action, child->actions()) {
            if (!action->shortcut().isEmpty()) {
                QString name = action->text();
                name.replace('&', "");
                shortcuts[name] = QPair<QString, QString>(action->shortcut().toString(QKeySequence::NativeText), action->toolTip());
            }
        }
    }

    QStringList names = shortcuts.keys();
    names.sort();
    foreach (const QString &name, names) {
        QStringList row;
        row << shortcuts[name].first << name << shortcuts[name].second;
        appendRow(row);
        if (shortcuts[name].first == QKeySequence(Qt::CTRL | Qt::Key_Up).toString(QKeySequence::NativeText)) {
            appendRow(QStringList() << "F7" << name << shortcuts[name].second);
        }
        if (shortcuts[name].first == QKeySequence(Qt::CTRL | Qt::Key_Down).toString(QKeySequence::NativeText)) {
            appendRow(QStringList() << "F8" << name << shortcuts[name].second);
        }
    }

    /* Hard coded keyPressEvent() */
    appendRow(QStringList() << QKeySequence(Qt::CTRL | Qt::Key_Slash).toString(QKeySequence::NativeText) << tr("Display Filter Input") << tr("Jump to display filter input box"));
}

QStringList ShortcutListModel::headerColumns() const
{
    return QStringList() << tr("Shortcut") << tr("Name") << tr("Description");
}

KeyboardShortcutsDialog::KeyboardShortcutsDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::KeyboardShortcutsDialog),
    shortcut_model_(new ShortcutListModel(this)),
    shortcut_proxy_model_(new AStringListListSortFilterProxyModel(this))
{
    ui->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);

    shortcut_proxy_model_->setSourceModel(shortcut_model_);
    shortcut_proxy_model_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    shortcut_proxy_model_->setColumnToFilter(0);
    shortcut_proxy_model_->setColumnToFilter(1);
    shortcut_proxy_model_->setColumnToFilter(2);

    ui->shortcutTreeView->setModel(shortcut_proxy_model_);
    ui->shortcutTreeView->setRootIsDecorated(false);
    ui->shortcutTreeView->setSortingEnabled(true);
    ui->shortcutTreeView->sortByColumn(1, Qt::AscendingOrder);
    ui->shortcutTreeView->setContextMenuPolicy(Qt::CustomContextMenu);

    if (parent) {
        loadGeometry(parent->width() * 3 / 4, parent->height());
    }

    setWindowTitle(mainApp->windowTitleString(tr("Keyboard Shortcuts")));

    connect(ui->searchLineEdit, &QLineEdit::textChanged,
            shortcut_proxy_model_, &AStringListListSortFilterProxyModel::setFilter);
    connect(ui->shortcutTreeView, &QTreeView::customContextMenuRequested,
            this, &KeyboardShortcutsDialog::showCopyMenu);
    connect(ui->btnClose, &QPushButton::clicked, this, &QDialog::accept);
#ifndef QT_NO_PRINTER
    connect(ui->btnPrint, &QPushButton::clicked, this, &KeyboardShortcutsDialog::printShortcuts);
#else
    ui->btnPrint->setEnabled(false);
#endif
}

KeyboardShortcutsDialog::~KeyboardShortcutsDialog()
{
    delete ui;
}

void KeyboardShortcutsDialog::showEvent(QShowEvent *event)
{
    GeometryStateDialog::showEvent(event);

    int one_em = fontMetrics().height();

    ui->shortcutTreeView->resizeColumnToContents(0);
    ui->shortcutTreeView->setColumnWidth(0, ui->shortcutTreeView->columnWidth(0) + (one_em * 2));
    ui->shortcutTreeView->setColumnWidth(1, one_em * 12);
    ui->shortcutTreeView->resizeColumnToContents(2);
}

void KeyboardShortcutsDialog::showCopyMenu(const QPoint &pos)
{
    QModelIndex index = ui->shortcutTreeView->indexAt(pos);
    if (!index.isValid()) {
        return;
    }

    context_menu_index_ = index;

    QMenu *menu = new QMenu(this);
    menu->setAttribute(Qt::WA_DeleteOnClose);

    QAction *copyColumnAction = menu->addAction(tr("Copy"));
    connect(copyColumnAction, &QAction::triggered, this, &KeyboardShortcutsDialog::copyColumnSelection);

    QModelIndexList selectedRows = ui->shortcutTreeView->selectionModel()->selectedRows();
    QAction *copyRowAction = menu->addAction(tr("Copy Row(s)", "", static_cast<int>(selectedRows.count())));
    connect(copyRowAction, &QAction::triggered, this, &KeyboardShortcutsDialog::copyRowSelection);

    menu->popup(ui->shortcutTreeView->viewport()->mapToGlobal(pos));
}

void KeyboardShortcutsDialog::copyColumnSelection()
{
    copySelection(false);
}

void KeyboardShortcutsDialog::copyRowSelection()
{
    copySelection(true);
}

void KeyboardShortcutsDialog::printShortcuts()
{
#ifndef QT_NO_PRINTER
    QPrinter printer(QPrinter::HighResolution);
    QPrintDialog dialog(&printer, this);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    QTextDocument document;
    document.setHtml(buildShortcutsHtml());
    document.print(&printer);
#endif
}

void KeyboardShortcutsDialog::copySelection(bool copy_row)
{
    QTreeView *tree = ui->shortcutTreeView;
    if (!tree || !tree->selectionModel()) {
        return;
    }

    QModelIndexList selected_indexes = tree->selectionModel()->selectedIndexes();
    if (selected_indexes.isEmpty()) {
        return;
    }

    QAbstractItemModel *model = tree->model();
    if (!model) {
        return;
    }

    QString clipdata;
    QList<int> visited_rows;
    const int column_count = model->columnCount();
    const int column_to_copy = context_menu_index_.isValid() ? context_menu_index_.column() : 0;

    foreach (const QModelIndex &index, selected_indexes) {
        if (visited_rows.contains(index.row())) {
            continue;
        }

        QStringList row;
        if (copy_row) {
            for (int col = 0; col < column_count; col++) {
                QModelIndex data_index = model->index(index.row(), col);
                row << model->data(data_index).toString();
            }
        } else {
            QModelIndex data_index = model->index(index.row(), column_to_copy);
            row << model->data(data_index).toString();
        }

        clipdata.append(row.join("\t"));
        clipdata.append("\n");

        visited_rows << index.row();
    }

    QApplication::clipboard()->setText(clipdata);
}

/**
 * @brief Build an HTML representation of the keyboard shortcuts.
 * This function constructs an HTML table containing all keyboard shortcuts,
 * including their names, descriptions, and key bindings.   
 * @return An HTML string representing the keyboard shortcuts.
 */
QString KeyboardShortcutsDialog::buildShortcutsHtml() const
{
    QString html = QStringLiteral(
                "<html><head><meta charset=\"utf-8\"/>"
                "<style>"
                "table { border-collapse: collapse; width: 100%; }"
                "th, td { border: 1px solid #999; padding: 4px; }"
                "th { background-color: #f0f0f0; }"
                ".footer { margin-top: 12px; text-align: right; font-size: 9pt; color: #555; }"
                "</style>"
                "</head><body>");
    html += QStringLiteral("<h2>%1 - %2</h2>").arg(tr("Keyboard Shortcuts")).arg(applicationVersionLabel().toHtmlEscaped());

    if (!shortcut_model_) {
        html += QStringLiteral("</body></html>");
        return html;
    }

    const int column_count = shortcut_model_->columnCount();
    html += QStringLiteral("<table>");

    html += QStringLiteral("<tr>");
    for (int col = 0; col < column_count; col++) {
        QString header = shortcut_model_->headerData(col, Qt::Horizontal, Qt::DisplayRole).toString().toHtmlEscaped();
        html += QStringLiteral("<th>%1</th>").arg(header);
    }
    html += QStringLiteral("</tr>");

    const int row_count = shortcut_model_->rowCount();
    for (int row = 0; row < row_count; row++) {
        html += QStringLiteral("<tr>");
        for (int col = 0; col < column_count; col++) {
            QString cell = shortcut_model_->index(row, col).data().toString().toHtmlEscaped();
            if (cell.isEmpty()) {
                cell = QStringLiteral("&nbsp;");
            }
            html += QStringLiteral("<td>%1</td>").arg(cell);
        }
        html += QStringLiteral("</tr>");
    }

    html += QStringLiteral("</table>");
    html += QStringLiteral("</body></html>");
    
    return html;
}

QString KeyboardShortcutsDialog::applicationVersionLabel() const
{
    const bool is_ws = application_flavor_is_wireshark();
    const char *version_info = application_get_vcs_version_info();
    QString version = version_info ? QString::fromUtf8(version_info) : QString();

    QString product_name = is_ws ? QStringLiteral("Wireshark") : QStringLiteral("Stratoshark");
    if (version.isEmpty()) {
        return product_name;
    }
    return tr("%1 %2").arg(product_name, version);
}
