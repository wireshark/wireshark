/* about_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "about_dialog.h"
#include <ui_about_dialog.h>

#include "main_application.h"
#include <wsutil/filesystem.h>

#include <QDesktopServices>
#include <QUrl>

#ifdef HAVE_LIBSMI
#include <epan/oids.h>
#endif

#include <epan/maxmind_db.h>
#include <epan/prefs.h>

#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif

#include "ui/alert_box.h"
#include "ui/last_open_dir.h"
#include "ui/help_url.h"
#include <wsutil/utf8_entities.h>

#include "file.h"
#include "wsutil/file_util.h"
#include "wsutil/tempfile.h"
#include "wsutil/plugins.h"
#include "ui/version_info.h"
#include "ui/capture_globals.h"

#include "extcap.h"

#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>

#include <ui/qt/models/astringlist_list_model.h>
#include <ui/qt/models/url_link_delegate.h>

#include <QFontMetrics>
#include <QKeySequence>
#include <QTextStream>
#include <QUrl>
#include <QRegularExpression>
#include <QAbstractItemModel>
#include <QHash>
#include <QDesktopServices>
#include <QClipboard>
#include <QMenu>
#include <QFileInfo>
#include <QMessageBox>
#include <QPlainTextEdit>

AuthorListModel::AuthorListModel(QObject * parent) :
AStringListListModel(parent)
{
    QFile f_authors;

    f_authors.setFileName(get_datafile_path("AUTHORS-SHORT"));
    f_authors.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_authors(&f_authors);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    ReadFile_authors.setEncoding(QStringConverter::Utf8);
#else
    ReadFile_authors.setCodec("UTF-8");
#endif

    QRegularExpression rx("(.*)[<(]([\\s'a-zA-Z0-9._%+-]+(\\[[Aa][Tt]\\])?[a-zA-Z0-9._%+-]+)[>)]");
    while (!ReadFile_authors.atEnd()) {
        QString line = ReadFile_authors.readLine();

        if (line.trimmed().length() == 0)
                continue;
        if (line.startsWith("------"))
            continue;

        QRegularExpressionMatch match = rx.match(line);
        if (match.hasMatch()) {
            appendRow(QStringList() << match.captured(1).trimmed() << match.captured(2).trimmed());
        }
    }
    f_authors.close();

}

AuthorListModel::~AuthorListModel() { }

QStringList AuthorListModel::headerColumns() const
{
    return QStringList() << tr("Name") << tr("Email");
}

static void plugins_add_description(const char *name, const char *version,
                                    const char *types, const char *filename,
                                    void *user_data)
{
    QList<QStringList> *plugin_data = (QList<QStringList> *)user_data;
    QStringList plugin_row = QStringList() << name << version << types << filename;
    *plugin_data << plugin_row;
}

PluginListModel::PluginListModel(QObject * parent) : AStringListListModel(parent)
{
    QList<QStringList> plugin_data;
#ifdef HAVE_PLUGINS
    plugins_get_descriptions(plugins_add_description, &plugin_data);
#endif

#ifdef HAVE_LUA
    wslua_plugins_get_descriptions(plugins_add_description, &plugin_data);
#endif

    extcap_get_descriptions(plugins_add_description, &plugin_data);

    typeNames_ << QString("");
    foreach(QStringList row, plugin_data)
    {
        QString type_name = row.at(2);
        typeNames_ << type_name;
        appendRow(row);
    }

    typeNames_.sort();
    typeNames_.removeDuplicates();
}

QStringList PluginListModel::typeNames() const
{
    return typeNames_;
}

QStringList PluginListModel::headerColumns() const
{
    return QStringList() << tr("Name") << tr("Version") << tr("Type") << tr("Path");
}

ShortcutListModel::ShortcutListModel(QObject * parent):
        AStringListListModel(parent)
{
    QMap<QString, QPair<QString, QString> > shortcuts; // name -> (shortcut, description)
    foreach (const QWidget *child, mainApp->mainWindow()->findChildren<QWidget *>()) {
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
    }
}

QStringList ShortcutListModel::headerColumns() const
{
    return QStringList() << tr("Shortcut") << tr("Name") << tr("Description");
}

FolderListModel::FolderListModel(QObject * parent):
        AStringListListModel(parent)
{
    /* "file open" */
    appendRow(QStringList() << tr("\"File\" dialogs") << get_last_open_dir() << tr("capture files"));

    /* temp */
    appendRow(QStringList() << tr("Temp") << (global_capture_opts.temp_dir && global_capture_opts.temp_dir[0] ? global_capture_opts.temp_dir : g_get_tmp_dir()) << tr("untitled capture files"));

    /* pers conf */
    appendRow(QStringList() << tr("Personal configuration")
            << gchar_free_to_qstring(get_persconffile_path("", FALSE))
            << tr("dfilters, preferences, ethers, …"));

    /* global conf */
    QString dirPath = get_datafile_dir();
    if (! dirPath.isEmpty()) {
        appendRow (QStringList() << tr("Global configuration") << dirPath
                << tr("dfilters, preferences, manuf, …"));
    }

    /* system */
    appendRow(QStringList() << tr("System") << get_systemfile_dir() << tr("ethers, ipxnets"));

    /* program */
    appendRow(QStringList() << tr("Program") << get_progfile_dir() << tr("program files"));

#ifdef HAVE_PLUGINS
    /* pers plugins */
    appendRow(QStringList() << tr("Personal Plugins") << get_plugins_pers_dir_with_version() << tr("binary plugins"));

    /* global plugins */
    appendRow(QStringList() << tr("Global Plugins") << get_plugins_dir_with_version() << tr("binary plugins"));
#endif

#ifdef HAVE_LUA
    /* pers plugins */
    appendRow(QStringList() << tr("Personal Lua Plugins") << get_plugins_pers_dir() << tr("lua scripts"));

    /* global plugins */
    appendRow(QStringList() << tr("Global Lua Plugins") << get_plugins_dir() << tr("lua scripts"));
#endif

    /* Extcap */
    appendRow(QStringList() << tr("Personal Extcap path") << QString(get_persconffile_path("extcap", FALSE)).trimmed() << tr("Extcap Plugins search path"));
    appendRow(QStringList() << tr("Global Extcap path") << QString(get_extcap_dir()).trimmed() << tr("Extcap Plugins search path"));

#ifdef HAVE_MAXMINDDB
    /* MaxMind DB */
    QStringList maxMindDbPaths = QString(maxmind_db_get_paths()).split(G_SEARCHPATH_SEPARATOR_S);
    foreach(QString path, maxMindDbPaths)
        appendRow(QStringList() << tr("MaxMind DB path") << path.trimmed() << tr("MaxMind DB database search path"));
#endif

#ifdef HAVE_LIBSMI
    /* SMI MIBs/PIBs */
    char *default_mib_path = oid_get_default_mib_path();
    QStringList smiPaths = QString(default_mib_path).split(G_SEARCHPATH_SEPARATOR_S);
    g_free(default_mib_path);
    foreach(QString path, smiPaths)
        appendRow(QStringList() << tr("MIB/PIB path") << path.trimmed() << tr("SMI MIB/PIB search path"));
#endif

#ifdef Q_OS_MAC
    /* Mac Extras */
    QString extras_path = mainApp->applicationDirPath() + "/../Resources/Extras";
    appendRow(QStringList() << tr("macOS Extras") << QDir::cleanPath(extras_path) << tr("Extra macOS packages"));

#endif
}

QStringList FolderListModel::headerColumns() const
{
    return QStringList() << tr("Name") << tr("Location") << tr("Typical Files");
}

// To do:
// - Tweak and enhance ui...

AboutDialog::AboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    setAttribute(Qt::WA_DeleteOnClose, true);
    QFile f_acknowledgements;
    QFile f_license;

    AuthorListModel * authorModel = new AuthorListModel(this);
    AStringListListSortFilterProxyModel * proxyAuthorModel = new AStringListListSortFilterProxyModel(this);
    proxyAuthorModel->setSourceModel(authorModel);
    proxyAuthorModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyAuthorModel->setColumnToFilter(0);
    proxyAuthorModel->setColumnToFilter(1);
    ui->tblAuthors->setModel(proxyAuthorModel);
    ui->tblAuthors->setRootIsDecorated(false);
    ui->tblAuthors->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->tblAuthors, &QTreeView::customContextMenuRequested, this, &AboutDialog::handleCopyMenu);
    connect(ui->searchAuthors, &QLineEdit::textChanged, proxyAuthorModel, &AStringListListSortFilterProxyModel::setFilter);

    /* Wireshark tab */
    updateWiresharkText();

    ui->pte_wireshark->setFrameStyle(QFrame::NoFrame);
    ui->pte_wireshark->viewport()->setAutoFillBackground(false);

/* Check if it is a dev release... (VERSION_MINOR is odd in dev release) */
#if VERSION_MINOR & 1
        ui->label_logo->setPixmap(QPixmap(":/about/wssplash_dev.png"));
#endif

    /* Folders */
    FolderListModel * folderModel = new FolderListModel(this);
    AStringListListSortFilterProxyModel * folderProxyModel = new AStringListListSortFilterProxyModel(this);
    folderProxyModel->setSourceModel(folderModel);
    folderProxyModel->setColumnToFilter(1);
    folderProxyModel->setFilterType(AStringListListSortFilterProxyModel::FilterByStart);
    AStringListListUrlProxyModel * folderDisplayModel = new AStringListListUrlProxyModel(this);
    folderDisplayModel->setSourceModel(folderProxyModel);
    folderDisplayModel->setUrlColumn(1);
    ui->tblFolders->setModel(folderDisplayModel);
    ui->tblFolders->setRootIsDecorated(false);
    ui->tblFolders->setItemDelegateForColumn(1, new UrlLinkDelegate(this));
    ui->tblFolders->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tblFolders->setTextElideMode(Qt::ElideMiddle);
    ui->tblFolders->setSortingEnabled(true);
    ui->tblFolders->sortByColumn(0, Qt::AscendingOrder);
    connect(ui->tblFolders, &QTreeView::customContextMenuRequested, this, &AboutDialog::handleCopyMenu);
    connect(ui->searchFolders, &QLineEdit::textChanged, folderProxyModel, &AStringListListSortFilterProxyModel::setFilter);
    connect(ui->tblFolders, &QTreeView::doubleClicked, this, &AboutDialog::urlDoubleClicked);


    /* Plugins */
    ui->label_no_plugins->hide();
    PluginListModel * pluginModel = new PluginListModel(this);
    AStringListListSortFilterProxyModel * pluginFilterModel = new AStringListListSortFilterProxyModel(this);
    pluginFilterModel->setSourceModel(pluginModel);
    pluginFilterModel->setColumnToFilter(0);
    AStringListListSortFilterProxyModel * pluginTypeModel = new AStringListListSortFilterProxyModel(this);
    pluginTypeModel->setSourceModel(pluginFilterModel);
    pluginTypeModel->setColumnToFilter(2);
    ui->tblPlugins->setModel(pluginTypeModel);
    ui->tblPlugins->setRootIsDecorated(false);
    UrlLinkDelegate *plugin_delegate = new UrlLinkDelegate(this);
    script_pattern = QString("\\.(lua|py)$");
    plugin_delegate->setColCheck(3, script_pattern);
    ui->tblPlugins->setItemDelegateForColumn(3, plugin_delegate);
    ui->cmbType->addItems(pluginModel->typeNames());
    ui->tblPlugins->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tblPlugins->setTextElideMode(Qt::ElideMiddle);
    ui->tblPlugins->setSortingEnabled(true);
    ui->tblPlugins->sortByColumn(0, Qt::AscendingOrder);
    connect(ui->tblPlugins, &QTreeView::customContextMenuRequested, this, &AboutDialog::handleCopyMenu);
    connect(ui->searchPlugins, &QLineEdit::textChanged, pluginFilterModel, &AStringListListSortFilterProxyModel::setFilter);
    connect(ui->cmbType, &QComboBox::currentTextChanged, pluginTypeModel, &AStringListListSortFilterProxyModel::setFilter);
    if (ui->tblPlugins->model()->rowCount() < 1) {
        foreach (QWidget *w, ui->tab_plugins->findChildren<QWidget *>()) {
            w->hide();
        }
        ui->label_no_plugins->setAlignment(Qt::AlignVCenter | Qt::AlignHCenter);
        ui->label_no_plugins->setEnabled(false);
        ui->label_no_plugins->show();
    }

    /* Shortcuts */
    ShortcutListModel * shortcutModel = new ShortcutListModel(this);
    AStringListListSortFilterProxyModel * shortcutProxyModel = new AStringListListSortFilterProxyModel(this);
    shortcutProxyModel->setSourceModel(shortcutModel);
    shortcutProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    shortcutProxyModel->setColumnToFilter(1);
    shortcutProxyModel->setColumnToFilter(2);
    ui->tblShortcuts->setModel(shortcutProxyModel);
    ui->tblShortcuts->setRootIsDecorated(false);
    ui->tblShortcuts->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tblShortcuts->setSortingEnabled(true);
    ui->tblShortcuts->sortByColumn(1, Qt::AscendingOrder);
    connect(ui->tblShortcuts, &QTreeView::customContextMenuRequested, this, &AboutDialog::handleCopyMenu);
    connect(ui->searchShortcuts, &QLineEdit::textChanged, shortcutProxyModel, &AStringListListSortFilterProxyModel::setFilter);

    /* Acknowledgements */
    f_acknowledgements.setFileName(get_datafile_path("Acknowledgements.md"));

    f_acknowledgements.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_acks(&f_acknowledgements);

    /* QTextBrowser markdown support added in 5.14. */
#if QT_VERSION >= QT_VERSION_CHECK(5, 14, 0)
    QTextBrowser *textBrowserAcks = new QTextBrowser();
    textBrowserAcks->setMarkdown(ReadFile_acks.readAll());
    textBrowserAcks->setReadOnly(true);
    textBrowserAcks->setOpenExternalLinks(true);
    textBrowserAcks->moveCursor(QTextCursor::Start);
    ui->ackVerticalLayout->addWidget(textBrowserAcks);
#else
    QPlainTextEdit *pte = new QPlainTextEdit();
    pte->setPlainText(ReadFile_acks.readAll());
    pte->setReadOnly(true);
    pte->moveCursor(QTextCursor::Start);
    ui->ackVerticalLayout->addWidget(pte);
#endif

    /* License */
    f_license.setFileName(get_datafile_path("gpl-2.0-standalone.html"));

    f_license.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_license(&f_license);

    ui->textBrowserLicense->setHtml(ReadFile_license.readAll());
    ui->textBrowserLicense->moveCursor(QTextCursor::Start);
}

AboutDialog::~AboutDialog()
{
    delete ui;
}

bool AboutDialog::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        updateWiresharkText();
        break;
    default:
        break;

    }
    return QDialog::event(event);
}

void AboutDialog::showEvent(QShowEvent * event)
{
    int one_em = fontMetrics().height();

    // Authors: Names slightly narrower than emails.
    QAbstractItemModel *model = ui->tblAuthors->model();
    int column_count = model->columnCount();
    if (column_count) {
        ui->tblAuthors->setColumnWidth(0, (ui->tblAuthors->parentWidget()->width() / column_count) - one_em);
    }

    // Folders: First and last to contents.
    ui->tblFolders->resizeColumnToContents(0);
    ui->tblFolders->resizeColumnToContents(2);
    ui->tblFolders->setColumnWidth(1, ui->tblFolders->parentWidget()->width() -
                                   (ui->tblFolders->columnWidth(0) + ui->tblFolders->columnWidth(2)));

    // Plugins: All but the last to contents.
    model = ui->tblPlugins->model();
    for (int col = 0; model && col < model->columnCount() - 1; col++) {
        ui->tblPlugins->resizeColumnToContents(col);
    }

    // Contents + 2 em-widths
    ui->tblShortcuts->resizeColumnToContents(0);
    ui->tblShortcuts->setColumnWidth(0, ui->tblShortcuts->columnWidth(0) + (one_em * 2));
    ui->tblShortcuts->setColumnWidth(1, one_em * 12);
    ui->tblShortcuts->resizeColumnToContents(2);

    QDialog::showEvent(event);
}

void AboutDialog::updateWiresharkText()
{
    QString vcs_version_info_str = get_ws_vcs_version_info();
    QString copyright_info_str = get_copyright_info();
    QString license_info_str = get_license_info();
    QString comp_info_str = gstring_free_to_qbytearray(get_compiled_version_info(gather_wireshark_qt_compiled_info));
    QString runtime_info_str = gstring_free_to_qbytearray(get_runtime_version_info(gather_wireshark_runtime_info));

    QString message = ColorUtils::themeLinkStyle();

    /* Construct the message string */
    message += "<p>Version " + html_escape(vcs_version_info_str) + ".</p>\n";
    message += "<p>" + html_escape(copyright_info_str) + "</p>\n";
    message += "<p>" + html_escape(license_info_str) + "</p>\n";
    message += "<p>" + html_escape(comp_info_str) + "</p>\n";
    message += "<p>" + html_escape(runtime_info_str) + "</p>\n";
    message += "<p>Check the man page and <a href=https://www.wireshark.org>www.wireshark.org</a> "
               "for more information.</p>\n";
    ui->pte_wireshark->setHtml(message);

    /* Save the info for the clipboard copy */
    clipboardInfo = "";
    clipboardInfo += "Version " + vcs_version_info_str + ".\n\n";
    /* XXX: GCC 12.1 has a bogus stringop-overread warning using the Qt
     * conversions from QByteArray to QString at -O2 and higher due to
     * computing a branch that will never be taken.
     */
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_OFF(stringop-overread)
#endif
    clipboardInfo += gstring_free_to_qbytearray(get_compiled_version_info(gather_wireshark_qt_compiled_info)) + "\n";
    clipboardInfo += gstring_free_to_qbytearray(get_runtime_version_info(gather_wireshark_runtime_info)) + "\n";
#if WS_IS_AT_LEAST_GNUC_VERSION(12,1)
DIAG_ON(stringop-overread)
#endif
}

void AboutDialog::on_copyToClipboard_clicked()
{
    QClipboard * clipBoard = QApplication::clipboard();
    clipBoard->setText(clipboardInfo);
}

void AboutDialog::urlDoubleClicked(const QModelIndex &idx)
{
    if (idx.column() != 1) {
        return;
    }
    QTreeView * table = qobject_cast<QTreeView *>(sender());
    if (! table)
        return;

    QString urlText = table->model()->data(idx).toString();
    if (urlText.isEmpty())
        return;

    if (! QDir(urlText).exists())
    {
        if (QMessageBox::question(this, tr("The directory does not exist"),
                          QString(tr("Should the directory %1 be created?").arg(urlText))) == QMessageBox::Yes)
        {
            if (! QDir().mkpath(urlText))
            {
                QMessageBox::warning(this, tr("The directory could not be created"),
                                     QString(tr("The directory %1 could not be created.").arg(urlText)));
            }
        }
    }

    if (QDir(urlText).exists())
    {
        QUrl url = QUrl::fromLocalFile(urlText);
        if (url.isValid())
            QDesktopServices::openUrl(url);
    }
}

void AboutDialog::handleCopyMenu(QPoint pos)
{
    QTreeView * tree = qobject_cast<QTreeView *>(sender());
    if (! tree)
        return;

    QModelIndex index = tree->indexAt(pos);
    if (! index.isValid())
        return;

    QMenu * menu = new QMenu(this);

    if (ui->tabWidget->currentWidget() == ui->tab_plugins)
    {
#ifdef Q_OS_MAC
        QString show_in_str = tr("Show in Finder");
#else
        QString show_in_str = tr("Show in Folder");
#endif
        QAction * showInFolderAction = menu->addAction(show_in_str);
        showInFolderAction->setData(VariantPointer<QTreeView>::asQVariant(tree));
        connect(showInFolderAction, &QAction::triggered, this, &AboutDialog::showInFolderActionTriggered);
    }

    QAction * copyColumnAction = menu->addAction(tr("Copy"));
    copyColumnAction->setData(VariantPointer<QTreeView>::asQVariant(tree));
    connect(copyColumnAction, &QAction::triggered, this, &AboutDialog::copyActionTriggered);

    QModelIndexList selectedRows = tree->selectionModel()->selectedRows();
    QAction * copyRowAction = menu->addAction(tr("Copy Row(s)", "", static_cast<int>(selectedRows.count())));
    copyRowAction->setData(VariantPointer<QTreeView>::asQVariant(tree));
    connect(copyRowAction, &QAction::triggered, this, &AboutDialog::copyRowActionTriggered);

    menu->popup(tree->viewport()->mapToGlobal(pos));
}

void AboutDialog::showInFolderActionTriggered()
{
    QAction * sendingAction = qobject_cast<QAction *>(sender());
    if (!sendingAction)
        return;

    QTreeView * tree = VariantPointer<QTreeView>::asPtr(sendingAction->data());
    QModelIndexList selectedRows = tree->selectionModel()->selectedRows();

    foreach (QModelIndex index, selectedRows)
    {
        QString cf_path = tree->model()->index(index.row(), 3).data().toString();
        desktop_show_in_folder(cf_path);
    }
}

void AboutDialog::copyRowActionTriggered()
{
    copyActionTriggered(true);
}

void AboutDialog::copyActionTriggered(bool copyRow)
{
    QAction * sendingAction = qobject_cast<QAction *>(sender());
    if (! sendingAction)
        return;

    QTreeView * tree = VariantPointer<QTreeView>::asPtr(sendingAction->data());

    QModelIndexList selIndeces = tree->selectionModel()->selectedIndexes();

    int copyColumn = -1;
    if (! copyRow)
    {
        QMenu * menu = qobject_cast<QMenu *>(sendingAction->parentWidget());
        if (menu)
        {
            QPoint menuPosOnTable = tree->mapFromGlobal(menu->pos());
            QModelIndex clickedIndex = tree->indexAt(menuPosOnTable);
            if (clickedIndex.isValid())
                copyColumn = clickedIndex.column();
        }
    }

    QString clipdata;
    if (selIndeces.count() > 0)
    {
        int columnCount = tree->model()->columnCount();
        QList<int> visitedRows;

        foreach(QModelIndex index, selIndeces)
        {
            if (visitedRows.contains(index.row()))
                continue;

            QStringList row;
            if (copyRow)
            {
                for (int cnt = 0; cnt < columnCount; cnt++)
                {
                    QModelIndex dataIdx = tree->model()->index(index.row(), cnt);
                    row << tree->model()->data(dataIdx).toString();
                }
            }
            else
            {
                if (copyColumn < 0)
                    copyColumn = index.column();

                QModelIndex dataIdx = tree->model()->index(index.row(), copyColumn);
                row << tree->model()->data(dataIdx).toString();
            }

            clipdata.append(row.join("\t\t").append("\n"));

            visitedRows << index.row();
        }
    }
    QClipboard * clipBoard = QApplication::clipboard();
    clipBoard->setText(clipdata);
}

void AboutDialog::on_tblPlugins_doubleClicked(const QModelIndex &index)
{
    const int path_col = 3;
    if (index.column() != path_col) {
        return;
    }
    const int row = index.row();
    const QAbstractItemModel *model = index.model();
    if (model->index(row, path_col).data().toString().contains(QRegularExpression(script_pattern))) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(model->index(row, path_col).data().toString()));
    }
}
