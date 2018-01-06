/* about_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "config.h"

#include "about_dialog.h"
#include <ui_about_dialog.h>

#include "wireshark_application.h"
#include <wsutil/filesystem.h>

#ifdef HAVE_LIBSMI
#include <epan/oids.h>
#endif
#ifdef HAVE_GEOIP
#include <epan/geoip_db.h>
#endif
#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif

#include "log.h"
#include "epan/register.h"

#include "ui/alert_box.h"
#include "ui/last_open_dir.h"
#include "ui/help_url.h"
#include "ui/text_import_scanner.h"
#include <wsutil/utf8_entities.h>

#include "file.h"
#include "wsutil/file_util.h"
#include "wsutil/tempfile.h"
#include "wsutil/plugins.h"
#include "wsutil/copyright_info.h"
#include "version_info.h"

#include "extcap.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/variant_pointer.h>
#include <ui/qt/models/astringlist_list_model.h>
#include <ui/qt/models/url_link_delegate.h>
#include <ui/qt/models/html_text_delegate.h>

#include <QFontMetrics>
#include <QKeySequence>
#include <QTextStream>
#include <QUrl>
#include <QRegExp>
#include <QAbstractItemModel>
#include <QHash>
#include <QDesktopServices>
#include <QClipboard>
#include <QMenu>
#include <QFileInfo>

AuthorListModel::AuthorListModel(QObject * parent) :
AStringListListModel(parent)
{
    bool readAck = false;
    QFile f_authors;

    f_authors.setFileName(get_datafile_path("AUTHORS-SHORT"));
    f_authors.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_authors(&f_authors);
    ReadFile_authors.setCodec("UTF-8");

    QRegExp rx("(.*)[<(]([\\s'a-zA-Z0-9._%+-]+(\\[[Aa][Tt]\\])?[a-zA-Z0-9._%+-]+)[>)]");
    acknowledgement_.clear();
    while (!ReadFile_authors.atEnd()) {
        QString line = ReadFile_authors.readLine();

        if ( ! readAck && line.trimmed().length() == 0 )
                continue;
        if ( line.startsWith("------") )
            continue;

        if ( line.compare(QStringLiteral("Acknowledgements") ) == 0 )
        {
            readAck = true;
            continue;
        }
        else if ( rx.indexIn(line) != -1 )
            appendRow( QStringList() << rx.cap(1).trimmed() << rx.cap(2).trimmed());

        if ( readAck )
            acknowledgement_.append(QString("%1\n").arg(line));
    }
    f_authors.close();

}

AuthorListModel::~AuthorListModel() { }

QString AuthorListModel::acknowledgment() const
{
    return acknowledgement_;
}

QStringList AuthorListModel::headerColumns() const
{
    return QStringList() << tr("Name") << tr("E-Mail");
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

    GHashTable * tools = extcap_loaded_interfaces();
    if (tools && g_hash_table_size(tools) > 0) {
        GList * walker = g_list_first(g_hash_table_get_keys(tools));
        while (walker && walker->data) {
            extcap_info * tool = (extcap_info *)g_hash_table_lookup(tools, walker->data);
            if (tool) {
                QStringList plugin_row = QStringList() << tool->basename << tool->version << "extcap" << tool->full_path;
                plugin_data << plugin_row;
            }
            walker = g_list_next(walker);
        }
    }

    typeNames_ << QString("");
    foreach(QStringList row, plugin_data)
    {
        typeNames_ << row.at(2);
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
    foreach (const QWidget *child, wsApp->mainWindow()->findChildren<QWidget *>()) {
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
    appendRow( QStringList() << "\"File\" dialogs" << get_last_open_dir() << "capture files");

    /* temp */
    appendRow( QStringList() <<  "Temp" << g_get_tmp_dir() << "untitled capture files");

    /* pers conf */
    appendRow( QStringList() << "Personal configuration"
            << gchar_free_to_qstring(get_persconffile_path("", FALSE))
            << "<i>dfilters</i>, <i>preferences</i>, <i>ethers</i>, " UTF8_HORIZONTAL_ELLIPSIS);

    /* global conf */
    QString dirPath = get_datafile_dir();
    if (! dirPath.isEmpty()) {
        appendRow ( QStringList() << "Global configuration" << dirPath
                << "<i>dfilters</i>, <i>preferences</i>, <i>manuf</i>, " UTF8_HORIZONTAL_ELLIPSIS);
    }

    /* system */
    appendRow( QStringList() << "System" << get_systemfile_dir() << "<i>ethers</i>, <i>ipxnets</i>");

    /* program */
    appendRow( QStringList() << "Program" << get_progfile_dir() << "program files");

#ifdef HAVE_PLUGINS
    /* pers plugins */
    appendRow( QStringList() << "Personal Plugins" << get_plugins_pers_dir_with_version() << "binary plugins");

    /* global plugins */
    appendRow( QStringList() << "Global Plugins" << get_plugins_dir_with_version() << "binary plugins");
#endif

#ifdef HAVE_LUA
    /* pers plugins */
    appendRow( QStringList() << "Personal Lua Plugins" << get_plugins_pers_dir() << "lua scripts");

    /* global plugins */
    appendRow( QStringList() << "Global Lua Plugins" << get_plugins_dir() << "lua scripts");
#endif

    /* Extcap */
    QStringList extPaths = QString(get_extcap_dir()).split(G_SEARCHPATH_SEPARATOR_S);

    foreach(QString path, extPaths)
        appendRow( QStringList() << "Extcap path" << path.trimmed() << "Extcap Plugins search path");

#ifdef HAVE_GEOIP
    /* GeoIP */
    QStringList geoIpPaths = QString(geoip_db_get_paths()).split(G_SEARCHPATH_SEPARATOR_S);
    foreach(QString path, geoIpPaths)
        appendRow( QStringList() << "GeoIP path" << path.trimmed() << "GeoIP database search path");
#endif

#ifdef HAVE_LIBSMI
    /* SMI MIBs/PIBs */
    QStringList smiPaths = QString(oid_get_default_mib_path()).split(G_SEARCHPATH_SEPARATOR_S);
    foreach(QString path, smiPaths)
        appendRow( QStringList() << "MIB/PIB path" << path.trimmed() << "SMI MIB/PIB search path");
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
    QFile f_license;
    QString message;

    GString *comp_info_str = get_compiled_version_info(get_wireshark_qt_compiled_info,
                                              get_gui_compiled_info);
    GString *runtime_info_str = get_runtime_version_info(get_wireshark_runtime_info);


    AuthorListModel * authorModel = new AuthorListModel(this);
    AStringListListSortFilterProxyModel * proxyAuthorModel = new AStringListListSortFilterProxyModel(this);
    proxyAuthorModel->setSourceModel(authorModel);
    proxyAuthorModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyAuthorModel->setColumnToFilter(0);
    proxyAuthorModel->setColumnToFilter(1);
    ui->tblAuthors->setModel(proxyAuthorModel);
    ui->tblAuthors->setRootIsDecorated(false);
    ui->pte_Authors->clear();
    ui->pte_Authors->appendPlainText(authorModel->acknowledgment());
    ui->pte_Authors->moveCursor(QTextCursor::Start);

    ui->tblAuthors->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->tblAuthors, &QTreeView::customContextMenuRequested, this, &AboutDialog::handleCopyMenu);
    connect(ui->searchAuthors, SIGNAL(textChanged(QString)), proxyAuthorModel, SLOT(setFilter(QString)));

    /* Wireshark tab */

    /* Construct the message string */
    message = QString(
        "Version %1\n"
        "\n"
        "%2"
        "\n"
        "%3"
        "\n"
        "%4"
        "\n"
        "Wireshark is Open Source Software released under the GNU General Public License.\n"
        "\n"
        "Check the man page and http://www.wireshark.org for more information.")
        .arg(get_ws_vcs_version_info(), get_copyright_info(), comp_info_str->str, runtime_info_str->str);

    ui->label_wireshark->setTextInteractionFlags(Qt::TextSelectableByMouse);
    ui->label_wireshark->setText(message);

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
    ui->tblFolders->setItemDelegateForColumn(2, new HTMLTextDelegate(this));
    ui->tblFolders->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->tblFolders, &QTreeView::customContextMenuRequested, this, &AboutDialog::handleCopyMenu);
    connect(ui->searchFolders, SIGNAL(textChanged(QString)), folderProxyModel, SLOT(setFilter(QString)));
    connect(ui->tblFolders, &QTreeView::clicked, this, &AboutDialog::urlClicked );


    /* Plugins */
#if defined(HAVE_PLUGINS) || defined(HAVE_LUA)

    PluginListModel * pluginModel = new PluginListModel(this);
    AStringListListSortFilterProxyModel * pluginFilterModel = new AStringListListSortFilterProxyModel(this);
    pluginFilterModel->setSourceModel(pluginModel);
    pluginFilterModel->setColumnToFilter(0);
    AStringListListSortFilterProxyModel * pluginTypeModel = new AStringListListSortFilterProxyModel(this);
    pluginTypeModel->setSourceModel(pluginFilterModel);
    pluginTypeModel->setColumnToFilter(2);
    ui->tblPlugins->setModel(pluginTypeModel);
    ui->tblPlugins->setRootIsDecorated(false);
    ui->cmbType->addItems(pluginModel->typeNames());
    ui->tblPlugins->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->tblPlugins, &QTreeView::customContextMenuRequested, this, &AboutDialog::handleCopyMenu);
    connect(ui->searchPlugins, SIGNAL(textChanged(QString)), pluginFilterModel, SLOT(setFilter(QString)));
    connect(ui->cmbType, SIGNAL(currentIndexChanged(QString)), pluginTypeModel, SLOT(setFilter(QString)));

#else
    ui->tabWidget->removeTab(ui->tabWidget->indexOf(ui->tab_plugins));
#endif

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
    connect(ui->tblShortcuts, &QTreeView::customContextMenuRequested, this, &AboutDialog::handleCopyMenu);
    connect(ui->searchShortcuts, SIGNAL(textChanged(QString)), shortcutProxyModel, SLOT(setFilter(QString)));

    /* License */
#if defined(_WIN32)
    f_license.setFileName(get_datafile_path("COPYING.txt"));
#else
    f_license.setFileName(get_datafile_path("COPYING"));
#endif

    f_license.open(QFile::ReadOnly | QFile::Text);
    QTextStream ReadFile_license(&f_license);

    ui->pte_License->setFont(wsApp->monospaceFont());
    ui->pte_License->insertPlainText(ReadFile_license.readAll());
    ui->pte_License->moveCursor(QTextCursor::Start);

}

AboutDialog::~AboutDialog()
{
    delete ui;
}

void AboutDialog::resizeEvent(QResizeEvent * event)
{
    QList<QWidget *> pages;

    pages << ui->tab_authors << ui->tab_folders << ui->tab_plugins << ui->tab_shortcuts;

    foreach ( QWidget * tabPage, pages )
    {
        QList<QTreeView *> childs = tabPage->findChildren<QTreeView*>();
        if ( childs.count() == 0 )
            continue;

        QTreeView * tree = childs.at(0);

        int columnCount = tree->model()->columnCount();
        for ( int cnt = 0; cnt < columnCount; cnt++ )
            tree->setColumnWidth(cnt, tabPage->width() / columnCount);
        tree->header()->setStretchLastSection(true);
    }

    QDialog::resizeEvent(event);
}

void AboutDialog::urlClicked(const QModelIndex &idx)
{
    QTreeView * table = qobject_cast<QTreeView *>(sender());
    if ( ! table )
        return;

    QString urlText = table->model()->data(idx).toString();
    if ( urlText.isEmpty() )
        return;

    QFileInfo fi (urlText);
    if ( fi.isDir() && fi.exists() )
    {
        QUrl url = QUrl::fromLocalFile(urlText);
        if ( url.isValid() )
            QDesktopServices::openUrl(url);
    }
}

void AboutDialog::handleCopyMenu(QPoint pos)
{
    QTreeView * tree = qobject_cast<QTreeView *>(sender());
    if ( ! tree )
        return;

    QModelIndex index = tree->indexAt(pos);
    if ( ! index.isValid() )
        return;

    QMenu * menu = new QMenu(this);

    QAction * copyColumnAction = menu->addAction(tr("Copy"));
    copyColumnAction->setData(VariantPointer<QTreeView>::asQVariant(tree));
    connect(copyColumnAction, &QAction::triggered, this, &AboutDialog::copyActionTriggered);

    QAction * copyRowAction = menu->addAction(tr("Copy Row(s)"));
    copyRowAction->setData(VariantPointer<QTreeView>::asQVariant(tree));
    connect(copyRowAction, &QAction::triggered, this, &AboutDialog::copyRowActionTriggered);

    menu->popup(tree->viewport()->mapToGlobal(pos));
}

void AboutDialog::copyRowActionTriggered()
{
    copyActionTriggered(true);
}

void AboutDialog::copyActionTriggered(bool copyRow)
{
    QAction * sendingAction = qobject_cast<QAction *>(sender());
    if ( ! sendingAction )
        return;

    QTreeView * tree = VariantPointer<QTreeView>::asPtr(sendingAction->data());

    QModelIndexList selIndeces = tree->selectionModel()->selectedIndexes();

    int copyColumn = -1;
    if ( ! copyRow )
    {
        QMenu * menu = qobject_cast<QMenu *>(sendingAction->parentWidget());
        if ( menu )
        {
            QPoint menuPosOnTable = tree->mapFromGlobal(menu->pos());
            QModelIndex clickedIndex = tree->indexAt(menuPosOnTable);
            if ( clickedIndex.isValid() )
                copyColumn = clickedIndex.column();
        }
    }

    QString clipdata;
    if ( selIndeces.count() > 0 )
    {
        int columnCount = tree->model()->columnCount();
        QList<int> visitedRows;

        foreach(QModelIndex index, selIndeces)
        {
            if ( visitedRows.contains(index.row()) )
                continue;

            QStringList row;
            if ( copyRow )
            {
                for ( int cnt = 0; cnt < columnCount; cnt++ )
                {
                    QModelIndex dataIdx = tree->model()->index(index.row(), cnt);
                    row << tree->model()->data(dataIdx).toString();
                }
            }
            else
            {
                if ( copyColumn < 0 )
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
