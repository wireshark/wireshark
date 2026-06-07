/* lua_debugger_files.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Files panel: scan plugin/script directories, navigate the tree.
 */

#include "lua_debugger_files.h"

#include <QAbstractItemView>
#include <QAction>
#include <QClipboard>
#include <QDesktopServices>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHeaderView>
#include <QMenu>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTreeView>
#include <QUrl>

#include "app/application_flavor.h"
#include "lua_debugger_dialog.h"
#include "lua_debugger_utils.h"
#include "utils/stock_icon.h"
#include "widgets/collapsible_section.h"
#include "wsutil/filesystem.h"
#include <epan/wslua/wslua_debugger.h>

/* ===== files_controller ===== */

namespace
{

static void loaded_script_callback(const char *file_path, void *user_data)
{
    auto *controller = static_cast<LuaDebuggerFilesController *>(user_data);
    if (controller && file_path)
    {
        controller->ensureEntry(QString::fromUtf8(file_path));
    }
}

} // namespace

void LuaDebuggerFilesController::attach(QTreeView *tree, QStandardItemModel *model)
{
    tree_ = tree;
    model_ = model;
    /* Stock icons need a styled application; loading them here (rather
     * than in the constructor) means the controller picks up the right
     * theme even if the host runs without a default style at construct
     * time. The icons are immutable for the dialog's lifetime. */
    folderIcon_ = StockIcon("folder");
    fileIcon_ = StockIcon("text-x-generic");
}

LuaDebuggerFilesController::LuaDebuggerFilesController(LuaDebuggerDialog *host) : QObject(host), host_(host) {}

void LuaDebuggerFilesController::configureTreeChrome() const
{
    if (!tree_)
    {
        return;
    }
    tree_->setRootIsDecorated(true);
    tree_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    if (tree_->header())
    {
        tree_->header()->setStretchLastSection(true);
        tree_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    }
}

void LuaDebuggerFilesController::sortModel()
{
    if (model_)
    {
        model_->sort(0, Qt::AscendingOrder);
    }
}

void LuaDebuggerFilesController::refreshAvailableScripts()
{
    if (!model_)
    {
        return;
    }
    model_->removeRows(0, model_->rowCount());

    const char *envPrefix = application_configuration_environment_prefix();
    if (envPrefix)
    {
        const char *personal = get_plugins_pers_dir(envPrefix);
        const char *global = get_plugins_dir(envPrefix);
        if (personal && personal[0])
        {
            scanScriptDirectory(QString::fromUtf8(personal));
        }
        if (global && global[0])
        {
            scanScriptDirectory(QString::fromUtf8(global));
        }
    }

    wslua_debugger_foreach_loaded_script(loaded_script_callback, this);

    model_->sort(0, Qt::AscendingOrder);
    if (tree_)
    {
        tree_->expandAll();
    }
}

void LuaDebuggerFilesController::scanScriptDirectory(const QString &dir_path)
{
    if (dir_path.isEmpty())
    {
        return;
    }

    QDir scriptDirectory(dir_path);
    if (!scriptDirectory.exists())
    {
        return;
    }

    QDirIterator scriptIterator(dir_path, QStringList() << "*.lua", QDir::Files, QDirIterator::Subdirectories);
    while (scriptIterator.hasNext())
    {
        ensureEntry(scriptIterator.next());
    }
}

bool LuaDebuggerFilesController::ensureEntry(const QString &file_path)
{
    if (!model_)
    {
        return false;
    }
    QString normalized = host_->normalizedFilePath(file_path);
    if (normalized.isEmpty())
    {
        return false;
    }

    QVector<QPair<QString, QString>> components;
    if (!appendPathComponents(normalized, components))
    {
        return false;
    }

    QStandardItem *parent = nullptr;
    bool createdLeaf = false;
    const qint32 componentCount = static_cast<qint32>(components.size());
    for (qint32 componentIndex = 0; componentIndex < componentCount; ++componentIndex)
    {
        const bool isLeaf = (componentIndex == componentCount - 1);
        const QString displayName = components.at(static_cast<int>(componentIndex)).first;
        const QString absolutePath = components.at(static_cast<int>(componentIndex)).second;
        QStandardItem *item = findChildItemByPath(parent, absolutePath);
        if (!item)
        {
            item = new QStandardItem();
            item->setText(displayName);
            item->setToolTip(absolutePath);
            item->setData(absolutePath, FileTreePathRole);
            item->setData(!isLeaf, FileTreeIsDirectoryRole);
            item->setIcon(isLeaf ? fileIcon_ : folderIcon_);
            if (parent)
            {
                parent->appendRow(item);
                parent->sortChildren(0, Qt::AscendingOrder);
            }
            else
            {
                model_->appendRow(item);
                model_->sort(0, Qt::AscendingOrder);
            }
            if (isLeaf)
            {
                createdLeaf = true;
            }
        }
        parent = item;
    }

    if (createdLeaf && tree_)
    {
        tree_->expandAll();
    }

    return createdLeaf;
}

QStandardItem *LuaDebuggerFilesController::findChildItemByPath(QStandardItem *parent, const QString &path) const
{
    if (parent)
    {
        const qint32 childCount = static_cast<qint32>(parent->rowCount());
        for (qint32 childIndex = 0; childIndex < childCount; ++childIndex)
        {
            QStandardItem *child = parent->child(static_cast<int>(childIndex));
            if (child->data(FileTreePathRole).toString() == path)
            {
                return child;
            }
        }
        return nullptr;
    }

    const qint32 topLevelCount = static_cast<qint32>(model_->rowCount());
    for (qint32 topLevelIndex = 0; topLevelIndex < topLevelCount; ++topLevelIndex)
    {
        QStandardItem *item = model_->item(static_cast<int>(topLevelIndex));
        if (item->data(FileTreePathRole).toString() == path)
        {
            return item;
        }
    }
    return nullptr;
}

bool LuaDebuggerFilesController::appendPathComponents(const QString &absolute_path,
                                                      QVector<QPair<QString, QString>> &components) const
{
    QString forwardPath = QDir::fromNativeSeparators(absolute_path);
    QStringList segments = forwardPath.split('/', Qt::SkipEmptyParts);
    const qint32 segmentCount = static_cast<qint32>(segments.size());
    QString currentForward;
    qint32 segmentStartIndex = 0;

    if (absolute_path.startsWith("\\\\") || absolute_path.startsWith("//"))
    {
        if (segmentCount < 2)
        {
            return false;
        }
        currentForward = QStringLiteral("//%1/%2").arg(segments.at(0), segments.at(1));
        QString display = QStringLiteral("\\\\%1\\%2").arg(segments.at(0), segments.at(1));
        components.append({display, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 2;
    }
    else if (segmentCount > 0 && segments.first().endsWith(QLatin1Char(':')))
    {
        currentForward = segments.first();
        QString storedRoot = currentForward;
        if (!storedRoot.endsWith(QLatin1Char('/')))
        {
            storedRoot += QLatin1Char('/');
        }
        components.append({currentForward, QDir::toNativeSeparators(storedRoot)});
        segmentStartIndex = 1;
    }
    else if (absolute_path.startsWith('/'))
    {
        currentForward = QStringLiteral("/");
        components.append({currentForward, currentForward});
    }
    else if (segmentCount > 0)
    {
        currentForward = segments.first();
        components.append({currentForward, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 1;
    }

    if (currentForward.isEmpty() && segmentCount > 0)
    {
        currentForward = segments.first();
        components.append({currentForward, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 1;
    }

    for (qint32 segmentIndex = segmentStartIndex; segmentIndex < segmentCount; ++segmentIndex)
    {
        const QString &segment = segments.at(static_cast<int>(segmentIndex));
        if (currentForward.isEmpty() || currentForward == "/")
        {
            currentForward = currentForward == "/" ? QStringLiteral("/%1").arg(segment) : segment;
        }
        else
        {
            currentForward += "/" + segment;
        }
        components.append({segment, QDir::toNativeSeparators(currentForward)});
    }

    return !components.isEmpty();
}

void LuaDebuggerFilesController::onItemDoubleClicked(const QModelIndex &index)
{
    if (!model_ || !index.isValid())
    {
        return;
    }
    QStandardItem *item = model_->itemFromIndex(index.sibling(index.row(), 0));
    if (!item || item->data(FileTreeIsDirectoryRole).toBool())
    {
        return;
    }
    const QString path = item->data(FileTreePathRole).toString();
    if (!path.isEmpty())
    {
        host_->codeTabsController().loadFile(path);
    }
}

void LuaDebuggerFilesController::showContextMenu(const QPoint &pos)
{
    if (!tree_ || !model_)
    {
        return;
    }
    const QModelIndex ix = tree_->indexAt(pos);
    if (!ix.isValid())
    {
        return;
    }
    QStandardItem *item = model_->itemFromIndex(ix.sibling(ix.row(), 0));
    if (!item || item->data(FileTreeIsDirectoryRole).toBool())
    {
        return;
    }
    const QString path = item->data(FileTreePathRole).toString();
    if (path.isEmpty())
    {
        return;
    }

    QMenu menu(host_);
    QAction *openAct = menu.addAction(QObject::tr("Open Source"));
#ifdef Q_OS_MAC
    QAction *revealAct = menu.addAction(QObject::tr("Show in Finder"));
#else
    QAction *revealAct = menu.addAction(QObject::tr("Show in Folder"));
#endif
    menu.addSeparator();
    QAction *copyPathAct = menu.addAction(QObject::tr("Copy Path"));

    QAction *chosen = menu.exec(tree_->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }
    if (chosen == openAct)
    {
        host_->codeTabsController().loadFile(path);
        return;
    }
    if (chosen == revealAct)
    {
        const QString parentDir = QFileInfo(path).absolutePath();
        if (!parentDir.isEmpty())
        {
            QDesktopServices::openUrl(QUrl::fromLocalFile(parentDir));
        }
        return;
    }
    if (chosen == copyPathAct)
    {
        if (QClipboard *clip = QGuiApplication::clipboard())
        {
            clip->setText(path);
        }
    }
}

/* ===== dialog_files (LuaDebuggerDialog members) ===== */

CollapsibleSection *LuaDebuggerDialog::createFilesSection(QWidget *parent)
{
    filesSection = new CollapsibleSection(tr("Files"), parent);
    fileModel = new QStandardItemModel(this);
    fileModel->setColumnCount(1);
    fileModel->setHorizontalHeaderLabels({tr("Files")});
    fileTree = new QTreeView();
    fileTree->setModel(fileModel);
    fileTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    filesSection->setContentWidget(fileTree);
    filesSection->setExpanded(true);
    return filesSection;
}

void LuaDebuggerDialog::wireFilesPanel()
{
    filesController_.attach(fileTree, fileModel);
    filesController_.configureTreeChrome();

    connect(fileTree, &QTreeView::doubleClicked, &filesController_, &LuaDebuggerFilesController::onItemDoubleClicked);
    fileTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(fileTree, &QTreeView::customContextMenuRequested, &filesController_,
            &LuaDebuggerFilesController::showContextMenu);
}
