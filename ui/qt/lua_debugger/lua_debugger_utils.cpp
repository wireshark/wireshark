/* lua_debugger_utils.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Shared helpers used across the debugger panels.
 */

#include <config.h>

#include "lua_debugger_utils.h"
#include "ui_lua_debugger_dialog.h"

#include <QAbstractItemModel>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QCoreApplication>
#include <QFontMetricsF>
#include <QGuiApplication>
#include <QKeyEvent>
#include <QKeySequence>
#include <QList>
#include <QMetaObject>
#include <QObject>
#include <QPainter>
#include <QPalette>
#include <QPen>
#include <QPersistentModelIndex>
#include <QPixmap>
#include <QPointer>
#include <QSizePolicy>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStyle>
#include <QTimer>
#include <QToolButton>
#include <QTreeView>
#include <QWidget>

#include <algorithm>
#include <glib.h>

#include "app/application_flavor.h"
#include "lua_debugger_breakpoints.h"
#include "lua_debugger_code_editor.h"
#include "lua_debugger_dialog.h"
#include "lua_debugger_pause.h"
#include "wsutil/filesystem.h"
#include <epan/prefs.h>
#include <epan/wslua/wslua_debugger.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>

/* ===== internal ===== */

#define LUA_DEBUGGER_SETTINGS_FILE "lua_debugger.json"

QString luaDebuggerSettingsFilePath()
{
    char *p = get_persconffile_path(LUA_DEBUGGER_SETTINGS_FILE, false, application_configuration_environment_prefix());
    return gchar_free_to_qstring(p);
}

void luaDbgRecordTreeSectionRootExpansion(QHash<QString, LuaDbgTreeSectionExpansionState> &map, const QString &rootKey,
                                          bool expanded)
{
    if (rootKey.isEmpty())
    {
        return;
    }
    if (!expanded && !map.contains(rootKey))
    {
        return;
    }
    LuaDbgTreeSectionExpansionState &e = map[rootKey];
    e.rootExpanded = expanded;
    if (!expanded && e.subpaths.isEmpty())
    {
        map.remove(rootKey);
    }
}

void luaDbgRecordTreeSectionSubpathExpansion(QHash<QString, LuaDbgTreeSectionExpansionState> &map,
                                             const QString &rootKey, const QString &key, bool expanded)
{
    if (rootKey.isEmpty() || key.isEmpty())
    {
        return;
    }
    if (expanded)
    {
        LuaDbgTreeSectionExpansionState &e = map[rootKey];
        if (!e.subpaths.contains(key))
        {
            e.subpaths.append(key);
        }
    }
    else
    {
        auto it = map.find(rootKey);
        if (it == map.end())
        {
            return;
        }
        it->subpaths.removeAll(key);
        if (!it->rootExpanded && it->subpaths.isEmpty())
        {
            map.erase(it);
        }
    }
}

QStringList luaDbgTreeSectionExpandedSubpaths(const QHash<QString, LuaDbgTreeSectionExpansionState> &map,
                                              const QString &rootKey)
{
    if (rootKey.isEmpty())
    {
        return QStringList();
    }
    const auto it = map.constFind(rootKey);
    if (it == map.constEnd())
    {
        return QStringList();
    }
    return it->subpaths;
}

const QKeySequence kLuaDbgCtxGoToLine(QKeySequence(Qt::CTRL | Qt::Key_G));
const QKeySequence kLuaDbgCtxRunToLine(QKeySequence(Qt::CTRL | Qt::Key_F10));
const QKeySequence kLuaDbgCtxWatchEdit(Qt::Key_F2);
const QKeySequence kLuaDbgCtxWatchCopyValue(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));
const QKeySequence kLuaDbgCtxWatchDuplicate(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_D));
const QKeySequence kLuaDbgCtxWatchRemoveAll(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_K));
const QKeySequence kLuaDbgCtxAddWatch(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_W));
const QKeySequence kLuaDbgCtxToggleBreakpoint(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_B));
const QKeySequence kLuaDbgCtxReloadLuaPlugins(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_L));
const QKeySequence kLuaDbgCtxRemoveAllBreakpoints(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_F9));

QKeySequence luaDbgSeqFromKeyEvent(const QKeyEvent *ke)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return QKeySequence(QKeyCombination(ke->modifiers(), static_cast<Qt::Key>(ke->key())));
#else
    return QKeySequence(ke->key() | ke->modifiers());
#endif
}

/* ===== path_utils ===== */

using namespace LuaDebuggerItems;

namespace LuaDebuggerPath
{

LuaDbgInvalidFilterColors invalidFilterColors()
{
    LuaDbgInvalidFilterColors colors;
    colors.fg = ColorUtils::fromColorT(&prefs.gui_filter_invalid_fg);
    colors.bg = ColorUtils::fromColorT(&prefs.gui_filter_invalid_bg);
    return colors;
}

bool watchSpecIsGlobalScoped(const QString &spec)
{
    const QString t = spec.trimmed();
    return t.startsWith(QLatin1String("Globals")) || t == QLatin1String("_G") || t.startsWith(QLatin1String("_G."));
}

bool variablesPathIsGlobalScoped(const QString &path)
{
    return path == QLatin1String("Globals") || path.startsWith(QLatin1String("Globals."));
}

QString changeKey(int stackLevel, const QString &path) { return QString::number(stackLevel) + CHANGE_KEY_SEP + path; }

QString watchSpecFromChangeKey(const QString &key)
{
    const qsizetype sep = key.indexOf(CHANGE_KEY_SEP);
    return sep < 0 ? key : key.mid(sep + 1);
}

QString stripWatchExpressionErrorPrefix(const QString &errStr)
{
    static const QLatin1String kPrefix("watch:");
    if (!errStr.startsWith(kPrefix))
    {
        return errStr;
    }
    qsizetype i = kPrefix.size();
    const qsizetype digitStart = i;
    while (i < errStr.size() && errStr.at(i).isDigit())
    {
        ++i;
    }
    if (i == digitStart || i >= errStr.size() || errStr.at(i) != QLatin1Char(':'))
    {
        return errStr;
    }
    ++i;
    while (i < errStr.size() && (errStr.at(i) == QLatin1Char(' ') || errStr.at(i) == QLatin1Char('\t')))
    {
        ++i;
    }
    return errStr.mid(i);
}

QString variableSectionRootKeyFromItem(const QStandardItem *item)
{
    if (!item)
    {
        return QString();
    }
    const QStandardItem *walk = item;
    while (walk->parent())
    {
        walk = walk->parent();
    }
    return walk->data(VariablePathRole).toString();
}

bool watchSpecUsesPathResolution(const QString &spec)
{
    const QByteArray ba = spec.toUtf8();
    return wslua_debugger_watch_spec_uses_path_resolution(ba.constData());
}

QString variableTreeChildPath(const QString &parentPath, const QString &nameText)
{
    if (parentPath.isEmpty())
    {
        return nameText;
    }
    if (nameText.startsWith(QLatin1Char('[')))
    {
        return parentPath + nameText;
    }
    return parentPath + QLatin1Char('.') + nameText;
}

QString expressionWatchChildSubpath(const QString &parentSubpath, const QString &nameText)
{
    if (nameText.startsWith(QLatin1Char('[')))
    {
        return parentSubpath + nameText;
    }
    return parentSubpath + QLatin1Char('.') + nameText;
}

bool variableChildrenShouldSortByName(const QString &parentPath)
{
    return !parentPath.isEmpty() && parentPath.startsWith(QLatin1String("Globals"));
}

VariableRowFields readVariableRowFields(const wslua_variable_t &v, const QString &parentPath)
{
    VariableRowFields f;
    f.name = QString::fromUtf8(v.name ? v.name : "");
    f.value = QString::fromUtf8(v.value ? v.value : "");
    f.type = QString::fromUtf8(v.type ? v.type : "");
    f.canExpand = v.can_expand ? true : false;
    f.childPath = variableTreeChildPath(parentPath, f.name);
    return f;
}

void applyVariableExpansionIndicator(QStandardItem *anchor, bool canExpand, bool enabledOnlyPlaceholder, int columnCount)
{
    if (!canExpand)
    {
        return;
    }
    if (columnCount == WatchColumn::Count)
    {
        auto *placeholderSpec = new QStandardItem();
        auto *placeholderValue = new QStandardItem();
        if (enabledOnlyPlaceholder)
        {
            placeholderSpec->setFlags(Qt::ItemIsEnabled);
            placeholderValue->setFlags(Qt::ItemIsEnabled);
        }
        anchor->appendRow({placeholderSpec, placeholderValue});
        return;
    }
    auto *placeholderName = new QStandardItem();
    auto *placeholderValue = new QStandardItem();
    auto *placeholderType = new QStandardItem();
    if (enabledOnlyPlaceholder)
    {
        placeholderName->setFlags(Qt::ItemIsEnabled);
        placeholderValue->setFlags(Qt::ItemIsEnabled);
        placeholderType->setFlags(Qt::ItemIsEnabled);
    }
    else
    {
        for (QStandardItem *p : {placeholderName, placeholderValue, placeholderType})
        {
            p->setFlags((p->flags() | Qt::ItemIsSelectable | Qt::ItemIsEnabled) & ~Qt::ItemIsEditable);
        }
    }
    anchor->appendRow({placeholderName, placeholderValue, placeholderType});
}

QString watchVariablePathForSpec(const QString &spec)
{
    char *p = wslua_debugger_watch_variable_path_for_spec(spec.toUtf8().constData());
    if (!p)
    {
        return QString();
    }
    QString s = QString::fromUtf8(p);
    g_free(p);
    return s;
}

QString watchResolvedVariablePathForTooltip(const QString &spec)
{
    if (spec.trimmed().isEmpty())
    {
        return QString();
    }
    char *p = wslua_debugger_watch_resolved_variable_path_for_spec(spec.toUtf8().constData());
    if (!p)
    {
        return QString();
    }
    QString s = QString::fromUtf8(p);
    g_free(p);
    return s;
}

void watchRootSetVariablePathRoleFromSpec(QStandardItem *row, const QString &spec)
{
    if (!row)
    {
        return;
    }
    const QString t = spec.trimmed();
    if (t.isEmpty())
    {
        row->setData(QVariant(), VariablePathRole);
        return;
    }
    const QString vpRes = watchResolvedVariablePathForTooltip(t);
    if (!vpRes.isEmpty())
    {
        row->setData(vpRes, VariablePathRole);
        return;
    }
    const QString vp = watchVariablePathForSpec(t);
    if (!vp.isEmpty())
    {
        row->setData(vp, VariablePathRole);
    }
    else
    {
        row->setData(QVariant(), VariablePathRole);
    }
}

QString watchPathOriginSuffix(const QStandardItem *item, const QString &spec)
{
    QString vp;
    if (!spec.trimmed().isEmpty())
    {
        vp = watchResolvedVariablePathForTooltip(spec);
    }
    if (vp.isEmpty() && item)
    {
        vp = item->data(VariablePathRole).toString();
    }
    if (vp.startsWith(QLatin1String("Locals.")) || vp == QLatin1String("Locals"))
    {
        return QStringLiteral("\n%1").arg(QCoreApplication::translate("LuaDebuggerDialog", "From: Locals"));
    }
    if (vp.startsWith(QLatin1String("Upvalues.")) || vp == QLatin1String("Upvalues"))
    {
        return QStringLiteral("\n%1").arg(QCoreApplication::translate("LuaDebuggerDialog", "From: Upvalues"));
    }
    if (vp.startsWith(QLatin1String("Globals.")) || vp == QLatin1String("Globals"))
    {
        return QStringLiteral("\n%1").arg(QCoreApplication::translate("LuaDebuggerDialog", "From: Globals"));
    }
    return QString();
}

QString capWatchTooltipText(const QString &s)
{
    if (s.size() <= WATCH_TOOLTIP_MAX_CHARS)
    {
        return s;
    }
    return s.left(WATCH_TOOLTIP_MAX_CHARS) + QCoreApplication::translate("LuaDebuggerDialog", "\n… (truncated)");
}

QString watchPathParentKey(const QString &path)
{
    if (path.isEmpty())
    {
        return QString();
    }
    if (path.endsWith(QLatin1Char(']')))
    {
        int depth = 0;
        for (int i = static_cast<int>(path.size()) - 1; i >= 0; --i)
        {
            const QChar c = path.at(i);
            if (c == QLatin1Char(']'))
            {
                depth++;
            }
            else if (c == QLatin1Char('['))
            {
                depth--;
                if (depth == 0)
                {
                    return path.left(i);
                }
            }
        }
        return QString();
    }
    const qsizetype dot = path.lastIndexOf(QLatin1Char('.'));
    if (dot > 0)
    {
        return path.left(dot);
    }
    return QString();
}

void applyWatchChildRowTextAndTooltip(QStandardItem *specItem, const QString &rawVal, const QString &typeText)
{
    auto *wm = qobject_cast<QStandardItemModel *>(specItem->model());
    if (!wm)
    {
        return;
    }
    setText(wm, specItem, WatchColumn::Value, rawVal);
    const QString tooltipSuffix =
        typeText.isEmpty() ? QString() : QCoreApplication::translate("LuaDebuggerDialog", "Type: %1").arg(typeText);
    setToolTip(wm, specItem, WatchColumn::Spec,
               capWatchTooltipText(tooltipSuffix.isEmpty()
                                       ? specItem->text()
                                       : QStringLiteral("%1\n%2").arg(specItem->text(), tooltipSuffix)));
    setToolTip(
        wm, specItem, WatchColumn::Value,
        capWatchTooltipText(tooltipSuffix.isEmpty() ? rawVal : QStringLiteral("%1\n%2").arg(rawVal, tooltipSuffix)));
}

int watchSubpathBoundaryCount(const QString &subpath)
{
    QString p = subpath;
    if (p.startsWith(QLatin1Char('.')))
    {
        p = p.mid(1);
    }
    int n = 0;
    for (QChar ch : p)
    {
        if (ch == QLatin1Char('.') || ch == QLatin1Char('['))
        {
            n++;
        }
    }
    return n;
}

QStandardItem *findWatchItemBySubpathOrPathKey(QStandardItem *subtree, const QString &key)
{
    if (!subtree || key.isEmpty())
    {
        return nullptr;
    }
    QList<QStandardItem *> queue;
    queue.append(subtree);
    while (!queue.isEmpty())
    {
        QStandardItem *it = queue.takeFirst();
        const QString sp = it->data(WatchSubpathRole).toString();
        const QString vp = it->data(VariablePathRole).toString();
        if ((!sp.isEmpty() && sp == key) || (!vp.isEmpty() && vp == key))
        {
            return it;
        }
        for (int i = 0; i < it->rowCount(); ++i)
        {
            queue.append(it->child(i));
        }
    }
    return nullptr;
}

QStandardItem *findVariableTreeItemByPathKey(QStandardItem *subtree, const QString &key)
{
    if (!subtree || key.isEmpty())
    {
        return nullptr;
    }
    QList<QStandardItem *> queue;
    queue.append(subtree);
    while (!queue.isEmpty())
    {
        QStandardItem *it = queue.takeFirst();
        if (it->data(VariablePathRole).toString() == key)
        {
            return it;
        }
        for (int i = 0; i < it->rowCount(); ++i)
        {
            queue.append(it->child(i));
        }
    }
    return nullptr;
}

void reexpandTreeDescendantsByPathKeys(QTreeView *tree, QStandardItemModel *model, QStandardItem *subtree,
                                       QStringList pathKeys, TreePathKeyFinder findByKey)
{
    if (!tree || !model || !subtree || pathKeys.isEmpty() || !findByKey)
    {
        return;
    }
    std::sort(pathKeys.begin(), pathKeys.end(),
              [](const QString &a, const QString &b)
              {
                  const int ca = watchSubpathBoundaryCount(a);
                  const int cb = watchSubpathBoundaryCount(b);
                  if (ca != cb)
                  {
                      return ca < cb;
                  }
                  return a < b;
              });
    for (const QString &pathKey : pathKeys)
    {
        QStringList chain;
        for (QString cur = pathKey; !cur.isEmpty(); cur = watchPathParentKey(cur))
        {
            chain.prepend(cur);
        }
        for (const QString &k : chain)
        {
            QStandardItem *n = findByKey(subtree, k);
            if (!n)
            {
                continue;
            }
            const QModelIndex ix = model->indexFromItem(n);
            if (ix.isValid() && !tree->isExpanded(ix))
            {
                tree->setExpanded(ix, true);
            }
        }
    }
}

void reexpandWatchDescendantsByPathKeys(QTreeView *tree, QStandardItemModel *model, QStandardItem *subtree,
                                        QStringList pathKeys)
{
    reexpandTreeDescendantsByPathKeys(tree, model, subtree, std::move(pathKeys), findWatchItemBySubpathOrPathKey);
}

void clearWatchFilterErrorChrome(QStandardItem *specItem, QTreeView *tree)
{
    auto *wm = qobject_cast<QStandardItemModel *>(specItem ? specItem->model() : nullptr);
    if (!wm || !tree)
    {
        return;
    }
    const QPalette &pal = tree->palette();
    setForeground(wm, specItem, WatchColumn::Spec, pal.brush(QPalette::Text));
    setForeground(wm, specItem, WatchColumn::Value, pal.brush(QPalette::Text));
    setBackground(wm, specItem, WatchColumn::Spec, QBrush());
    setBackground(wm, specItem, WatchColumn::Value, QBrush());
}

void applyWatchFilterErrorChrome(QStandardItem *specItem, QTreeView *tree)
{
    Q_UNUSED(tree);
    auto *wm = qobject_cast<QStandardItemModel *>(specItem ? specItem->model() : nullptr);
    if (!wm)
    {
        return;
    }
    const LuaDbgInvalidFilterColors colors = invalidFilterColors();
    setForeground(wm, specItem, WatchColumn::Spec, colors.fg);
    setForeground(wm, specItem, WatchColumn::Value, colors.fg);
    setBackground(wm, specItem, WatchColumn::Spec, colors.bg);
    setBackground(wm, specItem, WatchColumn::Value, colors.bg);
}

void setupWatchRootItemFromSpec(QStandardItem *specItem, QStandardItem *valueItem, const QString &spec)
{
    specItem->setFlags(specItem->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled | Qt::ItemIsSelectable |
                       Qt::ItemIsDragEnabled);
    valueItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    specItem->setText(spec);
    valueItem->setText(QString());
    specItem->setData(spec, WatchSpecRole);
    specItem->setData(QString(), WatchSubpathRole);
    specItem->setData(QVariant(false), WatchPendingNewRole);
    watchRootSetVariablePathRoleFromSpec(specItem, spec);
    auto *const placeholderSpec = new QStandardItem();
    auto *const placeholderValue = new QStandardItem();
    placeholderSpec->setFlags(Qt::ItemIsEnabled);
    placeholderValue->setFlags(Qt::ItemIsEnabled);
    specItem->appendRow({placeholderSpec, placeholderValue});
}

// NOLINTNEXTLINE(misc-no-recursion)
QStandardItem *findVariableItemByPathRecursive(QStandardItem *node, const QString &path)
{
    if (!node)
    {
        return nullptr;
    }
    if (node->data(VariablePathRole).toString() == path)
    {
        return node;
    }
    const int n = node->rowCount();
    for (int i = 0; i < n; ++i)
    {
        QStandardItem *r = findVariableItemByPathRecursive(node->child(i), path);
        if (r)
        {
            return r;
        }
    }
    return nullptr;
}

QString watchItemExpansionKey(const QStandardItem *item)
{
    if (!item || !item->parent())
    {
        return QString();
    }
    const QString sp = item->data(WatchSubpathRole).toString();
    if (!sp.isEmpty())
    {
        return sp;
    }
    return item->data(VariablePathRole).toString();
}

} // namespace LuaDebuggerPath

/* ===== header_styles ===== */

const QString kLuaDbgHeaderPlus{QStringLiteral("\uFF0B")};
const QString kLuaDbgHeaderMinus{QStringLiteral("\uFF0D")};
const QString kLuaDbgHeaderEdit{QStringLiteral("\u2699")};
const QString kLuaDbgHeaderRemoveAll{QStringLiteral("\u24CD")};
const QString kLuaDbgRowLog{QStringLiteral("\u2630")};
const QString kLuaDbgRowExtras{QStringLiteral("\u2699")};

const QString kLuaDbgHeaderToolButtonStyle{QStringLiteral("QToolButton { border: none; padding: 0px; margin: 0px; }")};

void luaDbgDrawBreakpointDot(QPainter &painter, qreal dotLeft, qreal dotTop, qreal radius, bool enabled,
                             bool hasExtras, int alpha)
{
    if (radius <= 0.0)
    {
        return;
    }

    const int clampedAlpha = qBound(0, alpha, 255);

    QColor fill = enabled ? QColor(QStringLiteral("#DC3545")) : QColor(QStringLiteral("#808080"));
    fill.setAlpha(clampedAlpha);

    QColor rim = fill.darker(140);
    rim.setAlpha(clampedAlpha);

    painter.setBrush(fill);
    painter.setPen(QPen(rim, 1.0));
    painter.drawEllipse(QRectF(dotLeft, dotTop, radius * 2.0, radius * 2.0));

    if (hasExtras)
    {
        QColor core(Qt::white);
        core.setAlpha(clampedAlpha);
        painter.setBrush(core);
        painter.setPen(Qt::NoPen);
        const qreal coreRadius = std::max<qreal>(2.0, radius / 2.0);
        const qreal coreX = dotLeft + radius - coreRadius;
        const qreal coreY = dotTop + radius - coreRadius;
        painter.drawEllipse(QRectF(coreX, coreY, coreRadius * 2.0, coreRadius * 2.0));
    }
}

QIcon luaDbgBreakpointHeaderIconForMode(const QFont *editorFont, LuaDbgBpHeaderIconMode mode, int headerSide, qreal dpr)
{
    if (headerSide < 4)
    {
        headerSide = 12;
    }
    if (dpr <= 0.0 || dpr > 8.0)
    {
        dpr = 1.0;
    }
    const QFont f = editorFont != nullptr ? *editorFont : QGuiApplication::font();
    const QFontMetrics fm(f);
    const int r = fm.height() / 2 - 2;
    int diam = 2 * qMax(0, r);
    diam = qMax(6, qMin(diam, headerSide - 4));
    const qreal s = static_cast<qreal>(headerSide);
    const qreal d = static_cast<qreal>(diam);
    const QRectF circleRect((s - d) / 2.0, (s - d) / 2.0, d, d);

    QPixmap pm(QSize(headerSide, headerSide) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    {
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing, true);
        bool enabled = false;
        switch (mode)
        {
        case LuaDbgBpHeaderIconMode::NoBreakpoints:
        case LuaDbgBpHeaderIconMode::ActivateAll:
            enabled = false;
            break;
        case LuaDbgBpHeaderIconMode::DeactivateAll:
            enabled = true;
            break;
        }
        luaDbgDrawBreakpointDot(p, circleRect.left(), circleRect.top(), circleRect.width() / 2.0, enabled);
    }
    return QIcon(pm);
}

QIcon luaDbgPaintedGlyphIcon(const QString &glyph, int side, qreal dpr,
                             const QFont &baseFont, const QColor &color,
                             int margin)
{
    if (glyph.isEmpty())
    {
        return QIcon();
    }
    if (side < 8)
    {
        side = 8;
    }
    if (dpr <= 0.0 || dpr > 8.0)
    {
        dpr = 1.0;
    }

    /* Size by ink extent (tightBoundingRect) instead of the typographic
     * box, so glyphs with design padding around the ink still reach the
     * requested side. Two phases: shrink from a coarse upper bound until
     * the inked rect fits, then grow by 0.5 pt while it still fits. The
     * upper cap (side*4 pt) prevents runaway growth when the font cannot
     * render the glyph at all. The @p margin reserves transparent
     * padding on each side of the cell so callers can dial back how
     * tightly the ink fills the icon. */
    const int safeMargin = qMax(0, margin);
    QFont f = baseFont;
    f.setPointSizeF(static_cast<qreal>(side));
    const qreal target = qMax(2.0, static_cast<qreal>(side) - 2.0 * safeMargin);
    const qreal upperCap = static_cast<qreal>(side) * 4.0;
    auto tightOf = [&glyph](const QFont &candidate) {
        const QFontMetricsF fm(candidate);
        return fm.tightBoundingRect(glyph);
    };
    auto tightFits = [&](const QFont &candidate) {
        const QRectF r = tightOf(candidate);
        return r.width() <= target && r.height() <= target;
    };
    for (int k = 0; k < 60 && f.pointSizeF() > 3.0 && !tightFits(f); ++k)
    {
        f.setPointSizeF(f.pointSizeF() - 0.5);
    }
    for (int k = 0; k < 120 && f.pointSizeF() < upperCap; ++k)
    {
        QFont tryF = f;
        tryF.setPointSizeF(f.pointSizeF() + 0.5);
        if (!tightFits(tryF))
        {
            break;
        }
        f = tryF;
    }

    QPixmap pm(QSize(side, side) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    {
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.setRenderHint(QPainter::TextAntialiasing, true);
        p.setFont(f);
        p.setPen(color);
        /* Position by ink extent: Qt::AlignCenter on a rect would centre
         * the typographic box (ascent + descent + horizontal advance),
         * which at the grown font size is much larger than the cell and
         * causes the glyph to overflow or be clipped. Anchor the tight
         * rect at the cell centre instead. */
        const QRectF tight = tightOf(f);
        const qreal drawX = (static_cast<qreal>(side) - tight.width()) / 2.0 - tight.left();
        const qreal drawY = (static_cast<qreal>(side) - tight.height()) / 2.0 - tight.top();
        p.drawText(QPointF(drawX, drawY), glyph);
    }
    return QIcon(pm);
}

QIcon luaDbgPaintedGlyphButtonIcon(const QString &glyph, int side, qreal dpr,
                                   const QFont &baseFont, const QPalette &palette,
                                   int margin)
{
    const QColor active = palette.color(QPalette::Active, QPalette::ButtonText);
    const QColor disabled = palette.color(QPalette::Disabled, QPalette::ButtonText);
    QIcon icon = luaDbgPaintedGlyphIcon(glyph, side, dpr, baseFont, active, margin);
    QIcon disabledIcon = luaDbgPaintedGlyphIcon(glyph, side, dpr, baseFont, disabled, margin);
    icon.addPixmap(disabledIcon.pixmap(QSize(side, side)), QIcon::Disabled);
    return icon;
}

void styleLuaDebuggerHeaderBreakpointToggleButton(QToolButton *btn, int side)
{
    btn->setToolButtonStyle(Qt::ToolButtonIconOnly);
    btn->setIconSize(QSize(side, side));
    btn->setFixedSize(side, side);
    btn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    btn->setText(QString());
}

void styleLuaDebuggerHeaderFittedTextButton(QToolButton *btn, int side, const QFont &titleFont,
                                            const QStringList &glyphs)
{
    if (glyphs.isEmpty())
    {
        return;
    }
    const QString &shrinkKey = glyphs[0];
    btn->setToolButtonStyle(Qt::ToolButtonTextOnly);
    QFont f = titleFont;
    for (int k = 0; k < 45 && f.pointSizeF() > 3.0; ++k)
    {
        QFontMetricsF m(f);
        const QRectF r = m.boundingRect(shrinkKey);
        if (m.height() <= static_cast<qreal>(side) + 0.5 && r.height() <= static_cast<qreal>(side) + 0.5)
        {
            break;
        }
        f.setPointSizeF(f.pointSizeF() - 0.5);
    }
    for (int k = 0; k < 3; ++k)
    {
        QFont tryF = f;
        tryF.setPointSizeF(f.pointSizeF() + 0.5);
        QFontMetricsF m(tryF);
        qreal rMax = 0.0;
        for (const QString &g : glyphs)
        {
            rMax = std::max(rMax, m.boundingRect(g).height());
        }
        if (m.height() <= static_cast<qreal>(side) + 0.5 && rMax <= static_cast<qreal>(side) + 0.5)
        {
            f = tryF;
        }
        else
        {
            break;
        }
    }
    btn->setFont(f);
    btn->setFixedSize(side, side);
    btn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    btn->setIcon(QIcon());
}

void styleLuaDebuggerHeaderPlusMinusButton(QToolButton *btn, int side, const QFont &titleFont)
{
    const QStringList pm{kLuaDbgHeaderPlus, kLuaDbgHeaderMinus};
    styleLuaDebuggerHeaderFittedTextButton(btn, side, titleFont, pm);
}

void styleLuaDebuggerHeaderIconOnlyButton(QToolButton *btn, int side)
{
    btn->setToolButtonStyle(Qt::ToolButtonIconOnly);
#ifdef Q_OS_MAC
    const int btnSide = side;
#else
    const int btnSide = qMax(1, side - 2);
#endif
    btn->setIconSize(QSize(btnSide, btnSide));
    btn->setFixedSize(btnSide, btnSide);
    btn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    btn->setText(QString());
}

QIcon luaDbgErrorBreakHeaderIcon(bool checked, int side, qreal dpr,
                                 const QFont &titleFont, const QPalette &palette)
{
    /* Paint a warning-sign glyph (U+26A0 + U+FE0E text-presentation
     * selector for monochrome rendering across platforms), red when
     * checked (active), gray when unchecked. Matches the red color
     * (#DC3545) used in the Toggle All button when active. */
    QColor glyphColor = checked ? QColor(QStringLiteral("#DC3545"))
                                : palette.color(QPalette::Disabled, QPalette::Text);

    QIcon icon = luaDbgPaintedGlyphButtonIcon(
        QString::fromUtf8("\xe2\x9a\xa0\xef\xb8\x8e"),
        side, dpr, titleFont, palette, /*margin=*/2);
    QPixmap pixmap = icon.pixmap(side, side, checked ? QIcon::Normal : QIcon::Disabled);

    if (!pixmap.isNull()) {
        QImage img = pixmap.toImage();
        for (int y = 0; y < img.height(); ++y) {
            for (int x = 0; x < img.width(); ++x) {
                QColor c = img.pixelColor(x, y);
                if (c.alpha() > 0) {
                    c.setRed(glyphColor.red());
                    c.setGreen(glyphColor.green());
                    c.setBlue(glyphColor.blue());
                    img.setPixelColor(x, y, c);
                }
            }
        }
        icon = QIcon(QPixmap::fromImage(img));
    }
    return icon;
}

QIcon luaDbgMakeSelectionAwareIcon(const QIcon &base, const QPalette &palette)
{
    if (base.isNull())
    {
        return base;
    }

    QIcon out;
    QList<QSize> sizes = base.availableSizes();
    if (sizes.isEmpty())
    {
        sizes = {QSize(16, 16), QSize(22, 22), QSize(32, 32)};
    }

    for (const QSize &sz : sizes)
    {
        const QPixmap normalPm = base.pixmap(sz);
        if (normalPm.isNull())
        {
            continue;
        }
        out.addPixmap(normalPm, QIcon::Normal);

        QPixmap tintedPm(normalPm.size());
        tintedPm.setDevicePixelRatio(normalPm.devicePixelRatio());
        tintedPm.fill(Qt::transparent);
        QPainter p(&tintedPm);
        p.drawPixmap(0, 0, normalPm);
        p.setCompositionMode(QPainter::CompositionMode_SourceIn);
        p.fillRect(tintedPm.rect(), palette.color(QPalette::Active, QPalette::HighlightedText));
        p.end();
        out.addPixmap(tintedPm, QIcon::Selected);
    }
    return out;
}

/* ===== key_router ===== */

namespace
{

/**
 * @brief True if @a pressed is one of the debugger shortcuts that overlap the
 *        main window and must be reserved in ShortcutOverride.
 */
bool matchesLuaDebuggerShortcutKeys(Ui::LuaDebuggerDialog *ui, const QKeySequence &pressed)
{
    return (pressed.matches(ui->actionFind->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionSaveFile->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionGoToLine->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionReloadLuaPlugins->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionAddWatch->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionContinue->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionStepIn->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(kLuaDbgCtxRunToLine) == QKeySequence::ExactMatch) ||
           (pressed.matches(kLuaDbgCtxToggleBreakpoint) == QKeySequence::ExactMatch) ||
           (pressed.matches(kLuaDbgCtxWatchCopyValue) == QKeySequence::ExactMatch) ||
           (pressed.matches(kLuaDbgCtxWatchDuplicate) == QKeySequence::ExactMatch);
}

/**
 * @brief Run debugger toolbar actions that share shortcuts with the main window.
 *
 * When a capture file is open, Wireshark enables Find Packet (Ctrl+F) and
 * Go to Packet (Ctrl+G). QEvent::ShortcutOverride is handled separately: we only
 * accept() there so Qt does not activate the main-window QAction; triggering
 * happens on KeyPress only. Doing both would call showAccordionFrame(..., true)
 * twice and toggle the bar closed immediately after opening.
 *
 * @return True if @a pressed matches one of these shortcuts (handled or not).
 */
bool triggerLuaDebuggerShortcuts(Ui::LuaDebuggerDialog *ui, const QKeySequence &pressed)
{
    if (pressed.matches(ui->actionFind->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionFind->isEnabled())
        {
            ui->actionFind->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionSaveFile->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionSaveFile->isEnabled())
        {
            ui->actionSaveFile->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionGoToLine->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionGoToLine->isEnabled())
        {
            ui->actionGoToLine->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionReloadLuaPlugins->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionReloadLuaPlugins->isEnabled())
        {
            ui->actionReloadLuaPlugins->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionAddWatch->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionAddWatch->isEnabled())
        {
            ui->actionAddWatch->trigger();
        }
        return true;
    }
    return false;
}

/** @brief Walk @a obj's parent chain looking for an enclosing
 *  @ref LuaDebuggerCodeView. Used so a keypress delivered to a code
 *  view's viewport (or any nested child) is routed back to the
 *  owning editor for line-aware actions. */
LuaDebuggerCodeView *codeViewFromObject(QObject *obj)
{
    for (QObject *o = obj; o; o = o->parent())
    {
        if (auto *cv = qobject_cast<LuaDebuggerCodeView *>(o))
        {
            return cv;
        }
    }
    return nullptr;
}

} // namespace

LuaDebuggerKeyRouter::LuaDebuggerKeyRouter(LuaDebuggerDialog *host)
    : host_(host)
{
}

void LuaDebuggerKeyRouter::attach(Ui::LuaDebuggerDialog *ui, QTreeView *breakpointsTree)
{
    ui_ = ui;
    breakpointsTree_ = breakpointsTree;
}

bool LuaDebuggerKeyRouter::reserveShortcutOverride(const QKeyEvent *ke) const
{
    if (!ui_)
    {
        return false;
    }
    const QKeySequence pressed = luaDbgSeqFromKeyEvent(ke);
    /*
     * Reserve debugger-owned overlaps before Qt can dispatch app-level
     * shortcuts in the main window. Keep this matcher aligned with any
     * debugger shortcut that can collide with global actions.
     */
    return pressed.matches(QKeySequence::Quit) == QKeySequence::ExactMatch ||
           matchesLuaDebuggerShortcutKeys(ui_, pressed);
}

bool LuaDebuggerKeyRouter::handleKeyPress(QObject *obj, const QKeyEvent *ke)
{
    if (!host_ || !ui_)
    {
        return false;
    }

    if (breakpointsTree_ && (obj == breakpointsTree_ || obj == breakpointsTree_->viewport()))
    {
        if (breakpointsTree_->hasFocus() ||
            (breakpointsTree_->viewport() && breakpointsTree_->viewport()->hasFocus()))
        {
            const QKeySequence pressedB = luaDbgSeqFromKeyEvent(ke);
            if (pressedB.matches(QKeySequence::Delete) == QKeySequence::ExactMatch ||
                pressedB.matches(Qt::Key_Backspace) == QKeySequence::ExactMatch)
            {
                if (host_->breakpointsController().removeSelected())
                {
                    return true;
                }
            }
        }
    }

    /* Watch-tree shortcuts (Ctrl+Shift+K / Ctrl+Shift+C / Ctrl+Shift+D /
     * Delete / F2) live on LuaDbgWatchTreeWidget itself: the
     * ShortcutOverride above still claims the ones that overlap
     * main-window actions, then Qt re-delivers the KeyPress to the focused
     * widget which dispatches via its request* signals (see wireWatchPanel).
     */
    if (LuaDebuggerCodeView *const focusCv = codeViewFromObject(obj))
    {
        if (focusCv->hasFocus() || (focusCv->viewport() && focusCv->viewport()->hasFocus()))
        {
            const QKeySequence pCv = luaDbgSeqFromKeyEvent(ke);
            const qint32 line = static_cast<qint32>(focusCv->textCursor().blockNumber() + 1);
            if (pCv.matches(kLuaDbgCtxToggleBreakpoint) == QKeySequence::ExactMatch)
            {
                host_->breakpointsController().toggleOnCodeViewLine(focusCv, line);
                return true;
            }
            if (host_->pauseController().hasActiveLoop() &&
                pCv.matches(kLuaDbgCtxRunToLine) == QKeySequence::ExactMatch)
            {
                host_->runToCurrentLineInPausedEditor(focusCv, line);
                return true;
            }
        }
    }

    /*
     * Esc must be handled here: QPlainTextEdit accepts Key_Escape without
     * propagating to QDialog::keyPressEvent, so reject() never runs.
     * Dismiss inline find/go bars first; then queue close() so closeEvent()
     * runs (unsaved-scripts prompt). Skip if a different modal dialog owns
     * the event (e.g. nested prompt).
     */
    const QKeySequence pressed = luaDbgSeqFromKeyEvent(ke);
    if (pressed.matches(Qt::Key_Escape) == QKeySequence::ExactMatch)
    {
        QWidget *const modal = QApplication::activeModalWidget();
        if (modal && modal != host_)
        {
            return false;
        }
        host_->handleEscapeKey();
        return true;
    }
    if (pressed.matches(QKeySequence::Quit) == QKeySequence::ExactMatch)
    {
        /*
         * Keep Ctrl+Q semantics identical to main-window quit when the
         * debugger has unsaved scripts: run the debugger close gate first
         * (Save/Discard/Cancel), then re-deliver main close if accepted.
         */
        QWidget *const modal = QApplication::activeModalWidget();
        if (modal && modal != host_)
        {
            return false;
        }
        LuaDebuggerMainClosePolicy::markQuitRequested();
        QMetaObject::invokeMethod(host_, "close", Qt::QueuedConnection);
        return true;
    }
    return triggerLuaDebuggerShortcuts(ui_, pressed);
}

/* ===== change_tracker ===== */

using namespace LuaDebuggerPath;

namespace
{

QColor blendRgb(const QColor &base, const QColor &accent, int alpha)
{
    const int a = std::max(0, std::min(255, alpha));
    const int inv = 255 - a;
    return QColor::fromRgb((base.red() * inv + accent.red() * a) / 255, (base.green() * inv + accent.green() * a) / 255,
                           (base.blue() * inv + accent.blue() * a) / 255);
}

QVector<QStandardItem *> rowCellsFor(QStandardItem *anchor)
{
    QVector<QStandardItem *> out;
    if (!anchor)
    {
        return out;
    }
    auto *model = qobject_cast<QStandardItemModel *>(anchor->model());
    if (!model)
    {
        return out;
    }
    const int cols = model->columnCount();
    QStandardItem *parent = anchor->parent();
    const int row = anchor->row();
    for (int c = 0; c < cols; ++c)
    {
        QStandardItem *cell = parent ? parent->child(row, c) : model->item(row, c);
        if (cell)
        {
            out.append(cell);
        }
    }
    return out;
}

void scheduleFlashClear(QObject *owner, QStandardItem *cell, qint32 serial, int delayMs)
{
    if (!cell || !cell->model())
    {
        return;
    }
    QPointer<QAbstractItemModel> modelGuard(cell->model());
    const QPersistentModelIndex pix(cell->index());
    QTimer::singleShot(delayMs, owner,
                       [modelGuard, pix, serial]()
                       {
                           if (!modelGuard || !pix.isValid())
                           {
                               return;
                           }
                           auto *sim = qobject_cast<QStandardItemModel *>(modelGuard.data());
                           if (!sim)
                           {
                               return;
                           }
                           QStandardItem *c = sim->itemFromIndex(pix);
                           if (!c)
                           {
                               return;
                           }
                           if (c->data(ChangedFlashSerialRole).toInt() != serial)
                           {
                               return;
                           }
                           c->setBackground(QBrush());
                           c->setData(QVariant(), ChangedFlashSerialRole);
                       });
}

} // namespace

void LuaDebuggerChangeHighlightTracker::refreshChangedValueBrushes(QTreeView *watchTree, QWidget *dialogWidget)
{
    QPalette pal = dialogWidget ? dialogWidget->palette() : QApplication::palette();
    if (watchTree)
    {
        pal = watchTree->palette();
    }

    QColor accent = ColorUtils::themeLinkBrush().color();
    if (!accent.isValid())
    {
        accent = QApplication::palette().color(QPalette::Highlight);
    }
    if (!accent.isValid())
    {
        accent = QColor(0x1F, 0x6F, 0xEB);
    }
    changedValueBrush_ = QBrush(accent);

    const QColor base = pal.color(QPalette::Base);
    const QColor hi = pal.color(QPalette::Highlight);
    changedFlashBrush_ = QBrush(blendRgb(base, hi, 50));
}

void LuaDebuggerChangeHighlightTracker::snapshotBaselinesOnPauseEntry()
{
    watchRootBaseline_ = std::move(watchRootCurrent_);
    watchRootCurrent_.clear();
    watchChildBaseline_ = std::move(watchChildCurrent_);
    watchChildCurrent_.clear();
    variablesBaseline_ = std::move(variablesCurrent_);
    variablesCurrent_.clear();
    variablesBaselineParents_ = std::move(variablesCurrentParents_);
    variablesCurrentParents_.clear();
    watchChildBaselineParents_ = std::move(watchChildCurrentParents_);
    watchChildCurrentParents_.clear();
}

void LuaDebuggerChangeHighlightTracker::updatePauseEntryFrameIdentity()
{
    int32_t frameCount = 0;
    wslua_stack_frame_t *stack = wslua_debugger_get_stack(&frameCount);

    QString newIdentity;
    if (stack && frameCount > 0)
    {
        const char *src = stack[0].source ? stack[0].source : "";
        newIdentity =
            QStringLiteral("%1:%2").arg(QString::fromUtf8(src)).arg(static_cast<qlonglong>(stack[0].linedefined));
    }
    if (stack)
    {
        wslua_debugger_free_stack(stack, frameCount);
    }

    pauseEntryFrame0MatchesPrev_ = !newIdentity.isEmpty() && newIdentity == pauseEntryFrame0Identity_;
    pauseEntryFrame0Identity_ = newIdentity;
}

void LuaDebuggerChangeHighlightTracker::applyChangedVisuals(QObject *timerOwner, QStandardItem *anchor, bool changed)
{
    if (!anchor)
    {
        return;
    }

    const QVector<QStandardItem *> cells = rowCellsFor(anchor);
    if (cells.isEmpty())
    {
        return;
    }

    if (changed)
    {
        const qint32 serial = isPauseEntryRefresh_ ? ++flashSerial_ : 0;
        for (QStandardItem *cell : cells)
        {
            QFont f = cell->font();
            f.setBold(true);
            cell->setFont(f);
            cell->setForeground(changedValueBrush_);
            if (isPauseEntryRefresh_)
            {
                cell->setData(serial, ChangedFlashSerialRole);
                cell->setBackground(changedFlashBrush_);
                scheduleFlashClear(timerOwner, cell, serial, CHANGED_FLASH_MS);
            }
        }
    }
    else
    {
        for (QStandardItem *cell : cells)
        {
            QFont f = cell->font();
            f.setBold(false);
            cell->setFont(f);
            if (cell->data(ChangedFlashSerialRole).isValid())
            {
                cell->setData(QVariant(), ChangedFlashSerialRole);
                cell->setBackground(QBrush());
            }
        }
    }
}

void LuaDebuggerChangeHighlightTracker::clearAllChangeBaselines()
{
    watchRootBaseline_.clear();
    watchRootCurrent_.clear();
    watchChildBaseline_.clear();
    watchChildCurrent_.clear();
    variablesBaseline_.clear();
    variablesCurrent_.clear();
    variablesBaselineParents_.clear();
    variablesCurrentParents_.clear();
    watchChildBaselineParents_.clear();
    watchChildCurrentParents_.clear();
    pauseEntryFrame0Identity_.clear();
    pauseEntryFrame0MatchesPrev_ = false;
}

void LuaDebuggerChangeHighlightTracker::clearWatchBaselines()
{
    watchRootBaseline_.clear();
    watchRootCurrent_.clear();
    watchChildBaseline_.clear();
    watchChildCurrent_.clear();
    watchChildBaselineParents_.clear();
    watchChildCurrentParents_.clear();
}

bool LuaDebuggerChangeHighlightTracker::observeWatchRootValue(const QString &rootKey, const QString &value)
{
    const bool changed = LuaDebuggerPath::shouldMarkChanged(watchRootBaseline_, rootKey, value);
    watchRootCurrent_[rootKey] = value;
    return changed;
}

bool LuaDebuggerChangeHighlightTracker::observeWatchChildParent(const QString &rootKey, const QString &parentPath)
{
    const bool wasInBaseline = watchChildBaselineParents_.value(rootKey).contains(parentPath);
    watchChildCurrentParents_[rootKey].insert(parentPath);
    return wasInBaseline;
}

bool LuaDebuggerChangeHighlightTracker::observeWatchChildValue(const QString &rootKey, const QString &childPath,
                                                               const QString &value, bool parentVisited)
{
    const auto &baseline = watchChildBaseline_.value(rootKey);
    const bool changed = LuaDebuggerPath::shouldMarkChanged(baseline, childPath, value, /*flashNew=*/parentVisited);
    watchChildCurrent_[rootKey][childPath] = value;
    return changed;
}

bool LuaDebuggerChangeHighlightTracker::observeVariablesParent(const QString &parentKey)
{
    const bool wasInBaseline = variablesBaselineParents_.contains(parentKey);
    variablesCurrentParents_.insert(parentKey);
    return wasInBaseline;
}

bool LuaDebuggerChangeHighlightTracker::observeVariablesValue(const QString &variablesKey, const QString &value,
                                                              bool parentVisited)
{
    const bool changed =
        LuaDebuggerPath::shouldMarkChanged(variablesBaseline_, variablesKey, value, /*flashNew=*/parentVisited);
    variablesCurrent_[variablesKey] = value;
    return changed;
}

void LuaDebuggerChangeHighlightTracker::clearChangeBaselinesForWatchSpec(const QString &spec)
{
    if (spec.isEmpty())
    {
        return;
    }
    const auto matches = [&spec](const QString &key) { return watchSpecFromChangeKey(key) == spec; };
    for (auto *m : {&watchRootBaseline_, &watchRootCurrent_})
    {
        for (auto it = m->begin(); it != m->end();)
        {
            if (matches(it.key()))
            {
                it = m->erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
    for (auto *m : {&watchChildBaseline_, &watchChildCurrent_})
    {
        for (auto it = m->begin(); it != m->end();)
        {
            if (matches(it.key()))
            {
                it = m->erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
    for (auto *m : {&watchChildBaselineParents_, &watchChildCurrentParents_})
    {
        for (auto it = m->begin(); it != m->end();)
        {
            if (matches(it.key()))
            {
                it = m->erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
}

void LuaDebuggerChangeHighlightTracker::pruneChangeBaselinesToLiveWatchSpecs(QStandardItemModel *watchModel)
{
    if (!watchModel)
    {
        return;
    }
    QSet<QString> liveSpecs;
    const int n = watchModel->rowCount();
    for (int i = 0; i < n; ++i)
    {
        const QStandardItem *it = watchModel->item(i);
        if (!it)
        {
            continue;
        }
        const QString spec = it->data(WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            liveSpecs.insert(spec);
        }
    }
    const auto pruneMap = [&](auto &m)
    {
        for (auto it = m.begin(); it != m.end();)
        {
            if (!liveSpecs.contains(watchSpecFromChangeKey(it.key())))
            {
                it = m.erase(it);
            }
            else
            {
                ++it;
            }
        }
    };
    pruneMap(watchRootBaseline_);
    pruneMap(watchRootCurrent_);
    pruneMap(watchChildBaseline_);
    pruneMap(watchChildCurrent_);
    pruneMap(watchChildBaselineParents_);
    pruneMap(watchChildCurrentParents_);
}

bool LuaDebuggerChangeHighlightTracker::changeHighlightAllowed(int stackSelectionLevel) const
{
    return stackSelectionLevel == pauseEntryStackLevel_ && pauseEntryFrame0MatchesPrev_;
}
