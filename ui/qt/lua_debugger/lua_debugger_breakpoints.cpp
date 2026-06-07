/* lua_debugger_breakpoints.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Breakpoints panel: list/model, inline editor + mode picker,
 * gutter integration, and persistence.
 */

#include "lua_debugger_breakpoints.h"

#include <QAbstractItemDelegate>
#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QByteArray>
#include <QChar>
#include <QComboBox>
#include <QCoreApplication>
#include <QEvent>
#include <QFileInfo>
#include <QFont>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QIntValidator>
#include <QItemSelectionModel>
#include <QJsonArray>
#include <QJsonObject>
#include <QJsonValue>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLineEdit>
#include <QListView>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QObject>
#include <QPaintEvent>
#include <QPainter>
#include <QPalette>
#include <QPen>
#include <QPixmap>
#include <QPoint>
#include <QPointer>
#include <QRect>
#include <QRectF>
#include <QResizeEvent>
#include <QShowEvent>
#include <QSignalBlocker>
#include <QSize>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QString>
#include <QStringList>
#include <QStyle>
#include <QStyleOptionFrame>
#include <QStyleOptionViewItem>
#include <QStyledItemDelegate>
#include <QTabWidget>
#include <QTimer>
#include <QToolButton>
#include <QTreeView>
#include <QVariant>
#include <QWidget>

#include <climits>
#include <utility>
#include <glib.h>

#include "lua_debugger_code_editor.h"
#include "lua_debugger_dialog.h"
#include "lua_debugger_files.h"
#include "lua_debugger_settings.h"
#include "lua_debugger_utils.h"
#include "widgets/collapsible_section.h"
#include <epan/wslua/wslua_debugger.h>

/* ===== breakpoint_modes ===== */

namespace LuaDbgBreakpointModes
{

const ModeSpec kBreakpointEditModes[kModeCount] = {
    {Mode::Expression, QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Expression"),
     QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Lua expression — pause when truthy"),
     QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Evaluated each time control reaches this line; locals, "
                                                      "upvalues, and globals are visible like Watch / Evaluate.\n"
                                                      "Runtime errors are treated as false (silent) and surface as "
                                                      "a warning icon on the row.")},
    {Mode::HitCount, QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Hit Count"),
     QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Pause after N hits (0 disables)"),
     QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Gate the pause on a hit counter. The dropdown next to N "
                                                      "picks the comparison mode: from pauses on every hit "
                                                      "from N onwards (default); every pauses on hits N, 2N, "
                                                      "3N, \xe2\x80\xa6; once pauses on the N-th hit and "
                                                      "deactivates the breakpoint. Use 0 to disable the gate. The "
                                                      "counter is preserved across edits to Expression / Hit "
                                                      "Count / Log Message; lowering the target below the current "
                                                      "count rolls the counter back to 0 so the breakpoint can "
                                                      "wait for the next N hits. Right-click the row to reset it "
                                                      "explicitly. Combined with an Expression on the same row, "
                                                      "the hit-count gate runs first.")},
    {Mode::LogMessage, QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Log Message"),
     QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Log message — supports {expr} and tags such as {filename}, "
                                                      "{basename}, {line}, {function}, {hits}, {timestamp}, "
                                                      "{delta}\xe2\x80\xa6"),
     QT_TRANSLATE_NOOP("BreakpointConditionDelegate", "Logpoints write a message to the Evaluate output (and "
                                                      "Wireshark's info log) each time the line is reached. By "
                                                      "default execution continues without pausing; tick the "
                                                      "Pause box on this editor to also pause after emitting "
                                                      "(useful for log-then-inspect without duplicating the "
                                                      "breakpoint). The line is emitted verbatim — there is no "
                                                      "automatic file:line prefix. Inside {} the text is "
                                                      "evaluated as a Lua expression in this frame and "
                                                      "converted to text the same way tostring() does; "
                                                      "reserved tags below shadow any same-named Lua local / "
                                                      "upvalue / global. "
                                                      "Origin: {filename}, {basename}, {line}, {function}, "
                                                      "{what}. Counters and scope: {hits}, {depth}, {thread}. "
                                                      "Time: {timestamp}, {datetime}, {epoch}, {epoch_ms}, "
                                                      "{elapsed}, {delta}. Use {{ and }} for literal { and }. "
                                                      "Per-placeholder errors substitute '<error: ...>' without "
                                                      "aborting the line.")},
};

QString translatedLabel(const ModeSpec &spec)
{
    return QCoreApplication::translate("BreakpointConditionDelegate", spec.label);
}

const char *draftPropertyName(Mode m)
{
    switch (m)
    {
    case Mode::Expression:
        return "luaDbgDraftExpression";
    case Mode::HitCount:
        return "luaDbgDraftHitCount";
    case Mode::LogMessage:
        return "luaDbgDraftLogMessage";
    }
    return "luaDbgDraftExpression";
}

QComboBox *editorHitModeCombo(QWidget *editor)
{
    if (!editor)
    {
        return nullptr;
    }
    return qobject_cast<QComboBox *>(editor->property("luaDbgHitModeCombo").value<QObject *>());
}

QToolButton *editorPauseToggle(QWidget *editor)
{
    if (!editor)
    {
        return nullptr;
    }
    return qobject_cast<QToolButton *>(editor->property("luaDbgPauseCheckBox").value<QObject *>());
}

void applyEditorMode(QWidget *editor, int modeIndex)
{
    if (!editor || modeIndex < 0 || modeIndex >= kModeCount)
    {
        return;
    }
    QLineEdit *valueEdit = qobject_cast<QLineEdit *>(editor);
    if (!valueEdit)
    {
        return;
    }

    const ModeSpec &spec = kBreakpointEditModes[modeIndex];
    const Mode newMode = spec.mode;
    const int prevModeRaw = editor->property("luaDbgCurrentMode").toInt();

    /* Stash whatever was in the line edit under the OLD mode's
     * draft slot before we overwrite it. -1 (the createEditor
     * sentinel) means "first call, nothing to stash yet". */
    if (prevModeRaw >= 0)
    {
        const auto prevMode = static_cast<Mode>(prevModeRaw);
        editor->setProperty(draftPropertyName(prevMode), valueEdit->text());
    }

    /* Restore (or seed, on the very first call) the new mode's
     * draft into the line edit. */
    const QString draft = editor->property(draftPropertyName(newMode)).toString();
    valueEdit->setText(draft);

    /* Validator: only the Hit Count mode constrains input. The
     * old validator (if any) is owned by the line edit, so
     * setValidator(nullptr) lets Qt clean it up on next attach. */
    if (newMode == Mode::HitCount)
    {
        valueEdit->setValidator(new QIntValidator(0, INT_MAX, valueEdit));
    }
    else
    {
        valueEdit->setValidator(nullptr);
    }

    if (spec.placeholder)
    {
        valueEdit->setPlaceholderText(QCoreApplication::translate("BreakpointConditionDelegate", spec.placeholder));
    }
    else
    {
        valueEdit->setPlaceholderText(QString());
    }
    if (spec.valueTooltip)
    {
        valueEdit->setToolTip(QCoreApplication::translate("BreakpointConditionDelegate", spec.valueTooltip));
    }
    else
    {
        valueEdit->setToolTip(QString());
    }

    if (QComboBox *hitModeCombo = editorHitModeCombo(editor))
    {
        hitModeCombo->setVisible(newMode == Mode::HitCount);
    }
    if (QToolButton *pauseChk = editorPauseToggle(editor))
    {
        pauseChk->setVisible(newMode == Mode::LogMessage);
    }

    editor->setProperty("luaDbgCurrentMode", static_cast<int>(newMode));

    /* The auxiliary visibility just changed; have the line edit
     * re-run its embedded-widget layout so the right-side text
     * margin matches what's currently shown. (BreakpointInlineLineEdit
     * has no Q_OBJECT — it adds no signals/slots/Q_PROPERTYs over
     * QLineEdit — so we use dynamic_cast rather than qobject_cast.) */
    if (auto *bple = dynamic_cast<BreakpointInlineLineEdit *>(editor))
    {
        bple->relayout();
    }

    valueEdit->selectAll();
}

QIcon makePauseIcon(const QPalette &palette)
{
    const int side = 16;
    const qreal dpr = 2.0;

    /* Layout: two bars, 3 px wide, with a 2 px gap, occupying the
     * central 8 px of a 16 px square. Rounded corners (1 px radius)
     * match the visual weight of macOS / Windows 11 media glyphs. */
    const qreal barW = 3.0;
    const qreal gap = 2.0;
    const qreal totalW = barW * 2 + gap;
    const qreal x0 = (side - totalW) / 2.0;
    const qreal y0 = 3.0;
    const qreal h = side - 6.0;
    const QRectF leftBar(x0, y0, barW, h);
    const QRectF rightBar(x0 + barW + gap, y0, barW, h);

    const auto drawBars = [&](QPainter *p, const QColor &color)
    {
        p->setPen(Qt::NoPen);
        p->setBrush(color);
        p->drawRoundedRect(leftBar, 1.0, 1.0);
        p->drawRoundedRect(rightBar, 1.0, 1.0);
    };

    const auto makePixmap = [&]()
    {
        QPixmap pm(int(side * dpr), int(side * dpr));
        pm.setDevicePixelRatio(dpr);
        pm.fill(Qt::transparent);
        return pm;
    };

    QIcon out;

    /* Off: bars in regular text color on transparent background. */
    {
        QPixmap pm = makePixmap();
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing, true);
        drawBars(&p, palette.color(QPalette::Active, QPalette::ButtonText));
        p.end();
        out.addPixmap(pm, QIcon::Normal, QIcon::Off);
    }

    /* On: white bars on transparent background. The stylesheet on
     * the QToolButton supplies the colored rounded background that
     * the bars sit on. */
    {
        QPixmap pm = makePixmap();
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing, true);
        drawBars(&p, palette.color(QPalette::Active, QPalette::HighlightedText));
        p.end();
        out.addPixmap(pm, QIcon::Normal, QIcon::On);
    }

    return out;
}

QString pauseToggleStyleSheet()
{
    return QStringLiteral("QToolButton {"
                          "  border: none;"
                          "  background: transparent;"
                          "  padding: 2px;"
                          "}"
                          "QToolButton:checked {"
                          "  background-color: palette(highlight);"
                          "  border-radius: 4px;"
                          "}"
                          "QToolButton:!checked:hover {"
                          "  background-color: palette(midlight);"
                          "  border-radius: 4px;"
                          "}");
}

} // namespace LuaDbgBreakpointModes

namespace
{

/**
 * @brief Compact one-cell rendering of a breakpoint's hit-count gate.
 *
 * Returns the text for the Breakpoints list @c Hits column. The
 * running counter comes first so the eye lands on the live value;
 * the gate (if any) follows in parentheses, which visually
 * quarantine the mode glyph from being read as an operator (the
 * @c every glyph @c "\xc3\x97" is otherwise easy to misread as a
 * multiplication sign next to the count). Glyph choices match the
 * column header tooltip:
 *   - @c "\xe2\x89\xa5N" (≥N) for @ref WSLUA_HIT_COUNT_MODE_FROM
 *   - @c "\xc3\x97N"   (×N) for @ref WSLUA_HIT_COUNT_MODE_EVERY
 *   - @c "@N"          for @ref WSLUA_HIT_COUNT_MODE_ONCE
 *
 * Examples: @c "3 (\xe2\x89\xa510)" for a @c from 10 row that has
 * been hit 3 times; @c "5" for an ungated row at 5 hits.
 */
QString formatBreakpointHitsSummary(int64_t hit_count_target, int64_t hit_count, wslua_hit_count_mode_t hit_mode)
{
    QString result = QString::number(hit_count);
    if (hit_count_target > 0)
    {
        result += QStringLiteral(" (");
        switch (hit_mode)
        {
        case WSLUA_HIT_COUNT_MODE_EVERY:
            result += QString::fromUtf8("\xc3\x97");
            break;
        case WSLUA_HIT_COUNT_MODE_ONCE:
            result += QStringLiteral("@");
            break;
        case WSLUA_HIT_COUNT_MODE_FROM:
        default:
            result += QString::fromUtf8("\xe2\x89\xa5");
            break;
        }
        result += QString::number(hit_count_target);
        result += QStringLiteral(")");
    }
    return result;
}

} // namespace

/* ===== breakpoint_inline_editor ===== */


BreakpointInlineLineEdit::BreakpointInlineLineEdit(QWidget *parent) : QLineEdit(parent) {}

void BreakpointInlineLineEdit::setEmbeddedWidgets(QComboBox *modeCombo, QComboBox *hitModeCombo,
                                                  QToolButton *pauseButton)
{
    modeCombo_ = modeCombo;
    hitModeCombo_ = hitModeCombo;
    pauseButton_ = pauseButton;
    relayout();
}

void BreakpointInlineLineEdit::relayout()
{
    if (!modeCombo_ || width() <= 0)
    {
        return;
    }

    const int kInnerGap = 4;
    /* The frame width Qt's style draws around the line edit's
     * content rect. We push our embedded widgets just inside the
     * frame so they don't overlap the native border. */
    QStyleOptionFrame opt;
    initStyleOption(&opt);
    const int frameW = style()->pixelMetric(QStyle::PM_DefaultFrameWidth, &opt, this);

    /* Vertically center every embedded widget on the line edit's
     * own visual mid-line, using each widget's natural sizeHint
     * height. This is the same alignment QLineEdit's built-in
     * trailing/leading actions use, and it's what makes the row
     * read as one coherent control on every platform — combos
     * with a different intrinsic height than the line edit's text
     * area sit pixel-aligned with the caret rather than stretched
     * top-to-bottom. */
    const auto centeredRect = [this](const QSize &hint, int x)
    {
        int h = hint.height();
        if (h > height())
        {
            h = height();
        }
        const int y = (height() - h) / 2;
        return QRect(x, y, hint.width(), h);
    };

    /* QMacStyle paints the @c QComboBox's native popup arrow with
     * one pixel of optical padding above the label, which makes
     * the combo's text baseline read 1 px higher than the
     * @c QLineEdit's caret baseline when both are vertically
     * centered in the same row. Other platforms render the combo
     * flush with the line edit's text, so the nudge is macOS-only.
     * Both combos (mode on the left, hit-count comparison on the
     * right) need the same nudge so they land on a shared
     * baseline. */
#ifdef Q_OS_MACOS
    constexpr int comboBaselineNudge = 1;
#else
    constexpr int comboBaselineNudge = 0;
#endif

    int leftEdge = frameW + kInnerGap;
    int rightEdge = width() - frameW - kInnerGap;

    const QSize modeHint = modeCombo_->sizeHint();
    QRect modeRect = centeredRect(modeHint, leftEdge);
    modeRect.translate(0, comboBaselineNudge);
    modeCombo_->setGeometry(modeRect);
    leftEdge += modeHint.width() + kInnerGap;

    if (pauseButton_ && !pauseButton_->isHidden())
    {
        /* Force the toggle's height to @c editor.height() - 6 so
         * its Highlight-color chip clears the line edit's frame
         * by 3 px on top and 3 px on bottom regardless of the
         * @c QToolButton's natural sizeHint.
         *
         * Two things conspire against a "shrink to a smaller
         * height" attempt that goes through sizeHint or
         * @c centeredRect:
         *   - @c centeredRect clamps @c h to @c editor.height()
         *     when sizeHint is taller, undoing any pre-shrink.
         *   - @c QToolButton's @c sizeHint() can be smaller than
         *     the editor on some platforms, so a @c qMin with
         *     sizeHint silently keeps the natural (larger
         *     relative to the chosen inset) height.
         *
         * @c setMaximumHeight is the belt-and-braces lock —
         * @c setGeometry alone is enough today, but a future
         * re-layout triggered by Qt's polish / size-policy
         * machinery would otherwise bring back the natural
         * height. The chip stylesheet renders at the button's
         * geometry, so capping the geometry caps the chip. */
        const QSize hint = pauseButton_->sizeHint();
        const int h = qMax(0, height() - 6);
        rightEdge -= hint.width();
        pauseButton_->setMaximumHeight(h);
        const int y = (height() - h) / 2;
        pauseButton_->setGeometry(rightEdge, y, hint.width(), h);
        rightEdge -= kInnerGap;
    }
    if (hitModeCombo_ && !hitModeCombo_->isHidden())
    {
        const QSize hint = hitModeCombo_->sizeHint();
        rightEdge -= hint.width();
        QRect hitRect = centeredRect(hint, rightEdge);
        hitRect.translate(0, comboBaselineNudge);
        hitModeCombo_->setGeometry(hitRect);
        rightEdge -= kInnerGap;
    }

    /* setTextMargins reserves space inside the line edit's content
     * rect for our embedded widgets — the typing area and the
     * placeholder text never collide with the combo / checkbox. */
    const int leftMargin = leftEdge - frameW;
    const int rightMargin = (width() - frameW) - rightEdge;
    setTextMargins(leftMargin, 0, rightMargin, 0);
}

void BreakpointInlineLineEdit::resizeEvent(QResizeEvent *e)
{
    QLineEdit::resizeEvent(e);
    relayout();
}

void BreakpointInlineLineEdit::showEvent(QShowEvent *e)
{
    QLineEdit::showEvent(e);
    /* The editor was created and configured (mode, visibility of
     * the auxiliary widgets) before the view called show() on us.
     * Any earlier @c relayout() bailed out on width()==0; this
     * is the first time we're guaranteed to have a real size and
     * a settled visibility for every child. */
    relayout();
}

void BreakpointInlineLineEdit::paintEvent(QPaintEvent *e)
{
    QLineEdit::paintEvent(e);
    /* Draw an explicit 1 px border on top of the native frame.
     * QMacStyle's @c QLineEdit frame is intentionally faint
     * (especially in dark mode) and disappears against the row's
     * highlight; embedding mode / hit-mode combos and the pause
     * toggle as children clutters the cell further, so without a
     * visible border the user can no longer tell where the
     * editable area begins and ends. We draw with @c QPalette::Mid
     * so the stroke adapts to light and dark themes automatically.
     *
     * Antialiasing is left off so the 1 px stroke lands on integer
     * pixel boundaries — a crisp line rather than a half-bright
     * 2 px smear — and we inset by 1 pixel so the border lives
     * inside the widget rect (which @c QLineEdit::paintEvent has
     * just painted) instead of outside it where the native focus
     * ring lives. */
    QPainter p(this);
    QPen pen(palette().color(QPalette::Active, QPalette::Mid));
    pen.setWidth(1);
    pen.setCosmetic(true);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);
    p.drawRect(rect().adjusted(0, 0, -1, -1));
}

/* ===== breakpoint_delegate ===== */

// Inline editor for the Breakpoints list's Location column. A small mode
// picker on the left
// (Expression / Hit Count / Log Message) reconfigures the value line
// edit's validator / placeholder / tooltip to match the chosen mode and
// stashes the previously-typed text under a per-mode draft slot so
// switching back restores it. The Hit Count mode restricts input to
// non-negative integers via a QIntValidator. Each commit updates only
// the selected mode's field; the others are preserved unchanged on the
// model item.
//
// The editor IS the value @c QLineEdit (see @c BreakpointInlineLineEdit
// above); the mode combo, hit-mode combo and pause checkbox are
// children of the line edit, positioned in the line edit's text
// margins. This keeps the inline editor's parent chain identical to
// the Watch tree's bare-@c QLineEdit editor, so the platform's native
// style draws both trees' edit fields at exactly the same height with
// exactly the same frame, focus ring and selection colours.
//
// Adding a fourth mode in the future is a one-row append to
// @c LuaDbgBreakpointModes::kBreakpointEditModes plus an extension of
// @c LuaDbgBreakpointModes::applyEditorMode and the commit/load logic
// in @c setEditorData / @c setModelData below; no other site needs to
// change.

LuaDbgBreakpointConditionDelegate::LuaDbgBreakpointConditionDelegate(LuaDebuggerDialog *dialog)
    : QStyledItemDelegate(dialog)
{
}

QWidget *LuaDbgBreakpointConditionDelegate::createEditor(QWidget *parent, const QStyleOptionViewItem & /*option*/,
                                                         const QModelIndex & /*index*/) const
{
    using namespace LuaDbgBreakpointModes;

    /* The editor IS a @c QLineEdit — same widget class as the Watch
     * editor, so the platform style draws an identical inline
     * edit. The mode combo, hit-count comparison combo and "also
     * pause" checkbox are children of the line edit, positioned
     * inside the line edit's text-margin area by
     * @ref BreakpointInlineLineEdit::relayout. */
    BreakpointInlineLineEdit *editor = new BreakpointInlineLineEdit(parent);
    /* Suppress the macOS focus ring around the actively edited
     * cell — same rationale as the Watch editor: the cell
     * selection plus the explicit border drawn in
     * BreakpointInlineLineEdit::paintEvent already make the
     * edited row obvious. No-op on Linux / Windows. */
    editor->setAttribute(Qt::WA_MacShowFocusRect, false);

    QComboBox *mode = new QComboBox(editor);
    /* Force a Qt-managed popup view. macOS otherwise opens the
     * combo as a native NSMenu, which is not a Qt widget and is
     * outside the editor's parent chain; while that menu is
     * active QApplication::focusWidget() returns @c nullptr, our
     * focusChanged listener treats that as "click outside",
     * commits the pending edit and tears the editor down before
     * the user can pick a row from the dropdown. Setting an
     * explicit QListView keeps the popup inside the editor's
     * widget tree so isAncestorOf() recognises it as part of the
     * edit session. */
    mode->setView(new QListView(mode));

    for (const ModeSpec &spec : kBreakpointEditModes)
    {
        mode->addItem(translatedLabel(spec), static_cast<int>(spec.mode));
    }

    /* The hit-count comparison-mode combo and the "also pause"
     * checkbox are children of the @c BreakpointInlineLineEdit
     * just like the mode combo. They are toggled visible by the
     * mode-combo currentIndexChanged handler below; the line
     * edit's @c relayout() pass reserves text-margin space for
     * whichever ones are currently visible. */
    QComboBox *hitModeCombo = new QComboBox(editor);
    hitModeCombo->setView(new QListView(hitModeCombo));
    /* Labels are deliberately short — the integer field next to
     * the combo carries the value of N, and the tooltip below
     * spells the modes out in full. The longest label drives the
     * combo's sizeHint width inside the inline editor; keeping
     * them at 1–5 visible characters lets the row stay narrow
     * even on tight columns. */
    hitModeCombo->addItem(QCoreApplication::translate("BreakpointConditionDelegate", "from"),
                          static_cast<int>(WSLUA_HIT_COUNT_MODE_FROM));
    hitModeCombo->addItem(QCoreApplication::translate("BreakpointConditionDelegate", "every"),
                          static_cast<int>(WSLUA_HIT_COUNT_MODE_EVERY));
    hitModeCombo->addItem(QCoreApplication::translate("BreakpointConditionDelegate", "once"),
                          static_cast<int>(WSLUA_HIT_COUNT_MODE_ONCE));
    hitModeCombo->setToolTip(QCoreApplication::translate("BreakpointConditionDelegate",
                                                         "Comparison mode for the hit count:\n"
                                                         "from — pause on every hit from N onwards.\n"
                                                         "every — pause on hits N, 2N, 3N…\n"
                                                         "once — pause once on the N-th hit and deactivate the "
                                                         "breakpoint."));
    hitModeCombo->setVisible(false);

    /* Icon-only "also pause" toggle. The horizontal space inside
     * the inline editor is tight (the QLineEdit must stay
     * usable), so we drop the "Pause" word and rely on the
     * platform pause glyph plus the tooltip. We use a checkable
     * @c QToolButton (auto-raise, icon-only) rather than a
     * @c QCheckBox so the cell shows just the pause glyph
     * without an empty @c QCheckBox indicator next to it; the
     * tool button's depressed-state visual already conveys the
     * "checked" semantics. The accessibility name preserves the
     * textual label for screen readers. */
    QToolButton *pauseChk = new QToolButton(editor);
    pauseChk->setCheckable(true);
    pauseChk->setFocusPolicy(Qt::TabFocus);
    pauseChk->setToolButtonStyle(Qt::ToolButtonIconOnly);
    /* Icon is drawn from the editor's own palette so the bars
     * automatically read white in dark mode and black in light
     * mode — a fixed stock pixmap would be near-invisible in
     * one of the two themes. */
    pauseChk->setIcon(makePauseIcon(editor->palette()));
    pauseChk->setIconSize(QSize(16, 16));
    /* Stylesheet drives the on/off background: transparent when
     * unchecked (just the bars on the cell background), full
     * Highlight-color rounded chip filling the button when
     * checked. The chip is the primary on/off signal; the icon
     * colors (ButtonText vs HighlightedText) follow it.
     *
     * Using a stylesheet here also disables @c autoRaise (which
     * is no longer needed since we paint our own hover / pressed
     * feedback) — both controls would otherwise compete and
     * leave the button looking ambiguous. */
    pauseChk->setStyleSheet(pauseToggleStyleSheet());
    pauseChk->setAccessibleName(QCoreApplication::translate("BreakpointConditionDelegate", "Pause"));
    pauseChk->setToolTip(QCoreApplication::translate("BreakpointConditionDelegate",
                                                     "Pause: format and emit the log message AND pause "
                                                     "execution.\n"
                                                     "Off = logpoint only (matches the historical "
                                                     "\"logpoints never pause\" convention)."));
    pauseChk->setVisible(false);

    editor->setEmbeddedWidgets(mode, hitModeCombo, pauseChk);

    editor->setProperty("luaDbgModeCombo", QVariant::fromValue<QObject *>(mode));
    editor->setProperty("luaDbgHitModeCombo", QVariant::fromValue<QObject *>(hitModeCombo));
    editor->setProperty("luaDbgPauseCheckBox", QVariant::fromValue<QObject *>(pauseChk));

    /* Per-mode draft text caches. The editor is a single line edit
     * shared across all three modes, so when the user switches mode
     * we have to remember what they typed under the previous mode
     * and restore what they had typed (or the persisted value, see
     * setEditorData) under the new mode. */
    editor->setProperty(draftPropertyName(Mode::Expression), QString());
    editor->setProperty(draftPropertyName(Mode::HitCount), QString());
    editor->setProperty(draftPropertyName(Mode::LogMessage), QString());
    /* -1 means "not initialised yet" so the very first
     * applyEditorMode does not write the empty current text into a
     * draft slot before it has loaded the actual draft. */
    editor->setProperty("luaDbgCurrentMode", -1);

    QObject::connect(mode, QOverload<int>::of(&QComboBox::currentIndexChanged), editor,
                     [editor](int idx) { applyEditorMode(editor, idx); });

    /* Install the event filter only on widgets whose lifetime
     * we explicitly manage:
     *   - the editor itself, which IS the QLineEdit (focus /
     *     Escape / generic safety net),
     *   - the popup view of every QComboBox in the editor
     *     (Show/Hide tracking; lets the focus-out commit logic
     *     keep the editor alive while any combo dropdown is
     *     open, including the inner hit-count-mode combo).
     *
     * Restricting the filter to widgets we own keeps @c watched
     * pointers stable: events emitted from partially-destroyed
     * children during editor teardown (e.g. ~QComboBox calling
     * close()/setVisible(false) and emitting Hide) never reach
     * the filter, so qobject_cast on the watched pointer cannot
     * dereference a freed vtable. */
    LuaDbgBreakpointConditionDelegate *self = const_cast<LuaDbgBreakpointConditionDelegate *>(this);
    editor->installEventFilter(self);
    const auto installPopupFilter = [self, editor](QComboBox *combo)
    {
        if (!combo || !combo->view())
        {
            return;
        }
        /* Tag the view with its owning editor so the eventFilter
         * Show/Hide branch can update the popup-open counter
         * without walking the parent chain (which during a
         * shown-popup state goes through Qt's internal
         * QComboBoxPrivateContainer top-level, not the editor). */
        combo->view()->setProperty("luaDbgEditorOwner", QVariant::fromValue<QObject *>(editor));
        combo->view()->installEventFilter(self);
    };
    installPopupFilter(mode);
    for (QComboBox *c : editor->findChildren<QComboBox *>())
    {
        if (c != mode)
        {
            installPopupFilter(c);
        }
    }

    /* Commit-on-Enter inside the value editors.
     *
     * Wired via @c QLineEdit::returnPressed on every QLineEdit
     * inside the stack pages. We also walk page descendants so
     * a future page that hosts multiple QLineEdit children is
     * covered without changes here.
     *
     * The closeEditorOnAccept lambda is one-shot per editor —
     * the @c luaDbgClosing guard ensures commitData/closeEditor
     * are emitted at most once. Enter, focus loss and the
     * delegate's own event filter can race to commit, and
     * re-emitting on an already-tearing-down editor crashes the
     * view. */
    const auto closeEditorOnAccept = [self](QWidget *editorWidget)
    {
        if (!editorWidget)
        {
            return;
        }
        if (editorWidget->property("luaDbgClosing").toBool())
        {
            return;
        }
        editorWidget->setProperty("luaDbgClosing", true);
        emit self->commitData(editorWidget);
        emit self->closeEditor(editorWidget, QAbstractItemDelegate::SubmitModelCache);
    };
    QObject::connect(editor, &QLineEdit::returnPressed, editor,
                     [closeEditorOnAccept, editor]() { closeEditorOnAccept(editor); });

    /* The editor IS the value line edit, so it receives keyboard
     * focus by default when QAbstractItemView shows it. The mode
     * combo, hit-mode combo and pause checkbox are reachable with
     * Tab as ordinary children of the line edit. */

    /* Click-outside-to-commit. QStyledItemDelegate's built-in
     * "FocusOut closes the editor" hook only watches the editor
     * widget itself; if the user opens the mode combo's popup and
     * then clicks somewhere outside the row, focus moves to a
     * widget that is neither the editor nor a descendant, so the
     * built-in handler doesn't fire — we have to do this in
     * @c QApplication::focusChanged instead.
     *
     * Listen to QApplication::focusChanged instead, deferring the
     * decision via a zero-delay timer so the new focus has settled
     * (covers both ordinary clicks elsewhere and clicks that land
     * on a widget with no focus policy, where focusWidget() ends
     * up @c nullptr). The combo's popup and any tooltip we show
     * all stay descendants of @a editor and leave the editor
     * open. */
    QPointer<QWidget> editorGuard(editor);
    QPointer<QComboBox> modeGuard(mode);
    QPointer<QAbstractItemView> popupGuard(mode->view());
    /* Helper: is the user currently inside the mode combo's
     * dropdown? Combines the explicit open/close flag we set from
     * the eventFilter (most reliable) with `view->isVisible()`
     * as a backup; in either case we treat "popup is open" as
     * "still inside the editor" so the editor doesn't close
     * while the user is picking a mode. */
    auto popupOpen = [editorGuard, popupGuard]()
    {
        if (editorGuard && editorGuard->property("luaDbgPopupOpen").toBool())
        {
            return true;
        }
        return popupGuard && popupGuard->isVisible();
    };
    /* Helper: should the focus shift to @a w be treated as "still
     * inside the editor"? True for the editor itself, any
     * descendant, the mode combo or its descendants, and the
     * combo popup view (which Qt may parent via a top-level
     * Qt::Popup window — so isAncestorOf isn't reliable across
     * platforms). */
    auto stillInside = [editorGuard, modeGuard = std::move(modeGuard),
                        popupGuard = std::move(popupGuard)](QWidget *w)
    {
        if (!w)
        {
            return false;
        }
        if (editorGuard && (w == editorGuard.data() || editorGuard->isAncestorOf(w)))
        {
            return true;
        }
        if (modeGuard && (w == modeGuard.data() || modeGuard->isAncestorOf(w)))
        {
            return true;
        }
        if (popupGuard && (w == popupGuard.data() || popupGuard->isAncestorOf(w)))
        {
            return true;
        }
        return false;
    };
    QObject::connect(qApp, &QApplication::focusChanged, editor,
                     [self, editorGuard = std::move(editorGuard), popupOpen = std::move(popupOpen),
                      stillInside = std::move(stillInside)](QWidget *old, QWidget *now)
                     {
                         if (!editorGuard)
                         {
                             return;
                         }
                         /* Already torn down or in the process of being torn
                          * down by another commit path (Enter via
                          * returnPressed, or a previous focus-loss tick).
                          * Re-emitting commitData / closeEditor on a
                          * deleteLater'd editor crashes the view. */
                         if (editorGuard->property("luaDbgClosing").toBool())
                         {
                             return;
                         }
                         if (popupOpen())
                         {
                             return;
                         }
                         if (stillInside(now))
                         {
                             return;
                         }
                         /* Transient null-focus state (e.g. native menu/popup
                          * just took focus, app deactivation, or focus moving
                          * through a non-Qt widget): keep the editor open. The
                          * deferred timer below re-checks once focus settles. */
                         if (!now)
                         {
                             if (stillInside(old))
                             {
                                 QTimer::singleShot(0, editorGuard.data(),
                                                    [editorGuard = std::move(editorGuard),
                                                     popupOpen = std::move(popupOpen),
                                                     stillInside = std::move(stillInside), self]()
                                                    {
                                                        if (!editorGuard)
                                                        {
                                                            return;
                                                        }
                                                        if (editorGuard->property("luaDbgClosing").toBool())
                                                        {
                                                            return;
                                                        }
                                                        if (popupOpen())
                                                        {
                                                            return;
                                                        }
                                                        QWidget *fw = QApplication::focusWidget();
                                                        if (!fw || stillInside(fw))
                                                        {
                                                            return;
                                                        }
                                                        editorGuard->setProperty("luaDbgClosing", true);
                                                        emit self->commitData(editorGuard.data());
                                                        emit self->closeEditor(
                                                            editorGuard.data(),
                                                            QAbstractItemDelegate::SubmitModelCache);
                                                    });
                             }
                             return;
                         }
                         editorGuard->setProperty("luaDbgClosing", true);
                         emit self->commitData(editorGuard.data());
                         emit self->closeEditor(editorGuard.data(), QAbstractItemDelegate::SubmitModelCache);
                     });

    return editor;
}

void LuaDbgBreakpointConditionDelegate::setEditorData(QWidget *editor, const QModelIndex &index) const
{
    using namespace LuaDbgBreakpointModes;

    QLineEdit *valueEdit = qobject_cast<QLineEdit *>(editor);
    QComboBox *mode = qobject_cast<QComboBox *>(editor->property("luaDbgModeCombo").value<QObject *>());
    if (!valueEdit || !mode)
    {
        return;
    }

    const QAbstractItemModel *model = index.model();
    const QModelIndex activeIndex = model->index(index.row(), BreakpointColumn::Active, index.parent());

    const QString condition = model->data(activeIndex, BreakpointConditionRole).toString();
    const qint64 target = model->data(activeIndex, BreakpointHitTargetRole).toLongLong();
    const int hitMode = model->data(activeIndex, BreakpointHitModeRole).toInt();
    const QString logMessage = model->data(activeIndex, BreakpointLogMessageRole).toString();

    /* Seed the per-mode draft caches with the persisted values
     * before applyEditorMode() runs — applyEditorMode loads the
     * draft for the active mode into the line edit. The Hit Count
     * cache is the integer rendered as a string (empty for
     * target == 0 so the field reads as unconfigured rather than
     * literal "0"). */
    editor->setProperty(draftPropertyName(Mode::Expression), condition);
    editor->setProperty(draftPropertyName(Mode::HitCount), target > 0 ? QString::number(target) : QString());
    editor->setProperty(draftPropertyName(Mode::LogMessage), logMessage);

    if (QComboBox *hitModeCombo = editorHitModeCombo(editor))
    {
        const int comboIdx = hitModeCombo->findData(hitMode);
        hitModeCombo->setCurrentIndex(comboIdx >= 0 ? comboIdx : 0);
    }
    if (QToolButton *logPauseChk = editorPauseToggle(editor))
    {
        logPauseChk->setChecked(model->data(activeIndex, BreakpointLogAlsoPauseRole).toBool());
    }

    Mode initial = Mode::Expression;
    if (!logMessage.isEmpty())
    {
        initial = Mode::LogMessage;
    }
    else if (!condition.isEmpty())
    {
        initial = Mode::Expression;
    }
    else if (target > 0)
    {
        initial = Mode::HitCount;
    }

    const int idx = mode->findData(static_cast<int>(initial));
    if (idx >= 0)
    {
        /* setCurrentIndex fires currentIndexChanged when the index
         * actually changes, which the connected handler routes to
         * applyEditorMode. The very first edit opens with the combo
         * at its default index 0 (Expression); if @c initial is
         * also Expression, no change → no signal → the line edit
         * would never get seeded. Always invoke applyEditorMode
         * explicitly here so the editor is fully configured
         * regardless of whether the index changed. */
        QSignalBlocker blocker(mode);
        mode->setCurrentIndex(idx);
        blocker.unblock();
        applyEditorMode(editor, idx);
    }
}

void LuaDbgBreakpointConditionDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                                                     const QModelIndex &index) const
{
    using namespace LuaDbgBreakpointModes;

    QLineEdit *valueEdit = qobject_cast<QLineEdit *>(editor);
    QComboBox *mode = qobject_cast<QComboBox *>(editor->property("luaDbgModeCombo").value<QObject *>());
    if (!valueEdit || !mode)
    {
        return;
    }

    const Mode chosen = static_cast<Mode>(mode->currentData().toInt());
    const QModelIndex activeIndex = model->index(index.row(), BreakpointColumn::Active, index.parent());
    const QString currentText = valueEdit->text();

    switch (chosen)
    {
    case Mode::Expression:
    {
        /* Accept whatever the user typed unconditionally — empty
         * (clears the condition) or syntactically invalid (the
         * dispatch in LuaDebuggerBreakpointsController::onModelDataChanged
         * runs the parse checker after writing the condition and stamps
         * the row with the @c condition_error warning icon + error
         * string tooltip immediately, so a typo is visible at commit
         * time rather than only after the line has been hit). */
        model->setData(activeIndex, currentText.trimmed(), BreakpointConditionRole);
        return;
    }
    case Mode::HitCount:
    {
        /* Empty / non-numeric / negative input maps to 0 ("no hit
         * count"). The QIntValidator on the editor already rejects
         * negatives and non-digits during typing, but we still
         * tolerate empty text here so an explicit clear commits
         * cleanly. */
        const QString text = currentText.trimmed();
        bool ok = false;
        const qlonglong v = text.toLongLong(&ok);
        const qlonglong target = (ok && v > 0) ? v : 0;
        model->setData(activeIndex, target, BreakpointHitTargetRole);
        /* Persist the comparison-mode pick alongside the integer so
         * the dispatch in LuaDebuggerBreakpointsController::onModelDataChanged
         * can forward both to the core in one tick. The mode is
         * meaningful only when target > 0; we still write it for
         * target == 0 so toggling the value back on later remembers
         * the previous mode. */
        if (QComboBox *hitModeCombo = editorHitModeCombo(editor))
        {
            model->setData(activeIndex, hitModeCombo->currentData().toInt(), BreakpointHitModeRole);
        }
        return;
    }
    case Mode::LogMessage:
    {
        /* Do NOT trim — leading / trailing whitespace can be
         * intentional in a log line. */
        model->setData(activeIndex, currentText, BreakpointLogMessageRole);
        if (QToolButton *logPauseChk = editorPauseToggle(editor))
        {
            model->setData(activeIndex, logPauseChk->isChecked(), BreakpointLogAlsoPauseRole);
        }
        return;
    }
    }
}

void LuaDbgBreakpointConditionDelegate::updateEditorGeometry(QWidget *editor, const QStyleOptionViewItem &option,
                                                             const QModelIndex & /*index*/) const
{
    /* Use the row rect, but ensure the editor is at least as tall
     * as a QLineEdit's natural sizeHint so the inline inputs read
     * at the same comfortable height as the Watch inline editor.
     * The accompanying @ref sizeHint override keeps the row itself
     * tall enough to host this geometry without overlapping the
     * row below. */
    QRect rect = option.rect;
    const int preferred = preferredEditorHeight();
    if (rect.height() < preferred)
    {
        rect.setHeight(preferred);
    }
    editor->setGeometry(rect);
}

QSize LuaDbgBreakpointConditionDelegate::sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    /* The Watch tree's inline QLineEdit reads taller than the
     * default text-only Breakpoints row because the row height
     * matches QLineEdit::sizeHint(); mirror that on this column so
     * the two inline editors visually agree. The row itself
     * inherits this height through QTreeView's per-row sizing. */
    QSize base = QStyledItemDelegate::sizeHint(option, index);
    const int preferred = preferredEditorHeight();
    if (base.height() < preferred)
    {
        base.setHeight(preferred);
    }
    return base;
}

bool LuaDbgBreakpointConditionDelegate::eventFilter(QObject *watched, QEvent *event)
{
    /* Track the open state of every QComboBox popup inside the
     * editor via Show/Hide events on its view. We can't rely on
     * `view->isVisible()` racing with focusChanged, and Qt has
     * no aboutToShow/aboutToHide signal on QComboBox we can use
     * here. We store a refcount on the editor (luaDbgPopupOpenCount)
     * so that ANY open dropdown — outer mode selector or the
     * inner hit-count-mode combo — keeps the editor alive
     * during focus shifts to its popup. The boolean
     * luaDbgPopupOpen is also kept in sync as a convenience for
     * existing readers.
     *
     * @c watched is guaranteed to be a popup view we explicitly
     * installed on in createEditor(), and its
     * @c luaDbgEditorOwner property points to the owning editor
     * that we set at install time. We avoid walking the runtime
     * parent chain because Qt reparents popup views into a
     * private top-level container while the popup is shown. */
    if (event->type() == QEvent::Show || event->type() == QEvent::Hide)
    {
        QWidget *view = qobject_cast<QWidget *>(watched);
        if (view)
        {
            QWidget *owner = qobject_cast<QWidget *>(view->property("luaDbgEditorOwner").value<QObject *>());
            if (owner)
            {
                int n = owner->property("luaDbgPopupOpenCount").toInt();
                if (event->type() == QEvent::Show)
                {
                    ++n;
                }
                else if (n > 0)
                {
                    --n;
                }
                owner->setProperty("luaDbgPopupOpenCount", n);
                owner->setProperty("luaDbgPopupOpen", n > 0);
            }
        }
    }
    /* Enter is intentionally NOT handled here. The dialog installs
     * its own descendant-shortcut filter and the platform input
     * method can both reorder/swallow key events before our
     * delegate filter sees them, which made an event-filter-based
     * Enter handler unreliable in practice. We instead wire the
     * QLineEdit's canonical "user accepted the input" signal
     * (returnPressed) in createEditor(); that is emitted by Qt
     * only after the widget has actually processed the key, and
     * it fires even when an outside filter swallowed the
     * QKeyEvent.
     *
     * We still handle Escape here because there is no Qt signal
     * for "user pressed Escape" on a QLineEdit. */
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent *ke = static_cast<QKeyEvent *>(event);
        const int key = ke->key();
        if (key != Qt::Key_Escape)
        {
            return QStyledItemDelegate::eventFilter(watched, event);
        }

        QWidget *editor = qobject_cast<QWidget *>(watched);
        if (!editor || !editor->isAncestorOf(QApplication::focusWidget()))
        {
            if (QWidget *w = qobject_cast<QWidget *>(watched))
            {
                editor = w;
                while (editor->parentWidget())
                {
                    if (editor->property("luaDbgModeCombo").isValid())
                    {
                        break;
                    }
                    editor = editor->parentWidget();
                }
            }
        }
        if (!editor)
        {
            return QStyledItemDelegate::eventFilter(watched, event);
        }

        /* Don't hijack Escape inside the mode combo or its popup;
         * the combo uses Escape to dismiss its dropdown, and we
         * want that to keep the editor open. */
        QComboBox *modeCombo = qobject_cast<QComboBox *>(editor->property("luaDbgModeCombo").value<QObject *>());
        QWidget *watchedWidget = qobject_cast<QWidget *>(watched);
        const bool inModeCombo =
            modeCombo && watchedWidget &&
            (watchedWidget == modeCombo || modeCombo->isAncestorOf(watchedWidget) ||
             (modeCombo->view() &&
              (watchedWidget == modeCombo->view() || modeCombo->view()->isAncestorOf(watchedWidget))));
        if (inModeCombo)
        {
            return QStyledItemDelegate::eventFilter(watched, event);
        }

        editor->setProperty("luaDbgClosing", true);
        emit closeEditor(editor, RevertModelCache);
        return true;
    }
    return QStyledItemDelegate::eventFilter(watched, event);
}

int LuaDbgBreakpointConditionDelegate::preferredEditorHeight() const
{
    if (cachedPreferredHeight_ <= 0)
    {
        QLineEdit probe;
        cachedPreferredHeight_ = probe.sizeHint().height();
    }
    return cachedPreferredHeight_;
}

/* ===== breakpoints_controller ===== */

LuaDebuggerBreakpointsController::LuaDebuggerBreakpointsController(LuaDebuggerDialog *host) : QObject(host), host_(host)
{
}

void LuaDebuggerBreakpointsController::attach(QTreeView *tree, QStandardItemModel *model)
{
    tree_ = tree;
    model_ = model;
    if (!tree_ || !model_)
    {
        return;
    }

    connect(model_, &QStandardItemModel::itemChanged, this, &LuaDebuggerBreakpointsController::onItemChanged);
    connect(model_, &QStandardItemModel::dataChanged, this, &LuaDebuggerBreakpointsController::onModelDataChanged);
    connect(tree_, &QTreeView::doubleClicked, this, &LuaDebuggerBreakpointsController::onItemDoubleClicked);
    connect(tree_, &QTreeView::customContextMenuRequested, this, &LuaDebuggerBreakpointsController::showContextMenu);
    connect(model_, &QAbstractItemModel::rowsInserted, this, [this]() { updateHeaderButtonState(); });
    connect(model_, &QAbstractItemModel::rowsRemoved, this, [this]() { updateHeaderButtonState(); });
    connect(model_, &QAbstractItemModel::modelReset, this, [this]() { updateHeaderButtonState(); });
    if (QItemSelectionModel *sel = tree_->selectionModel())
    {
        connect(sel, &QItemSelectionModel::selectionChanged, this, [this]() { updateHeaderButtonState(); });
    }
    updateHeaderButtonState();
}

void LuaDebuggerBreakpointsController::attachHeaderButtons(QToolButton *breakOnError, QToolButton *toggleAll,
                                                           QToolButton *remove, QToolButton *removeAll,
                                                           QToolButton *edit, QAction *removeAllAction)
{
    breakOnErrorButton_ = breakOnError;
    toggleAllButton_ = toggleAll;
    removeButton_ = remove;
    removeAllButton_ = removeAll;
    editButton_ = edit;
    removeAllAction_ = removeAllAction;

    if (breakOnErrorButton_)
    {
        connect(breakOnErrorButton_, &QToolButton::toggled, this, [this](bool checked) {
            wslua_debugger_set_error_break_enabled(checked);
            host_->ensureDebuggerEnabledForActiveBreakpoints();
        });
    }
    if (toggleAllButton_)
    {
        connect(toggleAllButton_, &QToolButton::clicked, this, &LuaDebuggerBreakpointsController::toggleAllActive);
    }
    if (removeButton_)
    {
        connect(removeButton_, &QToolButton::clicked, this, [this]() { removeSelected(); });
    }
    if (removeAllButton_)
    {
        connect(removeAllButton_, &QToolButton::clicked, this, &LuaDebuggerBreakpointsController::clearAll);
    }
    if (editButton_)
    {
        connect(editButton_, &QToolButton::clicked, this,
                [this]()
                {
                    if (!tree_)
                    {
                        return;
                    }
                    /* Resolve the edit target the same way the context
                     * menu does: prefer the focused / current row, fall
                     * back to the first selected row when nothing is
                     * focused. The button mirrors the Remove button's
                     * enable state (any selected row), and
                     * startInlineEdit() silently skips stale (file-missing)
                     * rows, so an "always single row" launch is enough here. */
                    int row = -1;
                    const QModelIndex cur = tree_->currentIndex();
                    if (cur.isValid())
                    {
                        row = cur.row();
                    }
                    else if (QItemSelectionModel *sel = tree_->selectionModel())
                    {
                        for (const QModelIndex &si : sel->selectedIndexes())
                        {
                            if (si.isValid())
                            {
                                row = si.row();
                                break;
                            }
                        }
                    }
                    startInlineEdit(row);
                });
    }
    if (removeAllAction_)
    {
        connect(removeAllAction_, &QAction::triggered, this, &LuaDebuggerBreakpointsController::clearAll);
    }
    updateHeaderButtonState();
}

void LuaDebuggerBreakpointsController::configureColumns() const
{
    if (!tree_ || !tree_->header() || !model_)
    {
        return;
    }
    QHeaderView *breakpointHeader = tree_->header();
    breakpointHeader->setStretchLastSection(true);
    breakpointHeader->setSectionsMovable(false);
    /* Active and Hits auto-fit the widest visible cell (header text
     * or any row's content, including the extras icon next to the
     * checkbox). Row count is bounded by the breakpoints array, so
     * the per-resize scan stays cheap; the auto-fit also tracks
     * Hits content as it grows from empty to e.g. "\xe2\x89\xa5""100\xc2\xb7""3"
     * without us having to pre-measure a worst-case string. */
    breakpointHeader->setSectionResizeMode(BreakpointColumn::Active, QHeaderView::ResizeToContents);
    breakpointHeader->setSectionResizeMode(BreakpointColumn::Hits, QHeaderView::ResizeToContents);
    breakpointHeader->setSectionResizeMode(BreakpointColumn::Line, QHeaderView::Interactive);
    breakpointHeader->setSectionResizeMode(BreakpointColumn::Location, QHeaderView::Interactive);
    model_->setHeaderData(BreakpointColumn::Location, Qt::Horizontal, QObject::tr("Location"));
    /* Hits column header tooltip — spells out the cell grammar so users
     * don't have to memorise the glyphs. The mode words match the
     * inline-editor combo labels so the column reads as a compact
     * mirror of what the user picked in the dropdown. */
    model_->setHeaderData(BreakpointColumn::Hits, Qt::Horizontal,
                          QObject::tr("<p><b>Hit-count summary</b></p>"
                                    "<p><code>\xe2\x89\xa5N</code> &mdash; <i>from</i> mode: pause from hit <i>N</i> "
                                    "onwards.<br/>"
                                    "<code>\xc3\x97N</code> &mdash; <i>every</i> mode: pause on hits <i>N</i>, "
                                    "<i>2N</i>, <i>3N</i>, &hellip;<br/>"
                                    "<code>@N</code> &mdash; <i>once</i> mode: pause once on the <i>N</i>th hit, "
                                    "then deactivate.</p>"
                                    "<p>The cell starts with the running hit counter; if a gate is set "
                                    "it follows in parentheses, e.g. <code>3 (\xe2\x89\xa5"
                                    "10)</code>. With no hit gate the cell is just the counter.</p>"
                                    "<p>Edit the <i>Location</i> cell to set or change the gate (see "
                                    "the breakpoint-extras section).</p>"),
                          Qt::ToolTipRole);
    tree_->setColumnHidden(BreakpointColumn::Line, true);
    /* No explicit setColumnWidth for Active or Hits — the
     * ResizeToContents mode above derives the width from header
     * text + the widest cell on every model change. */
}

void LuaDebuggerBreakpointsController::startInlineEdit(int row)
{
    if (!model_ || !tree_)
    {
        return;
    }
    if (row < 0 || row >= model_->rowCount())
    {
        return;
    }
    const QModelIndex editTarget = model_->index(row, BreakpointColumn::Location);
    if (!editTarget.isValid() || !(editTarget.flags() & Qt::ItemIsEditable))
    {
        return;
    }
    tree_->setCurrentIndex(editTarget);
    tree_->scrollTo(editTarget);
    tree_->edit(editTarget);
}

void LuaDebuggerBreakpointsController::onItemDoubleClicked(const QModelIndex &index)
{
    if (!index.isValid() || !model_)
    {
        return;
    }
    QStandardItem *activeItem = model_->item(index.row(), BreakpointColumn::Active);
    if (!activeItem)
    {
        return;
    }
    const QString file = activeItem->data(BreakpointFileRole).toString();
    const int64_t lineNumber = activeItem->data(BreakpointLineRole).toLongLong();
    if (file.isEmpty() || lineNumber <= 0)
    {
        return;
    }
    LuaDebuggerCodeView *view = host_->codeTabsController().loadFile(file);
    if (view)
    {
        view->moveCaretToLineStart(static_cast<qint32>(lineNumber));
    }
}

void LuaDebuggerBreakpointsController::showContextMenu(const QPoint &pos)
{
    if (!tree_ || !model_)
    {
        return;
    }

    const QModelIndex ix = tree_->indexAt(pos);
    if (ix.isValid() && tree_->selectionModel() && !tree_->selectionModel()->isRowSelected(ix.row(), ix.parent()))
    {
        tree_->setCurrentIndex(ix);
    }

    QMenu menu(host_);
    QAction *editAct = nullptr;
    QAction *openAct = nullptr;
    QAction *resetHitsAct = nullptr;
    QAction *removeAct = nullptr;

    auto rowHasResettableHits = [this](int row) -> bool
    {
        QStandardItem *activeItem = model_->item(row, BreakpointColumn::Active);
        if (!activeItem)
            return false;
        const qlonglong target = activeItem->data(BreakpointHitTargetRole).toLongLong();
        const qlonglong count = activeItem->data(BreakpointHitCountRole).toLongLong();
        return target > 0 || count > 0;
    };

    bool anyResettable = false;
    QSet<int> selRowsSet;
    if (tree_->selectionModel())
    {
        for (const QModelIndex &si : tree_->selectionModel()->selectedIndexes())
        {
            if (!si.isValid())
                continue;
            if (selRowsSet.contains(si.row()))
                continue;
            selRowsSet.insert(si.row());
            if (rowHasResettableHits(si.row()))
            {
                anyResettable = true;
            }
        }
    }
    if (selRowsSet.isEmpty() && ix.isValid())
    {
        anyResettable = rowHasResettableHits(ix.row());
    }

    bool anyResettableInModel = false;
    {
        const int rc = model_->rowCount();
        for (int r = 0; r < rc; ++r)
        {
            if (rowHasResettableHits(r))
            {
                anyResettableInModel = true;
                break;
            }
        }
    }

    if (ix.isValid())
    {
        editAct = menu.addAction(QObject::tr("Edit..."));
        editAct->setEnabled(ix.flags() & Qt::ItemIsEditable);
        openAct = menu.addAction(QObject::tr("Open Source"));
        menu.addSeparator();
        resetHitsAct = menu.addAction(QObject::tr("Reset Hit Count"));
        resetHitsAct->setEnabled(anyResettable);
        menu.addSeparator();
        removeAct = menu.addAction(QObject::tr("Remove"));
        removeAct->setShortcut(QKeySequence::Delete);
    }
    QAction *resetAllHitsAct = nullptr;
    QAction *removeAllAct = nullptr;
    if (model_->rowCount() > 0)
    {
        resetAllHitsAct = menu.addAction(QObject::tr("Reset All Hit Counts"));
        resetAllHitsAct->setEnabled(anyResettableInModel);
        removeAllAct = menu.addAction(QObject::tr("Remove All Breakpoints"));
        removeAllAct->setShortcut(kLuaDbgCtxRemoveAllBreakpoints);
    }
    if (menu.isEmpty())
    {
        return;
    }

    QAction *chosen = menu.exec(tree_->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }
    if (chosen == editAct)
    {
        startInlineEdit(ix.row());
        return;
    }
    if (chosen == openAct)
    {
        onItemDoubleClicked(ix);
        return;
    }
    if (chosen == resetHitsAct)
    {
        QSet<int> rows = std::move(selRowsSet);
        if (rows.isEmpty() && ix.isValid())
        {
            rows.insert(ix.row());
        }
        for (int row : rows)
        {
            QStandardItem *activeItem = model_->item(row, BreakpointColumn::Active);
            if (!activeItem)
                continue;
            const QString file = activeItem->data(BreakpointFileRole).toString();
            const int64_t line = activeItem->data(BreakpointLineRole).toLongLong();
            if (file.isEmpty() || line <= 0)
                continue;
            wslua_debugger_reset_breakpoint_hit_count(file.toUtf8().constData(), line);
        }
        refreshFromEngine();
        return;
    }
    if (chosen == removeAct)
    {
        removeSelected();
        return;
    }
    if (chosen == resetAllHitsAct)
    {
        wslua_debugger_reset_all_breakpoint_hit_counts();
        refreshFromEngine();
        return;
    }
    if (chosen == removeAllAct)
    {
        clearAll();
        return;
    }
}

void LuaDebuggerBreakpointsController::clearAll()
{
    const unsigned count = wslua_debugger_get_breakpoint_count();
    if (count == 0)
    {
        return;
    }

    QMessageBox::StandardButton reply =
        QMessageBox::question(host_, QObject::tr("Clear All Breakpoints"),
                              QObject::tr("Are you sure you want to remove %Ln breakpoint(s)?", "", count),
                              QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes)
    {
        return;
    }

    wslua_debugger_clear_breakpoints();
    refreshFromEngine();
    refreshAllOpenTabMarkers();
}

void LuaDebuggerBreakpointsController::refreshFromEngine()
{
    if (!model_)
    {
        return;
    }
    /* Suppress dispatch through onItemChanged while we rebuild the model;
     * the inline-edit slot is fine for user-triggered checkbox /
     * delegate-driven changes but a wholesale rebuild from core would
     * otherwise loop. Restored unconditionally on the function tail so
     * an early return does not leave the flag set. */
    const bool prevSuppress = suppressItemChanged_;
    suppressItemChanged_ = true;
    model_->removeRows(0, model_->rowCount());
    model_->setHeaderData(BreakpointColumn::Location, Qt::Horizontal, QObject::tr("Location"));
    unsigned count = wslua_debugger_get_breakpoint_count();
    const bool collectInitialFiles = !tabsPrimed_;
    QVector<QString> initialBreakpointFiles;
    QSet<QString> seenInitialFiles;
    for (unsigned i = 0; i < count; i++)
    {
        const char *file_path = nullptr;
        int64_t line = 0;
        bool active = false;
        const char *condition_c = nullptr;
        int64_t hit_count_target = 0;
        int64_t hit_count = 0;
        bool condition_error = false;
        const char *log_message_c = nullptr;
        wslua_hit_count_mode_t hit_count_mode = WSLUA_HIT_COUNT_MODE_FROM;
        bool log_also_pause = false;
        if (!wslua_debugger_get_breakpoint_extended(i, &file_path, &line, &active, &condition_c, &hit_count_target,
                                                    &hit_count, &condition_error, &log_message_c, &hit_count_mode,
                                                    &log_also_pause))
        {
            continue;
        }

        QString normalizedPath = host_->normalizedFilePath(QString::fromUtf8(file_path));
        const QString condition = condition_c ? QString::fromUtf8(condition_c) : QString();
        const QString logMessage = log_message_c ? QString::fromUtf8(log_message_c) : QString();
        const bool hasCondition = !condition.isEmpty();
        const bool hasLog = !logMessage.isEmpty();
        const bool hasHitTarget = hit_count_target > 0;

        QFileInfo fileInfo(normalizedPath);
        bool fileExists = fileInfo.exists() && fileInfo.isFile();

        QStandardItem *const activeItem = new QStandardItem();
        QStandardItem *const hitsItem = new QStandardItem();
        QStandardItem *const lineItem = new QStandardItem();
        QStandardItem *const locationItem = new QStandardItem();
        /* QStandardItem ships with Qt::ItemIsEditable on by default; the
         * Active checkbox cell, the new Hits summary cell, and the
         * (hidden) Line cell must not host an editor — the inline
         * condition / hit-count / log-message editor lives on the
         * Location column only. Without this, double-clicking the
         * checkbox column opens a stray QLineEdit over the row. */
        activeItem->setFlags(activeItem->flags() & ~Qt::ItemIsEditable);
        hitsItem->setFlags(hitsItem->flags() & ~Qt::ItemIsEditable & ~Qt::ItemIsUserCheckable);
        lineItem->setFlags(lineItem->flags() & ~Qt::ItemIsEditable);
        /* Hits summary cell text — formatter decides empty vs ≥N / ×N /
         * @N, with optional ·count suffix. Pure text; the Active cell
         * still carries the extras icon so we don't duplicate it here. */
        hitsItem->setText(formatBreakpointHitsSummary(hit_count_target, hit_count, hit_count_mode));
        activeItem->setCheckable(true);
        activeItem->setCheckState(active ? Qt::Checked : Qt::Unchecked);
        activeItem->setData(normalizedPath, BreakpointFileRole);
        activeItem->setData(static_cast<qlonglong>(line), BreakpointLineRole);
        activeItem->setData(condition, BreakpointConditionRole);
        activeItem->setData(static_cast<qlonglong>(hit_count_target), BreakpointHitTargetRole);
        activeItem->setData(static_cast<qlonglong>(hit_count), BreakpointHitCountRole);
        activeItem->setData(condition_error, BreakpointConditionErrRole);
        activeItem->setData(logMessage, BreakpointLogMessageRole);
        activeItem->setData(static_cast<int>(hit_count_mode), BreakpointHitModeRole);
        activeItem->setData(log_also_pause, BreakpointLogAlsoPauseRole);
        lineItem->setText(QString::number(line));
        const QString fileDisplayName = fileInfo.fileName();
        QString locationText =
            QStringLiteral("%1:%2").arg(fileDisplayName.isEmpty() ? normalizedPath : fileDisplayName).arg(line);
        locationItem->setText(locationText);
        locationItem->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        /* The location cell is the inline-edit target for condition /
         * hit count / log message. Make it editable on existing files;
         * stale rows below clear the flag. */
        locationItem->setFlags((locationItem->flags() | Qt::ItemIsEditable) & ~Qt::ItemIsUserCheckable);

        /* Compose a multi-line tooltip applied to all three cells, so
         * hovering anywhere on the row reveals the full condition / hit
         * count / log details that no longer have a dedicated column. */
        QStringList tooltipLines;
        tooltipLines.append(QObject::tr("Location: %1:%2").arg(normalizedPath).arg(line));
        if (hasCondition)
        {
            tooltipLines.append(QObject::tr("Condition: %1").arg(condition));
        }
        if (hasHitTarget)
        {
            QString modeDesc;
            switch (hit_count_mode)
            {
            case WSLUA_HIT_COUNT_MODE_EVERY:
                modeDesc = QObject::tr("pauses on hits %1, 2\xc3\x97%1, "
                                     "3\xc3\x97%1, \xe2\x80\xa6")
                               .arg(hit_count_target);
                break;
            case WSLUA_HIT_COUNT_MODE_ONCE:
                modeDesc = QObject::tr("pauses once on hit %1, then deactivates the "
                                     "breakpoint")
                               .arg(hit_count_target);
                break;
            case WSLUA_HIT_COUNT_MODE_FROM:
            default:
                modeDesc = QObject::tr("pauses on every hit from %1 onwards").arg(hit_count_target);
                break;
            }
            tooltipLines.append(
                QObject::tr("Hit Count: %1 / %2 (%3)").arg(hit_count).arg(hit_count_target).arg(modeDesc));
        }
        else if (hit_count > 0)
        {
            tooltipLines.append(QObject::tr("Hits: %1").arg(hit_count));
        }
        if (hasLog)
        {
            tooltipLines.append(QObject::tr("Log: %1").arg(logMessage));
            tooltipLines.append(log_also_pause ? QObject::tr("(logpoint — also pauses)")
                                               : QObject::tr("(logpoint — does not pause)"));
        }
        if (condition_error)
        {
            tooltipLines.append(QObject::tr("Condition error on last evaluation — treated as "
                                          "false (silent). Edit or reset the breakpoint to "
                                          "clear."));
            /* Surface the actual Lua error string so users don't have
             * to guess which identifier was nil. The C-side getter
             * returns a freshly allocated copy under the breakpoints
             * mutex, so reading it here is safe even when the line
             * hook is racing to overwrite the field. */
            char *err_msg = wslua_debugger_get_breakpoint_condition_error_message(i);
            if (err_msg && err_msg[0])
            {
                tooltipLines.append(QObject::tr("Condition error: %1").arg(QString::fromUtf8(err_msg)));
            }
            g_free(err_msg);
        }

        /* Cell icons render with @c QIcon::Selected mode when the row
         * is selected; theme icons (QIcon::fromTheme) usually don't
         * ship that mode, so a dark glyph against the dark blue
         * selection background reads as an invisible blob in dark
         * mode. luaDbgMakeSelectionAwareIcon synthesises the Selected
         * pixmap from the tree's palette (HighlightedText) so every
         * row indicator stays legible while the row is highlighted. */
        const QPalette bpPalette = tree_->palette();

        if (!fileExists)
        {
            /* Mark stale breakpoints with warning icon and gray text.
             * The "file not found" indicator stays on the Location cell
             * because it describes the *file*, not the breakpoint's
             * extras (condition / hit count / log message). */
            locationItem->setIcon(luaDbgMakeSelectionAwareIcon(QIcon::fromTheme("dialog-warning"), bpPalette));
            tooltipLines.prepend(QObject::tr("File not found: %1").arg(normalizedPath));
            activeItem->setForeground(QBrush(Qt::gray));
            hitsItem->setForeground(QBrush(Qt::gray));
            lineItem->setForeground(QBrush(Qt::gray));
            locationItem->setForeground(QBrush(Qt::gray));
            /* Disable the checkbox + inline editor for stale breakpoints */
            activeItem->setFlags(activeItem->flags() & ~Qt::ItemIsUserCheckable);
            activeItem->setCheckState(Qt::Unchecked);
            locationItem->setFlags(locationItem->flags() & ~Qt::ItemIsEditable);
        }
        else
        {
            /* Extras indicator on the Active column, drawn after the
             * checkbox (Qt's standard cell layout: check indicator,
             * decoration, then text). Mirrors the gutter dot's white
             * core so users get a consistent at-a-glance cue both in
             * the editor margin and in the Breakpoints list.
             *
             * Indicator priority: condition error > logpoint >
             * conditional / hit count > plain. */
            if (condition_error)
            {
                activeItem->setIcon(luaDbgMakeSelectionAwareIcon(QIcon::fromTheme("dialog-warning"), bpPalette));
            }
            else if (hasLog || hasCondition || hasHitTarget)
            {
                /* Painted glyph from kLuaDbgRowLog or kLuaDbgRowExtras,
                 * drawn in QPalette::Text and routed through
                 * luaDbgMakeSelectionAwareIcon so the glyph stays legible
                 * on the highlighted-row background. */
                const QSize iconSz = tree_->iconSize();
                const int side = (iconSz.isValid() && iconSz.height() > 0) ? iconSz.height() : 16;
                const QColor pen = bpPalette.color(QPalette::Text);
                const QString &glyph = hasLog ? kLuaDbgRowLog : kLuaDbgRowExtras;
                QIcon icon = luaDbgPaintedGlyphIcon(glyph, side, host_->devicePixelRatioF(), host_->font(), pen,
                                                    /*margin=*/2);
                activeItem->setIcon(luaDbgMakeSelectionAwareIcon(icon, bpPalette));
            }
        }

        const QString tooltipText = tooltipLines.join(QChar('\n'));
        activeItem->setToolTip(tooltipText);
        hitsItem->setToolTip(tooltipText);
        lineItem->setToolTip(tooltipText);
        locationItem->setToolTip(tooltipText);

        model_->appendRow({activeItem, hitsItem, lineItem, locationItem});

        /* Highlight the breakpoint row that matches the current pause
         * location with the same bold-accent (and one-shot background
         * flash on pause entry) treatment the Watch / Variables trees
         * use, so the row that "fired" stands out at a glance. The
         * matching gate is the file + line pair captured in
         * handlePause(); both are cleared in clearPausedStateUi(), so
         * this branch is dormant whenever the debugger is not paused.
         *
         * applyChangedVisuals must run after appendRow so the cells
         * have a concrete model index — scheduleFlashClear() captures
         * a QPersistentModelIndex on each cell to drive its timed
         * clear, and that index is only valid once the row is in the
         * model. */
        if (host_->isDebuggerPaused() && fileExists && !host_->pausedFile().isEmpty() &&
            normalizedPath == host_->pausedFile() && line == host_->pausedLine())
        {
            host_->applyChangedVisuals(activeItem, /*changed=*/true);
        }

        if (fileExists)
        {
            host_->filesController().ensureEntry(normalizedPath);
        }

        if (collectInitialFiles && fileExists && !seenInitialFiles.contains(normalizedPath))
        {
            initialBreakpointFiles.append(normalizedPath);
            seenInitialFiles.insert(normalizedPath);
        }
    }

    host_->ensureDebuggerEnabledForActiveBreakpoints();

    if (collectInitialFiles)
    {
        tabsPrimed_ = true;
        host_->codeTabsController().openInitialBreakpointFiles(initialBreakpointFiles);
    }

    updateHeaderButtonState();
    if (breakOnErrorButton_)
    {
        breakOnErrorButton_->setChecked(wslua_debugger_get_error_break_enabled());
    }
    suppressItemChanged_ = prevSuppress;
}

void LuaDebuggerBreakpointsController::onItemChanged(QStandardItem *item)
{
    if (!item)
    {
        return;
    }
    /* Re-entrancy guard: refreshFromEngine() rebuilds the model and writes
     * many roles via setData; without this gate every set during the
     * rebuild would loop back through wslua_debugger_set_breakpoint_*. */
    if (suppressItemChanged_)
    {
        return;
    }
    if (item->column() != BreakpointColumn::Active)
    {
        return;
    }

    const QString file = item->data(BreakpointFileRole).toString();
    const int64_t lineNumber = item->data(BreakpointLineRole).toLongLong();
    const bool active = item->checkState() == Qt::Checked;
    wslua_debugger_set_breakpoint_active(file.toUtf8().constData(), lineNumber, active);
    /* Reconcile debugger enabled state against the current trigger set
     * (active breakpoints + Break on Error). Live-capture suppression is
     * handled inside ensureDebuggerEnabledForActiveBreakpoints(). */
    host_->ensureDebuggerEnabledForActiveBreakpoints();

    refreshOpenTabMarkers({file});

    /* The Breakpoints table is the only mutation path that does not flow
     * through refreshFromEngine(); refresh the section-header dot here so
     * its color mirrors the new aggregate active state. */
    updateHeaderButtonState();
}

void LuaDebuggerBreakpointsController::onModelDataChanged(const QModelIndex &topLeft, const QModelIndex &bottomRight,
                                                          const QVector<int> &roles)
{
    if (suppressItemChanged_ || !model_)
    {
        return;
    }
    /* The delegate writes BreakpointConditionRole / BreakpointHitTargetRole
     * / BreakpointLogMessageRole on column 0 of the touched row. Translate
     * those changes into the matching wslua_debugger_set_breakpoint_*
     * calls and refresh the row visuals. We dispatch on `roles` so this
     * slot ignores the ordinary display / decoration churn that
     * refreshFromEngine itself emits. */
    const bool wantsCondition = roles.isEmpty() || roles.contains(BreakpointConditionRole);
    const bool wantsTarget = roles.isEmpty() || roles.contains(BreakpointHitTargetRole);
    const bool wantsLog = roles.isEmpty() || roles.contains(BreakpointLogMessageRole);
    const bool wantsHitMode = roles.isEmpty() || roles.contains(BreakpointHitModeRole);
    const bool wantsLogAlsoPause = roles.isEmpty() || roles.contains(BreakpointLogAlsoPauseRole);
    if (!wantsCondition && !wantsTarget && !wantsLog && !wantsHitMode && !wantsLogAlsoPause)
    {
        return;
    }

    bool touched = false;
    for (int row = topLeft.row(); row <= bottomRight.row(); ++row)
    {
        QStandardItem *activeItem = model_->item(row, BreakpointColumn::Active);
        if (!activeItem)
            continue;
        const QString file = activeItem->data(BreakpointFileRole).toString();
        const int64_t line = activeItem->data(BreakpointLineRole).toLongLong();
        if (file.isEmpty() || line <= 0)
            continue;
        const QByteArray fileUtf8 = file.toUtf8();

        if (wantsCondition)
        {
            const QString cond = activeItem->data(BreakpointConditionRole).toString();
            const QByteArray condUtf8 = cond.toUtf8();
            wslua_debugger_set_breakpoint_condition(fileUtf8.constData(), line,
                                                    cond.isEmpty() ? NULL : condUtf8.constData());
            /* Parse-time validation. The runtime evaluator treats
             * any error in the condition as silent-false, so without
             * this check a typo (e.g. unbalanced parens, or a
             * missing @c return inside a statement) would only
             * surface as a row icon after the line is hit. Running
             * the parse-only checker at commit time stamps the row
             * with the condition_error flag/message immediately; on
             * a successful parse the flag we just cleared via
             * set_breakpoint_condition stays cleared. */
            if (!cond.isEmpty())
            {
                char *parse_err = NULL;
                const bool parses_ok = wslua_debugger_check_condition_syntax(condUtf8.constData(), &parse_err);
                if (!parses_ok)
                {
                    wslua_debugger_set_breakpoint_condition_error(fileUtf8.constData(), line,
                                                                  parse_err ? parse_err : "Parse error");
                }
                g_free(parse_err);
            }
            touched = true;
        }
        if (wantsTarget)
        {
            const qlonglong target = activeItem->data(BreakpointHitTargetRole).toLongLong();
            wslua_debugger_set_breakpoint_hit_count_target(fileUtf8.constData(), line, static_cast<int64_t>(target));
            touched = true;
        }
        if (wantsHitMode)
        {
            /* The mode role is meaningful only when target > 0, but
             * we forward it regardless so toggling the integer back
             * on later remembers the last mode the user picked. The
             * core ignores the mode when target == 0. */
            const int hitMode = activeItem->data(BreakpointHitModeRole).toInt();
            wslua_debugger_set_breakpoint_hit_count_mode(fileUtf8.constData(), line,
                                                         static_cast<wslua_hit_count_mode_t>(hitMode));
            touched = true;
        }
        if (wantsLog)
        {
            const QString msg = activeItem->data(BreakpointLogMessageRole).toString();
            wslua_debugger_set_breakpoint_log_message(fileUtf8.constData(), line,
                                                      msg.isEmpty() ? NULL : msg.toUtf8().constData());
            touched = true;
        }
        if (wantsLogAlsoPause)
        {
            const bool alsoPause = activeItem->data(BreakpointLogAlsoPauseRole).toBool();
            wslua_debugger_set_breakpoint_log_also_pause(fileUtf8.constData(), line, alsoPause);
            touched = true;
        }
    }

    if (touched)
    {
        /* Rebuild rows so the tooltip and Location-cell indicator reflect
         * the updated condition / hit target / log message. Deferred to
         * the next event-loop tick on purpose: we are still inside the
         * model's dataChanged emit, immediately followed by an
         * itemChanged emit on the same item; tearing down every row
         * synchronously here would dangle the QStandardItem pointer
         * delivered to onItemChanged and would also leave the inline
         * editor pointing at a destroyed model index, which can
         * silently swallow the just-committed edit (the source of the
         * "condition / hit count are sticky" symptom). The
         * suppressItemChanged_ guard inside refreshFromEngine still
         * prevents this path from looping back into either slot. */
        QPointer<LuaDebuggerBreakpointsController> self(this);
        QTimer::singleShot(0, this,
                           [self = std::move(self)]()
                           {
                               if (self)
                               {
                                   self->refreshFromEngine();
                               }
                           });
    }
}

void LuaDebuggerBreakpointsController::showGutterMenu(const QString &filename, qint32 line, const QPoint &globalPos)
{
    /* Re-check the breakpoint state at popup time rather than trusting
     * what the gutter saw on the click. The model is the source of
     * truth and the C-side state may have changed between the click
     * and the queued slot dispatch (e.g. a hit-count target just got
     * met from another script line, or another reload-driven refresh
     * landed in the queue first). If the breakpoint has gone away,
     * silently skip — there's nothing meaningful to offer. */
    const QByteArray filePathUtf8 = filename.toUtf8();
    const int32_t state = wslua_debugger_get_breakpoint_state(filePathUtf8.constData(), line);
    if (state == -1)
    {
        return;
    }
    const bool currentlyActive = (state == 1);

    QMenu menu(host_);
    QAction *editAct = menu.addAction(QObject::tr("&Edit..."));
    QAction *toggleAct = menu.addAction(currentlyActive ? QObject::tr("&Disable") : QObject::tr("&Enable"));
    menu.addSeparator();
    QAction *removeAct = menu.addAction(QObject::tr("&Remove"));

    /* exec() returns the chosen action, or nullptr if the user
     * dismissed the menu (Escape, click outside, focus loss). The
     * dismiss path is a no-op by design — the user-typed condition /
     * hit-count target / log message stays exactly as it was. */
    QAction *chosen = menu.exec(globalPos);
    if (!chosen)
    {
        return;
    }

    if (chosen == editAct)
    {
        /* Find the row that matches this (file, line) pair so the
         * Location-cell delegate can open in place. Compare against
         * the *normalized* path stored under BreakpointFileRole — the
         * gutter may have handed us a non-canonical filename. */
        if (!model_)
        {
            return;
        }
        const QString normalized = host_->normalizedFilePath(filename);
        int targetRow = -1;
        for (int row = 0; row < model_->rowCount(); ++row)
        {
            QStandardItem *activeItem = model_->item(row, BreakpointColumn::Active);
            if (!activeItem)
                continue;
            const int64_t rowLine = activeItem->data(BreakpointLineRole).toLongLong();
            if (rowLine != line)
                continue;
            const QString rowFile = activeItem->data(BreakpointFileRole).toString();
            if (rowFile == normalized)
            {
                targetRow = row;
                break;
            }
        }
        if (targetRow >= 0)
        {
            startInlineEdit(targetRow);
        }
        return;
    }

    if (chosen == toggleAct)
    {
        setActiveFromUser(filename, line, !currentlyActive);
    }
    else if (chosen == removeAct)
    {
        removeAtLine(filename, line);
    }
}

bool LuaDebuggerBreakpointsController::removeRows(const QList<int> &rows)
{
    if (!model_ || rows.isEmpty())
    {
        return false;
    }

    /* Collect (file, line) pairs for the requested rows before touching the
     * model: rebuilding the model in refreshFromEngine() would invalidate
     * any QStandardItem pointers we held. De-duplicate row indices so callers
     * can pass selectionModel()->selectedIndexes() directly. */
    QVector<QPair<QString, int64_t>> toRemove;
    QSet<int> seenRows;
    for (int row : rows)
    {
        if (row < 0 || seenRows.contains(row))
        {
            continue;
        }
        seenRows.insert(row);
        QStandardItem *const activeItem = model_->item(row, BreakpointColumn::Active);
        if (!activeItem)
        {
            continue;
        }
        toRemove.append(
            {activeItem->data(BreakpointFileRole).toString(), activeItem->data(BreakpointLineRole).toLongLong()});
    }
    if (toRemove.isEmpty())
    {
        return false;
    }

    QSet<QString> touchedFiles;
    for (const auto &bp : toRemove)
    {
        wslua_debugger_remove_breakpoint(bp.first.toUtf8().constData(), bp.second);
        touchedFiles.insert(bp.first);
    }
    refreshFromEngine();
    refreshOpenTabMarkers(touchedFiles);
    return true;
}

bool LuaDebuggerBreakpointsController::removeSelected()
{
    if (!tree_)
    {
        return false;
    }
    QItemSelectionModel *const sm = tree_->selectionModel();
    if (!sm)
    {
        return false;
    }
    QList<int> rows;
    for (const QModelIndex &ix : sm->selectedIndexes())
    {
        if (ix.isValid())
        {
            rows.append(ix.row());
        }
    }
    return removeRows(rows);
}

void LuaDebuggerBreakpointsController::toggleAllActive()
{
    const unsigned n = wslua_debugger_get_breakpoint_count();
    if (n == 0U)
    {
        return;
    }
    /* Activate all only when every BP is off; if any is on (all on or mix),
     * this control shows "deactivate" and turns all off. */
    bool allInactive = true;
    for (unsigned i = 0; i < n; ++i)
    {
        const char *file_path;
        int64_t line;
        bool active;
        if (wslua_debugger_get_breakpoint(i, &file_path, &line, &active) && active)
        {
            allInactive = false;
            break;
        }
    }
    const bool makeActive = allInactive;
    for (unsigned i = 0; i < n; ++i)
    {
        const char *file_path;
        int64_t line;
        bool active;
        if (wslua_debugger_get_breakpoint(i, &file_path, &line, &active))
        {
            wslua_debugger_set_breakpoint_active(file_path, line, makeActive);
        }
    }
    refreshFromEngine();
    refreshAllOpenTabMarkers();
}

void LuaDebuggerBreakpointsController::updateHeaderButtonState()
{
    if (toggleAllButton_)
    {
        const int side = std::max(toggleAllButton_->height(), toggleAllButton_->width());
        const qreal dpr = toggleAllButton_->devicePixelRatioF();
        LuaDebuggerCodeView *const cv = host_->codeTabsController().currentCodeView();
        const QFont *const editorFont = (cv && !cv->getFilename().isEmpty()) ? &cv->font() : nullptr;
        const unsigned n = wslua_debugger_get_breakpoint_count();
        bool allInactive = n > 0U;
        for (unsigned i = 0; allInactive && i < n; ++i)
        {
            const char *file_path;
            int64_t line;
            bool active;
            if (wslua_debugger_get_breakpoint(i, &file_path, &line, &active))
            {
                if (active)
                {
                    allInactive = false;
                }
            }
        }
        LuaDbgBpHeaderIconMode mode;
        const QString tglLineKeys = kLuaDbgCtxToggleBreakpoint.toString(QKeySequence::NativeText);
        if (n == 0U)
        {
            mode = LuaDbgBpHeaderIconMode::NoBreakpoints;
            toggleAllButton_->setEnabled(false);
            toggleAllButton_->setToolTip(QObject::tr("No breakpoints\n%1: add or remove breakpoint on the current "
                                                   "line in the editor")
                                             .arg(tglLineKeys));
        }
        else if (allInactive)
        {
            /* All BPs off: dot is gray (mirrors gutter); click activates all. */
            mode = LuaDbgBpHeaderIconMode::ActivateAll;
            toggleAllButton_->setEnabled(true);
            toggleAllButton_->setToolTip(QObject::tr("All breakpoints are inactive — click to activate all\n"
                                                   "%1: add or remove on the current line in the editor")
                                             .arg(tglLineKeys));
        }
        else
        {
            /* Any BP on (all-on or mix): dot is red (mirrors gutter); click
             * deactivates all. */
            mode = LuaDbgBpHeaderIconMode::DeactivateAll;
            toggleAllButton_->setEnabled(true);
            toggleAllButton_->setToolTip(QObject::tr("Click to deactivate all breakpoints\n"
                                                   "%1: add or remove on the current line in the editor")
                                             .arg(tglLineKeys));
        }
        /* Cache the three icons keyed by (font, side, dpr); cursor moves
         * fire updateHeaderButtonState() frequently and only the mode
         * actually varies on hot paths. */
        const QString cacheKey = QStringLiteral("%1/%2/%3")
                                     .arg(editorFont != nullptr ? editorFont->key() : QGuiApplication::font().key())
                                     .arg(side)
                                     .arg(dpr);
        if (cacheKey != headerIconCacheKey_)
        {
            headerIconCacheKey_ = cacheKey;
            for (QIcon &cached : headerIconCache_)
            {
                cached = QIcon();
            }
        }
        const int modeIdx = static_cast<int>(mode);
        if (headerIconCache_[modeIdx].isNull())
        {
            headerIconCache_[modeIdx] = luaDbgBreakpointHeaderIconForMode(editorFont, mode, side, dpr);
        }
        toggleAllButton_->setIcon(headerIconCache_[modeIdx]);
    }
    /* The Edit and Remove header buttons share enable state: both act on
     * the breakpoint row(s) the user has selected, so a selection-only
     * gate keeps them visually and behaviourally in lockstep. Edit only
     * ever opens one editor (the current/first-selected row); the click
     * handler resolves a single row internally, and startInlineEdit() is
     * a no-op on stale (file-missing) rows, so we don't need to inspect
     * editability here. */
    QItemSelectionModel *const bpSelectionModel = tree_ ? tree_->selectionModel() : nullptr;
    const bool hasBreakpointSelection = bpSelectionModel && !bpSelectionModel->selectedRows().isEmpty();
    if (removeButton_)
    {
        removeButton_->setEnabled(hasBreakpointSelection);
    }
    if (editButton_)
    {
        editButton_->setEnabled(hasBreakpointSelection);
    }
    if (removeAllButton_)
    {
        const bool hasBreakpoints = model_ && model_->rowCount() > 0;
        removeAllButton_->setEnabled(hasBreakpoints);
        if (removeAllAction_)
        {
            removeAllAction_->setEnabled(hasBreakpoints);
        }
    }
}

void LuaDebuggerBreakpointsController::toggleAtLine(const QString &file, qint32 line)
{
    if (file.isEmpty() || line < 1)
    {
        return;
    }
    const QByteArray fileUtf8 = file.toUtf8();
    const int32_t state = wslua_debugger_get_breakpoint_state(fileUtf8.constData(), line);
    if (state == -1)
    {
        wslua_debugger_add_breakpoint(fileUtf8.constData(), line);
        host_->ensureDebuggerEnabledForActiveBreakpoints();
    }
    else
    {
        wslua_debugger_remove_breakpoint(fileUtf8.constData(), line);
        host_->refreshDebuggerStateUi();
    }
    refreshFromEngine();
    refreshAllOpenTabMarkers();
}

void LuaDebuggerBreakpointsController::toggleOnCodeViewLine(LuaDebuggerCodeView *codeView, qint32 line)
{
    if (!codeView)
    {
        return;
    }
    toggleAtLine(codeView->getFilename(), line);
}

void LuaDebuggerBreakpointsController::shiftToggleAtLine(const QString &file, qint32 line)
{
    if (file.isEmpty() || line < 1)
    {
        return;
    }
    const QByteArray fileUtf8 = file.toUtf8();
    const int32_t state = wslua_debugger_get_breakpoint_state(fileUtf8.constData(), line);
    if (state == -1)
    {
        /* Create the row pre-armed: keep the line-hook cost off the
         * caller's fast path until the user explicitly activates it. The
         * core's add+set-active sequence is the same one the JSON restore
         * path uses for a row that was saved inactive. */
        wslua_debugger_add_breakpoint(fileUtf8.constData(), line);
        wslua_debugger_set_breakpoint_active(fileUtf8.constData(), line, false);
    }
    else
    {
        /* Existing row: flip active. Do NOT call ensureDebuggerEnabledForActiveBreakpoints —
         * @c Shift+click is the "no surprise" companion to F9; it should
         * never silently turn the debugger back on. The matching gutter
         * Enable/Disable menu (see @ref setActiveFromUser) does enable
         * because that gesture is "I want this active right now". */
        wslua_debugger_set_breakpoint_active(fileUtf8.constData(), line, state == 0);
    }
    refreshFromEngine();
    refreshAllOpenTabMarkers();
}

void LuaDebuggerBreakpointsController::setActiveFromUser(const QString &file, qint32 line, bool active)
{
    if (file.isEmpty() || line < 1)
    {
        return;
    }
    const QByteArray fileUtf8 = file.toUtf8();
    wslua_debugger_set_breakpoint_active(fileUtf8.constData(), line, active);
    if (active)
    {
        host_->ensureDebuggerEnabledForActiveBreakpoints();
    }
    refreshFromEngine();
    refreshAllOpenTabMarkers();
}

void LuaDebuggerBreakpointsController::removeAtLine(const QString &file, qint32 line)
{
    if (file.isEmpty() || line < 1)
    {
        return;
    }
    const QByteArray fileUtf8 = file.toUtf8();
    wslua_debugger_remove_breakpoint(fileUtf8.constData(), line);
    host_->refreshDebuggerStateUi();
    refreshFromEngine();
    refreshAllOpenTabMarkers();
}

void LuaDebuggerBreakpointsController::moveAtLine(const QString &file, qint32 fromLine, qint32 toLine)
{
    if (file.isEmpty() || fromLine < 1 || toLine < 1 || fromLine == toLine)
    {
        return;
    }

    const QByteArray fileUtf8 = file.toUtf8();
    if (wslua_debugger_get_breakpoint_state(fileUtf8.constData(), fromLine) == -1)
    {
        return;
    }
    if (wslua_debugger_get_breakpoint_state(fileUtf8.constData(), toLine) != -1)
    {
        return;
    }

    bool isActive = true;
    int64_t hitTarget = 0;
    wslua_hit_count_mode_t hitMode = WSLUA_HIT_COUNT_MODE_FROM;
    bool logAlsoPause = false;
    QString condition;
    QString logMessage;
    bool found = false;

    const unsigned count = wslua_debugger_get_breakpoint_count();
    for (unsigned i = 0; i < count; ++i)
    {
        const char *file_path = nullptr;
        int64_t line = 0;
        bool active = false;
        const char *condition_c = nullptr;
        int64_t hit_target = 0;
        int64_t hit_count = 0;
        bool cond_err = false;
        const char *log_message = nullptr;
        wslua_hit_count_mode_t hit_mode = WSLUA_HIT_COUNT_MODE_FROM;
        bool log_also_pause = false;

        if (!wslua_debugger_get_breakpoint_extended(i, &file_path, &line, &active, &condition_c, &hit_target,
                                                    &hit_count, &cond_err, &log_message, &hit_mode,
                                                    &log_also_pause))
        {
            continue;
        }
        if (line != fromLine)
        {
            continue;
        }
        QString normalizedPath = host_->normalizedFilePath(QString::fromUtf8(file_path));
        if (normalizedPath != file)
        {
            continue;
        }

        isActive = active;
        hitTarget = hit_target;
        hitMode = hit_mode;
        logAlsoPause = log_also_pause;
        condition = QString::fromUtf8(condition_c ? condition_c : "");
        logMessage = QString::fromUtf8(log_message ? log_message : "");
        found = true;
        break;
    }

    if (!found)
    {
        return;
    }

    wslua_debugger_add_breakpoint(fileUtf8.constData(), toLine);
    wslua_debugger_set_breakpoint_active(fileUtf8.constData(), toLine, isActive);
    if (!condition.isEmpty())
    {
        const QByteArray conditionUtf8 = condition.toUtf8();
        wslua_debugger_set_breakpoint_condition(fileUtf8.constData(), toLine, conditionUtf8.constData());
    }
    if (hitTarget > 0)
    {
        wslua_debugger_set_breakpoint_hit_count_target(fileUtf8.constData(), toLine, hitTarget);
        wslua_debugger_set_breakpoint_hit_count_mode(fileUtf8.constData(), toLine, hitMode);
    }
    if (!logMessage.isEmpty())
    {
        const QByteArray logMessageUtf8 = logMessage.toUtf8();
        wslua_debugger_set_breakpoint_log_message(fileUtf8.constData(), toLine, logMessageUtf8.constData());
        wslua_debugger_set_breakpoint_log_also_pause(fileUtf8.constData(), toLine, logAlsoPause);
    }

    wslua_debugger_remove_breakpoint(fileUtf8.constData(), fromLine);
    refreshFromEngine();
    refreshAllOpenTabMarkers();
}

void LuaDebuggerBreakpointsController::refreshAllOpenTabMarkers() const
{
    if (!host_)
    {
        return;
    }
    QTabWidget *const tabs = host_->codeTabsController().tabs();
    if (!tabs)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(tabs->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *tabView = qobject_cast<LuaDebuggerCodeView *>(tabs->widget(static_cast<int>(tabIndex)));
        if (tabView)
        {
            tabView->updateBreakpointMarkers();
        }
    }
}

void LuaDebuggerBreakpointsController::refreshOpenTabMarkers(const QSet<QString> &files) const
{
    if (files.isEmpty() || !host_)
    {
        return;
    }
    QTabWidget *const tabs = host_->codeTabsController().tabs();
    if (!tabs)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(tabs->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *tabView = qobject_cast<LuaDebuggerCodeView *>(tabs->widget(static_cast<int>(tabIndex)));
        if (tabView && files.contains(tabView->getFilename()))
        {
            tabView->updateBreakpointMarkers();
        }
    }
}

void LuaDebuggerBreakpointsController::serializeTo(QVariantMap &settingsMap) const
{
    QVariantList list;
    const unsigned count = wslua_debugger_get_breakpoint_count();
    for (unsigned i = 0; i < count; i++)
    {
        const char *file = nullptr;
        int64_t line = 0;
        bool active = false;
        const char *condition = nullptr;
        int64_t hit_target = 0;
        int64_t hit_count = 0; /* runtime-only; not persisted */
        bool cond_err = false; /* runtime-only; not persisted */
        const char *log_message = nullptr;
        wslua_hit_count_mode_t hit_mode = WSLUA_HIT_COUNT_MODE_FROM;
        bool log_also_pause = false;
        if (!wslua_debugger_get_breakpoint_extended(i, &file, &line, &active, &condition, &hit_target, &hit_count,
                                                    &cond_err, &log_message, &hit_mode, &log_also_pause))
        {
            continue;
        }
        QJsonObject bp;
        bp[QStringLiteral("file")] = QString::fromUtf8(file);
        bp[QStringLiteral("line")] = static_cast<qint64>(line);
        bp[QStringLiteral("active")] = active;
        bp[QStringLiteral("condition")] = QString::fromUtf8(condition ? condition : "");
        bp[QStringLiteral("hitCountTarget")] = static_cast<qint64>(hit_target);
        /* @c hitCountMode is persisted as a string ("from" / "every" /
         * "once") so the JSON file is self-describing and matches the
         * UI dropdown verbatim. */
        const char *modeStr;
        switch (hit_mode)
        {
        case WSLUA_HIT_COUNT_MODE_EVERY:
            modeStr = "every";
            break;
        case WSLUA_HIT_COUNT_MODE_ONCE:
            modeStr = "once";
            break;
        case WSLUA_HIT_COUNT_MODE_FROM:
        default:
            modeStr = "from";
            break;
        }
        bp[QStringLiteral("hitCountMode")] = QString::fromLatin1(modeStr);
        bp[QStringLiteral("logMessage")] = QString::fromUtf8(log_message ? log_message : "");
        bp[QStringLiteral("logAlsoPause")] = log_also_pause;
        list.append(bp.toVariantMap());
    }
    settingsMap[LuaDebuggerSettingsKeys::Breakpoints] = list;
    settingsMap[LuaDebuggerSettingsKeys::BreakOnError] = wslua_debugger_get_error_break_enabled();
}

void LuaDebuggerBreakpointsController::restoreFrom(const QVariantMap &settingsMap)
{
    const bool breakOnError = settingsMap.value(LuaDebuggerSettingsKeys::BreakOnError, false).toBool();
    wslua_debugger_set_error_break_enabled(breakOnError);

    QJsonArray breakpointsArray = LuaDebuggerSettingsStore::jsonArrayAt(settingsMap, LuaDebuggerSettingsKeys::Breakpoints);
    for (const QJsonValue &val : breakpointsArray)
    {
        QJsonObject bp = val.toObject();
        const QString file = bp.value("file").toString();
        const int64_t line = bp.value("line").toVariant().toLongLong();
        if (file.isEmpty() || line <= 0)
        {
            continue;
        }
        const bool active = bp.value("active").toBool(true);
        const QString condition = bp.value("condition").toString();
        const int64_t hitCountTarget = bp.value("hitCountTarget").toVariant().toLongLong();
        const QString modeStr = bp.value("hitCountMode").toString().toLower();
        wslua_hit_count_mode_t hitCountMode = WSLUA_HIT_COUNT_MODE_FROM;
        if (modeStr == QStringLiteral("every"))
        {
            hitCountMode = WSLUA_HIT_COUNT_MODE_EVERY;
        }
        else if (modeStr == QStringLiteral("once"))
        {
            hitCountMode = WSLUA_HIT_COUNT_MODE_ONCE;
        }
        const QString logMessage = bp.value("logMessage").toString();
        const bool logAlsoPause = bp.value("logAlsoPause").toBool(false);

        const QByteArray fb = file.toUtf8();
        if (wslua_debugger_get_breakpoint_state(fb.constData(), line) < 0)
        {
            wslua_debugger_add_breakpoint(fb.constData(), line);
        }
        wslua_debugger_set_breakpoint_active(fb.constData(), line, active);
        const QByteArray cb = condition.toUtf8();
        wslua_debugger_set_breakpoint_condition(fb.constData(), line, condition.isEmpty() ? NULL : cb.constData());
        wslua_debugger_set_breakpoint_hit_count_target(fb.constData(), line, hitCountTarget);
        wslua_debugger_set_breakpoint_hit_count_mode(fb.constData(), line, hitCountMode);
        const QByteArray mb = logMessage.toUtf8();
        wslua_debugger_set_breakpoint_log_message(fb.constData(), line, logMessage.isEmpty() ? NULL : mb.constData());
        wslua_debugger_set_breakpoint_log_also_pause(fb.constData(), line, logAlsoPause);
    }
}

/* ===== dialog_breakpoints (LuaDebuggerDialog members) ===== */

CollapsibleSection *LuaDebuggerDialog::createBreakpointsSection(QWidget *parent)
{
    breakpointsSection = new CollapsibleSection(tr("Breakpoints"), parent);
    breakpointsSection->setToolTip(tr("<p><b>Expression</b><br/>"
                                      "Pause only when this Lua expression is truthy in the "
                                      "current frame. Runtime errors count as false and surface a "
                                      "warning icon on the row.</p>"
                                      "<p><b>Hit Count</b><br/>"
                                      "Gate the pause on a hit counter. "
                                      "The dropdown next to <i>N</i> picks the "
                                      "comparison mode: <code>from</code> pauses on every hit "
                                      "from <i>N</i> onwards (default); <code>every</code> "
                                      "pauses on hits <i>N</i>, 2&times;<i>N</i>, "
                                      "3&times;<i>N</i>, &hellip;; <code>once</code> pauses on "
                                      "the <i>N</i>-th hit and deactivates the breakpoint. The "
                                      "counter is preserved "
                                      "across edits; right-click the row to reset it.</p>"
                                      "<p><b>Log Message</b><br/>"
                                      "Write a line to the <i>Evaluate</i> output (and "
                                      "Wireshark's debug log) each time the breakpoint fires &mdash; "
                                      "after the <i>Hit Count</i> gate and any <i>Expression</i> "
                                      "allow it. By default execution continues; click the pause "
                                      "toggle on the editor row to also pause after emitting. "
                                      "Tags: <code>{expr}</code> (any Lua value); "
                                      "<code>{filename}</code>, <code>{basename}</code>, "
                                      "<code>{line}</code>, <code>{function}</code>, "
                                      "<code>{what}</code>; <code>{hits}</code>, "
                                      "<code>{depth}</code>, <code>{thread}</code>; "
                                      "<code>{timestamp}</code>, <code>{datetime}</code>, "
                                      "<code>{epoch}</code>, <code>{epoch_ms}</code>, "
                                      "<code>{elapsed}</code>, <code>{delta}</code>; "
                                      "<code>{{</code> / <code>}}</code> for literal braces.</p>"
                                      "<p>Edit the <i>Location</i> cell (double-click, F2, or "
                                      "right-click &rarr; Edit) to attach one of these. A white "
                                      "core inside the breakpoint dot &mdash; in this list and in "
                                      "the gutter &mdash; marks rows that carry extras.</p>"));
    breakpointsModel = new QStandardItemModel(this);
    breakpointsModel->setColumnCount(BreakpointColumn::Count);
    breakpointsModel->setHorizontalHeaderLabels({tr("Active"), tr("Hits"), tr("Line"), tr("Location")});
    breakpointsTree = new QTreeView();
    breakpointsTree->setModel(breakpointsModel);
    /* Inline edit on the Location column (delegate-driven mode picker for
     * Condition / Hit Count / Log Message). DoubleClicked is the default
     * trigger; the slot in onBreakpointItemDoubleClicked redirects double-
     * click on any row cell to the editable column so the editor opens
     * even when the user clicked the Active checkbox or the hidden Line
     * column. EditKeyPressed enables F2 to open the editor with keyboard. */
    breakpointsTree->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed |
                                     QAbstractItemView::SelectedClicked);
    breakpointsTree->setItemDelegateForColumn(BreakpointColumn::Location,
                                              new LuaDbgBreakpointConditionDelegate(this));
    breakpointsTree->setRootIsDecorated(false);
    breakpointsTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    breakpointsTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    breakpointsTree->setAllColumnsShowFocus(true);
    breakpointsTree->setContextMenuPolicy(Qt::CustomContextMenu);
    breakpointsSection->setContentWidget(breakpointsTree);
    {
        const int hdrH = breakpointsSection->titleButtonHeight();
        const QFont hdrTitleFont = breakpointsSection->titleButtonFont();
        auto *const bpHeaderBtnRow = new QWidget(breakpointsSection);
        auto *const bpHeaderBtnLayout = new QHBoxLayout(bpHeaderBtnRow);
        bpHeaderBtnLayout->setContentsMargins(0, 0, 0, 0);
        bpHeaderBtnLayout->setSpacing(4);
        bpHeaderBtnLayout->setAlignment(Qt::AlignVCenter);
        QToolButton *const bpErrBreakBtn = new QToolButton(bpHeaderBtnRow);
        breakpointHeaderBreakOnErrorButton_ = bpErrBreakBtn;

        /* Refresh the icon and tooltip to reflect the current checked state. */
        auto updateErrBreakChrome = [this, hdrH, hdrTitleFont]() {
            if (!breakpointHeaderBreakOnErrorButton_)
                return;
            bool checked = breakpointHeaderBreakOnErrorButton_->isChecked();
            QIcon icon = luaDbgErrorBreakHeaderIcon(checked, hdrH, devicePixelRatioF(),
                                                    hdrTitleFont, palette());
            breakpointHeaderBreakOnErrorButton_->setIcon(icon);
            breakpointHeaderBreakOnErrorButton_->setToolTip(
                checked ? tr("ON \u2014 Break on Lua errors")
                        : tr("OFF \u2014 Break on Lua errors"));
        };

        bpErrBreakBtn->setCheckable(true);
        bpErrBreakBtn->setChecked(wslua_debugger_get_error_break_enabled());

        styleLuaDebuggerHeaderIconOnlyButton(bpErrBreakBtn, hdrH);
        bpErrBreakBtn->setAutoRaise(true);
        bpErrBreakBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        updateErrBreakChrome();  /* Seed icon and tooltip from the initial state. */

        connect(bpErrBreakBtn, &QToolButton::toggled, this, updateErrBreakChrome);
        QToolButton *const bpTglBtn = new QToolButton(bpHeaderBtnRow);
        breakpointHeaderToggleButton_ = bpTglBtn;
        styleLuaDebuggerHeaderBreakpointToggleButton(bpTglBtn, hdrH);
        bpTglBtn->setIcon(luaDbgBreakpointHeaderIconForMode(nullptr, LuaDbgBpHeaderIconMode::NoBreakpoints, hdrH,
                                                            bpTglBtn->devicePixelRatioF()));
        bpTglBtn->setAutoRaise(true);
        bpTglBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        bpTglBtn->setEnabled(false);
        bpTglBtn->setToolTip(tr("No breakpoints"));
        QToolButton *const bpEditBtn = new QToolButton(bpHeaderBtnRow);
        breakpointHeaderEditButton_ = bpEditBtn;
        /* Painted via luaDbgPaintedGlyphButtonIcon so the disabled
         * pixmap is baked from the palette's disabled-text gray instead
         * of QStyle::generatedIconPixmap()'s synthesised filter, keeping
         * the disabled tone in step with the neighbouring +/- buttons. */
        {
            QIcon gear = luaDbgPaintedGlyphButtonIcon(kLuaDbgHeaderEdit, hdrH, devicePixelRatioF(),
                                                     hdrTitleFont, palette(), /*margin=*/2);
            bpEditBtn->setIcon(gear);
        }
        styleLuaDebuggerHeaderIconOnlyButton(bpEditBtn, hdrH);
        bpEditBtn->setAutoRaise(true);
        bpEditBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        bpEditBtn->setEnabled(false);
        bpEditBtn->setToolTip(tr("Edit Breakpoint"));
        QToolButton *const bpRemBtn = new QToolButton(bpHeaderBtnRow);
        breakpointHeaderRemoveButton_ = bpRemBtn;
        styleLuaDebuggerHeaderPlusMinusButton(bpRemBtn, hdrH, hdrTitleFont);
        bpRemBtn->setText(kLuaDbgHeaderMinus);
        bpRemBtn->setAutoRaise(true);
        bpRemBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        bpRemBtn->setEnabled(false);
        bpRemBtn->setToolTip(
            tr("Remove Breakpoint (%1)").arg(QKeySequence(QKeySequence::Delete).toString(QKeySequence::NativeText)));
        QToolButton *const bpRemAllBtn = new QToolButton(bpHeaderBtnRow);
        breakpointHeaderRemoveAllButton_ = bpRemAllBtn;
        {
            QIcon icon = luaDbgPaintedGlyphButtonIcon(kLuaDbgHeaderRemoveAll, hdrH, devicePixelRatioF(),
                                                     hdrTitleFont, palette(), /*margin=*/2);
            bpRemAllBtn->setIcon(icon);
        }
        styleLuaDebuggerHeaderIconOnlyButton(bpRemAllBtn, hdrH);
        bpRemAllBtn->setAutoRaise(true);
        bpRemAllBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        bpRemAllBtn->setEnabled(false);
        bpRemAllBtn->setToolTip(
            tr("Remove All Breakpoints (%1)").arg(kLuaDbgCtxRemoveAllBreakpoints.toString(QKeySequence::NativeText)));
        bpHeaderBtnLayout->addWidget(bpErrBreakBtn);
        bpHeaderBtnLayout->addWidget(bpTglBtn);
        bpHeaderBtnLayout->addWidget(bpRemBtn);
        bpHeaderBtnLayout->addWidget(bpEditBtn);
        bpHeaderBtnLayout->addWidget(bpRemAllBtn);
        breakpointsSection->setHeaderTrailingWidget(bpHeaderBtnRow);
    }
    breakpointsSection->setExpanded(true);
    return breakpointsSection;
}

void LuaDebuggerDialog::wireBreakpointsPanel()
{
    breakpointsController_.attach(breakpointsTree, breakpointsModel);

    /* "Remove All Breakpoints" needs a real, dialog-wide shortcut so
     * Ctrl+Shift+F9 fires regardless of focus. Setting the keys only
     * on the right-click menu action (built on demand) made the
     * shortcut a label without a binding. */
    actionRemoveAllBreakpoints_ = new QAction(tr("Remove All Breakpoints"), this);
    actionRemoveAllBreakpoints_->setShortcut(kLuaDbgCtxRemoveAllBreakpoints);
    actionRemoveAllBreakpoints_->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    actionRemoveAllBreakpoints_->setEnabled(false);
    addAction(actionRemoveAllBreakpoints_);

    breakpointsController_.attachHeaderButtons(breakpointHeaderBreakOnErrorButton_, breakpointHeaderToggleButton_,
                                               breakpointHeaderRemoveButton_, breakpointHeaderRemoveAllButton_,
                                               breakpointHeaderEditButton_, actionRemoveAllBreakpoints_);
}
