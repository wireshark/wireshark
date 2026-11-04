/* theme_lua_code_preview.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>

#include "theme_lua_code_preview.h"

#include <ui/qt/lua_debugger/lua_syntax_highlighter.h>
#include <ui/qt/utils/font_manager.h>
#include <ui/qt/utils/themes/contrast_adapt_icon.h>

#include <QAbstractTextDocumentLayout>
#include <QAction>
#include <QApplication>
#include <QContextMenuEvent>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPalette>
#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextOption>

namespace {

// A copy of doc/udpdelta.lua, the postdissector of the "Getting Started"
// section in doc/wsdg_src/wsdg_lua_debugger.adoc.
const char kUdpDeltaLua[] = R"lua(-- Time since the previous frame of the same UDP stream,
-- what tcp.time_delta shows for TCP

local udpdelta  = Proto("udpdelta", "UDP Stream Timing")
local f_delta   = ProtoField.double("udpdelta.time",
                                    "Time since previous stream frame")
udpdelta.fields = { f_delta }
local f_stream  = Field.new("udp.stream")
local state     = {}

function state:reset()
  self.last  = {}  -- stream index -> time of latest frame
  self.delta = {}  -- frame number -> seconds since previous frame
end

function udpdelta.init()
  state:reset()
end

function udpdelta.dissector(tvb, pinfo, tree)
  local stream = f_stream()
  if not stream then return end

  if state.delta[pinfo.number] == nil then
    local previous = state.last[stream.value]
    state.delta[pinfo.number] = previous and pinfo.abs_ts - previous or 0
    state.last[stream.value] = pinfo.abs_ts
  end

  tree:add(udpdelta):add(f_delta, state.delta[pinfo.number])
end

register_postdissector(udpdelta))lua";

// 1-based lines of the sample state.
const int kInactiveBreakpointLine = 17;
const int kBreakpointLine = 24;
const int kPausedLine = 26;
const int kLogpointLine = 30;
const int kSelectionLine = 30;
const char kSelectionText[] = "state";

// Space the debugger's gutter keeps right of the line numbers for its markers.
const int kMarkerWidth = 20;

} // namespace

ThemeLuaCodePreview::ThemeLuaCodePreview(QWidget *parent)
    : QWidget(parent)
    , document_(new QTextDocument(this))
    , highlighter_(nullptr)
    , picker_(this, [this]() { return renderPickImage(); }, [this]() { return pickTextHeight(); })
{
    setContentsMargins(0, 0, 0, 0);

    QTextOption option = document_->defaultTextOption();
    option.setWrapMode(QTextOption::NoWrap);
    document_->setDefaultTextOption(option);
    document_->setDefaultFont(resolvedFont());
    document_->setPlainText(QString::fromUtf8(kUdpDeltaLua));
    highlighter_ = new LuaSyntaxHighlighter(document_);
}

ThemeLuaCodePreview::~ThemeLuaCodePreview() = default;

void ThemeLuaCodePreview::setPreviewColors(const QHash<ThemeManager::ThemeToken, QColor> &colors)
{
    colors_ = colors;
    highlighter_->setColors(colors_);
    update();
}

void ThemeLuaCodePreview::setPreviewFont(const QFont &monospace)
{
    if (has_preview_font_ && preview_font_ == monospace)
        return;
    preview_font_ = monospace;
    has_preview_font_ = true;
    document_->setDefaultFont(resolvedFont());
    picker_.invalidate();
    updateGeometry();
    update();
}

QColor ThemeLuaCodePreview::c(ThemeManager::ThemeToken token, const QColor &fallback) const
{
    auto it = colors_.constFind(token);
    if (it != colors_.constEnd() && it.value().isValid())
        return it.value();
    if (!colors_.isEmpty())
        return fallback;
    const QColor live = ThemeManager::instance()->color(token);
    return live.isValid() ? live : fallback;
}

QFont ThemeLuaCodePreview::resolvedFont() const
{
    QFont font = has_preview_font_ ? preview_font_ : FontManager::monospaceFont();
    if (font.family().isEmpty())
        font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    return font;
}

int ThemeLuaCodePreview::gutterWidth(const QFont &font) const
{
    int digits = 1;
    for (int count = qMax(1, document_->blockCount()); count >= 10; count /= 10)
        ++digits;
    return 3 + QFontMetrics(font).horizontalAdvance(QLatin1Char('9')) * digits + kMarkerWidth;
}

QSize ThemeLuaCodePreview::minimumSizeHint() const
{
    return QSize(180, 120);
}

void ThemeLuaCodePreview::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    const QRect area = contentsRect();
    if (area.isEmpty())
        return;

    const QPalette pal = QApplication::palette();
    const QColor background    = c(ThemeManager::CodeBackground,    pal.color(QPalette::Base));
    const QColor text          = c(ThemeManager::CodeText,          pal.color(QPalette::Text));
    const QColor selection     = c(ThemeManager::CodeSelection,     pal.color(QPalette::Highlight));
    const QColor selectionText = c(ThemeManager::CodeSelectionText, pal.color(QPalette::HighlightedText));
    const QColor gutter        = c(ThemeManager::CodeGutter,        background);
    const QColor gutterText    = c(ThemeManager::CodeGutterText,    text);
    const QColor pausedLine    = c(ThemeManager::CodePausedLine);
    const QColor breakpoint    = c(ThemeManager::AccentError,       QColor(Qt::red));
    const QColor pausedMarker  = c(ThemeManager::AccentWarning,     QColor(Qt::darkYellow));

    const QFont font = resolvedFont();
    const QFontMetrics fm(font);
    const int gutterW = gutterWidth(font);
    const int textLeft = area.left() + gutterW;
    const int textWidth = qMax(0, area.right() - textLeft + 1);

    p.fillRect(area, background);
    p.fillRect(QRect(area.left(), area.top(), gutterW, area.height()), gutter);

    // The gutter, painted as LuaDebuggerCodeView::lineNumberAreaPaintEvent()
    // does: the number right-aligned before the marker column, the
    // breakpoint circles and the paused-line marker in it.
    p.setFont(font);
    p.setRenderHint(QPainter::Antialiasing, true);
    QAbstractTextDocumentLayout *layout = document_->documentLayout();
    for (QTextBlock block = document_->begin(); block.isValid(); block = block.next()) {
        const QRectF bounds = layout->blockBoundingRect(block);
        const int top = area.top() + qRound(bounds.top());
        if (top > area.bottom())
            break;
        const int line = block.blockNumber() + 1;

        if (line == kPausedLine && pausedLine.isValid())
            p.fillRect(QRect(textLeft, top, textWidth, qRound(bounds.height())), pausedLine);

        p.setPen(gutterText);
        p.drawText(area.left(), top, gutterW - kMarkerWidth, fm.height(), Qt::AlignRight,
                   QString::number(line));

        if (line == kInactiveBreakpointLine || line == kBreakpointLine || line == kLogpointLine) {
            // The Fluent circle covers 20/24 of the icon box.
            const int diameter = (fm.height() / 2 - 1) * 2;
            int box = qRound(diameter * 24.0 / 20.0);
            if ((box - diameter) % 2 != 0)
                ++box;
            const int inset = (box - diameter) / 2;
            const bool active = line != kInactiveBreakpointLine;
            ContrastAdaptIcon icon(line == kLogpointLine ? "lua-debug-breakpoint-actions" : "lua-debug-breakpoint");
            icon.setTokenColors({
                { ThemeManager::AccentError, active ? breakpoint : QColor(Qt::transparent) },
                { ThemeManager::PaletteText, active ? QColor(Qt::transparent) : gutterText },
            });
            icon.paint(&p, QRect(area.left() + gutterW - 16 - inset, top + 2 - inset, box, box));
        }

        if (line == kPausedLine) {
            // The play shape covers about 18/24 of the icon box.
            const int diameter = (fm.height() / 2 - 2) * 2;
            const int box = qRound(diameter * 24.0 / 18.0);
            ContrastAdaptIcon icon("lua-debug-paused-line");
            icon.setTokenColors({
                { ThemeManager::AccentWarning, pausedMarker },
                { ThemeManager::PaletteText, gutterText },
            });
            icon.paint(&p, QRect(area.left() + gutterW - 15 + (diameter - box) / 2,
                                 top + 2 + (diameter - box) / 2, box, box));
        }
    }
    p.setRenderHint(QPainter::Antialiasing, false);

    // The code, with the highlighter's formats and a fixed selection.
    QAbstractTextDocumentLayout::PaintContext context;
    context.palette.setColor(QPalette::Text, text);
    context.clip = QRectF(0, 0, textWidth, area.height());
    const QTextBlock selection_block = document_->findBlockByNumber(kSelectionLine - 1);
    const QString selection_word = QString::fromLatin1(kSelectionText);
    const int column = static_cast<int>(selection_block.text().indexOf(selection_word));
    if (column >= 0) {
        QAbstractTextDocumentLayout::Selection selected;
        selected.cursor = QTextCursor(selection_block);
        selected.cursor.setPosition(selection_block.position() + column);
        selected.cursor.setPosition(selection_block.position() + column + static_cast<int>(selection_word.size()),
                                    QTextCursor::KeepAnchor);
        selected.format.setBackground(selection);
        selected.format.setForeground(selectionText);
        context.selections.append(selected);
    }

    p.save();
    p.translate(textLeft, area.top());
    p.setClipRect(context.clip);
    layout->draw(&p, context);
    p.restore();
}

QImage ThemeLuaCodePreview::renderPickImage()
{
    // The probe is the same widget class, so its paint code decides which
    // token paints each pixel; it only differs by the unique key colors and
    // the unantialiased font.
    if (!pick_probe_) {
        pick_probe_ = std::make_unique<ThemeLuaCodePreview>();
        pick_probe_->setAttribute(Qt::WA_DontShowOnScreen);
        pick_probe_->show();
        pick_probe_->setPreviewColors(ThemeManager::flattenTokens(ThemePreviewPick::keyTokens(), false));
    }
    pick_probe_->setPreviewFont(ThemePreviewPick::keyFont(resolvedFont()));
    pick_probe_->resize(size());

    QImage image = ThemePreviewPick::keyCanvas(size());
    pick_probe_->render(&image);
    return image;
}

int ThemeLuaCodePreview::pickTextHeight() const
{
    return QFontMetrics(ThemePreviewPick::keyFont(resolvedFont())).height();
}

void ThemeLuaCodePreview::mouseMoveEvent(QMouseEvent *event)
{
    if (!picker_.hover(event->position().toPoint()))
        QWidget::mouseMoveEvent(event);
}

void ThemeLuaCodePreview::mousePressEvent(QMouseEvent *event)
{
    if (picker_.isPickClick(event)) {
        emit layerPicked(picker_.layerAt(event->position().toPoint()));
        event->accept();
        return;
    }
    QWidget::mousePressEvent(event);
}

void ThemeLuaCodePreview::contextMenuEvent(QContextMenuEvent *event)
{
    // Heap-allocated with WA_DeleteOnClose so popup() can return immediately;
    // the menu cleans itself up when dismissed.
    QMenu *menu = new QMenu(this);
    menu->setAttribute(Qt::WA_DeleteOnClose);

    QAction *separator = menu->addSeparator();
    QAction *saveAction = menu->addAction(tr("Save Image As…"));
    connect(saveAction, &QAction::triggered, this, [this]() {
        ThemePreviewPick::saveImage(this, QStringLiteral("theme-lua-code.png"),
                                    [this]() { emit childDialogClosed(); });
    });

    if (picker_.isEnabled())
        emit pickMenuRequested(menu, separator, picker_.layersAt(event->pos()));
    menu->popup(event->globalPos());
}
