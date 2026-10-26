/* theme_welcome_preview.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>

#include "theme_welcome_preview.h"

#include "ui_theme_welcome_preview.h"

#include <ui/qt/main_application.h>
#include <ui/qt/utils/themes/theme_stylesheet_loader.h>

#include <iterator>

#include <QContextMenuEvent>
#include <QHeaderView>
#include <QLayout>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPolygonF>
#include <QRegularExpression>
#include <QStyledItemDelegate>

namespace {

// Custom (non-Qt) type selectors used by the real welcome style sheets, and
// the selector that matches the equivalent widget in the preview. The
// application sheet's FilterEdit rules style the preview's plain filter field.
const struct { const char *from; const char *to; } kSelectorRewrites[] = {
    { "WelcomePage",      "ThemeWelcomePreview" },
    { "FilterEdit",       "QLineEdit#themePreviewFilter" },
};

// Draws a fixed sample line in the row's text color, as SparklineDelegate does
// for the live interface list.
class PreviewSparklineDelegate : public QStyledItemDelegate
{
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
    {
        QStyledItemDelegate::paint(painter, option, index);

        static const double kSamples[] = { 0.2, 0.3, 0.25, 0.6, 0.8, 0.5, 0.7, 0.35, 0.45, 0.3 };
        const int count = static_cast<int>(std::size(kSamples));
        const QRectF r = QRectF(option.rect).adjusted(4, 3, -4, -3);
        QPolygonF line;
        for (int i = 0; i < count; ++i) {
            line << QPointF(r.left() + r.width() * i / (count - 1),
                            r.bottom() - r.height() * kSamples[i]);
        }
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setPen(QPen(option.palette.color(option.state & QStyle::State_Selected
                                                  ? QPalette::HighlightedText : QPalette::Text), 1));
        painter->drawPolyline(line);
        painter->restore();
    }
};

} // namespace

ThemeWelcomePreview::ThemeWelcomePreview(QWidget *parent)
    : QFrame(parent),
      ui(new Ui::ThemeWelcomePreview),
      picker_(this, [this]() { return renderPickImage(); }, [this]() { return pickTextHeight(); })
{
    ui->setupUi(this);

    ui->headerTitle->setText(mainApp->applicationName());

    // The learn card is the real widget; this widget's sheet styles it.
    ui->learnCard->setStyledByParent(true);
    // The live page's compact links (one row of short labels), which it
    // also shows when vertical space is short.
    ui->learnCard->setLinksCollapsed(true);

    // The real welcome style sheets paint these containers' backgrounds.
    for (QWidget *w : { ui->welcomeHeader, ui->updateHeader })
        w->setAttribute(Qt::WA_StyledBackground, true);

    ui->openFileSectionRecentList->setFixedHeight(ui->openFileSectionRecentList->sizeHintForRow(0) * 2 + 12);

    QTreeWidget *tree = ui->interfaceTree;
    tree->setItemDelegateForColumn(1, new PreviewSparklineDelegate(tree));
    tree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    tree->header()->setSectionResizeMode(1, QHeaderView::Fixed);
    tree->setColumnWidth(1, 90);
    tree->setCurrentItem(tree->topLevelItem(0));
    tree->setFixedHeight(tree->sizeHintForRow(0) * 2 + 4);

    // Static preview: no interaction, no focus.  This also reaches the learn
    // card's links and buttons, which the card creates at run time.
    const QList<QWidget *> children = findChildren<QWidget *>();
    for (QWidget *w : children) {
        w->setAttribute(Qt::WA_TransparentForMouseEvents, true);
        w->setFocusPolicy(Qt::NoFocus);
    }
}

ThemeWelcomePreview::~ThemeWelcomePreview()
{
    delete ui;
}

QString ThemeWelcomePreview::buildStyleSheet(
    const QHash<ThemeManager::ThemeToken, ThemeColorPair> &tokens, bool dark,
    const QPalette &palette) const
{
    static const char *const kSheets[] = {
        "application", "welcome-page", "widgets/welcome-header", "widgets/capture-card", "widgets/learn-card"
    };
    QString sheet;
    for (const char *name : kSheets)
        sheet += ThemeStyleSheetLoader::load(QString::fromLatin1(name), tokens, dark) + QLatin1Char('\n');

    for (const auto &rw : kSelectorRewrites) {
        sheet.replace(QRegularExpression(QStringLiteral("\\b%1\\b").arg(QString::fromLatin1(rw.from))),
                      QString::fromLatin1(rw.to));
    }

    return ThemeStyleSheetLoader::resolvePaletteRoles(sheet, palette);
}

void ThemeWelcomePreview::setTheme(const QHash<ThemeManager::ThemeToken, ThemeColorPair> &tokens,
                                   bool dark, const QPalette &palette)
{
    // The unfocused selection must paint like the active one, as in the live
    // welcome page where the interface list is not focused either.
    QPalette pal = palette;
    for (QPalette::ColorRole role : { QPalette::Highlight, QPalette::HighlightedText })
        pal.setColor(QPalette::Inactive, role, pal.color(QPalette::Active, role));
    setPalette(pal);

    const QColor link = pal.color(QPalette::Link);
    for (int i = 0; i < ui->openFileSectionRecentList->count(); ++i)
        ui->openFileSectionRecentList->item(i)->setForeground(link);

    ui->updateText->setText(tr("Update available: %1 <b><span style=\"color:%2\">4.8.0</span></b>")
                              .arg(mainApp->applicationName(),
                                   tokens.value(ThemeManager::UpdateTextHighlight).forMode(dark).name()));

    ui->learnCard->setCardLinkColor(tokens.value(ThemeManager::CardLink).forMode(dark));

    setStyleSheet(buildStyleSheet(tokens, dark, pal));
}

void ThemeWelcomePreview::setPreviewFont(const QFont &regular)
{
    // Called on every draft change; an unchanged font must not drop the
    // key image and the hover tip.
    if (has_preview_font_ && preview_font_ == regular)
        return;
    preview_font_ = regular;
    has_preview_font_ = true;
    setFont(regular);
    picker_.invalidate();
}

int ThemeWelcomePreview::pickTextHeight() const
{
    // Tallest line among the probe's widgets (bold section headers, the
    // title); the image analysis uses it to tell glyphs from larger areas.
    int height = fontMetrics().height();
    if (pick_probe_) {
        for (const QWidget *w : pick_probe_->findChildren<QWidget *>())
            height = qMax(height, w->fontMetrics().height());
    }
    return height;
}

QImage ThemeWelcomePreview::renderPickImage()
{
    if (!pick_probe_) {
        pick_probe_ = std::make_unique<ThemeWelcomePreview>();
        pick_probe_->setAttribute(Qt::WA_DontShowOnScreen, true);
        pick_probe_->show();
        pick_probe_->setTheme(ThemePreviewPick::keyTokens(), false, ThemePreviewPick::keyPalette());
    }

    // Same widget tree and style sheets as this widget, themed with one key
    // color per token, so Qt's own cascade decides each pixel's token.
    pick_probe_->setPreviewFont(ThemePreviewPick::keyFont(font()));
    pick_probe_->resize(size());
    if (pick_probe_->layout())
        pick_probe_->layout()->activate();

    QImage image = ThemePreviewPick::keyCanvas(size());
    pick_probe_->render(&image);
    return image;
}

void ThemeWelcomePreview::mouseMoveEvent(QMouseEvent *event)
{
    if (!picker_.hover(event->position().toPoint()))
        QFrame::mouseMoveEvent(event);
}

void ThemeWelcomePreview::mousePressEvent(QMouseEvent *event)
{
    if (picker_.isPickClick(event)) {
        emit layerPicked(picker_.layerAt(event->position().toPoint()));
        event->accept();
        return;
    }
    QFrame::mousePressEvent(event);
}

void ThemeWelcomePreview::contextMenuEvent(QContextMenuEvent *event)
{
    // Heap-allocated with WA_DeleteOnClose so popup() can return immediately;
    // the menu cleans itself up when dismissed.
    QMenu *menu = new QMenu(this);
    menu->setAttribute(Qt::WA_DeleteOnClose);

    QAction *separator = menu->addSeparator();
    QAction *saveAction = menu->addAction(tr("Save Image As…"));
    connect(saveAction, &QAction::triggered, this, [this]() {
        ThemePreviewPick::saveImage(this, QStringLiteral("theme-welcome.png"),
                                    [this]() { emit childDialogClosed(); });
    });

    if (picker_.isEnabled())
        emit pickMenuRequested(menu, separator, picker_.layersAt(event->pos()));
    menu->popup(event->globalPos());
}
