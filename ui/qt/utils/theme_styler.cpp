/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/qt/utils/theme_styler.h"

#include <ui/qt/utils/zoom_scaling.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/themes/color_math.h>

#include <QAbstractButton>
#include <QColor>
#include <QDebug>
#include <QEvent>
#include <QList>
#include <QMainWindow>
#include <QMargins>
#include <QOperatingSystemVersion>
#include <QPainter>
#include <QPen>
#include <QRectF>
#include <QStyleOptionButton>
#include <QStyleOptionToolBar>
#include <QStyleOptionToolButton>
#include <QStyleOptionViewItem>
#include <QToolBar>

#ifdef Q_OS_MACOS
#include <ui/qt/utils/themes/native_push_button.h>

#include <QFocusFrame>
#include <QGuiApplication>
#include <QPushButton>
#include <QStyleHints>
#endif

static QString base_style_name_;

#ifdef Q_OS_WIN
// True if the base style is windows11. Item views are painted for every
// visible cell, so the style name is not compared on each paint.
static bool windows11_base_ = false;

// The windows11 style (Qt 6.7+) fills selected item view rows with a fixed,
// nearly transparent gray (WinUI's "subtle" fill) and draws their text in the
// normal text color. It ignores the palette's Highlight and HighlightedText,
// unless the view has alternating row colors or Windows uses a contrast
// theme, and looks the same whether the view has focus or not. To the user
// a selected row looks like an inactive selection all the time, and the
// theme's selection colors never show. The functions below hand selected
// rows to the base style with the palette colors instead, so the selection
// is drawn as on the other styles, in the windows11 shape.

// Corner radius of the windows11 style's item view selection (its
// secondLevelRoundingRadius, private in qwindows11style.cpp).
static constexpr int windows11_item_radius_ = 4;

// The palette group a view item is drawn with, as QCommonStyle picks it.
// Item views clear State_Active when the view does not have focus.
static QPalette::ColorGroup viewItemColorGroup(const QStyleOption *option)
{
    if (!(option->state & QStyle::State_Enabled))
        return QPalette::Disabled;
    return (option->state & QStyle::State_Active) ? QPalette::Active : QPalette::Inactive;
}

// True if the windows11 base style would paint this view item as selected
// with its subtle fill.
static bool takesWindows11Selection(const QStyleOptionViewItem *vopt)
{
    return windows11_base_ && vopt && (vopt->state & QStyle::State_Selected);
}

#endif // Q_OS_WIN

#ifdef Q_OS_MACOS
// The toolbars that make up the unified title and toolbar area of a
// main window: visible, docked, in the top area. The native style
// tests this with a private QMainWindowLayout call.
static QList<QToolBar *> dockedTopToolBars(const QMainWindow *mainWindow)
{
    QList<QToolBar *> result;
    const QList<QToolBar *> toolBars = mainWindow->findChildren<QToolBar *>(QString(), Qt::FindDirectChildrenOnly);
    for (QToolBar *toolBar : toolBars) {
        if (toolBar->isVisible() && !toolBar->isFloating()
                && mainWindow->toolBarArea(toolBar) == Qt::TopToolBarArea)
            result.append(toolBar);
    }
    return result;
}

// True if no other unified area toolbar sits below this one, i.e. the
// unified area ends at its bottom. The toolbars' line position is no
// help, since lines that hold only hidden toolbars still count.
static bool isLastTopToolBarRow(const QMainWindow *mainWindow, const QWidget *toolBar)
{
    const int bottom = toolBar->geometry().bottom();
    for (const QToolBar *other : dockedTopToolBars(mainWindow)) {
        if (other != toolBar && other->geometry().top() > bottom)
            return false;
    }
    return true;
}
#endif

// Pixel metrics that follow the application zoom. Icon sizes and the
// splitter width scale on every base style. The control metrics are not
// scaled on macOS: AppKit draws check boxes, radio buttons, scroll bars and
// sliders at fixed control sizes, so a larger rect would only add empty
// space around the native control.
struct ZoomedPixelMetric {
    QStyle::PixelMetric metric;
    bool scaleOnMacOS;
};

static const ZoomedPixelMetric zoomed_pixel_metrics[] = {
    { QStyle::PM_SmallIconSize,            true },
    { QStyle::PM_LargeIconSize,            true },
    { QStyle::PM_ToolBarIconSize,          true },
    { QStyle::PM_ListViewIconSize,         true },
    { QStyle::PM_IconViewIconSize,         true },
    { QStyle::PM_TabBarIconSize,           true },
    { QStyle::PM_ButtonIconSize,           true },
    { QStyle::PM_MessageBoxIconSize,       true },
    { QStyle::PM_SplitterWidth,            true },
    { QStyle::PM_IndicatorWidth,           false },
    { QStyle::PM_IndicatorHeight,          false },
    { QStyle::PM_ExclusiveIndicatorWidth,  false },
    { QStyle::PM_ExclusiveIndicatorHeight, false },
    { QStyle::PM_ScrollBarExtent,          false },
    { QStyle::PM_ScrollBarSliderMin,       false },
    { QStyle::PM_SliderThickness,          false },
    { QStyle::PM_SliderControlThickness,   false },
    { QStyle::PM_SliderLength,             false },
    { QStyle::PM_ToolBarExtensionExtent,   false },
    { QStyle::PM_ToolBarHandleExtent,      false },
};

static bool isZoomedPixelMetric(QStyle::PixelMetric metric)
{
    for (const ZoomedPixelMetric &entry : zoomed_pixel_metrics) {
        if (entry.metric == metric) {
            return entry.scaleOnMacOS
                    || ThemeStyler::baseStyleName() != QLatin1String("macos");
        }
    }
    return false;
}

ThemeStyler::ThemeStyler(QStyle *style) : QProxyStyle(style)
{
    base_style_name_ = baseStyle()->objectName();
#ifdef Q_OS_WIN
    windows11_base_ = base_style_name_ == QLatin1String("windows11");
#endif
}

ThemeStyler::ThemeStyler(const QString &key) : QProxyStyle(key)
{
    base_style_name_ = baseStyle()->objectName();
#ifdef Q_OS_WIN
    windows11_base_ = base_style_name_ == QLatin1String("windows11");
#endif
}

QString ThemeStyler::baseStyleName()
{
    return base_style_name_;
}

static const char *plain_submenus_property = "_ws_plain_submenus";

void ThemeStyler::setPlainSubMenus(QWidget *widget)
{
    widget->setProperty(plain_submenus_property, true);
}

// Whether a menu is created in a widget given to setPlainSubMenus()
static bool hasPlainSubMenus(const QWidget *widget)
{
    for (; widget != nullptr; widget = widget->parentWidget()) {
        if (widget->property(plain_submenus_property).toBool())
            return true;
    }
    return false;
}

int ThemeStyler::styleHint(StyleHint hint, const QStyleOption *option,
    const QWidget *widget, QStyleHintReturn *returnData) const
{
    if (hint == QStyle::SH_MessageBox_TextInteractionFlags)
            return QProxyStyle::styleHint(hint, option, widget, returnData) | Qt::TextSelectableByMouse;
    if (hint == QStyle::SH_Menu_SubMenuUniDirection && hasPlainSubMenus(widget))
        return false;
    if (hint == QStyle::SH_Menu_SubMenuSloppySelectOtherActions && hasPlainSubMenus(widget))
        return true;
    return QProxyStyle::styleHint(hint, option, widget, returnData);
}

int ThemeStyler::pixelMetric(PixelMetric metric, const QStyleOption *option,
    const QWidget *widget) const
{
    // A native style may compute this metric from others through
    // proxy()->pixelMetric(), which lands here again. Those nested values
    // are inputs of the outer metric and must stay unscaled, otherwise the
    // outer result would carry the zoom factor twice.
    if (metric_depth_ > 0)
        return QProxyStyle::pixelMetric(metric, option, widget);

    ++metric_depth_;
    const int base = QProxyStyle::pixelMetric(metric, option, widget);
    --metric_depth_;

    // Non-positive values are "not applicable" markers or resets.
    if (base <= 0 || !isZoomedPixelMetric(metric))
        return base;
    return ZoomScaling::scaledPixels(base);
}

#ifdef Q_OS_MACOS
// Size of the menu arrow the macOS style draws on a toolbar button and
// its margin from the bottom right corner (toolButtonArrowSize and
// toolButtonArrowMargin in qmacstyle_mac.mm).
static const int macToolButtonArrowSize = 7;
static const int macToolButtonArrowMargin = 2;

// True for a toolbar button with an InstantPopup or DelayedPopup menu
// that the macOS style draws without the menu arrow: it draws the arrow
// only for buttons that show an icon.
static bool macToolButtonLacksMenuArrow(const QStyleOptionToolButton *tb)
{
    return (tb->features & QStyleOptionToolButton::HasMenu)
            && !(tb->features & QStyleOptionToolButton::MenuButtonPopup)
            && (tb->toolButtonStyle == Qt::ToolButtonTextOnly || tb->icon.isNull());
}
#endif

QSize ThemeStyler::sizeFromContents(ContentsType type, const QStyleOption *option,
    const QSize &contentsSize, const QWidget *widget) const
{
    QSize size = QProxyStyle::sizeFromContents(type, option, contentsSize, widget);
#ifdef Q_OS_MACOS
    // QMacStyle gives OK and Cancel buttons a fixed width whatever their
    // font, and draws the label clipped to the title rect, so a wider font
    // or a zoomed one crops the label. Widen the button until its title
    // rect holds the content.
    //
    // QMacStyle also grows a push button above its bezel height once the
    // content is taller than the default, and then paints every non-flat
    // push button that is not exactly the bezel height as a square bezel.
    // Keep the bezel height while the zoomed content still fits the
    // bezel's title rect. The probes call the base implementation, not this
    // proxy, so they do not recurse.
    const QStyleOptionButton *button = qstyleoption_cast<const QStyleOptionButton *>(option);
    if (type == CT_PushButton && button && !(button->features & QStyleOptionButton::Flat)
            && baseStyleName() == QLatin1String("macos")) {
        const int bezel = pushButtonBezelHeight(button, contentsSize.width(), widget);
        QStyleOptionButton probe = *button;
        if (size.height() > bezel) {
            probe.rect = QRect(0, 0, size.width(), bezel);
            const QRect title = QProxyStyle::subElementRect(SE_PushButtonContents, &probe, widget);
            if (contentsSize.height() <= title.height())
                size.setHeight(bezel);
        }
        probe.rect = QRect(QPoint(0, 0), size);
        const QRect title = QProxyStyle::subElementRect(SE_PushButtonContents, &probe, widget);
        if (title.width() < contentsSize.width())
            size.rwidth() += contentsSize.width() - title.width();
    }

    // drawComplexControl() draws the menu arrow the macOS style leaves
    // out on text-only toolbar buttons. The macOS style gives a tool
    // button only a narrow margin, so widen the button to keep the
    // centered label clear of the arrow.
    const QStyleOptionToolButton *tb = qstyleoption_cast<const QStyleOptionToolButton *>(option);
    if (type == CT_ToolButton && tb && widget
            && qobject_cast<const QToolBar *>(widget->parentWidget())
            && baseStyleName() == QLatin1String("macos")
            && macToolButtonLacksMenuArrow(tb)) {
        size.rwidth() += macToolButtonArrowSize + macToolButtonArrowMargin;
    }
#endif
    return size;
}

#ifdef Q_OS_MACOS
int ThemeStyler::pushButtonBezelHeight(const QStyleOptionButton *button, int contentsWidth,
    const QWidget *widget) const
{
    // The base style returns at least the bezel height for empty content.
    return QProxyStyle::sizeFromContents(CT_PushButton, button, QSize(contentsWidth, 0), widget).height();
}

bool ThemeStyler::takesFlexibleBezel(const QStyleOptionButton *button, const QWidget *widget) const
{
    if (!button || !widget || baseStyleName() != QLatin1String("macos"))
        return false;
    if (button->features & (QStyleOptionButton::Flat | QStyleOptionButton::CommandLinkButton))
        return false;
    // The base style draws no bevel without one of these states either.
    if (!(button->state & (State_Raised | State_Sunken | State_On)))
        return false;
    // The native bezel is drawn in the window's native view; never create
    // one just to paint.
    if (widget->window()->effectiveWinId() == 0)
        return false;
    // Buttons of the bezel height get the native rounded bezel from the
    // base style. Lower ones keep its square bezel, since the flexible
    // bezel has a minimum height.
    return button->rect.height() > pushButtonBezelHeight(button, button->rect.width(), widget);
}

bool ThemeStyler::pushButtonEmphasized(const QStyleOptionButton *button)
{
    return (button->state & State_On)
            || (button->features & QStyleOptionButton::DefaultButton)
            || ((button->features & QStyleOptionButton::AutoDefaultButton)
                && (button->state & State_HasFocus));
}

NativePushButton::BezelState ThemeStyler::flexibleBezelState(const QStyleOptionButton *button)
{
    NativePushButton::BezelState state;
    state.enabled = button->state & State_Enabled;
    state.pressed = button->state & State_Sunken;
    state.highlighted = (button->state & State_Active) && pushButtonEmphasized(button);
    return state;
}

QRect ThemeStyler::flexibleBezelRect(const QStyleOptionButton *button, const QWidget *widget) const
{
    // At the bezel height the base style returns the visible outline of the
    // native bezel as SE_PushButtonBevel, without its shadow. Keep its
    // horizontal extent and its top and bottom insets, and stretch it to
    // the button height.
    const QRect &rect = button->rect;
    QStyleOptionButton probe = *button;
    probe.rect.setHeight(pushButtonBezelHeight(button, rect.width(), widget));
    const QRect bevel = QProxyStyle::subElementRect(SE_PushButtonBevel, &probe, widget);
    const int topInset = bevel.top() - probe.rect.top();
    const int bottomInset = probe.rect.bottom() - bevel.bottom();
    return QRect(bevel.left(), rect.top() + topInset, bevel.width(),
                 rect.height() - topInset - bottomInset);
}
#endif

void ThemeStyler::drawPrimitive(PrimitiveElement element, const QStyleOption *option,
    QPainter *painter, const QWidget *widget) const
{
#ifdef Q_OS_MACOS
    // With the Liquid Glass appearance (macOS 26+ SDK and runtime), the
    // macOS style ignores the position of the indicator rect and draws the
    // check box at the painter origin, so item view check boxes end up
    // outside the item and are invisible. Draw at the origin of a translated
    // painter instead.
    static const bool liquid_glass_os = QOperatingSystemVersion::current().majorVersion() >= 26;
    if (liquid_glass_os && element == PE_IndicatorItemViewItemCheck && option && painter
            && !option->rect.topLeft().isNull()) {
        QStyleOptionViewItem opt;
        if (const QStyleOptionViewItem *vopt = qstyleoption_cast<const QStyleOptionViewItem *>(option))
            opt = *vopt;
        else
            static_cast<QStyleOption &>(opt) = *option;
        opt.rect.moveTopLeft(QPoint(0, 0));

        painter->save();
        painter->translate(option->rect.topLeft());
        QProxyStyle::drawPrimitive(element, &opt, painter, widget);
        painter->restore();
        return;
    }
#endif
#ifdef Q_OS_WIN
    if (windows11_base_ && option && painter) {
        const QStyleOptionViewItem *vopt = qstyleoption_cast<const QStyleOptionViewItem *>(option);
        switch (element) {
        case PE_PanelItemViewItem:
            // The windows11 style's CE_ItemViewItem fills the cell with the
            // option's background brush through this primitive, and then
            // draws its rounded selection shape with the same brush. For a
            // selected item drawControl() passes the highlight as that brush;
            // fill the item's own background here, so the rounded highlight
            // sits on it the way the windows11 subtle fill does.
            if (vopt && selected_item_background_) {
                if (selected_item_background_->style() != Qt::NoBrush) {
                    painter->save();
                    painter->setBrushOrigin(vopt->rect.topLeft());
                    painter->fillRect(vopt->rect, *selected_item_background_);
                    painter->restore();
                }
                return;
            }
            break;
        case PE_PanelItemViewRow:
            // A tree view draws the branch area of a selected row with this
            // primitive. Without showDecorationSelected the windows11 style
            // only marks it with its accent bar, and the item cells aren't
            // joined to it; leave that to the base style.
            if (takesWindows11Selection(vopt) && vopt->showDecorationSelected
#if QT_VERSION >= QT_VERSION_CHECK(6, 9, 0)
                    && vopt->features.testFlag(QStyleOptionViewItem::IsDecorationForRootColumn)) {
#else
                    && vopt->features.testFlag(QStyleOptionViewItem::HasDecoration)) {
#endif
                drawWindows11DecorationSelection(vopt, painter, widget);
                return;
            }
            break;
        case PE_IndicatorBranch:
            // The windows11 style draws the chevron of an expanded item in
            // the Active WindowText color and that of a collapsed one in
            // the Disabled WindowText color, which don't read on the
            // highlight.
            if (takesWindows11Selection(vopt) && vopt->showDecorationSelected) {
                QStyleOptionViewItem opt(*vopt);
                const QColor text = vopt->palette.color(viewItemColorGroup(vopt), QPalette::HighlightedText);
                opt.palette.setColor(QPalette::Active, QPalette::WindowText, text);
                opt.palette.setColor(QPalette::Disabled, QPalette::WindowText, text);
                QProxyStyle::drawPrimitive(element, &opt, painter, widget);
                return;
            }
            break;
        default:
            break;
        }
    }
#endif // Q_OS_WIN

    QProxyStyle::drawPrimitive(element, option, painter, widget);

    // Fusion outlines buttons, combo boxes and line edits with
    // Window.darker(140), about 2:1 on a light window, which misses the
    // non-text contrast a High control boundary needs.  Paint the frame
    // again in ControlBorder on Fusion's own geometry.  Fusion also draws
    // raised or pressed tool buttons through PE_PanelButtonCommand, so a
    // hovered tool button gets the same frame.
    if ((element == PE_PanelButtonCommand || element == PE_FrameLineEdit)
            && option && painter
            && ColorMath::activeRatios().level == ThemeContrast::High
            && baseStyleName() == QLatin1String("fusion")) {
        // QFusionStyle's button and line edit frame geometry (private in
        // qfusionstyle.cpp, no API exposes it): the rect inset by half a
        // pixel with a 2 px corner radius.
        constexpr qreal fusionFrameInset = 0.5;
        constexpr qreal fusionFrameRadius = 2.0;
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setPen(QPen(ThemeManager::instance()->color(ThemeManager::ControlBorder), 1));
        painter->setBrush(Qt::NoBrush);
        painter->drawRoundedRect(
                QRectF(option->rect).adjusted(fusionFrameInset, fusionFrameInset,
                                              -fusionFrameInset, -fusionFrameInset),
                fusionFrameRadius, fusionFrameRadius);
        painter->restore();
    }
}

void ThemeStyler::drawControl(ControlElement element, const QStyleOption *option,
    QPainter *painter, const QWidget *widget) const
{
#ifdef Q_OS_MACOS
    // drawComplexControl() clears State_On on toolbar buttons so the
    // macOS style skips its own checked background, but the label needs
    // it (pressed look, icon state), so restore it for a checked button.
    //
    // The macOS style also draws the label of a pressed text-only tool
    // button in a toolbar with a dark drop shadow, in the menu highlight
    // text color and shifted down. drawComplexControl() already shows the
    // press with a fill, so draw the label as for a released button.
    const QStyleOptionToolButton *tb = qstyleoption_cast<const QStyleOptionToolButton *>(option);
    if (element == CE_ToolButtonLabel && tb && painter && widget
            && qobject_cast<const QToolBar *>(widget->parentWidget())
            && baseStyleName() == QLatin1String("macos")) {
        QStyleOptionToolButton labelOpt = *tb;
        const QAbstractButton *button = qobject_cast<const QAbstractButton *>(widget);
        if (button && button->isChecked()) {
            labelOpt.state |= State_On;
        }
        if (!(tb->features & QStyleOptionToolButton::Arrow) && !tb->text.isEmpty()
                && (tb->toolButtonStyle == Qt::ToolButtonTextOnly || tb->icon.isNull())) {
            labelOpt.state &= ~State_Sunken;
        }
        QProxyStyle::drawControl(element, &labelOpt, painter, widget);
        return;
    }

    // The macOS style draws a push button taller than its native bezel
    // (zoomed fonts) as a flat square. Such buttons get AppKit's
    // flexible-height rounded push bezel instead. Only the bevel is
    // replaced: QCommonStyle composes CE_PushButton from bevel and label
    // through proxy(), so the label and the hit rects stay the base
    // style's.
    if (element == CE_PushButtonBevel && option && painter) {
        const QStyleOptionButton *btn = qstyleoption_cast<const QStyleOptionButton *>(option);
        if (btn && takesFlexibleBezel(btn, widget)) {
            if (NativePushButton::drawFlexibleBezel(painter, flexibleBezelRect(btn, widget),
                                                    flexibleBezelState(btn), widget)) {
                if (btn->features & QStyleOptionButton::HasMenu) {
                    // Menu arrow placement of QMacStyle's CE_PushButtonBevel
                    // for square buttons (private, no API exposes it). For
                    // a square button the base SE_PushButtonBevel is the
                    // frame rect that code places the arrow in.
                    const QRect ir = QProxyStyle::subElementRect(SE_PushButtonBevel, btn, widget);
                    const int mbi = proxy()->pixelMetric(PM_MenuButtonIndicator, btn, widget);
                    QStyleOption arrowOpt = *option;
                    arrowOpt.rect = visualRect(btn->direction, ir,
                                               QRect(ir.right() - mbi - 6, ir.height() / 2, mbi, mbi));
                    proxy()->drawPrimitive(PE_IndicatorArrowDown, &arrowOpt, painter, widget);
                }
                return;
            }
        }
    }

    // The label color of QMacStyle's CE_PushButtonLabel depends on the
    // accent state its own bevel code records in a private pointer, which
    // is never updated for the buttons drawn above. Set the final color
    // here from the option alone, with QMacStyle's rules.
    if (element == CE_PushButtonLabel && option && painter && widget) {
        const QStyleOptionButton *btn = qstyleoption_cast<const QStyleOptionButton *>(option);
        if (btn) {
            // The label option carries the contents rect; judge the button.
            QStyleOptionButton buttonOpt = *btn;
            buttonOpt.rect = widget->rect();
            if (takesFlexibleBezel(&buttonOpt, widget)) {
                QStyleOptionButton labelOpt = *btn;
                const NativePushButton::BezelState state = flexibleBezelState(btn);
                const bool emphasized = pushButtonEmphasized(btn);
                // White label on the accent fill or a pressed bezel, as
                // QMacStyle does for its rounded push button; menu buttons
                // are never whitened.
                if (!(btn->features & QStyleOptionButton::HasMenu)
                        && (state.pressed || (state.enabled && state.highlighted)))
                    labelOpt.palette.setColor(QPalette::ButtonText, Qt::white);
                // QMacStyle's gray button rule: black on a light enabled
                // non-accent bezel. Same color scheme test as QMacStyle.
                const bool lightMode = QGuiApplication::styleHints()->colorScheme() != Qt::ColorScheme::Dark;
                if (state.enabled && lightMode && !emphasized)
                    labelOpt.palette.setColor(QPalette::ButtonText, Qt::black);
                // QMacStyle forces black on a light button it does not
                // consider default and that is not checked. Mark an
                // emphasized button checked so that override, driven by
                // the stale private pointer, never fires for it.
                if (emphasized)
                    labelOpt.state |= State_On;
                QProxyStyle::drawControl(element, &labelOpt, painter, widget);
                return;
            }
        }
    }

    // The focus ring of a button drawn above follows its flexible bezel.
    if (element == CE_FocusFrame && option && painter) {
        const QFocusFrame *frame = qobject_cast<const QFocusFrame *>(widget);
        const QPushButton *button = frame ? qobject_cast<const QPushButton *>(frame->widget()) : nullptr;
        if (button) {
            // Rebuild the option QPushButton::initStyleOption() gives the bevel
            // (that function is protected), so the take-over decision and the
            // rect match the bevel path. Its private menuOpen -> State_Sunken is
            // left out; State_Raised is always set, which the decision accepts
            // either way.
            QStyleOptionButton buttonOpt;
            buttonOpt.initFrom(button);
            if (button->isFlat())
                buttonOpt.features |= QStyleOptionButton::Flat;
            if (button->menu())
                buttonOpt.features |= QStyleOptionButton::HasMenu;
            if (button->isDefault())
                buttonOpt.features |= QStyleOptionButton::DefaultButton;
            if (button->autoDefault())
                buttonOpt.features |= QStyleOptionButton::AutoDefaultButton;
            buttonOpt.state |= State_Raised;
            if (button->isDown())
                buttonOpt.state |= State_Sunken;
            if (button->isChecked())
                buttonOpt.state |= State_On;
            buttonOpt.rect = button->rect();
            if (takesFlexibleBezel(&buttonOpt, button)) {
                const QPoint offset = button->mapTo(button->window(), QPoint())
                        - frame->mapTo(frame->window(), QPoint());
                const QRect ring = flexibleBezelRect(&buttonOpt, button).translated(offset);
                if (NativePushButton::drawFocusRing(painter, ring, button))
                    return;
            }
        }
    }

    // In the unified title and toolbar area the macOS style fills top
    // toolbars with transparent pixels so the window's native content
    // border shows through, which ignores the application palette. A
    // theme that sets palette.window expects its toolbars in that
    // color, as on the other platforms and in non-unified mode, where
    // the macOS style fills palette.window itself. The check runs at
    // paint time: every theme, mode or contrast switch sets the
    // application style sheet again, which repaints the toolbars, so
    // switching to a theme without palette.window restores the native
    // look.
    if (element == CE_ToolBar && option && painter && widget) {
        const QStyleOptionToolBar *toolBarOption = qstyleoption_cast<const QStyleOptionToolBar *>(option);
        const QMainWindow *mainWindow = qobject_cast<const QMainWindow *>(widget->window());
        ThemeManager *themeManager = ThemeManager::instance();
        if (toolBarOption && toolBarOption->toolBarArea == Qt::TopToolBarArea
                && mainWindow && mainWindow->unifiedTitleAndToolBarOnMac()
                && themeManager->colorIsAvailable(ThemeManager::PaletteWindow)) {
            painter->fillRect(option->rect, option->palette.window());
            if (isLastTopToolBarRow(mainWindow, widget)) {
                // The native separator is one pixel high.
                constexpr int separatorHeight = 1;
                painter->fillRect(QRect(option->rect.left(), option->rect.bottom(),
                                        option->rect.width(), separatorHeight),
                                  themeManager->color(ThemeManager::BorderSeparator));
            }
            return;
        }
    }
#endif
#ifdef Q_OS_WIN
    // Hand a selected item to the windows11 style as an unselected item
    // whose background is the highlight and whose text is the highlighted
    // text, so it draws its rounded item shape in the palette's selection
    // colors instead of its subtle fill. The highlight comes from the
    // Inactive group when the view doesn't have focus, as on other styles.
    if (element == CE_ItemViewItem && painter) {
        const QStyleOptionViewItem *vopt = qstyleoption_cast<const QStyleOptionViewItem *>(option);
        if (takesWindows11Selection(vopt)) {
            const QPalette::ColorGroup cg = viewItemColorGroup(vopt);
            QStyleOptionViewItem opt(*vopt);
            opt.backgroundBrush = vopt->palette.brush(cg, QPalette::Highlight);
            opt.palette.setBrush(QPalette::Text, vopt->palette.brush(cg, QPalette::HighlightedText));
            opt.state &= ~(State_Selected | State_MouseOver);
            selected_item_background_ = &vopt->backgroundBrush;
            QProxyStyle::drawControl(element, &opt, painter, widget);
            selected_item_background_ = nullptr;
            return;
        }
    }
#endif // Q_OS_WIN

    QProxyStyle::drawControl(element, option, painter, widget);
}

#ifdef Q_OS_WIN
void ThemeStyler::drawWindows11DecorationSelection(const QStyleOptionViewItem *vopt,
    QPainter *painter, const QWidget *widget) const
{
    // The base style draws the unselected row background (alternate row
    // colors), without its subtle fill and accent bar.
    QStyleOptionViewItem opt(*vopt);
    opt.state &= ~(State_Selected | State_MouseOver);
    QProxyStyle::drawPrimitive(PE_PanelItemViewRow, &opt, painter, widget);

    // The highlight in the windows11 shape and geometry: the branch area
    // starts the row's selection, so it is rounded on the leading side, and
    // the item cells continue it (qwindows11style.cpp, PE_PanelItemViewRow).
    const QRect &rect = vopt->rect;
    const bool onlyOne = vopt->viewItemPosition == QStyleOptionViewItem::OnlyOne
            || vopt->viewItemPosition == QStyleOptionViewItem::Invalid;
    bool isFirst = onlyOne || vopt->viewItemPosition == QStyleOptionViewItem::Beginning;
    bool isLast = vopt->viewItemPosition == QStyleOptionViewItem::End;
    if (vopt->direction == Qt::RightToLeft) {
        isFirst = !isFirst;
        isLast = !isLast;
    }

    constexpr int r = windows11_item_radius_;
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->setPen(Qt::NoPen);
    painter->setBrush(vopt->palette.brush(viewItemColorGroup(vopt), QPalette::Highlight));
    painter->setClipRect(rect);
    if (isFirst) {
        painter->drawRoundedRect(rect.marginsRemoved(QMargins(2, 2, -r, 2)), r, r);
    } else if (isLast) {
        painter->drawRoundedRect(rect.marginsRemoved(QMargins(-r, 2, 2, 2)), r, r);
    } else {
        painter->drawRect(rect.marginsRemoved(QMargins(0, 2, 0, 2)));
    }
    painter->restore();
}
#endif // Q_OS_WIN

void ThemeStyler::drawComplexControl(ComplexControl control, const QStyleOptionComplex *option,
    QPainter *painter, const QWidget *widget) const
{
#ifdef Q_OS_MACOS
    // In a toolbar the macOS style draws a tool button's background only
    // for the checked (State_On) state, so hovering or pressing a toolbar
    // button gives no feedback, and it draws that background 4 px taller
    // than the button, so its bottom corners are cut off square.
    //
    // Fill the button with a translucent window text color first, as a
    // rect with all four corners rounded: lighter for a checked button,
    // stronger for a hovered and then a pressed one. Then let the base
    // style draw the label on top, with State_On cleared so it skips its
    // own checked background (drawControl() restores it for the label).
    //
    // The macOS style draws the menu arrow of a toolbar button only when
    // the button shows an icon, so text-only buttons with a menu, such as
    // display filter button groups, give no hint of it. Draw the arrow
    // for those, where the macOS style puts it for icon buttons.
    const QStyleOptionToolButton *tb = qstyleoption_cast<const QStyleOptionToolButton *>(option);
    if (control == CC_ToolButton && tb && painter && widget
            && qobject_cast<const QToolBar *>(widget->parentWidget())
            && baseStyleName() == QLatin1String("macos")) {
        const bool checked = tb->state & State_On;
        const bool active = (tb->state & State_Enabled)
                && (tb->state & (State_MouseOver | State_Sunken));
        if (checked || active) {
            // Corner radius of the macOS style's checked background
            // (QMacStyle CC_ToolButton, private in qmacstyle_mac.mm).
            constexpr qreal macToolButtonRadius = 4.0;
            const bool dark = ColorMath::isDark(tb->palette.color(QPalette::Window));
            QColor fill = tb->palette.color(QPalette::WindowText);
            if (checked) {
                // About the macOS style's own checked fill
                // (brushForToolButton() in qmacstyle_mac.mm), for the key
                // window or not.
                const bool key = widget->window()->isActiveWindow();
                fill.setAlphaF(dark ? (key ? 0.06f : 0.04f) : (key ? 0.11f : 0.08f));
            } else {
                const bool pressed = tb->state & State_Sunken;
                fill.setAlphaF(pressed ? (dark ? 0.20f : 0.16f) : (dark ? 0.10f : 0.08f));
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, true);
            painter->setPen(Qt::NoPen);
            painter->setBrush(fill);
            painter->drawRoundedRect(QRectF(tb->rect), macToolButtonRadius, macToolButtonRadius);
            painter->restore();
        }

        QStyleOptionToolButton buttonOpt = *tb;
        buttonOpt.state &= ~State_On;
        QProxyStyle::drawComplexControl(control, &buttonOpt, painter, widget);
        if (macToolButtonLacksMenuArrow(tb)) {
            QStyleOption arrowOpt = *tb;
            arrowOpt.rect = QRect(tb->rect.right() - (macToolButtonArrowSize + macToolButtonArrowMargin),
                                  tb->rect.bottom() - (macToolButtonArrowSize + macToolButtonArrowMargin),
                                  macToolButtonArrowSize, macToolButtonArrowSize);
            proxy()->drawPrimitive(PE_IndicatorArrowDown, &arrowOpt, painter, widget);
        }
        return;
    }
#endif
    QProxyStyle::drawComplexControl(control, option, painter, widget);
}

void ThemeStyler::polish(QWidget *widget)
{
    QProxyStyle::polish(widget);
#ifdef Q_OS_MACOS
    // Which toolbar row is the last one changes when any toolbar is
    // shown, hidden or moved, but the other toolbars keep their
    // geometry, so Qt does not repaint them. Watch the toolbars to
    // repaint their separator line. Installing the filter again on a
    // repolish does not add a second entry.
    if (qobject_cast<QToolBar *>(widget))
        widget->installEventFilter(this);
#endif
}

void ThemeStyler::unpolish(QWidget *widget)
{
#ifdef Q_OS_MACOS
    if (qobject_cast<QToolBar *>(widget))
        widget->removeEventFilter(this);
#endif
    QProxyStyle::unpolish(widget);
}

bool ThemeStyler::eventFilter(QObject *watched, QEvent *event)
{
#ifdef Q_OS_MACOS
    switch (event->type()) {
    case QEvent::Show:
    case QEvent::Hide:
    case QEvent::Move:
    case QEvent::Resize:
        if (const QToolBar *toolBar = qobject_cast<const QToolBar *>(watched)) {
            // A toolbar shown before the layout has placed it gets a
            // Move or Resize afterwards, which repaints again with the
            // final geometry.
            const QMainWindow *mainWindow = qobject_cast<const QMainWindow *>(toolBar->parentWidget());
            if (mainWindow && mainWindow->unifiedTitleAndToolBarOnMac()) {
                for (QToolBar *other : dockedTopToolBars(mainWindow)) {
                    if (other != toolBar)
                        other->update();
                }
            }
        }
        break;
    default:
        break;
    }
#endif
    return QProxyStyle::eventFilter(watched, event);
}

QString ThemeStyler::buttonStyleSheet(const QString &objectname, const QColor &baseColor)
{
    QString buttonStyle = QStringLiteral(
        "QPushButton#%1%2 { "
        "    background-color: %3; "
        "    color: %4; "
        "}");

    // The label is white in every state.  The fill is darkened until
    // white reads on it, so a pastel dark-mode accent still carries the
    // label; hover and pressed darken further, which only raises the
    // contrast.  contrastingText() is not used: on a fill just at the
    // readable ratio it would pick black, and the label would flip
    // between states.
    const QColor labelColor(Qt::white);
    const QColor fillColor = ColorMath::ensureContrast(baseColor, labelColor,
                                                       ColorMath::activeRatios().readableText);
    const QColor hoverColor = ColorMath::darken(fillColor, 12);
    const QColor pressedColor = ColorMath::darken(fillColor, 20);

    QString resultStyle = buttonStyle.arg(objectname, "", fillColor.name(), labelColor.name());
    resultStyle += buttonStyle.arg(objectname, ":hover", hoverColor.name(), labelColor.name());
    resultStyle += buttonStyle.arg(objectname, ":pressed", pressedColor.name(), labelColor.name());

    return resultStyle;
}
