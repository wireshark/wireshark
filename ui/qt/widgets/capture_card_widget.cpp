/* capture_card_widget.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/widgets/capture_card_widget.h>
#include <ui_capture_card_widget.h>

#include <ui/capture_globals.h>

#include <ui/qt/interface_frame.h>
#include <ui/qt/main_application.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/capture_filter_entry.h>

#include <QEvent>
#include <QFile>
#include <QFontMetrics>
#include <QLineEdit>
#include <QPushButton>
#include <QResizeEvent>
#include <QStyle>
#include <QStyleOption>

CaptureCardWidget::CaptureCardWidget(QWidget *parent) :
    QFrame(parent),
    ui_(new Ui::CaptureCardWidget)
{
    ui_->setupUi(this);

    setStyleSheet(ThemeManager::styleSheet(QStringLiteral("widgets/capture-card")));

    // Reload the stylesheet whenever the theme (or its light/dark
    // selection) changes.  QEvent::ApplicationPaletteChange alone isn't
    // reliable — a mode flip on a theme with no palette overrides may
    // not produce a palette delta large enough for Qt to propagate.
    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, [this]() {
        setStyleSheet(ThemeManager::styleSheet(QStringLiteral("widgets/capture-card")));
    });

    // Internal wiring: interface frame ↔ filter entry
    connect(ui_->captureInterfaceFrame, &InterfaceFrame::itemSelectionChanged,
            ui_->captureFilterEntry, &CaptureFilterEntry::recheck);
    connect(ui_->captureInterfaceFrame, &InterfaceFrame::typeSelectionChanged,
            this, &CaptureCardWidget::interfaceListChanged);
    connect(ui_->captureInterfaceFrame, &InterfaceFrame::itemSelectionChanged,
            this, &CaptureCardWidget::interfaceSelected);

    // Internal wiring: filter entry → this
    connect(ui_->captureFilterEntry, &QLineEdit::textEdited,
            this, &CaptureCardWidget::captureFilterTextEdited);
    // The clear button empties the field via QLineEdit::clear(), which does not
    // emit textEdited, so propagate the cleared filter to the selected devices
    // explicitly — otherwise the previous filter stays on the interface.
    connect(ui_->captureFilterEntry, &FilterExpressionEdit::cleared, this, [this]() {
        captureFilterTextEdited(QString());
    });
    connect(ui_->captureFilterEntry, &CaptureFilterEntry::captureFilterSyntaxChanged,
            this, &CaptureCardWidget::captureFilterSyntaxChanged);
    connect(ui_->captureFilterEntry, &CaptureFilterEntry::startCapture,
            this, &CaptureCardWidget::captureStarting);

    // Signal relay: interface frame → this (forwarded to WelcomePage)
    connect(ui_->captureInterfaceFrame, &InterfaceFrame::showExtcapOptions,
            this, &CaptureCardWidget::showExtcapOptions);
    connect(ui_->captureInterfaceFrame, &InterfaceFrame::startCapture,
            this, &CaptureCardWidget::startCapture);

    // App-level connections
    connect(mainApp, &MainApplication::appInitialized,
            this, &CaptureCardWidget::appInitialized);
    connect(mainApp, &MainApplication::localInterfaceListChanged,
            this, &CaptureCardWidget::interfaceListChanged);
#ifdef HAVE_LIBPCAP
    connect(mainApp, &MainApplication::scanLocalInterfaces,
            ui_->captureInterfaceFrame, &InterfaceFrame::scanLocalInterfaces);
#endif
}

CaptureCardWidget::~CaptureCardWidget()
{
    delete ui_;
}

InterfaceFrame *CaptureCardWidget::interfaceFrame()
{
    return ui_->captureInterfaceFrame;
}

const QString CaptureCardWidget::captureFilter()
{
    return ui_->captureFilterEntry->text();
}

void CaptureCardWidget::setCaptureFilter(const QString &filter)
{
    ui_->captureFilterEntry->setText(filter);
}

void CaptureCardWidget::setCaptureFilterText(const QString &filter)
{
    ui_->captureFilterEntry->setText(filter);
    captureFilterTextEdited(filter);
}

void CaptureCardWidget::appInitialized()
{
#ifdef HAVE_LIBPCAP
    ui_->captureFilterEntry->setText(global_capture_opts.default_options.cfilter);
#endif

    ui_->captureFilterEntry->setEnabled(true);

    interfaceListChanged();

    ui_->captureInterfaceFrame->ensureSelectedInterface();
}

void CaptureCardWidget::interfaceListChanged()
{
    int shown = ui_->captureInterfaceFrame->interfacesPresent();
    int hidden = ui_->captureInterfaceFrame->interfacesHidden();

    // Label variants, most verbose first. updateInterfaceTypeButton() picks
    // the longest one that fits the available width, so the button stays
    // informative when there's room and compact when there isn't.
    interfaceTypeButtonTexts_.clear();
    if (hidden > 0) {
        int total = shown + hidden;
        interfaceTypeButtonTexts_
            << tr("%n interface(s) shown, %1 hidden", "", shown).arg(hidden)
            << tr("%1 / %2 interfaces").arg(shown).arg(total)
            << tr("%1 / %2").arg(shown).arg(total);
    } else {
        interfaceTypeButtonTexts_
            << tr("All interfaces shown")
            << tr("%n interface(s)", "", shown);
    }

    ui_->captureInterfaceTypeButton->setMenu(ui_->captureInterfaceFrame->getSelectionMenu());

    updateInterfaceTypeButton();
}

// Full rendered width (text + frame + padding + menu-indicator arrow) the
// button would need for a given label. Uses the same style call Qt uses to
// size the button, so the fit test below matches the real layout exactly.
static int buttonWidthForText(QPushButton *btn, const QString &text)
{
    QStyleOptionButton opt;
    opt.initFrom(btn);
    opt.text = text;
    QSize contents(btn->fontMetrics().horizontalAdvance(text),
                   btn->fontMetrics().height());
    int w = btn->style()->sizeFromContents(QStyle::CT_PushButton, &opt, contents, btn).width();
    // QMacStyle (and some others) don't reserve space for the menu-indicator
    // arrow in CT_PushButton, so add it explicitly: otherwise the arrow paints
    // over the label and the variant never collapses early enough.
    if (btn->menu())
        w += btn->style()->pixelMetric(QStyle::PM_MenuButtonIndicator, &opt, btn);
    return w;
}

// Keep the interface-type button from crowding out the capture filter combo
// on narrow windows. The button (a QPushButton) won't shrink below its own
// label, so we pick the most verbose label variant that still leaves the
// combo a comfortable width, and pin the button to exactly that width. The
// full text stays as the tooltip.
void CaptureCardWidget::updateInterfaceTypeButton()
{
    if (interfaceTypeButtonTexts_.isEmpty())
        return;

    QPushButton *btn = ui_->captureInterfaceTypeButton;
    btn->setToolTip(interfaceTypeButtonTexts_.constFirst());

    // Width the button may use = the card width (authoritative and current in
    // resizeEvent, unlike the not-yet-relaid-out child row) minus the label
    // and a comfortable reserve for the capture filter combo. The label's
    // footprint is subtracted unconditionally (even while it's hidden below
    // 460px) so the chosen variant changes monotonically with width instead of
    // jumping when the label shows/hides.
    int spacing = ui_->captureFilterRow->layout()->spacing();
    int labelW = ui_->captureFilterLabel->sizeHint().width() + spacing;
    const int comboReserveW = 290; // keep the capture filter combo prominent
    int avail = width() - labelW - comboReserveW - spacing;

    // Most verbose variant that fits; the tersest one is the fallback. Pin the
    // button to the chosen variant's width so it neither clips (it's never
    // smaller than its label) nor lets the combo starve it (it grows back when
    // there's room again).
    QString chosen = interfaceTypeButtonTexts_.constLast();
    int chosenW = buttonWidthForText(btn, chosen);
    for (const QString &candidate : interfaceTypeButtonTexts_) {
        int candidateW = buttonWidthForText(btn, candidate);
        if (candidateW <= avail) {
            chosen = candidate;
            chosenW = candidateW;
            break;
        }
    }

    btn->setText(chosen);
    btn->setFixedWidth(chosenW);
}

// Update each selected device cfilter when the user changes the contents
// of the capture filter lineedit. We do so here so that we don't clobber
// filters set in the Capture Options / Interfaces dialog or ones set via
// the command line.
void CaptureCardWidget::captureFilterTextEdited(const QString &filter)
{
#ifdef HAVE_LIBPCAP
    if (global_capture_opts.num_selected > 0) {
        interface_t *device;

        for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (!device->selected) {
                continue;
            }
            g_free(device->cfilter);
            if (filter.isEmpty()) {
                device->cfilter = NULL;
            } else {
                device->cfilter = qstring_strdup(filter);
            }
        }
    }
#else
    Q_UNUSED(filter);
#endif
}

// The interface list selection has changed. At this point the user might
// have entered a filter or we might have pre-filled one from a number of
// sources such as our remote connection, the command line, or a previous
// selection.
// Must not change any interface data.
void CaptureCardWidget::interfaceSelected()
{
    QPair<const QString, bool> sf_pair = CaptureFilterEntry::getSelectedFilter();
    const QString user_filter = sf_pair.first;
    bool conflict = sf_pair.second;

    if (conflict) {
        ui_->captureFilterEntry->clear();
        ui_->captureFilterEntry->setConflict(true);
    } else {
        ui_->captureFilterEntry->setText(user_filter);
    }

    // Notify others (capture options dialog) that the selection has changed.
    emit interfacesChanged();
}

void CaptureCardWidget::captureStarting()
{
    ui_->captureInterfaceFrame->ensureSelectedInterface();
    emit startCapture(QStringList());
}

/*
 * Adapts the filter row visibility based on available width.
 *
 * Three responsive modes:
 *   1. Normal (width >= 400px): All elements visible
 *   2. Compact (width 250-399px): Filter label hidden, combo gets more room
 *   3. Minimal (width < 250px): Entire filter row hidden, capture via
 *      interface double-click only
 */
void CaptureCardWidget::updateFilterRowVisibility()
{
    int w = width();
    ui_->captureFilterLabel->setVisible(w >= 460);
    ui_->captureFilterRow->setVisible(w >= 250);
}

bool CaptureCardWidget::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        setStyleSheet(ThemeManager::styleSheet(QStringLiteral("widgets/capture-card")));
        break;
    case QEvent::LanguageChange:
        ui_->retranslateUi(this);
        interfaceListChanged();
        break;
    default:
        break;
    }
    return QFrame::event(event);
}

void CaptureCardWidget::resizeEvent(QResizeEvent *event)
{
    QFrame::resizeEvent(event);

    updateFilterRowVisibility();
    updateInterfaceTypeButton();
}
