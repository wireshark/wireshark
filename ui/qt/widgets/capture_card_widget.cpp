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
#include <ui/qt/widgets/capture_filter_combo.h>
#include <ui/qt/widgets/capture_filter_edit.h>

#include <QEvent>
#include <QFile>
#include <QLineEdit>
#include <QResizeEvent>

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

    // Internal wiring: interface frame ↔ filter combo
    connect(ui_->captureInterfaceFrame, &InterfaceFrame::itemSelectionChanged,
            ui_->captureFilterCombo, &CaptureFilterCombo::interfacesChanged);
    connect(ui_->captureInterfaceFrame, &InterfaceFrame::typeSelectionChanged,
            this, &CaptureCardWidget::interfaceListChanged);
    connect(ui_->captureInterfaceFrame, &InterfaceFrame::itemSelectionChanged,
            this, &CaptureCardWidget::interfaceSelected);

    // Internal wiring: filter combo → this
    connect(ui_->captureFilterCombo->lineEdit(), &QLineEdit::textEdited,
            this, &CaptureCardWidget::captureFilterTextEdited);
    connect(ui_->captureFilterCombo, &CaptureFilterCombo::captureFilterSyntaxChanged,
            this, &CaptureCardWidget::captureFilterSyntaxChanged);
    connect(ui_->captureFilterCombo, &CaptureFilterCombo::startCapture,
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
    return ui_->captureFilterCombo->currentText();
}

void CaptureCardWidget::setCaptureFilter(const QString &filter)
{
    ui_->captureFilterCombo->lineEdit()->setText(filter);
}

void CaptureCardWidget::setCaptureFilterText(const QString &filter)
{
    ui_->captureFilterCombo->lineEdit()->setText(filter);
    captureFilterTextEdited(filter);
}

void CaptureCardWidget::appInitialized()
{
#ifdef HAVE_LIBPCAP
    ui_->captureFilterCombo->lineEdit()->setText(global_capture_opts.default_options.cfilter);
#endif

    ui_->captureFilterCombo->setEnabled(true);

    interfaceListChanged();

    ui_->captureInterfaceFrame->ensureSelectedInterface();
}

void CaptureCardWidget::interfaceListChanged()
{
    QString btnText = tr("All interfaces shown");
    if (ui_->captureInterfaceFrame->interfacesHidden() > 0) {
        btnText = tr("%n interface(s) shown, %1 hidden", "",
                     ui_->captureInterfaceFrame->interfacesPresent())
                .arg(ui_->captureInterfaceFrame->interfacesHidden());
    }
    ui_->captureInterfaceTypeButton->setText(btnText);
    ui_->captureInterfaceTypeButton->setMenu(ui_->captureInterfaceFrame->getSelectionMenu());
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
    QPair<const QString, bool> sf_pair = CaptureFilterEdit::getSelectedFilter();
    const QString user_filter = sf_pair.first;
    bool conflict = sf_pair.second;

    if (conflict) {
        ui_->captureFilterCombo->lineEdit()->clear();
        ui_->captureFilterCombo->setConflict(true);
    } else {
        ui_->captureFilterCombo->lineEdit()->setText(user_filter);
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
}
