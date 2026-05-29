/* theme_debug_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/theme_debug_dialog.h>

#include <ui/qt/utils/theme_manager.h>
#include "main_application.h"

#include <QApplication>
#include <QCheckBox>
#include <QCursor>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFontInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMetaEnum>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScreen>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>
#include <QWindow>

namespace {

QString rectToString(const QRect &r)
{
    return QStringLiteral("(%1, %2)  %3 \u00d7 %4")
        .arg(r.x()).arg(r.y()).arg(r.width()).arg(r.height());
}

QString fontToString(const QFont &f)
{
    // Report the *resolved* font (QFontInfo) so substitutions are visible —
    // useful for spotting a monospace request that fell back to a
    // proportional family.
    const QFontInfo fi(f);
    QString s = fi.family();
    if (fi.family() != f.family())
        s += QStringLiteral(" (requested %1)").arg(f.family());
    if (fi.pointSizeF() > 0)
        s += QStringLiteral("  •  %1pt").arg(fi.pointSizeF(), 0, 'g', 4);
    else if (fi.pixelSize() > 0)
        s += QStringLiteral("  •  %1px").arg(fi.pixelSize());
    s += fi.fixedPitch() ? QStringLiteral("  •  fixed-pitch")
                         : QStringLiteral("  •  proportional");
    if (fi.bold())   s += QStringLiteral("  •  bold");
    if (fi.italic()) s += QStringLiteral("  •  italic");
    return s;
}

QString modeToString(ThemeManager::ThemeMode m)
{
    switch (m) {
    case ThemeManager::ThemeMode::System: return QStringLiteral("System");
    case ThemeManager::ThemeMode::Dark:   return QStringLiteral("Dark");
    case ThemeManager::ThemeMode::Light:  return QStringLiteral("Light");
    }
    return QStringLiteral("?");
}

QString parentChain(QWidget *w)
{
    QStringList parts;
    QWidget *cur = w;
    while (cur) {
        QString name = cur->objectName();
        if (name.isEmpty())
            name = QStringLiteral("(unnamed)");
        parts.prepend(QStringLiteral("%1[%2]")
                      .arg(QString::fromLatin1(cur->metaObject()->className()))
                      .arg(name));
        cur = cur->parentWidget();
    }
    return parts.join(QStringLiteral(" \u203a "));
}

} // namespace

ThemeDebugDialog::ThemeDebugDialog(QWidget *parent) :
    GeometryStateDialog(parent, Qt::Tool),
    main_window_(parent),
    theme_name_(nullptr),
    theme_internal_(nullptr),
    theme_version_(nullptr),
    theme_author_(nullptr),
    theme_description_(nullptr),
    theme_mode_(nullptr),
    theme_dark_(nullptr),
    mw_geometry_(nullptr),
    mw_frame_(nullptr),
    mw_screen_(nullptr),
    mw_dpi_(nullptr),
    mw_state_(nullptr),
    track_widgets_(nullptr),
    cursor_pos_(nullptr),
    widget_class_(nullptr),
    widget_name_(nullptr),
    widget_font_(nullptr),
    widget_geometry_(nullptr),
    widget_global_(nullptr),
    widget_parents_(nullptr),
    widget_stylesheet_(nullptr),
    widget_palette_(nullptr),
    token_table_(nullptr),
    poll_timer_(nullptr)
{
    setAttribute(Qt::WA_DeleteOnClose, true);
    setWindowTitle(mainApp->windowTitleString(tr("Theme Debug")));

    buildUi();

    if (parent) {
        int w = qMax(parent->width() * 2 / 3, 720);
        int h = qMax(parent->height() * 3 / 4, 600);
        loadGeometry(w, h);
    } else {
        loadGeometry(720, 600);
    }

    populateTokens();
    refresh();

    if (ThemeManager *tm = ThemeManager::instance()) {
        connect(tm, &ThemeManager::themeChanged,
                this, &ThemeDebugDialog::refresh);
    }

    poll_timer_ = new QTimer(this);
    poll_timer_->setInterval(100);
    connect(poll_timer_, &QTimer::timeout, this, [this]() {
        updateMainWindowSection();
        pollWidgetUnderCursor();
    });
    poll_timer_->start();

    // Application-wide filter for the Alt+Shift+click pin gesture only; it
    // reacts to that one combination and passes everything else through.
    // (The cursor tracking above stays poll-based, no per-event work.)
    qApp->installEventFilter(this);
}

ThemeDebugDialog::~ThemeDebugDialog()
{
}

void ThemeDebugDialog::buildUi()
{
    auto *root = new QVBoxLayout(this);

    auto *tabs = new QTabWidget(this);
    root->addWidget(tabs, /*stretch=*/1);

    // ---- Tab: Theme ------------------------------------------------------
    {
        auto *page = new QWidget(tabs);
        auto *layout = new QVBoxLayout(page);
        auto *form = new QFormLayout();

        theme_name_        = new QLabel(page);
        theme_internal_    = new QLabel(page);
        theme_version_     = new QLabel(page);
        theme_author_      = new QLabel(page);
        theme_description_ = new QLabel(page);
        theme_description_->setWordWrap(true);
        theme_mode_        = new QLabel(page);
        theme_dark_        = new QLabel(page);

        for (QLabel *l : {theme_name_, theme_internal_, theme_version_,
                          theme_author_, theme_description_, theme_mode_, theme_dark_}) {
            l->setTextInteractionFlags(Qt::TextSelectableByMouse);
        }

        form->addRow(tr("Name:"),        theme_name_);
        form->addRow(tr("Internal:"),    theme_internal_);
        form->addRow(tr("Version:"),     theme_version_);
        form->addRow(tr("Author:"),      theme_author_);
        form->addRow(tr("Description:"), theme_description_);
        form->addRow(tr("Mode:"),        theme_mode_);
        form->addRow(tr("Dark mode:"),   theme_dark_);
        layout->addLayout(form);
        layout->addStretch(1);

        tabs->addTab(page, tr("Theme"));
    }

    // ---- Tab: Main window (live) ----------------------------------------
    {
        auto *page = new QWidget(tabs);
        auto *layout = new QVBoxLayout(page);
        auto *form = new QFormLayout();

        mw_geometry_ = new QLabel(page);
        mw_frame_    = new QLabel(page);
        mw_screen_   = new QLabel(page);
        mw_dpi_      = new QLabel(page);
        mw_state_    = new QLabel(page);

        for (QLabel *l : {mw_geometry_, mw_frame_, mw_screen_, mw_dpi_, mw_state_}) {
            l->setTextInteractionFlags(Qt::TextSelectableByMouse);
        }

        form->addRow(tr("Geometry:"),       mw_geometry_);
        form->addRow(tr("Frame geometry:"), mw_frame_);
        form->addRow(tr("Screen:"),         mw_screen_);
        form->addRow(tr("DPI / DPR:"),      mw_dpi_);
        form->addRow(tr("Window state:"),   mw_state_);
        layout->addLayout(form);

        auto *hint = new QLabel(tr("These values refresh live while the dialog is open."), page);
        hint->setEnabled(false);
        hint->setWordWrap(true);
        layout->addWidget(hint);
        layout->addStretch(1);

        tabs->addTab(page, tr("Main Window"));
    }

    // ---- Tab: Widget inspector ------------------------------------------
    {
        auto *page = new QWidget(tabs);
        auto *layout = new QVBoxLayout(page);

        track_widgets_ = new QCheckBox(tr("Track widget under mouse"), page);
        track_widgets_->setChecked(true);
        layout->addWidget(track_widgets_);

        auto *note = new QLabel(
            tr("The inspector reports any widget in this application under the "
               "cursor — including child dialogs. Widgets that belong to this "
               "debug window are skipped so the last hovered target stays pinned. "
               "Hold Alt+Shift and click any widget to pin it: this turns off "
               "tracking and locks the readout onto that widget (re-check the box "
               "above to resume). Note: on macOS, tool windows are hidden "
               "whenever another application has focus, so tracking pauses until "
               "Wireshark is frontmost again."),
            page);
        note->setWordWrap(true);
        note->setEnabled(false);
        layout->addWidget(note);

        auto *form = new QFormLayout();
        cursor_pos_      = new QLabel(page);
        widget_class_    = new QLabel(page);
        widget_name_     = new QLabel(page);
        widget_font_     = new QLabel(page);
        widget_geometry_ = new QLabel(page);
        widget_global_   = new QLabel(page);
        widget_parents_  = new QLabel(page);
        widget_parents_->setWordWrap(true);
        for (QLabel *l : {cursor_pos_, widget_class_, widget_name_, widget_font_,
                          widget_geometry_, widget_global_, widget_parents_}) {
            l->setTextInteractionFlags(Qt::TextSelectableByMouse);
        }
        form->addRow(tr("Cursor (global):"), cursor_pos_);
        form->addRow(tr("Class:"),           widget_class_);
        form->addRow(tr("Object name:"),     widget_name_);
        form->addRow(tr("Font:"),            widget_font_);
        form->addRow(tr("Geometry:"),        widget_geometry_);
        form->addRow(tr("Global rect:"),     widget_global_);
        form->addRow(tr("Parent chain:"),    widget_parents_);
        layout->addLayout(form);

        // Effective palette of the hovered widget (Active group).  The
        // ThemeManager column shows color(Palette*) for the roles that map to
        // a token; an "(unset)" there means the theme map has no entry and the
        // widget falls back to the bare QPalette — exactly the case we are
        // chasing for the dark-mode header / byte-view contrast bugs.
        layout->addWidget(new QLabel(tr("Palette (Active group):"), page));
        widget_palette_ = new QTableWidget(page);
        widget_palette_->setColumnCount(4);
        widget_palette_->setHorizontalHeaderLabels(
            {tr("Role"), tr("Color"), tr("ThemeManager token"), tr("Swatch")});
        widget_palette_->verticalHeader()->setVisible(false);
        widget_palette_->horizontalHeader()->setStretchLastSection(true);
        widget_palette_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        widget_palette_->setSelectionMode(QAbstractItemView::NoSelection);
        layout->addWidget(widget_palette_, /*stretch=*/1);

        layout->addWidget(new QLabel(tr("Stylesheet:"), page));
        widget_stylesheet_ = new QPlainTextEdit(page);
        widget_stylesheet_->setReadOnly(true);
        widget_stylesheet_->setMaximumHeight(90);
        widget_stylesheet_->setPlaceholderText(tr("(no stylesheet)"));
        layout->addWidget(widget_stylesheet_);

        tabs->addTab(page, tr("Widget Inspector"));
    }

    // ---- Tab: Theme tokens ----------------------------------------------
    {
        auto *page = new QWidget(tabs);
        auto *layout = new QVBoxLayout(page);

        token_table_ = new QTableWidget(page);
        token_table_->setColumnCount(3);
        token_table_->setHorizontalHeaderLabels({tr("Token"), tr("Hex"), tr("Swatch")});
        token_table_->verticalHeader()->setVisible(false);
        token_table_->horizontalHeader()->setStretchLastSection(true);
        token_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        token_table_->setSelectionMode(QAbstractItemView::SingleSelection);
        token_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        layout->addWidget(token_table_, /*stretch=*/1);

        tabs->addTab(page, tr("Tokens"));
    }

    // ---- Buttons ---------------------------------------------------------
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    auto *refreshBtn = buttons->addButton(tr("Refresh"), QDialogButtonBox::ActionRole);
    connect(refreshBtn, &QPushButton::clicked, this, &ThemeDebugDialog::refresh);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
    root->addWidget(buttons);
}

void ThemeDebugDialog::refresh()
{
    updateThemeSection();
    updateMainWindowSection();
    populateTokens();
}

void ThemeDebugDialog::updateThemeSection()
{
    ThemeManager *tm = ThemeManager::instance();
    if (!tm)
        return;
    ThemeInfo info = tm->info();
    theme_name_->setText(info.name);
    theme_internal_->setText(info.internalName);
    theme_version_->setText(QString::number(info.version));
    theme_author_->setText(info.author);
    theme_description_->setText(info.description);
    theme_mode_->setText(modeToString(tm->mode()));
    theme_dark_->setText(tm->isDarkMode() ? tr("yes") : tr("no"));
}

void ThemeDebugDialog::updateMainWindowSection()
{
    QWidget *mw = main_window_;
    if (!mw)
        mw = parentWidget();
    if (!mw) {
        mw_geometry_->setText(tr("(no main window)"));
        return;
    }

    mw_geometry_->setText(rectToString(mw->geometry()));
    mw_frame_->setText(rectToString(mw->frameGeometry()));

    QString screenInfo = tr("(unknown)");
    QScreen *scr = nullptr;
    if (mw->windowHandle())
        scr = mw->windowHandle()->screen();
    if (!scr)
        scr = QGuiApplication::primaryScreen();
    if (scr) {
        screenInfo = QStringLiteral("%1 — %2")
            .arg(scr->name())
            .arg(rectToString(scr->geometry()));
    }
    mw_screen_->setText(screenInfo);

    qreal dpr = mw->devicePixelRatioF();
    qreal logical = scr ? scr->logicalDotsPerInch() : 0;
    qreal physical = scr ? scr->physicalDotsPerInch() : 0;
    mw_dpi_->setText(QStringLiteral("logical %1 / physical %2  •  DPR %3")
                     .arg(logical, 0, 'f', 1)
                     .arg(physical, 0, 'f', 1)
                     .arg(dpr, 0, 'f', 2));

    QStringList state;
    if (mw->isMaximized())  state << tr("maximized");
    if (mw->isMinimized())  state << tr("minimized");
    if (mw->isFullScreen()) state << tr("fullscreen");
    if (mw->isActiveWindow()) state << tr("active");
    if (state.isEmpty()) state << tr("normal");
    mw_state_->setText(state.join(QStringLiteral(", ")));
}

void ThemeDebugDialog::populateTokens()
{
    ThemeManager *tm = ThemeManager::instance();
    if (!tm)
        return;
    const QMetaEnum me = QMetaEnum::fromType<ThemeManager::ThemeToken>();
    token_table_->setRowCount(0);
    for (int i = 0; i < me.keyCount(); ++i) {
        const auto token = static_cast<ThemeManager::ThemeToken>(me.value(i));
        if (token == ThemeManager::NoRole)
            continue;
        QColor c = tm->color(token);
        const int row = token_table_->rowCount();
        token_table_->insertRow(row);

        auto *nameItem = new QTableWidgetItem(QString::fromLatin1(me.key(i)));
        token_table_->setItem(row, 0, nameItem);

        QString hex = c.isValid()
            ? c.name(QColor::HexArgb).toUpper()
            : tr("(unset)");
        auto *hexItem = new QTableWidgetItem(hex);
        hexItem->setFont(QFont(QStringLiteral("monospace")));
        token_table_->setItem(row, 1, hexItem);

        auto *swatch = new QTableWidgetItem();
        if (c.isValid())
            swatch->setBackground(c);
        token_table_->setItem(row, 2, swatch);
    }
    token_table_->resizeColumnToContents(0);
    token_table_->resizeColumnToContents(1);
}

void ThemeDebugDialog::populateWidgetPalette(QWidget *w)
{
    // Roles shown for the hovered widget, paired with the ThemeManager token
    // that maps to them (NoRole where ThemeManager has no equivalent).  The
    // 3D/Mid roles are included because native controls (QHeaderView,
    // QToolButton) draw their backgrounds and bevels from them.
    struct RoleEntry {
        QPalette::ColorRole      role;
        const char              *name;
        ThemeManager::ThemeToken token;
    };
    static const RoleEntry roles[] = {
        { QPalette::Window,          "Window",          ThemeManager::PaletteWindow     },
        { QPalette::WindowText,      "WindowText",      ThemeManager::PaletteWindowText },
        { QPalette::Base,            "Base",            ThemeManager::PaletteBase       },
        { QPalette::AlternateBase,   "AlternateBase",   ThemeManager::NoRole            },
        { QPalette::Text,            "Text",            ThemeManager::PaletteText       },
        { QPalette::Button,          "Button",          ThemeManager::NoRole            },
        { QPalette::ButtonText,      "ButtonText",      ThemeManager::NoRole            },
        { QPalette::BrightText,      "BrightText",      ThemeManager::NoRole            },
        { QPalette::Light,           "Light",           ThemeManager::NoRole            },
        { QPalette::Midlight,        "Midlight",        ThemeManager::NoRole            },
        { QPalette::Mid,             "Mid",             ThemeManager::PaletteMid        },
        { QPalette::Dark,            "Dark",            ThemeManager::NoRole            },
        { QPalette::Shadow,          "Shadow",          ThemeManager::NoRole            },
        { QPalette::Highlight,       "Highlight",       ThemeManager::NoRole            },
        { QPalette::HighlightedText, "HighlightedText", ThemeManager::NoRole            },
        { QPalette::PlaceholderText, "PlaceholderText", ThemeManager::NoRole            },
        { QPalette::ToolTipBase,     "ToolTipBase",     ThemeManager::NoRole            },
        { QPalette::ToolTipText,     "ToolTipText",     ThemeManager::NoRole            },
        { QPalette::Link,            "Link",            ThemeManager::NoRole            },
    };

    ThemeManager *tm = ThemeManager::instance();
    const QPalette pal = w->palette();
    const QFont mono(QStringLiteral("monospace"));

    widget_palette_->setRowCount(0);
    for (const RoleEntry &e : roles) {
        const QColor c = pal.color(QPalette::Active, e.role);
        const int row = widget_palette_->rowCount();
        widget_palette_->insertRow(row);

        widget_palette_->setItem(row, 0,
            new QTableWidgetItem(QString::fromLatin1(e.name)));

        auto *hexItem = new QTableWidgetItem(
            c.isValid() ? c.name(QColor::HexArgb).toUpper() : tr("(unset)"));
        hexItem->setFont(mono);
        widget_palette_->setItem(row, 1, hexItem);

        QString tmText;
        if (e.token != ThemeManager::NoRole && tm) {
            const QColor tc = tm->color(e.token);
            tmText = tc.isValid() ? tc.name(QColor::HexArgb).toUpper() : tr("(unset)");
        }
        auto *tmItem = new QTableWidgetItem(tmText);
        tmItem->setFont(mono);
        widget_palette_->setItem(row, 2, tmItem);

        auto *swatch = new QTableWidgetItem();
        if (c.isValid())
            swatch->setBackground(c);
        widget_palette_->setItem(row, 3, swatch);
    }
    widget_palette_->resizeColumnToContents(0);
    widget_palette_->resizeColumnToContents(1);
    widget_palette_->resizeColumnToContents(2);
}

void ThemeDebugDialog::pollWidgetUnderCursor()
{
    if (!track_widgets_->isChecked())
        return;

    const QPoint global = QCursor::pos();
    cursor_pos_->setText(QStringLiteral("(%1, %2)").arg(global.x()).arg(global.y()));

    QWidget *w = QApplication::widgetAt(global);

    // Skip widgets that belong to this dialog so the readout stays
    // pinned to whatever the user was last hovering in the main window.
    if (w) {
        QWidget *top = w;
        while (top->parentWidget())
            top = top->parentWidget();
        if (top == this)
            return;
    }

    if (w == tracked_.data())
        return;
    tracked_ = w;
    displayWidget(w);
}

void ThemeDebugDialog::displayWidget(QWidget *w)
{
    if (!w) {
        widget_class_->setText(tr("(none)"));
        widget_name_->clear();
        widget_font_->clear();
        widget_geometry_->clear();
        widget_global_->clear();
        widget_parents_->clear();
        widget_stylesheet_->clear();
        widget_palette_->setRowCount(0);
        return;
    }

    widget_class_->setText(QString::fromLatin1(w->metaObject()->className()));
    widget_name_->setText(w->objectName().isEmpty() ? tr("(unnamed)") : w->objectName());
    widget_font_->setText(fontToString(w->font()));
    widget_geometry_->setText(rectToString(w->geometry()));

    QPoint topLeft = w->mapToGlobal(QPoint(0, 0));
    widget_global_->setText(rectToString(QRect(topLeft, w->size())));
    widget_parents_->setText(parentChain(w));

    widget_stylesheet_->setPlainText(w->styleSheet());

    populateWidgetPalette(w);
}

bool ThemeDebugDialog::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress) {
        auto *me = static_cast<QMouseEvent *>(event);
        if (me->modifiers() == (Qt::AltModifier | Qt::ShiftModifier)) {
            const QPoint global = QCursor::pos();
            QWidget *w = QApplication::widgetAt(global);
            // Never pin our own dialog.
            QWidget *top = w;
            while (top && top->parentWidget())
                top = top->parentWidget();
            if (w && top != this) {
                track_widgets_->setChecked(false);  // freeze cursor tracking
                tracked_ = w;
                cursor_pos_->setText(QStringLiteral("(%1, %2)  [pinned]")
                                     .arg(global.x()).arg(global.y()));
                displayWidget(w);
                return true;  // consume so the click doesn't also hit the target
            }
        }
    }
    return GeometryStateDialog::eventFilter(watched, event);
}
