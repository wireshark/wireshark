/* capture_filter_entry.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <ui/qt/widgets/capture_filter_entry.h>

#include <ui/qt/models/capture_filter_validator.h>
#include <ui/qt/models/capture_filter_completer.h>
#include <ui/qt/models/capture_filter_history_model.h>
#include <ui/qt/models/capture_filter_bookmark_model.h>

#include <ui/qt/filter_dialog.h>
#include <ui/qt/main_application.h>
#include <ui/qt/utils/themes/themed_icon.h>

#include <ui/capture_globals.h>
#include <wsutil/utf8_entities.h>

#include <QConcatenateTablesProxyModel>
#include <QStringListModel>

CaptureFilterEntry::CaptureFilterEntry(QWidget *parent) :
    FilterExpressionEdit(parent)
{
    setAccessibleName(tr("Capture filter entry"));

    // Backends. setValidator/setCompleter/setBookmarkModel are widget-owned;
    // the history model is a thin view over the global recent store, parented
    // here for lifetime.
    setValidator(new CaptureFilterValidator(this));

    CaptureFilterCompleter *completer = new CaptureFilterCompleter(this);
    setCompleter(completer);

    setHistoryModel(new CaptureFilterHistoryModel(this));
    setBookmarkModel(new CaptureFilterBookmarkModel());

    // Merged typeahead source: recent history + saved bookmarks + the fixed
    // libpcap primitive list.
    completionModel()->addSourceModel(completer->primitivesModel());
    completer->setModel(completionModel());

    // Capture chrome and mode. Green bookmark (distinct from display's blue);
    // yellow when the filter is saved.
    setBookmarkIcon(ThemedIcon(":/svg_icons/x-capture-filter-bookmark.svg",
                               ThemeManager::FilterBookmarkCapture),
                    ThemedIcon(":/svg_icons/x-capture-filter-bookmark.svg",
                               ThemeManager::FilterBookmarkMatch));
    setBookmarkMenuLabels(tr("Saved Capture Filters"),
                          tr("Save this filter"),
                          tr("Remove this filter"),
                          tr("Manage Capture Filters"),
                          QString());
    setApplyActionVisible(false);       // implicit apply
    setPreferencesActionVisible(false); // capture has no filter-button prefs pane

    setConflict(false);

    // Generic base signals → capture vocabulary. An empty capture filter is
    // valid — it means "capture everything, discard nothing" — but the base
    // validityChanged only reports Valid/Deprecated as true. Fold the Empty
    // state in here, where the capture-specific meaning lives, so clearing the
    // box re-enables capture.
    connect(this, &FilterExpressionEdit::validityChanged, this, [this](bool valid) {
        emit captureFilterSyntaxChanged(valid || state() == FilterEdit::SyntaxState::Empty);
    });
    connect(this, &FilterExpressionEdit::textChangedExpr,
            this, &CaptureFilterEntry::captureFilterChanged);
    connect(this, &FilterExpressionEdit::applied, this, [this](const QString &) {
        emit startCapture();
    });

    // Bookmark menu behaviour.
    connect(this, &FilterExpressionEdit::saveBookmarkRequested, this, [this](const QString &expr) {
        emit addBookmark(expr);
        FilterDialog *dlg = new FilterDialog(window(), FilterDialog::CaptureFilter, expr);
        dlg->setWindowModality(Qt::ApplicationModal);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });
    connect(this, &FilterExpressionEdit::removeBookmarkRequested, this, [this](const QString &expr) {
        if (CaptureFilterBookmarkModel *bm = qobject_cast<CaptureFilterBookmarkModel *>(bookmarkModel()))
            bm->removeBookmark(expr);
    });
    connect(this, &FilterExpressionEdit::manageBookmarksRequested, this, [this]() {
        FilterDialog *dlg = new FilterDialog(window(), FilterDialog::CaptureFilter);
        dlg->setWindowModality(Qt::ApplicationModal);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    });

    // Keep the injected stores fresh when they change elsewhere.
    connect(mainApp, &MainApplication::captureFilterListChanged, this, [this]() {
        if (CaptureFilterBookmarkModel *bm = qobject_cast<CaptureFilterBookmarkModel *>(bookmarkModel()))
            bm->reload();
    });
    connect(mainApp, &MainApplication::preferencesChanged, this, [this]() {
        if (CaptureFilterHistoryModel *hm = qobject_cast<CaptureFilterHistoryModel *>(historyModel()))
            hm->reload();
    });
}

void CaptureFilterEntry::recheck()
{
    // Validity depends on the selected interfaces' DLTs, so re-run on selection
    // change.
    validateNow();
}

void CaptureFilterEntry::setConflict(bool conflict)
{
    if (conflict) {
        //: This is a very long concept that needs to fit into a short space.
        placeholder_text_ = tr("Multiple filters selected. Override them here or leave this blank to preserve them.");
        setToolTip(tr("<p>The interfaces you have selected have different capture filters."
                      " Typing a filter here will override them. Doing nothing will"
                      " preserve them.</p>"));
    } else {
        placeholder_text_ = tr("Enter a capture filter %1").arg(UTF8_HORIZONTAL_ELLIPSIS);
        setToolTip(QString());
    }
    setPlaceholderText(placeholder_text_);
}

QPair<const QString, bool> CaptureFilterEntry::getSelectedFilter()
{
    QString user_filter;
    bool filter_conflict = false;
#ifdef HAVE_LIBPCAP
    int selected_devices = 0;

    for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
        if (device->selected) {
            selected_devices++;
            if (selected_devices == 1) {
                user_filter = device->cfilter;
            } else {
                if (user_filter.compare(device->cfilter)) {
                    filter_conflict = true;
                }
            }
        }
    }
#endif // HAVE_LIBPCAP
    return QPair<const QString, bool>(user_filter, filter_conflict);
}
