/* profile_switcher.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// #include <capture_file.h>
#include <main_application.h>

#include <ui/profile.h>
#include <ui/recent.h>

#include <ui/qt/capture_file.h>
#include <ui/qt/models/packet_list_model.h>

#include "profile_switcher.h"

#include "file.h"

#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/prefs.h>
#include "frame_tvbuff.h"

// Enable switching iff:
// - We're opening a new capture file via the UI.
// - We haven't changed our profile, either manually or automatically.

ProfileSwitcher::ProfileSwitcher(QObject *parent) :
    QObject(parent),
    capture_file_changed_(true),
    profile_changed_(false)
{
    if (g_list_length(current_profile_list()) == 0) {
        init_profile_list();
    }
    connect(mainApp, &MainApplication::profileChanging, this, &ProfileSwitcher::disableSwitching);
}

void ProfileSwitcher::captureEventHandler(CaptureEvent ev)
{
    if (ev.captureContext() != CaptureEvent::File) {
        return;
    }

    CaptureFile *capture_file = qobject_cast<CaptureFile *>(sender());
    if (!capture_file) {
        return;
    }

    // CaptureEvent doesn't have a "this is the same file" flag, so
    // track that via the filename.
    switch (ev.eventType()) {
    case CaptureEvent::Opened:
        if (previous_cap_file_ != capture_file->filePath()) {
            capture_file_changed_ = true;
            profile_changed_ = false;
        }
        break;
    case CaptureEvent::Closing:
        previous_cap_file_ = capture_file->filePath();
        break;
    default:
        break;
    }
}

void ProfileSwitcher::checkPacket(capture_file *cap_file, frame_data *fdata, qsizetype row)
{
    if (profile_changed_ || !capture_file_changed_ || row >= recent.gui_profile_switch_check_count) {
        return;
    }

    if (row == 0) {
        clearProfileFilters();
        for (GList *cur = current_profile_list() ; cur; cur = cur->next) {
            profile_def *profile = static_cast<profile_def *>(cur->data);
            if (!profile->auto_switch_filter) {
                continue;
            }
            dfilter_t *dfcode;
            if (dfilter_compile(profile->auto_switch_filter, &dfcode, NULL) && dfcode) {
                profile_filters_.append({profile->name, dfcode});
            }
        }
    }

    if (profile_filters_.empty()) {
        return;
    }

    QString new_profile;
    wtap_rec rec;
    Buffer buf;
    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);
    epan_dissect_t edt;

    for (auto &cur_filter : profile_filters_) {
        if (!cf_read_record(cap_file, fdata, &rec, &buf)) {
            continue;
        }
        epan_dissect_init(&edt, cap_file->epan, TRUE, FALSE);
        epan_dissect_prime_with_dfilter(&edt, cur_filter.dfcode);
        epan_dissect_run(&edt, cap_file->cd_t, &rec,
                         frame_tvbuff_new_buffer(&cap_file->provider, fdata, &buf),
                         fdata, NULL);
        bool matched = dfilter_apply_edt(cur_filter.dfcode, &edt);
        epan_dissect_cleanup(&edt);
        if (matched) {
            new_profile = cur_filter.name;
            break;
        }
    }

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    if (!new_profile.isEmpty()) {
        clearProfileFilters();
        previous_cap_file_ = cap_file->filename;
        mainApp->setConfigurationProfile(qUtf8Printable(new_profile), false);
    }
}

void ProfileSwitcher::clearProfileFilters()
{
    for (auto &cur_filter : profile_filters_) {
        dfilter_free(cur_filter.dfcode);
    }
    profile_filters_.clear();
}

void ProfileSwitcher::disableSwitching()
{
    profile_changed_ = true;
}
