/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FRAME_INFORMATION_H_
#define FRAME_INFORMATION_H_

#include <config.h>

#include <epan/proto.h>
#include <epan/epan_dissect.h>
#include "epan/epan.h"
#include "epan/column.h"
#include "epan/ftypes/ftypes.h"

#include <ui/qt/capture_file.h>

#include "data_printer.h"

#include <QObject>

/**
 * @brief Provides printable data and dissection information for a single frame.
 */
class FrameInformation : public QObject, public IDataPrintable
{
    Q_OBJECT
    Q_INTERFACES(IDataPrintable)

public:

    /**
     * @brief Constructs a new FrameInformation object.
     * @param cfile Pointer to the capture file containing the frame.
     * @param fi Pointer to the frame data structure.
     * @param parent The parent QObject, defaults to Q_NULLPTR.
     */
    explicit FrameInformation(CaptureFile * cfile, frame_data * fi, QObject * parent = Q_NULLPTR);

    /**
     * @brief Destroys the FrameInformation object.
     */
    virtual ~FrameInformation();

    /**
     * @brief Checks if the frame information is valid and fully loaded.
     * @return True if valid, false otherwise.
     */
    bool isValid();

    /**
     * @brief Retrieves the underlying frame data structure.
     * @return Pointer to the frame_data.
     */
    frame_data * frameData() const;

    /**
     * @brief Retrieves the packet or frame number.
     * @return The frame number.
     */
    int frameNum() const;

    /**
     * @brief Generates the printable data representation of the frame.
     * @return A QByteArray containing the printable frame data.
     */
    const QByteArray printableData();

private:

    /** Pointer to the core frame data structure. */
    frame_data * fi_;

    /** Pointer to the associated capture file. */
    CaptureFile * cap_file_;

    /** Pointer to the epan dissection context. */
    epan_dissect_t * edt_;

    /** Record information. */
    wtap_rec rec_;

    /**
     * @brief Loads the protocol dissection tree for the frame.
     */
    void loadFrameTree();

};


#endif // FRAME_INFORMATION_H_
