/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_AUDIO_ROUTING_FILTER_H
#define RTP_AUDIO_ROUTING_FILTER_H

#include "config.h"

#include <ui/rtp_media.h>
#include <ui/qt/utils/rtp_audio_routing.h>

#include <QObject>
#include <QIODevice>

/**
 * @brief A QIODevice filter that applies audio routing to a raw PCM stream.
 */
class AudioRoutingFilter : public QIODevice
{
public:
    /**
     * @brief Construct an AudioRoutingFilter.
     * @param input           The upstream PCM device to read raw audio from.
     *                        Must outlive this filter. The filter does not
     *                        take ownership of the pointer.
     * @param stereo_required true if the downstream audio output expects
     *                        interleaved stereo (two-channel) PCM;
     *                        false if it expects mono (single-channel) PCM.
     *                        This controls how the routing transformation
     *                        maps input samples to output samples.
     * @param audio_routing   The initial mute state and channel assignment
     *                        to apply to the stream.
     */
    explicit AudioRoutingFilter(QIODevice *input, bool stereo_required,
                                AudioRouting audio_routing);

    /** @brief Destroy the filter. The upstream device is not closed or deleted. */
    ~AudioRoutingFilter() { }

    /**
     * @brief Close this filter device.
     */
    void close() override;

    /**
     * @brief Return the total byte size of the audio stream.
     * @return The number of bytes available in the upstream device, or -1
     *         if the size is not known.
     */
    qint64 size() const override;

    /**
     * @brief Return the current read position within the stream.
     * @return The current byte offset from the start of the stream.
     */
    qint64 pos() const override;

    /**
     * @brief Seek to an absolute byte offset in the stream.
     * @param off The target byte offset from the start of the stream.
     * @return true if the upstream device accepted the seek; false otherwise.
     */
    bool seek(qint64 off) override;

protected:
    /**
     * @brief Read and route up to @p maxSize bytes from the upstream device.
     *
     * @param data    Output buffer to write transformed PCM into.
     * @param maxSize Maximum number of bytes to write into @p data.
     * @return The number of bytes written, or -1 on error.
     */
    qint64 readData(char *data, qint64 maxSize) override;

    /**
     * @brief Not supported — this filter is read-only.
     *
     * @param data    Ignored.
     * @param maxSize Ignored.
     * @return -1 unconditionally.
     */
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    QIODevice *input_;          /**< Upstream PCM source; not owned by this filter. */
    bool stereo_required_;      /**< true if the downstream output expects stereo interleaved PCM. */
    AudioRouting audio_routing_; /**< Current mute state and channel routing applied in readData(). */
};

#endif // RTP_AUDIO_ROUTING_FILTER_H
