/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTP_AUDIO_SILENCE_GENERATOR_H
#define RTP_AUDIO_SILENCE_GENERATOR_H

#include "config.h"

#include <QIODevice>

/**
 * @brief A QIODevice that produces an infinite stream of silence (zero-valued PCM samples).
 */
class AudioSilenceGenerator : public QIODevice
{
public:
    /**
     * @brief Construct an AudioSilenceGenerator.
     * @param parent The parent QObject; may be nullptr.
     */
    explicit AudioSilenceGenerator(QObject *parent = nullptr);

    /** @brief Destroy the generator. No resources are released. */
    ~AudioSilenceGenerator() { }

    /**
     * @brief Return the logical size of the silence stream.
     * @return @c std::numeric_limits<qint64>::max() (or equivalent).
     */
    qint64 size() const override;

    /**
     * @brief Return the current read position within the silence stream.
     * @return The number of bytes that have been read since construction
     *         or the last @c seek().
     */
    qint64 pos() const override;

    /**
     * @brief Seek to an absolute byte offset within the silence stream.
     *
     * @param off The target byte offset. Must be non-negative.
     * @return true unconditionally; seeking always succeeds.
     */
    bool seek(qint64 off) override;

protected:
    /**
     * @brief Fill @p data with up to @p maxSize zero-valued (silent) bytes.
     *
     * @param data    Output buffer to fill with silence.
     * @param maxSize Number of bytes the caller has requested.
     * @return @p maxSize — the number of bytes written into @p data.
     */
    qint64 readData(char *data, qint64 maxSize) override;

    /**
     * @brief Not supported — this device is read-only.
     *
     * @param data    Ignored.
     * @param maxSize Ignored.
     * @return -1 unconditionally.
     */
    qint64 writeData(const char *data, qint64 maxSize) override;

private:
    quint64 pos_; /**< Running byte offset, advanced by readData() and updated by seek(). */
};

#endif // RTP_AUDIO_SILENCE_GENERATOR_H
