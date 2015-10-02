/* rtp_audio_stream.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef RTPAUDIOSTREAM_H
#define RTPAUDIOSTREAM_H

#include "config.h"

#ifdef QT_MULTIMEDIA_LIB

#include <glib.h>

#include <epan/address.h>

#include <QAudio>
#include <QColor>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QVector>

class QAudioOutput;
class QTemporaryFile;

struct _rtp_stream_info;
struct _rtp_sample;

class RtpAudioStream : public QObject
{
    Q_OBJECT
public:
    explicit RtpAudioStream(QObject *parent, struct _rtp_stream_info *rtp_stream);
    ~RtpAudioStream();
    bool isMatch(const struct _rtp_stream_info *rtp_stream) const;
    bool isMatch(const struct _packet_info *pinfo, const struct _rtp_info *rtp_info) const;
    void addRtpStream(const struct _rtp_stream_info *rtp_stream);
    void addRtpPacket(const struct _packet_info *pinfo, const struct _rtp_info *rtp_info);
    void reset(double start_rel_time);

    double startRelTime() const { return start_rel_time_; }
    double stopRelTime() const { return stop_rel_time_; }
    unsigned sampleRate() const { return audio_out_rate_; }
    const QStringList payloadNames() const;

    /**
     * @brief Return a list of visual timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> visualTimestamps(bool relative = true);
    /**
     * @brief Return a list of visual samples. There will be fewer visual samples
     * per second (1000) than the actual audio.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> visualSamples(int y_offset = 0);

    /**
     * @brief Return a list of out-of-sequence timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> outOfSequenceTimestamps(bool relative = true);
    int outOfSequence() { return out_of_seq_timestamps_.size(); }
    /**
     * @brief Return a list of out-of-sequence samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> outOfSequenceSamples(int y_offset = 0);

    quint32 nearestPacket(double timestamp, bool is_relative = true);

    QRgb color() { return color_; }
    void setColor(QRgb color) { color_ = color; }

    QAudio::State outputState() const;

signals:
    void startedPlaying();
    void processedSecs(double secs);
    void finishedPlaying();

public slots:
    void startPlaying();
    void stopPlaying();

private:
    address src_addr_;
    quint16 src_port_;
    address dst_addr_;
    quint16 dst_port_;
    quint32 ssrc_;
    int last_sequence_;
    QTemporaryFile *tempfile_;
    struct _GHashTable *decoders_hash_;
    QList<const struct _rtp_stream_info *>rtp_streams_;
    double global_start_rel_time_;
    double start_abs_offset_;
    double start_rel_time_;
    double stop_rel_time_;
    quint32 audio_out_rate_;
    QSet<QString> payload_names_;
    struct SpeexResamplerState_ *audio_resampler_;
    struct SpeexResamplerState_ *visual_resampler_;
    QAudioOutput *audio_output_;
    QMap<double, quint32> packet_timestamps_;
    QVector<qint16> visual_samples_;
    QVector<double> out_of_seq_timestamps_;
    qint16 max_sample_val_;
    QRgb color_;

private slots:
    void outputStateChanged();
    void outputNotify();

};

#endif // QT_MULTIMEDIA_LIB

#endif // RTPAUDIOSTREAM_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
