/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RTPAUDIOSTREAM_H
#define RTPAUDIOSTREAM_H

#include "config.h"

#ifdef QT_MULTIMEDIA_LIB

#include <glib.h>

#include <epan/address.h>
#include <ui/rtp_stream.h>
#include <ui/qt/utils/rtp_audio_routing.h>
#include <ui/qt/utils/rtp_audio_file.h>
#include <ui/rtp_media.h>

#include <QAudio>
#include <QColor>
#include <QMap>
#include <QObject>
#include <QSet>
#include <QVector>
#include <QIODevice>
#include <QAudioOutput>

class QAudioFormat;
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
class QAudioSink;
#else
class QAudioOutput;
#endif
class QIODevice;


class RtpAudioStream : public QObject
{
    Q_OBJECT
public:
    enum TimingMode { JitterBuffer, RtpTimestamp, Uninterrupted };

    explicit RtpAudioStream(QObject *parent, rtpstream_id_t *id, bool stereo_required);
    ~RtpAudioStream();
    bool isMatch(const rtpstream_id_t *id) const;
    bool isMatch(const struct _packet_info *pinfo, const struct _rtp_info *rtp_info) const;
    void addRtpPacket(const struct _packet_info *pinfo, const struct _rtp_info *rtp_info);
    void clearPackets();
    void reset(double global_start_time);
    AudioRouting getAudioRouting();
    void setAudioRouting(AudioRouting audio_routing);
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    void decode(QAudioDevice out_device);
#else
    void decode(QAudioDeviceInfo out_device);
#endif

    double startRelTime() const { return start_rel_time_; }
    double stopRelTime() const { return stop_rel_time_; }
    unsigned sampleRate() const { return first_sample_rate_; }
    unsigned playRate() const { return audio_out_rate_; }
    void setRequestedPlayRate(unsigned new_rate) { audio_requested_out_rate_ = new_rate; }
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
    int outOfSequence() { return static_cast<int>(out_of_seq_timestamps_.size()); }
    /**
     * @brief Return a list of out-of-sequence samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> outOfSequenceSamples(int y_offset = 0);

    /**
     * @brief Return a list of jitter dropped timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> jitterDroppedTimestamps(bool relative = true);
    int jitterDropped() { return static_cast<int>(jitter_drop_timestamps_.size()); }
    /**
     * @brief Return a list of jitter dropped samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> jitterDroppedSamples(int y_offset = 0);

    /**
     * @brief Return a list of wrong timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> wrongTimestampTimestamps(bool relative = true);
    int wrongTimestamps() { return static_cast<int>(wrong_timestamp_timestamps_.size()); }
    /**
     * @brief Return a list of wrong timestamp samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> wrongTimestampSamples(int y_offset = 0);

    /**
     * @brief Return a list of inserted silence timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> insertedSilenceTimestamps(bool relative = true);
    int insertedSilences() { return static_cast<int>(silence_timestamps_.size()); }
    /**
     * @brief Return a list of wrong timestamp samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> insertedSilenceSamples(int y_offset = 0);

    quint32 nearestPacket(double timestamp, bool is_relative = true);

    QRgb color() { return color_; }
    void setColor(QRgb color) { color_ = color; }

    QAudio::State outputState() const;

    void setJitterBufferSize(int jitter_buffer_size) { jitter_buffer_size_ = jitter_buffer_size; }
    void setTimingMode(TimingMode timing_mode) { timing_mode_ = timing_mode; }
    void setStartPlayTime(double start_play_time) { start_play_time_ = start_play_time; }
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    bool prepareForPlay(QAudioDevice out_device);
#else
    bool prepareForPlay(QAudioDeviceInfo out_device);
#endif
    void startPlaying();
    void pausePlaying();
    void stopPlaying();
    void seekPlaying(qint64 samples);
    void setStereoRequired(bool stereo_required) { stereo_required_ = stereo_required; }
    qint16 getMaxSampleValue() { return max_sample_val_; }
    void setMaxSampleValue(gint16 max_sample_val) { max_sample_val_used_ = max_sample_val; }
    void seekSample(qint64 samples);
    qint64 readSample(SAMPLE *sample);
    qint64 getLeadSilenceSamples() { return prepend_samples_; }
    qint64 getTotalSamples() { return (audio_file_->getTotalSamples()); }
    qint64 getEndOfSilenceSample() { return (audio_file_->getEndOfSilenceSample()); }
    double getEndOfSilenceTime() { return (double)getEndOfSilenceSample() / (double)playRate(); }
    qint64 convertTimeToSamples(double time) { return (qint64)(time * playRate()); }
    bool savePayload(QIODevice *file);
    guint getHash() { return rtpstream_id_to_hash(&(id_)); }
    rtpstream_id_t *getID() { return &(id_); }
    QString getIDAsQString();
    rtpstream_info_t *getStreamInfo() { return &rtpstream_; }

signals:
    void processedSecs(double secs);
    void playbackError(const QString error_msg);
    void finishedPlaying(RtpAudioStream *stream, QAudio::Error error);

private:
    // Used to identify unique streams.
    // The GTK+ UI also uses the call number + current channel.
    rtpstream_id_t id_;
    rtpstream_info_t rtpstream_;
    bool first_packet_;

    QVector<struct _rtp_packet *>rtp_packets_;
    RtpAudioFile *audio_file_;      // Stores waveform samples in sparse file
    QIODevice *temp_file_;
    struct _GHashTable *decoders_hash_;
    double global_start_rel_time_;
    double start_abs_offset_;
    double start_rel_time_;
    double stop_rel_time_;
    qint64 prepend_samples_; // Count of silence samples at begin of the stream to align with other streams
    AudioRouting audio_routing_;
    bool stereo_required_;
    quint32 first_sample_rate_;
    quint32 audio_out_rate_;
    quint32 audio_requested_out_rate_;
    QSet<QString> payload_names_;
    struct SpeexResamplerState_ *audio_resampler_;
    struct SpeexResamplerState_ *visual_resampler_;
    QMap<double, quint32> packet_timestamps_;
    QVector<qint16> visual_samples_;
    QVector<double> out_of_seq_timestamps_;
    QVector<double> jitter_drop_timestamps_;
    QVector<double> wrong_timestamp_timestamps_;
    QVector<double> silence_timestamps_;
    qint16 max_sample_val_;
    qint16 max_sample_val_used_;
    QRgb color_;

    int jitter_buffer_size_;
    TimingMode timing_mode_;
    double start_play_time_;

    const QString formatDescription(const QAudioFormat & format);
    QString currentOutputDevice();

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    QAudioSink *audio_output_;
    void decodeAudio(QAudioDevice out_device);
    quint32 calculateAudioOutRate(QAudioDevice out_device, unsigned int sample_rate, unsigned int requested_out_rate);
#else
    QAudioOutput *audio_output_;
    void decodeAudio(QAudioDeviceInfo out_device);
    quint32 calculateAudioOutRate(QAudioDeviceInfo out_device, unsigned int sample_rate, unsigned int requested_out_rate);
#endif
    void decodeVisual();
    SAMPLE *resizeBufferIfNeeded(SAMPLE *buff, gint32 *buff_bytes, qint64 requested_size);

private slots:
    void outputStateChanged(QAudio::State new_state);
    void delayedStopStream();
};

#endif // QT_MULTIMEDIA_LIB

#endif // RTPAUDIOSTREAM_H
