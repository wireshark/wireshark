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
#include <QColor>
#include <QIODevice>
#include <QAudioOutput>

class QAudioFormat;
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
class QAudioSink;
#else
class QAudioOutput;
#endif
class QIODevice;


/**
 * @brief Manages a single RTP audio stream for decoding, playback, and visualization.
 */
class RtpAudioStream : public QObject
{
    Q_OBJECT
public:
    /**
     * @brief Defines the timing mode for RTP playback.
     */
    enum TimingMode {
        JitterBuffer,  /**< Playback uses a jitter buffer. */
        RtpTimestamp,  /**< Playback is based on RTP timestamps. */
        Uninterrupted  /**< Playback is uninterrupted. */
    };

    /**
     * @brief Constructs an RtpAudioStream.
     * @param parent The parent object.
     * @param id The RTP stream identifier.
     * @param stereo_required Indicates if stereo playback is required.
     */
    explicit RtpAudioStream(QObject *parent, rtpstream_id_t *id, bool stereo_required);

    /**
     * @brief Destroys the RtpAudioStream.
     */
    ~RtpAudioStream();

    /**
     * @brief Checks if the given stream ID matches this stream.
     * @param id The stream identifier to check.
     * @return True if the ID matches, false otherwise.
     */
    bool isMatch(const rtpstream_id_t *id) const;

    /**
     * @brief Checks if the given packet and RTP info match this stream.
     * @param pinfo Pointer to the packet info.
     * @param rtp_info Pointer to the RTP info.
     * @return True if it matches, false otherwise.
     */
    bool isMatch(const struct _packet_info *pinfo, const struct _rtp_info *rtp_info) const;

    /**
     * @brief Adds an RTP packet to the stream.
     * @param pinfo Pointer to the packet info.
     * @param rtp_info Pointer to the RTP info.
     */
    void addRtpPacket(const struct _packet_info *pinfo, const struct _rtp_info *rtp_info);

    /**
     * @brief Clears all stored packets from the stream.
     */
    void clearPackets();

    /**
     * @brief Resets the stream with a new global start time.
     * @param global_start_time The new global start time.
     */
    void reset(double global_start_time);

    /**
     * @brief Retrieves the current audio routing configuration.
     * @return The active AudioRouting setting.
     */
    AudioRouting getAudioRouting();

    /**
     * @brief Sets the audio routing configuration.
     * @param audio_routing The new audio routing setting.
     */
    void setAudioRouting(AudioRouting audio_routing);

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    /**
     * @brief Decodes the audio stream using the specified output device.
     * @param out_device The audio output device.
     */
    void decode(QAudioDevice out_device);
#else
    /**
     * @brief Decodes the audio stream using the specified output device info.
     * @param out_device The audio output device info.
     */
    void decode(QAudioDeviceInfo out_device);
#endif

    /**
     * @brief Decodes the stream data for visualization.
     */
    void decodeVisual();

    /**
     * @brief Gets the start relative time of the stream.
     * @return The start relative time in seconds.
     */
    double startRelTime() const { return start_rel_time_; }

    /**
     * @brief Gets the stop relative time of the stream.
     * @return The stop relative time in seconds.
     */
    double stopRelTime() const { return stop_rel_time_; }

    /**
     * @brief Gets the initial sample rate.
     * @return The first sample rate.
     */
    unsigned sampleRate() const { return first_sample_rate_; }

    /**
     * @brief Gets the audio playback rate.
     * @return The audio output rate.
     */
    unsigned playRate() const { return audio_out_rate_; }

    /**
     * @brief Sets the requested playback rate.
     * @param new_rate The newly requested audio output rate.
     */
    void setRequestedPlayRate(unsigned new_rate) { audio_requested_out_rate_ = new_rate; }

    /**
     * @brief Sets the visual sample rate.
     * @param new_rate The new visual sample rate.
     */
    void setVisualSampleRate(unsigned new_rate) { visual_sample_rate_ = new_rate; }

    /**
     * @brief Gets a list of payload names present in the stream.
     * @return A list of payload name strings.
     */
    const QStringList payloadNames() const;

    /**
     * @brief Return a list of visual timestamps.
     * @param relative Indicates whether to use relative timestamps.
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
     * @param relative Indicates whether to use relative timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> outOfSequenceTimestamps(bool relative = true);

    /**
     * @brief Gets the total count of out-of-sequence packets.
     * @return The count of out-of-sequence packets.
     */
    int outOfSequence() { return static_cast<int>(out_of_seq_timestamps_.size()); }

    /**
     * @brief Return a list of out-of-sequence samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> outOfSequenceSamples(int y_offset = 0);

    /**
     * @brief Return a list of jitter dropped timestamps.
     * @param relative Indicates whether to use relative timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> jitterDroppedTimestamps(bool relative = true);

    /**
     * @brief Gets the total count of packets dropped due to jitter.
     * @return The count of jitter dropped packets.
     */
    int jitterDropped() { return static_cast<int>(jitter_drop_timestamps_.size()); }

    /**
     * @brief Return a list of jitter dropped samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> jitterDroppedSamples(int y_offset = 0);

    /**
     * @brief Return a list of wrong timestamps.
     * @param relative Indicates whether to use relative timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> wrongTimestampTimestamps(bool relative = true);

    /**
     * @brief Gets the total count of wrong timestamps.
     * @return The count of wrong timestamps.
     */
    int wrongTimestamps() { return static_cast<int>(wrong_timestamp_timestamps_.size()); }

    /**
     * @brief Return a list of wrong timestamp samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> wrongTimestampSamples(int y_offset = 0);

    /**
     * @brief Return a list of inserted silence timestamps.
     * @param relative Indicates whether to use relative timestamps.
     * @return A set of timestamps suitable for passing to QCPGraph::setData.
     */
    const QVector<double> insertedSilenceTimestamps(bool relative = true);

    /**
     * @brief Gets the total count of inserted silences.
     * @return The count of inserted silence events.
     */
    int insertedSilences() { return static_cast<int>(silence_timestamps_.size()); }

    /**
     * @brief Return a list of inserted silence samples. Y value is constant.
     * @param y_offset Y axis offset to be used for stacking graphs.
     * @return A set of values suitable for passing to QCPGraph::setData.
     */
    const QVector<double> insertedSilenceSamples(int y_offset = 0);

    /**
     * @brief Finds the frame number of the packet nearest to the given timestamp.
     * @param timestamp The target timestamp.
     * @param is_relative Indicates whether the timestamp is relative.
     * @return The frame number of the nearest packet.
     */
    quint32 nearestPacket(double timestamp, bool is_relative = true);

    /**
     * @brief Gets the color associated with this stream.
     * @return The assigned color.
     */
    QColor color() { return color_; }

    /**
     * @brief Sets the color for this stream.
     * @param color The new color to assign.
     */
    void setColor(QColor color) { color_ = color; }

    /**
     * @brief Retrieves the current state of the audio output.
     * @return The QAudio::State of the audio output.
     */
    QAudio::State outputState() const;

    /**
     * @brief Sets the jitter buffer size.
     * @param jitter_buffer_size The jitter buffer size in milliseconds.
     */
    void setJitterBufferSize(int jitter_buffer_size) { jitter_buffer_size_ = jitter_buffer_size; }

    /**
     * @brief Sets the timing mode for the stream.
     * @param timing_mode The selected TimingMode.
     */
    void setTimingMode(TimingMode timing_mode) { timing_mode_ = timing_mode; }

    /**
     * @brief Sets the start play time.
     * @param start_play_time The start time for playback.
     */
    void setStartPlayTime(double start_play_time) { start_play_time_ = start_play_time; }

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    /**
     * @brief Prepares the stream for playback on the specified device.
     * @param out_device The audio device to use.
     * @return True if preparation succeeds, false otherwise.
     */
    bool prepareForPlay(QAudioDevice out_device);
#else
    /**
     * @brief Prepares the stream for playback on the specified device info.
     * @param out_device The audio device info to use.
     * @return True if preparation succeeds, false otherwise.
     */
    bool prepareForPlay(QAudioDeviceInfo out_device);
#endif

    /**
     * @brief Starts playing the audio stream.
     */
    void startPlaying();

    /**
     * @brief Pauses the audio stream playback.
     */
    void pausePlaying();

    /**
     * @brief Stops the audio stream playback.
     */
    void stopPlaying();

    /**
     * @brief Seeks playback by a specific number of samples.
     * @param samples The number of samples to seek.
     */
    void seekPlaying(qint64 samples);

    /**
     * @brief Configures whether stereo output is required.
     * @param stereo_required True if stereo is required, false otherwise.
     */
    void setStereoRequired(bool stereo_required) { stereo_required_ = stereo_required; }

    /**
     * @brief Gets the maximum sample value found in the stream.
     * @return The maximum sample value.
     */
    qint16 getMaxSampleValue() { return max_sample_val_; }

    /**
     * @brief Sets the maximum sample value used for scaling.
     * @param max_sample_val The maximum sample value.
     */
    void setMaxSampleValue(int16_t max_sample_val) { max_sample_val_ = max_sample_val; }

    /**
     * @brief Seeks to a specific sample position in the file.
     * @param samples The target sample position.
     */
    void seekSample(qint64 samples);

    /**
     * @brief Reads a sample from the file.
     * @param sample Pointer to store the read sample.
     * @return The number of samples read.
     */
    qint64 readSample(SAMPLE *sample);

    /**
     * @brief Gets the number of silence samples prepended to the stream.
     * @return The number of leading silence samples.
     */
    qint64 getLeadSilenceSamples() { return prepend_samples_; }

    /**
     * @brief Gets the total number of samples in the stream.
     * @return The total sample count.
     */
    qint64 getTotalSamples() { return (audio_file_->getTotalSamples()); }

    /**
     * @brief Gets the sample index at the end of silence.
     * @return The sample index.
     */
    qint64 getEndOfSilenceSample() { return (audio_file_->getEndOfSilenceSample()); }

    /**
     * @brief Gets the time at the end of silence.
     * @return The time in seconds.
     */
    double getEndOfSilenceTime() { return (double)getEndOfSilenceSample() / (double)playRate(); }

    /**
     * @brief Converts a time in seconds to a sample count.
     * @param time The time in seconds.
     * @return The equivalent number of samples.
     */
    qint64 convertTimeToSamples(double time) { return (qint64)(time * playRate()); }

    /**
     * @brief Saves the stream payload to the provided IO device.
     * @param file The output device/file.
     * @return True if successful, false otherwise.
     */
    bool savePayload(QIODevice *file);

    /**
     * @brief Gets the hash value for the stream ID.
     * @return The hash value.
     */
    unsigned getHash() { return rtpstream_id_to_hash(&(id_)); }

    /**
     * @brief Gets a pointer to the stream ID.
     * @return Pointer to the stream ID.
     */
    rtpstream_id_t *getID() { return &(id_); }

    /**
     * @brief Gets the stream ID formatted as a QString.
     * @return The string representation of the ID.
     */
    QString getIDAsQString();

    /**
     * @brief Gets a pointer to the RTP stream info.
     * @return Pointer to the stream info.
     */
    rtpstream_info_t *getStreamInfo() { return &rtpstream_; }

signals:
    /**
     * @brief Signal emitted periodically indicating the number of processed seconds.
     * @param secs The processed time in seconds.
     */
    void processedSecs(double secs);

    /**
     * @brief Signal emitted when a playback error occurs.
     * @param error_msg The error message.
     */
    void playbackError(const QString error_msg);

    /**
     * @brief Signal emitted when the stream finishes playing.
     * @param stream The stream that finished playing.
     * @param error The audio error state upon finishing.
     */
    void finishedPlaying(RtpAudioStream *stream, QAudio::Error error);

private:
    /** @brief Used to identify unique streams. The GTK+ UI also uses the call number + current channel. */
    rtpstream_id_t id_;
    /** @brief The underlying RTP stream information. */
    rtpstream_info_t rtpstream_;
    /** @brief Flag indicating if the current packet is the first. */
    bool first_packet_;

    /** @brief Collection of RTP packets in this stream. */
    QVector<struct _rtp_packet *>rtp_packets_;
    /** @brief Stores waveform samples in sparse file. */
    RtpAudioFile *audio_file_;
    /** @brief Temporary file used during processing. */
    QIODevice *temp_file_;
    /** @brief Hash table mapping to specific decoders. */
    struct _GHashTable *decoders_hash_;
    /** @brief The global start time across streams. */
    double global_start_rel_time_;
    /** @brief The absolute offset of the stream start. */
    double start_abs_offset_;
    /** @brief The start time relative to the capture. */
    double start_rel_time_;
    /** @brief The stop time relative to the capture. */
    double stop_rel_time_;
    /** @brief Count of silence samples at begin of the stream to align with other streams. */
    qint64 prepend_samples_;
    /** @brief The configured audio routing for playback. */
    AudioRouting audio_routing_;
    /** @brief Flag indicating if stereo output is forced. */
    bool stereo_required_;
    /** @brief The base sample rate for the stream. */
    quint32 first_sample_rate_;
    /** @brief The effective output sample rate. */
    quint32 audio_out_rate_;
    /** @brief The user requested output sample rate. */
    quint32 audio_requested_out_rate_;
    /** @brief The sample rate used for visualization generation. */
    uint32_t visual_sample_rate_;
    /** @brief Unique set of payload type names in the stream. */
    QSet<QString> payload_names_;
    /** @brief Resampler state for generating visual samples. */
    struct SpeexResamplerState_ *visual_resampler_;
    /** @brief Mapping from timestamp to packet frame number. */
    QMap<double, quint32> packet_timestamps_;
    /** @brief Vector of downsampled values for visualization. */
    QVector<qint16> visual_samples_;
    /** @brief Timestamps where packets arrived out of sequence. */
    QVector<double> out_of_seq_timestamps_;
    /** @brief Timestamps of packets dropped by jitter buffer. */
    QVector<double> jitter_drop_timestamps_;
    /** @brief Timestamps of packets with incorrect timestamp sequences. */
    QVector<double> wrong_timestamp_timestamps_;
    /** @brief Timestamps where silence was artificially inserted. */
    QVector<double> silence_timestamps_;

    /** @brief The maximum sample value. */
    qint16 max_sample_val_;

    /** @brief The maximum sample value used. */
    qint16 max_sample_val_used_;

    /** @brief Color for the visualization of this stream. */
    QColor color_;

    /** @brief Size of the jitter buffer in milliseconds. */
    int jitter_buffer_size_;

    /** @brief Configured timing mode. */
    TimingMode timing_mode_;

    /** @brief Start time for playback. */
    double start_play_time_;

    /**
     * @brief Gets a description of the audio format.
     * @param format The QAudioFormat to describe.
     * @return The format description string.
     */
    const QString formatDescription(const QAudioFormat & format);

    /**
     * @brief Retrieves the name of the current output device.
     * @return The output device name.
     */
    QString currentOutputDevice();

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    /** @brief Pointer to the audio sink for output. */
    QAudioSink *audio_output_;

    /**
     * @brief Inner method to decode audio for the specified device.
     * @param out_device The target audio device.
     */
    void decodeAudio(QAudioDevice out_device);

    /**
     * @brief Calculates the actual output rate based on device capabilities.
     * @param out_device The target audio device.
     * @param sample_rate The original sample rate.
     * @param requested_out_rate The requested sample rate.
     * @return The chosen output rate.
     */
    quint32 calculateAudioOutRate(QAudioDevice out_device, unsigned int sample_rate, unsigned int requested_out_rate);
#else
    /** @brief Pointer to the audio output for playback. */
    QAudioOutput *audio_output_;

    /**
     * @brief Inner method to decode audio for the specified device info.
     * @param out_device The target audio device info.
     */
    void decodeAudio(QAudioDeviceInfo out_device);

    /**
     * @brief Calculates the actual output rate based on device capabilities.
     * @param out_device The target audio device info.
     * @param sample_rate The original sample rate.
     * @param requested_out_rate The requested sample rate.
     * @return The chosen output rate.
     */
    quint32 calculateAudioOutRate(QAudioDeviceInfo out_device, unsigned int sample_rate, unsigned int requested_out_rate);
#endif

    /**
     * @brief Resizes a sample buffer if needed.
     * @param buff Pointer to the existing buffer.
     * @param buff_bytes Pointer to store the new buffer size in bytes.
     * @param requested_size The requested buffer size in samples.
     * @return Pointer to the potentially newly allocated buffer.
     */
    SAMPLE *resizeBufferIfNeeded(SAMPLE *buff, int32_t *buff_bytes, qint64 requested_size);

private slots:
    /**
     * @brief Slot called when the state of the audio output changes.
     * @param new_state The new QAudio::State.
     */
    void outputStateChanged(QAudio::State new_state);

    /**
     * @brief Triggers stopping the stream with a delay.
     */
    void delayedStopStream();
};

#endif // QT_MULTIMEDIA_LIB

#endif // RTPAUDIOSTREAM_H
