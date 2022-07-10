/* rtp_audio_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "rtp_audio_stream.h"

#ifdef QT_MULTIMEDIA_LIB

#ifdef HAVE_SPEEXDSP
#include <speex/speex_resampler.h>
#else
#include "../../speexdsp/speex_resampler.h"
#endif /* HAVE_SPEEXDSP */

#include <epan/rtp_pt.h>
#include <epan/to_str.h>

#include <epan/dissectors/packet-rtp.h>

#include <ui/rtp_media.h>
#include <ui/rtp_stream.h>
#include <ui/tap-rtp-common.h>

#include <wsutil/nstime.h>

#include <ui/qt/utils/rtp_audio_routing_filter.h>
#include <ui/qt/utils/rtp_audio_file.h>

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
#include <QAudioDevice>
#include <QAudioSink>
#endif
#include <QAudioFormat>
#include <QAudioOutput>
#include <QVariant>
#include <QTimer>

// To do:
// - Only allow one rtpstream_info_t per RtpAudioStream?

static const spx_int16_t visual_sample_rate_ = 1000;

RtpAudioStream::RtpAudioStream(QObject *parent, rtpstream_id_t *id, bool stereo_required) :
    QObject(parent)
    , first_packet_(true)
    , decoders_hash_(rtp_decoder_hash_table_new())
    , global_start_rel_time_(0.0)
    , start_abs_offset_(0.0)
    , start_rel_time_(0.0)
    , stop_rel_time_(0.0)
    , stereo_required_(stereo_required)
    , first_sample_rate_(0)
    , audio_out_rate_(0)
    , audio_requested_out_rate_(0)
    , audio_resampler_(0)
    , max_sample_val_(1)
    , max_sample_val_used_(1)
    , color_(0)
    , jitter_buffer_size_(50)
    , timing_mode_(RtpAudioStream::JitterBuffer)
    , start_play_time_(0)
    , audio_output_(NULL)
{
    rtpstream_id_copy(id, &id_);
    memset(&rtpstream_, 0, sizeof(rtpstream_));
    rtpstream_id_copy(&id_, &rtpstream_.id);

    // Rates will be set later, we just init visual resampler
    visual_resampler_ = speex_resampler_init(1, visual_sample_rate_,
                                                visual_sample_rate_, SPEEX_RESAMPLER_QUALITY_MIN, NULL);

    try {
        // RtpAudioFile is ready for writing Frames
        audio_file_ = new RtpAudioFile(prefs.gui_rtp_player_use_disk1, prefs.gui_rtp_player_use_disk2);
    } catch (...) {
        speex_resampler_destroy(visual_resampler_);
        rtpstream_info_free_data(&rtpstream_);
        rtpstream_id_free(&id_);
        throw -1;
    }

    // RTP_STREAM_DEBUG("Writing to %s", tempname.toUtf8().constData());
}

RtpAudioStream::~RtpAudioStream()
{
    for (int i = 0; i < rtp_packets_.size(); i++) {
        rtp_packet_t *rtp_packet = rtp_packets_[i];
        g_free(rtp_packet->info);
        g_free(rtp_packet->payload_data);
        g_free(rtp_packet);
    }
    g_hash_table_destroy(decoders_hash_);
    if (audio_resampler_) speex_resampler_destroy(audio_resampler_);
    speex_resampler_destroy(visual_resampler_);
    rtpstream_info_free_data(&rtpstream_);
    rtpstream_id_free(&id_);
    if (audio_file_) delete audio_file_;
    // temp_file_ is released by audio_output_
    if (audio_output_) delete audio_output_;
}

bool RtpAudioStream::isMatch(const rtpstream_id_t *id) const
{
    if (id
        && rtpstream_id_equal(&id_, id, RTPSTREAM_ID_EQUAL_SSRC))
        return true;
    return false;
}

bool RtpAudioStream::isMatch(const _packet_info *pinfo, const _rtp_info *rtp_info) const
{
    if (pinfo && rtp_info
        && rtpstream_id_equal_pinfo_rtp_info(&id_, pinfo, rtp_info))
        return true;
    return false;
}

void RtpAudioStream::addRtpPacket(const struct _packet_info *pinfo, const struct _rtp_info *rtp_info)
{
    if (!rtp_info) return;

    if (first_packet_) {
        rtpstream_info_analyse_init(&rtpstream_, pinfo, rtp_info);
        first_packet_ = false;
    }
    rtpstream_info_analyse_process(&rtpstream_, pinfo, rtp_info);

    rtp_packet_t *rtp_packet = g_new0(rtp_packet_t, 1);
    rtp_packet->info = (struct _rtp_info *) g_memdup2(rtp_info, sizeof(struct _rtp_info));
    if (rtp_info->info_all_data_present && (rtp_info->info_payload_len != 0)) {
        rtp_packet->payload_data = (guint8 *) g_memdup2(&(rtp_info->info_data[rtp_info->info_payload_offset]),
          rtp_info->info_payload_len);
    }

    if (rtp_packets_.size() < 1) { // First packet
        start_abs_offset_ = nstime_to_sec(&pinfo->abs_ts) - start_rel_time_;
        start_rel_time_ = stop_rel_time_ = nstime_to_sec(&pinfo->rel_ts);
    }
    rtp_packet->frame_num = pinfo->num;
    rtp_packet->arrive_offset = nstime_to_sec(&pinfo->rel_ts) - start_rel_time_;

    rtp_packets_ << rtp_packet;
}

void RtpAudioStream::clearPackets()
{
    for (int i = 0; i < rtp_packets_.size(); i++) {
        rtp_packet_t *rtp_packet = rtp_packets_[i];
        g_free(rtp_packet->info);
        g_free(rtp_packet->payload_data);
        g_free(rtp_packet);
    }
    rtp_packets_.clear();
    rtpstream_info_free_data(&rtpstream_);
    memset(&rtpstream_, 0, sizeof(rtpstream_));
    rtpstream_id_copy(&id_, &rtpstream_.id);
    first_packet_ = true;
}

void RtpAudioStream::reset(double global_start_time)
{
    global_start_rel_time_ = global_start_time;
    stop_rel_time_ = start_rel_time_;
    audio_out_rate_ = 0;
    max_sample_val_ = 1;
    packet_timestamps_.clear();
    visual_samples_.clear();
    out_of_seq_timestamps_.clear();
    jitter_drop_timestamps_.clear();
}

AudioRouting RtpAudioStream::getAudioRouting()
{
    return audio_routing_;
}

void RtpAudioStream::setAudioRouting(AudioRouting audio_routing)
{
    audio_routing_ = audio_routing;
}

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
void RtpAudioStream::decode(QAudioDevice out_device)
#else
void RtpAudioStream::decode(QAudioDeviceInfo out_device)
#endif
{
    if (rtp_packets_.size() < 1) return;

    if (audio_resampler_) {
        speex_resampler_reset_mem(audio_resampler_);
    }
    audio_file_->setFrameWriteStage();
    decodeAudio(out_device);

    // Skip silence at begin of the stream
    audio_file_->setFrameReadStage(prepend_samples_);

    speex_resampler_reset_mem(visual_resampler_);
    decodeVisual();
    audio_file_->setDataReadStage();
}

// Side effect: it creates and initiates resampler if needed
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
quint32 RtpAudioStream::calculateAudioOutRate(QAudioDevice out_device, unsigned int sample_rate, unsigned int requested_out_rate)
#else
quint32 RtpAudioStream::calculateAudioOutRate(QAudioDeviceInfo out_device, unsigned int sample_rate, unsigned int requested_out_rate)
#endif
{
    quint32 out_rate;

    // Use the first non-zero rate we find. Ajust it to match
    // our audio hardware.
    QAudioFormat format;
    format.setSampleRate(sample_rate);
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    // Must match rtp_media.h.
    format.setSampleFormat(QAudioFormat::Int16);
#else
    format.setSampleSize(SAMPLE_BYTES * 8); // bits
    format.setSampleType(QAudioFormat::SignedInt);
#endif
    if (stereo_required_) {
        format.setChannelCount(2);
    } else {
        format.setChannelCount(1);
    }
#if (QT_VERSION < QT_VERSION_CHECK(6, 0, 0))
    format.setCodec("audio/pcm");
#endif

    if (!out_device.isNull() &&
        !out_device.isFormatSupported(format) &&
        (requested_out_rate == 0)
       ) {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
        out_rate = out_device.preferredFormat().sampleRate();
#else
        out_rate = out_device.nearestFormat(format).sampleRate();
#endif
        audio_resampler_ = speex_resampler_init(1, sample_rate, out_rate, 10, NULL);
        RTP_STREAM_DEBUG("Started resampling from %u to (out) %u Hz.", sample_rate, out_rate);
    } else {
        if ((requested_out_rate != 0) &&
            (requested_out_rate != sample_rate)
           ) {
            out_rate = requested_out_rate;
            audio_resampler_ = speex_resampler_init(1, sample_rate, out_rate, 10, NULL);
            RTP_STREAM_DEBUG("Started resampling from %u to (out) %u Hz.", sample_rate, out_rate);
        } else {
            out_rate = sample_rate;
        }
    }

    RTP_STREAM_DEBUG("Audio sample rate is %u", out_rate);

    return out_rate;
}

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
void RtpAudioStream::decodeAudio(QAudioDevice out_device)
#else
void RtpAudioStream::decodeAudio(QAudioDeviceInfo out_device)
#endif
{
    // XXX This is more messy than it should be.

    gint32 resample_buff_bytes = 0x1000;
    SAMPLE *resample_buff = (SAMPLE *) g_malloc(resample_buff_bytes);
    char *write_buff = NULL;
    qint64 write_bytes = 0;
    unsigned int channels = 0;
    unsigned int sample_rate = 0;
    guint32 last_sequence = 0;
    guint32 last_sequence_w = 0;  // Last sequence number we wrote data

    double rtp_time_prev = 0.0;
    double arrive_time_prev = 0.0;
    double pack_period = 0.0;
    double start_time = 0.0;
    double start_rtp_time = 0.0;
    guint64 start_timestamp = 0;

    size_t decoded_bytes_prev = 0;

    for (int cur_packet = 0; cur_packet < rtp_packets_.size(); cur_packet++) {
        SAMPLE *decode_buff = NULL;
        // TODO: Update a progress bar here.
        rtp_packet_t *rtp_packet = rtp_packets_[cur_packet];

        stop_rel_time_ = start_rel_time_ + rtp_packet->arrive_offset;

        QString payload_name;
        if (rtp_packet->info->info_payload_type_str) {
            payload_name = rtp_packet->info->info_payload_type_str;
        } else {
            payload_name = try_val_to_str_ext(rtp_packet->info->info_payload_type, &rtp_payload_type_short_vals_ext);
        }
        if (!payload_name.isEmpty()) {
            payload_names_ << payload_name;
        }

        if (cur_packet < 1) { // First packet
            start_timestamp = rtp_packet->info->info_extended_timestamp;
            start_rtp_time = 0;
            rtp_time_prev = 0;
            last_sequence = rtp_packet->info->info_extended_seq_num - 1;
        }

        size_t decoded_bytes = decode_rtp_packet(rtp_packet, &decode_buff, decoders_hash_, &channels, &sample_rate);

        unsigned rtp_clock_rate = sample_rate;
        if (rtp_packet->info->info_payload_type == PT_G722) {
            // G.722 sample rate is 16kHz, but RTP clock rate is 8kHz
            // for historic reasons.
            rtp_clock_rate = 8000;
        }

        // Length 2 for PT_PCM mean silence packet probably, ignore
        if (decoded_bytes == 0 || sample_rate == 0 ||
            ((rtp_packet->info->info_payload_type == PT_PCMU ||
              rtp_packet->info->info_payload_type == PT_PCMA
             ) && (decoded_bytes == 2)
            )
           ) {
            // We didn't decode anything. Clean up and prep for
            // the next packet.
            last_sequence = rtp_packet->info->info_extended_seq_num;
            g_free(decode_buff);
            continue;
        }

        if (audio_out_rate_ == 0) {
            first_sample_rate_ = sample_rate;

            // We calculate audio_out_rate just for first sample_rate.
            // All later are just resampled to it.
            // Side effect: it creates and initiates resampler if needed
            audio_out_rate_ = calculateAudioOutRate(out_device, sample_rate, audio_requested_out_rate_);

            // Calculate count of prepend samples for the stream
            // The earliest stream starts at 0.
            // Note: Order of operations and separation to two formulas is
            // important.
            // When joined, calculated incorrectly - probably caused by
            // conversions between int/double
            prepend_samples_ = (start_rel_time_ - global_start_rel_time_) * sample_rate;
            prepend_samples_ = prepend_samples_ * audio_out_rate_ / sample_rate;

            // Prepend silence to match our sibling streams.
            if ((prepend_samples_ > 0) && (audio_out_rate_ != 0)) {
                audio_file_->frameWriteSilence(rtp_packet->frame_num, prepend_samples_);
            }
        }

        if (rtp_packet->info->info_extended_seq_num != last_sequence+1) {
            out_of_seq_timestamps_.append(stop_rel_time_);
        }
        last_sequence = rtp_packet->info->info_extended_seq_num;

        double rtp_time = (double)(rtp_packet->info->info_extended_timestamp-start_timestamp)/rtp_clock_rate - start_rtp_time;
        double arrive_time;
        if (timing_mode_ == RtpTimestamp) {
            arrive_time = rtp_time;
        } else {
            arrive_time = rtp_packet->arrive_offset - start_time;
        }

        double diff = qAbs(arrive_time - rtp_time);
        if (diff*1000 > jitter_buffer_size_ && timing_mode_ != Uninterrupted) {
            // rtp_player.c:628

            jitter_drop_timestamps_.append(stop_rel_time_);
            RTP_STREAM_DEBUG("Packet drop by jitter buffer exceeded %f > %d", diff*1000, jitter_buffer_size_);

            /* if there was a silence period (more than two packetization
             * period) resync the source */
            if ((rtp_time - rtp_time_prev) > pack_period*2) {
                qint64 silence_samples;
                RTP_STREAM_DEBUG("Resync...");

                silence_samples = (qint64)((arrive_time - arrive_time_prev)*sample_rate - decoded_bytes_prev / SAMPLE_BYTES);
                silence_samples = silence_samples * audio_out_rate_ / sample_rate;
                silence_timestamps_.append(stop_rel_time_);
                // Timestamp shift can make silence calculation negative
                if ((silence_samples > 0) && (audio_out_rate_ != 0)) {
                    audio_file_->frameWriteSilence(rtp_packet->frame_num, silence_samples);
                }

                decoded_bytes_prev = 0;
                start_timestamp = rtp_packet->info->info_extended_timestamp;
                start_rtp_time = 0;
                start_time = rtp_packet->arrive_offset;
                rtp_time_prev = 0;
            }

        } else {
            // rtp_player.c:664
            /* Add silence if it is necessary */
            qint64 silence_samples;

            if (timing_mode_ == Uninterrupted) {
                silence_samples = 0;
            } else {
                silence_samples = (int)((rtp_time - rtp_time_prev)*sample_rate - decoded_bytes_prev / SAMPLE_BYTES);
                silence_samples = silence_samples * audio_out_rate_ / sample_rate;
            }

            if (silence_samples != 0) {
                wrong_timestamp_timestamps_.append(stop_rel_time_);
            }

            if (silence_samples > 0) {
                silence_timestamps_.append(stop_rel_time_);
                if ((silence_samples > 0) && (audio_out_rate_ != 0)) {
                    audio_file_->frameWriteSilence(rtp_packet->frame_num, silence_samples);
                }
            }

            // XXX rtp_player.c:696 adds audio here.
            rtp_time_prev = rtp_time;
            pack_period = (double) decoded_bytes / SAMPLE_BYTES / sample_rate;
            decoded_bytes_prev = decoded_bytes;
            arrive_time_prev = arrive_time;
        }

        // Prepare samples to write
        write_buff = (char *) decode_buff;
        write_bytes = decoded_bytes;

        if (audio_out_rate_ != sample_rate) {
            // Resample the audio to match output rate.
            // Buffer is in SAMPLEs
            spx_uint32_t in_len = (spx_uint32_t) (write_bytes / SAMPLE_BYTES);
            // Output is audio_out_rate_/sample_rate bigger than input
            spx_uint32_t out_len = (spx_uint32_t) ((guint64)in_len * audio_out_rate_ / sample_rate);
            resample_buff = resizeBufferIfNeeded(resample_buff, &resample_buff_bytes, out_len * SAMPLE_BYTES);

            speex_resampler_process_int(audio_resampler_, 0, decode_buff, &in_len, resample_buff, &out_len);

            write_buff = (char *) resample_buff;
            write_bytes = out_len * SAMPLE_BYTES;
        }

        // We should write only newer data to avoid duplicates in replay
        if (last_sequence_w < last_sequence) {
            // Write the decoded, possibly-resampled audio to our temp file.
            audio_file_->frameWriteSamples(rtp_packet->frame_num, write_buff, write_bytes);
            last_sequence_w = last_sequence;
        }

        g_free(decode_buff);
    }
    g_free(resample_buff);
}

// We preallocate buffer, 320 samples is enough for most scenarios
#define VISUAL_BUFF_LEN (320)
#define VISUAL_BUFF_BYTES (SAMPLE_BYTES * VISUAL_BUFF_LEN)
void RtpAudioStream::decodeVisual()
{
    spx_uint32_t read_len = 0;
    gint32 read_buff_bytes = VISUAL_BUFF_BYTES;
    SAMPLE *read_buff = (SAMPLE *) g_malloc(read_buff_bytes);
    gint32 resample_buff_bytes = VISUAL_BUFF_BYTES;
    SAMPLE *resample_buff = (SAMPLE *) g_malloc(resample_buff_bytes);
    unsigned int sample_no = 0;
    spx_uint32_t out_len;
    guint32 frame_num;
    rtp_frame_type type;

    speex_resampler_set_rate(visual_resampler_, audio_out_rate_, visual_sample_rate_);

    // Loop over every frame record
    // readFrameSamples() maintains size of buffer for us
    while (audio_file_->readFrameSamples(&read_buff_bytes, &read_buff, &read_len, &frame_num, &type)) {
        out_len = (spx_uint32_t)(((guint64)read_len * visual_sample_rate_ ) / audio_out_rate_);

        if (type == RTP_FRAME_AUDIO) {
            // We resample only audio samples
            resample_buff = resizeBufferIfNeeded(resample_buff, &resample_buff_bytes, out_len * SAMPLE_BYTES);

            // Resample
            speex_resampler_process_int(visual_resampler_, 0, read_buff, &read_len, resample_buff, &out_len);

            // Create timestamp and visual sample
            for (unsigned i = 0; i < out_len; i++) {
                double time = start_rel_time_ + (double) sample_no / visual_sample_rate_;
                packet_timestamps_[time] = frame_num;
                if (qAbs(resample_buff[i]) > max_sample_val_) max_sample_val_ = qAbs(resample_buff[i]);
                visual_samples_.append(resample_buff[i]);
                sample_no++;
            }
        } else {
            // Insert end of line mark
            double time = start_rel_time_ + (double) sample_no / visual_sample_rate_;
            packet_timestamps_[time] = frame_num;
            visual_samples_.append(SAMPLE_NaN);
            sample_no += out_len;
        }
    }

    max_sample_val_used_ = max_sample_val_;
    g_free(resample_buff);
    g_free(read_buff);
}

const QStringList RtpAudioStream::payloadNames() const
{
    QStringList payload_names = payload_names_.values();
    payload_names.sort();
    return payload_names;
}

const QVector<double> RtpAudioStream::visualTimestamps(bool relative)
{
    QVector<double> ts_keys = packet_timestamps_.keys().toVector();
    if (relative) return ts_keys;

    QVector<double> adj_timestamps;
    for (int i = 0; i < ts_keys.size(); i++) {
        adj_timestamps.append(ts_keys[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

// Scale the height of the waveform to global scale (max_sample_val_used_)
// and adjust its Y offset so that they overlap slightly (stack_offset_).
static const double stack_offset_ = G_MAXINT16 / 3;
const QVector<double> RtpAudioStream::visualSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_;
    for (int i = 0; i < visual_samples_.size(); i++) {
        if (SAMPLE_NaN != visual_samples_[i]) {
            adj_samples.append(((double)visual_samples_[i] * G_MAXINT16 / max_sample_val_used_) + scaled_offset);
        } else {
            // Convert to break in graph line
            adj_samples.append(qQNaN());
        }
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::outOfSequenceTimestamps(bool relative)
{
    if (relative) return out_of_seq_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < out_of_seq_timestamps_.size(); i++) {
        adj_timestamps.append(out_of_seq_timestamps_[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::outOfSequenceSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_;  // XXX Should be different for seq, jitter, wrong & silence
    for (int i = 0; i < out_of_seq_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::jitterDroppedTimestamps(bool relative)
{
    if (relative) return jitter_drop_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < jitter_drop_timestamps_.size(); i++) {
        adj_timestamps.append(jitter_drop_timestamps_[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::jitterDroppedSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_; // XXX Should be different for seq, jitter, wrong & silence
    for (int i = 0; i < jitter_drop_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::wrongTimestampTimestamps(bool relative)
{
    if (relative) return wrong_timestamp_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < wrong_timestamp_timestamps_.size(); i++) {
        adj_timestamps.append(wrong_timestamp_timestamps_[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::wrongTimestampSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_; // XXX Should be different for seq, jitter, wrong & silence
    for (int i = 0; i < wrong_timestamp_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::insertedSilenceTimestamps(bool relative)
{
    if (relative) return silence_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < silence_timestamps_.size(); i++) {
        adj_timestamps.append(silence_timestamps_[i] + start_abs_offset_ - start_rel_time_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::insertedSilenceSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_;  // XXX Should be different for seq, jitter, wrong & silence
    for (int i = 0; i < silence_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

quint32 RtpAudioStream::nearestPacket(double timestamp, bool is_relative)
{
    if (packet_timestamps_.size() < 1) return 0;

    if (!is_relative) timestamp -= start_abs_offset_;
    QMap<double, quint32>::iterator it = packet_timestamps_.lowerBound(timestamp);
    if (it == packet_timestamps_.end()) return 0;
    return it.value();
}

QAudio::State RtpAudioStream::outputState() const
{
    if (!audio_output_) return QAudio::IdleState;
    return audio_output_->state();
}

const QString RtpAudioStream::formatDescription(const QAudioFormat &format)
{
    QString fmt_descr = QString("%1 Hz, ").arg(format.sampleRate());
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    switch (format.sampleFormat()) {
    case QAudioFormat::UInt8:
        fmt_descr += "UInt8";
        break;
    case QAudioFormat::Int16:
        fmt_descr += "Int16";
        break;
    case QAudioFormat::Int32:
        fmt_descr += "Int32";
        break;
    case QAudioFormat::Float:
        fmt_descr += "Float";
        break;
    default:
        fmt_descr += "Unknown";
        break;
    }
#else
    switch (format.sampleType()) {
    case QAudioFormat::SignedInt:
        fmt_descr += "Int";
        fmt_descr += QString::number(format.sampleSize());
        fmt_descr += format.byteOrder() == QAudioFormat::BigEndian ? "BE" : "LE";
        break;
    case QAudioFormat::UnSignedInt:
        fmt_descr += "UInt";
        fmt_descr += QString::number(format.sampleSize());
        fmt_descr += format.byteOrder() == QAudioFormat::BigEndian ? "BE" : "LE";
        break;
    case QAudioFormat::Float:
        fmt_descr += "Float";
        break;
    default:
        fmt_descr += "Unknown";
        break;
    }
#endif

    return fmt_descr;
}

QString RtpAudioStream::getIDAsQString()
{
    gchar *src_addr_str = address_to_display(NULL, &id_.src_addr);
    gchar *dst_addr_str = address_to_display(NULL, &id_.dst_addr);
    QString str = QString("%1:%2 - %3:%4 %5")
        .arg(src_addr_str)
        .arg(id_.src_port)
        .arg(dst_addr_str)
        .arg(id_.dst_port)
        .arg(QString("0x%1").arg(id_.ssrc, 0, 16));
    wmem_free(NULL, src_addr_str);
    wmem_free(NULL, dst_addr_str);

    return str;
}

#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
bool RtpAudioStream::prepareForPlay(QAudioDevice out_device)
#else
bool RtpAudioStream::prepareForPlay(QAudioDeviceInfo out_device)
#endif
{
    qint64 start_pos;
    qint64 size;

    if (audio_routing_.isMuted())
        return false;

    if (audio_output_)
        return false;

    if (audio_out_rate_ == 0) {
        /* It is observed, but is not an error
        QString error = tr("RTP stream (%1) is empty or codec is unsupported.")
            .arg(getIDAsQString());

        emit playbackError(error);
        */
        return false;
    }

    QAudioFormat format;
    format.setSampleRate(audio_out_rate_);
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
    // Must match rtp_media.h.
    format.setSampleFormat(QAudioFormat::Int16);
#else
    format.setSampleSize(SAMPLE_BYTES * 8); // bits
    format.setSampleType(QAudioFormat::SignedInt);
#endif
    if (stereo_required_) {
        format.setChannelCount(2);
    } else {
        format.setChannelCount(1);
    }
#if (QT_VERSION < QT_VERSION_CHECK(6, 0, 0))
    format.setCodec("audio/pcm");
#endif

    // RTP_STREAM_DEBUG("playing %s %d samples @ %u Hz",
    //                 sample_file_->fileName().toUtf8().constData(),
    //                 (int) sample_file_->size(), audio_out_rate_);

    if (!out_device.isFormatSupported(format)) {
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
        QString playback_error = tr("%1 does not support PCM at %2. Preferred format is %3")
                .arg(out_device.description(), formatDescription(format), formatDescription(out_device.preferredFormat()));
#else
        QString playback_error = tr("%1 does not support PCM at %2. Preferred format is %3")
                .arg(out_device.deviceName())
                .arg(formatDescription(format))
                .arg(formatDescription(out_device.nearestFormat(format)));
#endif
        emit playbackError(playback_error);
    }

    start_pos = (qint64)(start_play_time_ * SAMPLE_BYTES * audio_out_rate_);
    // Round to SAMPLE_BYTES boundary
    start_pos = (start_pos / SAMPLE_BYTES) * SAMPLE_BYTES;
    size = audio_file_->sampleFileSize();
    if (stereo_required_) {
        // There is 2x more samples for stereo
        start_pos *= 2;
        size *= 2;
    }
    if (start_pos < size) {
        audio_file_->setDataReadStage();
        temp_file_ = new AudioRoutingFilter(audio_file_, stereo_required_, audio_routing_);
        temp_file_->seek(start_pos);
        if (audio_output_) delete audio_output_;
#if (QT_VERSION >= QT_VERSION_CHECK(6, 0, 0))
        audio_output_ = new QAudioSink(out_device, format, this);
        connect(audio_output_, &QAudioSink::stateChanged, this, &RtpAudioStream::outputStateChanged);
#else
        audio_output_ = new QAudioOutput(out_device, format, this);
        connect(audio_output_, &QAudioOutput::stateChanged, this, &RtpAudioStream::outputStateChanged);
#endif
        return true;
    } else {
        // Report stopped audio if start position is later than stream ends
        outputStateChanged(QAudio::StoppedState);
        return false;
    }

    return false;
}

void RtpAudioStream::startPlaying()
{
   audio_output_->start(temp_file_);
   // QTBUG-6548 StoppedState is not always emitted on error, force a cleanup
   // in case playback fails immediately.
   if (audio_output_ && audio_output_->state() == QAudio::StoppedState) {
       outputStateChanged(QAudio::StoppedState);
   }
}

void RtpAudioStream::pausePlaying()
{
    if (audio_routing_.isMuted())
        return;

    if (audio_output_) {
        if (QAudio::ActiveState == audio_output_->state()) {
            audio_output_->suspend();
        } else if (QAudio::SuspendedState == audio_output_->state()) {
            audio_output_->resume();
        }
    }
}

void RtpAudioStream::stopPlaying()
{
    if (audio_routing_.isMuted())
        return;

    if (audio_output_) {
        if (audio_output_->state() == QAudio::StoppedState) {
            // Looks like "delayed" QTBUG-6548
            // It may happen that stream is stopped, but no signal emited
            // Probably triggered by some issue in sound system which is not
            // handled by Qt correctly
            outputStateChanged(QAudio::StoppedState);
        } else {
            audio_output_->stop();
        }
    }
}

void RtpAudioStream::seekPlaying(qint64 samples _U_)
{
    if (audio_routing_.isMuted())
        return;

    if (audio_output_) {
        audio_output_->suspend();
        audio_file_->seekSample(samples);
        audio_output_->resume();
    }
}

void RtpAudioStream::outputStateChanged(QAudio::State new_state)
{
    if (!audio_output_) return;

    // On some platforms including macOS and Windows, the stateChanged signal
    // is emitted while a QMutexLocker is active. As a result we shouldn't
    // delete audio_output_ here.
    switch (new_state) {
    case QAudio::StoppedState:
        {
            // RTP_STREAM_DEBUG("stopped %f", audio_output_->processedUSecs() / 100000.0);
            // Detach from parent (RtpAudioStream) to prevent deleteLater
            // from being run during destruction of this class.
            QAudio::Error error = audio_output_->error();

            audio_output_->setParent(0);
            audio_output_->disconnect();
            audio_output_->deleteLater();
            audio_output_ = NULL;
            emit finishedPlaying(this, error);
            break;
        }
    case QAudio::IdleState:
        // Workaround for Qt behaving on some platforms with some soundcards:
        // When ->stop() is called from outputStateChanged(),
        // internalQMutexLock is locked and application hangs.
        // We can stop the stream later.
        QTimer::singleShot(0, this, SLOT(delayedStopStream()));

        break;
    default:
        break;
    }
}

void RtpAudioStream::delayedStopStream()
{
    audio_output_->stop();
}

SAMPLE *RtpAudioStream::resizeBufferIfNeeded(SAMPLE *buff, gint32 *buff_bytes, qint64 requested_size)
{
    if (requested_size > *buff_bytes) {
        while ((requested_size > *buff_bytes))
            *buff_bytes *= 2;
        buff = (SAMPLE *) g_realloc(buff, *buff_bytes);
    }

    return buff;
}

void RtpAudioStream::seekSample(qint64 samples)
{
    audio_file_->seekSample(samples);
}

qint64 RtpAudioStream::readSample(SAMPLE *sample)
{
    return audio_file_->readSample(sample);
}

bool RtpAudioStream::savePayload(QIODevice *file)
{
    for (int cur_packet = 0; cur_packet < rtp_packets_.size(); cur_packet++) {
        // TODO: Update a progress bar here.
        rtp_packet_t *rtp_packet = rtp_packets_[cur_packet];

        if ((rtp_packet->info->info_payload_type != PT_CN) &&
            (rtp_packet->info->info_payload_type != PT_CN_OLD)) {
            // All other payloads
            int64_t nchars;

            if (rtp_packet->payload_data && (rtp_packet->info->info_payload_len > 0)) {
                nchars = file->write((char *)rtp_packet->payload_data, rtp_packet->info->info_payload_len);
                if (nchars != rtp_packet->info->info_payload_len) {
                    return false;
                }
            }
        }
    }

    return true;
}


#endif // QT_MULTIMEDIA_LIB
