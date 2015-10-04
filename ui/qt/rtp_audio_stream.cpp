/* rtp_audio_frame.h
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


#include "rtp_audio_stream.h"

#ifdef QT_MULTIMEDIA_LIB

#include <codecs/speex/speex_resampler.h>

#include <epan/rtp_pt.h>

#include <epan/dissectors/packet-rtp.h>

#include <ui/rtp_media.h>
#include <ui/rtp_stream.h>

#include <wsutil/nstime.h>

#include <QAudioFormat>
#include <QAudioOutput>
#include <QDir>
#include <QTemporaryFile>

static spx_int16_t default_audio_sample_rate_ = 8000;
static const spx_int16_t visual_sample_rate_ = 1000;

RtpAudioStream::RtpAudioStream(QObject *parent, _rtp_stream_info *rtp_stream) :
    QObject(parent),
    decoders_hash_(rtp_decoder_hash_table_new()),
    global_start_rel_time_(0.0),
    start_abs_offset_(0.0),
    start_rel_time_(0.0),
    stop_rel_time_(0.0),
    audio_out_rate_(0),
    audio_resampler_(0),
    audio_output_(0),
    max_sample_val_(1)
{
    copy_address(&src_addr_, &rtp_stream->src_addr);
    src_port_ = rtp_stream->src_port;
    copy_address(&dst_addr_, &rtp_stream->dest_addr);
    dst_port_ = rtp_stream->dest_port;
    ssrc_ = rtp_stream->ssrc;

    // We keep visual samples in memory. Make fewer of them.
    visual_resampler_ = ws_codec_resampler_init(1, default_audio_sample_rate_,
                                                visual_sample_rate_, SPEEX_RESAMPLER_QUALITY_MIN, NULL);
    ws_codec_resampler_skip_zeros(visual_resampler_);

    QString tempname = QString("%1/wireshark_rtp_stream").arg(QDir::tempPath());
    tempfile_ = new QTemporaryFile(tempname, this);
    tempfile_->open();

    // RTP_STREAM_DEBUG("Writing to %s", tempname.toUtf8().constData());
}

RtpAudioStream::~RtpAudioStream()
{
    g_hash_table_destroy(decoders_hash_);
    if (audio_resampler_) ws_codec_resampler_destroy (audio_resampler_);
    ws_codec_resampler_destroy (visual_resampler_);
}

bool RtpAudioStream::isMatch(const _rtp_stream_info *rtp_stream) const
{
    if (rtp_stream
            && addresses_equal(&rtp_stream->src_addr, &src_addr_)
            && rtp_stream->src_port == src_port_
            && addresses_equal(&rtp_stream->dest_addr, &dst_addr_)
            && rtp_stream->dest_port == dst_port_
            && rtp_stream->ssrc == ssrc_)
        return true;
    return false;
}

bool RtpAudioStream::isMatch(const _packet_info *pinfo, const _rtp_info *rtp_info) const
{
    if (pinfo && rtp_info
            && addresses_equal(&pinfo->src, &src_addr_)
            && pinfo->srcport == src_port_
            && addresses_equal(&pinfo->dst, &dst_addr_)
            && pinfo->destport == dst_port_
            && rtp_info->info_sync_src == ssrc_)
        return true;
    return false;
}

// XXX We add multiple RTP streams here because that's what the GTK+ UI does.
// Should we make these distinct, with their own waveforms? It seems like
// that would simplify a lot of things.
void RtpAudioStream::addRtpStream(const _rtp_stream_info *rtp_stream)
{
    if (!rtp_stream) return;

    // RTP_STREAM_DEBUG("added %d:%u packets", g_list_length(rtp_stream->rtp_packet_list), rtp_stream->packet_count);
    rtp_streams_ << rtp_stream;

    double stream_srt = nstime_to_sec(&rtp_stream->start_rel_time);
    if (rtp_streams_.length() < 2 || stream_srt > start_rel_time_) {
        start_rel_time_ = stop_rel_time_ = stream_srt;
        start_abs_offset_ = nstime_to_sec(&rtp_stream->start_fd->abs_ts) - start_rel_time_;
    }
}

static const int sample_bytes_ = sizeof(SAMPLE) / sizeof(char);
void RtpAudioStream::addRtpPacket(const struct _packet_info *pinfo, const _rtp_info *rtp_info)
{
    if (!rtp_info) return;

    // Combination of gtk/rtp_player.c:decode_rtp_stream + decode_rtp_packet
    // XXX This is more messy than it should be.

    SAMPLE *decode_buff = NULL;
    SAMPLE *resample_buff = NULL;
    spx_uint32_t cur_in_rate, visual_out_rate;
    char *write_buff;
    qint64 write_bytes;
    unsigned channels;
    unsigned sample_rate;
    rtp_packet_t rtp_packet;

    stop_rel_time_ = nstime_to_sec(&pinfo->rel_ts);
    ws_codec_resampler_get_rate(visual_resampler_, &cur_in_rate, &visual_out_rate);

    QString payload_name;
    if (rtp_info->info_payload_type_str) {
        payload_name = rtp_info->info_payload_type_str;
    } else {
        payload_name = try_val_to_str_ext(rtp_info->info_payload_type, &rtp_payload_type_short_vals_ext);
    }
    if (!payload_name.isEmpty()) {
        payload_names_ << payload_name;
    }

    // First, decode the payload.
    rtp_packet.info = (_rtp_info *) g_memdup(rtp_info, sizeof(struct _rtp_info));
    rtp_packet.arrive_offset = start_rel_time_;
    if (rtp_info->info_all_data_present && (rtp_info->info_payload_len != 0)) {
        rtp_packet.payload_data = (guint8 *)g_malloc(rtp_info->info_payload_len);
        memcpy(rtp_packet.payload_data, rtp_info->info_data + rtp_info->info_payload_offset, rtp_info->info_payload_len);
    } else {
        rtp_packet.payload_data = NULL;
    }

    //size_t decoded_bytes =
    decode_rtp_packet(&rtp_packet, &decode_buff, decoders_hash_, &channels, &sample_rate);
    write_buff = (char *) decode_buff;
    write_bytes = rtp_info->info_payload_len * sample_bytes_;

    if (tempfile_->pos() == 0) {
        // First packet. Let it determine our sample rate.
        audio_out_rate_ = sample_rate;

        last_sequence_ = rtp_info->info_seq_num - 1;

        // Prepend silence to match our sibling streams.
        int prepend_samples = (start_rel_time_ - global_start_rel_time_) * audio_out_rate_;
        if (prepend_samples > 0) {
            int prepend_bytes = prepend_samples * sample_bytes_;
            char *prepend_buff = (char *) g_malloc(prepend_bytes);
            SAMPLE silence = 0;
            memccpy(prepend_buff, &silence, prepend_samples, sample_bytes_);
            tempfile_->write(prepend_buff, prepend_bytes);
        }
    } else if (audio_out_rate_ != sample_rate) {
        // Resample the audio to match our previous output rate.
        if (!audio_resampler_) {
            audio_resampler_ = ws_codec_resampler_init(1, sample_rate, audio_out_rate_, 10, NULL);
            ws_codec_resampler_skip_zeros(audio_resampler_);
            // RTP_STREAM_DEBUG("Started resampling from %u to (out) %u Hz.", sample_rate, audio_out_rate_);
        } else {
            spx_uint32_t audio_out_rate;
            ws_codec_resampler_get_rate(audio_resampler_, &cur_in_rate, &audio_out_rate);

            // Adjust rates if needed.
            if (sample_rate != cur_in_rate) {
                ws_codec_resampler_set_rate(audio_resampler_, sample_rate, audio_out_rate);
                ws_codec_resampler_set_rate(visual_resampler_, sample_rate, visual_out_rate);
                // RTP_STREAM_DEBUG("Changed input rate from %u to %u Hz. Out is %u.", cur_in_rate, sample_rate, audio_out_rate_);
            }
        }
        spx_uint32_t in_len = (spx_uint32_t)rtp_info->info_payload_len;
        spx_uint32_t out_len = (audio_out_rate_ * (spx_uint32_t)rtp_info->info_payload_len / sample_rate) + (audio_out_rate_ % sample_rate != 0);
        resample_buff = (SAMPLE *) g_malloc(out_len * sample_bytes_);

        ws_codec_resampler_process_int(audio_resampler_, 0, decode_buff, &in_len, resample_buff, &out_len);
        write_buff = (char *) decode_buff;
        write_bytes = out_len * sample_bytes_;
    }

    if (rtp_info->info_seq_num != last_sequence_+1) {
        out_of_seq_timestamps_.append(stop_rel_time_);
        // XXX Add silence to tempfile_ and visual_samples_
    }
    last_sequence_ = rtp_info->info_seq_num;

    // Write the decoded, possibly-resampled audio to our temp file.
    tempfile_->write(write_buff, write_bytes);

    // Collect our visual samples.
    spx_uint32_t in_len = (spx_uint32_t)rtp_info->info_payload_len;
    spx_uint32_t out_len = (visual_out_rate * in_len / sample_rate) + (visual_out_rate % sample_rate != 0);
    resample_buff = (SAMPLE *) g_realloc(resample_buff, out_len * sizeof(SAMPLE));

    ws_codec_resampler_process_int(visual_resampler_, 0, decode_buff, &in_len, resample_buff, &out_len);
    for (unsigned i = 0; i < out_len; i++) {
        packet_timestamps_[stop_rel_time_ + (double) i / visual_out_rate] = pinfo->fd->num;
        if (qAbs(resample_buff[i]) > max_sample_val_) max_sample_val_ = qAbs(resample_buff[i]);
        visual_samples_.append(resample_buff[i]);
    }

    // Finally, write the resampled audio to our temp file and clean up.
    g_free(rtp_packet.payload_data);
    g_free(decode_buff);
    g_free(resample_buff);
}

void RtpAudioStream::reset(double start_rel_time)
{
    last_sequence_ = 0;
    global_start_rel_time_ = start_rel_time;
    stop_rel_time_ = start_rel_time_;
    audio_out_rate_ = 0;
    max_sample_val_ = 1;
    packet_timestamps_.clear();
    visual_samples_.clear();
    out_of_seq_timestamps_.clear();

    if (audio_resampler_) {
        ws_codec_resampler_reset_mem(audio_resampler_);
    }
    if (visual_resampler_) {
        ws_codec_resampler_reset_mem(visual_resampler_);
    }
    tempfile_->seek(0);
}

const QStringList RtpAudioStream::payloadNames() const
{
    QStringList payload_names = payload_names_.toList();
    payload_names.sort();
    return payload_names;
}

const QVector<double> RtpAudioStream::visualTimestamps(bool relative)
{
    QVector<double> ts_keys = packet_timestamps_.keys().toVector();
    if (relative) return ts_keys;

    QVector<double> adj_timestamps;
    for (int i = 0; i < ts_keys.size(); i++) {
        adj_timestamps.append(ts_keys[i] + start_abs_offset_);
    }
    return adj_timestamps;
}

// Scale the height of the waveform (max_sample_val_) and adjust its Y
// offset so that they overlap slightly (stack_offset_).

// XXX This means that waveforms can be misleading with respect to relative
// amplitude. We might want to add a "global" max_sample_val_.
static const double stack_offset_ = G_MAXINT16 / 3;
const QVector<double> RtpAudioStream::visualSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_;
    for (int i = 0; i < visual_samples_.size(); i++) {
        adj_samples.append(((double)visual_samples_[i] * G_MAXINT16 / max_sample_val_) + scaled_offset);
    }
    return adj_samples;
}

const QVector<double> RtpAudioStream::outOfSequenceTimestamps(bool relative)
{
    if (relative) return out_of_seq_timestamps_;

    QVector<double> adj_timestamps;
    for (int i = 0; i < out_of_seq_timestamps_.size(); i++) {
        adj_timestamps.append(out_of_seq_timestamps_[i] + start_abs_offset_);
    }
    return adj_timestamps;
}

const QVector<double> RtpAudioStream::outOfSequenceSamples(int y_offset)
{
    QVector<double> adj_samples;
    double scaled_offset = y_offset * stack_offset_;
    for (int i = 0; i < out_of_seq_timestamps_.size(); i++) {
        adj_samples.append(scaled_offset);
    }
    return adj_samples;
}

quint32 RtpAudioStream::nearestPacket(double timestamp, bool is_relative)
{
    if (packet_timestamps_.keys().count() < 1) return 0;

    if (!is_relative) timestamp -= start_abs_offset_;
    QMap<double, quint32>::const_iterator it = packet_timestamps_.lowerBound(timestamp);
    if (it == packet_timestamps_.end()) return 0;
    return it.value();
}

QAudio::State RtpAudioStream::outputState() const
{
    if (!audio_output_) return QAudio::IdleState;
    return audio_output_->state();
}

void RtpAudioStream::startPlaying()
{
    if (audio_output_) return;

    QAudioFormat format;
    format.setSampleRate(audio_out_rate_);
    format.setSampleSize(sample_bytes_ * 8); // bits
    format.setSampleType(QAudioFormat::SignedInt);
    format.setChannelCount(1);
    format.setCodec("audio/pcm");

    // RTP_STREAM_DEBUG("playing %s %d samples @ %u Hz",
    //                 tempfile_->fileName().toUtf8().constData(),
    //                 (int) tempfile_->size(), audio_out_rate_);

    audio_output_ = new QAudioOutput(format, this);
    audio_output_->setNotifyInterval(65); // ~15 fps
    connect(audio_output_, SIGNAL(stateChanged(QAudio::State)), this, SLOT(outputStateChanged()));
    connect(audio_output_, SIGNAL(notify()), this, SLOT(outputNotify()));
    tempfile_->seek(0);
    audio_output_->start(tempfile_);
    emit startedPlaying();
}

void RtpAudioStream::stopPlaying()
{
    if (audio_output_) {
        audio_output_->stop();
        delete audio_output_;
        audio_output_ = NULL;
    }
    emit finishedPlaying();
}

void RtpAudioStream::outputStateChanged()
{
    if (!audio_output_) return;

    if (audio_output_->state() == QAudio::IdleState) {
        // RTP_STREAM_DEBUG("stopped %f", audio_output_->processedUSecs() / 100000.0);
        delete audio_output_;
        audio_output_ = NULL;

        emit finishedPlaying();
    }
}

void RtpAudioStream::outputNotify()
{
    if (!audio_output_) return;
    emit processedSecs(audio_output_->processedUSecs() / 1000000.0);
}

#endif // QT_MULTIMEDIA_LIB

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
