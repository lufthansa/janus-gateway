#include "rtmp.h"
#include "debug.h"
#include "../rtp.h"
#include <assert.h>

void print_malloc(char* dest, char* log)
{
    unsigned long* a;
    a = (char*)dest - sizeof(long)*4;
    printf("print_malloc 44444 %s is 0x%lx\n",log ,*a);
    a = (char*)dest - sizeof(long)*3;
    printf("print_malloc 33333 %s is 0x%lx\n",log, *a);
    a = (char*)dest - sizeof(long)*2;
    printf("print_malloc 22222 %s is 0x%lx\n",log, *a);
    a = (char*)dest - sizeof(long)*1;
    printf("print_malloc 11111 %s is 0x%lx\n",log, *a);
}

void rtmp_module_init() {
    // ffmpeg init
    avcodec_register_all();
    avformat_network_init();
    // create hashtable for different room_id
    context_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify)context_destroy);
    if (!context_table) {
        assert(context_table != NULL);
    }
    JANUS_LOG(LOG_INFO, "rtmp module init success\n");
    return;
}

int rtmp_stream_open(char* room_id, char* url, Audio_Param* ap, Video_Param* vp) {
    JANUS_LOG(LOG_INFO, "rtmp open, roomid[%s], url[%s]\n", room_id, url);
    janus_mutex_lock(&context_mutex);  
    Stream_Context* ctx = context_create(ap, vp, url);
    if (!ctx) {
        JANUS_LOG(LOG_ERR, "stream_context create fail\n");
        janus_mutex_unlock(&context_mutex);
        return -1;
    }
    // insert to hashtable
    g_hash_table_insert(context_table, g_strdup(room_id), ctx);
    JANUS_LOG(LOG_INFO, "insert stream_context:[%s:%p]\n", room_id, ctx);
    janus_mutex_unlock(&context_mutex);
    return 0;
}

void rtmp_stream_close(char* room_id) {
    JANUS_LOG(LOG_INFO, "room[%s] stream push over, release resources\n", room_id);
    janus_mutex_lock(&context_mutex);
    if (!g_hash_table_contains(context_table, room_id)) {
        JANUS_LOG(LOG_WARN, "room_id[%s] not exist, stream close error\n", room_id);
        janus_mutex_unlock(&context_mutex);
        return;
    }
    // delete from hashtable
    g_hash_table_remove(context_table, room_id);
    janus_mutex_unlock(&context_mutex);
    return;
}

int rtmp_stream_push(char* room_id, char* buf, int len, Media_Type av) {
    // find context by room_id
    janus_mutex_lock(&context_mutex);
    Stream_Context* ctx = g_hash_table_lookup(context_table, room_id);
    if (!ctx) {
        JANUS_LOG(LOG_WARN, "room_id[%s] not exist, stream push error, tablesize=%d\n", room_id, g_hash_table_size(context_table));
        janus_mutex_unlock(&context_mutex);
        return -1;
    }
    janus_rtp_header *rtp_header = (janus_rtp_header *)buf;
    if (av == Media_Video) {
        if (!ctx->rtp_ctx) {
            ctx->rtp_ctx = rtp_parse_open(rtp_header->type, 5 * 1024 * 1024);
            if (!ctx->rtp_ctx) {
                JANUS_LOG(LOG_ERR, "rtp parse open fail\n");
                return -1;
            }
        }
        // decode rtp data
        int rv = 0;
        do {
            Packet* pkt = create_packet();
            rv = rtp_parse_packet(ctx->rtp_ctx, pkt, rv == 1 ? NULL : &buf, len);
            if (rv < 0) {
                JANUS_LOG(LOG_ERR, "room[%s] rtp parse fail\n", room_id);
                release_packet(&pkt);
                break;
            }
            // find the nal header
            if (pkt->buf[0] == 0x00 && pkt->buf[1] == 0x00 && pkt->buf[2] == 0x00 && pkt->buf[3] == 0x01) {
                if (ctx->avdata.v_buf && ctx->ff_ofmt_ctx) {
                    // Send video frame
                    AVPacket vpkt;
                    av_init_packet(&vpkt);
                    vpkt.data = ctx->avdata.v_buf;
                    vpkt.size = ctx->avdata.v_len;
                    vpkt.stream_index = 0;
                    vpkt.pts = ctx->avdata.v_pts;
                    vpkt.dts = ctx->avdata.v_pts;
                    if (av_interleaved_write_frame(ctx->ff_ofmt_ctx, &vpkt) < 0) {
                        JANUS_LOG(LOG_ERR, "send video frame fail\n");
                    }
                    av_packet_unref(&vpkt);
                    // release buf, notmater how
                    g_free(ctx->avdata.v_buf);
                    ctx->avdata.v_buf = NULL;
                    ctx->avdata.v_len = 0;
                }
                ctx->avdata.v_buf = g_malloc0(pkt->size);
                memcpy(ctx->avdata.v_buf, pkt->buf, pkt->size);
                ctx->avdata.v_len += pkt->size;
                ctx->avdata.v_pts = ntohl(rtp_header->timestamp) / 90;
            } else {
                if (!ctx->avdata.v_buf) {
                    release_packet(&pkt);
                    break;
                }
                // Assemble one nalu util
                ctx->avdata.v_buf = g_realloc(ctx->avdata.v_buf, ctx->avdata.v_len + pkt->size);
                memcpy(ctx->avdata.v_buf + ctx->avdata.v_len, pkt->buf, pkt->size);
                ctx->avdata.v_len += pkt->size;
            }
            release_packet(&pkt);
        } while(rv == 1);
    } else if (av == Media_Audio) {
        // find rtp's payload
        int plen = 0;
        char *payload = janus_rtp_payload(buf, len, &plen);
        if(!payload) {
            janus_mutex_unlock(&context_mutex);
            return -1;
        }
        // opus decode
        int frame_size = ctx->ap.sample_rate / 50 * ctx->ap.channels;
        opus_uint16 pcmbuf[1024 * 1024] = {0};
        int pcmlen = frame_size * 1 * sizeof(opus_int16);
        int ret = opus_decode(ctx->opus_dec, payload, plen, pcmbuf, frame_size, 0);
        if (ret <= 0) {
            JANUS_LOG(LOG_ERR, "room[%s] opus decode fail\n", room_id);
            janus_mutex_unlock(&context_mutex);
            return -1;
        }
        // pcm resample
        int pcm_samples = pcmlen / sizeof(uint16_t);   // 16bit as one sample
        float* fpcmbuf = g_malloc0(sizeof(float) * pcm_samples);   // length not change
        src_short_to_float_array(pcmbuf, fpcmbuf, pcm_samples);
        float* fpcm44buf = g_malloc0(sizeof(float) * pcm_samples);
        SRC_DATA data = {
            .data_in = fpcmbuf,
            .input_frames = pcm_samples,
            .data_out = fpcm44buf,
            .output_frames = pcm_samples,
            .src_ratio = ctx->sample_ratio,
            .output_frames_gen = 0
        };
        ret = src_process(ctx->sample_handle, &data);
        if (0 != ret || 0 == data.output_frames_gen) {
            JANUS_LOG(LOG_ERR, "audio resample from %d to 44100 fail\n", ctx->ap.sample_rate);
            g_free(fpcmbuf), fpcmbuf = NULL;
            g_free(fpcm44buf), fpcm44buf = NULL;
            janus_mutex_unlock(&context_mutex);
            return -1;
        }
        // JANUS_LOG(LOG_INFO, "resample pcm_samples=%d, used=%d, gen=%d\n", pcm_samples, data.input_frames_used, data.output_frames_gen);
        uint16_t* pcm44buf = g_malloc0(sizeof(uint16_t) * data.output_frames_gen);
        src_float_to_short_array(fpcm44buf, pcm44buf, data.output_frames_gen);
        // copy audio data to cache
        memcpy(ctx->avdata.a_buf + ctx->avdata.a_end, (uint8_t*)pcm44buf, data.output_frames_gen * sizeof(uint16_t));
        ctx->avdata.a_end += data.output_frames_gen * sizeof(uint16_t);
        // release cache
        g_free(fpcmbuf), fpcmbuf = NULL;
        g_free(fpcm44buf), fpcm44buf = NULL;
        g_free(pcm44buf), pcm44buf = NULL;

        // Accumulate one frame and then perform aac encoding
        if (ctx->avdata.a_end - ctx->avdata.a_begin >= ctx->avdata.a_input_samples * sizeof(uint16_t)) {
            // aac encode
            uint8_t* aacbuf = g_malloc0(ctx->avdata.a_max_output_bytes);
            if (!aacbuf) {
                JANUS_LOG(LOG_ERR, "room[%s] aacbuf g_malloc0 fail\n", room_id);
                janus_mutex_unlock(&context_mutex);
                return -1;
            }
            uint aaclen = faacEncEncode(ctx->aac_enc, (int32_t*)ctx->avdata.a_buf, ctx->avdata.a_input_samples, aacbuf, ctx->avdata.a_max_output_bytes);
            // Send audio frame
            if (aaclen > 0  && ctx->ff_ofmt_ctx) {
                AVPacket apkt;
                av_init_packet(&apkt);
                apkt.data = aacbuf;
                apkt.size = aaclen;
                apkt.stream_index = 1;
                apkt.pts = ctx->avdata.a_pts;
                apkt.dts = ctx->avdata.a_pts;
                if (av_interleaved_write_frame(ctx->ff_ofmt_ctx, &apkt) < 0) {
                    JANUS_LOG(LOG_ERR, "send audio frame fail\n");
                }
                av_packet_unref(&apkt);
            }
            g_free(aacbuf), aacbuf = NULL; 
            // move the cache's pos
            ctx->avdata.a_begin += ctx->avdata.a_input_samples * sizeof(uint16_t);
            memcpy(ctx->avdata.a_buf, ctx->avdata.a_buf + ctx->avdata.a_begin, ctx->avdata.a_end - ctx->avdata.a_begin);
            ctx->avdata.a_begin = 0;
            ctx->avdata.a_end -= ctx->avdata.a_input_samples * sizeof(uint16_t);
            ctx->avdata.a_pts = ntohl(rtp_header->timestamp) / (ctx->ap.sample_rate / 1000);
        }
    }
    janus_mutex_unlock(&context_mutex);
    return 0;
}

Stream_Context* context_create(Audio_Param* ap, Video_Param* vp, char* url) {
    int ret = 0;
    if (!ap || !url) {
        JANUS_LOG(LOG_ERR, "stream context create input error\n");
        return -1;
    }
    Stream_Context* ctx = g_malloc0(sizeof(Stream_Context));
    if (!ctx) {
        JANUS_LOG(LOG_ERR, "Stream_Context malloc fail\n");
        return NULL;
    }
    JANUS_LOG(LOG_INFO, "context create ctx=%p\n", ctx);
    do {
        // set params
        ctx->ap.channels = ap->channels;
        ctx->ap.input_format = ap->input_format;
        ctx->ap.sample_rate = ap->sample_rate;
        // rtp
        ret = rtp_decoder_create_(ctx);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "ffmpeg decoder create fail, err=%d\n", ret);
            break;
        }
        // opus
        ret = opus_decoder_create_(ctx, ap);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "opus decoder create fail, err=%d\n", ret);
            break;
        }
        // resample
        ret = resample_create_(ctx, ap);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "resample create fail, err=%d\n", ret);
            break;
        }
        // faac
        ret = faac_encoder_create_(ctx, ap);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "faac encoder create fail, err=%d\n", ret);
            break;
        }
        // srs-librtmp
        ret = rtmp_create_(ctx, vp, url);
        if (ret < 0) {
            JANUS_LOG(LOG_ERR, "ffmpeg rtmp create fail, err=%d\n", ret);
            break;
        }
        return ctx;
    } while(0);
    // release handles
    rtp_decoder_destroy_(ctx);
    opus_decoder_destroy_(ctx);
    resample_destroy_(ctx);
    faac_encoder_destroy_(ctx);
    rtmp_destroy_(ctx);
    JANUS_LOG(LOG_INFO, "context create fail, release sources\n");
    g_free(ctx);
    ctx = NULL;
    return NULL;
}

void context_destroy(Stream_Context* ctx) {
	JANUS_LOG(LOG_INFO, "context destroy ctx=%p\n", ctx);
	if (!ctx) {
        return;
    }
    // release handles 
    rtp_decoder_destroy_(ctx);
    opus_decoder_destroy_(ctx);
    resample_destroy_(ctx);
    faac_encoder_destroy_(ctx);
    rtmp_destroy_(ctx);
    // release video cache
    if (ctx->avdata.v_buf) {
        JANUS_LOG(LOG_INFO, "g_free ctx[%p] avdata.v_buf=%p\n", ctx, ctx->avdata.v_buf);
        g_free(ctx->avdata.v_buf);
        ctx->avdata.v_buf = NULL;
    }
    // release audio cache
    if (ctx->avdata.a_buf) {
        JANUS_LOG(LOG_INFO, "g_free ctx[%p] avdata.a_buf=%p\n", ctx, ctx->avdata.a_buf);
        g_free(ctx->avdata.a_buf);
        ctx->avdata.a_buf = NULL;
    }
    // release ctx
    JANUS_LOG(LOG_WARN, "ctx[%p] free\n", ctx);
    g_free(ctx);
    return;
}

int rtp_decoder_create_(Stream_Context* ctx) {
    if (!ctx) {
        JANUS_LOG(LOG_ERR, "rtp decoder create input error\n");
        return -1;
    }
    ctx->rtp_ctx = NULL;
    return 0;
}

void rtp_decoder_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->rtp_ctx) {
        rtp_parse_close(ctx->rtp_ctx);
        ctx->rtp_ctx = NULL;
    }
}

int opus_decoder_create_(Stream_Context* ctx, Audio_Param* ap) {
    if (!ctx || !ap) {
        JANUS_LOG(LOG_ERR, "srs rtmp create input error\n");
        return -1;
    }
    int err = 0;
    ctx->opus_dec = opus_decoder_create(ap->sample_rate, ap->channels, &err);
    if (err != OPUS_OK) {
        JANUS_LOG(LOG_ERR, "opus decoder create fail, err=%d\n", err);
        return -1;
    }
    JANUS_LOG(LOG_INFO, "opus decoder create success %p\n", ctx->opus_dec);
    return 0;
}

void opus_decoder_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->opus_dec) {
        JANUS_LOG(LOG_INFO, "destroy ctx[%p] opus_dec %p\n", ctx, ctx->opus_dec);
        opus_decoder_destroy(ctx->opus_dec);
        ctx->opus_dec = NULL;
    }
    return;
}

int resample_create_(Stream_Context* ctx, Audio_Param* ap) {
    if (!ctx || !ap) {
        JANUS_LOG(LOG_ERR, "resample create input error\n");
        return -1;
    }
    int err = 0;
    ctx->sample_handle = src_new(SRC_SINC_BEST_QUALITY, ctx->ap.channels, &err);
    if (!ctx->sample_handle || err) {
        JANUS_LOG(LOG_ERR, "src_new fail, err=%d\n", err);
        return -1;
    }
    ctx->sample_ratio = (double)44100 / (double)ctx->ap.sample_rate;
    JANUS_LOG(LOG_INFO, "samplerate create success, handle=%p\n", ctx->sample_handle);
    return 0;
}

void resample_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->sample_handle) {
        src_delete(ctx->sample_handle);
        ctx->sample_handle = NULL;
    }
    return;
}

int faac_encoder_create_(Stream_Context* ctx, Audio_Param* ap) {
    if (!ctx || !ap) {
        JANUS_LOG(LOG_ERR, "faac encoder create input error\n");
        return -1;
    }
    // open aac encoder
    ctx->aac_enc = faacEncOpen(ap->sample_rate, ap->channels, &ctx->avdata.a_input_samples, &ctx->avdata.a_max_output_bytes);
    if (!ctx->aac_enc) {
        JANUS_LOG(LOG_ERR, "faac enc open fail\n");
        return -1;
    }
	// config aac encoder param
    faacEncConfigurationPtr pConfiguration = NULL;
	pConfiguration = faacEncGetCurrentConfiguration(ctx->aac_enc);
	pConfiguration->inputFormat = ap->input_format;
	pConfiguration->outputFormat = RAW_STREAM;
	pConfiguration->aacObjectType = LOW;
	pConfiguration->allowMidside = 0;
	pConfiguration->useLfe = 0;
    pConfiguration->useTns = 1;
    pConfiguration->shortctl = SHORTCTL_NORMAL;
    pConfiguration->quantqual = 100;
	pConfiguration->bitRate = 0;
	pConfiguration->bandWidth = 0;
	faacEncSetConfiguration(ctx->aac_enc, pConfiguration);
    JANUS_LOG(LOG_INFO, "faac enc open success, a_input_samples=%lu, a_max_output_bytes=%lu\n", ctx->avdata.a_input_samples, ctx->avdata.a_max_output_bytes);
    // alloc audio cache
    ctx->avdata.a_buf = g_malloc0(ctx->avdata.a_input_samples * sizeof(uint16_t) * 2);
    ctx->avdata.a_begin = 0;
    ctx->avdata.a_end = 0;
    return 0;
}

void faac_encoder_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->aac_enc) {
        JANUS_LOG(LOG_INFO, "destroy ctx[%p] aac_enc=%p\n", ctx, ctx->aac_enc);
        faacEncClose(ctx->aac_enc);
        ctx->aac_enc = NULL;
    }
    return;
}

int rtmp_create_(Stream_Context* ctx, Video_Param* vp, char* url) {
    if (!ctx || !url) {
        JANUS_LOG(LOG_ERR, "srs rtmp create input error\n");
        return -1;
    }
    // ffmpeg ctx
    int ret = avformat_alloc_output_context2(&ctx->ff_ofmt_ctx, NULL, "flv", url);
    if (ret < 0) {
        JANUS_LOG(LOG_ERR, "avformat alloc output context2 fail, err:%s\n", av_err2str(ret));
        return -1;
    }
    do {
        // video
        AVCodec* pCodec = avcodec_find_encoder(AV_CODEC_ID_H264);
        if (!pCodec) {
            JANUS_LOG(LOG_ERR, "avcodec h264 not found\n");
            break;
        }
        AVStream* ff_stream_v = avformat_new_stream(ctx->ff_ofmt_ctx, pCodec);
        if (!ff_stream_v) {
            JANUS_LOG(LOG_ERR, "avformat new stream video fail\n");
            break;
        }
        ff_stream_v->time_base = (AVRational){1, 1000};
        ff_stream_v->codec->codec_id = pCodec->id;
        ff_stream_v->codec->codec_type = AVMEDIA_TYPE_VIDEO;
        ff_stream_v->codec->pix_fmt = AV_PIX_FMT_YUV420P;
        ff_stream_v->codec->width = vp->width;
        ff_stream_v->codec->height = vp->height;
        ff_stream_v->codec->time_base = (AVRational){1, 1000};
        if (ctx->ff_ofmt_ctx->oformat->flags & AVFMT_GLOBALHEADER) {
            ff_stream_v->codec->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
        }
        if (avcodec_open2(ff_stream_v->codec, pCodec, NULL) < 0) {
            JANUS_LOG(LOG_ERR, "avcodec video open fail\n");
            break;
        }
        // audio
        pCodec = avcodec_find_encoder_by_name("libfdk_aac");
        if (!pCodec) {
            JANUS_LOG(LOG_ERR, "avcodec aac not found\n");
            break;
        }
        AVStream* ff_stream_a = avformat_new_stream(ctx->ff_ofmt_ctx, pCodec);
        if (!ff_stream_a) {
            JANUS_LOG(LOG_ERR, "avformat new stream audio fail\n");
            break;
        }
        ff_stream_a->codec->sample_fmt = AV_SAMPLE_FMT_S16;
        ff_stream_a->codec->bit_rate = 0;
        ff_stream_a->codec->sample_rate = 44100;
        ff_stream_a->codec->channel_layout = AV_CH_LAYOUT_MONO;
        ff_stream_a->codec->channels = 1;
        ff_stream_a->codec->time_base = (AVRational){1, 1000};
        if (ctx->ff_ofmt_ctx->oformat->flags & AVFMT_GLOBALHEADER) {
            ff_stream_a->codec->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
        }
        if (avcodec_open2(ff_stream_a->codec, pCodec, NULL) < 0) {
            JANUS_LOG(LOG_ERR, "avcodec audio open fail\n");
            break;
        }

        // dump codec info
        av_dump_format(ctx->ff_ofmt_ctx, 0, url, 1);

        // Open output URL
        if (!(ctx->ff_ofmt_ctx->oformat->flags & AVFMT_NOFILE)) {
            if (avio_open(&ctx->ff_ofmt_ctx->pb, url, AVIO_FLAG_WRITE) < 0) {
                JANUS_LOG(LOG_ERR, "Could not open url:[%s]", url);
                break;
            }
        }
        // Write rtmp header
        if (avformat_write_header(ctx->ff_ofmt_ctx, NULL) < 0) {
            JANUS_LOG(LOG_ERR, "Error occurred when write rtmp header\n");
            break;
        }
        JANUS_LOG(LOG_INFO, "ffmpeg stream create success\n");
        return 0;
    } while(0);

    avformat_free_context(ctx->ff_ofmt_ctx);
    ctx->ff_ofmt_ctx = NULL;
    return -1;
}

void rtmp_destroy_(Stream_Context* ctx) {
    if (ctx && ctx->ff_ofmt_ctx) {
        JANUS_LOG(LOG_INFO, "destroy ctx[%p] ff_ofmt_ctx[%p]\n", ctx, ctx->ff_ofmt_ctx);
        av_write_trailer(ctx->ff_ofmt_ctx);
        avformat_free_context(ctx->ff_ofmt_ctx);
        ctx->ff_ofmt_ctx = NULL;
    }
    return;
}