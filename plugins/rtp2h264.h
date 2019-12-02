#ifndef __RTP_2_H264_H__
#define __RTP_2_H264_H__

#include <inttypes.h>
#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif

#define RTP_FLAG_KEY    0x1 ///< RTP packet contains a keyframe
#define RTP_FLAG_MARKER 0x2 ///< RTP marker bit was set for this packet
#define RTP_SEQ_MOD (1 << 16)
#define NAL_COUNTERS NULL
#define NAL_MASK 0x1f
#define RTP_VERSION 2

static const uint8_t start_sequence[] = { 0, 0, 0, 1 };

typedef struct RTPPacket {
    uint16_t seq;
    uint8_t *buf;
    int len;
    int64_t recvtime;
    struct RTPPacket *next;
} RTPPacket;

// these statistics are used for rtcp receiver reports...
typedef struct RTPStatistics {
    uint16_t max_seq;           ///< highest sequence number seen
    uint32_t cycles;            ///< shifted count of sequence number cycles
    uint32_t base_seq;          ///< base sequence number
    uint32_t bad_seq;           ///< last bad sequence number + 1
    int probation;              ///< sequence packets till source is valid
    uint32_t received;          ///< packets received
    uint32_t expected_prior;    ///< packets expected in last interval
    uint32_t received_prior;    ///< packets received in last interval
    uint32_t transit;           ///< relative transit time for previous packet
    uint32_t jitter;            ///< estimated jitter.
} RTPStatistics;

typedef struct RTPDemuxContext {
    int payload_type;
    uint32_t ssrc;
    uint16_t seq;
    int64_t  range_start_offset;
    int max_payload_size;

    /** Statistics for this stream (used by RTCP receiver reports) */
    RTPStatistics statistics;

    /** Fields for packet reordering @{ */
    int prev_ret;     ///< The return value of the actual parsing of the previous packet
    RTPPacket* queue; ///< A sorted queue of buffered packets not yet returned
    int queue_len;    ///< The number of packets in queue
    int queue_size;   ///< The size of queue, or 0 if reordering is disabled
} RTPDemuxContext;

typedef struct Packet {
    uint8_t* buf;
    int size;
} Packet;

// external
RTPDemuxContext* rtp_parse_open(int payload_type, int queue_size);
void rtp_parse_close(RTPDemuxContext* s);
int rtp_parse_packet(RTPDemuxContext* s, Packet* pkt, uint8_t** buf, int len);
Packet* create_packet(void);
void release_packet(Packet** pkt);

// internal
int rtp_parse_one_packet(RTPDemuxContext *s, Packet *pkt, uint8_t **bufptr, int len);
int has_next_packet(RTPDemuxContext *s);
int rtp_parse_queued_packet(RTPDemuxContext *s, Packet *pkt);
void rtp_init_sequence(RTPStatistics *s, uint16_t seq);
int rtp_valid_packet_in_sequence(RTPStatistics *s, uint16_t seq);
int rtp_parse_packet_internal(RTPDemuxContext *s, Packet *pkt, const uint8_t *buf, int len);
int h264_handle_packet(Packet *pkt, const uint8_t *buf, int len, uint16_t seq, int flags);
int h264_handle_frag_packet(Packet *pkt, const uint8_t *buf, int len,
                               int start_bit, const uint8_t *nal_header,
                               int nal_header_len);
int h264_handle_packet_fu_a(Packet *pkt, const uint8_t *buf, int len, int *nal_counters, int nal_mask);
int h264_handle_aggregated_packet(Packet *pkt,
                                     const uint8_t *buf, int len,
                                     int skip_between, int *nal_counters,
                                     int nal_mask);
int enqueue_packet(RTPDemuxContext *s, uint8_t *buf, int len);



#endif