#ifndef _AVD_MESSAGE_H_
#define _AVD_MESSAGE_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "avd_log.h"

#define  __INT8_NUM_BYTES__ (1)
#define  __INT16_NUM_BYTES__ (2)
#define  __INT32_NUM_BYTES__ (4)
#define  __INT64_NUM_BYTES__ (8)
#define  __FLOAT_NUM_BYTES__ (4)
#define  __DOUBLE_NUM_BYTES__ (8)

#define  __boolean_encoded_array_size __int8_t_encoded_array_size
#define  __boolean_encode_array __int8_t_encode_array
#define  __boolean_decode_array __int8_t_decode_array
#define  __boolean_encode_little_endian_array __int8_t_encode_little_endian_array
#define  __boolean_decode_little_endian_array __int8_t_decode_little_endian_array
#define  __boolean_clone_array __int8_t_clone_array

// Message type flags
#define AVD_MSG_F_NEW_CON   (1 << 0)
#define AVD_MSG_F_RE_CON    (1 << 1)
#define AVD_MSG_F_FILE      (1 << 2)
#define AVD_MSG_F_CTRL      (1 << 3)
#define AVD_MSG_F_CLOSE     (1 << 4)

#define reset_msg_type(type)        (type = 0)
#define set_msg_type(type, flag)    (type |= flag)
#define unset_msg_type(type, flag)  (type &= (~flag))
#define is_msg_type(type, flag)     (type & flag)

#define MSG_HDR_SZ sizeof(msg_hdr_t)
#define msg_sz(__msg) MSG_HDR_SZ + sizeof(__msg)

/* Message Header
 *  1. Type : type of message - e.g new user, reconnect etc
 *  2. Seq Number : this will be used in sending chunked messages e.g file transfer
 *  3. Size : size of whole message i.e MSG_HDR_SZ + size of encoded message
 */
typedef struct msg_hdr_s {
    int32_t      type;
    int32_t     seq_no;
    size_t      size;
} __attribute__((packed)) msg_hdr_t;

typedef struct message_s {
    msg_hdr_t   hdr;
    char        buf[1024];
} __attribute__((packed)) message_t;

// User Message : Reconnect (rc)
typedef struct umsg_rc_s {
    int32_t     uid;
} umsg_rc_t;

// Server Message : New User Connect (nuc)
typedef struct smsg_conn_s {
    int32_t     uid;
    int32_t     poll_id;
} smsg_conn_t;

int32_t recv_avd_hdr(int32_t sockfd, msg_hdr_t *h) {
    int32_t     rc = -1;

    rc = recv(sockfd, h, MSG_HDR_SZ, 0);

    if (0 == rc) {
        return rc;
    }

    if (MSG_HDR_SZ != rc) {
        avd_log_error("Error receiving avd_hdr");
        avd_log_debug("Error : %s", strerror(errno));
        return -1;
    }

    avd_log_debug("Received Header of size :%d", rc);
    return rc;
}

int32_t recv_avd_msg(int32_t sockfd, char *buf, size_t sz) {
    int32_t     rc = -1;

    if (0 >= (rc = recv(sockfd, buf, sz, 0))) {
        avd_log_error("Error receiving avd_msg");
        avd_log_debug("Error : %s", strerror(errno));
        return rc;
    }

    avd_log_debug("Received Msg of size :%d", rc);
    return rc;
}

static inline uint32_t __int8_t_encoded_array_sz(const int8_t *msg, uint32_t elements) {
    (void) msg;
    return (__INT8_NUM_BYTES__ * elements);
}

static inline int32_t __int8_t_encode_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                            const int8_t *p, uint32_t elements) {
    if (maxlen < elements)
        return -1;

    char    *buf = (char *) _buf;

    memcpy(&buf[offset], p, elements);

    return elements;
}

static inline int32_t __int8_t_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                        int8_t *p, uint32_t elements) {
    if (maxlen < elements)
        return -1;

    char    *buf = (char *) _buf;

    memcpy(p, &buf[offset], elements);

    return elements;
}

static inline int32_t __int8_t_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                                      const int8_t *p, uint32_t elements) {
    return __int8_t_encode_array(_buf, offset, maxlen, p, elements);
}

static inline int32_t __int8_t_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                                          int8_t *p, uint32_t elements) {
    return __int8_t_decode_array(_buf, offset, maxlen, p, elements);
}

static inline uint32_t __int8_t_clone_array(const int8_t *p, int8_t *q, uint32_t elements) {
    uint32_t    n = elements * sizeof(int8_t);

    memcpy(q, p, n);

    return n;
}

static inline uint32_t __int16_t_encoded_array_sz(const int16_t *p, uint32_t elements) {
    (void) p;
    return (__INT16_NUM_BYTES__ * elements);
}

static inline int32_t __int16_t_encode_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                             const int16_t *p, uint32_t elements) {
    uint32_t        total_size = (__INT16_NUM_BYTES__ * elements);
    uint32_t        pos = offset;
    uint32_t        ele;
    char            *buf = (char *) _buf;
    const uint16_t  *unsigned_p = (uint16_t *)p;

    if (maxlen < total_size)
        return -1;

    for (ele = 0; ele < elements; ++ele) {
        uint16_t v = unsigned_p[ele];
        buf[pos++] = (v >> 8) & 0xff;
        buf[pos++] = (v & 0xff);
    }

    return total_size;
}

static inline int32_t __int16_t_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                             int16_t *p, uint32_t elements) {
    u_int32_t   total_size = (__INT16_NUM_BYTES__ * elements);
    char        *buf = (char *) _buf;
    uint32_t    pos = offset;
    uint32_t    ele;

    if (maxlen < total_size)
        return -1;

    for (ele = 0; ele < elements; ++ele) {
        p[ele] = (buf[pos] << 8) + buf[pos + 1];
        pos += 2;
    }

    return total_size;
}

static inline int32_t __int16_t_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                                           const int16_t *p, uint32_t elements) {
    uint32_t        total_size = (__INT16_NUM_BYTES__ * elements);
    uint32_t        pos = offset;
    uint32_t        ele;
    char            *buf = (char *) _buf;
    const uint16_t  *unsigned_p = (uint16_t *)p;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        uint16_t v = unsigned_p[ele];
        buf[pos++] = (v & 0xff);
        buf[pos++] = (v >> 8) & 0xff;
    }

    return total_size;
}

static inline int32_t __int16_t_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                                           int16_t *p, uint32_t elements) {
    uint32_t    total_size = (__INT16_NUM_BYTES__ * elements);
    char        *buf = (char *) _buf;
    uint32_t    pos = offset;
    uint32_t    ele;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        p[ele] = (buf[pos + 1] << 8) + buf[pos];
        pos += 2;
    }

    return total_size;
}

static inline uint32_t __int16_t_clone_array(const int16_t *p, int16_t *q, uint32_t elements) {
    uint32_t    n = elements * sizeof(int16_t);

    memcpy(q, p, n);

    return n;
}

static inline uint32_t __int32_t_encoded_array_sz(const int32_t *p, uint32_t elements) {
    (void) p;
    return (__INT32_NUM_BYTES__ * elements);
}

static inline int32_t __int32_t_encode_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                         const int32_t *msg, uint32_t elements) {
    uint32_t        total_size = (__INT32_NUM_BYTES__ * elements);
    uint32_t        pos = offset;
    uint32_t        ele;
    char            *buf = (char *) _buf;
    const uint32_t * unsigned_msg = (uint32_t *)msg;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        uint32_t v = unsigned_msg[ele];
        buf[pos++] = (v >> 24) & 0xff;
        buf[pos++] = (v >> 16) & 0xff;
        buf[pos++] = (v >> 8) & 0xff;
        buf[pos++] = (v & 0xff);
    }

    return total_size;
}

static inline int32_t __int32_t_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen,
                                         int32_t *msg, uint32_t elements) {
    uint32_t    total_size = (__INT32_NUM_BYTES__ * elements);
    char        *buf = (char *) _buf;
    uint32_t    pos = offset;
    uint32_t    ele;

    if (maxlen < total_size)
        return -1;

    for (ele = 0; ele < elements; ++ele) {
        msg[ele] = (((uint32_t)buf[pos + 0]) << 24) +
                       (((uint32_t)buf[pos + 1]) << 16) +
                       (((uint32_t)buf[pos + 2]) << 8) +
                       ((uint32_t)buf[pos + 3]);
        pos += 4;
    }

    return total_size;
}

static inline int32_t __int32_t_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen,
                                                           const int32_t *p, uint32_t elements) {
    uint32_t        total_size = (__INT32_NUM_BYTES__ * elements);
    uint32_t        pos = offset;
    uint32_t        ele;
    char            *buf = (char *) _buf;
    const uint32_t  *unsigned_p = (uint32_t*)p;

    if (maxlen < total_size)
        return -1;

    for (ele = 0; ele < elements; ++ele) {
        uint32_t v = unsigned_p[ele];
        buf[pos++] = (v & 0xff);
        buf[pos++] = (v >> 8) & 0xff;
        buf[pos++] = (v >> 16) & 0xff;
        buf[pos++] = (v >> 24) & 0xff;
    }

    return total_size;
}

static inline int32_t __int32_t_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, int32_t *p, uint32_t elements) {
    uint32_t    total_size = (__INT32_NUM_BYTES__ * elements);
    uint32_t    pos = offset;
    uint32_t    ele;
    char        *buf = (char *) _buf;

    if (maxlen < total_size)
        return -1;

    for (ele = 0; ele < elements; ++ele) {
        p[ele] = (((uint32_t)buf[pos + 3]) << 24) +
                      (((uint32_t)buf[pos + 2]) << 16) +
                      (((uint32_t)buf[pos + 1]) << 8) +
                       ((uint32_t)buf[pos + 0]);
        pos += 4;
    }

    return total_size;
}

static inline uint32_t __int32_t_clone_array(const int32_t *p, int32_t *q, uint32_t elements) {
    uint32_t    n = elements * sizeof(int32_t);

    memcpy(q, p, n);

    return n;
}


static inline uint32_t __int64_t_encoded_array_sz(const int64_t *p, uint32_t elements) {
    (void)p;
    return __INT64_NUM_BYTES__ * elements;
}

static inline int32_t __int64_t_encode_array(void *_buf, uint32_t offset, uint32_t maxlen, const int64_t *p, uint32_t elements) {
    uint32_t total_size = __INT64_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;

    if (maxlen < total_size) return -1;

    const uint64_t* unsigned_p = (uint64_t*)p;
    for (ele = 0; ele < elements; ++ele) {
        uint64_t v = unsigned_p[ele];
        buf[pos++] = (v>>56)&0xff;
        buf[pos++] = (v>>48)&0xff;
        buf[pos++] = (v>>40)&0xff;
        buf[pos++] = (v>>32)&0xff;
        buf[pos++] = (v>>24)&0xff;
        buf[pos++] = (v>>16)&0xff;
        buf[pos++] = (v>>8)&0xff;
        buf[pos++] = (v & 0xff);
    }

    return total_size;
}

static inline int32_t __int64_t_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen, int64_t *p, uint32_t elements) {
    uint32_t total_size = __INT64_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        uint64_t a = (((uint32_t)buf[pos+0])<<24) +
                     (((uint32_t)buf[pos+1])<<16) +
                     (((uint32_t)buf[pos+2])<<8) +
                      ((uint32_t)buf[pos+3]);
        pos+=4;
        uint64_t b = (((uint32_t)buf[pos+0])<<24) +
                     (((uint32_t)buf[pos+1])<<16) +
                     (((uint32_t)buf[pos+2])<<8) +
                      ((uint32_t)buf[pos+3]);
        pos+=4;
        p[ele] = (a<<32) + (b&0xffffffff);
    }

    return total_size;
}

static inline int32_t __int64_t_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen, const int64_t *p, uint32_t elements) {
    uint32_t total_size = __INT64_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;

    if (maxlen < total_size) return -1;

    const uint64_t* unsigned_p = (uint64_t*)p;
    for (ele = 0; ele < elements; ++ele) {
        uint64_t v = unsigned_p[ele];
        buf[pos++] = (v & 0xff);
        buf[pos++] = (v>>8)&0xff;
        buf[pos++] = (v>>16)&0xff;
        buf[pos++] = (v>>24)&0xff;
        buf[pos++] = (v>>32)&0xff;
        buf[pos++] = (v>>40)&0xff;
        buf[pos++] = (v>>48)&0xff;
        buf[pos++] = (v>>56)&0xff;
    }

    return total_size;
}

static inline int32_t __int64_t_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, int64_t *p, uint32_t elements) {
    uint32_t total_size = __INT64_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        uint64_t b = (((uint32_t)buf[pos+3])<<24) +
                     (((uint32_t)buf[pos+2])<<16) +
                     (((uint32_t)buf[pos+1])<<8) +
                      ((uint32_t)buf[pos+0]);
        pos+=4;
        uint64_t a = (((uint32_t)buf[pos+3])<<24) +
                     (((uint32_t)buf[pos+2])<<16) +
                     (((uint32_t)buf[pos+1])<<8) +
                      ((uint32_t)buf[pos+0]);
        pos+=4;
        p[ele] = (a<<32) + (b&0xffffffff);
    }

    return total_size;
}

static inline uint32_t __int64_t_clone_array(const int64_t *p, int64_t *q, uint32_t elements) {
    uint32_t n = elements * sizeof(int64_t);
    memcpy(q, p, n);
    return n;
}

/**
 * FLOAT
 */
typedef union __zcm__float_uint32_t {
    float flt;
    uint32_t uint;
} __zcm__float_uint32_t;

static inline uint32_t __float_encoded_array_sz(const float *p, uint32_t elements) {
    (void)p;
    return __FLOAT_NUM_BYTES__ * elements;
}

static inline int32_t __float_encode_array(void *_buf, uint32_t offset, uint32_t maxlen, const float *p, uint32_t elements) {
    uint32_t total_size = __FLOAT_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;
    __zcm__float_uint32_t tmp;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        tmp.flt = p[ele];
        buf[pos++] = (tmp.uint >> 24) & 0xff;
        buf[pos++] = (tmp.uint >> 16) & 0xff;
        buf[pos++] = (tmp.uint >>  8) & 0xff;
        buf[pos++] = (tmp.uint      ) & 0xff;
    }

    return total_size;
}

static inline int32_t __float_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen, float *p, uint32_t elements) {
    uint32_t total_size = __FLOAT_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;
    __zcm__float_uint32_t tmp;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        tmp.uint = (((uint32_t)buf[pos + 0]) << 24) |
                   (((uint32_t)buf[pos + 1]) << 16) |
                   (((uint32_t)buf[pos + 2]) <<  8) |
                    ((uint32_t)buf[pos + 3]);
        p[ele] = tmp.flt;
        pos += 4;
    }

    return total_size;
}

static inline int32_t __float_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen, const float *p, uint32_t elements) {
    uint32_t total_size = __FLOAT_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;
    __zcm__float_uint32_t tmp;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        tmp.flt = p[ele];
        buf[pos++] = (tmp.uint      ) & 0xff;
        buf[pos++] = (tmp.uint >>  8) & 0xff;
        buf[pos++] = (tmp.uint >> 16) & 0xff;
        buf[pos++] = (tmp.uint >> 24) & 0xff;
    }

    return total_size;
}

static inline int32_t __float_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, float *p, uint32_t elements) {
    uint32_t total_size = __FLOAT_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;
    __zcm__float_uint32_t tmp;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        tmp.uint = (((uint32_t)buf[pos + 3]) << 24) |
                   (((uint32_t)buf[pos + 2]) << 16) |
                   (((uint32_t)buf[pos + 1]) <<  8) |
                    ((uint32_t)buf[pos + 0]);
        p[ele] = tmp.flt;
        pos += 4;
    }

    return total_size;
}

static inline uint32_t __float_clone_array(const float *p, float *q, uint32_t elements) {
    uint32_t n = elements * sizeof(float);
    memcpy(q, p, n);
    return n;
}

/**
 * DOUBLE
 */
typedef union __zcm__double_uint64_t {
    double dbl;
    uint64_t uint;
} __zcm__double_uint64_t;

static inline uint32_t __double_encoded_array_sz(const double *p, uint32_t elements) {
    (void)p;
    return __DOUBLE_NUM_BYTES__ * elements;
}

static inline int32_t __double_encode_array(void *_buf, uint32_t offset, uint32_t maxlen, const double *p, uint32_t elements) {
    uint32_t total_size = __DOUBLE_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;
    __zcm__double_uint64_t tmp;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        tmp.dbl = p[ele];
        buf[pos++] = (tmp.uint >> 56) & 0xff;
        buf[pos++] = (tmp.uint >> 48) & 0xff;
        buf[pos++] = (tmp.uint >> 40) & 0xff;
        buf[pos++] = (tmp.uint >> 32) & 0xff;
        buf[pos++] = (tmp.uint >> 24) & 0xff;
        buf[pos++] = (tmp.uint >> 16) & 0xff;
        buf[pos++] = (tmp.uint >>  8) & 0xff;
        buf[pos++] = (tmp.uint      ) & 0xff;
    }

    return total_size;
}

static inline int32_t __double_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen, double *p, uint32_t elements) {
    uint32_t total_size = __DOUBLE_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;
    __zcm__double_uint64_t tmp;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        uint64_t a = (((uint32_t) buf[pos + 0]) << 24) +
                     (((uint32_t) buf[pos + 1]) << 16) +
                     (((uint32_t) buf[pos + 2]) <<  8) +
                      ((uint32_t) buf[pos + 3]);
        pos += 4;
        uint64_t b = (((uint32_t) buf[pos + 0]) << 24) +
                     (((uint32_t) buf[pos + 1]) << 16) +
                     (((uint32_t) buf[pos + 2]) <<  8) +
                      ((uint32_t) buf[pos + 3]);
        pos += 4;
        tmp.uint = (a << 32) + (b & 0xffffffff);
        p[ele] = tmp.dbl;
    }

    return total_size;
}

static inline int32_t __double_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen, const double *p, uint32_t elements) {
    uint32_t total_size = __DOUBLE_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;
    __zcm__double_uint64_t tmp;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        tmp.dbl = p[ele];
        buf[pos++] = (tmp.uint      ) & 0xff;
        buf[pos++] = (tmp.uint >>  8) & 0xff;
        buf[pos++] = (tmp.uint >> 16) & 0xff;
        buf[pos++] = (tmp.uint >> 24) & 0xff;
        buf[pos++] = (tmp.uint >> 32) & 0xff;
        buf[pos++] = (tmp.uint >> 40) & 0xff;
        buf[pos++] = (tmp.uint >> 48) & 0xff;
        buf[pos++] = (tmp.uint >> 56) & 0xff;
    }

    return total_size;
}

static inline int32_t __double_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, double *p, uint32_t elements) {
    uint32_t total_size = __DOUBLE_NUM_BYTES__ * elements;
    char *buf = (char *) _buf;
    uint32_t pos = offset;
    uint32_t ele;
    __zcm__double_uint64_t tmp;

    if (maxlen < total_size) return -1;

    for (ele = 0; ele < elements; ++ele) {
        uint64_t b = (((uint32_t)buf[pos + 3]) << 24) +
                     (((uint32_t)buf[pos + 2]) << 16) +
                     (((uint32_t)buf[pos + 1]) <<  8) +
                      ((uint32_t)buf[pos + 0]);
        pos += 4;
        uint64_t a = (((uint32_t)buf[pos + 3]) << 24) +
                     (((uint32_t)buf[pos + 2]) << 16) +
                     (((uint32_t)buf[pos + 1]) <<  8) +
                      ((uint32_t)buf[pos + 0]);
        pos += 4;
        tmp.uint = (a << 32) + (b & 0xffffffff);
        p[ele] = tmp.dbl;
    }

    return total_size;
}

static inline uint32_t __double_clone_array(const double *p, double *q, uint32_t elements) {
    uint32_t n = elements * sizeof(double);
    memcpy(q, p, n);
    return n;
}

/**
 * STRING
 */
static inline int32_t __string_decode_array_cleanup(char **s, uint32_t elements) {
    uint32_t ele;
    for (ele = 0; ele < elements; ++ele)
        free(s[ele]);
    return 0;
}

// TODO: Figure out why "const char * const * p" doesn't work
static inline uint32_t __string_encoded_array_sz(char * const *s, uint32_t elements) {
    uint32_t size = 0, ele;
    for (ele = 0; ele < elements; ++ele)
        size += __INT32_NUM_BYTES__ + strlen(s[ele]) + __INT8_NUM_BYTES__;

    return size;
}

// TODO: Figure out why "const char * const * p" doesn't work
static inline int32_t __string_encode_array(void *_buf, uint32_t offset, uint32_t maxlen, char * const *p, uint32_t elements) {
    uint32_t pos = 0, ele;
    int thislen;

    for (ele = 0; ele < elements; ++ele) {
        int32_t length = strlen(p[ele]) + __INT8_NUM_BYTES__; // length includes \0

        thislen = __int32_t_encode_array(_buf, offset + pos, maxlen - pos, &length, 1);
        if (thislen < 0) return thislen; else pos += thislen;

        thislen = __int8_t_encode_array(_buf, offset + pos, maxlen - pos, (int8_t*) p[ele], length);
        if (thislen < 0) return thislen; else pos += thislen;
    }

    return pos;
}

static inline int32_t __string_decode_array(const void *_buf, uint32_t offset, uint32_t maxlen, char **p, uint32_t elements) {
    uint32_t pos = 0, ele;
    int thislen;

    for (ele = 0; ele < elements; ++ele) {
        int32_t length;

        // read length including \0
        thislen = __int32_t_decode_array(_buf, offset + pos, maxlen - pos, &length, 1);
        if (thislen < 0) return thislen; else pos += thislen;

        p[ele] = (char*) malloc(length);
        thislen = __int8_t_decode_array(_buf, offset + pos, maxlen - pos, (int8_t*) p[ele], length);
        if (thislen < 0) return thislen; else pos += thislen;
    }

    return pos;
}

// TODO: Figure out why "const char * const * p" doesn't work
static inline int32_t __string_encode_little_endian_array(void *_buf, uint32_t offset, uint32_t maxlen, char * const *p, uint32_t elements) {
    uint32_t pos = 0, ele;
    int thislen;

    for (ele = 0; ele < elements; ++ele) {
        int32_t length = strlen(p[ele]) + 1; // length includes \0

        thislen = __int32_t_encode_little_endian_array(_buf, offset + pos, maxlen - pos, &length, 1);
        if (thislen < 0) return thislen; else pos += thislen;

        thislen = __int8_t_encode_little_endian_array(_buf, offset + pos, maxlen - pos, (int8_t*) p[ele], length);
        if (thislen < 0) return thislen; else pos += thislen;
    }

    return pos;
}

static inline int32_t __string_decode_little_endian_array(const void *_buf, uint32_t offset, uint32_t maxlen, char **p, uint32_t elements) {
    uint32_t pos = 0, ele;
    int thislen;

    for (ele = 0; ele < elements; ++ele) {
        int32_t length;

        // read length including \0
        thislen = __int32_t_decode_little_endian_array(_buf, offset + pos, maxlen - pos, &length, 1);
        if (thislen < 0) return thislen; else pos += thislen;

        p[ele] = (char*) malloc(length);
        thislen = __int8_t_decode_little_endian_array(_buf, offset + pos, maxlen - pos, (int8_t*) p[ele], length);
        if (thislen < 0) return thislen; else pos += thislen;
    }

    return pos;
}

/* User Message : Reconnect | Encoding & Decoding */
uint32_t __umsg_rc_t_encoded_sz(const umsg_rc_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->uid), 1);

    return sz;
}

uint32_t umsg_rc_t_encoded_sz (const umsg_rc_t *msg) {
    return 8 + __umsg_rc_t_encoded_sz(msg);
}

int32_t __umsg_rc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const umsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->uid), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t umsg_rc_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const umsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __umsg_rc_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __umsg_rc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, umsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->uid), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t umsg_rc_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, umsg_rc_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __umsg_rc_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

/* Server Message : New User Connect | Encoding & Decoding */
uint32_t __smsg_conn_t_encoded_sz(const smsg_conn_t *msg) {
    uint32_t    sz = 0;

    sz += __int32_t_encoded_array_sz(&(msg->uid), 1);
    sz += __int32_t_encoded_array_sz(&(msg->poll_id), 1);

    return sz;
}

uint32_t smsg_conn_t_encoded_sz (const smsg_conn_t *msg) {
    return 8 + __smsg_conn_t_encoded_sz(msg);
}

int32_t __smsg_conn_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_conn_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->uid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_encode_array(buf, offset + pos, maxlen - pos, &(msg->poll_id), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t smsg_conn_t_encode(void *buf, uint32_t offset, uint32_t maxlen, const smsg_conn_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_conn_t_encode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t __smsg_conn_t_decode(const void *buf, uint32_t offset, uint32_t maxlen, smsg_conn_t *msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->uid), 1);
    if (len < 0) return len; else pos += len;

    len = __int32_t_decode_array(buf, offset + pos, maxlen - pos, &(msg->poll_id), 1);
    if (len < 0) return len; else pos += len;

    return pos;
}

int32_t smsg_conn_t_decode(const void* buf, uint32_t offset, uint32_t maxlen, smsg_conn_t* msg) {
    uint32_t    pos = 0;
    int32_t     len;

    len = __smsg_conn_t_decode(buf, offset + pos, maxlen - pos, msg);
    if (len < 0) return len; else pos += len;

    return pos;
}

#endif
