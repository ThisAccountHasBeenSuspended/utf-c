/**
 * ┌────────────────────────────────────────────────────────────────────────────────┐
 * │ MIT License                                                                    │
 * │                                                                                │
 * │ Copyright (c) 2025 Nick Ilhan Atamgüc <nickatamguec@outlook.com>               │
 * │                                                                                │
 * │ Permission is hereby granted, free of charge, to any person obtaining a copy   │
 * │ of this software and associated documentation files (the "Software"), to deal  │
 * │ in the Software without restriction, including without limitation the rights   │
 * │ to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      │
 * │ copies of the Software, and to permit persons to whom the Software is          │
 * │ furnished to do so, subject to the following conditions:                       │  
 * │                                                                                │
 * │ The above copyright notice and this permission notice shall be included in all │
 * │ copies or substantial portions of the Software.                                │
 * │                                                                                │
 * │ THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     │
 * │ IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       │
 * │ FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    │
 * │ AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         │
 * │ LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  │
 * │ OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  │
 * │ SOFTWARE.                                                                      │
 * └────────────────────────────────────────────────────────────────────────────────┘
 * 
 * To use SIMD and increase performance, the following must be defined:
 * - AVX512BW  = UTFC_SIMD_512
 * - AVX2      = UTFC_SIMD_256
 * - SSE2,NEON = UTFC_SIMD_128
 * 
 * ╭─────────╴HEADER╶─────────╮
 * ├──────────┬───┬───┬───┬───┼────────────────┐
 * │ 55 38 43 │ ? │ ? │ 0 │ 8 │ D7 A9 9C 95 9D │
 * ├──────────┼───┴───┼───┴───┼[5 bytes]───────┘
 * └Magic     └Major  ├Flags  ├"שלום" (8 bytes)
 *               Minor┘ Length┘
 * 
 * Written by Nick Ilhan Atamgüc <nickatamguec@outlook.com>
 */

#if !defined(UTFC_H)
#define UTFC_H 1

#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64) || defined(_M_AMD64) || defined(__i386__) || defined(_M_IX86)
    #define _UTFC_X86 1
    #if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64) || defined(_M_AMD64)
        #define _UTFC_64BIT 1
    #endif
#elif defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64) || (defined(_M_ARM) && defined(_M_ARM_NEON))
    #define _UTFC_ARM 1
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#if defined(_UTFC_X86)
    // Instructions for SSE|AVX.
    #include <immintrin.h>
    #if defined(_MSC_VER)
        // MS-specific instrinsics.
        #include <intrin.h>
    #endif
#elif defined(_UTFC_ARM)
    #include <arm_neon.h>
#endif

#define _UTFC_MAGIC_LEN 3
#define _UTFC_MAJOR 0
#define _UTFC_MINOR 0
#define _UTFC_PATCH 0
#define _UTFC_MIN_HEADER_LEN 7 // Magic(3) + Major(1) + Minor(1) + Flags(1) + Length(1)
#define _UTFC_MAX_CHAR_LEN 4
#define _UTFC_RESERVED_LEN 50
#define _UTFC_MAX_DATA_LEN (UINT32_MAX - _UTFC_RESERVED_LEN)
#define _UTFC_UNUSED_FLAG_BITS 0b11111100 // _UTFC_HEADER_FLAGS

const char _UTFC_MAGIC_BYTES[_UTFC_MAGIC_LEN] = { 'U', '8', 'C' };

typedef enum {
    /// No error.
    UTFC_ERROR_NONE,
    /// An unknown error occurred.
    UTFC_ERROR_UNKNOWN,
    /// A (re)allocation failed.
    UTFC_ERROR_OUT_OF_MEMORY,
    /// The length of your data requires too many bytes.
    /// Make sure the length of your data is less than:
    // (UINT32_MAX - _UTFC_RESERVED_LEN) bytes.
    UTFC_ERROR_TOO_MANY_BYTES,
    /// Invalid header format.
    UTFC_ERROR_INVALID_HEADER,
    /// A character contains an invalid byte.
    UTFC_ERROR_INVALID_BYTE,
} UTFC_ERROR;

typedef enum {
    /// Extended length up to 65.535 bytes.
    _UTFC_HEADER_FLAG_16_BIT_LENGTH = 0b00000001,
    /// Extended length up to 16.777.215 bytes.
    _UTFC_HEADER_FLAG_24_BIT_LENGTH = 0b00000010,
    /// Extended length up to 4.294.967.295 bytes.
    _UTFC_HEADER_FLAG_32_BIT_LENGTH = 0b00000011,
} _UTFC_HEADER_FLAGS;

typedef struct {
    uint32_t data_len;
    uint8_t error;
    uint8_t major, minor, flags;
    uint8_t len;
    char magic[_UTFC_MAGIC_LEN];
} _UTFC_HEADER;

typedef struct {
    size_t len;
    char *value;
    uint8_t error;
} UTFC_RESULT;

/* ==================== #!PRIVATE!# ==================== */

static bool _utfc_next_non_ascii(const char *value, size_t len, size_t idx, size_t *out) {
    if (idx >= len) {
        return false;
    }

    size_t pos = idx;

#if defined(UTFC_SIMD_512) && defined(_UTFC_X86) && defined(_UTFC_64BIT) && defined(__AVX512BW__)
    while ((pos + 64) <= len) {
        const __m512i vec = _mm512_loadu_si512((const __m512i *)&value[pos]);
        const uint64_t mask = _mm512_movepi8_mask(vec);
        if (mask != 0) {
        #if defined(_MSC_VER)
            if (_BitScanForward64(out, mask) != 0) {
                return false;
            }
        #else
            *out = __builtin_ctzll(mask);
        #endif
            *out += pos;
            return true;
        }

        pos += 64;
    }
#endif

#if defined(UTFC_SIMD_256) && defined(_UTFC_X86) && defined(__AVX2__)
    while ((pos + 32) <= len) {
        const __m256i vec = _mm256_loadu_si256((const __m256i *)&value[pos]);
        const uint32_t mask = _mm256_movemask_epi8(vec);
        if (mask != 0) {
        #if defined(_MSC_VER)
            if (_BitScanForward(out, mask) != 0) {
                return false;
            }
        #else
            *out = __builtin_ctz(mask);
        #endif
            *out += pos;
            return true;
        }

        pos += 32;
    }
#endif

#if defined(UTFC_SIMD_128) && ((defined(_UTFC_X86) && defined(__SSE2__)) || defined(_UTFC_ARM))
    while ((pos + 16) <= len) {
    #if defined(_UTFC_X86)
        const __m128i vec = _mm_loadu_si128((const __m128i *)&value[pos]);
        const uint16_t mask = _mm_movemask_epi8(vec);
    #else
        const uint8x16_t vec = vld1q_u8((const uint8_t *)&value[pos]);
        // Right-shift each 8-bit element by 7,
        // effectively extracting the MSB into the LSB.
        const uint8x16_t msbs = vshrq_n_u8(vec, 7);
        // Reinterpret 16x8-bit elements as 2x64-bit elements.
        uint64x2_t bits = vreinterpretq_u64_u8(msbs);
        // The bits B are shifted to the right by C and accumulated with A.
        bits = vsraq_n_u64(bits, bits, 7);
        bits = vsraq_n_u64(bits, bits, 14);
        bits = vsraq_n_u64(bits, bits, 28);
        // Reinterpret 2x64-bit elements as 16x8-bit elements.
        const uint8x16_t output = vreinterpretq_u8_u64(bits);
        // Get all MSB of the 16 bytes from index 0(low) and 8(high).
        const uint16_t mask = ((uint16_t)vgetq_lane_u8(output, 8) << 8) | (uint16_t)vgetq_lane_u8(output, 0);
    #endif
        if (mask != 0) {
        #if defined(_MSC_VER)
            if (_BitScanForward(out, mask) != 0) {
                return false;
            }
        #else
            *out = __builtin_ctz(mask);
        #endif
            *out += pos;
            return true;
        }

        pos += 16;
    }
#endif

    while (pos < len) {
        if ((value[pos] & 0x80) != 0) {
            *out = pos;
            return true;
        }
        pos += 1;
    }

    return false;
}

/**
 * Returns the byte length for the next char of a UTF-8 string.
 * 
 * Notices:
 * - The bytes from `idx` up to `idx` + `return` represent the prefix.
 * - `idx` + `return` is the index of the actual char.
 * - The `return` value 0 means that something went wrong.
 */
static uint8_t _utfc_char_len(const char *value, size_t len, size_t idx) {
    const char byte = value[idx];
    uint8_t char_len = 1;

    // Single-byte character
    if ((byte & 0x80) == 0) return 1;
    // Two-byte character
    else if ((byte & 0xE0) == 0xC0) char_len = 2;
    // Three-byte character
    else if ((byte & 0xF0) == 0xE0) char_len = 3;
    // Four-byte character
    else if ((byte & 0xF8) == 0xF0) char_len = 4;
    // Invalid start byte
    else return 0;

    if ((len - idx) < char_len) return 0;

    for (uint8_t i = 1; i < char_len; ++i) {
        if ((value[idx + i] & 0xC0) != 0x80) {
            // No valid continuation byte
            return 0;
        }
    }

    return char_len;
}

static bool _utfc_handle_ascii(UTFC_RESULT *result, const char *data, size_t len, size_t *idx) {
    size_t nna_out = 0;
    const bool nna_result = _utfc_next_non_ascii(data, len, *idx, &nna_out);
    if (nna_result) {
        // We found a non-ASCII char.
        const size_t count = (nna_out - *idx);
        memcpy(&result->value[result->len], &data[*idx], count);
        result->len += count;
        *idx += count;
        return false;
    }

    // Only ASCII chars left.
    const size_t count = (len - *idx);
    memcpy(&result->value[result->len], &data[*idx], count);
    result->len += count;
    return true;
}

static bool _utfc_write_header(UTFC_RESULT *result, size_t len) {
    uint8_t extra_length_bytes = 0;
    if (len > (UINT32_MAX ^ 0xFF000000)) {
        extra_length_bytes = _UTFC_HEADER_FLAG_32_BIT_LENGTH;
    } else if (len > UINT16_MAX) {
        extra_length_bytes = _UTFC_HEADER_FLAG_24_BIT_LENGTH;
    } else if (len > UINT8_MAX) {
        extra_length_bytes = _UTFC_HEADER_FLAG_16_BIT_LENGTH;
    }

    const size_t value_len = _UTFC_MIN_HEADER_LEN + extra_length_bytes + len;
    result->value = (char *)malloc(value_len);
    if (result->value == NULL) {
        result->error = UTFC_ERROR_OUT_OF_MEMORY;
        return false;
    }

    // Write magic
    memcpy(&result->value[result->len], _UTFC_MAGIC_BYTES, _UTFC_MAGIC_LEN);
    result->len += _UTFC_MAGIC_LEN;

    // Write major
    result->value[result->len++] = _UTFC_MAJOR;

    // Write minor
    result->value[result->len++] = _UTFC_MINOR;

    // Write flags
    uint8_t flags = 0;
    flags |= extra_length_bytes; // 000000xx
    result->value[result->len++] = flags;

    // Write length of decompressed data
    result->value[result->len++] = (char)len;
    if (extra_length_bytes == _UTFC_HEADER_FLAG_16_BIT_LENGTH) {
        result->value[result->len++] = (char)(len >> 8);
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_24_BIT_LENGTH) {
        result->value[result->len++] = (char)(len >> 8);
        result->value[result->len++] = (char)(len >> 16);
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_32_BIT_LENGTH) {
        result->value[result->len++] = (char)(len >> 8);
        result->value[result->len++] = (char)(len >> 16);
        result->value[result->len++] = (char)(len >> 24);
    }
    
    return true;
}

static _UTFC_HEADER _utfc_read_header(const char *data, size_t len) {
    _UTFC_HEADER header = { 0 };
    if (len < _UTFC_MIN_HEADER_LEN) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    if (memcmp(data, _UTFC_MAGIC_BYTES, 3) != 0) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }
    memcpy(header.magic, data, 3);

    header.major = data[3];
    header.minor = data[4];

    // Should we allow higher versions?
    if (header.major > _UTFC_MAJOR || header.minor > _UTFC_MINOR) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    header.flags = data[5];
    // Something important may be missing.
    // We should only allow older versions with the same possible flags.
    if ((header.flags & _UTFC_UNUSED_FLAG_BITS) != 0) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    header.data_len = (uint32_t)data[6] & 0xFF;

    uint8_t extra_length_bytes = header.flags & 0b11;
    if (extra_length_bytes == _UTFC_HEADER_FLAG_16_BIT_LENGTH) {
        header.data_len |= ((uint32_t)data[7] & 0xFF) << 8;
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_24_BIT_LENGTH) {
        header.data_len |= ((uint32_t)data[7] & 0xFF) << 8;
        header.data_len |= ((uint32_t)data[8] & 0xFF) << 16;
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_32_BIT_LENGTH) {
        header.data_len |= ((uint32_t)data[7] & 0xFF) << 8;
        header.data_len |= ((uint32_t)data[8] & 0xFF) << 16;
        header.data_len |= ((uint32_t)data[9] & 0xFF) << 24;
    }

    uint8_t total_header_length = (_UTFC_MIN_HEADER_LEN + extra_length_bytes);
    header.len = total_header_length;

    return header;
}

/* ==================== #!PUBLIC!# ==================== */

void utfc_result_deinit(UTFC_RESULT *result) {
    if (result != NULL && result->value != NULL) {
        free(result->value);
        result->value = NULL;
    }
}

UTFC_RESULT utfc_compress(const char *data, size_t len) {
    UTFC_RESULT result = { 0 };
    
    if (len > _UTFC_MAX_DATA_LEN) {
        result.error = UTFC_ERROR_TOO_MANY_BYTES;
        return result;
    }

    if (!_utfc_write_header(&result, len)) {
        return result;
    }

    char *cached_prefix = NULL;
    uint8_t cached_prefix_len = 0;

    size_t read_pos = 0;
    while (read_pos < len) {
        const uint8_t char_len = _utfc_char_len(data, len, read_pos);
        if (char_len == 0) {
            // Something is wrong with the next character, so we return
            // the maximum of 4 checked bytes as the value to check them.
            result.error = UTFC_ERROR_INVALID_BYTE;

            // No longer needed.
            // Instead, we use the pointer starting at `read_pos` for data.
            free(result.value);

            size_t remaining_bytes = (len - read_pos);
            if (remaining_bytes > _UTFC_MAX_CHAR_LEN) {
                remaining_bytes = _UTFC_MAX_CHAR_LEN;
            }
            result.len = remaining_bytes;
            result.value = (char *)&data[read_pos];

            return result;
        }
        const uint8_t prefix_len = (char_len - 1);

        if (prefix_len > 0) {
            bool prefix_changed = (prefix_len != cached_prefix_len);

            // If the length is not different, we check if the bytes are identical.
            if (!prefix_changed) {
                if (memcmp(cached_prefix, &data[read_pos], prefix_len) != 0) {
                    prefix_changed = true;
                }
            }

            // When we have a new prefix, it is cached and written.
            if (prefix_changed) {
                cached_prefix = (char *)&data[read_pos];
                cached_prefix_len = prefix_len;

                memcpy(&result.value[result.len], &data[read_pos], prefix_len);
                result.len += prefix_len;
            }

            read_pos += prefix_len;
        } else if ((read_pos + 1) < len && (data[read_pos + 1] & 0x80) == 0) {
            const bool ha_result = _utfc_handle_ascii(&result, data, len, &read_pos);
            if (ha_result) break;
            continue;
        }

        result.value[result.len++] = data[read_pos++];
    }

    char *resized_value = (char *)realloc(result.value, result.len);
    if (resized_value != NULL) {
        result.value = resized_value;
    }

    return result;
}

/**
 * Notes:
 * - `return.len` contains only the written bytes, not the possible '\0' at the end.
 */
UTFC_RESULT utfc_decompress(const char *data, size_t len, bool terminate) {
    UTFC_RESULT result = { 0 };
    _UTFC_HEADER header = _utfc_read_header(data, len);
    if (header.error != UTFC_ERROR_NONE) {
        result.error = header.error;
        return result;
    }

    // If terminate = 1 we allocate one more to terminate it with a '\0'.
    result.value = (char *)malloc(header.data_len + (terminate == false ? 0 : 1));
    if (result.value == NULL) {
        result.error = UTFC_ERROR_OUT_OF_MEMORY;
        return result;
    }

    char *cached_prefix = NULL;
    uint8_t cached_prefix_len = 0;

    size_t read_pos = header.len;
    while ((read_pos < len) && (result.len < header.data_len)) {
        // 0:   cached_prefix + value
        // 1:   ASCII (no prefix)
        // 2-4: new prefix + value
        const uint8_t char_len = _utfc_char_len(data, len, read_pos);
        if (char_len == 1) {
            // If the next byte is also ASCII, we use SIMD to find the next
            // non-ASCII byte and efficiently copy everything up to that index.
            if ((read_pos + 1) < len && (data[read_pos + 1] & 0x80) == 0) {
                const bool ha_result = _utfc_handle_ascii(&result, data, len, &read_pos);
                if (ha_result) return result;
                continue;
            }
        }
        
        if (char_len > 1) {
            cached_prefix = (char *)&data[read_pos];
            cached_prefix_len = char_len - 1;
            read_pos += cached_prefix_len;
        }

        if (char_len != 1) {
            memcpy(&result.value[result.len], cached_prefix, cached_prefix_len);
            result.len += cached_prefix_len;
        }

        result.value[result.len++] = data[read_pos++];
    }

    return result;
}

#endif // !defined(UTFC_H)