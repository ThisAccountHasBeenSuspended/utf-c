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
    #define UTFC__X86 1
    #if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64) || defined(_M_AMD64)
        #define UTFC__64BIT 1
    #endif
#elif defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64) || (defined(_M_ARM) && defined(_M_ARM_NEON))
    #define UTFC__ARM 1
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#if defined(UTFC__X86)
    // Instructions for SSE|AVX.
    #include <immintrin.h>
    #if defined(_MSC_VER)
        // MS-specific instrinsics.
        #include <intrin.h>
    #endif
#elif defined(UTFC__ARM)
    #include <arm_neon.h>
#endif

#define UTFC__MAGIC_LEN 3
#define UTFC__MAJOR 0
#define UTFC__MINOR 0
#define UTFC__PATCH 0
#define UTFC__MIN_HEADER_LEN 7 // Magic(3) + Major(1) + Minor(1) + Flags(1) + Length(1)
#define UTFC__MAX_CHAR_LEN 4
#define UTFC__RESERVED_LEN 50
#define UTFC__MAX_DATA_LEN (UINT32_MAX - UTFC__RESERVED_LEN)

static const char UTFC__MAGIC_BYTES[] = { 'U', '8', 'C' };

enum {
    /// No error.
    UTFC_ERROR_NONE,
    /// An unknown error occurred.
    UTFC_ERROR_UNKNOWN,
    /// A (re)allocation failed.
    UTFC_ERROR_OUT_OF_MEMORY,
    /// Your string length requires too many bytes.
    /// Make sure your string length is less than:
    // (UINT32_MAX - UTFC__RESERVED_LEN) bytes.
    UTFC_ERROR_TOO_MANY_BYTES,
    /// Invalid header format.
    UTFC_ERROR_INVALID_HEADER,
    /// A character contains an invalid byte.
    UTFC_ERROR_INVALID_BYTE,
};

enum {
    /// No additional bytes.
    /// The maximum length is 255 bytes (8 bits).
    UTFC__EXTRA_LENGTH_BYTES_0 = 0,
    /// 1 additional byte (8 bits) for the length.
    /// The maximum length is 65.535 bytes (16 bits).
    UTFC__EXTRA_LENGTH_BYTES_1 = 1,
    /// 2 additional bytes (16 bits) for the length.
    /// The maximum length is 16.777.215 bytes (24 bits).
    UTFC__EXTRA_LENGTH_BYTES_2 = 2,
    /// 3 additional bytes (24 bits) for the length.
    /// The maximum length is (4.294.967.295 - UTFC__RESERVED_LEN) bytes (32 bits).
    UTFC__EXTRA_LENGTH_BYTES_3 = 3,
};

typedef struct {
    uint32_t data_len;
    uint8_t error;
    uint8_t minor, flags;
    uint8_t len;
} UTFC__HEADER;

typedef struct {
    size_t len;
    char *value;
    uint8_t error;
} UTFC_RESULT;

/* ==================== #!PRIVATE!# ==================== */

static bool utfc__next_non_ascii(const char *value, size_t len, size_t idx, size_t *out) {
    if (idx >= len) {
        return false;
    }

    size_t pos = idx;

#if defined(UTFC_SIMD_512) && defined(UTFC__X86) && defined(UTFC__64BIT) && defined(__AVX512BW__)
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

#if defined(UTFC_SIMD_256) && defined(UTFC__X86) && defined(__AVX2__)
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

#if defined(UTFC_SIMD_128) && ((defined(UTFC__X86) && defined(__SSE2__)) || defined(UTFC__ARM))
    while ((pos + 16) <= len) {
    #if defined(UTFC__X86)
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
static uint8_t utfc__char_len(const char *value, size_t len, size_t idx) {
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

/**
 * This function searches for the next non-ASCII char and writes everything up to that index.
 */
static bool utfc__handle_ascii(UTFC_RESULT *result, const char *data, size_t len, size_t *idx) {
    size_t nna_out = 0;
    const bool nna_result = utfc__next_non_ascii(data, len, *idx, &nna_out);
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

static bool utfc__write_header(UTFC_RESULT *result, size_t len) {
    uint8_t extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_0;
    if (len > (UINT32_MAX ^ 0xFF000000)) {
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_3;
    } else if (len > UINT16_MAX) {
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_2;
    } else if (len > UINT8_MAX) {
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_1;
    }

    const size_t value_len = UTFC__MIN_HEADER_LEN + extra_length_bytes + len;
    result->value = (char *)malloc(value_len);
    if (result->value == NULL) {
        result->error = UTFC_ERROR_OUT_OF_MEMORY;
        return false;
    }

    // Write magic
    memcpy(&result->value[result->len], UTFC__MAGIC_BYTES, UTFC__MAGIC_LEN);
    result->len += UTFC__MAGIC_LEN;

    // Write major
    result->value[result->len++] = UTFC__MAJOR;

    // Write minor
    result->value[result->len++] = UTFC__MINOR;

    // Write flags
    uint8_t flags = 0;
    flags |= extra_length_bytes; // 000000xx
    result->value[result->len++] = flags;

    // Write length of decompressed data
    result->value[result->len++] = (char)len;
    if (extra_length_bytes == UTFC__EXTRA_LENGTH_BYTES_1) {
        result->value[result->len++] = (char)(len >> 8);
    } else if (extra_length_bytes == UTFC__EXTRA_LENGTH_BYTES_2) {
        result->value[result->len++] = (char)(len >> 8);
        result->value[result->len++] = (char)(len >> 16);
    } else if (extra_length_bytes == UTFC__EXTRA_LENGTH_BYTES_3) {
        result->value[result->len++] = (char)(len >> 8);
        result->value[result->len++] = (char)(len >> 16);
        result->value[result->len++] = (char)(len >> 24);
    }
    
    return true;
}

static UTFC__HEADER utfc__read_header(const char *data, size_t len) {
    UTFC__HEADER header = { 0 };
    if (len < UTFC__MIN_HEADER_LEN) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    if (memcmp(data, UTFC__MAGIC_BYTES, 3) != 0) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    const uint8_t major = data[3];
    if (major != UTFC__MAJOR) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    header.minor = data[4];
    if (header.minor > UTFC__MINOR) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    header.flags = data[5];
    uint8_t extra_length_bytes = (header.flags & 0b11);
    if (len < (size_t)(UTFC__MIN_HEADER_LEN + extra_length_bytes)) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    header.data_len = (uint32_t)data[6] & 0xFF;
    if (extra_length_bytes == UTFC__EXTRA_LENGTH_BYTES_1) {
        header.data_len |= ((uint32_t)data[7] & 0xFF) << 8;
    } else if (extra_length_bytes == UTFC__EXTRA_LENGTH_BYTES_2) {
        header.data_len |= ((uint32_t)data[7] & 0xFF) << 8;
        header.data_len |= ((uint32_t)data[8] & 0xFF) << 16;
    } else if (extra_length_bytes == UTFC__EXTRA_LENGTH_BYTES_3) {
        header.data_len |= ((uint32_t)data[7] & 0xFF) << 8;
        header.data_len |= ((uint32_t)data[8] & 0xFF) << 16;
        header.data_len |= ((uint32_t)data[9] & 0xFF) << 24;
    }

    uint8_t header_length = (UTFC__MIN_HEADER_LEN + extra_length_bytes);
    header.len = header_length;

    return header;
}

/* ==================== #!PUBLIC!# ==================== */

inline void utfc_result_deinit(UTFC_RESULT *result) {
    if (
        result != NULL                   &&
        // No allocated memory in case of failure.
        result->error == UTFC_ERROR_NONE &&
        result->value != NULL
    ) {
        result->len = 0;
        free(result->value);
        result->value = NULL;
    }
}

/**
 * Notes:
 * - `result.len` contains the entire length of `result.value`.
 */
UTFC_RESULT utfc_compress(const char *data, size_t len) {
    UTFC_RESULT result = { 0 };
    
    if (len > UTFC__MAX_DATA_LEN) {
        result.error = UTFC_ERROR_TOO_MANY_BYTES;
        return result;
    }

    if (!utfc__write_header(&result, len)) {
        return result;
    }

    char *cached_prefix = NULL;
    uint8_t cached_prefix_len = 0;

    size_t read_pos = 0;
    while (read_pos < len) {
        const uint8_t char_len = utfc__char_len(data, len, read_pos);
        if (char_len == 0) {
            // Something is wrong with the next char, so we return
            // the maximum of 4 checked bytes as the value to check them.
            result.error = UTFC_ERROR_INVALID_BYTE;

            // No longer needed.
            // Instead, we use the pointer starting at `read_pos`.
            free(result.value);

            size_t remaining_bytes = (len - read_pos);
            if (remaining_bytes > UTFC__MAX_CHAR_LEN) {
                remaining_bytes = UTFC__MAX_CHAR_LEN;
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
        }
        // If the next byte is also ASCII, we use SIMD to find the next
        // non-ASCII byte and efficiently copy everything up to that index.
        else if ((read_pos + 1) < len && (data[read_pos + 1] & 0x80) == 0) {
            const bool ha_result = utfc__handle_ascii(&result, data, len, &read_pos);
            if (ha_result) break;
            continue;
        }

        result.value[result.len++] = data[read_pos++];
    }

    const char *resized_value = (const char *)realloc(result.value, result.len);
    if (resized_value != NULL) {
        result.value = (char *)resized_value;
    }

    return result;
}

/**
 * Notes:
 * - `terminate` adds a '\0' at the end.
 * - `return.len` contains only the written bytes, not the possible '\0' at the end.
 */
UTFC_RESULT utfc_decompress(const char *data, size_t len, bool terminate) {
    UTFC_RESULT result = { 0 };
    UTFC__HEADER header = utfc__read_header(data, len);
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
        const uint8_t char_len = utfc__char_len(data, len, read_pos);
        if (char_len == 1) {
            // If the next byte is also ASCII, we use SIMD to find the next
            // non-ASCII byte and efficiently copy everything up to that index.
            if ((read_pos + 1) < len && (data[read_pos + 1] & 0x80) == 0) {
                const bool ha_result = utfc__handle_ascii(&result, data, len, &read_pos);
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