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

#if defined(__x86_64__) || defined(_M_X64) || defined(_M_AMD64) || defined(__i386__) || defined(_M_IX86)
    #define UTFC__X86 1
    #if defined(__BMI__) || (defined(_MSC_VER) && defined(__AVX2__))
        #define UTFC__BMI_INTRINSICS 1
    #endif
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__arm__) || defined(_M_ARM)
    #define UTFC__ARM 1
#endif

#if !defined(UTFC_64BIT)
    #if defined(__LP64__) || defined(_WIN64)
        #define UTFC_64BIT 1
    #endif
#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#if defined(_MSC_VER)
    #include <intrin.h>
#endif

#if defined(UTFC__X86)
    #include <immintrin.h>
#elif defined(UTFC__ARM)
    #include <arm_neon.h>
#endif

#define UTFC__MAGIC_LEN 3
#define UTFC__MAJOR 0
#define UTFC__MINOR 2
#define UTFC__PATCH 0
#define UTFC__MIN_HEADER_LEN 7 // Magic(3) + Major(1) + Minor(1) + Flags(1) + Length(1)
#define UTFC__MAX_CHAR_LEN 4
#define UTFC__RESERVED_LEN 500
#define UTFC__MAX_PAYLOAD_LEN (UINT32_MAX - UTFC__RESERVED_LEN)
// This is the minimum value of various prefixes for a reduction.
// A value below 5 is inefficient and not recommended.
// To disable "Prefix reducer", set the value to `UINT32_MAX` or higher.
#if !defined(UTFC__PREFIX_REDUCER_THRESHOLD)
    #define UTFC__PREFIX_REDUCER_THRESHOLD 5
#endif
// This is the limit of different prefixes that can be selected for sorting.
#if !defined(UTFC__PREFIX_REDUCER_STACK_LIMIT)
    #define UTFC__PREFIX_REDUCER_STACK_LIMIT 24
#elif (UTFC__PREFIX_REDUCER_STACK_LIMIT == 0) || (UTFC__PREFIX_REDUCER_STACK_LIMIT > 48)
    #warning "`UTFC__PREFIX_REDUCER_STACK_LIMIT` is invalid and has been changed to `32`"
    #undef UTFC__PREFIX_REDUCER_STACK_LIMIT
    #define UTFC__PREFIX_REDUCER_STACK_LIMIT 32
#endif
#define UTFC__MAX_PREFIX_MARKERS 13

static const char UTFC__MAGIC_BYTES[] = { 'U', '8', 'C' };
/// Guaranteed unused bytes in UTF-8. (Perfect for markers)
static const char UTFC__PREFIX_MARKERS[UTFC__MAX_PREFIX_MARKERS] = { 0xC0, 0xC1, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };

enum {
    UTFC__HEADER_IDX_MAGIC1 = 0,
    UTFC__HEADER_IDX_MAGIC2 = 1,
    UTFC__HEADER_IDX_MAGIC3 = 2,
    UTFC__HEADER_IDX_MAJOR  = 3,
    UTFC__HEADER_IDX_MINOR  = 4,
    UTFC__HEADER_IDX_FLAGS  = 5,
    UTFC__HEADER_IDX_LENGTH = 6,
};

enum {
    /// No error.
    UTFC_ERROR_NONE,
    /// An unknown error occurred.
    UTFC_ERROR_UNKNOWN,
    /// A (re)allocation failed.
    UTFC_ERROR_OUT_OF_MEMORY,
    /// Your string length requires too many bytes.
    /// - For compression the limit is: `UINT32_MAX - UTFC__RESERVED_LEN`
    /// - For decompression the limit is: `UINT32_MAX`
    UTFC_ERROR_TOO_MANY_BYTES,
    /// More bytes were expected.
    UTFC_ERROR_MISSING_BYTES,
    /// Invalid header format.
    UTFC_ERROR_INVALID_HEADER,
    /// An unexpected byte was found.
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

enum {
    UTFC__FLAG_EXTRA_LENGTH_BYTES_1 = 0b00000001, // 1
    UTFC__FLAG_EXTRA_LENGTH_BYTES_2 = 0b00000010, // 2
    UTFC__FLAG_PREFIX_REDUCER       = 0b00000100, // 4
    UTFC__FLAG_RESERVED4            = 0b00001000, // 8
    UTFC__FLAG_RESERVED5            = 0b00010000, // 16
    UTFC__FLAG_RESERVED6            = 0b00100000, // 32
    UTFC__FLAG_RESERVED7            = 0b01000000, // 64
    UTFC__FLAG_RESERVED8            = 0b10000000, // 128
    
    /**
     * Special flags.
     */

    UTFC__FLAG_EXTRA_LENGTH_BYTES_3 = 0b00000011, // 3
};

typedef struct {
    uint32_t payload_len;
    uint8_t error;
    uint8_t minor, flags;
    uint8_t len;
} utfc__header;

typedef struct utfc_result {
    size_t len;
    char *value;
    uint8_t error;
} utfc_result;

typedef struct {
    size_t *indices;
    size_t len, cap;
    /// A value consists of the length (maximum 3 | 8 bits)
    /// and the maximum 3 bytes of the prefix (8 bits each).
    uint32_t *values;
} utfc__prefix_map;

/* ==================== #!PRIVATE!# ==================== */

/// A helper function to count the `0` bits from the LSB to the MSB until the first `1` bit was found.
static inline uint8_t utfc__zero_bits_count(size_t mask, bool start_msb) {
    if (mask == 0) return 0;
    size_t result;
    #if defined(_MSC_VER)
        #if defined(UTFC__BMI_INTRINSICS)
            #if defined(UTFC_64BIT)
                result = (size_t)(start_msb ? _lzcnt_u64(mask) : _tzcnt_u64(mask));
            #else
                result = (size_t)(start_msb ? _lzcnt_u32(mask) : _tzcnt_u32(mask));
            #endif
        #else
            unsigned long idx;
            #if defined(UTFC_64BIT)
                unsigned char _ = (start_msb ? _BitScanReverse64(&idx, mask) : _BitScanForward64(&idx, mask));
            #else
                unsigned char _ = (start_msb ? _BitScanReverse(&idx, mask) : _BitScanForward(&idx, mask));
            #endif
            result = (size_t)idx;
        #endif
    #else
        #if defined(UTFC_64BIT)
            result = (size_t)(start_msb ? __builtin_clzll(mask) : __builtin_ctzll(mask));
        #else
            result = (size_t)(start_msb ? __builtin_clz(mask) : __builtin_ctz(mask));
        #endif
    #endif
    return (uint8_t)result;
}

static bool utfc__prefix_map_init(utfc__prefix_map *map) {
    if (map->cap > 0) return true; // Already initialized

    uint32_t *tmp_values = (uint32_t *)malloc(5 * sizeof(*tmp_values));
    if (tmp_values == NULL) return false;

    size_t *tmp_indices = (size_t *)malloc(5 * sizeof(*tmp_indices));
    if (tmp_indices == NULL) {
        if (tmp_values != NULL) free(tmp_values);
        return false;
    }

    map->values = tmp_values;
    map->indices = tmp_indices;
    map->cap = 5;
    return true;
}

static void utfc__prefix_map_deinit(utfc__prefix_map *map) {
    map->cap = 0;
    if (map->values != NULL) {
        free(map->values);
        map->values = NULL;
    }
    if (map->indices != NULL) {
        free(map->indices);
        map->indices = NULL;
    }
    map->len = 0;
}

static inline uint32_t utfc__prefix_pack(const char *prefix, uint8_t len) {
    uint32_t result = 0;
    memcpy(&result, prefix, 3);
    result |= ((uint32_t)len << 24);
    return result;
}

static inline void utfc__prefix_unpack(uint32_t value, char *prefix_out, uint8_t *len_out) {
    *len_out = (uint8_t)(value >> 24);
    memcpy(prefix_out, &value, 3);
}

static void utfc__prefix_map_add(utfc__prefix_map *map, const char *prefix, uint8_t len, size_t idx) {
    if (map->cap == 0) return; // Not initialized

    if (map->len == map->cap) {
        uint32_t *tmp_values = (uint32_t *)realloc(map->values, ((map->cap + 5) * sizeof(*tmp_values)));
        if (tmp_values == NULL) return;
        map->values = tmp_values;

        size_t *tmp_indices = (size_t *)realloc(map->indices, ((map->cap + 5) * sizeof(*tmp_indices)));
        if (tmp_indices == NULL) return;
        map->indices = tmp_indices;

        map->cap += 5;
    }

    uint32_t value = utfc__prefix_pack(prefix, len);
    map->values[map->len] = value;
    map->indices[map->len] = idx;
    map->len++;
}

static bool utfc__next_non_ascii(const char *value, size_t len, size_t idx, size_t *out) {
    if (idx >= len) return false;

#if defined(UTFC_SIMD_512) && defined(UTFC__X86) && defined(UTFC_64BIT) && defined(__AVX512BW__)
    while ((idx + 64) <= len) {
        const __m512i vec = _mm512_loadu_si512((const __m512i *)&value[idx]);
        const uint64_t mask = _mm512_movepi8_mask(vec);
        if (mask != 0) {
            *out = (size_t)utfc__zero_bits_count((size_t)mask, false);
            *out += idx;
            return true;
        }

        idx += 64;
    }
#endif

#if defined(UTFC_SIMD_256) && defined(UTFC__X86) && defined(__AVX2__)
    while ((idx + 32) <= len) {
        const __m256i vec = _mm256_loadu_si256((const __m256i *)&value[idx]);
        const uint32_t mask = _mm256_movemask_epi8(vec);
        if (mask != 0) {
            *out = (size_t)utfc__zero_bits_count((size_t)mask, false);
            *out += idx;
            return true;
        }

        idx += 32;
    }
#endif

#if defined(UTFC_SIMD_128) && ((defined(UTFC__X86) && defined(__SSE2__)) || defined(UTFC__ARM))
    while ((idx + 16) <= len) {
    #if defined(UTFC__X86)
        const __m128i vec = _mm_loadu_si128((const __m128i *)&value[idx]);
        const uint16_t mask = _mm_movemask_epi8(vec);
    #else
        const uint8x16_t vec = vld1q_u8((const uint8_t *)&value[idx]);
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
            *out = (size_t)utfc__zero_bits_count((size_t)mask, false);
            *out += idx;
            return true;
        }

        idx += 16;
    }
#endif

    while (idx < len) {
        if ((value[idx] & 0x80) != 0) {
            *out = idx;
            return true;
        }
        idx += 1;
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

    // Do that many bytes even exist?
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
static bool utfc__handle_ascii(utfc_result *result, const char *data, size_t len, size_t *idx) {
    size_t nna_out = 0;
    if (utfc__next_non_ascii(data, len, *idx, &nna_out)) {
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

static bool utfc__write_header(utfc_result *result, size_t len) {
    uint8_t extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_0; // Up to 8  bits
    if (len > (UINT32_MAX ^ 0xFF000000)) { // ----------------- Up to 32 bits
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_3;
    } else if (len > UINT16_MAX) { // ------------------------- Up to 24 bits
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_2;
    } else if (len > UINT8_MAX) { // -------------------------- Up to 16 bits
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_1;
    }

    const size_t value_len = UTFC__MIN_HEADER_LEN + extra_length_bytes + len;
    result->value = (char *)malloc(value_len * sizeof(*result->value));
    if (result->value == NULL) {
        result->error = UTFC_ERROR_OUT_OF_MEMORY;
        return false;
    }
    result->len = UTFC__MIN_HEADER_LEN;

    // Write magic.
    memcpy(result->value, UTFC__MAGIC_BYTES, UTFC__MAGIC_LEN);

    // Write major.
    result->value[UTFC__HEADER_IDX_MAJOR] = UTFC__MAJOR;

    // Write minor.
    result->value[UTFC__HEADER_IDX_MINOR] = UTFC__MINOR;

    // Write flags.
    char flags = 0;
    flags |= extra_length_bytes; // 000000xx
    result->value[UTFC__HEADER_IDX_FLAGS] = flags;

    // Write length of decompressed payload.
    result->value[UTFC__HEADER_IDX_LENGTH] = (char)len;
    if (extra_length_bytes >= UTFC__EXTRA_LENGTH_BYTES_1)
        result->value[result->len++] = (char)(len >> 8);
    if (extra_length_bytes >= UTFC__EXTRA_LENGTH_BYTES_2)
        result->value[result->len++] = (char)(len >> 16);
    if (extra_length_bytes >= UTFC__EXTRA_LENGTH_BYTES_3)
        result->value[result->len++] = (char)(len >> 24);
    
    return true;
}

static utfc__header utfc__read_header(const char *data, size_t len) {
    utfc__header header = { 0 };
    if (len < UTFC__MIN_HEADER_LEN) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    // Check magic.
    if (memcmp(data, UTFC__MAGIC_BYTES, UTFC__MAGIC_LEN) != 0) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    // Check major.
    const uint8_t major = data[UTFC__HEADER_IDX_MAJOR];
    if (major != UTFC__MAJOR) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    // Check minor.
    header.minor = data[UTFC__HEADER_IDX_MINOR];
    if (header.minor > UTFC__MINOR) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    // Check flags.
    header.flags = data[UTFC__HEADER_IDX_FLAGS];
    const uint8_t extra_length_bytes = (header.flags & UTFC__FLAG_EXTRA_LENGTH_BYTES_3);
    if (len < (size_t)(UTFC__MIN_HEADER_LEN + extra_length_bytes)) {
        header.error = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    // Determine the payload length.
    header.payload_len = (uint32_t)data[UTFC__HEADER_IDX_LENGTH] & 0xFF;
    if (extra_length_bytes >= UTFC__EXTRA_LENGTH_BYTES_1)
        header.payload_len |= ((uint32_t)data[UTFC__HEADER_IDX_LENGTH + 1] & 0xFF) << 8;
    if (extra_length_bytes >= UTFC__EXTRA_LENGTH_BYTES_2)
        header.payload_len |= ((uint32_t)data[UTFC__HEADER_IDX_LENGTH + 2] & 0xFF) << 16;
    if (extra_length_bytes >= UTFC__EXTRA_LENGTH_BYTES_3)
        header.payload_len |= ((uint32_t)data[UTFC__HEADER_IDX_LENGTH + 3] & 0xFF) << 24;

    // The total length of the header.
    // (We start the decompression at this index)
    uint8_t header_length = (UTFC__MIN_HEADER_LEN + extra_length_bytes);
    header.len = header_length;

    return header;
}

static void utfc__pick_prefix_values(const utfc__prefix_map *prefix_map, uint32_t *out, uint8_t *out_len) {
    // NOTE: The minimum `value_count` for an element should be `3`.
    // (A value below 3 is too inefficient)

    uint8_t max_values = prefix_map->len;
    if (max_values > UTFC__PREFIX_REDUCER_STACK_LIMIT) {
        max_values = UTFC__PREFIX_REDUCER_STACK_LIMIT;
    }

    size_t value_count[UTFC__PREFIX_REDUCER_STACK_LIMIT] = { 0 };

    // Pick new prefixes and count.
    for (size_t i = 0; i < prefix_map->len && *out_len < max_values; i++) {
        const uint32_t value = prefix_map->values[i];

        bool found = false;
        for (uint8_t j = 0; j < *out_len; ++j) {
            if (out[j] == value) {
                value_count[j]++;
                found = true;
                break;
            }
        }

        if (!found) {
            value_count[*out_len] = 1;
            out[*out_len] = value;
            *out_len += 1;
        }
    }

    // Sort in descending order.
    for (uint8_t i = 0; (i + 1) < *out_len; ++i) {
        // Best ...
        uint8_t bi = i;              // index
        size_t bvc = value_count[i]; // value_count
        uint8_t bl = (out[i] >> 24); // length
        size_t bs = SIZE_MAX;        // score
        if ((size_t)bl < (SIZE_MAX / bvc)) {
            bs = (size_t)(bl * bvc);
        }

        // Find the best element after index `i`.
        for (uint8_t j = (i + 1); j < *out_len; ++j) {
            const size_t jvc = value_count[j];
            if (jvc < 3) continue;

            const uint8_t jl = (out[j] >> 24);
            size_t js = SIZE_MAX;
            if ((size_t)jl < (SIZE_MAX / jvc)) {
                js = (size_t)(jl * jvc);
            }

            // Either a higher score or the same with a longer prefix.
            if (js > bs || (js == bs && jl > bl)) {
                bi = j;
                bvc = jvc;
                bl = jl;
                bs = js;
            }
        }

        // We swap the position of the best element with the current one.
        if (bi != i) {
            // Swap count
            size_t tmp_count = value_count[i];
            value_count[i] = bvc;
            value_count[bi] = tmp_count;
            // Swap value
            uint32_t tmp_value = out[i];
            out[i] = out[bi];
            out[bi] = tmp_value;
        }
    }

    // We cannot exceed the limit.
    if (*out_len > UTFC__MAX_PREFIX_MARKERS) {
        *out_len = UTFC__MAX_PREFIX_MARKERS;
    }

    // After sorting, we only want prefixes with a `value_count` of at least 3.
    for (uint8_t i = 0; i < *out_len; i++) {
        if (value_count[i] < 3) {
            *out_len = i;
            break;
        }
    }
}

static bool utfc__prefix_reducer(utfc_result *result, const utfc__prefix_map *prefix_map) {
    if (prefix_map->len < UTFC__PREFIX_REDUCER_THRESHOLD) return true;

    uint32_t picked_values[UTFC__PREFIX_REDUCER_STACK_LIMIT] = { 0 };
    uint8_t picked_values_len = 0;
    utfc__pick_prefix_values(prefix_map, picked_values, &picked_values_len);
    if (picked_values_len == 0) return false;

    // Set header flag.
    result->value[UTFC__HEADER_IDX_FLAGS] |= UTFC__FLAG_PREFIX_REDUCER;

    /* ====== REMOVE ====== */
    size_t removed_bytes = 0;
    for (size_t i = prefix_map->len; i-- > 0;) {
        int8_t marker = -1;
        for (uint8_t j = 0; j < picked_values_len; j++) {
            if (picked_values[j] == prefix_map->values[i]) {
                marker = j;
                break;
            }
        }

        if (marker != -1) {
            const uint32_t val = prefix_map->values[i];
            const size_t idx = prefix_map->indices[i];

            // The length is located in the high 8 bits of the value.
            const uint8_t val_len = (uint8_t)(val >> 24);

            // Change first prefix byte to marker.
            result->value[idx] = UTFC__PREFIX_MARKERS[marker];

            const size_t move_len = (result->len - (idx + val_len));
            memmove(&result->value[idx + 1], &result->value[idx + val_len], move_len);
            removed_bytes += (val_len - 1);
        }
    }
    result->len -= removed_bytes;

    /* ====== ADD ====== */
    const uint8_t header_len = UTFC__MIN_HEADER_LEN + (result->value[UTFC__HEADER_IDX_FLAGS] & UTFC__FLAG_EXTRA_LENGTH_BYTES_3);

    // Set the byte for the length of the reduced prefixes directly after the header.
    memmove(&result->value[header_len + 1], &result->value[header_len], (result->len - header_len));
    result->len += 1;
    result->value[header_len] = picked_values_len;

    // A prefix consists of up to 3 bytes.
    // We add (3 * picked_values_len) to ensure sufficient capacity.
    const size_t realloc_size = (result->len + (3 * picked_values_len));
    const char *tmp_value = (char *)realloc(result->value, realloc_size * sizeof(*tmp_value));
    if (tmp_value == NULL) return false;
    result->value = (char *)tmp_value;

    for (uint8_t i = picked_values_len; i-- > 0;) {
        char prefix[3] = { 0 };
        uint8_t prefix_len = 0;
        utfc__prefix_unpack(picked_values[i], prefix, &prefix_len);

        const size_t from = (header_len + 1);
        const size_t to = (from + prefix_len);

        memmove(&result->value[to], &result->value[from], (result->len - from));
        for (uint8_t j = 0; j < prefix_len; j++) {
            result->value[from + j] = prefix[j];
        }
        result->len += prefix_len;
    }

    return true;
}

static bool utfc__compression(utfc_result *result, utfc__prefix_map *prefix_map, const char *data, size_t len) {
    size_t cached_prefix_idx = 0;
    uint8_t cached_prefix_len = 0;

    size_t read_idx = 0;
    while (read_idx < len) {
        const uint8_t char_len = utfc__char_len(data, len, read_idx);
        if (char_len == 0) {
            // Something is wrong with this char, so we return
            // the maximum of 4 checked bytes as the value to check them.

            result->error = UTFC_ERROR_INVALID_BYTE;
            const size_t remaining_bytes = (len - read_idx);
            result->len = ((remaining_bytes > UTFC__MAX_CHAR_LEN) ? UTFC__MAX_CHAR_LEN : remaining_bytes);
            memcpy(result->value, &data[read_idx], remaining_bytes);

            return false;
        }

        const uint8_t prefix_len = (char_len - 1);
        if (prefix_len > 0) {
            bool prefix_changed = (prefix_len != cached_prefix_len);

            // If the length is not different, we check if the bytes are identical.
            if (!prefix_changed) {
                if (memcmp(&data[cached_prefix_idx], &data[read_idx], prefix_len) != 0) {
                    prefix_changed = true;
                }
            }

            // When we have a new prefix, it is cached and written.
            if (prefix_changed) {
                cached_prefix_idx = read_idx;
                cached_prefix_len = prefix_len;

                utfc__prefix_map_add(prefix_map, &data[cached_prefix_idx], cached_prefix_len, result->len);

                memcpy(&result->value[result->len], &data[read_idx], prefix_len);
                result->len += prefix_len;
            }

            read_idx += prefix_len;
        }
        // If the next byte is also ASCII, we use SIMD to find the next
        // non-ASCII byte and efficiently copy everything up to that index.
        else if ((read_idx + 1) < len && (data[read_idx + 1] & 0x80) == 0) {
            if (utfc__handle_ascii(result, data, len, &read_idx)) break;
            continue;
        }

        result->value[result->len++] = data[read_idx++];
    }

    return true;
}

/* ==================== #!PUBLIC!# ==================== */

/**
 * This function should always be called after `utfc_compression`
 * and `utfc_decompression` when the result is no longer needed.
 */
inline void utfc_result_deinit(utfc_result *result) {
    result->error = UTFC_ERROR_NONE;
    result->len = 0;
    if (result != NULL) {
        free(result->value);
        result = NULL;
    }
}

/**
 * Notes:
 * - `result.len` contains the entire length of `result.value`.
 */
utfc_result utfc_compress(const char *data, size_t len) {
    utfc_result result = { 0 };
    
    if (len > UTFC__MAX_PAYLOAD_LEN) {
        result.error = UTFC_ERROR_TOO_MANY_BYTES;
        return result;
    }

    if (!utfc__write_header(&result, len)) {
        return result;
    }

    utfc__prefix_map prefix_map = { 0 };
    if (!utfc__prefix_map_init(&prefix_map)) {
        result.error = UTFC_ERROR_OUT_OF_MEMORY;
        return result;
    }

    if (utfc__compression(&result, &prefix_map, data, len)) {
        bool failed = !utfc__prefix_reducer(&result, &prefix_map);

        if (failed) {
            result.error = UTFC_ERROR_OUT_OF_MEMORY;
        } else {
            char *resized_value = (char *)realloc(result.value, result.len * sizeof(*resized_value));
            if (resized_value != NULL) result.value = resized_value;
        }
    }

    utfc__prefix_map_deinit(&prefix_map);

    return result;
}

/**
 * Notes:
 * - `terminate` adds a '\0' at the end.
 * - `return.len` contains only the written bytes, not the possible '\0' at the end.
 */
utfc_result utfc_decompress(const char *data, size_t len, bool terminate) {
    utfc_result result = { 0 };
    if (len > UINT32_MAX) {
        result.error = UTFC_ERROR_TOO_MANY_BYTES;
        return result;
    }

    utfc__header header = utfc__read_header(data, len);
    if (header.error != UTFC_ERROR_NONE) {
        result.error = header.error;
        return result;
    }

    // If terminate = 1 we allocate one more to terminate it with a '\0'.
    result.value = (char *)malloc((header.payload_len + (terminate == false ? 0 : 1)) * sizeof(*result.value));
    if (result.value == NULL) {
        result.error = UTFC_ERROR_OUT_OF_MEMORY;
        return result;
    }

    size_t read_idx = (size_t)header.len;

    // Prefix reducer.
    utfc__prefix_map map = { 0 };
    const bool use_prefix_reducer = ((data[UTFC__HEADER_IDX_FLAGS] & UTFC__FLAG_PREFIX_REDUCER) > 0);
    if (use_prefix_reducer) {
        const uint8_t prefix_count = data[read_idx++];
        if (len < (read_idx + prefix_count)) {
            result.error = UTFC_ERROR_MISSING_BYTES;
            return result;
        }

        if (!utfc__prefix_map_init(&map)) {
            result.error = UTFC_ERROR_OUT_OF_MEMORY;
            return result;
        }

        // Read all reduced prefixes and insert them into `map`.
        for (uint8_t i = 0; i < prefix_count; i++) {
            // The length can be determined from the high bits of the first byte of each prefix.
            // For example, 3 bits means that the char has 3 bytes, so the prefix must have 2 bytes.
            const uint8_t first_prefix_byte = (uint8_t)data[read_idx] & 0b11110000;
            if ((first_prefix_byte & 0xC0) != 0xC0) {
                utfc__prefix_map_deinit(&map);
                result.error = UTFC_ERROR_INVALID_BYTE;
                break;
            }
            const uint8_t shift_distance = ((sizeof(size_t) * 8) - 8);
            const size_t mask = ((size_t)(~first_prefix_byte) << shift_distance);
            const uint8_t bit_count = utfc__zero_bits_count(mask, true);
            const uint8_t prefix_len = (bit_count - 1);

            // A prefix with a length of 4 or more doesn't exist.
            if (prefix_len >= UTFC__MAX_CHAR_LEN) {
                utfc__prefix_map_deinit(&map);
                result.error = UTFC_ERROR_INVALID_BYTE;
                break;
            }

            if (len < (read_idx + prefix_len)) {
                utfc__prefix_map_deinit(&map);
                result.error = UTFC_ERROR_MISSING_BYTES;
                break;
            }

            utfc__prefix_map_add(&map, &data[read_idx], prefix_len, read_idx);
            read_idx += prefix_len;
        }
    }

    size_t cached_prefix_idx = 0;
    uint8_t cached_prefix_len = 0;
    while ((read_idx < len) && (result.len < header.payload_len)) {
        if (use_prefix_reducer) {
            const char byte = data[read_idx];
            // We should first check if the current byte is a valid marker.
            if ((byte == UTFC__PREFIX_MARKERS[0]) || (byte == UTFC__PREFIX_MARKERS[1]) || (byte >= UTFC__PREFIX_MARKERS[2])) {
                // We use a single variable for checking and the marker index.
                // `UINT8_MAX` means "not found", all other values ​​are the index.
                uint8_t reduced = UINT8_MAX;
                for (uint8_t i = 0; i < UTFC__MAX_PREFIX_MARKERS; i++) {
                    if (byte == UTFC__PREFIX_MARKERS[i]) {
                        reduced = i;
                        break;
                    }
                }

                if (reduced != UINT8_MAX) {
                    char prefix[3] = { 0 };
                    uint8_t prefix_len = 0;
                    utfc__prefix_unpack(map.values[reduced], prefix, &prefix_len);
                    cached_prefix_idx = map.indices[reduced];
                    cached_prefix_len = prefix_len;

                    memcpy(&result.value[result.len], prefix, prefix_len);
                    read_idx += 1;
                    continue;
                }
            }
        }

        // 0:   cached_prefix + value
        // 1:   ASCII (no prefix)
        // 2-4: new prefix + value
        const uint8_t char_len = utfc__char_len(data, len, read_idx);

        if (char_len == 1) {
            // If the next byte is also ASCII, we use SIMD to find the next
            // non-ASCII byte and efficiently copy everything up to that index.
            if ((read_idx + 1) < len && (data[read_idx + 1] & 0x80) == 0) {
                if (utfc__handle_ascii(&result, data, len, &read_idx)) break;
                continue;
            }
        }
        
        if (char_len > 1) {
            cached_prefix_idx = read_idx;
            cached_prefix_len = char_len - 1;
            read_idx += cached_prefix_len;
        }

        if (char_len != 1) {
            memcpy(&result.value[result.len], &data[cached_prefix_idx], cached_prefix_len);
            result.len += cached_prefix_len;
        }

        result.value[result.len++] = data[read_idx++];
    }

    utfc__prefix_map_deinit(&map);

    return result;
}

#endif // !defined(UTFC_H)