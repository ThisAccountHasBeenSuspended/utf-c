/**
 * ┌────────────────────────────────────────────────────────────────────────────────┐
 * │ MIT License                                                                    │
 * │                                                                                │
 * │ Copyright (c) 2025-2026 Nick Ilhan Atamgüc <nickatamguec@outlook.com>          │
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
 * The following example shows the result of "😂😊😑😔😭":
 * ┌────────────────────────────────────────────────────────────────────────┐
 * │  bytes: [F0 9F 98 82 F0 9F 98 8A F0 9F 98 91 F0 9F 98 94 F0 9F 98 AD]  │
 * ├────────────────────────────────────────────────────────────────────────┤
 * │                             ┌Prefix reducer                            │
 * │                             │┌──[24 bits]┬Second bit                   │
 * │                      ┌[00000XXX][32 bits]┼Both bits together           │
 * │                      │       │├─[16 bits]┴First bit                    │
 * │                      │       └┴Additional bytes & total bits of length │
 * │ ┌──────────┬───┬───┬─┴─┬────┬─────────────────────────┐                │
 * │ │ 55 38 43 │ ? │ ? │ 0 │ 20 │ F0 9F 98 82 8A 91 94 AD │                │
 * │ ├──────────┼───┴───┼───┴────┼[8 bytes]────────────────┘                │
 * │ └Magic     └Major  ├Flags   ├Payload                                   │
 * │               Minor┘  Length┘                                          │
 * └────────────────────────────────────────────────────────────────────────┘
 * 
 * Written by Nick Ilhan Atamgüc <nickatamguec@outlook.com>
 */

#if !defined(UTFC_H)
#define UTFC_H 1

#if defined(_M_IX86) || defined(_M_X64) || defined(_M_AMD64) || defined(__i386__) || defined(__x86_64__)
    #define UTFC__X86 1
    #if defined(__BMI__) || (defined(_MSC_VER) && defined(__AVX2__))
        #define UTFC__BMI_INTRINSICS 1
    #endif
#elif defined(_M_ARM) || defined(_M_ARM64) || defined(__arm__) || defined(__aarch64__)
    #define UTFC__ARM 1
#elif defined(__riscv) || defined(__riscv__)
    #define UTFC__RISCV 1
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
#elif defined(_M_ARM64) || defined(__arch64__) || defined(__ARM_NEON) || defined(__ARM_NEON__)
    #define UTFC__NEON 1
    #include <arm_neon.h>
#elif defined(__riscv_vector)
    #include <riscv_vector.h>
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
    UTFC__FLAG_EXTRA_LENGTH_BYTES_1 = 0x01, // 0b00000001
    UTFC__FLAG_EXTRA_LENGTH_BYTES_2 = 0x02, // 0b00000010
    UTFC__FLAG_EXTRA_LENGTH_BYTES_3 = 0x03, // 0b00000011 (Special)
    UTFC__FLAG_PREFIX_REDUCER       = 0x04, // 0b00000100
    UTFC__FLAG_RESERVED4            = 0x08, // 0b00001000
    UTFC__FLAG_RESERVED5            = 0x10, // 0b00010000
    UTFC__FLAG_RESERVED6            = 0x20, // 0b00100000
    UTFC__FLAG_RESERVED7            = 0x40, // 0b01000000
    UTFC__FLAG_RESERVED8            = 0x80, // 0b10000000
};

typedef struct {
    uint32_t payload_len;
    uint8_t minor, flags;
    uint8_t len;
} utfc__header;

typedef struct utfc_result {
    char *value;
    uint32_t len;
    uint8_t error;
} utfc_result;

/// Prefix map value.
typedef struct {
    uint32_t index;
    // The length (1 byte) followed by the maximum 3 bytes of the prefix.
    uint32_t value;
} utfc__prefix_map_v;

typedef struct {
    utfc__prefix_map_v *values;
    uint32_t len, cap;
} utfc__prefix_map;

/* ==================== #!PRIVATE!# ==================== */

/// A helper function to count the `0` bits from the LSB to the MSB until the first `1` bit was found.
static inline uint8_t utfc__zero_bits_count(size_t mask) {
    if (mask == 0) return 0;
    size_t result;
    #if defined(_MSC_VER)
        #if defined(UTFC__BMI_INTRINSICS)
            #if defined(UTFC_64BIT)
                result = (size_t)(_tzcnt_u64(mask));
            #else
                result = (size_t)(_tzcnt_u32(mask));
            #endif
        #else
            unsigned long idx;
            #if defined(UTFC_64BIT)
                unsigned char _ = _BitScanForward64(&idx, mask);
            #else
                unsigned char _ = _BitScanForward(&idx, mask);
            #endif
            result = (size_t)idx;
        #endif
    #else
        #if defined(UTFC_64BIT)
            result = (size_t)(__builtin_ctzll(mask));
        #else
            result = (size_t)(__builtin_ctz(mask));
        #endif
    #endif
    return (uint8_t)result;
}

static bool utfc__prefix_map_init(utfc__prefix_map *map) {
    if (map->cap > 0) return true; // Already initialized

    utfc__prefix_map_v *tmp_values = (utfc__prefix_map_v *)malloc(5 * sizeof(*tmp_values));
    if (tmp_values == NULL) return false;

    map->values = tmp_values;
    map->cap = 5;
    return true;
}

static void utfc__prefix_map_deinit(utfc__prefix_map *map) {
    map->cap = 0;
    if (map->values != NULL) {
        free(map->values);
        map->values = NULL;
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

static void utfc__prefix_map_add(utfc__prefix_map *map, const char *prefix, uint8_t len, uint32_t idx) {
    if (map->cap == 0) return; // Not initialized

    if (map->len == map->cap) {
        if (map->cap > (UINT32_MAX - 5)) return;
        const uint32_t new_cap = (map->cap + 5);
        utfc__prefix_map_v *tmp_values = (utfc__prefix_map_v *)realloc(map->values, (new_cap * sizeof(*tmp_values)));
        if (tmp_values == NULL) return;

        map->values = tmp_values;
        map->cap = new_cap;
    }

    map->values[map->len++] = (utfc__prefix_map_v){
        .index = idx,
        .value = utfc__prefix_pack(prefix, len)
    };
}

static bool utfc__next_non_ascii(const char *value, uint32_t len, uint32_t idx, uint32_t *out) {
    if (idx >= len) return false;

#if defined(UTFC_SIMD_512) && defined(UTFC__X86) && defined(UTFC_64BIT) && defined(__AVX512BW__)
    while ((idx + 64) <= len) {
        const __m512i vec = _mm512_loadu_si512((const __m512i *)&value[idx]);
        const uint64_t mask = _mm512_movepi8_mask(vec);
        if (mask != 0) {
            *out = (uint32_t)utfc__zero_bits_count((size_t)mask);
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
            *out = (uint32_t)utfc__zero_bits_count((size_t)mask);
            *out += idx;
            return true;
        }

        idx += 32;
    }
#endif

#if defined(UTFC_SIMD_128) && (defined(__SSE2__) || defined(UTFC__NEON) || defined(__riscv_vector))
    while ((idx + 16) <= len) {
        #if defined(UTFC__RISCV)
            const vuint8m1_t vec = __riscv_vle8_v_u8m1((const uint8_t *)&value[idx], 16);
            // Returns a mask in which the bit was set to 1 at each position where the value was greater than 0x7F(127).
            const vbool8_t mask = __riscv_vmsgtu_vx_u8m1_b8(vec, 0x7F, 16);
            // Starts at the index-0 and returns the index of the first 1-bit.
            const int f_idx = __riscv_vfirst_m_b8(mask, 16);
            if (f_idx >= 0) {
                *out = idx + (uint32_t)f_idx;
                return true;
            }
        #else
            #if defined(UTFC__X86)
                const __m128i vec = _mm_loadu_si128((const __m128i *)&value[idx]);
                const uint16_t mask = _mm_movemask_epi8(vec);
            #elif defined(UTFC__ARM)
                const uint8x16_t vec = vld1q_u8((const uint8_t *)&value[idx]);
                // Right-shift each byte by 7 to extract MSB into LSB.
                const uint8x16_t msbs = vshrq_n_u8(vec, 7);
                // Reinterpret as 64-bit elements (2 lanes).
                uint64x2_t bits = vreinterpretq_u64_u8(msbs);
                // Accumulate bits with shifting.
                bits = vsraq_n_u64(bits, bits, 7);
                bits = vsraq_n_u64(bits, bits, 14);
                bits = vsraq_n_u64(bits, bits, 28);
                // Reinterpret back to 8-bit elements.
                const uint8x16_t output = vreinterpretq_u8_u64(bits);
                // Extract the two bytes at positions 0(low) and 8(high).
                const uint8_t low = vgetq_lane_u8(output, 0);
                const uint8_t high = vgetq_lane_u8(output, 8);
                // Combine into 16-bit mask.
                const uint16_t mask = ((uint16_t)high << 8) | (uint16_t)low;
            #endif
            if (mask != 0) {
                *out = idx + (uint32_t)utfc__zero_bits_count((size_t)mask);
                return true;
            }
        #endif

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
 * Returns the byte length for the next character of a UTF-8 string.
 * 
 * Notices:
 * - The bytes from `idx` up to `idx` + `return` represent the prefix.
 * - `idx` + `return` is the index of the actual character.
 * - The `return` value `0` means that the first byte is invalid (continuation byte).
 * - The `return` value `-1` means that bytes are missing.
 * - The `return` value `-2` means that the continuation bytes are invalid.
 */
static int8_t utfc__char_len(const char *value, uint32_t len, uint32_t idx) {
    const char first_byte = value[idx];
    if ((first_byte & 0xC0) == 0x00) return 1; // Single-byte character
    if ((first_byte & 0xC0) == 0x80) return 0; // Invalid start byte
    const size_t mask = (size_t)(first_byte & 0xF0);
    const uint8_t bit_count = ((-utfc__zero_bits_count(mask)) & 0x07);

    // Do that many bytes even exist?
    if ((len - idx) < bit_count) return -1;

    // The `fallthrough` comment prevents a warning from the compiler,
    // because `case 3` and `case 2` are also entered when `bit_count == 4`.
    switch (bit_count) {
        case 4: if ((value[idx + 3] & 0xC0) != 0x80) return -2; // fallthrough
        case 3: if ((value[idx + 2] & 0xC0) != 0x80) return -2; // fallthrough
        case 2: if ((value[idx + 1] & 0xC0) != 0x80) return -2; // fallthrough
    }

    return bit_count;
}

/**
 * This function searches for the next non-ASCII character and writes everything up to that index.
 */
static bool utfc__handle_ascii(utfc_result *result, const char *data, uint32_t len, uint32_t *idx) {
    uint32_t nna_out = 0;
    if (utfc__next_non_ascii(data, len, *idx, &nna_out)) {
        // We found a non-ASCII character.
        const uint32_t count = (nna_out - *idx);
        memcpy(&result->value[result->len], &data[*idx], count);
        result->len += count;
        *idx += count;
        return false;
    }

    // Only ASCII chars left.
    const uint32_t count = (len - *idx);
    memcpy(&result->value[result->len], &data[*idx], count);
    result->len += count;
    return true;
}

static bool utfc__write_header(utfc_result *result, uint32_t len) {
    uint8_t extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_0; // Up to 8  bits
    if (len > (UINT32_MAX ^ 0xFF000000)) { // ----------------- Up to 32 bits
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_3;
    } else if (len > UINT16_MAX) { // ------------------------- Up to 24 bits
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_2;
    } else if (len > UINT8_MAX) { // -------------------------- Up to 16 bits
        extra_length_bytes = UTFC__EXTRA_LENGTH_BYTES_1;
    }

    const uint32_t value_len = UTFC__MIN_HEADER_LEN + extra_length_bytes + len;
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

    // Copy the payload length into the next `1 + extra_length_bytes` bytes.
    memcpy(&result->value[UTFC__HEADER_IDX_LENGTH], &len, (1 + extra_length_bytes));
    result->len += extra_length_bytes;

    return true;
}

static bool utfc__read_header(utfc__header *header, const char *data, uint32_t len) {
    if (len < UTFC__MIN_HEADER_LEN) return false;

    // Check magic.
    if (memcmp(data, UTFC__MAGIC_BYTES, UTFC__MAGIC_LEN) != 0) return false;

    // Check major.
    const uint8_t major = data[UTFC__HEADER_IDX_MAJOR];
    if (major != UTFC__MAJOR) return false;

    // Check minor.
    header->minor = data[UTFC__HEADER_IDX_MINOR];
    if (header->minor > UTFC__MINOR) return false;

    // Check flags.
    header->flags = data[UTFC__HEADER_IDX_FLAGS];
    const uint8_t extra_length_bytes = (header->flags & UTFC__FLAG_EXTRA_LENGTH_BYTES_3);
    if (len < (uint32_t)(UTFC__MIN_HEADER_LEN + extra_length_bytes)) return false;

    // Copy the payload length bytes into `payload_length`.
    memcpy(&header->payload_len, &data[UTFC__HEADER_IDX_LENGTH], (1 + extra_length_bytes));

    // Write the total length of the header.
    // (We start the decompression at this index)
    header->len = (UTFC__MIN_HEADER_LEN + extra_length_bytes);

    return true;
}

static void utfc__prefix_reducer_sort_desc(const utfc__prefix_map *prefix_map, uint32_t out[], uint8_t *out_len) {
    uint8_t max_values = prefix_map->len;
    if (max_values > UTFC__PREFIX_REDUCER_STACK_LIMIT) {
        max_values = UTFC__PREFIX_REDUCER_STACK_LIMIT;
    }

    // NOTE: The minimum `value_count` for an element should be `3`.
    // (A value below 3 is too inefficient)
    uint32_t value_count[UTFC__PREFIX_REDUCER_STACK_LIMIT] = { 0 };

    // Select new prefixes and count.
    for (uint32_t i = 0; i < prefix_map->len && *out_len < max_values; i++) {
        const uint32_t value = prefix_map->values[i].value;

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

    // Sort the strongest prefixes in descending order.
    for (uint8_t i = 0; (i + 1) < *out_len; ++i) {
        // Best ...
        uint8_t bi = i;                // index
        uint32_t bvc = value_count[i]; // value_count
        uint8_t bl = (out[i] >> 24);   // length
        uint32_t bs = UINT32_MAX;      // score
        if ((uint32_t)bl < (UINT32_MAX / bvc)) {
            bs = (uint32_t)(bl * bvc);
        }

        // Find the best element after index `i`.
        for (uint8_t j = (i + 1); j < *out_len; ++j) {
            const uint32_t jvc = value_count[j];
            if (jvc < 3) continue;

            const uint8_t jl = (out[j] >> 24);
            uint32_t js = UINT32_MAX;
            if ((uint32_t)jl < (UINT32_MAX / jvc)) {
                js = (uint32_t)(jl * jvc);
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
            uint32_t tmp = value_count[i];
            value_count[i] = bvc;
            value_count[bi] = tmp;
            // Swap value
            tmp = out[i];
            out[i] = out[bi];
            out[bi] = tmp;
        }
    }

    // After sorting, we only want prefixes with a `value_count` of at least 3.
    for (uint8_t i = 0; i < *out_len && i < UTFC__MAX_PREFIX_MARKERS; i++) {
        if (value_count[i] < 3) {
            *out_len = i;
            return;
        }
    }

    // We cannot exceed the limit.
    if (*out_len > UTFC__MAX_PREFIX_MARKERS) {
        *out_len = UTFC__MAX_PREFIX_MARKERS;
    }
}

static bool utfc__prefix_reducer(utfc_result *result, const utfc__prefix_map *prefix_map) {
    if (prefix_map->len < UTFC__PREFIX_REDUCER_THRESHOLD) return true;

    // We need a descending sorted list of the strongest prefixes found.
    uint32_t sorted_prefixes[UTFC__PREFIX_REDUCER_STACK_LIMIT] = { 0 };
    uint8_t sorted_prefixes_len = 0;
    utfc__prefix_reducer_sort_desc(prefix_map, sorted_prefixes, &sorted_prefixes_len);
    if (sorted_prefixes_len == 0) return false;

    // Set header flag.
    result->value[UTFC__HEADER_IDX_FLAGS] |= UTFC__FLAG_PREFIX_REDUCER;

    /* ====== REMOVE ====== */
    // We loop through the entire map and replace the selected prefixes with markers.
    for (uint32_t i = prefix_map->len; i-- > 0;) {
        const utfc__prefix_map_v pmv = prefix_map->values[i];

        // If the current prefix is ​​present in `sorted_prefixes`,
        // the marker is determined based on its position.
        int8_t marker_idx = -1;
        for (uint8_t j = 0; j < sorted_prefixes_len; j++) {
            if (sorted_prefixes[j] == pmv.value) {
                marker_idx = j;
                break;
            }
        }

        // If `marker_idx` is not `-1`, the bytes of the current prefix
        // are removed and replaced with a single byte (the marker).
        if (marker_idx != -1) {
            // The length is located in the high 8 bits of the value.
            const uint8_t pmv_value_len = (uint8_t)(pmv.value >> 24);

            // Change first prefix byte to marker.
            result->value[pmv.index] = UTFC__PREFIX_MARKERS[marker_idx];

            const uint32_t src_len = (pmv.index + pmv_value_len);
            const uint32_t move_len = (result->len - src_len);
            memmove(&result->value[pmv.index + 1], &result->value[src_len], move_len);
            result->len -= (pmv_value_len - 1);
        }
    }

    /* ====== ADD ====== */
    const uint8_t header_len = UTFC__MIN_HEADER_LEN + (result->value[UTFC__HEADER_IDX_FLAGS] & UTFC__FLAG_EXTRA_LENGTH_BYTES_3);

    // Set the byte for the length of the reduced prefixes directly after the header.
    memmove(&result->value[header_len + 1], &result->value[header_len], (result->len - header_len));
    result->len += 1;
    result->value[header_len] = sorted_prefixes_len;

    // We move the payload (number of bytes of the prefix)
    // to the right and write the prefix in front of it.
    for (uint8_t i = sorted_prefixes_len; i-- > 0;) {
        char prefix[3] = { 0 };
        uint8_t prefix_len = 0;
        utfc__prefix_unpack(sorted_prefixes[i], prefix, &prefix_len);

        const uint32_t from = (header_len + 1);
        const uint32_t to = (from + prefix_len);

        memmove(&result->value[to], &result->value[from], (result->len - from));
        for (uint8_t j = 0; j < prefix_len; j++) {
            result->value[from + j] = prefix[j];
        }
        result->len += prefix_len;
    }

    return true;
}

static bool utfc__compression(utfc_result *result, utfc__prefix_map *prefix_map, const char *data, uint32_t len) {
    uint32_t cached_prefix_idx = 0;
    uint8_t cached_prefix_len = 0;

    uint32_t read_idx = 0;
    while (read_idx < len) {
        const int8_t char_len = utfc__char_len(data, len, read_idx);
        if (char_len <= 0) {
            // Something is wrong with this character.
            // We will use the next (up to) 4 bytes to find the problem.

            result->error = (char_len == -1 ? UTFC_ERROR_MISSING_BYTES : UTFC_ERROR_INVALID_BYTE);
            const uint32_t remaining_bytes = (len - read_idx);
            result->len = ((remaining_bytes > UTFC__MAX_CHAR_LEN) ? UTFC__MAX_CHAR_LEN : remaining_bytes);
            memcpy(result->value, &data[read_idx], result->len);

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
    const uint32_t data_len = (uint32_t)len;

    if (!utfc__write_header(&result, data_len)) {
        return result;
    }

    utfc__prefix_map prefix_map = { 0 };
    if (!utfc__prefix_map_init(&prefix_map)) {
        result.error = UTFC_ERROR_OUT_OF_MEMORY;
        return result;
    }

    if (utfc__compression(&result, &prefix_map, data, data_len)) {
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
    const uint32_t data_len = (uint32_t)len;

    utfc__header header = { 0 };
    if (!utfc__read_header(&header, data, data_len)) {
        result.error = UTFC_ERROR_INVALID_HEADER;
        return result;
    }

    // If terminate = 1 we allocate one more to terminate it with a '\0'.
    result.value = (char *)malloc((header.payload_len + (terminate == false ? 0 : 1)) * sizeof(*result.value));
    if (result.value == NULL) {
        result.error = UTFC_ERROR_OUT_OF_MEMORY;
        return result;
    }

    uint32_t read_idx = (uint32_t)header.len;

    // Prefix reducer.
    utfc__prefix_map map = { 0 };
    const bool use_prefix_reducer = ((data[UTFC__HEADER_IDX_FLAGS] & UTFC__FLAG_PREFIX_REDUCER) > 0);
    if (use_prefix_reducer) {
        const uint8_t prefix_count = data[read_idx++];
        if (data_len < (read_idx + prefix_count)) {
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
            // For example, 3 bits means that the character has 3 bytes, so the prefix must have 2 bytes.
            const char first_prefix_byte = data[read_idx];
            if ((first_prefix_byte & 0xC0) != 0xC0) {
                utfc__prefix_map_deinit(&map);
                result.error = UTFC_ERROR_INVALID_BYTE;
                break;
            }
            const size_t mask = (size_t)(first_prefix_byte & 0xF0);
            const uint8_t bit_count = ((-utfc__zero_bits_count(mask)) & 0x07);
            const uint8_t prefix_len = (bit_count - 1);

            if (data_len < (read_idx + prefix_len)) {
                utfc__prefix_map_deinit(&map);
                result.error = UTFC_ERROR_MISSING_BYTES;
                break;
            }

            utfc__prefix_map_add(&map, &data[read_idx], prefix_len, read_idx);
            read_idx += prefix_len;
        }
    }

    uint32_t cached_prefix_idx = 0;
    uint8_t cached_prefix_len = 0;
    while ((read_idx < data_len) && (result.len < header.payload_len)) {
        if (use_prefix_reducer) {
            const uint8_t byte = (uint8_t)data[read_idx];
            if (byte == 0xC0 || byte == 0xC1 || byte >= 0xF5) {
                const uint8_t marker_idx = (byte - ((byte >= 0xF5) ? 0xF0 : 0xC0));
                const utfc__prefix_map_v pmv = map.values[marker_idx];

                cached_prefix_idx = pmv.index;
                cached_prefix_len = (uint8_t)(pmv.value >> 24); // Length extraction

                read_idx += 1;
                continue;
            }
        }

        // -2:  Missing bytes
        // -1:  Invalid continuation bytes
        // 0:   cached_prefix + value
        // 1:   ASCII (no prefix)
        // 2-4: new prefix + value
        const int8_t char_len = utfc__char_len(data, data_len, read_idx);
        if (char_len < 0) { // Something is wrong
            // Something is wrong with this character.
            // We will use the next (up to) 4 bytes to find the problem.

            result.error = (char_len == -1 ? UTFC_ERROR_MISSING_BYTES : UTFC_ERROR_INVALID_BYTE);
            const uint32_t remaining_bytes = (data_len - read_idx);
            result.len = ((remaining_bytes > UTFC__MAX_CHAR_LEN) ? UTFC__MAX_CHAR_LEN : remaining_bytes);
            memcpy(result.value, &data[read_idx], result.len);

            break;
        }

        if (char_len == 1) { // ASCII
            // If the next byte is also ASCII, we use SIMD to find the next
            // non-ASCII byte and efficiently copy everything up to that index.
            if ((read_idx + 1) < data_len && (data[read_idx + 1] & 0x80) == 0) {
                if (utfc__handle_ascii(&result, data, data_len, &read_idx)) break;
                continue;
            }
        } else {
            if (char_len > 1) { // New prefix
                cached_prefix_idx = read_idx;
                cached_prefix_len = char_len - 1;
                read_idx += cached_prefix_len;
            }
            memcpy(&result.value[result.len], &data[cached_prefix_idx], cached_prefix_len);
            result.len += cached_prefix_len;
        }

        result.value[result.len++] = data[read_idx++];
    }

    utfc__prefix_map_deinit(&map);

    return result;
}

#endif // !defined(UTFC_H)