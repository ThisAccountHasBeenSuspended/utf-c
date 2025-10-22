/**
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
#endif // defined(__x86_64__) || defined(__amd64__) || defined(_M_X64) || defined(_M_AMD64) || defined(__i386__) || defined(_M_IX86)

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
    #endif // defined(_MSC_VER)
#endif // defined(_UTFC_X86)

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
    uint32_t data_length;
    UTFC_ERROR status;
    uint8_t major, minor, flags;
    uint8_t length;
    char magic[_UTFC_MAGIC_LEN];
} _UTFC_HEADER;

typedef struct {
    char *value;
    uint32_t length;
    UTFC_ERROR status;
} UTFC_RESULT;

/* ==================== #!PRIVATE!# ==================== */

static bool _utfc_next_non_ascii(const char *value, uint32_t length, uint32_t idx, uint32_t *out) {
    if (idx >= length) {
        return false;
    }

    uint32_t pos = idx;

#if defined(_UTFC_X86) && defined(__AVX2__)
    while ((pos + 32) <= length) {
        const __m256i v = _mm256_loadu_si256((const __m256i *)&value[pos]);
        const int m = _mm256_movemask_epi8(v);
        if (m != 0) {
#if defined(_MSC_VER)
            if (_BitScanForward(out, m) != 0) {
                return false;
            }
#else // defined(_MSC_VER)
            *out = __builtin_ctz(m);
#endif // defined(_MSC_VER)
            *out += pos;
            return true;
        }

        pos += 32;
    }
#endif // defined(_UTFC_X86) && defined(__AVX2__)

#if defined(_UTFC_X86) && defined(__SSE2__)
    while ((pos + 16) <= length) {
        const __m128i v = _mm_loadu_si128((const __m128i *)&value[pos]);
        const int m = _mm_movemask_epi8(v);
        if (m != 0) {
#if defined(_MSC_VER)
            if (_BitScanForward(out, m) != 0) {
                return false;
            }
#else // defined(_MSC_VER)
            *out  = __builtin_ctz(m);
#endif // defined(_MSC_VER)
            *out += pos;
            return true;
        }

        pos += 16;
    }
#endif // defined(_UTFC_X86) && defined(__SSE2__)

    while ((pos + 1) <= length) {
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
static uint8_t _utfc_char_len(const char *value, uint32_t length, uint32_t idx) {
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

    if ((length - idx) < char_len) return 0;

    for (uint8_t i = 1; i < char_len; ++i) {
        if ((value[idx + i] & 0xC0) != 0x80) {
            // No valid continuation byte
            return 0;
        }
    }

    return char_len;
}

static bool _utfc_write_header(UTFC_RESULT *result, uint32_t length) {
    uint8_t extra_length_bytes = 0;
    if (length > (((uint32_t)UINT8_MAX << 16) | UINT16_MAX)) {
        extra_length_bytes = _UTFC_HEADER_FLAG_32_BIT_LENGTH;
    } else if (length > UINT16_MAX) {
        extra_length_bytes = _UTFC_HEADER_FLAG_24_BIT_LENGTH;
    } else if (length > UINT8_MAX) {
        extra_length_bytes = _UTFC_HEADER_FLAG_16_BIT_LENGTH;
    }

    const uint32_t estimated_size = _UTFC_MIN_HEADER_LEN + extra_length_bytes + length;
    result->value = (char *)malloc(estimated_size);
    if (result->value == NULL) {
        result->status = UTFC_ERROR_OUT_OF_MEMORY;
        return false;
    }

    // Write magic
    for (uint8_t i = 0; i < _UTFC_MAGIC_LEN; i++) {
        result->value[result->length++] = _UTFC_MAGIC_BYTES[i];
    }

    // Write major
    result->value[result->length++] = _UTFC_MAJOR;

    // Write minor
    result->value[result->length++] = _UTFC_MINOR;

    // Write flags
    uint8_t flags = 0;
    flags |= extra_length_bytes; // 000000xx
    result->value[result->length++] = flags;

    // Write length of decompressed data
    result->value[result->length++] = (char)length;
    if (extra_length_bytes == _UTFC_HEADER_FLAG_16_BIT_LENGTH) {
        result->value[result->length++] = (char)(length >> 8);
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_24_BIT_LENGTH) {
        result->value[result->length++] = (char)(length >> 8);
        result->value[result->length++] = (char)(length >> 16);
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_32_BIT_LENGTH) {
        result->value[result->length++] = (char)(length >> 8);
        result->value[result->length++] = (char)(length >> 16);
        result->value[result->length++] = (char)(length >> 24);
    }
    
    return true;
}

static _UTFC_HEADER _utfc_read_header(const char *data, uint32_t length) {
    _UTFC_HEADER header = { 0 };
    if (length < _UTFC_MIN_HEADER_LEN) {
        header.status = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    if (memcmp(data, _UTFC_MAGIC_BYTES, 3) != 0) {
        header.status = UTFC_ERROR_INVALID_HEADER;
        return header;
    }
    memcpy(header.magic, data, 3);

    header.major = data[3];
    header.minor = data[4];

    // Should we allow higher versions?
    if (header.major > _UTFC_MAJOR || header.minor > _UTFC_MINOR) {
        header.status = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    header.flags = data[5];
    // Something important may be missing.
    // We should only allow older versions with the same possible flags.
    if ((header.flags & _UTFC_UNUSED_FLAG_BITS) != 0) {
        header.status = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    header.data_length = (uint32_t)data[6] & 0xFF;

    uint8_t extra_length_bytes = header.flags & 0b11;
    if (extra_length_bytes == _UTFC_HEADER_FLAG_16_BIT_LENGTH) {
        header.data_length |= ((uint32_t)data[7] & 0xFF) << 8;
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_24_BIT_LENGTH) {
        header.data_length |= ((uint32_t)data[7] & 0xFF) << 8;
        header.data_length |= ((uint32_t)data[8] & 0xFF) << 16;
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_32_BIT_LENGTH) {
        header.data_length |= ((uint32_t)data[7] & 0xFF) << 8;
        header.data_length |= ((uint32_t)data[8] & 0xFF) << 16;
        header.data_length |= ((uint32_t)data[9] & 0xFF) << 24;
    }

    uint8_t total_header_length = _UTFC_MIN_HEADER_LEN + extra_length_bytes;
    header.length = total_header_length;

    return header;
}

/* ==================== #!PUBLIC!# ==================== */

void utfc_result_deinit(UTFC_RESULT *result) {
    if (result != NULL && result->value != NULL) {
        free(result->value);
        result->value = NULL;
    }
}

UTFC_RESULT utfc_compress(const char *data, uint32_t length) {
    UTFC_RESULT result = { 0 };
    
    if (length > _UTFC_MAX_DATA_LEN) {
        result.status = UTFC_ERROR_TOO_MANY_BYTES;
        return result;
    }

    if (_utfc_write_header(&result, length) == false) {
        return result;
    }

    char *cached_prefix = NULL;
    uint8_t cached_prefix_len = 0;

    uint32_t read_pos = 0;
    while (read_pos < length) {
        const uint8_t char_len = _utfc_char_len(data, length, read_pos);
        if (char_len == 0) {
            // Something is wrong with the next character, so we return
            // the maximum of 4 checked bytes as the value to check them.
            result.status = UTFC_ERROR_INVALID_BYTE;

            // No longer needed.
            // Instead, we use the pointer starting at read_pos for data.
            free(result.value);

            uint32_t remaining_bytes = length - read_pos;
            if (remaining_bytes > _UTFC_MAX_CHAR_LEN) {
                remaining_bytes = _UTFC_MAX_CHAR_LEN;
            }
            result.length = remaining_bytes;
            result.value = (char *)&data[read_pos];

            return result;
        }
        const uint8_t prefix_len = char_len - 1;

        if (prefix_len > 0) {
            bool prefix_changed = (prefix_len != cached_prefix_len);

            // If the length is not different, we check if the bytes are identical.
            if (prefix_changed == false) {
                if (memcmp(cached_prefix, &data[read_pos], prefix_len) != 0) {
                    prefix_changed = true;
                }
            }

            // When we have a new prefix, it is cached and written.
            if (prefix_changed == true) {
                cached_prefix = (char *)&data[read_pos];
                cached_prefix_len = prefix_len;

                memcpy(&result.value[result.length], &data[read_pos], prefix_len);
                result.length += prefix_len;
            }

            read_pos += prefix_len;
        } else if ((read_pos + 1) < length && (data[read_pos + 1] & 0x80) == 0) {
            // Our current and next chars are ASCII.
            // Let's find the next non-ASCII char and efficiently copy them all up to that index.
            uint32_t next_idx = 0;
            bool found = _utfc_next_non_ascii(data, length, read_pos, &next_idx);
            if (found == true) {
                while (read_pos < next_idx) {
                    result.value[result.length++] = data[read_pos++];
                }
                continue;
            }

            // Only ASCII chars left.
            uint32_t left = (length - read_pos);
            memcpy(&result.value[result.length], &data[read_pos], left);
            result.length += left;
            break;
        }

        result.value[result.length++] = data[read_pos++];
    }

    char *resized_value = (char *)realloc(result.value, result.length);
    if (resized_value != NULL) {
        result.value = resized_value;
    }

    return result;
}

/**
 * Notes:
 * - return.length contains only the written bytes, not the possible '\0' at the end.
 */
UTFC_RESULT utfc_decompress(const char *data, uint32_t length, bool terminate) {
    UTFC_RESULT result = { 0 };
    _UTFC_HEADER header = _utfc_read_header(data, length);
    if (header.status != UTFC_ERROR_NONE) {
        return result;
    }

    // If terminate = 1 we allocate one more to terminate it with a '\0'.
    result.value = (char *)malloc(header.data_length + (terminate != 0 ? 1 : 0));
    if (result.value == NULL) {
        result.status = UTFC_ERROR_OUT_OF_MEMORY;
        return result;
    }

    char *cached_prefix = NULL;
    uint8_t cached_prefix_len = 0;

    uint32_t read_pos = header.length;
    while ((read_pos < length) && (result.length < header.data_length)) {
        // 0:   cached_prefix + value
        // 1:   ASCII (no prefix)
        // 2-4: new prefix + value
        const uint8_t char_len = _utfc_char_len(data, length, read_pos);
        if (char_len > 1) {
            cached_prefix = (char *)&data[read_pos];
            cached_prefix_len = char_len - 1;

            read_pos += cached_prefix_len;
        }

        if (char_len != 1) {
            memcpy(&result.value[result.length], cached_prefix, cached_prefix_len);
            result.length += cached_prefix_len;
        }

        result.value[result.length++] = data[read_pos++];
    }

    return result;
}

#endif // !defined(UTFC_H)