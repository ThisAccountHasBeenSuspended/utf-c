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
#define UTFC_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    /// No error.
    UTFC_ERROR_NONE,
    /// An unknown error occurred.
    UTFC_ERROR_UNKNOWN,
    /// A (re)allocation failed.
    UTFC_ERROR_OUT_OF_MEMORY,
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

    _UTFC_HEADER_FLAG_RESERVED1     = 0b00000100,
    _UTFC_HEADER_FLAG_RESERVED2     = 0b00001000,
    _UTFC_HEADER_FLAG_RESERVED3     = 0b00010000,
    _UTFC_HEADER_FLAG_RESERVED4     = 0b00100000,
    _UTFC_HEADER_FLAG_RESERVED5     = 0b01000000,
    _UTFC_HEADER_FLAG_RESERVED6     = 0b10000000,
} _UTFC_HEADER_FLAGS;

typedef struct {
    UTFC_ERROR status;
    uint32_t length;
    char *value;
} UTFC_RESULT;

/* ==================== #!PRIVATE!# ==================== */

#define _UTFC_MAGIC_LEN 3
#define _UTFC_MAJOR 0
#define _UTFC_MINOR 0
#define _UTFC_PATCH 0
#define _UTFC_MIN_HEADER_LEN 6 // Magic(3) + Major(1) + Minor(1) + Flags(1)
#define _UTFC_MAX_CHAR_LEN 4

static const char _UTFC_MAGIC_BYTES[_UTFC_MAGIC_LEN] = { 'U', '8', 'C' };

/**
 * Returns the byte length for the next char of a UTF-8 string.
 * 
 * Notices:
 * - The bytes from `idx` up to `idx` + `return` represent the prefix.
 * - `idx` + `return` is the index of the actual char.
 * - The `return` value 0 means that something went wrong.
 */
static uint32_t _utfc_char_len(const char *value, uint32_t length, uint32_t idx) {
    const int8_t byte = (int8_t)value[idx];
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

    for (uint32_t i = 1; i < char_len; ++i) {
        if ((value[idx + i] & 0xC0) != 0x80) {
            // No valid continuation byte
            return 0;
        }
    }

    return char_len;
}

static inline UTFC_RESULT _utfc_result_init() {
    UTFC_RESULT result = (UTFC_RESULT){
        .status = UTFC_ERROR_NONE,
        .length = 0,
        .value = NULL
    };
    return result;
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

    const uint32_t estimated_size = _UTFC_MIN_HEADER_LEN + 1 + extra_length_bytes + length;
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
    result->value[result->length++] = (length & 0xFF);
    if (extra_length_bytes == _UTFC_HEADER_FLAG_16_BIT_LENGTH) {
        result->value[result->length++] = ((length >> 8) & 0xFF);
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_24_BIT_LENGTH) {
        result->value[result->length++] = ((length >> 8) & 0xFF);
        result->value[result->length++] = ((length >> 16) & 0xFF);
    } else if (extra_length_bytes == _UTFC_HEADER_FLAG_32_BIT_LENGTH) {
        result->value[result->length++] = ((length >> 8) & 0xFF);
        result->value[result->length++] = ((length >> 16) & 0xFF);
        result->value[result->length++] = ((length >> 24) & 0xFF);
    }
    
    return true;
}

/* ==================== #!PUBLIC!# ==================== */

void utfc_result_deinit(UTFC_RESULT *result) {
    if (result != NULL && result->value != NULL) {
        free(result->value);
        result->value = NULL;
    }
}

UTFC_RESULT utfc_compress(const char *data, uint32_t length) {
    UTFC_RESULT result = _utfc_result_init();
    if (_utfc_write_header(&result, length) == false) {
        return result;
    }

    char *cached_prefix = NULL;
    uint8_t cached_prefix_len = 0;

    for (uint32_t read_pos = 0; read_pos < length; read_pos++) {
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
                for (int8_t i = 0; i < prefix_len; i++) {
                    if (cached_prefix[i] != data[read_pos + i]) {
                        prefix_changed = true;
                        break;
                    }
                }
            }

            // When we have a new prefix, it is cached and written.
            if (prefix_changed == true) {
                cached_prefix = (char *)&data[read_pos];
                cached_prefix_len = prefix_len;

                for (int8_t i = 0; i < prefix_len; i++) {
                    result.value[result.length++] = data[read_pos + i];
                }
            }

            read_pos += prefix_len;
        }

        const char byte = data[read_pos];
        result.value[result.length++] = byte;
        if (byte == '\0') {
            // End of string reached
            break;
        }
    }

    char *resized_value = (char *)realloc(result.value, result.length);
    if (resized_value != NULL) {
        result.value = resized_value;
    }

    return result;
}

UTFC_RESULT utfc_decompress(const char *data, uint32_t length) {
    UTFC_RESULT result = _utfc_result_init();

    // TODO

    return result;
}

#endif // !defined(UTFC_H)