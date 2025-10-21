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

#define _UTFC_MAGIC_LEN 3
#define _UTFC_MAJOR 0
#define _UTFC_MINOR 0
#define _UTFC_PATCH 0
#define _UTFC_MIN_HEADER_LEN 7 // Magic(3) + Major(1) + Minor(1) + Flags(1) + Length(1)
#define _UTFC_MAX_CHAR_LEN 4
#define _UTFC_RESERVED_LEN 50
#define _UTFC_MAX_DATA_LEN (UINT32_MAX - _UTFC_RESERVED_LEN)

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

    _UTFC_HEADER_FLAG_RESERVED1     = 0b00000100,
    _UTFC_HEADER_FLAG_RESERVED2     = 0b00001000,
    _UTFC_HEADER_FLAG_RESERVED3     = 0b00010000,
    _UTFC_HEADER_FLAG_RESERVED4     = 0b00100000,
    _UTFC_HEADER_FLAG_RESERVED5     = 0b01000000,
    _UTFC_HEADER_FLAG_RESERVED6     = 0b10000000,
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

static _UTFC_HEADER _utfc_read_header(const char *data) {
    _UTFC_HEADER header = { 0 };

    for (uint8_t i = 0; i < _UTFC_MAGIC_LEN; i++) {
        if (data[i] == '\0' || data[i] != _UTFC_MAGIC_BYTES[i]) {
            header.status = UTFC_ERROR_INVALID_HEADER;
            return header;
        }
        header.magic[i] = data[i];
    }

    header.major = data[3];
    header.minor = data[4];

    // TODO
    if (header.major > _UTFC_MAJOR || header.minor > _UTFC_MINOR) {
        header.status = UTFC_ERROR_INVALID_HEADER;
        return header;
    }

    header.flags = data[5];
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
    UTFC_RESULT result = _utfc_result_init();
    
    if (length > _UTFC_MAX_DATA_LEN) {
        result.status = UTFC_ERROR_TOO_MANY_BYTES;
        return result;
    }

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

        result.value[result.length++] = data[read_pos];
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
    UTFC_RESULT result = _utfc_result_init();
    _UTFC_HEADER header = _utfc_read_header(data);
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

    for (
            uint32_t read_pos = header.length;
            (read_pos < length) && (result.length < header.data_length);
            read_pos++
    ) {
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
            for (uint8_t i = 0; i < cached_prefix_len; i++) {
                result.value[result.length++] = cached_prefix[i];
            }
        }

        result.value[result.length++] = data[read_pos];
    }

    return result;
}

#endif // !defined(UTFC_H)