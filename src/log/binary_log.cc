//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2007-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

/**
 * @file   log/binary_log.c
 * @author Miguel Álvarez <malvarez@redborder.com>
 * @date
 *
 * @brief  implements binary writer/reader for easy write or read into/from a buffer
 */

#include <sys/stat.h>
#include <time.h>

#include <cstring>
#include <cstdlib>

#include <algorithm>
#include <cstdarg>

#include "utils/util.h"

#include "log.h"

using namespace snort;

/* a reasonable minimum */
#define MIN_BUF  (4 * 1024)
#define TMP_BUFF_SIZE 1024

struct BinaryWriter
{
    unsigned char* buffer;
    size_t size;
    size_t pos;
    size_t maxBuf;
};

/*-------------------------------------------------------------------
 * BinaryWriter_Init: constructor
 *-------------------------------------------------------------------
 */
BinaryWriter* BinaryWriter_Init(size_t maxBuf)
{
    BinaryWriter* bin;

    if (maxBuf < MIN_BUF)
        maxBuf = MIN_BUF;

    bin = (BinaryWriter*)snort_alloc(sizeof(BinaryWriter));
    bin->buffer = (unsigned char*)snort_alloc(maxBuf);
    bin->size = 0;
    bin->maxBuf = maxBuf;
    bin->pos = 0;
    return bin;
}

/*-------------------------------------------------------------------
 * BinaryWriter_Term: destructor
 *-------------------------------------------------------------------
 */
void BinaryWriter_Term(BinaryWriter* const bin)
{
    if (!bin)
        return;

    if (bin->buffer) {
        snort_free(bin->buffer);
        bin->buffer = nullptr;
    }
    
    snort_free(bin);
}

/*-------------------------------------------------------------------
 * BinaryWriter_Flush: resets the buffer (if needed)
 *-------------------------------------------------------------------
 */
void BinaryWriter_Flush(BinaryWriter* const bin)
{
    bin->pos = 0;
    bin->size = 0;
}

/*-------------------------------------------------------------------
 * BinaryWriter_Write: append data to buffer
 *-------------------------------------------------------------------
 */
bool BinaryWriter_Write(BinaryWriter* const bin, const void* data, size_t len)
{
    if (len == 0) return true;

    if (bin->pos + len > bin->maxBuf)
    {
        return false;
    }

    memcpy(bin->buffer + bin->pos, data, len);
    bin->pos += len;
    bin->size += len;

    return true;
}


/*-------------------------------------------------------------------
 * BinaryWriter_WriteByte: append a single byte to buffer
 *-------------------------------------------------------------------
 */
bool BinaryWriter_WriteByte(BinaryWriter* const bin, unsigned char byte)
{
    return BinaryWriter_Write(bin, &byte, sizeof(byte));
}

// Forward declaration of BinaryWriter_Putc
bool BinaryWriter_Putc(BinaryWriter* const writer, char c);

/*-------------------------------------------------------------------
 * BinaryWriter_Putc: function to write a single character to the buffer
 *-------------------------------------------------------------------
 */
bool BinaryWriter_Putc(BinaryWriter* const writer, char c) {
    return BinaryWriter_WriteByte(writer, (unsigned char)c);
}

/*-------------------------------------------------------------------
 * BinaryWriter_WriteString: function to write a string to the buffer
 *-------------------------------------------------------------------
 */
bool BinaryWriter_WriteString(BinaryWriter* const writer, const char* str) {
    if (!str)
        return false;

    return BinaryWriter_Write(writer, str, strlen(str));
}

/*-------------------------------------------------------------------
 * BinaryWriter_Quote: function to write a quoted string to the buffer
 *-------------------------------------------------------------------
 */
bool BinaryWriter_Quote(BinaryWriter* const writer, const char* str) {
    if (!str)
        return false;

    BinaryWriter_Putc(writer, '"');
    BinaryWriter_WriteString(writer, str);
    BinaryWriter_Putc(writer, '"');
    return true;
}

/*-------------------------------------------------------------------
 * BinaryWriter_Print: function to format and write a string to the buffer
 *-------------------------------------------------------------------
 */
bool BinaryWriter_Print(BinaryWriter* const writer, const char* format, ...) {
    if (!writer || !format)
        return false;

    va_list args;
    va_start(args, format);

    char temp[TMP_BUFF_SIZE];
    int len = vsnprintf(temp, sizeof(temp), format, args);

    va_end(args);

    if (len < 0 || (size_t)len >= sizeof(temp))
        return false;

    return BinaryWriter_WriteString(writer, temp);
}

char* BinaryWriter_FlushToString(BinaryWriter* const bin) {
    if (!bin || bin->size == 0) {
        return nullptr;
    }

    char* str = (char*)malloc(bin->size + 1);
    if (!str) {
        return nullptr;
    }

    memcpy(str, bin->buffer, bin->size);
    str[bin->size] = '\0';

    BinaryWriter_Flush(bin);

    return str;
} // namespace snort