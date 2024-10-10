//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
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

// binary_log.h Miguel Álvarez <malvarez@redborder.com.com>

#ifndef BINARY_WRITER_H
#define BINARY_WRITER_H

#include <cstddef>
#include <stdbool.h>

struct BinaryWriter
{
    unsigned char* buffer;
    size_t size;
    size_t pos;
    size_t maxBuf;
};

BinaryWriter* BinaryWriter_Init(size_t maxBuf);
void BinaryWriter_Term(BinaryWriter* const bin);
void BinaryWriter_Flush(BinaryWriter* const bin);
bool BinaryWriter_Write(BinaryWriter* const bin, const void* data, size_t len);
bool BinaryWriter_WriteByte(BinaryWriter* const bin, unsigned char byte);
bool BinaryWriter_Putc(BinaryWriter* const writer, char c);
bool BinaryWriter_WriteString(BinaryWriter* const writer, const char* str);
bool BinaryWriter_Quote(BinaryWriter* const writer, const char* str);
char* BinaryWriter_FlushToString(BinaryWriter* const bin);
bool BinaryWriter_Print(BinaryWriter* const writer, const char* format, ...);
inline bool BinaryWriter_Puts(BinaryWriter* const writer, const char* str)
{
    return BinaryWriter_WriteString(writer, str);
}

#endif // BINARY_WRITER_H
