//--------------------------------------------------------------------------
// Copyright (C) 2020-2023 Cisco and/or its affiliates. All rights reserved.
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
// sensor_enrichment.cc author Miguel Álvarez <malvarez@redborder.com>

#include <iostream>
#include "enrichment/sensor_enrichment.h"
#include "sensor_enrichment.h"

using namespace std;

void SensorEnrichment::EnrichJsonLog(BinaryWriter* writer, const string& enrichment) {
    BinaryWriter_WriteString(writer, ", ");
    if (enrichment.length() > 1) {
        BinaryWriter_WriteString(writer, enrichment.substr(1, enrichment.length() - 2).c_str());
    } else {
        BinaryWriter_WriteString(writer, "");
    }
}