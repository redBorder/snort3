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
// rbgeoip.cc author Miguel Álvarez <malvarez@redborder.com>
// Simple SINGLETON to load/unload geoip database for libgeoip++

#include "geoip/rbgeoip.h"

namespace GeoIpLoader {

    Manager* Manager::instance = nullptr;

    Manager::Manager() : db(nullptr), isLoaded(false) {}

    Manager::~Manager() {
        unloadDB();
    }

    Manager* Manager::getInstance(const std::string& dbPath) {
        if (instance == nullptr) {
            instance = new Manager();
            if (!dbPath.empty()) {
                instance->loadDB(dbPath);
            }
        }
        return instance;
    }

    void Manager::loadDB(const std::string& dbPath) {
        if (!isLoaded) {
            db = new GeoLite2PP::DB(dbPath);
            isLoaded = true;
        }
    }

    void Manager::unloadDB() {
        if (db != nullptr) {
            delete db;
            db = nullptr;
            isLoaded = false;
        }
    }

    std::string Manager::getFieldByIP(const std::string& ip_string, const std::string& field_key) {
        if (db == nullptr) {
            return "Unknown";
        }

        try {
            GeoLite2PP::MStr fields = db->get_all_fields(ip_string);
            auto it = fields.find(field_key);
            return (it != fields.end() && !it->second.empty()) ? it->second : "Unknown";
        } catch (const std::exception&) {
            return "Unknown";
        }
    }

    std::string Manager::getCountryByIP(const std::string& ip_string) {
        return getFieldByIP(ip_string, "country_iso_code");
    }

    std::string Manager::getContinentByIP(const std::string& ip_string) {
        return getFieldByIP(ip_string, "continent_name");
    }

}  // namespace GeoIpLoader
