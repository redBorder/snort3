//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
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

#pragma once
#include <vector>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <chrono>
#include <cpr/cpr.h>

#define CLEAN_VECTOR_EVERY 60

class AsyncResponseManager {
private:
    std::vector<cpr::AsyncResponse> pending_responses;
    std::mutex mtx;
    std::condition_variable cv;
    bool shutdown;
    std::thread worker_thread;
    std::chrono::milliseconds interval;

    AsyncResponseManager(std::chrono::milliseconds interval = std::chrono::seconds(CLEAN_VECTOR_EVERY));
    ~AsyncResponseManager();

    AsyncResponseManager(const AsyncResponseManager&) = delete;
    AsyncResponseManager& operator=(const AsyncResponseManager&) = delete;

    void worker();

public:
    static AsyncResponseManager& getInstance();

    void addResponse(cpr::AsyncResponse&& response);
};