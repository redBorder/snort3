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

#include "http_queue.h"

AsyncResponseManager::AsyncResponseManager(std::chrono::milliseconds interval_)
    : shutdown(false), interval(interval_), worker_thread(&AsyncResponseManager::worker, this) {}

AsyncResponseManager::~AsyncResponseManager() {
    {
        std::lock_guard<std::mutex> lock(mtx);
        shutdown = true;
    }
    cv.notify_one();
    if (worker_thread.joinable()) {
        worker_thread.join();
    }
}

void AsyncResponseManager::worker() {
    std::unique_lock<std::mutex> lock(mtx);
    while (!shutdown) {
        cv.wait_for(lock, interval);
        std::vector<cpr::AsyncResponse> to_process;
        to_process.swap(pending_responses);
        lock.unlock();
        for (auto& resp : to_process) {
            resp.get();
        }
        lock.lock();
    }
    for (auto& resp : pending_responses) {
        resp.get();
    }
    pending_responses.clear();
}

AsyncResponseManager& AsyncResponseManager::getInstance() {
    static AsyncResponseManager instance;
    return instance;
}

void AsyncResponseManager::addResponse(cpr::AsyncResponse&& response) {
    {
        std::lock_guard<std::mutex> lock(mtx);
        pending_responses.push_back(std::move(response));
    }
    cv.notify_one();
}
