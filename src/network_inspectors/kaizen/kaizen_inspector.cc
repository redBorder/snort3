//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// kaizen_inspector.cc author Brandon Stultz <brastult@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "kaizen_inspector.h"

#include <cassert>

#ifdef HAVE_LIBML
#include <libml.h>
#endif

#include "detection/detection_engine.h"
#include "log/messages.h"
#include "managers/inspector_manager.h"
#include "pub_sub/http_events.h"
#include "pub_sub/ftp_events.h"
#include "pub_sub/http_request_body_event.h"
#include "utils/util.h"

#include "kaizen_engine.h"
#include <iostream>

using namespace snort;
using namespace std;

THREAD_LOCAL KaizenStats kaizen_stats;
THREAD_LOCAL ProfileStats kaizen_prof;

//--------------------------------------------------------------------------
// HTTP body event handler
//--------------------------------------------------------------------------

class HttpBodyHandler : public DataHandler
{
public:
    HttpBodyHandler(Kaizen& kz)
        : DataHandler(KZ_NAME), inspector(kz) {}

    void handle(DataEvent& de, Flow*) override;

private:
    Kaizen& inspector;
};

void HttpBodyHandler::handle(DataEvent& de, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(kaizen_prof);

    const std::vector<BinaryClassifier*>& classifiers = KaizenEngine::get_classifiers(KaizenEngine::ClassifierType::HTTP);
    KaizenConfig config = inspector.get_config();
    HttpRequestBodyEvent* he = (HttpRequestBodyEvent*)&de;

    if (he->is_mime())
        return;

    int32_t body_len = 0;
    const char* body = (const char*)he->get_client_body(body_len);

    if (!body || body_len <= 0)
        return;

    const size_t len = std::min((size_t)config.client_body_depth, (size_t)body_len);

    if (classifiers.empty())
        return;

    kaizen_stats.libml_calls++;

    for (size_t i = 0; i < classifiers.size(); ++i)
    {
        BinaryClassifier* classifier = classifiers[i];
        assert(classifier);

        if (!classifier)
            continue;

        float output = 0.0;
        if (classifier->run(body, len, output))
        {
            debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "input (body): %.*s\n", (int)len, body);
            debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "output: %f\n", static_cast<double>(output));

            if ((double)output > config.http_param_threshold)
            {
                kaizen_stats.client_body_alerts++;
                debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "<ALERT>\n");
                DetectionEngine::queue_event(KZ_GID, KZ_HTTP_SID);
                break;
            }
        }
    }

    kaizen_stats.client_body_bytes += len;
}

//--------------------------------------------------------------------------
// HTTP uri event handler
//--------------------------------------------------------------------------

class HttpUriHandler : public DataHandler
{
public:
    HttpUriHandler(Kaizen& kz)
        : DataHandler(KZ_NAME), inspector(kz) {}

    void handle(DataEvent&, Flow*) override;

private:
    Kaizen& inspector;
};

void HttpUriHandler::handle(DataEvent& de, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(kaizen_prof);

    const std::vector<BinaryClassifier*>& classifiers = KaizenEngine::get_classifiers(KaizenEngine::ClassifierType::HTTP);
    const KaizenConfig config = inspector.get_config();
    HttpEvent* he = (HttpEvent*)&de;

    int32_t query_len = 0;
    const char* query = (const char*)he->get_uri_query(query_len);

    if (!query || query_len <= 0 || classifiers.empty())
        return;

    const size_t len = std::min((size_t)config.uri_depth, (size_t)query_len);
    kaizen_stats.uri_bytes += len;

    for (size_t i = 0; i < classifiers.size(); ++i)
    {
        BinaryClassifier* classifier = classifiers[i];
        assert(classifier);

        float output = 0.0;
        kaizen_stats.libml_calls++;

        if (!classifier->run(query, len, output))
            continue;

        debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu input (query): %.*s\n", i, (int)len, query);
        debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu output: %f\n", i, static_cast<double>(output));

        if ((double)output > config.http_param_threshold)
        {
            kaizen_stats.uri_alerts++;
            debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu <ALERT>\n", i);
            DetectionEngine::queue_event(KZ_GID, KZ_HTTP_SID);
            break;
        }
    }
}

//--------------------------------------------------------------------------
// FTP cmd event handler
//--------------------------------------------------------------------------

class FtpRequestHandler : public DataHandler
{
public:
    FtpRequestHandler(Kaizen& kz)
        : DataHandler(KZ_NAME), inspector(kz) {}

    void handle(DataEvent&, Flow*) override;

private:
    Kaizen& inspector;
};

void FtpRequestHandler::handle(DataEvent& de, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(kaizen_prof);

    const std::vector<BinaryClassifier*>& classifiers = KaizenEngine::get_classifiers(KaizenEngine::ClassifierType::FTP);
    const KaizenConfig config = inspector.get_config();

    FtpRequestEvent* fe = (FtpRequestEvent*)&de;
    const FTP_CLIENT_REQ& req = fe->get_request();

    const char* data = req.cmd_line;
    int32_t data_len = req.cmd_line_size;

    if (!data || data_len <= 0 || classifiers.empty())
        return;

    const size_t len = std::min((size_t)config.ftp_request_depth, (size_t)data_len);
    kaizen_stats.ftp_cmd_bytes += len;
    kaizen_stats.libml_calls++;

    for (size_t i = 0; i < classifiers.size(); ++i)
    {
        BinaryClassifier* classifier = classifiers[i];
        assert(classifier);

        float output = 0.0;
        if (!classifier->run(data, len, output))
            continue;

        debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu input (FTP cmd): %.*s\n", i, (int)len, data);
        debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu output: %f\n", i, static_cast<double>(output));

        if ((double)output > config.ftp_cmd_threshold)
        {
            kaizen_stats.ftp_cmd_alerts++;
            debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu <ALERT>\n", i);
            DetectionEngine::queue_event(KZ_GID, KZ_FTP_SID);
            break;
        }
    }
}

class FtpResponseHandler : public DataHandler
{
public:
    FtpResponseHandler(Kaizen& kz)
        : DataHandler(KZ_NAME), inspector(kz) {}

    void handle(DataEvent&, Flow*) override;

private:
    Kaizen& inspector;
};

void FtpResponseHandler::handle(DataEvent& de, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(kaizen_prof);

    const std::vector<BinaryClassifier*>& classifiers = KaizenEngine::get_classifiers(KaizenEngine::ClassifierType::FTP);

    const KaizenConfig config = inspector.get_config();

    FtpResponseEvent* fe = static_cast<FtpResponseEvent*>(&de);
    const FTP_SERVER_RSP& rsp = fe->get_response();

    const char* data = rsp.msg_begin;
    int32_t data_len = rsp.msg_size;

    std::cout << "FTP Res " << std::endl;
    if (!data || data_len <= 0 || classifiers.empty())
        return;

    const size_t len = std::min(
        static_cast<size_t>(config.ftp_response_depth),
        static_cast<size_t>(data_len));

    kaizen_stats.ftp_cmd_bytes += len;
    kaizen_stats.libml_calls++;

    for (size_t i = 0; i < classifiers.size(); ++i)
    {
        BinaryClassifier* classifier = classifiers[i];
        assert(classifier);

        float output = 0.0;
        if (!classifier->run(data, len, output))
            continue;

        debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu input (FTP response): %.*s\n", i, static_cast<int>(len), data);
        debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu output: %f\n", i, static_cast<double>(output));

        if (static_cast<double>(output) > config.ftp_cmd_threshold)
        {
            kaizen_stats.ftp_cmd_alerts++;
            debug_logf(kaizen_trace, TRACE_CLASSIFIER, nullptr, "Model %zu <ALERT>\n", i);
            DetectionEngine::queue_event(KZ_GID, KZ_FTP_SID);
            break;
        }
    }
}


//--------------------------------------------------------------------------
// inspector
//--------------------------------------------------------------------------

void Kaizen::show(const SnortConfig*) const
{
    ConfigLogger::log_limit("uri_depth", config.uri_depth, -1);
    ConfigLogger::log_limit("client_body_depth", config.client_body_depth, -1);
    ConfigLogger::log_limit("ftp_request_depth", config.ftp_request_depth, -1);
    ConfigLogger::log_limit("ftp_response_depth", config.ftp_response_depth, -1);
    ConfigLogger::log_value("ftp_cmd_threshold", config.ftp_cmd_threshold);
    ConfigLogger::log_value("http_param_threshold", config.http_param_threshold);
}

bool Kaizen::configure(SnortConfig* sc)
{

    if (config.uri_depth != 0)
        DataBus::subscribe(http_pub_key, HttpEventIds::REQUEST_HEADER, new HttpUriHandler(*this));

    if (config.client_body_depth != 0)
        DataBus::subscribe(http_pub_key, HttpEventIds::REQUEST_BODY, new HttpBodyHandler(*this));

    if (config.ftp_request_depth != 0)
        DataBus::subscribe(ftp_pub_key, FtpEventIds::FTP_REQUEST, new FtpRequestHandler(*this));
    
    if (config.ftp_response_depth != 0)
        DataBus::subscribe(ftp_pub_key, FtpEventIds::FTP_RESPONSE, new FtpResponseHandler(*this));

    if(!InspectorManager::get_inspector(KZ_ENGINE_NAME, true, sc))
    {
        ParseError("snort_ml requires %s to be configured in the global policy.", KZ_ENGINE_NAME);
        return false;
    }

    return true;
}

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new KaizenModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* kaizen_ctor(Module* m)
{
    KaizenModule* km = (KaizenModule*)m;
    return new Kaizen(km->get_conf());
}

static void kaizen_dtor(Inspector* p)
{
    assert(p);
    delete p;
}

static const InspectApi kaizen_api =
{
    {
#if defined(HAVE_LIBML) || defined(REG_TEST)
        PT_INSPECTOR,
#else
        PT_MAX,
#endif
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        KZ_NAME,
        KZ_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__ANY_IP,  // proto_bits;
    nullptr,  // buffers
    nullptr,  // service
    nullptr,  // pinit
    nullptr,  // pterm
    nullptr,  // tinit
    nullptr,  // tterm
    kaizen_ctor,
    kaizen_dtor,
    nullptr,  // ssn
    nullptr   // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_kaizen[] =
#endif
{
    &kaizen_api.base,
    nullptr
};