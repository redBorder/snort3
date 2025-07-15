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
// kaizen_engine.cc author Vitalii Horbatov <vhorbato@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "kaizen_engine.h"

#include <cassert>
#include <fstream>
#include <memory>

#ifdef HAVE_LIBML
#include <libml.h>
#endif

#include "framework/decode_data.h"
#include "log/messages.h"
#include "main/reload_tuner.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "parser/parse_conf.h"
#include "utils/util.h"

using namespace snort;
using namespace std;

static thread_local vector<BinaryClassifier*>* classifiers_ptr = nullptr;

static vector<BinaryClassifier*>& get_classifiers_storage()
{
    if (!classifiers_ptr)
        classifiers_ptr = new vector<BinaryClassifier*>();
    return *classifiers_ptr;
}

static bool build_classifier(const string& model, BinaryClassifier*& dst)
{
    dst = new BinaryClassifier();
    return dst->build(model);
}

//--------------------------------------------------------------------------
// module
//--------------------------------------------------------------------------

static const Parameter model_params[] =
{
    { "path", Parameter::PT_STRING, nullptr, nullptr, "Path to model file" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

static const Parameter kaizen_engine_params[] =
{
    { "models", Parameter::PT_LIST, model_params, nullptr, "List of ML models" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


KaizenEngineModule::KaizenEngineModule() : Module(KZ_ENGINE_NAME, KZ_ENGINE_HELP, kaizen_engine_params) {}

bool KaizenEngineModule::set(const char* fqn, Value& v, SnortConfig*)
{
    if (strcmp(fqn, "snort_ml_engine.models.path") == 0)
    {
        conf.http_param_model_paths.push_back(v.get_string());
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// reload tuner
//--------------------------------------------------------------------------

class KaizenReloadTuner : public snort::ReloadResourceTuner
{
public:
    explicit KaizenReloadTuner(const vector<string>& models) : models(models) {}
    ~KaizenReloadTuner() override = default;

    bool tinit() override
    {
        vector<BinaryClassifier*>& classifiers = get_classifiers_storage();

        for (auto* c : classifiers)
            delete c;
        classifiers.clear();

        for (const auto& model : models)
        {
            BinaryClassifier* c = nullptr;
            if (!build_classifier(model, c))
                ErrorMessage("Can't build the classifier model: %s\n", model.c_str());
            classifiers.push_back(c);
        }

        return false;
    }

    bool tune_packet_context() override { return true; }
    bool tune_idle_context() override { return true; }

private:
    const vector<string>& models;
};

//--------------------------------------------------------------------------
// inspector
//--------------------------------------------------------------------------

KaizenEngine::KaizenEngine(const KaizenEngineConfig& c) : config(c)
{
    http_param_models = read_models();
    for (size_t i = 0; i < http_param_models.size(); ++i)
    {
        if (!validate_model(http_param_models[i]))
            ParseError("Can't build the classifier model %s.", config.http_param_model_paths[i].c_str());
    }
}

void KaizenEngine::show(const SnortConfig*) const
{
    for (const auto& path : config.http_param_model_paths)
        ConfigLogger::log_value("http_param_model", path.c_str());
}

vector<string> KaizenEngine::read_models()
{
    vector<string> model_buffers;

    for (const auto& model_path : config.http_param_model_paths)
    {
        const char* hint = model_path.c_str();
        string path;
        size_t size = 0;

        if (!get_config_file(hint, path) || !get_file_size(path, size))
            ParseError("snort_ml_engine: could not read model file: %s", hint);

        ifstream file(path, ios::binary);
        if (!file.is_open())
            ParseError("snort_ml_engine: could not read model file: %s", hint);

        if (size == 0)
            ParseError("snort_ml_engine: empty model file: %s", hint);

        string buffer(size, '\0');
        file.read(&buffer[0], streamsize(size));
        model_buffers.push_back(std::move(buffer));
    }

    return model_buffers;
}

bool KaizenEngine::validate_model(const string& model)
{
    BinaryClassifier* test_classifier = nullptr;
    bool res = build_classifier(model, test_classifier);
    delete test_classifier;
    return res;
}

void KaizenEngine::tinit()
{
    vector<BinaryClassifier*>& classifiers = get_classifiers_storage();

    for (auto* c : classifiers)
        delete c;
    classifiers.clear();

    for (const auto& model : http_param_models)
    {
        BinaryClassifier* c = nullptr;
        if (build_classifier(model, c))
            classifiers.push_back(c);
    }
}

void KaizenEngine::tterm()
{
    vector<BinaryClassifier*>& classifiers = get_classifiers_storage();

    for (auto* c : classifiers)
        delete c;
    classifiers.clear();
}

void KaizenEngine::install_reload_handler(SnortConfig* sc)
{
    sc->register_reload_handler(new KaizenReloadTuner(http_param_models));
}

const vector<BinaryClassifier*>& KaizenEngine::get_classifiers()
{
    return get_classifiers_storage();
}

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{ return new KaizenEngineModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* kaizen_engine_ctor(Module* m)
{
    KaizenEngineModule* mod = (KaizenEngineModule*)m;
    return new KaizenEngine(mod->get_config());
}

static void kaizen_engine_dtor(Inspector* p)
{
    assert(p);
    delete p;
}

static const InspectApi kaizen_engine_api =
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
        KZ_ENGINE_NAME,
        KZ_ENGINE_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__NONE,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    kaizen_engine_ctor,
    kaizen_engine_dtor,
    nullptr,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* nin_kaizen_engine[] =
#endif
{
    &kaizen_engine_api.base,
    nullptr
};