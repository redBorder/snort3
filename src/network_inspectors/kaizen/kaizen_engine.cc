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
#include <iostream>  // <--- Added for std::cout

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

static thread_local std::vector<BinaryClassifier*>* http_classifiers_ptr = nullptr;
static thread_local std::vector<BinaryClassifier*>* ftp_classifiers_ptr = nullptr;

static std::vector<BinaryClassifier*>& get_classifiers_storage(KaizenEngine::ClassifierType type)
{
    thread_local std::vector<BinaryClassifier*>*& ptr =
        (type == KaizenEngine::ClassifierType::HTTP) ? http_classifiers_ptr : ftp_classifiers_ptr;

    if (!ptr)
    {
        std::cout << "[DEBUG] Initializing classifiers storage for type: " << (type == KaizenEngine::ClassifierType::HTTP ? "HTTP" : "FTP") << std::endl;
        ptr = new std::vector<BinaryClassifier*>();
    }

    return *ptr;
}

static bool build_classifier(const string& model, BinaryClassifier*& dst)
{
    std::cout << "[DEBUG] Building classifier for model, size: " << model.size() << std::endl;
    dst = new BinaryClassifier();
    bool result = dst->build(model);
    std::cout << "[DEBUG] Classifier build result: " << (result ? "success" : "failure") << std::endl;
    return result;
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
    { "http_param_models", Parameter::PT_LIST, model_params, nullptr, "List of ML models" },
    { "ftp_cmd_models", Parameter::PT_LIST, model_params, nullptr, "List of ML models" },
    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};


KaizenEngineModule::KaizenEngineModule() : Module(KZ_ENGINE_NAME, KZ_ENGINE_HELP, kaizen_engine_params) 
{
    std::cout << "[DEBUG] KaizenEngineModule constructed" << std::endl;
}

bool KaizenEngineModule::set(const char* fqn, Value& v, SnortConfig*)
{
    std::cout << "[DEBUG] KaizenEngineModule::set called with fqn: " << fqn << ", value: " << v.get_string() << std::endl;

    if (strcmp(fqn, "snort_ml_engine.http_param_models.path") == 0)
    {
        conf.http_param_model_paths.push_back(v.get_string());
        std::cout << "[DEBUG] Added HTTP model path: " << v.get_string() << std::endl;
        return true;
    }

    if (strcmp(fqn, "snort_ml_engine.ftp_cmd_models.path") == 0)
    {
        conf.ftp_cmd_model_paths.push_back(v.get_string());
        std::cout << "[DEBUG] Added FTP model path: " << v.get_string() << std::endl;
        return true;
    }

    std::cout << "[DEBUG] Unknown config key in set: " << fqn << std::endl;
    return false;
}

//--------------------------------------------------------------------------
// reload tuner for models
//--------------------------------------------------------------------------

class KaizenReloadTuner : public snort::ReloadResourceTuner
{
public:
    KaizenReloadTuner(const std::vector<std::string>& models, KaizenEngine::ClassifierType type, const char* type_label)
        : models(models), type(type), label(type_label) 
    {
        std::cout << "[DEBUG] KaizenReloadTuner created for type: " << label << ", model count: " << models.size() << std::endl;
    }

    ~KaizenReloadTuner() override
    {
        std::cout << "[DEBUG] KaizenReloadTuner destroyed for type: " << label << std::endl;
    }

    bool tinit() override
    {
        std::cout << "[DEBUG] KaizenReloadTuner tinit called for type: " << label << std::endl;
        std::vector<BinaryClassifier*>& classifiers = get_classifiers_storage(type);

        for (auto* c : classifiers)
        {
            std::cout << "[DEBUG] Deleting existing classifier for type: " << label << std::endl;
            delete c;
        }
        classifiers.clear();

        for (const auto& model : models)
        {
            BinaryClassifier* c = nullptr;
            if (!build_classifier(model, c))
                ErrorMessage("Can't build the %s classifier model: %s\n", label, model.c_str());
            classifiers.push_back(c);
            std::cout << "[DEBUG] Added classifier for model size: " << model.size() << " to " << label << std::endl;
        }

        std::cout << "[DEBUG] KaizenReloadTuner tinit completed for type: " << label << std::endl;
        return false;
    }

    bool tune_packet_context() override 
    { 
        std::cout << "[DEBUG] KaizenReloadTuner tune_packet_context called for type: " << label << std::endl;
        return true; 
    }
    bool tune_idle_context() override 
    { 
        std::cout << "[DEBUG] KaizenReloadTuner tune_idle_context called for type: " << label << std::endl;
        return true; 
    }

private:
    const std::vector<std::string>& models;
    KaizenEngine::ClassifierType type;
    const char* label;
};

//--------------------------------------------------------------------------
// inspector
//--------------------------------------------------------------------------

KaizenEngine::KaizenEngine(const KaizenEngineConfig& c) : config(c)
{
    std::cout << "[DEBUG] KaizenEngine constructor called" << std::endl;
    KaizenModelBuffers buffers = read_models();

    auto kaizen_validate = [this](std::vector<std::string>& target,
                                      std::vector<std::string>&& source,
                                      const std::vector<std::string>& paths)
    {
        std::cout << "[DEBUG] Validating models, count: " << source.size() << std::endl;
        target = std::move(source);
        for (size_t i = 0; i < target.size(); ++i)
        {
            std::cout << "[DEBUG] Validating model at index " << i << " with path: " << paths[i] << std::endl;
            if (!validate_model(target[i]))
                ParseError("Can't build the classifier model %s.", paths[i].c_str());
        }
        std::cout << "[DEBUG] Validation complete" << std::endl;
    };

    kaizen_validate(http_param_models, std::move(buffers.http_models), config.http_param_model_paths);
    kaizen_validate(ftp_cmd_models, std::move(buffers.ftp_models), config.ftp_cmd_model_paths);
}

void KaizenEngine::show(const SnortConfig*) const
{
    std::cout << "[DEBUG] KaizenEngine::show called" << std::endl;
    for (const auto& path : config.http_param_model_paths)
        ConfigLogger::log_value("http_param_model", path.c_str());

    for (const auto& path : config.ftp_cmd_model_paths)
        ConfigLogger::log_value("ftp_cmd_model", path.c_str());
}

void load_model_files(const std::vector<std::string>& model_paths, std::vector<std::string>& out_buffers, const char* error_prefix)
{
    std::cout << "[DEBUG] load_model_files called, model count: " << model_paths.size() << std::endl;
    for (const auto& model_path : model_paths)
    {
        const char* hint = model_path.c_str();
        std::string path;
        size_t size = 0;

        std::cout << "[DEBUG] Loading model file: " << hint << std::endl;

        if (!get_config_file(hint, path) || !get_file_size(path, size))
            ParseError("%s: could not read model file: %s", error_prefix, hint);

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
            ParseError("%s: could not read model file: %s", error_prefix, hint);

        if (size == 0)
            ParseError("%s: empty model file: %s", error_prefix, hint);

        std::string buffer(size, '\0');
        file.read(&buffer[0], std::streamsize(size));
        out_buffers.push_back(std::move(buffer));
        std::cout << "[DEBUG] Loaded model file: " << hint << " size: " << size << std::endl;
    }
}

KaizenModelBuffers KaizenEngine::read_models()
{
    std::cout << "[DEBUG] KaizenEngine::read_models called" << std::endl;
    KaizenModelBuffers model_buffers;

    load_model_files(config.http_param_model_paths, model_buffers.http_models, "snort_ml_engine");
    load_model_files(config.ftp_cmd_model_paths, model_buffers.ftp_models, "snort_ml_engine");

    std::cout << "[DEBUG] KaizenEngine::read_models completed" << std::endl;
    return model_buffers;
}

bool KaizenEngine::validate_model(const string& model)
{
    std::cout << "[DEBUG] Validating model, size: " << model.size() << std::endl;
    BinaryClassifier* test_classifier = nullptr;
    bool res = build_classifier(model, test_classifier);
    delete test_classifier;
    std::cout << "[DEBUG] Model validation result: " << (res ? "success" : "failure") << std::endl;
    return res;
}

static void rebuild_classifiers(std::vector<BinaryClassifier*>& storage, const std::vector<std::string>& models, const char* label)
{
    std::cout << "[DEBUG] Rebuilding classifiers for: " << label << ", model count: " << models.size() << std::endl;

    for (auto* c : storage)
    {
        std::cout << "[DEBUG] Deleting old classifier in rebuild for: " << label << std::endl;
        delete c;
    }
    storage.clear();

    for (const auto& model : models)
    {
        BinaryClassifier* c = nullptr;
        if (!build_classifier(model, c))
            ErrorMessage("Can't build the %s classifier model: %s\n", label, model.c_str());
        storage.push_back(c);
        std::cout << "[DEBUG] Added new classifier for model size: " << model.size() << " to " << label << std::endl;
    }
}

void KaizenEngine::tinit()
{
    std::cout << "[DEBUG] KaizenEngine::tinit called" << std::endl;
    rebuild_classifiers(get_classifiers_storage(KaizenEngine::ClassifierType::HTTP), http_param_models, "HTTP");
    rebuild_classifiers(get_classifiers_storage(KaizenEngine::ClassifierType::FTP), ftp_cmd_models, "FTP");
}

void KaizenEngine::tterm()
{
    std::cout << "[DEBUG] KaizenEngine::tterm called" << std::endl;
    for (KaizenEngine::ClassifierType type : {KaizenEngine::ClassifierType::HTTP, KaizenEngine::ClassifierType::FTP})
    {
        std::vector<BinaryClassifier*>& classifiers = get_classifiers_storage(type);
        std::cout << "[DEBUG] Deleting classifiers for type: " << (type == KaizenEngine::ClassifierType::HTTP ? "HTTP" : "FTP") << std::endl;

        for (auto* c : classifiers)
            delete c;
        classifiers.clear();
    }
    std::cout << "[DEBUG] KaizenEngine::tterm completed" << std::endl;
}

void KaizenEngine::install_reload_handler(SnortConfig* sc)
{
    std::cout << "[DEBUG] KaizenEngine::install_reload_handler called" << std::endl;
    sc->register_reload_handler(new KaizenReloadTuner(http_param_models, KaizenEngine::ClassifierType::HTTP, "HTTP"));
    sc->register_reload_handler(new KaizenReloadTuner(ftp_cmd_models, KaizenEngine::ClassifierType::FTP, "FTP"));
}

const std::vector<BinaryClassifier*>& KaizenEngine::get_classifiers(KaizenEngine::ClassifierType type)
{
    std::cout << "[DEBUG] KaizenEngine::get_classifiers called for type: " << (type == KaizenEngine::ClassifierType::HTTP ? "HTTP" : "FTP") << std::endl;
    return get_classifiers_storage(type);
}

//--------------------------------------------------------------------------
// api stuff
//--------------------------------------------------------------------------

static Module* mod_ctor()
{
    std::cout << "[DEBUG] Module constructor called" << std::endl;
    return new KaizenEngineModule;
}

static void mod_dtor(Module* m)
{
    std::cout << "[DEBUG] Module destructor called" << std::endl;
    delete m;
}

static Inspector* kaizen_engine_ctor(Module* m)
{
    std::cout << "[DEBUG] Inspector constructor called" << std::endl;
    KaizenEngineModule* mod = (KaizenEngineModule*)m;
    return new KaizenEngine(mod->get_config());
}

static void kaizen_engine_dtor(Inspector* p)
{
    assert(p);
    std::cout << "[DEBUG] Inspector destructor called" << std::endl;
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
    PROTO_BIT__NONE,  // proto_bits;
    nullptr,  // buffers
    nullptr,  // service
    nullptr,  // pinit
    nullptr,  // pterm
    nullptr,  // tinit
    nullptr,  // tterm
    kaizen_engine_ctor,
    kaizen_engine_dtor,
    nullptr,  // ssn
    nullptr   // reset
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
