//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2004-2013 Sourcefire, Inc.
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

// reputation_inspect.cc author Hui Cao <huica@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "reputation_inspect.h"

#include "detection/detection_engine.h"
#include "detection/signature.h"
#include "log/messages.h"
#include "main/snort.h"
#include "main/snort_config.h"
#include "packet_io/active.h"
#include "packet_io/packet_tracer.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "pub_sub/auxiliary_ip_event.h"
#include "pub_sub/reputation_events.h"
#include "utils/util.h"
#include <optional>
#include "reputation_parse.h"
#include "detection/detect.h"
#include "geoip/rbgeoip.h"
#include <iostream>

using namespace snort;

THREAD_LOCAL ProfileStats reputation_perf_stats;
THREAD_LOCAL ReputationStats reputationstats;

const int FLAG_COUNTRY = 1 << 0;
const int FLAG_CONTINENT = 1 << 1;

static unsigned pub_id = 0;

const PegInfo reputation_peg_names[] =
{
{ CountType::SUM, "packets", "total packets processed" },
{ CountType::SUM, "blocked", "number of packets blocked" },
{ CountType::SUM, "trusted", "number of packets trusted" },
{ CountType::SUM, "monitored", "number of packets monitored" },
{ CountType::SUM, "geo_ip_blocked", "number of packets blocked by geoip" },
{ CountType::SUM, "geo_ip_trusted", "number of packets trusted by geoip" },
{ CountType::SUM, "geo_ip_monitored", "number of packets monitored by geoip" },
{ CountType::SUM, "memory_allocated", "total memory allocated" },
{ CountType::SUM, "aux_ip_blocked", "number of auxiliary ip packets blocked" },
{ CountType::SUM, "aux_ip_trusted", "number of auxiliary ip packets trusted" },
{ CountType::SUM, "aux_ip_monitored", "number of auxiliary ip packets monitored" },
{ CountType::END, nullptr, nullptr }
};

#define MANIFEST_FILENAME "interface.info"

static inline IPrepInfo* reputation_lookup(const ReputationConfig& config,
    ReputationData& data, const SfIp* ip)
{
    if (!config.scanlocal)
    {
        if (ip->is_private() )
            return nullptr;
    }

    return (IPrepInfo*)sfrt_flat_dir8x_lookup(ip, data.ip_list);
}

static inline IPdecision get_reputation(const ReputationConfig& config, ReputationData& data,
    IPrepInfo* rep_info, uint32_t& listid, uint32_t ingress_intf, uint32_t egress_intf)
{
    IPdecision decision = DECISION_NULL;

    /*Walk through the IPrepInfo lists*/
    uint8_t* base = (uint8_t*)data.ip_list;
    ListFiles& list_info = data.list_files;

    while (rep_info)
    {
        int i;
        for (i = 0; i < NUM_INDEX_PER_ENTRY; i++)
        {
            uint8_t list_index = rep_info->list_indexes[i];
            if (!list_index)
                break;
            list_index--;
            if (list_info[list_index]->all_intfs_enabled ||
                list_info[list_index]->intfs.count(ingress_intf) ||
                list_info[list_index]->intfs.count(egress_intf))
            {
                if (TRUSTED_DO_NOT_BLOCK == (IPdecision)list_info[list_index]->list_type)
                    return DECISION_NULL;
                if (config.priority == (IPdecision)list_info[list_index]->list_type )
                {
                    listid = list_info[list_index]->list_id;
                    return  ((IPdecision)list_info[list_index]->list_type);
                }
                else if ( decision < list_info[list_index]->list_type)
                {
                    decision = (IPdecision)list_info[list_index]->list_type;
                    listid = list_info[list_index]->list_id;
                }
            }
        }

        if (!rep_info->next)
            break;
        rep_info = (IPrepInfo*)(&base[rep_info->next]);
    }

    return decision;
}

struct DecisionInfo {
    const char* type;
    const char* reason;
    const char* action;
};

static const std::unordered_map<IPdecision, DecisionInfo> decision_map = {
    { BLOCKED,    { "BLOCKED",   "Blocked IP",    "reputation-drop"  } },
    { MONITORED,  { "MONITORED", "Monitoring IP", "reputation-alert" } },
    { TRUSTED,    { "TRUSTED",   "Trusted IP",    "reputation-pass"  } }
};

struct GeoInfo {
    std::string country;
    std::string continent;
};

static bool snort_not_inline(const ReputationConfig& config){
    return !(config.snort_flags & RUN_FLAG__INLINE);
}

static GeoInfo lookup_geo(const SfIpString& ip) {
    GeoInfo gi;
    auto mgr = GeoIpLoader::Manager::getInstance();
    gi.country   = mgr->getCountryByIP(ip);
    gi.continent = mgr->getContinentByIP(ip);
    if (gi.country.empty())   gi.country = "Unknown";
    if (gi.continent.empty()) gi.continent = "Unknown";
    return gi;
}

struct RbCustomAlert {
    DecisionInfo info;
    std::string src_ip;
    std::string dst_ip;
    GeoInfo src_geo;
    GeoInfo dst_geo;
    const char* decision_maker;
    int geo_flags;
};

static std::string build_alert_message(const RbCustomAlert& data) {
    std::ostringstream oss;

    oss << '"';

    oss << "Traffic from " << data.src_ip
        << " (located in " << data.src_geo.country << ", " << data.src_geo.continent << ") "
        << "to " << data.dst_ip
        << " (located in " << data.dst_geo.country << ", " << data.dst_geo.continent << ") ";

    if (data.info.action == "drop") {
        oss << "was blocked";
    } else if (data.info.action == "pass") {
        oss << "was allowed";
    } else if (data.info.action == "alert") {
        oss << "was flagged for monitoring";
    } else {
        oss << "resulted in action: " << data.info.action;
    }

    if (data.geo_flags & FLAG_COUNTRY) {
        oss << " due to country-level restrictions";
    } else if (data.geo_flags & FLAG_CONTINENT) {
        oss << " due to continent-level restrictions";
    } else {
        oss << " based on IP-based policy rules";
    }

    oss << ". Decision type: " << data.info.type
        << ". Decision made by: " << data.decision_maker
        << '"';

    return oss.str();
}

std::unordered_map<std::string, std::string> generate_custom_alert(
    const ip::IpApi& ip_api,
    IPdecision decision,
    int geo_flags
) {
    if (decision == BLOCKED_SRC || decision == BLOCKED_DST)   decision = BLOCKED;
    else if (decision == MONITORED_SRC || decision == MONITORED_DST) decision = MONITORED;
    else if (decision == TRUSTED_SRC || decision == TRUSTED_DST)     decision = TRUSTED;

    const auto& info = decision_map.at(decision);

    SfIpString src_ip, dst_ip;
    ip_api.get_src()->ntop(src_ip);
    ip_api.get_dst()->ntop(dst_ip);

    GeoInfo src_geo = lookup_geo(src_ip);
    GeoInfo dst_geo = lookup_geo(dst_ip);

    const char* decision_maker = "intrusion-reputation-ip";
    if (geo_flags & FLAG_COUNTRY)   decision_maker = "intrusion-reputation-country";
    else if (geo_flags & FLAG_CONTINENT) decision_maker = "intrusion-reputation-continent";

    RbCustomAlert alert;
    alert.info = info;
    alert.src_ip = src_ip;
    alert.src_geo = src_geo;
    alert.dst_ip = dst_ip;
    alert.dst_geo = dst_geo;
    alert.decision_maker = decision_maker;
    alert.geo_flags = geo_flags;

    std::string msg = build_alert_message(alert);

    return {{"message", std::move(msg)}, {"action", info.action}};
}

struct GeoAlert {
    char* msg;
    char* action;
};

void FireCustomAlert(GeoAlert alert, Packet* p){
    SigInfo sig_info;
    sig_info.sid = -1;
    sig_info.gid = GID_REPUTATION;
    sig_info.rev = 1;
    RbCallCustomAlert(alert.msg, alert.action, sig_info, p, 3);
}

static bool decision_per_layer(const ReputationConfig& config, ReputationData& data,
    uint32_t& iplist_id, uint32_t ingress_intf, uint32_t egress_intf, const ip::IpApi& ip_api,
    IPdecision* decision_final)
{
    const SfIp* ip = ip_api.get_src();
    IPrepInfo* result = reputation_lookup(config, data, ip);
    if (result)
    {
        IPdecision decision = get_reputation(config, data, result, iplist_id, ingress_intf,
            egress_intf);

        if (decision == BLOCKED)
            *decision_final = BLOCKED_SRC;
        else if (decision == MONITORED)
            *decision_final = MONITORED_SRC;
        else if (decision == TRUSTED)
            *decision_final = TRUSTED_SRC;
        else
            *decision_final = decision;

        if ( config.priority == decision)
            return true;
    }

    ip = ip_api.get_dst();
    result = reputation_lookup(config, data, ip);
    if (result)
    {
        IPdecision decision = get_reputation(config, data, result, iplist_id, ingress_intf,
            egress_intf);

        if (decision == BLOCKED)
            *decision_final = BLOCKED_DST;
        else if (decision == MONITORED)
            *decision_final = MONITORED_DST;
        else if (decision == TRUSTED)
            *decision_final = TRUSTED_DST;
        else
            *decision_final = decision;

        if ( config.priority == decision)
            return true;
    }

    return false;
}

static std::optional<IPdecision> apply_geo_action(
    const std::string& key,
    bool is_src,
    const std::unordered_map<std::string, IPdecision>& action_map
) {
    auto it = action_map.find(key);
    if (it == action_map.end()) {
        return std::nullopt;
    }

    IPdecision base_dec = it->second;

    switch (base_dec) {
        case BLOCKED:
            reputationstats.geo_ip_blocked++;
            return is_src ? BLOCKED_SRC : BLOCKED_DST;
        case TRUSTED:
            reputationstats.geo_ip_trusted++;
            return is_src ? TRUSTED_SRC : TRUSTED_DST;
        case MONITORED:
            reputationstats.geo_ip_monitored++;
            return is_src ? MONITORED_SRC : MONITORED_DST;
        default:
            return base_dec;
    }
}

static std::pair<IPdecision, int> resolve_endpoint_geo(
    const SfIp* ip_ptr,
    bool is_src,
    ip::IpApi& ip_api,
    const ReputationConfig& config
) {
    if (!ip_ptr) {
        return {DECISION_NULL, 0};
    }

    SfIpString ip_str;
    if (is_src) {
        ip_api.get_src()->ntop(ip_str);
    } else {
        ip_api.get_dst()->ntop(ip_str);
    }

    std::string key = static_cast<std::string>(ip_str);
    if (key.empty()) {
        return {DECISION_NULL, 0};
    }

    std::string country   = GeoIpLoader::Manager::getInstance()->getCountryByIP(key);
    std::string continent = GeoIpLoader::Manager::getInstance()->getContinentByIP(key);

    int flags = 0;
    if (auto dec = apply_geo_action(country, is_src, config.geoip_actions_countries)) {
        flags |= FLAG_COUNTRY;
        return {*dec, flags};
    }

    if (auto dec = apply_geo_action(continent, is_src, config.geoip_actions_continents)) {
        flags |= FLAG_CONTINENT;
        return {*dec, flags};
    }

    return {DECISION_NULL, flags};
}

std::pair<IPdecision, int> resolve_geo_decision(
    const ReputationConfig& config,
    ip::IpApi& ip_api
) {
    auto result = resolve_endpoint_geo(ip_api.get_src(), true, ip_api, config);

    if (result.first == DECISION_NULL) {
        result = resolve_endpoint_geo(ip_api.get_dst(), false, ip_api, config);
    }

    return result;
}

static std::pair<IPdecision,int> reputation_decision(
    const ReputationConfig& config,
    ReputationData& data,
    Packet* p,
    uint32_t& iplist_id
) {
    IPdecision decision_final = DECISION_NULL;
    int geo_flags = 0;

    if (snort_not_inline(config))
        return {decision_final, geo_flags}; // redBorder patch (only act if -Q)

    uint32_t ingress_intf = 0, egress_intf = 0;
    if (p->pkth) {
        ingress_intf = p->pkth->ingress_index;
        egress_intf  = (p->pkth->egress_index < 0) 
                     ? ingress_intf 
                     : p->pkth->egress_index;
    }

    if (data.ip_list && config.nested_ip == INNER) {
        decision_per_layer(
            config, data, iplist_id,
            ingress_intf, egress_intf,
            p->ptrs.ip_api, &decision_final
        );

        if (decision_final == DECISION_NULL) {
            auto [new_decision, gf] = resolve_geo_decision(config, p->ptrs.ip_api);
            decision_final = new_decision;
            geo_flags     = gf;
        }

        return {decision_final, geo_flags};
    }

    // Save/restore for OUTER or ALL
    ip::IpApi blocked_api;
    ip::IpApi tmp_api     = p->ptrs.ip_api;
    IpProtocol tmp_next   = p->get_ip_proto_next();
    int8_t     num_layer  = 0;

    if (data.ip_list) {
        if (config.nested_ip == OUTER) {
            layer::set_outer_ip_api(p, p->ptrs.ip_api, p->ip_proto_next, num_layer);
            decision_per_layer(
                config, data, iplist_id, ingress_intf, egress_intf,
                p->ptrs.ip_api, &decision_final
            );
        }
        else if (config.nested_ip == ALL) {
            bool done = false;
            IPdecision decision_current = DECISION_NULL;
            while (!done && layer::set_outer_ip_api(
                    p, p->ptrs.ip_api, p->ip_proto_next, num_layer
                )) {
                done = decision_per_layer(
                    config, data, iplist_id, ingress_intf, egress_intf,
                    p->ptrs.ip_api, &decision_current
                );
                if (decision_current != DECISION_NULL) {
                    if (decision_current == BLOCKED_SRC || decision_current == BLOCKED_DST)
                        blocked_api = p->ptrs.ip_api;

                    decision_final   = decision_current;
                    decision_current = DECISION_NULL;
                }
            }
        }
        else {
            assert(false); // unreachable
        }
    }

    if (decision_final == DECISION_NULL) {
        auto [new_decision, gf] = resolve_geo_decision(config, p->ptrs.ip_api);
        decision_final = new_decision;
        geo_flags      = gf;
    }

    if (decision_final != BLOCKED_SRC && decision_final != BLOCKED_DST)
        p->ptrs.ip_api = tmp_api;
    else if (config.nested_ip == ALL && p->ptrs.ip_api != blocked_api)
        p->ptrs.ip_api = blocked_api;

    p->ip_proto_next = tmp_next;

    return {decision_final, geo_flags};
}

static IPdecision snort_reputation_aux_ip(const ReputationConfig& config, ReputationData& data,
    Packet* p, const SfIp* ip)
{
    IPdecision decision = DECISION_NULL;
    if(snort_not_inline(config))
        return decision;  // redBorder patch (only act if -Q)
    uint32_t ingress_intf = 0;
    uint32_t egress_intf = 0;

    if (p->pkth)
    {
        ingress_intf = p->pkth->ingress_index;
        if (p->pkth->egress_index < 0)
            egress_intf = ingress_intf;
        else
            egress_intf = p->pkth->egress_index;
    }

    uint32_t iplist_id = 0;

    if(data.ip_list){
        IPrepInfo* result = reputation_lookup(config, data, ip);
        if (result)
        {
            decision = get_reputation(config, data, result, iplist_id, ingress_intf,
                egress_intf);
        }
    }

    IPdecision original_decision = decision;

    auto [new_decision, geo_flags] = resolve_geo_decision(config, p->ptrs.ip_api);

    if(new_decision == BLOCKED_SRC || new_decision == BLOCKED_DST){
        new_decision = BLOCKED;
    } else if(new_decision == MONITORED_SRC || new_decision == MONITORED_DST){
        new_decision = MONITORED;
    } else if(new_decision == TRUSTED_SRC || new_decision == TRUSTED_DST){
        new_decision = TRUSTED;
    }

    if(new_decision == DECISION_NULL){
        new_decision = original_decision;
        geo_flags = 0;
    }

    decision = new_decision;

    if(decision != DECISION_NULL){
        auto alert = generate_custom_alert(p->ptrs.ip_api, decision, geo_flags);
        GeoAlert rep_alert;
        rep_alert.msg = const_cast<char*>(alert["message"].c_str());
        rep_alert.action = const_cast<char*>(alert["action"].c_str());
        FireCustomAlert(rep_alert, p);
    }

    /* redBorder custom alerter, bypass detection engine and all snort decisions
        it will send alert data directly to the running alerter
    */

    if (decision == BLOCKED)
    {
        // Prior to IPRep logging, IPS policy must be set to the default policy,
        set_ips_policy(get_default_ips_policy(SnortConfig::get_conf()));

        DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_BLOCKLIST_DST);
        ReputationVerdictEvent event(p, REP_VERDICT_BLOCKED, iplist_id, false);
        DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
        p->active->drop_packet(p, true);

        // disable all preproc analysis and detection for this packet
        DetectionEngine::disable_all(p);
        p->active->block_session(p, true);
        p->active->set_drop_reason("reputation");
        reputationstats.aux_ip_blocked++;
        if (PacketTracer::is_active())
        {
            char ip_str[INET6_ADDRSTRLEN];
            sfip_ntop(ip, ip_str, sizeof(ip_str));
            PacketTracer::log("Reputation: packet blocked for auxiliary ip %s, drop\n",
                ip_str);
        }
    }
    else if (decision == MONITORED)
    {
        DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_MONITOR_DST);
        ReputationVerdictEvent event(p, REP_VERDICT_MONITORED, iplist_id, false);
        DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
        reputationstats.aux_ip_monitored++;
    }
    else if (decision == TRUSTED)
    {
        DetectionEngine::queue_event(GID_REPUTATION, REPUTATION_EVENT_ALLOWLIST_DST);
        ReputationVerdictEvent event(p, REP_VERDICT_TRUSTED, iplist_id, false);
        DataBus::publish(pub_id, ReputationEventIds::REP_MATCHED, event);
        p->active->trust_session(p, true);
        reputationstats.aux_ip_trusted++;
    }
    
    return decision;
}

static const char* to_string(IPdecision ipd)
{
    switch (ipd)
    {
    case BLOCKED:
        return "blocked";
    case TRUSTED:
        return "trusted";
    case MONITORED:
        return "monitored";
    case BLOCKED_SRC:
        return "blocked_src";
    case BLOCKED_DST:
        return "blocked_dst";
    case TRUSTED_SRC:
        return "trusted_src";
    case TRUSTED_DST:
        return "trusted_dst";
    case TRUSTED_DO_NOT_BLOCK:
        return "trusted_do_not_block";
    case MONITORED_SRC:
        return "monitored_src";
    case MONITORED_DST:
        return "monitored_dst";
    case DECISION_NULL:
    case DECISION_MAX:
    default:
        return "";
    }
}

static void populate_trace_data(IPdecision& decision, Packet* p, uint32_t iplist_id)
{
    char addr[INET6_ADDRSTRLEN];
    const SfIp* ip = nullptr;

    if (BLOCKED_SRC == decision or MONITORED_SRC == decision or TRUSTED_SRC == decision)
    {
        ip = p->ptrs.ip_api.get_src();
    }
    else if (BLOCKED_DST == decision or MONITORED_DST == decision or TRUSTED_DST == decision)
    {
        ip = p->ptrs.ip_api.get_dst();
    }

    sfip_ntop(ip, addr, sizeof(addr));

    PacketTracer::daq_log("SI-IP+%" PRId64"+%s list id %u+Matched ip %s, action %s$",
        PacketTracer::get_time(),
        (TRUSTED_SRC == decision or TRUSTED_DST == decision)?"Do_not_block":"Block",
        iplist_id, addr, to_string(decision));
}

static void snort_reputation(
    const ReputationConfig& config,
    ReputationData& data,
    Packet* p
) {
    uint32_t iplist_id = 0;
    auto [decision, geo_flags] =
        reputation_decision(config, data, p, iplist_id);

    Active* act = p->active;

    if (decision != DECISION_NULL) {
        auto alert = generate_custom_alert(p->ptrs.ip_api, decision, geo_flags);
        GeoAlert rep_alert;
        rep_alert.msg    = const_cast<char*>(alert["message"].c_str());
        rep_alert.action = const_cast<char*>(alert["action"].c_str());
        FireCustomAlert(rep_alert, p);
    }

    // BLOCKED_SRC / BLOCKED_DST handling
    if (decision == BLOCKED_SRC || decision == BLOCKED_DST) {
        unsigned blocklist_event =
            (decision == BLOCKED_SRC)
                ? REPUTATION_EVENT_BLOCKLIST_SRC
                : REPUTATION_EVENT_BLOCKLIST_DST;

        DetectionEngine::queue_event(GID_REPUTATION, blocklist_event);
        ReputationVerdictEvent ev(p, REP_VERDICT_BLOCKED,
                                  iplist_id, decision == BLOCKED_SRC);
        DataBus::publish(pub_id,
                         ReputationEventIds::REP_MATCHED, ev);

        act->drop_packet(p, true);
        DetectionEngine::disable_all(p);
        act->block_session(p, true);
        if (p->flow) p->flow->set_state(Flow::FlowState::BLOCK);
        act->set_drop_reason("reputation");
        reputationstats.blocked++;
        if (PacketTracer::is_active())
            PacketTracer::log("Reputation: packet blocked, drop\n");

        if (PacketTracer::is_daq_activated())
            populate_trace_data(decision, p, iplist_id);

        return;
    }

    // Aux‐IP replay
    if (p->flow && p->flow->reload_id > 0) {
        const auto& aux_ip_list = p->flow->stash->get_aux_ip_list();
        for (const auto& ip : aux_ip_list) {
            if (snort_reputation_aux_ip(config, data, p, &ip) == BLOCKED)
                return;
        }
    }

    if (decision == DECISION_NULL) {
        return;
    }

    // MONITORED / TRUSTED events
    if (decision == MONITORED_SRC || decision == MONITORED_DST) {
        unsigned monitor_event =
            (decision == MONITORED_SRC)
                ? REPUTATION_EVENT_MONITOR_SRC
                : REPUTATION_EVENT_MONITOR_DST;

        DetectionEngine::queue_event(GID_REPUTATION, monitor_event);
        ReputationVerdictEvent ev(p, REP_VERDICT_MONITORED,
                                  iplist_id, decision == MONITORED_SRC);
        DataBus::publish(pub_id,
                         ReputationEventIds::REP_MATCHED, ev);
        reputationstats.monitored++;
    }
    else if (decision == TRUSTED_SRC || decision == TRUSTED_DST) {
        unsigned allow_event =
            (decision == TRUSTED_SRC)
                ? REPUTATION_EVENT_ALLOWLIST_SRC
                : REPUTATION_EVENT_ALLOWLIST_DST;

        DetectionEngine::queue_event(GID_REPUTATION, allow_event);
        ReputationVerdictEvent ev(p, REP_VERDICT_TRUSTED,
                                  iplist_id, decision == TRUSTED_SRC);
        DataBus::publish(pub_id,
                         ReputationEventIds::REP_MATCHED, ev);
        act->trust_session(p, true);
        reputationstats.trusted++;
    }

    if (PacketTracer::is_daq_activated())
        populate_trace_data(decision, p, iplist_id);
}

static const char* to_string(NestedIP nip)
{
    switch (nip)
    {
    case INNER:
        return "inner";
    case OUTER:
        return "outer";
    case ALL:
        return "all";
    }

    return "";
}

static const char* to_string(AllowAction aa)
{
    switch (aa)
    {
    case DO_NOT_BLOCK:
        return "do_not_block";
    case TRUST:
        return "trust";
    }

    return "";
}

class IpRepHandler : public DataHandler
{
public:
    explicit IpRepHandler(Reputation& inspector)
        : DataHandler(REPUTATION_NAME), inspector(inspector)
    { order = 5; }
    void handle(DataEvent&, Flow*) override;

private:
    Reputation& inspector;
};

void IpRepHandler::handle(DataEvent& event, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(reputation_perf_stats);
    Packet* p = const_cast<Packet*>(event.get_packet());
    assert(p);
    if (!p->has_ip())
        return;

    if (PacketTracer::is_daq_activated())
        PacketTracer::restart_timer();

    ReputationData* data = static_cast<ReputationData*>(inspector.get_thread_specific_data());
    assert(data);
    snort_reputation(inspector.get_config(), *data, p);
    ++reputationstats.packets;
}

class AuxiliaryIpRepHandler : public DataHandler
{
public:
    explicit AuxiliaryIpRepHandler(Reputation& inspector)
        : DataHandler(REPUTATION_NAME), inspector(inspector)
    { }
    void handle(DataEvent&, Flow*) override;

private:
    Reputation& inspector;
};

void AuxiliaryIpRepHandler::handle(DataEvent& event, Flow*)
{
    // cppcheck-suppress unreadVariable
    Profile profile(reputation_perf_stats);
    ReputationData* data = static_cast<ReputationData*>(inspector.get_thread_specific_data());
    assert(data);
    snort_reputation_aux_ip(inspector.get_config(), *data, DetectionEngine::get_current_packet(),
        static_cast<AuxiliaryIpEvent*>(&event)->get_ip());
}

//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

ReputationData::~ReputationData()
{
    if (reputation_segment)
        snort_free(reputation_segment);

    for (auto& file : list_files)
        delete file;
}

Reputation::Reputation(ReputationConfig* pc) : config(*pc)
{ rep_data = load_data(); }

Reputation::~Reputation()
{ delete rep_data; }

ReputationData* Reputation::load_data()
{
    ReputationData* data = new ReputationData();
    if (!config.list_dir.empty())
        ReputationParser::read_manifest(MANIFEST_FILENAME, config, *data);
    if (config.geoip_db_path.size() > 0)
        GeoIpLoader::Manager::getInstance(config.geoip_db_path);
        ReputationParser::load_geoip_manifest(config);
    ReputationParser::add_block_allow_List(config, *data);
    ReputationParser::estimate_num_entries(*data);
    if (0 >= data->num_entries)
    {
        ParseWarning(WARN_CONF,
            "reputation: can't find any allowlist/blocklist entries; disabled.");
    }
    else
    {
        ReputationParser parser;
        parser.ip_list_init(data->num_entries + 1, config, *data);
        reputationstats.memory_allocated = parser.get_usage();
    }

    return data;
}

void Reputation::swap_thread_data(ReputationData* data)
{ set_thread_specific_data(data); }

void Reputation::swap_data(ReputationData* data)
{
    delete rep_data;
    rep_data = data;
}

void Reputation::tinit()
{ set_thread_specific_data(rep_data); }

void Reputation::tterm()
{ set_thread_specific_data(nullptr); }

void Reputation::show(const SnortConfig*) const
{
    ConfigLogger::log_value("blocklist", config.blocklist_path.c_str());
    ConfigLogger::log_value("geoip_db_path", config.geoip_db_path.c_str());
    ConfigLogger::log_value("geoip_manifest_path", config.geoip_manifest_path.c_str());
    ConfigLogger::log_value("list_dir", config.list_dir.c_str());
    ConfigLogger::log_value("memcap", config.memcap);
    ConfigLogger::log_value("nested_ip", to_string(config.nested_ip));
    ConfigLogger::log_value("priority", to_string(config.priority));
    ConfigLogger::log_flag("scan_local", config.scanlocal);
    ConfigLogger::log_value("allow (action)", to_string(config.allow_action));
    ConfigLogger::log_value("allowlist", config.allowlist_path.c_str());
    ConfigLogger::log_value("monitorlist", config.monitorlist_path.c_str());
}

bool Reputation::configure(SnortConfig*)
{
    DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_SETUP, new IpRepHandler(*this));
    DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::FLOW_STATE_RELOADED, new IpRepHandler(*this));
    DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::AUXILIARY_IP, new AuxiliaryIpRepHandler(*this));
    DataBus::subscribe_network(intrinsic_pub_key, IntrinsicEventIds::PKT_WITHOUT_FLOW, new IpRepHandler(*this));

    pub_id = DataBus::get_id(reputation_pub_key);
    return true;
}

void Reputation::install_reload_handler(SnortConfig* sc)
{ sc->register_reload_handler(new ReputationReloadSwapper(*this)); }

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ReputationModule; }

static void mod_dtor(Module* m)
{ delete m; }


static Inspector* reputation_ctor(Module* m)
{
    ReputationModule* mod = (ReputationModule*)m;
    ReputationConfig* conf = mod->get_data();
    conf->snort_flags = SnortConfig::get_conf()->run_flags;
    return conf ? new Reputation(conf) : nullptr;
}

static void reputation_dtor(Inspector* p)
{
    delete p;
}

const InspectApi reputation_api =
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        REPUTATION_NAME,
        REPUTATION_HELP,
        mod_ctor,
        mod_dtor
    },
    IT_PASSIVE,
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    reputation_ctor,
    reputation_dtor,
    nullptr, // ssn
    nullptr  // reset
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &reputation_api.base,
    nullptr
};
#else
const BaseApi* nin_reputation = &reputation_api.base;
#endif
