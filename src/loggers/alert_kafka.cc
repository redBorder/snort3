//--------------------------------------------------------------------------
// Copyright (C) 2017-2023 Cisco and/or its affiliates. All rights reserved.
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

// alert_kafka.cc author Miguel Álvarez <malvarez@redborder.com>

// preliminary version based on hacking up alert_json.cc and putting data into a buffer for sending to kafka

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <librdkafka/rdkafka.h>
#include "geoip/rbgeoip.h"
#include "macs/mac_vendors.h"
#include "detection/detection_engine.h"
#include "detection/signature.h"
#include "events/event.h"
#include "flow/flow_key.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "helpers/base64_encoder.h"
#include "log/log.h"
#include "log/log_text.h"
#include "log/binary_log.h"
#include "packet_io/active.h"
#include "packet_io/sfdaq.h"
#include "protocols/cisco_meta_data.h"
#include "protocols/eth.h"
#include "protocols/icmp4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/vlan.h"
#include "utils/stats.h"
#include "enrichment/sensor_enrichment.h"

using namespace snort;
using namespace std;

#define LOG_BUFFER (4 * K_BYTES)

static THREAD_LOCAL BinaryWriter *json_log;
MacVendorDatabase MacVendorDB;

#define S_NAME "alert_kafka"
#define D_TOPIC "rb_event"

//-------------------------------------------------------------------------
// field formatting functions
//-------------------------------------------------------------------------

/* SHOULD BE IN HELPERS */

uint64_t mac_string_to_uint64(const string &mac_address)
{
    stringstream ss;
    uint64_t mac = 0;
    unsigned int byte;

    for (size_t i = 0; i < mac_address.size(); ++i)
    {
        if (mac_address[i] != ':')
        {
            ss << mac_address[i];
        }
    }

    ss >> hex >> mac;
    return mac;
}

/* END */

struct Args
{
    Packet *pkt;
    const char *msg;
    const Event &event;
    bool comma;
    time_t timestamp;
};

bool AddTimestampField(const Args &a)
{
    time_t current_time = time(nullptr);
    if (a.comma)
    {
        BinaryWriter_Putc(json_log, ',');
    }
    BinaryWriter_Print(json_log, "\"timestamp\": ");
    BinaryWriter_Print(json_log, to_string(current_time).c_str());
    return true;
}

static void print_label(const Args &a, const char *label)
{
    if (a.comma)
        BinaryWriter_Print(json_log, ",");

    BinaryWriter_Print(json_log, " \"%s\" : ", label);
}

static bool ff_action(const Args &a)
{
    print_label(a, "action");
    BinaryWriter_Quote(json_log, a.pkt->active->get_action_string());
    return true;
}

static bool ff_class(const Args &a)
{
    const char *cls = "none";

    if (a.event.sig_info->class_type and !a.event.sig_info->class_type->text.empty())
        cls = a.event.sig_info->class_type->text.c_str();

    print_label(a, "class");
    BinaryWriter_Quote(json_log, cls);
    return true;
}

static bool ff_b64_data(const Args &a)
{
    if (!a.pkt->dsize)
        return false;

    const unsigned block_size = 2048;
    char out[2 * block_size];
    const uint8_t *in = a.pkt->data;

    unsigned nin = 0;
    Base64Encoder b64;

    print_label(a, "b64_data");
    BinaryWriter_Putc(json_log, '"');

    while (nin < a.pkt->dsize)
    {
        unsigned kin = min(a.pkt->dsize - nin, block_size);
        unsigned kout = b64.encode(in + nin, kin, out);
        BinaryWriter_Write(json_log, out, kout);
        nin += kin;
    }

    if (unsigned kout = b64.finish(out))
        BinaryWriter_Write(json_log, out, kout);

    BinaryWriter_Putc(json_log, '"');
    return true;
}

static bool ff_client_bytes(const Args &a)
{
    if (a.pkt->flow)
    {
        print_label(a, "client_bytes");
        BinaryWriter_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.client_bytes);
        return true;
    }
    return false;
}

static bool ff_client_pkts(const Args &a)
{
    if (a.pkt->flow)
    {
        print_label(a, "client_pkts");
        BinaryWriter_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.client_pkts);
        return true;
    }
    return false;
}

static bool ff_dir(const Args &a)
{
    const char *dir;

    if (a.pkt->is_from_application_client())
        dir = "C2S";
    else if (a.pkt->is_from_application_server())
        dir = "S2C";
    else
        dir = "UNK";

    print_label(a, "dir");
    BinaryWriter_Quote(json_log, dir);
    return true;
}

static bool ff_dst(const Args &a)
{
    if (a.pkt->has_ip() or a.pkt->is_data())
    {
        SfIpString ip_str;
        print_label(a, "dst");
        BinaryWriter_Quote(json_log, a.pkt->ptrs.ip_api.get_dst()->ntop(ip_str));
        return true;
    }
    return false;
}

static bool ff_dst_ap(const Args &a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if (a.pkt->has_ip() or a.pkt->is_data())
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    if (a.pkt->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP))
        port = a.pkt->ptrs.dp;

    print_label(a, "dst_ap");
    BinaryWriter_Print(json_log, "\"%s:%u\"", addr, port);
    return true;
}

static bool ff_dst_port(const Args &a)
{
    if (a.pkt->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP))
    {
        print_label(a, "dst_port");
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.dp);
        return true;
    }
    return false;
}

static bool ff_eth_len(const Args &a)
{
    if (!(a.pkt->proto_bits & PROTO_BIT__ETH))
        return false;

    print_label(a, "ethlength");
    BinaryWriter_Print(json_log, "%u", a.pkt->pkth->pktlen);
    return true;
}

static bool ff_eth_src(const Args &a)
{
    if (!(a.pkt->proto_bits & PROTO_BIT__ETH))
        return false;

    print_label(a, "ethsrc");
    const eth::EtherHdr *eh = layer::get_eth_layer(a.pkt);

    BinaryWriter_Print(json_log, "\"%02X:%02X:%02X:%02X:%02X:%02X\"", eh->ether_src[0],
                       eh->ether_src[1], eh->ether_src[2], eh->ether_src[3],
                       eh->ether_src[4], eh->ether_src[5]);
    return true;
}

static bool ff_eth_src_mac(const Args &a)
{
    if (!(a.pkt->proto_bits & PROTO_BIT__ETH))
        return false;

    print_label(a, "ethsrcmac");

    const eth::EtherHdr *eh = layer::get_eth_layer(a.pkt);

    uint64_t mac_prefix = 0;
    for (int i = 0; i < 6; ++i)
    {
        mac_prefix <<= 8;
        mac_prefix |= static_cast<uint64_t>(eh->ether_src[i]);
    }

    const char *vendor = MacVendorDB.find_mac_vendor(mac_prefix);

    if (vendor)
    {
        BinaryWriter_Print(json_log, "\"%s\"", vendor);
    }
    else
    {
        BinaryWriter_Print(json_log, "\"%s\"", "Unknown");
    }

    return true;
}

static bool ff_eth_dst(const Args &a)
{
    if (!(a.pkt->proto_bits & PROTO_BIT__ETH))
        return false;

    print_label(a, "ethdst");
    const eth::EtherHdr *eh = layer::get_eth_layer(a.pkt);

    BinaryWriter_Print(json_log, "\"%02X:%02X:%02X:%02X:%02X:%02X\"", eh->ether_dst[0],
                       eh->ether_dst[1], eh->ether_dst[2], eh->ether_dst[3],
                       eh->ether_dst[4], eh->ether_dst[5]);

    return true;
}

static bool ff_eth_dst_mac(const Args &a)
{
    if (!(a.pkt->proto_bits & PROTO_BIT__ETH))
        return false;

    print_label(a, "ethdstmac");

    const eth::EtherHdr *eh = layer::get_eth_layer(a.pkt);

    uint64_t mac_prefix = 0;
    for (int i = 0; i < 6; ++i)
    {
        mac_prefix <<= 8;
        mac_prefix |= static_cast<uint64_t>(eh->ether_dst[i]);
    }

    const char *vendor = MacVendorDB.find_mac_vendor(mac_prefix);

    if (vendor)
    {
        BinaryWriter_Print(json_log, "\"%s\"", vendor);
    }
    else
    {
        BinaryWriter_Print(json_log, "\"%s\"", "Unknown");
    }

    return true;
}

static bool ff_eth_type(const Args &a)
{
    if (!(a.pkt->proto_bits & PROTO_BIT__ETH))
        return false;

    const eth::EtherHdr *eh = layer::get_eth_layer(a.pkt);

    print_label(a, "eth_type");
    BinaryWriter_Print(json_log, "\"0x%X\"", ntohs(eh->ether_type));
    return true;
}

static bool ff_flowstart_time(const Args &a)
{
    if (a.pkt->flow)
    {
        print_label(a, "flowstart_time");
        BinaryWriter_Print(json_log, "%ld", a.pkt->flow->flowstats.start_time.tv_sec);
        return true;
    }
    return false;
}

static bool ff_geneve_vni(const Args &a)
{
    if (a.pkt->proto_bits & PROTO_BIT__GENEVE)
    {
        print_label(a, "geneve_vni");
        BinaryWriter_Print(json_log, "%u", a.pkt->get_flow_geneve_vni());
    }
    return true;
}

static bool ff_gid(const Args &a)
{
    print_label(a, "gid");
    BinaryWriter_Print(json_log, "%u", a.event.sig_info->gid);
    return true;
}

static bool ff_icmp_code(const Args &a)
{
    if (a.pkt->ptrs.icmph)
    {
        print_label(a, "icmp_code");
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.icmph->code);
        return true;
    }
    return false;
}

static bool ff_icmp_id(const Args &a)
{
    if (a.pkt->ptrs.icmph)
    {
        print_label(a, "icmp_id");
        BinaryWriter_Print(json_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_id));
        return true;
    }
    return false;
}

static bool ff_icmp_seq(const Args &a)
{
    if (a.pkt->ptrs.icmph)
    {
        print_label(a, "icmp_seq");
        BinaryWriter_Print(json_log, "%u", ntohs(a.pkt->ptrs.icmph->s_icmp_seq));
        return true;
    }
    return false;
}

static bool ff_icmp_type(const Args &a)
{
    if (a.pkt->ptrs.icmph)
    {
        print_label(a, "icmp_type");
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.icmph->type);
        return true;
    }
    return false;
}

static bool ff_iface(const Args &a)
{
    print_label(a, "iface");
    BinaryWriter_Quote(json_log, SFDAQ::get_input_spec());
    return true;
}

static bool ff_ip_id(const Args &a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ip_id");
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.ip_api.id());
        return true;
    }
    return false;
}

static bool ff_iplen(const Args &a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "iplen");
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.ip_api.pay_len());
        return true;
    }
    return false;
}

static bool ff_msg(const Args &a)
{
    print_label(a, "msg");
    BinaryWriter_Puts(json_log, a.msg);
    return true;
}

static bool ff_mpls(const Args &a)
{
    uint32_t mpls;

    if (a.pkt->flow)
        mpls = a.pkt->flow->key->mplsLabel;

    else if (a.pkt->proto_bits & PROTO_BIT__MPLS)
        mpls = a.pkt->ptrs.mplsHdr.label;

    else
        return false;

    print_label(a, "mpls");
    BinaryWriter_Print(json_log, "%u", mpls);
    return true;
}

static bool ff_pkt_gen(const Args &a)
{
    print_label(a, "pkt_gen");
    BinaryWriter_Quote(json_log, a.pkt->get_pseudo_type());
    return true;
}

static bool ff_dst_country_code(const Args &a)
{
    if (a.pkt->has_ip() || a.pkt->is_data())
    {
        print_label(a, "dst_country_code");
        SfIpString ip_str;
        a.pkt->ptrs.ip_api.get_dst()->ntop(ip_str);
        string ip_string = ip_str;
        string country = GeoIpLoader::Manager::getInstance()->getCountryByIP(ip_string);
        BinaryWriter_Print(json_log, "\"%s\"", country.c_str());
        return true;
    }
    return false;
}

static bool ff_src_country_code(const Args &a)
{
    if (a.pkt->has_ip() || a.pkt->is_data())
    {
        print_label(a, "src_country_code");
        SfIpString ip_str;
        a.pkt->ptrs.ip_api.get_src()->ntop(ip_str);
        string ip_string = ip_str;
        string country = GeoIpLoader::Manager::getInstance()->getCountryByIP(ip_string);
        BinaryWriter_Print(json_log, "\"%s\"", country.c_str());
        return true;
    }
    return false;
}

static bool ff_dst_country(const Args &a)
{
    print_label(a, "dst_country");
    BinaryWriter_Print(json_log, "\"Unknown\"");
    return true;
}

static bool ff_src_country(const Args &a)
{
    print_label(a, "src_country");
    BinaryWriter_Print(json_log, "\"Unknown\"");
    return true;
}

static bool ff_ethlength_range(const Args &a)
{
    if (a.pkt)
    {
        int len = 0;

        if (a.pkt->has_ip())
            len = a.pkt->ptrs.ip_api.dgram_len();
        else
            len = a.pkt->dsize;

        print_label(a, "ethlength_range");

        if (len == 0)
        {
            BinaryWriter_Print(json_log, "\"0\"");
        }
        else if (len <= 64)
        {
            BinaryWriter_Print(json_log, "\"(0-64]\"");
        }
        else if (len <= 128)
        {
            BinaryWriter_Print(json_log, "\"(64-128]\"");
        }
        else if (len <= 256)
        {
            BinaryWriter_Print(json_log, "\"(128-256]\"");
        }
        else if (len <= 512)
        {
            BinaryWriter_Print(json_log, "\"(256-512]\"");
        }
        else if (len <= 768)
        {
            BinaryWriter_Print(json_log, "\"(512-768]\"");
        }
        else if (len <= 1024)
        {
            BinaryWriter_Print(json_log, "\"(768-1024]\"");
        }
        else if (len <= 1280)
        {
            BinaryWriter_Print(json_log, "\"(1024-1280]\"");
        }
        else if (len <= 1514)
        {
            BinaryWriter_Print(json_log, "\"(1280-1514]\"");
        }
        else if (len <= 2048)
        {
            BinaryWriter_Print(json_log, "\"(1514-2048]\"");
        }
        else if (len <= 4096)
        {
            BinaryWriter_Print(json_log, "\"(2048-4096]\"");
        }
        else if (len <= 8192)
        {
            BinaryWriter_Print(json_log, "\"(4096-8192]\"");
        }
        else if (len <= 16384)
        {
            BinaryWriter_Print(json_log, "\"(8192-16384]\"");
        }
        else if (len <= 32768)
        {
            BinaryWriter_Print(json_log, "\"(16384-32768]\"");
        }
        else
        {
            BinaryWriter_Print(json_log, "\">32768\"");
        }

        return true;
    }
    return false;
}

static bool ff_pkt_len(const Args &a)
{
    print_label(a, "pkt_len");

    if (a.pkt->has_ip())
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.ip_api.dgram_len());
    else
        BinaryWriter_Print(json_log, "%u", a.pkt->dsize);

    return true;
}

static bool ff_pkt_num(const Args &a)
{
    print_label(a, "pkt_num");
    BinaryWriter_Print(json_log, STDu64, a.pkt->context->packet_number);
    return true;
}

static bool ff_priority(const Args &a)
{
    print_label(a, "priority");
    BinaryWriter_Print(json_log, "%u", a.event.sig_info->priority);
    return true;
}

static bool ff_proto(const Args &a)
{
    print_label(a, "proto");
    BinaryWriter_Quote(json_log, a.pkt->get_type());
    return true;
}

static bool ff_rev(const Args &a)
{
    print_label(a, "rev");
    BinaryWriter_Print(json_log, "%u", a.event.sig_info->rev);
    return true;
}

static bool ff_sig_generator(const Args &a)
{
    print_label(a, "sig_generator");
    BinaryWriter_Print(json_log, "\"%u\"", a.event.sig_info->rev);

    return true;
}

static bool ff_seconds(const Args &a)
{
    print_label(a, "seconds");
    BinaryWriter_Print(json_log, "%ld", a.pkt->pkth->ts.tv_sec);
    return true;
}

static bool ff_server_bytes(const Args &a)
{
    if (a.pkt->flow)
    {
        print_label(a, "server_bytes");
        BinaryWriter_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.server_bytes);
        return true;
    }
    return false;
}

static bool ff_server_pkts(const Args &a)
{
    if (a.pkt->flow)
    {
        print_label(a, "server_pkts");
        BinaryWriter_Print(json_log, "%" PRIu64, a.pkt->flow->flowstats.server_pkts);
        return true;
    }
    return false;
}

static bool ff_service(const Args &a)
{
    const char *svc = "unknown";

    if (a.pkt->flow and a.pkt->flow->service)
        svc = a.pkt->flow->service;

    print_label(a, "service");
    BinaryWriter_Quote(json_log, svc);
    return true;
}

static bool ff_sgt(const Args &a)
{
    if (a.pkt->proto_bits & PROTO_BIT__CISCO_META_DATA)
    {
        const cisco_meta_data::CiscoMetaDataHdr *cmdh = layer::get_cisco_meta_data_layer(a.pkt);
        print_label(a, "sgt");
        BinaryWriter_Print(json_log, "%hu", cmdh->sgt_val());
        return true;
    }
    return false;
}

static bool ff_sig_id(const Args &a)
{
    print_label(a, "sig_id");
    BinaryWriter_Print(json_log, "\"%u\"", a.event.sig_info->sid);
    return true;
}

static bool ff_src(const Args &a)
{
    if (a.pkt->has_ip() or a.pkt->is_data())
    {
        SfIpString ip_str;
        print_label(a, "src");
        BinaryWriter_Quote(json_log, a.pkt->ptrs.ip_api.get_src()->ntop(ip_str));
        return true;
    }
    return false;
}

static bool ff_src_ap(const Args &a)
{
    SfIpString addr = "";
    unsigned port = 0;

    if (a.pkt->has_ip() or a.pkt->is_data())
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    if (a.pkt->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP))
        port = a.pkt->ptrs.sp;

    print_label(a, "src_ap");
    BinaryWriter_Print(json_log, "\"%s:%u\"", addr, port);
    return true;
}

static bool ff_src_port(const Args &a)
{
    if (a.pkt->proto_bits & (PROTO_BIT__TCP | PROTO_BIT__UDP))
    {
        print_label(a, "src_port");
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.sp);
        return true;
    }
    return false;
}

static bool ff_target(const Args &a)
{
    SfIpString addr = "";

    if (a.event.sig_info->target == TARGET_SRC)
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    else if (a.event.sig_info->target == TARGET_DST)
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

    else
        return false;

    print_label(a, "target");
    BinaryWriter_Quote(json_log, addr);
    return true;
}

static bool ff_tcp_ack(const Args &a)
{
    if (a.pkt->ptrs.tcph)
    {
        print_label(a, "tcp_ack");
        BinaryWriter_Print(json_log, "%u", ntohl(a.pkt->ptrs.tcph->th_ack));
        return true;
    }
    return false;
}

static bool ff_tcp_flags(const Args &a)
{
    if (a.pkt->ptrs.tcph)
    {
        char tcpFlags[9];
        CreateTCPFlagString(a.pkt->ptrs.tcph, tcpFlags);

        print_label(a, "tcp_flags");
        BinaryWriter_Quote(json_log, tcpFlags);
        return true;
    }
    return false;
}

static bool ff_tcp_len(const Args &a)
{
    if (a.pkt->ptrs.tcph)
    {
        print_label(a, "tcp_len");
        BinaryWriter_Print(json_log, "%u", (a.pkt->ptrs.tcph->off()));
        return true;
    }
    return false;
}

static bool ff_tcp_seq(const Args &a)
{
    if (a.pkt->ptrs.tcph)
    {
        print_label(a, "tcp_seq");
        BinaryWriter_Print(json_log, "%u", ntohl(a.pkt->ptrs.tcph->th_seq));
        return true;
    }
    return false;
}

static bool ff_tcp_win(const Args &a)
{
    if (a.pkt->ptrs.tcph)
    {
        print_label(a, "tcp_win");
        BinaryWriter_Print(json_log, "%u", ntohs(a.pkt->ptrs.tcph->th_win));
        return true;
    }
    return false;
}

static bool ff_tos(const Args &a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "tos");
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.ip_api.tos());
        return true;
    }
    return false;
}

static bool ff_ttl(const Args &a)
{
    if (a.pkt->has_ip())
    {
        print_label(a, "ttl");
        BinaryWriter_Print(json_log, "%u", a.pkt->ptrs.ip_api.ttl());
        return true;
    }
    return false;
}

static bool ff_udplen(const Args &a)
{
    if (a.pkt->ptrs.udph)
    {
        print_label(a, "udplen");
        BinaryWriter_Print(json_log, "%u", ntohs(a.pkt->ptrs.udph->uh_len));
        return true;
    }
    return false;
}

static bool ff_vlan(const Args &a)
{
    print_label(a, "vlan");
    BinaryWriter_Print(json_log, "%hu", a.pkt->get_flow_vlan_id());
    return true;
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

typedef bool (*JsonFunc)(const Args &);

static const JsonFunc json_func[] =
    {
        ff_action, ff_class, ff_b64_data, ff_client_bytes, ff_client_pkts, ff_dir,
        ff_src, ff_dst, ff_dst_ap, ff_dst_port, ff_eth_dst, ff_eth_dst_mac, ff_eth_src_mac, ff_eth_len, ff_eth_src,
        ff_eth_type, ff_flowstart_time, ff_geneve_vni, ff_gid, ff_icmp_code, ff_icmp_id, ff_icmp_seq,
        ff_icmp_type, ff_iface, ff_ip_id, ff_iplen, ff_msg, ff_mpls, ff_pkt_gen, ff_pkt_len,
        ff_pkt_num, ff_priority, ff_proto, ff_rev, ff_sig_generator, ff_seconds, ff_server_bytes,
        ff_server_pkts, ff_service, ff_sgt, ff_sig_id, ff_src_ap, ff_src_port,
        ff_target, ff_tcp_ack, ff_tcp_flags, ff_tcp_len, ff_tcp_seq, ff_tcp_win,
        ff_tos, ff_ttl, ff_udplen, ff_ethlength_range, ff_vlan, ff_src_country, ff_dst_country, ff_src_country_code, ff_dst_country_code};

#define json_range                                                                               \
    "action | class | b64_data | client_bytes | client_pkts | dir | "                            \
    "src | dst | dst_ap | dst_port | eth_dst | eth_dst_mac | eth_src_mac | eth_len | eth_src | " \
    "eth_type | flowstart_time | geneve_vni | gid | icmp_code | icmp_id | icmp_seq | "           \
    "icmp_type | iface | ip_id | iplen | msg | mpls | pkt_gen | pkt_len | "                      \
    "pkt_num | priority | proto | rev | sig_generator | seconds | server_bytes | "               \
    "server_pkts | service | sgt | sig_id | src_ap | src_port | "                                \
    "target | tcp_ack | tcp_flags | tcp_len | tcp_seq | tcp_win | "                              \
    "tos | ttl | udplen | ethlength_range | vlan | src_country | dst_country | src_country_code | dst_country_code"

#define json_deflt \
    "pkt_num proto pkt_gen pkt_len dir src_ap dst_ap action"

static const Parameter s_params[] =
    {
        {"topic", Parameter::PT_STRING, nullptr, "rb_event",
         "send data to topic " D_TOPIC},

        {"broker_host", Parameter::PT_STRING, nullptr, "kafka.service",
         "Kafka broker host"},

        {"sensor_uuid", Parameter::PT_STRING, nullptr, "sensor_uuid",
         "Sensor uuid"},

        {"sensor_type", Parameter::PT_STRING, nullptr, "sensor_type",
         "Sensor type"},

        {"sensor_id_snort", Parameter::PT_STRING, nullptr, "sensor_id_snort",
         "Sensor binding id"},

        {"sensor_name", Parameter::PT_STRING, nullptr, "sensor_name",
         "Sensor name"},

        {"sensor_ip", Parameter::PT_STRING, nullptr, "sensor_ip",
         "Sensor ip"},

        {"group_name", Parameter::PT_STRING, nullptr, "group_name",
         "Snort group name"},

        {"mac_vendors", Parameter::PT_STRING, nullptr, "/path/to/mac_vendors",
         "Snort group name"},

        {"geoip_db", Parameter::PT_STRING, nullptr, "/path/to/db",
         "geoip database"},

        {"fields", Parameter::PT_MULTI, json_range, json_deflt,
         "selected fields will be output in given order left to right"},

        {"separator", Parameter::PT_STRING, nullptr, ", ",
         "separate fields with this character sequence"},

        {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

#define s_help \
    "send snort event to kafka"

class KafkaModule : public Module
{
public:
    KafkaModule() : Module(S_NAME, s_help, s_params) {}

    bool set(const char *, Value &, SnortConfig *) override;
    bool begin(const char *, int, SnortConfig *) override;

    Usage get_usage() const override
    {
        return GLOBAL;
    }

public:
    string sep;
    string topic;
    string broker_host;
    string sensor_uuid;
    string sensor_type;
    string sensor_name;
    string sensor_ip;
    string sensor_id_snort;
    string group_name;
    string mac_vendors;
    string geoip_db;
    vector<JsonFunc> fields;
};

bool KafkaModule::set(const char *, Value &v, SnortConfig *)
{
    if (v.is("fields"))
    {
        string tok;
        v.set_first_token();
        fields.clear();

        while (v.get_next_token(tok))
        {
            int i = Parameter::index(json_range, tok.c_str());
            if (i >= 0)
                fields.emplace_back(json_func[i]);
        }
    }

    else if (v.is("topic"))
        topic = v.get_string();

    else if (v.is("broker_host"))
        broker_host = v.get_string();

    else if (v.is("separator"))
        sep = v.get_string();

    else if (v.is("sensor_uuid"))
        sensor_uuid = v.get_string();

    else if (v.is("sensor_type"))
        sensor_type = v.get_string();

    else if (v.is("sensor_id_snort"))
        sensor_id_snort = v.get_string();

    else if (v.is("sensor_ip"))
        sensor_ip = v.get_string();

    else if (v.is("sensor_name"))
        sensor_name = v.get_string();

    else if (v.is("group_name"))
        group_name = v.get_string();

    else if (v.is("mac_vendors"))
        mac_vendors = v.get_string();

    else if (v.is("geoip_db"))
        geoip_db = v.get_string();

    return true;
}

bool KafkaModule::begin(const char *, int, SnortConfig *)
{
    sep = ", ";

    if (fields.empty())
    {
        Value v(json_deflt);
        string tok;
        v.set_first_token();

        while (v.get_next_token(tok))
        {
            int i = Parameter::index(json_range, tok.c_str());
            if (i >= 0)
                fields.emplace_back(json_func[i]);
        }
    }
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class KafkaLogger : public Logger
{
public:
    KafkaLogger(KafkaModule *m);

    void open() override;
    void close() override;

    void alert(Packet *p, const char *msg, const Event &event) override;

private:
    string topic;
    string broker_host;
    string sep;
    string sensor_uuid;
    string sensor_type;
    string sensor_name;
    string sensor_ip;
    string sensor_id_snort;
    string group_name;
    string mac_vendors;
    string geoip_db;
    vector<JsonFunc> fields;
    Enrichment enrichment;
    rd_kafka_t *rk;
    rd_kafka_conf_t *conf;
    rd_kafka_topic_t *rkt;
    char errstr[512];
};

KafkaLogger::KafkaLogger(KafkaModule *m)
{
    topic = m->topic;
    sep = m->sep;
    fields = move(m->fields);
    fields.push_back(AddTimestampField);
    broker_host = m->broker_host;
    rk = nullptr;
    conf = rd_kafka_conf_new();
    rkt = nullptr;
    sensor_uuid = m->sensor_uuid;
    sensor_type = m->sensor_type;
    sensor_name = m->sensor_name;
    sensor_ip = m->sensor_ip;
    sensor_id_snort = m->sensor_id_snort;
    group_name = m->group_name;
    mac_vendors = m->mac_vendors;
    geoip_db = m->geoip_db;
    enrichment.sensor_uuid = sensor_uuid.c_str();
    enrichment.sensor_type = sensor_type.c_str();
    enrichment.sensor_name = sensor_name.c_str();
    enrichment.sensor_ip = sensor_ip.c_str();
    enrichment.sensor_id_snort = sensor_id_snort.c_str();
    enrichment.group_name = group_name.c_str();
}

void KafkaLogger::open()
{
    if (conf == nullptr)
    {
        throw runtime_error("Failed to create Kafka configuration");
    }
    if (rd_kafka_conf_set(conf, "bootstrap.servers", broker_host.c_str(), errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK)
    {
        throw runtime_error("Failed to configure Kafka producer: " + string(errstr));
    }

    json_log = BinaryWriter_Init(LOG_BUFFER);
    GeoIpLoader::Manager::getInstance(geoip_db);

    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (!rk)
    {
        throw runtime_error("Failed to create Kafka producer: " + string(errstr));
    }

    rkt = rd_kafka_topic_new(rk, topic.c_str(), nullptr);
    if (!rkt)
    {
        throw runtime_error("Failed to create Kafka topic: " + string(rd_kafka_err2str(rd_kafka_last_error())));
    }

    MacVendorDB.insert_mac_vendors_from_file(mac_vendors.c_str());
}

void KafkaLogger::close()
{
    if (json_log)
        BinaryWriter_Term(json_log);
    if (rkt)
    {
        rd_kafka_topic_destroy(rkt);
    }
    if (rk)
    {
        rd_kafka_flush(rk, 10000);
        rd_kafka_destroy(rk);
    }
    GeoIpLoader::Manager::getInstance()->unloadDB();
}

void KafkaLogger::alert(Packet *p, const char *msg, const Event &event)
{
    Args a = {p, msg, event, false};
    BinaryWriter_Putc(json_log, '{');
    for (JsonFunc f : fields)
    {
        f(a);
        a.comma = true;
    }

    SensorEnrichment::EnrichJsonLog(json_log, enrichment);
    BinaryWriter_Print(json_log, " }");

    char *json_event = BinaryWriter_FlushToString(json_log);
    if (json_event)
    {
        size_t json_event_size = strlen(json_event);

        if (rd_kafka_produce(
                rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
                json_event, json_event_size,
                nullptr, 0, nullptr) == -1)
        {
            fprintf(stderr, "Failed to send event to Kafka: %s\n", rd_kafka_err2str(rd_kafka_last_error()));
        }
    }

    free(json_event);
    rd_kafka_poll(rk, 0);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module *mod_ctor()
{
    return new KafkaModule;
}

static void mod_dtor(Module *m)
{
    delete m;
}

static Logger *kafka_ctor(Module *mod)
{
    return new KafkaLogger((KafkaModule *)mod);
}

static void kafka_dtor(Logger *p)
{
    delete p;
}

static LogApi kafka_api{
    {PT_LOGGER,
     sizeof(LogApi),
     LOGAPI_VERSION,
     0,
     API_RESERVED,
     API_OPTIONS,
     S_NAME,
     s_help,
     mod_ctor,
     mod_dtor},
    OUTPUT_TYPE_FLAG__ALERT,
    kafka_ctor,
    kafka_dtor};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi *snort_plugins[] =
#else
const BaseApi *alert_kafka[] =
#endif
    {
        &kafka_api.base,
        nullptr};
