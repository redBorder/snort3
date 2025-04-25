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

// alert_http.cc author Miguel Álvarez <malvarez@redborder.com>

// preliminary version based on hacking up alert_json.cc and putting data into a buffer for sending to kafka

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

#define DEF_VERIFY_SSL "true"

using namespace snort;
using namespace std;

#define LOG_BUFFER (4 * K_BYTES)

static THREAD_LOCAL BinaryWriter *json_log;
static const char *priority_name[] = {NULL, "high", "medium", "low", "very low"};

thread_local std::unique_ptr<MacVendorDatabase> _HTTPMacVendorDB = nullptr;

MacVendorDatabase& HTTPMacVendorDB() {
    if (!_HTTPMacVendorDB) {
        _HTTPMacVendorDB = std::make_unique<MacVendorDatabase>();
    }
    return *_HTTPMacVendorDB;
}

#define S_NAME "alert_http"


class Socket {
    int fd_;
public:
    explicit Socket(int fd) : fd_(fd) {
        if (fd_ < 0) throw std::runtime_error("Invalid socket descriptor");
    }
    ~Socket() {
        if (fd_ >= 0) close(fd_);
    }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
    Socket& operator=(Socket&& o) noexcept {
        if (this != &o) {
            if (fd_ >= 0) close(fd_);
            fd_ = o.fd_;
            o.fd_ = -1;
        }
        return *this;
    }
    int fd() const { return fd_; }
};

static Socket connect_tcp(const std::string& host, const std::string& port) {
    struct addrinfo hints{}, *res, *rp;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (int err = getaddrinfo(host.c_str(), port.c_str(), &hints, &res); err)
        throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(err)));

    Socket sock(-1);
    for (rp = res; rp; rp = rp->ai_next) {
        int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        try {
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                sock = Socket(fd);
                break;
            }
        } catch (...) {
            close(fd);
            throw;
        }
        close(fd);
    }
    freeaddrinfo(res);
    if (sock.fd() < 0)
        throw std::runtime_error("Could not connect to " + host + ":" + port);
    return sock;
}

static std::tuple<std::string,std::string,std::string>
parse_http_url(const std::string& url) {
    const std::string prefix = "http://";
    if (url.rfind(prefix, 0) != 0)
        throw std::invalid_argument("URL must start with http://");

    auto rem = url.substr(prefix.size());
    auto slash_pos = rem.find('/');
    std::string hostport = rem.substr(0, slash_pos);
    std::string path     = slash_pos == std::string::npos ? "/" : rem.substr(slash_pos);

    auto colon_pos = hostport.find(':');
    std::string host = hostport.substr(0, colon_pos);
    std::string port = colon_pos == std::string::npos
                       ? "80"
                       : hostport.substr(colon_pos + 1);

    return {host, port, path};
}

static std::string http_post(const std::string& url,
                             const std::string& body,
                             bool verify_ssl = false /*unused*/) 
{
    auto [host, port, path] = parse_http_url(url);

    auto sock = connect_tcp(host, port);

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: "      << host         << "\r\n"
        << "User-Agent: HTTPLogger/1.0\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;

    std::string out = req.str();
    size_t total = out.size(), sent = 0;
    while (sent < total) {
        ssize_t n = ::send(sock.fd(), out.data() + sent, total - sent, 0);
        if (n <= 0)
            throw std::runtime_error("Failed to send HTTP request");
        sent += n;
    }

    std::string resp;
    char buffer[4096];
    while (true) {
        ssize_t n = ::recv(sock.fd(), buffer, sizeof(buffer), 0);
        if (n < 0)
            throw std::runtime_error("Error reading HTTP response");
        if (n == 0) break;
        resp.append(buffer, n);
    }
    return resp;
}

//-------------------------------------------------------------------------
// field formatting functions
//-------------------------------------------------------------------------

struct Args
{
    Packet *pkt;
    const char *msg;
    const Event &event;
    bool comma;
    time_t timestamp;
};

static bool AddTimestampField(const Args &a)
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
    BinaryWriter_Quote(json_log, a.pkt->active->get_real_action_string());
    return true;
}

static bool ff_class(const Args& a)
{
    const char* cls = a.event.get_class_type();
    if ( !cls ) cls = "none";

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

    const char *vendor = HTTPMacVendorDB().find_mac_vendor(mac_prefix);

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

    const char *vendor = HTTPMacVendorDB().find_mac_vendor(mac_prefix);

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
    BinaryWriter_Print(json_log, "%u", a.event.get_gid());
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

static bool ff_priority(const Args &a){
    const int priority_id = a.event.get_priority();
    const char *prio_name = NULL;
    if(priority_id < sizeof(priority_name)/sizeof(priority_name[0]))
        prio_name = priority_name[priority_id];
    print_label(a, "priority");
    BinaryWriter_Print(json_log, "\"%s\"", prio_name);
    return true;
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

static bool ff_proto(const Args &a)
{
    print_label(a, "proto");
    BinaryWriter_Quote(json_log, a.pkt->get_type());
    return true;
}

static bool ff_rev(const Args &a)
{
    print_label(a, "rev");
    BinaryWriter_Print(json_log, "%u",  a.event.get_rev());
    return true;
}

static bool ff_sig_generator(const Args &a)
{
    print_label(a, "sig_generator");
    BinaryWriter_Print(json_log, "\"%u\"",  a.event.get_rev());

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
    uint32_t gid, sid, rev;
    a.event.get_sig_ids(gid, sid, rev);
    BinaryWriter_Print(json_log, "\"%u\"", sid);
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

static bool ff_target(const Args& a)
{
    SfIpString addr = "";
    bool src;

    if ( !a.event.get_target(src) )
        return false;

    if ( src )
        a.pkt->ptrs.ip_api.get_src()->ntop(addr);

    else
        a.pkt->ptrs.ip_api.get_dst()->ntop(addr);

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

static bool ff_tcp_flags(const Args& a)
{
    if (a.pkt->ptrs.tcph )
    {
        char tcpFlags[9];
        a.pkt->ptrs.tcph->stringify_flags(tcpFlags);

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
        ff_tos, ff_ttl, ff_udplen, ff_ethlength_range, ff_vlan, ff_src_country, ff_dst_country, ff_src_country_code,
        ff_dst_country_code
    };

#define json_range                                                                               \
    "action | class | b64_data | client_bytes | client_pkts | dir | "                            \
    "src | dst | dst_ap | dst_port | eth_dst | eth_dst_mac | eth_src_mac | eth_len | eth_src | " \
    "eth_type | flowstart_time | geneve_vni | gid | icmp_code | icmp_id | icmp_seq | "           \
    "icmp_type | iface | ip_id | iplen | msg | mpls | pkt_gen | pkt_len | "                      \
    "pkt_num | priority | proto | rev | sig_generator | seconds | server_bytes | "               \
    "server_pkts | service | sgt | sig_id | src_ap | src_port | "                                \
    "target | tcp_ack | tcp_flags | tcp_len | tcp_seq | tcp_win | "                              \
    "tos | ttl | udplen | ethlength_range | vlan | src_country | dst_country | "                 \
    "src_country_code | dst_country_code "

#define json_deflt \
    "pkt_num proto pkt_gen pkt_len dir src_ap dst_ap action"

static const Parameter s_params[] =
    {

        { "http_endpoint", Parameter::PT_STRING, nullptr, nullptr,
        "HTTP endpoint for send data to the manager" },

        { "verify_ssl", Parameter::PT_BOOL, nullptr, DEF_VERIFY_SSL,
        "Verify SSL Cert when sending requests" },

        {"enrichment", Parameter::PT_STRING, nullptr, nullptr,
         "JSON enrichment object"},

        {"mac_vendors", Parameter::PT_STRING, nullptr, nullptr,
         "Snort group name"},

        {"geoip_db", Parameter::PT_STRING, nullptr, nullptr,
         "geoip database"},

        {"fields", Parameter::PT_MULTI, json_range, json_deflt,
         "selected fields will be output in given order left to right"},

        {"separator", Parameter::PT_STRING, nullptr, ", ",
         "separate fields with this character sequence"},

        {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

#define s_help \
    "send snort event to http endpoint"

class HTTPModule : public Module
{
public:
    HTTPModule() : Module(S_NAME, s_help, s_params) {}

    bool set(const char *, Value &, SnortConfig *) override;
    bool begin(const char *, int, SnortConfig *) override;

    Usage get_usage() const override
    {
        return GLOBAL;
    }

public:
    string sep;
    string http_endpoint;
    string enrichment;
    string mac_vendors;
    string geoip_db;
    vector<JsonFunc> fields;
};

bool HTTPModule::set(const char *, Value &v, SnortConfig *)
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

    if ( v.is("http_endpoint") )
        http_endpoint = v.get_string();

    else if (v.is("separator"))
        sep = v.get_string();

    else if (v.is("enrichment"))
        enrichment = v.get_string();

    else if (v.is("mac_vendors"))
        mac_vendors = v.get_string();

    else if (v.is("geoip_db"))
        geoip_db = v.get_string();

    return true;
}

bool HTTPModule::begin(const char *, int, SnortConfig *)
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

class HTTPLogger : public Logger
{
public:
    HTTPLogger(HTTPModule *m);

    void open() override;
    void close() override;

    void alert(Packet *p, const char *msg, const Event &event) override;

private:
    string sep;
    string group_name;
    string mac_vendors;
    string geoip_db;
    vector<JsonFunc> fields;
    string enrichment;
    std::string http_endpoint;
    bool verify_ssl;
    char errstr[512];
};

HTTPLogger::HTTPLogger(HTTPModule *m)
{
    sep = m->sep;
    enrichment = m->enrichment;
    fields = move(m->fields);
    fields.push_back(AddTimestampField);
    mac_vendors = m->mac_vendors;
    geoip_db = m->geoip_db;
    http_endpoint = m->http_endpoint;
}

void HTTPLogger::open()
{
    json_log = BinaryWriter_Init(LOG_BUFFER);

    if(geoip_db.length() > 0) GeoIpLoader::Manager::getInstance(geoip_db);
    if(mac_vendors.length() > 0) HTTPMacVendorDB().insert_mac_vendors_from_file(mac_vendors.c_str());

}

void HTTPLogger::close()
{
    if (json_log)
        BinaryWriter_Term(json_log);
    
    if (_HTTPMacVendorDB) {
        _HTTPMacVendorDB.reset();
    }
    GeoIpLoader::Manager::getInstance()->unloadDB();
}

void HTTPLogger::alert(Packet *p, const char *msg, const Event &event)
{
    Args a = {p, msg, event, false};
    BinaryWriter_Putc(json_log, '{');
    for (JsonFunc f : fields)
    {
        f(a);
        a.comma = true;
    }

    if(enrichment.length() > 0) SensorEnrichment::EnrichJsonLog(json_log, enrichment);

    BinaryWriter_Print(json_log, " }");

    char *json_event = BinaryWriter_FlushToString(json_log);
    if (json_event)
    {
        size_t json_event_size = strlen(json_event);
        try {
            std::string body{json_event};
            free(json_event);
            std::string server_reply = http_post(http_endpoint, body, verify_ssl);
        }
        catch (const std::exception &ex) {
            std::cerr << "[HTTPLogger ERROR] " << ex.what() << "\n";
        }
        free(json_event);
    }
}   

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module *mod_ctor()
{
    return new HTTPModule;
}

static void mod_dtor(Module *m)
{
    delete m;
}

static Logger *http_ctor(Module *mod)
{
    return new HTTPLogger((HTTPModule *)mod);
}

static void http_dtor(Logger *p)
{
    delete p;
}

static LogApi http_api{
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
    http_ctor,
    http_dtor};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi *snort_plugins[] =
#else
const BaseApi *alert_http[] =
#endif
    {
        &http_api.base,
        nullptr};
