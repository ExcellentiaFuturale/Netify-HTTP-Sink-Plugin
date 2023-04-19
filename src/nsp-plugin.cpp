// Netify Agent HTTP POST Sink Plugin
// Copyright (C) 2023 eGloo Incorporated <http://www.egloo.ca>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <vector>
#include <set>
#include <map>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <fstream>
#include <sstream>
#include <atomic>
#include <regex>
#include <iomanip>
#include <mutex>

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

class ndPluginLoader;

#include <netifyd.h>
#include <nd-config.h>
#include <nd-ndpi.h>
#include <nd-risks.h>
#include <nd-serializer.h>
#include <nd-packet.h>
#include <nd-json.h>
#include <nd-util.h>
#include <nd-addr.h>
#include <nd-thread.h>
#include <nd-netlink.h>
#include <nd-apps.h>
#include <nd-protos.h>
#include <nd-category.h>
#include <nd-flow.h>
#include <nd-flow-parser.h>
class ndFlowMap;
#include <nd-plugin.h>
#if (_ND_PLUGIN_VER > 0x20211111)
#include <nd-flow-map.h>
#endif

#include "nsp-plugin.h"

static bool nap_privacy_mode = false;

napStatsFlow::napStatsFlow(const ndFlow *flow)
{
    if (flow->lower_map == ndFlow::LOWER_OTHER) {
        mac = flow->upper_mac.GetString();
        ip = flow->upper_addr.GetString();
        download = flow->lower_bytes;
        upload = flow->upper_bytes;
    }
    else if (flow->lower_map == ndFlow::LOWER_LOCAL) {
        mac = flow->lower_mac.GetString();
        ip = flow->lower_addr.GetString();
        download = flow->upper_bytes;
        upload = flow->lower_bytes;
    }

    string app_tag = (flow->detected_application_name) ?
        flow->detected_application_name : "netify.unclassified";

    app_id = to_string(flow->detected_application) + "." + app_tag;

    proto_id = to_string(flow->detected_protocol);

    packets = flow->lower_packets + flow->upper_packets;

    if (nap_privacy_mode)
        key = app_id + proto_id;
    else
        key = mac + ip + app_id + proto_id;
#if 0
    nd_dprintf("%s: mac: %s, ip: %s, app_id: %s, proto_id: %s\n",
        tag.c_str(), mac.str().c_str(), ip.c_str(),
        app_id.c_str(), proto_id.c_str());
#endif
}

void napStatsFlow::Append(json &j)
{
    json stats;
    stats["upload"] = upload;
    stats["download"] = download;
    stats["packets"] = packets;

    if (nap_privacy_mode)
        j[app_id][proto_id] = stats;
    else
        j[mac][ip][app_id][proto_id] = stats;
}

napStats::napStats(const string &tag)
    : ndPluginStats(tag), ld(NULL),
    log_interval(_NAP_LOG_INTERVAL), log_path("/tmp"),
    log_prefix(PACKAGE_TARNAME), log_suffix(".log")
{
    int rc;

    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&lock_cond, &cond_attr)) != 0)
        throw ndThreadException(strerror(rc));

    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&cond_mutex, NULL)) != 0)
        throw ndThreadException(strerror(rc));

    nd_dprintf("%s: initialized\n", tag.c_str());
}

napStats::~napStats()
{
    pthread_cond_broadcast(&lock_cond);

    Join();

    pthread_cond_destroy(&lock_cond);
    pthread_mutex_destroy(&cond_mutex);

    if (ld != NULL) {
        delete ld;
        ld = NULL;
    }

    nd_dprintf("%s: destroyed\n", tag.c_str());
}

void *napStats::Entry(void)
{
    int rc;

    nd_printf("%s: %s v%s (C) 2021 eGloo Incorporated.\n", tag.c_str(),
        PACKAGE_NAME, PACKAGE_VERSION);

    Reload();

    time_t log_start = time(NULL);
    struct timespec ts_epoch, ts_now;

    if (clock_gettime(CLOCK_MONOTONIC, &ts_epoch) != 0)
        throw ndThreadException(strerror(errno));

    while (! ShouldTerminate()) {

        if (clock_gettime(CLOCK_MONOTONIC, &ts_now) != 0)
            throw ndThreadException(strerror(errno));

        if (ts_now.tv_sec - ts_epoch.tv_sec < log_interval) {

            if ((rc = pthread_mutex_lock(&cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));
            if ((rc = pthread_cond_wait(&lock_cond, &cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));
            if ((rc = pthread_mutex_unlock(&cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));

            continue;
        }

        Lock();

        json js;

        for (auto fdi = flow_data.begin(); fdi != flow_data.end(); fdi++)
            fdi->second.Append(js);

        nd_dprintf("%s: appended %lu new stats record(s).\n",
            tag.c_str(), flow_data.size());

        flow_data.clear();

        FILE *hf;

        if ((hf = ld->Open())) {

            json j;

            j["log_time_start"] = log_start;
            j["log_time_end"] = time(NULL);
            j["stats"] = js;

            log_start = time(NULL);

            string json_string;
            nd_json_to_string(j, json_string);

            fprintf(hf, "%s\n", json_string.c_str());

            ld->Close();
        }
        else {
            nd_dprintf("%s: Error opening new log file: %s\n",
                tag.c_str(), strerror(errno));
        }

        Unlock();

        if (clock_gettime(CLOCK_MONOTONIC, &ts_epoch) != 0)
            throw ndThreadException(strerror(rc));
    }

    return NULL;
}

void napStats::Reload(void)
{
    Lock();

    nd_dprintf("%s: Loading configuration...\n", tag.c_str());

    json j;
    string filename(ndGC.path_state_persistent + "/netify-plugin-stats.json");

    ifstream ifs(filename);
    if (! ifs.is_open()) {
        nd_printf("%s: Error loading configuration: %s: %s\n",
            tag.c_str(), filename.c_str(), strerror(ENOENT));
        Unlock();
        return;
    }

    try {
        ifs >> j;
    }
    catch (exception &e) {
        nd_printf("%s: Error loading configuration: %s: JSON parse error\n",
            tag.c_str(), filename.c_str());
        nd_dprintf("%s: %s: %s\n", tag.c_str(), filename.c_str(), e.what());
        Unlock();
        return;
    }

    try {
        nap_privacy_mode = j["privacy_mode"].get<bool>();
    } catch (...) { }

    try {
        log_path = j["log_path"].get<string>();
    } catch (...) { }

    try {
        log_prefix = j["log_prefix"].get<string>();
    } catch (...) { }

    try {
        log_suffix = j["log_suffix"].get<string>();
    } catch (...) { }

    try {
        log_interval = (time_t)j["log_interval"].get<unsigned>();
    } catch (...) { }

    if (ld != NULL) delete ld;

    bool overwrite = false;

    try {
        overwrite = j["overwrite"].get<bool>();
    } catch (...) { }

    try {
        ld = new ndLogDirectory(
            log_path, log_prefix, log_suffix, overwrite
        );
    } catch (exception &e) {
        nd_printf("%s: Error initializing log directory: %s: %s.\n",
            tag.c_str(), log_path.c_str(), e.what());
    }

    Unlock();
}

void napStats::ProcessEvent(ndPluginEvent event, void *param)
{
    switch (event) {
    case ndPlugin::EVENT_RELOAD:
        Reload();
        break;
    default:
        break;
    }
}

void napStats::ProcessStats(const ndFlowMap *flows)
{
    size_t buckets = flows->GetBuckets();
    size_t processed = 0, total = 0, filter_nat = 0,
        filter_complete = 0, filter_packets = 0, filter_lower_map = 0;

    for (size_t b = 0; b < buckets; b++) {

        const nd_flow_map *fm = flows->AcquireConst(b);
        total += fm->size();

        for (nd_flow_map::const_iterator ifl = fm->begin();
            ifl != fm->end(); ifl++) {

            if (ifl->second->flags.ip_nat.load()) {
                filter_nat++;
                continue;
            }
            /*
             * XXX: Process all flows...
             *
            if (! ifl->second->flags.detection_complete.load()) {
                filter_complete++;
                continue;
            }
            */
            if ((ifl->second->lower_packets + ifl->second->upper_packets) == 0) {
                filter_packets++;
                continue;
            }

            if (ifl->second->lower_map == ndFlow::LOWER_UNKNOWN) {
                filter_lower_map++;
                continue;
            }

            const napStatsFlow flow_stats(ifl->second);

            Lock();

            auto fdi = flow_data.find(flow_stats.key);

            if (fdi == flow_data.end())
                flow_data[flow_stats.key] = flow_stats;
            else
                flow_data[flow_stats.key] += flow_stats;

            Unlock();

            processed++;
        }

        flows->Release(b);
    }

    if (processed) {
        int rc;
        if ((rc = pthread_cond_broadcast(&lock_cond)) != 0)
            throw ndThreadException(strerror(rc));

        nd_dprintf("%s: flows: %lu/%lu, filtered: NAT: %lu, processing: %lu,"
            " no packets: %lu, unknown map: %lu\n", tag.c_str(),
            processed, total, filter_nat, filter_complete, filter_packets,
            filter_lower_map
        );
    }
}

ndPluginInit(napStats);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
