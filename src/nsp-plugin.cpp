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

nspPlugin::nspPlugin(
    const string &tag, const ndPlugin::Params &params)
    : ndPluginSink(tag, params)
{
    reload = true;

    nd_dprintf("%s: initialized\n", tag.c_str());
}

nspPlugin::~nspPlugin()
{
    Join();

    nd_dprintf("%s: destroyed\n", tag.c_str());
}

void *nspPlugin::Entry(void)
{
    int rc;

    nd_printf("%s: %s v%s (C) 2021 eGloo Incorporated.\n",
        tag.c_str(), PACKAGE_NAME, PACKAGE_VERSION
    );

    while (! ShouldTerminate()) {

        if (reload.load()) {
            Reload();
            reload = false;
        }

        if (WaitOnPayloadQueue()) {
            ndPluginSinkPayload *p;
            while ((p = PopPayloadQueue())) {
                nd_dprintf("%s: payload, length: %lu, %p\n",
                    tag.c_str(), p->length, p->data
                );
                for (auto &c : p->channels) {
                    nd_dprintf("%s: -> channel: %s\n",
                        tag.c_str(), c.c_str()
                    );
                }
                delete p;
            }
        }

        nd_dprintf("%s: tick.\n", tag.c_str());
    }

    return NULL;
}

void nspPlugin::Reload(void)
{
    nd_dprintf("%s: Loading configuration...\n", tag.c_str());
#if 0
    json j;

    ifstream ifs(conf_filename);
    if (! ifs.is_open()) {
        nd_printf("%s: Error loading configuration: %s: %s\n",
            tag.c_str(), conf_filename.c_str(), strerror(ENOENT));
        return;
    }

    try {
        ifs >> j;
    }
    catch (exception &e) {
        nd_printf("%s: Error loading configuration: %s: JSON parse error\n",
            tag.c_str(), conf_filename.c_str());
        nd_dprintf("%s: %s: %s\n", tag.c_str(), conf_filename.c_str(), e.what());
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
#endif
}

void nspPlugin::DispatchEvent(ndPlugin::Event event, void *param)
{
    switch (event) {
    case ndPlugin::EVENT_RELOAD:
        reload = true;
        break;
    default:
        break;
    }
}

ndPluginInit(nspPlugin);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
