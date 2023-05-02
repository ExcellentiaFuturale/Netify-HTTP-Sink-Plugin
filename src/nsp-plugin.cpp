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
#include <list>
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

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include <netifyd.h>
#include <nd-config.h>
#include <nd-signal.h>
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
#include <nd-flow-map.h>
#include <nd-dhc.h>
#include <nd-fhc.h>
class ndInstanceStatus;
#include <nd-plugin.h>
#include <nd-instance.h>
#include <nd-flow-parser.h>

#include "nsp-plugin.h"

nspChannelConfig::nspChannelConfig(
    const string &channel, const json &jconf,
    nspChannelConfig &defaults)
    : channel(channel)
{
    auto it = jconf.find("overwrite");
    if (it != jconf.end() && it->type() == json::value_t::boolean)
        overwrite = it->get<bool>();
    else
        overwrite = defaults.overwrite;

    it = jconf.find("log_path");
    if (it != jconf.end() && it->type() == json::value_t::string)
        log_path = it->get<string>();
    else
        log_path = defaults.log_path;

    it = jconf.find("log_name");
    if (it != jconf.end() && it->type() == json::value_t::string)
        log_name = it->get<string>();
    else
        throw ndPluginException("log_name", strerror(EINVAL));
}

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

    nd_printf("%s: %s v%s (C) 2023 eGloo Incorporated.\n",
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
    nd_dprintf(
        "%s: Loading configuration: %s\n",
        tag.c_str(), conf_filename.c_str()
    );

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
        nd_printf("%s: Error loading configuration: %s: %s\n",
            "parse error", tag.c_str(), conf_filename.c_str());
        nd_dprintf("%s: %s: %s\n",
            tag.c_str(), conf_filename.c_str(), e.what());
        return;
    }

    Lock();

    channels.clear();

    try {
        auto jchannels = j.find("channels");
        if (jchannels != j.end()) {
            for (auto &kvp : jchannels->get<json::object_t>()) {
                it = kvp.second.find("enable");
                if (it != kvp.second.end()) {
                    if (it->type() == json::value_t::boolean &&
                        it->get<bool>() != true) break;
                }
                channels.insert(
                    make_pair(
                        kvp.first, nspChannelConfig(
                            kvp.first, kvp.second, defaults
                        )
                    )
                );
            }
        }
    }
    catch (exception &e) {
        Unlock();
        throw e;
    }

    Unlock();
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
