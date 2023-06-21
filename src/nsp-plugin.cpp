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

#include <curl/curl.h>

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

static int nspCURL_debug(CURL *ch __attribute__((unused)),
    curl_infotype type, char *data, size_t size, void *param)
{
    string buffer;
    if (! ndGC_DEBUG_UPLOAD) return 0;

    ndThread *thread = reinterpret_cast<ndThread *>(param);

    switch (type) {
    case CURLINFO_TEXT:
        buffer.assign(data, size);
        nd_dprintf("%s: %s",
            thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_HEADER_IN:
        buffer.assign(data, size);
        nd_dprintf("%s: <-- %s",
            thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_HEADER_OUT:
        buffer.assign(data, size);
        nd_dprintf("%s: --> %s",
            thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_DATA_IN:
        nd_dprintf("%s: <-- %lu data bytes\n",
            thread->GetTag().c_str(), size);
        break;
    case CURLINFO_DATA_OUT:
        nd_dprintf("%s: --> %lu data bytes\n",
            thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_IN:
        nd_dprintf("%s: <-- %lu SSL bytes\n",
            thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_OUT:
        nd_dprintf("%s: --> %lu SSL bytes\n",
            thread->GetTag().c_str(), size);
        break;
    default:
        break;
    }

    return 0;
}

static size_t nspCURL_read_data(
    char *data, size_t size, size_t nmemb, void *param)
{
    size_t length = size * nmemb;
    nspPlugin *plugin = reinterpret_cast<nspPlugin *>(param);

    return plugin->AppendData((const char *)data, length);
}

#if (LIBCURL_VERSION_NUM < 0x073200)
static int nspCURL_progress(void *user,
    double dltotal __attribute__((unused)),
    double dlnow __attribute__((unused)),
    double ultotal __attribute__((unused)),
    double ulnow __attribute__((unused)))
#else
static int nspCURL_progress(void *user,
    curl_off_t dltotal __attribute__((unused)),
    curl_off_t dlnow __attribute__((unused)),
    curl_off_t ultotal __attribute__((unused)),
    curl_off_t ulnow __attribute__((unused)))
#endif
{
    nspPlugin *plugin = reinterpret_cast<nspPlugin *>(user);

    if (plugin->ShouldTerminate()) return 1;

    return 0;
}

void nspChannelConfig::Load(ndGlobalConfig::ConfVars &conf_vars,
    const string &channel, const json &jconf)
{
    this->channel = channel;

    auto it = jconf.find("timeout_connect");
    if (it != jconf.end() &&
        it->type() == json::value_t::number_unsigned)
        timeout_connect = it->get<unsigned>();

    it = jconf.find("timeout_transfer");
    if (it != jconf.end() &&
        it->type() == json::value_t::number_unsigned)
        timeout_xfer = it->get<unsigned>();

    it = jconf.find("url");
    if (it != jconf.end() && it->type() == json::value_t::string)
        nd_expand_variables(it->get<string>(), url, conf_vars);

    it = jconf.find("headers");
    if (it != jconf.end() && it->type() == json::value_t::object) {
        Headers headers_in(it->get<Headers>());
        for (auto& h : headers_in) {
            string value;
            nd_expand_variables(h.second, value, conf_vars);
            if (value.empty()) value = "-";
            headers.insert(make_pair(h.first, value));
        }
    }
}

struct curl_slist *nspChannelConfig::GetHeaders(uint8_t flags)
{
    string header;
    struct curl_slist **headers_slist = nullptr;

    if (! (flags & ndPlugin::DF_GZ_DEFLATE))
        headers_slist = &curl_headers;
    else {
        headers_slist = &curl_headers_gz;
        header = "Content-Encoding: gzip";
    }

    if (*headers_slist != nullptr)
        return *headers_slist;

    if (! header.empty()) {
        *headers_slist = curl_slist_append(
            *headers_slist, header.c_str()
        );

        header.clear();
    }

    if ((flags & ndPlugin::DF_FORMAT_JSON))
        header = "Content-Type: application/json";
    else if ((flags & ndPlugin::DF_FORMAT_MSGPACK))
        header = "Content-Type: application/msgpack";

    if (! header.empty()) {
        *headers_slist = curl_slist_append(
            *headers_slist, header.c_str()
        );
    }

    header = "User-Agent: ";
    header.append(nd_get_version_and_features());

    *headers_slist = curl_slist_append(
        *headers_slist, header.c_str()
    );

    for (auto& i : headers) {
        header = i.first;
        header.append(": ");
        header.append(i.second);

        *headers_slist = curl_slist_append(
            *headers_slist, header.c_str()
        );
    }

    return *headers_slist;
}

nspPlugin::nspPlugin(
    const string &tag, const ndPlugin::Params &params)
    : ndPluginSink(tag, params), ch(nullptr), curl_error_buffer{}
{
    reload = true;

    nd_dprintf("%s: initialized\n", tag.c_str());
}

nspPlugin::~nspPlugin()
{
    Join();

    if (ch != nullptr) {
        curl_easy_cleanup(ch);
        ch = nullptr;
    }

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
#if 0
                nd_dprintf("%s: payload, length: %lu, %p\n",
                    tag.c_str(), p->length, p->data
                );
                for (auto &c : p->channels) {
                    nd_dprintf("%s: -> channel: %s\n",
                        tag.c_str(), c.c_str()
                    );
                }
#endif
                for (auto &c : p->channels) {
                    auto channel = channels.find(c);
                    if (channel == channels.end()) {
                        nd_dprintf("%s: channel not defined: %s\n",
                            tag.c_str(), c.c_str()
                        );
                        continue;
                    }

                    PostPayload(channel->second, p);
                }

                delete p;
            }
        }
    }

    return NULL;
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

size_t nspPlugin::AppendData(const char *data, size_t length)
{
    try {
        http_return_buffer.append(data, length);
    } catch (bad_alloc &e) {
        nd_printf(
            "%s: Error appending %lu bytes for return data: %s\n",
            tag.c_str(), length, e.what()
        );
        return 0;
    }

    return length;
}

void nspPlugin::Reload(void)
{
    nd_dprintf(
        "%s: Loading configuration: %s\n",
        tag.c_str(), conf_filename.c_str()
    );

    ndGlobalConfig::ConfVars conf_vars(ndGC.conf_vars);

    static map<ndGlobalConfig::UUID, string> vars = {
        { ndGlobalConfig::UUID_AGENT, "${uuid_agent}" },
        { ndGlobalConfig::UUID_SERIAL, "${uuid_serial}" },
        { ndGlobalConfig::UUID_SITE, "${uuid_site}" }
    };

    for (auto& v : vars) {
        string value;

        ndGC.LoadUUID(v.first, value);
        conf_vars.insert(make_pair(v.second, value));
    }

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

    defaults.Load(conf_vars, "defaults", j);

    channels.clear();

    try {
        auto jchannels = j.find("channels");
        if (jchannels != j.end()) {
            for (auto &kvp : jchannels->get<json::object_t>()) {

                auto it = kvp.second.find("enable");
                if (it != kvp.second.end()) {
                    if (it->type() == json::value_t::boolean &&
                        it->get<bool>() != true) break;
                }

                nspChannelConfig config;
                config.Load(conf_vars, kvp.first, kvp.second);

                if (config.url.empty()) {
                    throw ndPluginException(
                        "url", strerror(EINVAL)
                    );
                }

                channels.insert(make_pair(kvp.first, config));
            }
        }
    }
    catch (exception &e) {
        Unlock();
        throw e;
    }

    Unlock();
}

void nspPlugin::PostPayload(
    nspChannelConfig &channel, ndPluginSinkPayload *payload)
{
    bool init = (ch == nullptr);

    if (init) {
        if ((ch = curl_easy_init()) == NULL) {
            throw ndPluginException(
                "curl_easy_init", strerror(EINVAL));
        }

        curl_easy_setopt(ch, CURLOPT_ERRORBUFFER,
            curl_error_buffer);
        curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(ch, CURLOPT_POST, 1);
        curl_easy_setopt(ch, CURLOPT_POSTREDIR, 3);
        curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);

        curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, nspCURL_read_data);
        curl_easy_setopt(ch, CURLOPT_WRITEDATA, static_cast<void *>(this));

        curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 0);
#if (LIBCURL_VERSION_NUM < 0x073200)
        curl_easy_setopt(ch, CURLOPT_PROGRESSFUNCTION, nspCURL_progress);
        curl_easy_setopt(ch, CURLOPT_PROGRESSDATA, static_cast<void *>(this));
#else
        curl_easy_setopt(ch, CURLOPT_XFERINFOFUNCTION, nspCURL_progress);
        curl_easy_setopt(ch, CURLOPT_XFERINFODATA, static_cast<void *>(this));
#endif
#ifdef _ND_WITH_LIBCURL_ZLIB
#if (LIBCURL_VERSION_NUM < 0x072106)
        curl_easy_setopt(ch, CURLOPT_ENCODING, "gzip");
#else
        curl_easy_setopt(ch, CURLOPT_ACCEPT_ENCODING, "gzip");
#endif
#endif // _ND_WITH_LIBCURL_ZLIB
        if (ndGC_DEBUG_UPLOAD) {
            curl_easy_setopt(ch, CURLOPT_VERBOSE, 1);
            curl_easy_setopt(ch, CURLOPT_DEBUGFUNCTION, nspCURL_debug);
            curl_easy_setopt(ch, CURLOPT_DEBUGDATA, static_cast<void *>(this));
        }
#if 0
        if (! ND_SSL_VERIFY) {
            curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0L);
        }

        if (ND_SSL_USE_TLSv1)
            curl_easy_setopt(ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
#endif
    }

    curl_easy_setopt(ch, CURLOPT_HTTPHEADER,
        channel.GetHeaders(payload->flags));

    curl_easy_setopt(ch, CURLOPT_URL, channel.url.c_str());

    curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT,
        channel.timeout_connect);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT,
        channel.timeout_xfer);

    curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE,
        payload->length);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS,
        payload->data);

    http_return_buffer.clear();

    CURLcode curl_rc;

    if ((curl_rc = curl_easy_perform(ch)) != CURLE_OK) {
        nd_printf("%s: %s: %s: %s [%d]", tag.c_str(),
            channel.channel.c_str(),
            channel.url.c_str(), curl_error_buffer, curl_rc);
        return;
    }

    long http_rc = 0;
    if ((curl_rc = curl_easy_getinfo(ch,
        CURLINFO_RESPONSE_CODE, &http_rc)) != CURLE_OK) {
        nd_printf("%s: %s: %s: %s [%d]", tag.c_str(),
            channel.channel.c_str(),
            channel.url.c_str(), curl_error_buffer, curl_rc);
        return;
    }

    if (http_rc != 200) {
        nd_printf("%s: %s: %s: %s [%d]", tag.c_str(),
            channel.channel.c_str(),
            channel.url.c_str(), curl_error_buffer, http_rc);
    }
}

ndPluginInit(nspPlugin);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
