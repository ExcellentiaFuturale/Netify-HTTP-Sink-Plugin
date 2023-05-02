// Netify Agent HTTP POST Sink Plugin
// Copyright (C) 2021-2023 eGloo Incorporated <http://www.egloo.ca>

#ifndef _NSP_PLUGIN_H
#define _NSP_PLUGIN_H

#define _NSP_URL_PROVISION      "https://sink.netify.ai/provision/"
#define _NSP_MAX_POST_ERRORS    3
#define _NSP_TIMEOUT_CONNECT    30
#define _NSP_TIMEOUT_XFER       300

class nspChannelConfig
{
public:
    nspChannelConfig(
        const string &channel, const json &jconf,
        nspChannelConfig &defaults
    );
    nspChannelConfig(const string &channel,
        const string &url, const string &url_provision,
        bool overwrite = false) :
        channel(channel), log_path(log_path),
        log_name(log_name), overwrite(overwrite) { }

    string channel;
    string url;
    string url_provision;
    unsigned timeout_connect;
    unsigned timeout_xfer;
    unsigned max_post_errors;
    map<string, string> headers;
};

class nspPlugin : public ndPluginSink
{
public:
    nspPlugin(const string &tag, const ndPlugin::Params &params);
    virtual ~nspPlugin();

    virtual void *Entry(void);

    virtual void DispatchEvent(
        ndPlugin::Event event, void *param = nullptr);

    virtual void GetVersion(string &version) {
        version = PACKAGE_VERSION;
    }

protected:
    atomic<bool> reload;

    void Reload(void);

    nspChannelConfig defaults;
    map<string, nspChannelConfig> channels;
};

#endif // _NSP_PLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
