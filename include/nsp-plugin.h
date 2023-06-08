// Netify Agent HTTP POST Sink Plugin
// Copyright (C) 2021-2023 eGloo Incorporated <http://www.egloo.ca>

#ifndef _NSP_PLUGIN_H
#define _NSP_PLUGIN_H

#define _NSP_MAX_POST_ERRORS    3
#define _NSP_TIMEOUT_CONNECT    30
#define _NSP_TIMEOUT_XFER       300

class nspChannelConfig
{
public:
    nspChannelConfig() :
        timeout_connect(_NSP_TIMEOUT_CONNECT),
        timeout_xfer(_NSP_TIMEOUT_XFER) { }

    void Load(
        const string &channel, const json &jconf);
    inline void Load(
        const string &channel, const json &jconf,
        nspChannelConfig &defaults) {
        timeout_connect = defaults.timeout_connect;
        timeout_xfer = defaults.timeout_xfer;
        Load(channel, jconf);
    }

    string channel;
    string url;
    unsigned timeout_connect;
    unsigned timeout_xfer;
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

    nspChannelConfig defaults;
    map<string, nspChannelConfig> channels;

    void Reload(void);
    void PostPayload(ndPluginSinkPayload *payload);
};

#endif // _NSP_PLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
