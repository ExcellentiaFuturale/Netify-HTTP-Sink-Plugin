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
        timeout_xfer(_NSP_TIMEOUT_XFER),
        curl_headers(nullptr),
        curl_headers_gz(nullptr) { }

    virtual ~nspChannelConfig() {
        if (curl_headers != nullptr) {
            curl_slist_free_all(curl_headers);
            curl_headers = nullptr;
        }
        if (curl_headers != nullptr) {
            curl_slist_free_all(curl_headers_gz);
            curl_headers_gz = nullptr;
        }
    }

    void Load(ndGlobalConfig::ConfVars &conf_vars,
        const string &channel, const json &jconf);
    inline void Load(ndGlobalConfig::ConfVars &conf_vars,
        const string &channel, const json &jconf,
        nspChannelConfig &defaults) {
        timeout_connect = defaults.timeout_connect;
        timeout_xfer = defaults.timeout_xfer;
        Load(conf_vars, channel, jconf);
    }

    struct curl_slist *GetHeaders(uint8_t flags);

    string channel;
    string url;
    unsigned timeout_connect;
    unsigned timeout_xfer;

    typedef map<string, string> Headers;
    Headers headers;

protected:
    struct curl_slist *curl_headers;
    struct curl_slist *curl_headers_gz;
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

    size_t AppendData(const char *data, size_t length);

protected:
    atomic<bool> reload;

    nspChannelConfig defaults;

    typedef map<string, nspChannelConfig> Channels;
    Channels channels;

    CURL *ch;
    char curl_error_buffer[CURL_ERROR_SIZE];
    string http_return_buffer;

    void Reload(void);
    void PostPayload(
        nspChannelConfig &channel, ndPluginSinkPayload *payload);
};

#endif // _NSP_PLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
