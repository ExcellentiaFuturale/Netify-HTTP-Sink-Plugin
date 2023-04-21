// Netify Agent HTTP POST Sink Plugin
// Copyright (C) 2021-2023 eGloo Incorporated <http://www.egloo.ca>

#ifndef _NSP_PLUGIN_H
#define _NSP_PLUGIN_H

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
};

#endif // _NSP_PLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
