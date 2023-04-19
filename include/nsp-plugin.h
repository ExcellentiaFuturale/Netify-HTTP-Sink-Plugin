// Netify Agent Stats Plugin
// Copyright (C) 2021-2022 eGloo Incorporated <http://www.egloo.ca>

#ifndef _NAP_STATS_H
#define _NAP_STATS_H

#define _NAP_LOG_INTERVAL   60

class napStatsFlow
{
public:
    napStatsFlow(const ndFlow *flow);
    napStatsFlow() : upload(0), download(0), packets(0) { }

    inline napStatsFlow& operator+=(const napStatsFlow &f)
    {
        this->upload += f.upload;
        this->download += f.download;
        this->packets += f.packets;
        return *this;
    }

    void Append(json &j);

    string key;
    string mac;
    string ip;
    string app_id;
    string proto_id;
    uint64_t upload;
    uint64_t download;
    uint32_t packets;
};

class napStats : public ndPluginStats
{
public:
    napStats(const string &tag);
    virtual ~napStats();

    virtual void *Entry(void);

    virtual void Reload(void);

    virtual void ProcessEvent(ndPluginEvent event, void *param = NULL);

    virtual void ProcessStats(const ndFlowMap *flows);

    virtual void GetVersion(string &version) { version = PACKAGE_VERSION; }

protected:
    ndLogDirectory *ld;

    time_t log_interval;
    string log_path;
    string log_prefix;
    string log_suffix;

    pthread_cond_t lock_cond;
    pthread_mutex_t cond_mutex;

    using map_flow_data = unordered_map<string, napStatsFlow>;

    map_flow_data flow_data;
};

#endif // _NAP_STATS_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
