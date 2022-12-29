#ifndef __AGENT_MODEL_FEATURE_TYPE_H__
#define __AGENT_MODEL_FEATURE_TYPE_H__

#include <stdio.h>
#include <string>
#include <vector>
#include "../../common/common.h"
#include "../../common/config.pb.h"

using namespace std;
using namespace config;

//enum Weekday {SUN, MON, TUE, WED, THU, FRI, STA};
//enum Coverrange {WITHIN, WITHOUT};

struct Pattern {
    string type;
    string sip;
    string sport;
    string dip;
    string dport;
    string protocol;
    u64 peers;
    u64 flows;
    u64 pkts;
    u64 bytes;
    u32 grouths;
    u32 type_id;
    u32 config_id;
    u32 start_time;
    u32 end_time;
    u32 dev_id;
    u64 min;
    u64 max;
    string data_type;
    vector<config::Event_Weekday> weekday;
    config::Event_Coverrange coverrange;
    i32 stime_hour;
    i32 stime_min;
    i32 stime_sec;
    i32 etime_hour;
    i32 etime_min;
    i32 etime_sec;

    bool operator<(const Pattern& k) const {
      return memcmp(this, &k, sizeof(k)) < 0;
    }
    bool operator==(const Pattern& s) const {
     return type == s.type && sip == s.sip && sport == s.sport && dip == s.dip &&
            dport == s.dport && protocol == s.protocol && peers == s.peers &&
            flows == s.flows && pkts == s.pkts && bytes == s.bytes && grouths == s.grouths &&
            type_id == s.type_id && start_time == s.start_time && config_id == s.config_id
            && dev_id == s.dev_id && max == s.max && data_type == s.data_type && min == s.min
            && end_time == s.end_time && stime_hour == s.stime_hour && stime_min == s.stime_min
						&& stime_sec == s.stime_sec && etime_hour == s.etime_hour 
						&& etime_min == s.etime_min && etime_sec == s.etime_sec
						&& weekday == s.weekday && coverrange == s.coverrange;
    }
  };

struct Match_res {
    bool res;
    Pattern pat;
  };

#endif
