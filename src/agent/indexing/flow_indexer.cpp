#include "flow_indexer.h"

#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <memory>
#include <iostream>
#include <sstream>
#include <string>

#include "../../common/common.h"
#include "../../common/config.h"
#include "../../common/config.pb.h"
#include "../../common/datetime.h"
#include "../../common/file.h"
#include "../../common/http.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../config/cached_config.h"
#include "../define.h"
#include "../../common/threadpool.hpp"

using namespace std;
using config::Event;
using event::GenEventRes;
using event::GenEventRecord;
using google::protobuf::io::IstreamInputStream;
using google::protobuf::io::OstreamOutputStream;

//static bool enable_event = getenv("enable_event");
static bool enable_event = true;

static string model;    // v4 or v6

static u32 kEventTTL = 3600*24; // Event time to live. 24H

static std::set<string> asset_ips;

namespace {

void LoadFilterConfigFromFile(const string& file_name, std::map<string, int>* filters) {
  u32 loaded = 0;
  try {
    ifstream ifs(file_name);
    string line;
    while (getline(ifs, line)) {
      trim(line);
      if (line.empty() || line[0] == '#' || line[0] == '\n') continue;
      u32 equal = line.find("=");
      if (equal == line.npos) continue;
      string filter = line.substr(0, equal);
      trim(filter);
      string switcher = line.substr(equal+1);
      trim(switcher);
      int enable = (switcher == "enable") ? 1 : 0;
      filters->insert(std::pair<string, int>(filter, enable));
      
      ++loaded;
    }
  } catch (...) {
    log_warning("Could not load filter config from file %s\n", file_name.c_str());
  }
}

bool ReadEventsFromFile(const string& file_name, GenEventRes* events) {
  ifstream ifs(file_name, ios_base::in);
  IstreamInputStream is(&ifs);
  return google::protobuf::TextFormat::Parse(&is, events);
}

void SaveEventsToFile(const string& file_name, const GenEventRes& events) {
  ofstream ofs(file_name, ios_base::out);
  //ofstream ofs(file_name, ios_base::out|ios_base::app);

  /*auto helper = [](std::filebuf& fb) -> int {
    class Helper : public std::filebuf {
    public:
      int handle() { return _M_file.fd(); }
    };

    return static_cast<Helper&>(fb).handle();
  };

  int fd = helper(*ofs.rdbuf());
  struct flock lock;
  memset(&lock, 0, sizeof(lock));
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start = 0;
  lock.l_len = 0;

  if((fcntl(fd, F_SETLKW, &lock)) < 0) {
    log_warning("Lock failed:type = %d\n", lock.l_type);
  }*/

  OstreamOutputStream os(&ofs);
  google::protobuf::TextFormat::Print(events, &os);
}

// Return num of expired events which time() is less than expiration.
int RemoveExpiredEvents(u32 expiration, GenEventRes* events,
                        GenEventRes* filtered) {
  int expired = 0;
  auto* records = events->mutable_records();
  for (auto it = records->begin(); it != records->end(); ++it) {
    if (it->time() < expiration) {
      ++expired;
    } else {
      filtered->mutable_records()->Add()->Swap(&*it);
    }
  }
  return expired;
}

void SerializeToStrings(const GenEventRes& events,
                        std::vector<std::string>* strs) {
  strs->resize(events.records_size());
  std::transform(events.records().begin(), events.records().end(), strs->begin(),
                 [](const GenEventRecord& record) {
                   return record.SerializeAsString();
                 });
}

// Return num of added events.
int AddNonDuplicatedEvents(const GenEventRes& new_events,
                            GenEventRes* to_events) {
  std::vector<string> strs;
  SerializeToStrings(*to_events, &strs);

  // De-dup and merge.
  int added = 0;
  for (const auto& record : new_events.records()) {
    if (strs.end() == std::find(strs.begin(), strs.end(),
                                record.SerializeAsString())) {
      to_events->mutable_records()->Add()->CopyFrom(record);
      ++added;
    }
  }
  return added;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////
FlowIndexer::FlowIndexer(u32 devid, u32 start_time, u32 end_time,
                         CachedConfig* cfg) {
  string devid_str = to_string(devid);
  const auto& config = cfg->config();
  for (const auto& dev : config.dev()) {
    if (dev.id() == devid) {
      model = dev.model();
    }
  }

  //加载资产ip
  for (const auto& policy_data : config.policy_data()) {
    if (policy_data.label() == "asset") {
      for (const auto& item : policy_data.item()) {
        if (item.has_ip()) { 
          if (item.has_devid()) {
            if (devid != item.devid()) continue;
          } else {
            if (model == "V4") {
              if (std::string::npos != item.ip().find(":")) continue;
            } else if (model == "V6") {
              if (std::string::npos == item.ip().find(":")) continue;
            }
          }
          asset_ips.emplace(item.ip());
        }
      } 
    }
  }

  DBCtxOptions options;
  options.set_read_only(false);
  db_builder_.reset(new DBBuilder(options, AGENT_DB_ROOT));
  if (enable_event)
    eventdb_builder_.reset(new DBBuilder(options, AGENT_EVENT_DB_ROOT));
 
  const string filter_config_file = AGENT_FILTER_FILE;
  std::map<string, int> filters_flag;
  LoadFilterConfigFromFile(filter_config_file, &filters_flag);

  if(filters_flag.find("ip_scan") != filters_flag.end() && filters_flag["ip_scan"]) 
    ip_scan_.reset(IPScanFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));
  if(filters_flag.find("port_scan") != filters_flag.end() && filters_flag["port_scan"])
    port_scan_.reset(PortScanFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));
  if(filters_flag.find("tcpinit") != filters_flag.end() && filters_flag["tcpinit"])
    tcpinit_.reset(TcpinitFilter::Create(devid, model, db_builder_.get()));
  if(filters_flag.find("service") != filters_flag.end() && filters_flag["service"])
    service_.reset(ServiceFilter::Create(devid, model, db_builder_.get()));
  if(filters_flag.find("assetsrv") != filters_flag.end() && filters_flag["assetsrv"])
    assetsrv_.reset(AssetsrvFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));
  if(filters_flag.find("mo") != filters_flag.end() && filters_flag["mo"])
    mo_.reset(MOFilter::Create(cfg, devid, db_builder_.get()));
  if(filters_flag.find("dns") != filters_flag.end() && filters_flag["dns"])
    dns_.reset(DnsFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));  
  if(filters_flag.find("dnstunnel") != filters_flag.end() && filters_flag["dnstunnel"])
    dnstunnel_.reset(DnstunnelFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get())); 
  if (filters_flag.find("url_content") != filters_flag.end() && filters_flag["url_content"])
    url_content_.reset(UrlContentFilter::Create(devid, model, db_builder_.get())); 
  if(filters_flag.find("icmptunnel") != filters_flag.end() && filters_flag["icmptunnel"])
    icmptunnel_.reset(IcmpTunnelFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));
  if(filters_flag.find("dga") != filters_flag.end() && filters_flag["dga"])
    dga_.reset(DgaFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));
  if(filters_flag.find("frn_trip") != filters_flag.end() && filters_flag["frn_trip"])
    frn_trip_.reset(FrnTripFilter::Create(devid, model, eventdb_builder_.get()));
  if(filters_flag.find("threat") != filters_flag.end() && filters_flag["threat"])
    threat_.reset(ThreatFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));
  if(filters_flag.find("dnstun_ai") != filters_flag.end() && filters_flag["dnstun_ai"])
    dnstun_ai_.reset(DnstunAIFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));
  if(filters_flag.find("mining") != filters_flag.end() && filters_flag["mining"])
    mining_.reset(MiningFilter::Create(devid, model, db_builder_.get(), eventdb_builder_.get()));
 

  if(filters_flag.find("ip_set") != filters_flag.end() && filters_flag["ip_set"])
    for (const auto& policy_index : config.policy_index()) {
      for (const auto& label : policy_index.policy_data_label()) {
        if (policy_index.format() != policy::CSV ||
            !policy_index.has_storage() ||
            policy_index.storage().empty()) {
          continue;
        }
			  //sus or pop 
        ip_set_filters_.emplace_back(IPSetFilter::Create(devid,
          db_builder_.get(), eventdb_builder_.get(), model, label,
          AGENT_DATA_DIR"/" + policy_index.storage()));
      }
    }
		//black or white
  if(filters_flag.find("bw") != filters_flag.end() && filters_flag["bw"])
	  for (const auto& policy_data : config.policy_data()) {
		  if (policy_data.label() == "white" || policy_data.label() == "black") {
			  bw_filters_.emplace_back(BWFilter::Create(devid, 
				  policy_data, db_builder_.get(), eventdb_builder_.get(), model, policy_data.label()));
		  } else {
			  continue;
		  }
	  }


  if (enable_event) {
    for (const auto& event : config.event()) {
      if (event.has_devid() && event.devid() != devid) continue;
      if (event.type_id() == Event::THRESHOLD && event.thres_type() == "abs") {
        if(filters_flag.find("threshold") != filters_flag.end() && filters_flag["threshold"])
          threshold_filters_.emplace_back(ThresholdFilter::Create(
            cfg, event, devid, model, start_time, end_time, eventdb_builder_.get()));
      } else if (event.type_id() == Event::IP_SCAN && ip_scan_) {
        ip_scan_->event_generators()->emplace_back(
          IPScanFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::PORT_SCAN && port_scan_) {
        port_scan_->event_generators()->emplace_back(
          PortScanFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::SRV && assetsrv_) {
        assetsrv_->event_generators()->emplace_back(
            AssetsrvFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::SUS) {
        for (auto& ip_set_filter : ip_set_filters_) {
          if (ip_set_filter && !ip_set_filter->is_popular_service_)
            ip_set_filter->event_generators()->emplace_back( 
              IPSetFilter::EventGenerator(event, devid, start_time, end_time));
        }
      } else if (event.type_id() == Event::BLACK) {
        for (auto& bw_filter : bw_filters_) {
          if (bw_filter && bw_filter->is_black_list_)
            bw_filter->event_generators()->emplace_back(
              BWFilter::EventGenerator(event, devid, start_time, end_time));
        }
      } else if (event.type_id() == Event::DNS && dns_) {
        dns_->event_generators()->emplace_back(
            DnsFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::ICMP_TUN && icmptunnel_) {
        icmptunnel_->event_generators()->emplace_back(
            IcmpTunnelFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::DNS_TUN && dnstunnel_) {
        dnstunnel_->event_generators()->emplace_back(
            DnstunnelFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::URL_CONTENT && url_content_) {
        url_content_->event_generators()->emplace_back(
            UrlContentFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::FRN_TRIP && frn_trip_) {
        frn_trip_->event_generators()->emplace_back(
            FrnTripFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::DGA && dga_) {
        dga_->event_generators()->emplace_back(
            DgaFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::THREAT && threat_) {
        threat_->event_generators()->emplace_back(
            ThreatFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::DNSTUN_AI && dnstun_ai_) {
        dnstun_ai_->event_generators()->emplace_back(
            DnstunAIFilter::EventGenerator(event, devid, start_time, end_time));
      } else if (event.type_id() == Event::MINING && mining_) {
        mining_->event_generators()->emplace_back(
            MiningFilter::EventGenerator(event, devid, start_time, end_time));
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////
FlowIndexer::~FlowIndexer() {
  GenEventRes all;
  std::vector< std::future<GenEventRes> > events;
  std::vector< std::future<void> > results;
  int cpu_num = sysconf(_SC_NPROCESSORS_CONF) * 0.8;
  threadpool::Threadpool pool(cpu_num);

  if (ip_scan_) events.emplace_back(pool.commit(IPScanFilter::UpdateFinished, &flowset_, std::move(ip_scan_), model));
  if (port_scan_) events.emplace_back(pool.commit(PortScanFilter::UpdateFinished, &flowset_, std::move(port_scan_), model));
  if (tcpinit_) results.emplace_back(pool.commit(TcpinitFilter::UpdateFinished, &flowset_, std::move(tcpinit_), model));
  if (service_) results.emplace_back(pool.commit(ServiceFilter::UpdateFinished, &flowset_, std::move(service_), model));
  if (mo_) results.emplace_back(pool.commit(MOFilter::UpdateFinished, &flowset_, std::move(mo_)));
  if (assetsrv_) events.emplace_back(pool.commit(AssetsrvFilter::UpdateFinished, &flowset_, std::move(assetsrv_), model, asset_ips)); 
  if (dns_) events.emplace_back(pool.commit(DnsFilter::UpdateFinished, &flowset_, std::move(dns_), model));
  if (dnstunnel_) events.emplace_back(pool.commit(DnstunnelFilter::UpdateFinished, &flowset_, std::move(dnstunnel_), model));
  if (url_content_) events.emplace_back(pool.commit(UrlContentFilter::UpdateFinished, &flowset_, std::move(url_content_), model, asset_ips));
  if (icmptunnel_) events.emplace_back(pool.commit(IcmpTunnelFilter::UpdateFinished, &flowset_, std::move(icmptunnel_), model)); 
  if (dga_) events.emplace_back(pool.commit(DgaFilter::UpdateFinished, &flowset_, std::move(dga_), model)); 
  if (threat_) events.emplace_back(pool.commit(ThreatFilter::UpdateFinished, &flowset_, std::move(threat_), model)); 
  if (dnstun_ai_) events.emplace_back(pool.commit(DnstunAIFilter::UpdateFinished, &flowset_, std::move(dnstun_ai_), model)); 
  if (mining_) events.emplace_back(pool.commit(MiningFilter::UpdateFinished, &flowset_, std::move(mining_), model)); 
  if (frn_trip_) events.emplace_back(pool.commit(FrnTripFilter::UpdateFinished, &flowset_, std::move(frn_trip_), model, asset_ips)); 

  for (auto& ip_set_filter : ip_set_filters_) {
    if (ip_set_filter)
      events.emplace_back(pool.commit(IPSetFilter::UpdateFinished, &flowset_, std::move(ip_set_filter), model));
  }

  for (auto& bw_filter : bw_filters_) {
    if (bw_filter)
      events.emplace_back(pool.commit(BWFilter::UpdateFinished, &flowset_, std::move(bw_filter), model));
  }

  for (u32 i = 0 ; i < threshold_filters_.size(); ++i) {
    if (threshold_filters_[i])
      events.emplace_back(pool.commit(ThresholdFilter::CheckThreshold, &flowset_, std::move(threshold_filters_[i]), model));
  }

  for (auto&& res : results) 
    res.get();

  for(auto&& es: events) {
    all.MergeFrom(es.get());
  }

  UpdateEventFile(all);
}

////////////////////////////////////////////////////////////////////////////
void FlowIndexer::UpdateEventFile(const GenEventRes& new_events) {
  const string event_file = AGENT_EVENT_FILE;
  GenEventRes existing;
  if (!ReadEventsFromFile(event_file, &existing)) {
    log_warning("Can't load existing events from %s\n", event_file.c_str());
  }

  GenEventRes filtered;
  auto expired = RemoveExpiredEvents(time(NULL) - kEventTTL, &existing,
                                     &filtered);
  auto added = AddNonDuplicatedEvents(new_events, &filtered);

  SaveEventsToFile(event_file, filtered);
  log_info("Generated %u events. %u are new. %u existings expired.\n",
           new_events.records_size(), added, expired);
}
