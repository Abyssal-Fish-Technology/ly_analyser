#ifndef AGENT_FLOW_INDEXER_H
#define AGENT_FLOW_INDEXER_H

#include <memory>
#include <vector>

#include "../../common/common.h"
#include "../../common/config.h"
#include "../../common/config.pb.h"
#include "../dump/libnfdump.h"
#include "../config/cached_config.h"
#include "../data/dbctx.h"
#include "../flow/ip_set_filter.h"
#include "../flow/bw_filter.h"
#include "../flow/ip_scan_filter.h"
#include "../flow/port_scan_filter.h"
#include "../flow/tcpinit_filter.h"
#include "../flow/service_filter.h"
#include "../flow/assetsrv_filter.h"
#include "../flow/threshold_filter.h"
#include "../flow/mo_filter.h"
#include "../flow/dns_filter.h"
#include "../flow/dns_tunnel.h"
#include "../flow/url_content_filter.h"
#include "../flow/frn_trip_filter.h"
#include "../flow/icmp_tunnel.h"
#include "../flow/dga_filter.h"
#include "../flow/threat_filter.h"
#include "../flow/dnstun_ai_filter.h"
#include "../flow/mining_filter.h"

class FlowIndexer {
 public:
  FlowIndexer(u32 devid, u32 start_time, u32 end_time, CachedConfig* cfg);
  ~FlowIndexer();

  std::vector<master_record_t> flowset_;
  void UpdateByFlow();

 private:
  void UpdateEventFile(const event::GenEventRes& events);

  unique_ptr<DBBuilder> db_builder_;
  unique_ptr<DBBuilder> eventdb_builder_;
  unique_ptr<IPScanFilter> ip_scan_;
  unique_ptr<PortScanFilter> port_scan_;
  unique_ptr<TcpinitFilter> tcpinit_;
  unique_ptr<AssetsrvFilter> assetsrv_;
  unique_ptr<UrlContentFilter> url_content_;
	unique_ptr<ServiceFilter> service_;
	unique_ptr<MOFilter> mo_;
  unique_ptr<DnsFilter> dns_;
  unique_ptr<DnstunnelFilter> dnstunnel_;
  std::vector<unique_ptr<IPSetFilter> > ip_set_filters_;
  std::vector<unique_ptr<BWFilter> > bw_filters_;
  std::vector<unique_ptr<ThresholdFilter> > threshold_filters_;
  unique_ptr<FrnTripFilter> frn_trip_;
  unique_ptr<IcmpTunnelFilter> icmptunnel_;
  unique_ptr<DgaFilter> dga_;
  unique_ptr<ThreatFilter> threat_;
  unique_ptr<DnstunAIFilter> dnstun_ai_;
  unique_ptr<MiningFilter> mining_;
};

#endif  // AGENT_FLOW_INDEXER_H
