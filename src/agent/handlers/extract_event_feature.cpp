#include <Cgicc.h>
#include <google/protobuf/text_format.h>

#include "../../common/common.h"
#include "../../common/datetime.h"
#include "../../common/log.h"
#include "../../common/sha256.h"
#include "../../common/strings.h"
#include "../../common/event_feature_req.h"
#include "../data/dbctx.h"
#include "../define.h"
#include "../flow/ip_scan_filter.h"
#include "../flow/port_scan_filter.h"
#include "../flow/assetsrv_filter.h"
#include "../flow/ip_set_filter.h"
#include "../flow/bw_filter.h"
#include "../flow/dns_filter.h"
#include "../flow/dns_tunnel.h"
#include "../flow/dga_filter.h"
#include "../flow/frn_trip_filter.h"
#include "../flow/icmp_tunnel.h"
#include "../flow/url_content_filter.h"
#include "../flow/threat_filter.h"
#include "../flow/mining_filter.h"
#include "../config/cached_config.h"

using namespace std;
using namespace eventfeature;

static EventFeatureReq req;
static EventFeatureResponse rsp;
static bool is_http = false;

////////////////////////////////////////////////////////////////////////////
static void process()
{
  if (is_http) std::cout << "Content-Type: application/protobuf; charset=UTF-8\r\n\r\n";
  DBCtxOptions options;
  options.set_read_only(true);
  unique_ptr<DBBuilder> db_builder(new DBBuilder(options, AGENT_EVENT_DB_ROOT));
  unique_ptr<CachedConfig> cfg(CachedConfig::Create());
  string model;
  for (const auto& dev : cfg->config().dev()) {
    if (dev.id() == req.devid()) {
      model = dev.model();
    }
  }


 	std::ostringstream out;
  string str;
  switch (req.type()) {
    case eventfeature::EventFeatureReq::FRN_TRIP:
    {
      unique_ptr<FrnTripFilter> frn_filter(FrnTripFilter::Create(req.devid(), model, db_builder.get()));
      if (!frn_filter) {
        log_err("frntrip: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("frntrip: initialized.\n");
      frn_filter->FilterFrnTripEvent(req, &rsp);
      break;
    }
    case eventfeature::EventFeatureReq::TI:
    {
      unique_ptr<IPSetFilter> ip_set_filter(IPSetFilter::Create(req.devid(), nullptr,
         db_builder.get(), model, "sus"));
      if (!ip_set_filter) {
        log_err("Sus: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Sus: initialized.\n"); 
      ip_set_filter->FilterSusEvent(req, &rsp);
      break;
    }
		case eventfeature::EventFeatureReq::PORT_SCAN:
		{	
			unique_ptr<PortScanFilter> pscan_filter(PortScanFilter::Create(req.devid(), model, nullptr, db_builder.get()));
			if (!pscan_filter) {
				log_err("pscan: initialization FAILED.\n");
				return;
			}		
			if (DEBUG) log_info("pscan: initialized.\n");
      pscan_filter->FilterScanEvent(req, &rsp);
		  break;
		}
    case eventfeature::EventFeatureReq::IP_SCAN:
    {
      unique_ptr<IPScanFilter> ip_scan_filter(IPScanFilter::Create(req.devid(), model, nullptr, db_builder.get()));
      if (!ip_scan_filter) {
        log_err("IPScan: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info(" IP Scanner: initialized.\n");
      ip_scan_filter->FilterScanEvent(req, &rsp);
      break;
    }
		case eventfeature::EventFeatureReq::SRV:
		{
			unique_ptr<AssetsrvFilter>assetsrv_filter(AssetsrvFilter::Create(req.devid(), model, nullptr, db_builder.get()));
			if (!assetsrv_filter) {
				log_err("Assetsrv: initialization FAILED.\n");
				return;
			}		
			if (DEBUG) log_info("Service: initialized.\n");
      assetsrv_filter->FilterServiceEvent(req, &rsp);
		  break;
		}
		case eventfeature::EventFeatureReq::BLACK:
		{
			unique_ptr<BWFilter>bw_filter(BWFilter::Create(req.devid(), nullptr, db_builder.get(), model, "black"));
			if (!bw_filter) {
				log_err("Bwlist: initialization FAILED.\n");
				return;
			}
			if (DEBUG) log_info("Bwlist: initialized.\n");
      bw_filter->FilterBWEvent(req,&rsp);
		  break;
		}
    case eventfeature::EventFeatureReq::DNS:
    {
      unique_ptr<DnsFilter> dns_filter(DnsFilter::Create(req.devid(), model, nullptr, db_builder.get()));
      if (!dns_filter) {
        log_err("Dns: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Dns: initialized.\n");
      dns_filter->FilterDnsEvent(req, &rsp);
      break;
    }
    case eventfeature::EventFeatureReq::ICMP_TUN:
    {
      unique_ptr<IcmpTunnelFilter> icmptun_filter(IcmpTunnelFilter::Create(req.devid(), model, nullptr, db_builder.get()));
      if (!icmptun_filter) {
        log_err("Icmptunnel: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Icmptunnel: initialized.\n");
      icmptun_filter->FilterIcmptunEvent(req, &rsp);
      break;
    }
		case eventfeature::EventFeatureReq::DNS_TUN:
    {      
      unique_ptr<DnstunnelFilter> dnstunnel_filter(DnstunnelFilter::Create(req.devid(), model, nullptr, db_builder.get()));
      if (!dnstunnel_filter) {
        log_err("Dnstunnel: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Dnstunnel: initialized.\n");
      dnstunnel_filter->FilterDnsTunEvent(req, &rsp);
	  	break;
    }
    case eventfeature::EventFeatureReq::DGA:
    {
      unique_ptr<DgaFilter> dga_filter(DgaFilter::Create(req.devid(), model, nullptr, db_builder.get()));
      if (!dga_filter) {
        log_err("Dga: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Dga: initialized.\n");
      dga_filter->FilterDgaEvent(req, &rsp);
      break;
    }
    case eventfeature::EventFeatureReq::CAP:
    {
      unique_ptr<ThreatFilter> threat_filter(ThreatFilter::Create(req.devid(), model, nullptr, db_builder.get()));
      if (!threat_filter) {
        log_err("Threat cap: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Threat cap: initialized.\n");
      threat_filter->FilterThreatEvent(req, &rsp);
      break;
    }
    case eventfeature::EventFeatureReq::MINING:
    {
      unique_ptr<MiningFilter> mining_filter(MiningFilter::Create(req.devid(), model, nullptr, db_builder.get()));
      if (!mining_filter) {
        log_err("Mining: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Mining: initialized.\n");
      mining_filter->FilterMiningEvent(req, &rsp);
      break;
    }
    // case eventfeature::EventFeatureReq::URL_CONTENT:
    // {
    //   unique_ptr<UrlContentFilter> url_content_filter(UrlContentFilter::Create(req.devid(), model, db_builder.get()));
    //   if (!url_content_filter) {
    //     log_err("UrlContentFilter: initialization FAILED.\n");
    //     return;
    //   }
    //   if (DEBUG) log_info("UrlContentFilter: initialized.\n");
    //   url_content_filter->FilterUrlContentEvent(req, &rsp);
    //   break;
    // }
		case eventfeature::EventFeatureReq::EMPTY:
		  break;
		default:
		  break;
	 }

 	 if (!rsp.SerializeToOstream(&out)) {
			log_err("failed to serialize to string");
 	 }
   std::cout << out.str();

}


int main(int argc, char *argv[])
{
  setvbuf(stdout, NULL, _IOFBF, 81920);
  is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) {
    bool parsed = false;
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) setenv("DEBUG", "true", 1);
    const cgicc::CgiEnvironment &cgienv = cgi.getEnvironment();

    const std::string& method = cgienv.getRequestMethod();
    if (method == "PUT" || method == "POST") {
      parsed = google::protobuf::TextFormat::ParseFromString(cgienv.getPostData(), &req);
    } else if (method == "GET") {
      parsed = ParseFeatureReqFromUrlParams(cgi, &req);
    }
    if (!parsed) {
      std::cout << "HTTP/1.1 400 Invalid Params\r\n\r\n";
      return 0;
    }
  }

 try {
    if (DEBUG) log_info("feature_req: %s\n", req.DebugString().c_str());
    process();
  } catch (std::exception const &e) {
    log_err(__FILE__":%s\n", e.what());
  }
  return 0;
}
