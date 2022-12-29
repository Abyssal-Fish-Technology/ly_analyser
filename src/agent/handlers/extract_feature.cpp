#include <Cgicc.h>
#include <google/protobuf/text_format.h>
#include <iomanip>

#include "../../common/common.h"
#include "../../common/datetime.h"
#include "../../common/log.h"
#include "../../common/sha256.h"
#include "../../common/strings.h"
#include "../../common/feature_req.h"
#include "../data/dbctx.h"
#include "../define.h"
#include "../flow/ip_scan_filter.h"
#include "../flow/port_scan_filter.h"
#include "../flow/tcpinit_filter.h"
#include "../flow/service_filter.h"
#include "../flow/assetsrv_filter.h"
#include "../flow/ip_set_filter.h"
#include "../flow/bw_filter.h"
#include "../flow/mo_filter.h"
#include "../flow/dns_filter.h"
#include "../flow/url_content_filter.h"
#include "../flow/dns_tunnel.h"
#include "../flow/dga_filter.h"
#include "../config/cached_config.h"

#define SPC_CHAR_PATTERN "[^\\x00-\\x7f\\u4E00-\\u9FFF]+"

using namespace std;
using namespace feature;

static string err_str = "abnormal character";
static FeatureReq req;
static FeatureResponse rsp;
static bool is_http = false;
static bool first = true;

static bool filter_spc_char(const string& str) {
  regex pattern(SPC_CHAR_PATTERN, regex::nosubs);
  smatch m;
  return regex_search(str, m, pattern);
}

static void inline output_u64(stringstream& out, const string& name, u64 value)
{
  out << '"' << name << "\":" << value;
}

static void inline output_double(stringstream& out, const string& name, double value)
{
  out << '"' << name << "\":" << fixed << setprecision(2) << value;
}

static void inline output_string(stringstream& out, const string& name, const string& value)
{
  out << '"' << name << "\":\"" << value << '"';
}


static inline void OutputRecord(const FeatureRecord& rec, stringstream& output){
  output_u64(output, "devid", req.devid());
  output << ",";
  if (rec.has_time()) {
    output_u64(output, "time",  rec.time());
    output << ",";
  }
  if (rec.has_duration()) {
    output_u64(output, "duration",  rec.duration());
    output << ",";
  }
  if (rec.has_moid()) {
    output_u64(output, "moid", rec.moid());
    output << ",";
  }
  if (rec.has_ip()) {
    output_string(output, "ip", rec.ip());
    output << ",";
  }
  if (rec.has_sip()) {
    output_string(output, "sip", rec.sip());
    output << ",";
  }
  if (rec.has_dip()) {
    output_string(output, "dip", rec.dip());
    output << ",";
  }
  if (rec.has_peers()) {
    output_u64(output, "peers",  rec.peers());
    output << ",";
  }
  if (rec.has_sport()) {
    output_u64(output, "sport",  rec.sport());
    output << ",";
  }
  if (rec.has_dport()) {
    output_u64(output, "dport",  rec.dport());
    output << ",";
  }
  if (rec.has_port()) {
    output_u64(output, "port",  rec.port());
    output << ",";
  }
  if (rec.has_protocol()) {
    output_string(output, "protocol",  proto_to_string(rec.protocol()));
    output << ",";
  }
  if (rec.has_type()) {
    output_string(output, "type", rec.type());
    output << ",";
  }
  if (rec.has_bwclass()) {
    output_string(output, "bwclass",  rec.bwclass());
    output << ",";
  }
  if (rec.has_ti_mark()) {
    output_string(output, "ti_mark",  rec.ti_mark());
    output << ",";
  }
  if (rec.has_srv_mark()) {
    output_string(output, "srv_mark",  rec.srv_mark());
    output << ",";
  }
  if (rec.has_app_proto()) {
    output_string(output, "app_proto",  rec.app_proto());
    output << ",";
  }
  if (rec.has_srv_name()) {
    output_string(output, "srv_name",  rec.srv_name());
    output << ",";
  }
  if (rec.has_srv_version()) {
    output_string(output, "srv_version",  escape_back_slash(rec.srv_version()));
    output << ",";
  }
  if (rec.has_srv_type()) {
    output_string(output, "srv_type",  rec.srv_type());
    output << ",";
  }
  if (rec.has_srv_time()) {
    output_u64(output, "srv_time",  rec.srv_time());
    output << ",";
  }
  if (rec.has_dev_type()) {
    output_string(output, "dev_type",  rec.dev_type());
    output << ",";
  }
  if (rec.has_dev_name()) {
    output_string(output, "dev_name",  rec.dev_name());
    output << ",";
  }
  if (rec.has_dev_vendor()) {
    output_string(output, "dev_vendor",  escape_back_slash(rec.dev_vendor()));
    output << ",";
  }
  if (rec.has_dev_model()) {
    output_string(output, "dev_model",  escape_back_slash(rec.dev_model()));
    output << ",";
  }
  if (rec.has_dev_time()) {
    output_u64(output, "dev_time",  rec.dev_time());
    output << ",";
  }
  if (rec.has_os_type()) {
    output_string(output, "os_type",  rec.os_type());
    output << ",";
  }
  if (rec.has_os_name()) {
    output_string(output, "os_name",  rec.os_name());
    output << ",";
  }
  if (rec.has_os_version()) {
    output_string(output, "os_version",  escape_back_slash(rec.os_version()));
    output << ",";
  }
  if (rec.has_os_time()) {
    output_u64(output, "os_time",  rec.os_time());
    output << ",";
  }
  if (rec.has_midware_type()) {
    output_string(output, "midware_type",  rec.midware_type());
    output << ",";
  }
  if (rec.has_midware_name()) {
    output_string(output, "midware_name",  rec.midware_name());
    output << ",";
  }
  if (rec.has_midware_version()) {
    output_string(output, "midware_version",  escape_back_slash(rec.midware_version()));
    output << ",";
  }  
  if (rec.has_midware_time()) {
    output_u64(output, "midware_time",  rec.midware_time());
    output << ",";
  }
  if (rec.has_threat_type()) {
    output_string(output, "threat_type",  rec.threat_type());
    output << ",";
  }
  if (rec.has_threat_name()) {
    output_string(output, "threat_name",  rec.threat_name());
    output << ",";
  }
  if (rec.has_threat_version()) {
    output_string(output, "os_version",  rec.os_version());
    output << ",";
  }
  if (rec.has_url()) {
    if (filter_spc_char(rec.url()))
      output_string(output, "url", err_str);
    else
      output_string(output, "url",  escape_back_slash(rec.url()));
    output << ",";
  }
  if (rec.has_host()) {
    if (filter_spc_char(rec.host()))
      output_string(output, "host", err_str);
    else
      output_string(output, "host",  escape_back_slash(rec.host()));
    output << ",";
  }
  if (rec.has_qname()) {
    if (filter_spc_char(rec.qname()))
      output_string(output, "qname", err_str);
    else
      output_string(output, "qname",  escape_back_slash(rec.qname()));
    output << ",";
  }
  if (rec.has_fqname()) {
    if (filter_spc_char(rec.fqname()))
      output_string(output, "fqname", err_str);
    else
      output_string(output, "fqname",  escape_back_slash(rec.fqname()));
    output << ",";
  }
  if (rec.has_qtype()) {
    output_string(output, "qtype",  qtype_to_str(rec.qtype()));
    output << ",";
  }
  if (rec.has_fratio()) {
    output_double(output, "fratio",  rec.fratio());
    output << ",";
  }
  if (rec.has_score()) {
    output_u64(output, "score",  rec.score());
    output << ",";
  }
  if (rec.has_retcode()) {
    output_u64(output, "retcode",  rec.retcode());
    output << ",";
  }
  if (rec.has_peak_flows()) {
    output_u64(output, "peak_flows", rec.peak_flows());
    output << ",";
  }
  if (rec.has_peak_pkts()) {
    output_u64(output, "peak_pkts", rec.peak_pkts());
    output << ",";
  }
  if (rec.has_peak_bytes()) {
    output_u64(output, "peak_bytes", rec.peak_bytes());
    output << ",";
  }
  if (rec.has_flows()) {
    output_u64(output, "flows", rec.flows());
    output << ",";
  }
  if (rec.has_pkts()) {
    output_u64(output, "pkts", rec.pkts());
    output << ",";
  }
  if (rec.has_bytes()) {
    output_u64(output, "bytes", rec.bytes());
  }
}

static void OutputResult(FeatureResponse& res) {
  stringstream sout;
  sout << "[" << endl;
  for (int i = 0;i < res.records_size();i++) {
    auto rec = res.records(i);
    if (first)
      first = false;
    else
      sout << ",\n";
    sout << "{";
    OutputRecord(rec, sout);
    sout << "}";
  }
  sout << "]" << endl;
  std::cout<<sout.str();
}


////////////////////////////////////////////////////////////////////////////
static void process()
{
  if (is_http) std::cout << "Content-Type: application/protobuf; charset=UTF-8\r\n\r\n";
  DBCtxOptions options;
  options.set_read_only(true);
  unique_ptr<DBBuilder> db_builder(new DBBuilder(options, AGENT_DB_ROOT));
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
    case feature::FeatureReq::POP:
    {
      unique_ptr<IPSetFilter> ip_set_filter(IPSetFilter::Create(req.devid(),
        db_builder.get(), nullptr, model, "pop"));
      if (!ip_set_filter) {
        log_err("Pop: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Pop: initialized.\n");
      ip_set_filter->FilterIPSets(req, &rsp);
      break;
    }
    case feature::FeatureReq::SUS:
    {
      unique_ptr<IPSetFilter> ip_set_filter(IPSetFilter::Create(req.devid(),
         db_builder.get(), nullptr, model, "sus"));
      if (!ip_set_filter) {
        log_err("Sus: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Sus: initialized.\n"); 
      ip_set_filter->FilterIPSets(req, &rsp);
      break;
    }
		case feature::FeatureReq::PORT_SCAN:
		{	
			unique_ptr<PortScanFilter> pscan_filter(PortScanFilter::Create(req.devid(), model,
																						db_builder.get(), nullptr));
			if (!pscan_filter) {
				log_err("Port Scan: initialization FAILED.\n");
				return;
			}		
			if (DEBUG) log_info("Port Scan: initialized.\n");
      pscan_filter->FilterScan(req, &rsp);
		  break;
		}
    case feature::FeatureReq::IP_SCAN:
    {
      unique_ptr<IPScanFilter> iscan_filter(IPScanFilter::Create(req.devid(), model,
                                            db_builder.get(), nullptr));
      if (!iscan_filter) {
        log_err("IP Scan: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("IP Scan: initialized.\n");
      iscan_filter->FilterScan(req, &rsp);
      break;
    }
		case feature::FeatureReq::SERVICE:
		{
			unique_ptr<ServiceFilter> service_filter(ServiceFilter::Create(req.devid(), model,
																	  db_builder.get()));
			if (!service_filter) {
				log_err("Service: initialization FAILED.\n");
				return;
			}
			if (DEBUG) log_info("Service: initialized.\n");
      service_filter->FilterService(req, &rsp);
		  break;
		}
		case feature::FeatureReq::ASSET_SRV:
		{
			unique_ptr<AssetsrvFilter> assetsrv_filter(AssetsrvFilter::Create(req.devid(), model,
																	  db_builder.get(), nullptr));
			if (!assetsrv_filter) {
				log_err("Assetsrv: initialization FAILED.\n");
				return;
			}		
			if (DEBUG) log_info("Service: initialized.\n");
      assetsrv_filter->FilterService(req, &rsp);
		  break;
		}
		case feature::FeatureReq::TCPINIT:
		{
			unique_ptr<TcpinitFilter> tcpinit_filter(TcpinitFilter::Create(req.devid(), model,
																	  db_builder.get()));
			if (!tcpinit_filter) {
				log_err("Tcpinit: initialization FAILED.\n");
				return;
			}		
			if (DEBUG) log_info("Tcpinit: initialized.\n");
      tcpinit_filter->FilterTcpinit(req, &rsp);
		  break;
		}
		case feature::FeatureReq::BLACK:
		{
			unique_ptr<BWFilter> bw_filter(BWFilter::Create(req.devid(), db_builder.get(), nullptr, model, "black"));
			if (!bw_filter) {
				log_err("Bwlist: initialization FAILED.\n");
				return;
			}
			if (DEBUG) log_info("Bwlist: initialized.\n");
      bw_filter->FilterBwlist(req,&rsp);
		  break;
		}
		case feature::FeatureReq::WHITE:
		{
			unique_ptr<BWFilter> bw_filter(BWFilter::Create(req.devid(), db_builder.get(), nullptr, model, "white"));
			if (!bw_filter) {
				log_err("Bwlist: initialization FAILED.\n");
				return;
			}
			if (DEBUG) log_info("Bwlist: initialized.\n");
      bw_filter->FilterBwlist(req,&rsp);
      break;
		}
    case feature::FeatureReq::MO:
    {
      unique_ptr<MOFilter> mo_filter(MOFilter::Create(cfg.get(), req.devid(), db_builder.get()));
      if (!mo_filter) {
        log_err("Mo: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Mo: initialized.\n");
      mo_filter->FilterMO(req, &rsp);
      break;
    }
    case feature::FeatureReq::DNS:
    {
      unique_ptr<DnsFilter> dns_filter(DnsFilter::Create(req.devid(), model, db_builder.get(), nullptr));
      if (!dns_filter) {
        log_err("Dns: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Dns: initialized.\n");
      dns_filter->FilterDns(req, &rsp);
      break;
    }
		case feature::FeatureReq::FORCE:
		  break;
		case feature::FeatureReq::DNS_TUN:
    {      
      unique_ptr<DnstunnelFilter> dnstunnel_filter(DnstunnelFilter::Create(req.devid(), model, db_builder.get(), nullptr));
      if (!dnstunnel_filter) {
        log_err("Dnstunnel: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Dnstunnel: initialized.\n");
      dnstunnel_filter->FilterDnstunnel(req, &rsp);
	  	break;
    }
    case feature::FeatureReq::DGA:
    {
      unique_ptr<DgaFilter> dga_filter(DgaFilter::Create(req.devid(), model, db_builder.get(), nullptr));
      if (!dga_filter) {
        log_err("Dga: initialization FAILED.\n");
        return;
      }
      if (DEBUG) log_info("Dga: initialized.\n");
      dga_filter->FilterDga(req, &rsp);
      break;
    }
		case feature::FeatureReq::FLOOD:
		  break;
		case feature::FeatureReq::EMPTY:
		  break;
		default:
		  break;
	 }

  if (is_http) {
    if (!rsp.SerializeToOstream(&out)) {
      log_err("failed to serialize to string");
    }
    std::cout << out.str();
  } else {
    OutputResult(rsp);
  }
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
