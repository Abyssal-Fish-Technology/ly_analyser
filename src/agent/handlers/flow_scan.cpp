#include <boost/algorithm/string.hpp>
#include <Cgicc.h>
#include <google/protobuf/text_format.h>

#include "../../common/common.h"
#include "../../common/config.h"
#include "../../common/config.pb.h"
#include "../../common/topn_param.h"
#include "../../common/datetime.h"
#include "../../common/log.h"
#include "../../common/policy.pb.h"
#include "../../common/csv.hpp"
#include "../../common/sha256.h"
#include "../../common/strings.h"
#include "../../common/topn.pb.h"
#include "../../common/topn_req.h"
#include "../data/dbctx.h"
#include "../data/web_cache.h"
#include "../define.h"
#include "../flow/flow_file_util.h"
#include "../flow/nf_scanner.h"
#include "../model/policy.h"
#include "../utils/time_util.h"

static bool is_http = false;

using namespace std;
using namespace topn;
using google::protobuf::TextFormat;
using config::Config;
using config::Device;
using policy::PolicyIndex;
using policy::PolicyData;
static TopnReq req;


////////////////////////////////////////////////////////////////////////////
static bool read_config(Config* cfg)
{
  ConfigReader cfg_reader(AGENT_CFG_FILE);
  if (!cfg_reader.LoadFromFile()) return false;
  cfg->Swap(cfg_reader.mutable_config());
  return true;
}

////////////////////////////////////////////////////////////////////////////
bool IsValidDevid(const Config& cfg, u32 devid) {
  for (const auto& dev : cfg.dev()) {
    if (dev.id() == devid) return true;
  }
  return false;
}

////////////////////////////////////////////////////////////////////////////
void OutputErrorMessage(ostream& out, const string& error) {
  if (is_http) out << "Content-Type: text/html; charset=UTF-8\r\n\r\n";
  out << error;
}

////////////////////////////////////////////////////////////////////////////
void OutputResponse(const TopnResponse& rsp, ostream& out) {
  if (is_http) out << "Content-Type: application/protobuf; charset=UTF-8\r\n\r\n";
  if (!rsp.SerializeToOstream(&out)) {
    log_err("Failed to serialize response %s\n", rsp.DebugString().c_str());
  }
}

////////////////////////////////////////////////////////////////////////////
void OutputInvalidRequest(ostream& out) {
  if (is_http) out << "HTTP/1.1 400 Invalid Request Params\r\n\r\n";
}

////////////////////////////////////////////////////////////////////////////
void UpdateRequestLogging(u32 starttime, u32 endtime, u32 step, const TopnReq& req) {
  if (!req.setupcache()) return;

  TopnReq request = req;
  request.clear_devid();
  request.clear_starttime();
  request.clear_endtime();
  DBCtxOptions options;
  options.set_read_only(false);
  unique_ptr<DBBuilder> db_builder(new DBBuilder(options, AGENT_DB_ROOT));
  unique_ptr<TSDB> tsdb(new TSDB(db_builder.get(), "topn"));
  string key = request.DebugString();
  u32 now = time(NULL);
  Slice value;

  struct RequestLog {
    u32 latest;
    u32 count;
  };

  for (auto t = starttime; t <= endtime; t += step) {
    RequestLog log;
    if (tsdb->Get(t, Slice(key), &value) && value.size() >= sizeof(RequestLog)) {
			const RequestLog* p = (const RequestLog*)value.data();
      if (p->latest != now) {
        log.latest = now;
        log.count = p->count + 1;
      }
    } else {
      log.latest = now;
      log.count = 1;
    }
    tsdb->Put(t, Slice(key), Slice(&log, sizeof(log)));
  }
}

////////////////////////////////////////////////////////////////////////////
static void validate_time(TopnReq* req) {
  u32 latest_time = datetime::latest_flow_time();
  if (!req->has_endtime() || req->endtime() == 0)
    req->set_endtime(latest_time);

  if (!req->has_starttime() || req->starttime() == 0)
    req->set_starttime(latest_time);
  req->set_starttime(MAX(latest_time - SECONDS_PER_DAY*MAX_BACKTRACK_DAY,
                         req->starttime()));
  req->set_starttime(MIN(latest_time, req->starttime()));
  req->set_starttime(req->starttime() - req->starttime() % 300);

  req->set_endtime(req->endtime() - req->endtime() % 300);
  req->set_endtime(MIN(latest_time, req->endtime()));

  req->set_starttime(MIN(req->starttime(), req->endtime()));

  if (req->has_step()){
    req->set_step( MAX(req->step(), 300) );
    req->set_step( MIN(req->step(), req->endtime() - req->starttime() + 300) );
    req->set_step( req->step() - req->step() % 300 );
  }
}

//////////////////////////////////////////////////////////////////////
static void process(ostream& out)
{
  Config cfg;
  if (!read_config(&cfg)) {
    log_err("Can't load config file.\n");
    return;
  }

  validate_time(&req);

	if (!req.has_groupid()) {
    req.set_groupid(0);
	}
  
  /*if(!req.has_srcdst()) {
    req.set_srcdst("srcdst");
  }*/

	if (req.has_include()) 
		req.set_include(parse_include_exclude_params(req.include(), 
																		&cfg, req.groupid(), req.devid()));
	if ( req.has_exclude() )
    req.set_exclude(parse_include_exclude_params(req.exclude(),
																		&cfg, req.groupid(), req.devid()));

 // ComposeReqFilter(&req);
  u32 starttime = req.starttime();
  u32 endtime = req.endtime();
  u32 step = req.step();
  u32 timeunit = 300;
  if (!TimeUtil::ValidateTimeRange(&starttime, &endtime, &step, &timeunit)) {
    OutputErrorMessage(out, "Invalid start time, end time or step of request " + req.DebugString());
    return;
  }

  if (!req.has_devid()) {
    OutputErrorMessage(out, "Missing devid of request " + req.DebugString());
    return;
  }
  UpdateRequestLogging(starttime, endtime, step, req);

  TopnResponse rsp;
  std::vector<u32> missing_time_range;

  {
    DBCtxOptions options;
    options.set_read_only(true);
    unique_ptr<DBBuilder> db_builder(new DBBuilder(options, AGENT_CACHE_DIR));
    WebCache cache(db_builder.get());
    for (auto t = starttime; t <= endtime - 300; t += step) {
      auto cache_entry_req = req;
      cache_entry_req.set_starttime(t);
      cache_entry_req.set_endtime(t);
      cache_entry_req.set_step(step);
      TopnResponse cache_entry_rsp;

      if (!DEBUG && cache.Get(t, cache_entry_req, &cache_entry_rsp)) {
        // Cache hit
        if (DEBUG) log_info("Web cache hit of request %s\n", cache_entry_req.DebugString().c_str());
        rsp.MergeFrom(cache_entry_rsp);
      } else {
        // Cache miss
        if (DEBUG) log_info("Web cache miss of request %s\n", cache_entry_req.DebugString().c_str());
        missing_time_range.push_back(t);
      }
    }
  }

  s32 devid = req.devid();
  if (!missing_time_range.empty() && IsValidDevid(cfg, devid)) {
    starttime = missing_time_range.front();
    endtime = missing_time_range.back();
    if (DEBUG) log_info("Missing time range [%u,%u]\n", starttime, endtime);
    // Remove cached entries witin missing time range. This is
    // to prevent from returning duplicated entries.
    auto* records = rsp.mutable_records();
    int first_to_remove = INT_MAX;
    int last_to_remove = 0;
    for (int i = 0; i < records->size(); ++i) {
      auto time = records->Get(i).time();
      if (time >= starttime && time <= endtime) {
        first_to_remove = std::min(first_to_remove, i);
        last_to_remove = std::max(last_to_remove, i);
      }
    }
    if (last_to_remove >= first_to_remove) {
      if (DEBUG) {
        log_info("Remove %u cached entries\n",
                 last_to_remove - first_to_remove + 1);
      }
      records->DeleteSubrange(
        first_to_remove, last_to_remove - first_to_remove + 1);
    }

    auto scan_flow_req = req;
    scan_flow_req.set_starttime(starttime);
    scan_flow_req.set_endtime(endtime + 300);
    scan_flow_req.set_step(step);
    TopnResponse scan_flow_rsp;
    string error;

    string flow_dir = GetFlowDir(devid);
    string flow_file_prefix = GetFlowFilePrefix(cfg, devid);
    if (DEBUG) {
      log_info("Scan flow for <%s> at flow dir <%s> with file prefix <%s>\n",
               scan_flow_req.DebugString().c_str(), flow_dir.c_str(), 
               flow_file_prefix.c_str());
    }

    NFScanner scanner(flow_dir, flow_file_prefix);
    if (scanner.ScanFlowFiles(scan_flow_req, &scan_flow_rsp, &error)) {
      rsp.MergeFrom(scan_flow_rsp);
    } else {
      log_err("ScanFlowFiles error: %s\n", error.c_str());
    }
  }
  OutputResponse(rsp, out);
}

////////////////////////////////////////////////////////////////////////////
static void usage(char * pn)
{
  fprintf(stderr, "usage: %s [options]\n\n", pn);
  fprintf(stderr, "-r <router_ip>\tdefault:''\n");
  fprintf(stderr, "-s <starttime>\tdefault:<latest>\n");
  fprintf(stderr, "-S <starttime>\tFormat:YYYYmmddHHMM default:<latest>\n");
  fprintf(stderr, "-e <endtime>\tdefault:latest\n");
  fprintf(stderr, "-E <endtime>\tFormat:YYYYmmddHHMM default:<latest>\n");
  fprintf(stderr, "-f <filter>\tdefault:any\n");
  fprintf(stderr, "-t <sortby>\tdefault:ALL\n");
  fprintf(stderr, "-b <step>\tdefault:<NULL>\n");
  fprintf(stderr, "-d <srcdst>\tdefault:''\n");
  fprintf(stderr, "-n <limit>\tdefalut:10\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  setvbuf(stdout, NULL, _IOFBF, 81920);
  is_http = getenv("REMOTE_ADDR") != NULL;
  if (is_http) {
    bool parsed = false;
    cgicc::Cgicc cgi;
    if (!cgi("dbg").empty()) setenv("DEBUG", "ALL", 1);
    const cgicc::CgiEnvironment &cgienv = cgi.getEnvironment();

    const std::string& method = cgienv.getRequestMethod();
    if (method == "PUT" || method == "POST") {
      parsed = TextFormat::ParseFromString(cgienv.getPostData(), &req);
    } else if (method == "GET") {
      parsed = ParseTopnReqFromUrlParams(cgi, &req);
    }
    if (!parsed) {
      OutputInvalidRequest(cout);
      return 0;
    }
  } else if (!ParseTopnReqFromCmdline(argc, argv, &req)) {
     usage(argv[0]);
  }

  try {
    if (DEBUG) log_info("topn_req: %s\n", req.DebugString().c_str());
    process(cout);
  } catch (std::exception const &e) {
    log_err(__FILE__":%s\n", e.what());
  }
  return 0;
}
