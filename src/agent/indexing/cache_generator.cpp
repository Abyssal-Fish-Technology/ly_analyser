#include "cache_generator.h"

#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <boost/algorithm/string.hpp>
#include <algorithm>
#include <memory>
#include <iostream>
#include <string>
#include <sstream>
#include "../../common/common.h"
#include "../../common/topn_param.h"
#include "../../common/log.h"
#include "../define.h"
#include "../flow/flow_file_util.h"
#include "../flow/nf_scanner.h"

using namespace std;
using config::Cache;
using config::CacheEntry;
using config::Config;
using google::protobuf::TextFormat;
using google::protobuf::io::IstreamInputStream;
using topn::TopnReq;
using topn::TopnResponse;

CacheGenerator::CacheGenerator(u32 devid, u32 time, CachedConfig* cfg, CMyINI* myini)
  : devid_(devid), time_(time), config_(cfg), myini_(myini) {
  if (LoadCacheConfigFromFile(AGENT_CACHE_CONFIG_FILE)) {
    GenerateCacheEntries();
  }  
}

bool CacheGenerator::LoadCacheConfigFromFile(const string& file_name) {
	if (!myini_->ReadINI(file_name)) {
		log_err("Error read cache config file %s\n", file_name.c_str());
	}
	return true;
}

/*bool CacheGenerator::ReadConfig(Config* cfg) {
  ConfigReader cfg_reader(AGENT_CFG_FILE);
  if (!cfg_reader.LoadFromFile()) return false;
  cfg->Swap(cfg_reader.mutable_config());
  return true;
}*/

static void SetOrderByByString(const string& orderbystr, TopnReq* req) {
  string orderby = boost::to_upper_copy(orderbystr);
  if (orderby == "BYTE" && req->orderby() != TopnReq::Bytes) {
    req->set_orderby(TopnReq::Bytes);
  } else if (orderby == "PKT" && req->orderby() != TopnReq::Packets) {
    req->set_orderby(TopnReq::Packets);
  } else if (orderby == "FLOW" && req->orderby() != TopnReq::Flows) {
    req->set_orderby(TopnReq::Flows);
  }
}


void CacheGenerator::GenerateCacheEntries() {
	for (auto itr = myini_->map_ini.begin();itr != myini_->map_ini.end(); itr++) {
		auto tmp = itr->second.sub_node;
	  TopnReq req;
		req.set_devid(devid_);
		req.set_starttime(time_);
	  req.set_endtime(time_);
    string sortby = boost::to_upper_copy(tmp["sortby"]);
		if (sortby == "PORT") sortby = "PORT";
    else if (sortby == "IP") sortby = "IP";
    else if (sortby == "CONV" ) sortby = "CONV";
    else if (sortby == "AS") sortby = "AS";
    else if (sortby == "PROTO" ) sortby = "PROTO";
    else  sortby = "ALL";
    req.set_sortby(sortby);

    SetOrderByByString(tmp["orderby"], &req);    
    /*string orderby = boost::to_upper_copy(tmp["orderby"]);
    if (orderby == "FLOW" || orderby == "FLOWS") req.set_orderby(TopnReq::Flows);
    else if (orderby == "PKT" || orderby == "PKTS" || orderby == "PACKETS") 
      req.set_orderby(TopnReq::Packets);
    else  req.set_orderby(TopnReq::Bytes);*/
    if (!tmp["step"].empty())
		  req.set_step(atoi(tmp["step"].c_str()));
    else 
      req.set_step(300);

    if (!tmp["limit"].empty())
      req.set_limit(atoi(tmp["limit"].c_str()));
  //  else  req.set_limit(10);

    if (!tmp["srcdst"].empty())
      req.set_srcdst(tmp["srcdst"]);
  //  else req.set_srcdst("srcdst");

		if (!tmp["groupid"].empty()) {
			req.set_groupid(atoi(tmp["groupid"].c_str()));
		} else {
			req.set_groupid(0);
		}
			
		if (!tmp["include"].empty()) 
			req.set_include(parse_include_exclude_params(tmp["include"], 
																					 &config_->config(), req.groupid(), req.devid()));
		if (!tmp["exclude"].empty())
			req.set_exclude(parse_include_exclude_params(tmp["exclude"],
																					 &config_->config(), req.groupid(), req.devid()));
		if (!tmp["filter"].empty()) req.set_filter(tmp["filter"]);
    if (!tmp["ip"].empty()) req.set_ip(tmp["ip"]);
    if (!tmp["ip1"].empty()) req.set_ip(tmp["ip1"]);
    if (!tmp["ip2"].empty()) req.set_ip(tmp["ip2"]);
		if (!tmp["proto"].empty())
			req.set_proto(atoi(tmp["proto"].c_str()));
		if (!tmp["port"].empty())
			req.set_port(atoi(tmp["port"].c_str()));
		if (!tmp["port1"].empty())
			req.set_port1(atoi(tmp["port1"].c_str()));
		if (!tmp["port2"].empty())
			req.set_port2(atoi(tmp["port2"].c_str()));

		ComposeReqFilter(&req);
    if (!tmp["setupcache"].empty()) 
      req.set_setupcache(boost::to_upper_copy(tmp["setupcache"]) == "TRUE");

   	GenerateCacheEntry(req);
  }
}

void CacheGenerator::GenerateCacheEntry(const TopnReq& req) {
  string error;
  TopnResponse topn_rsp;
  NFScanner scanner(GetFlowDir(devid_),
                    GetFlowFilePrefix(config_->config(), devid_));
  scanner.ScanFlowFiles(req, &topn_rsp, &error);

//  log_info("the request is %s\n",req.DebugString().c_str());
  //log_info("topn_rsp size is %d\n", topn_rsp.records_size()); 
  //log_info("the response is %s\n",topn_rsp.DebugString().c_str());
}

