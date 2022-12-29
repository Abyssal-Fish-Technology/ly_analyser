#include "topn_req.h"
#include "strings.h"
#include "log.h"
#include "datetime.h"
#include "ip.h"
#include <algorithm>
#include <string>
#include <Cgicc.h>
#include <boost/algorithm/string.hpp>
// #include "boost/regex.hpp"
#include "regex_validation.hpp"

using namespace std;

namespace topn {

// #define IP_PATTERN "^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}$"

#define VALID_FILTER_PATTERN "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./<>= ()[]0123456789"
////////////////////////////////////////////////////////////////////////////
/*static bool is_valid_molist(const string& s) {
  return s.size() > 0 && s.size() == strspn(s.c_str(), ",0123456789");
}*/

////////////////////////////////////////////////////////////////////////////
/*static bool parse_xdayypercent(const string& s, u32* x, u32* y) {
  if (2 != sscanf(s.c_str(), "%d:%d", x, y)) return false;
  char buf[100];
  snprintf(buf, sizeof(buf), "%d:%d", *x, *y);
  return s == buf;
}*/

////////////////////////////////////////////////////////////////////////////
// static inline bool is_valid_ip(const string& ip) {
//   boost::regex pattern(IP_PATTERN, boost::regex::nosubs);
//   boost::smatch m;
//   return boost::regex_match(ip,m,pattern);
// }

////////////////////////////////////////////////////////////////////////////
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

////////////////////////////////////////////////////////////////////////////
static bool validate_request(TopnReq* req) {
  if (!req->has_devid())
    req->set_devid(1);
/*  u32 latest_time = datetime::latest_flow_time();
  req->set_starttime(MAX(0, req->starttime()));
  if (req->starttime() == 0 || req->starttime() >= latest_time) req->set_starttime(latest_time);
  req->set_starttime(MAX(latest_time - SECONDS_PER_DAY*MAX_BACKTRACK_DAY,
                         req->starttime()));
  req->set_starttime(MIN(latest_time, req->starttime()));
  req->set_starttime(req->starttime() - req->starttime() % 300);

  req->set_endtime(MIN(latest_time, req->endtime()));
  req->set_endtime(req->endtime() - req->endtime() % 300);

  req->set_starttime(MIN(req->starttime() + 300, req->endtime()));

  if (req->has_step()){
    req->set_step( MAX(req->step(), 300) );
    req->set_step( MIN(req->step(), req->endtime() - req->starttime() + 300) );
    req->set_step( req->step() - req->step() % 300 );
  }*/
  // if (req->has_limit()) req->set_limit(MIN(1000, MAX(req->limit(), 0)));
  if (req->has_limit()) req->set_limit(MAX(req->limit(), 0));
  /*if (!req->ip().empty() && !is_valid_ip(req->ip())) {
    cerr << "Invalid ip: " << req->ip() << endl;
    return false;
  }
  if (!req->ip1().empty() && !is_valid_ip(req->ip1())) {
    cerr << "Invalid ip1: " << req->ip1() << endl;
    return false;
  }
  if (!req->ip2().empty() && !is_valid_ip(req->ip2())) {
    cerr << "Invalid ip2: " << req->ip2() << endl;
    return false;
  }*/
  if (req->has_filter() &&
      req->filter().size() != strspn(req->filter().c_str(), VALID_FILTER_PATTERN)) {
    cerr << "Invalid filter: " << req->filter() << endl;
    return false;
  }
  if (req->srcdst() != "" && req->srcdst() != "src" && req->srcdst() != "dst" &&
      req->srcdst() != "srcdst") {
    cerr << "Invalid srcdst: " << req->srcdst() << endl;
    return false;
  }
  return true;
}

void ComposeReqFilter(TopnReq* req) {
  // prepare filter param
  string* filter = req->mutable_filter();
  if (filter->empty())
    *filter = "any";
  else
    *filter = "(" + *filter + ")";

  if (!req->ip().empty()) *filter += " and host " + req->ip();
  if (!req->ip1().empty()) *filter += " and host " + req->ip1();
  if (!req->ip2().empty()) *filter += " and host " + req->ip2();
  req->clear_ip();
  req->clear_ip1();
  req->clear_ip2();

  if (req->has_proto()) *filter += " and proto " + to_string(req->proto());
  if (req->has_port()) *filter += " and port " + to_string(req->port());
  if (req->has_port1()) *filter += " and port " + to_string(req->port1());
  if (req->has_port2()) *filter += " and port " + to_string(req->port2());
  req->clear_proto();
  req->clear_port();
  req->clear_port1();
  req->clear_port2();

}

////////////////////////////////////////////////////////////////////////////
bool ParseTopnReqFromCmdline(int argc, char*argv[], TopnReq* req) {
  char c;
  while ((c = getopt(argc, argv, "i:r:s:S:e:E:f:t:b:d:n:c:o:g:")) != -1)
  {
    if (optarg==NULL)
        continue;

    switch (c)
    {
    case 'i':
      req->set_devid(atoi(optarg));
      break;
    case 's':
      req->set_starttime(atoi(optarg));
      break;
    case 'S':
      req->set_starttime(datetime::parse_timestamp(optarg));
      break;
    case 'e':
      req->set_endtime(atoi(optarg));
      break;
    case 'E':
      req->set_endtime(datetime::parse_timestamp(optarg));
      break;
    case 'f':
      req->set_filter(optarg);
      break;
    case 't':
      req->set_sortby(optarg);
      break;
    case 'o':
      SetOrderByByString(optarg, req);
      break;
    case 'b':
      req->set_step(atoi(optarg));
      break;
    case 'n':
      req->set_limit(atoi(optarg));
      break;
		case 'g':
			req->set_exclude(optarg);
			break;
    case 'd':
      req->set_srcdst(optarg);
      break;
    default:
      return false;
    }
  }
  return validate_request(req);
}

////////////////////////////////////////////////////////////////////////////
bool ParseTopnReqFromUrlParams(cgicc::Cgicc& cgi, TopnReq* req) {
  //const cgicc::CgiEnvironment &cgienv = cgi.getEnvironment();
  //log_err("query: %s\n", cgienv.getQueryString().c_str());
  if (!cgi("devid").empty())
    req->set_devid(atoi(cgi("devid").c_str()));
  else //validate
    req->set_devid(1);
  if (!cgi("starttime").empty()) req->set_starttime(atoll(cgi("starttime").c_str()));
  if (!cgi("startdate").empty()) req->set_starttime(datetime::parse_timestamp(cgi("startdate")));
  if (!cgi("endtime").empty()) req->set_endtime(atoll(cgi("endtime").c_str()));
  if (!cgi("enddate").empty()) req->set_endtime(datetime::parse_timestamp(cgi("enddate")));
  if (!cgi("filter").empty()) req->set_filter(cgi("filter"));
  if (req->has_filter() &&//validate
      req->filter().size() != strspn(req->filter().c_str(), VALID_FILTER_PATTERN)) {
    cerr << "Invalid filter: " << req->filter() << endl;
    return false;
  }

  string sortby;
  if (!cgi("type").empty()) sortby = cgi("type");
  if (!cgi("sortby").empty()) sortby = cgi("sortby");

  if (sortby == "port" || sortby == "PORT") sortby = "PORT";
  else if (sortby == "ip" || sortby == "IP") sortby = "IP";
  else if (sortby == "conv" || sortby == "CONV" ) sortby = "CONV";
  else if (sortby == "as" || sortby == "AS") sortby = "AS";
  else if (sortby == "proto" || sortby == "PROTO" ) sortby = "PROTO";
  else sortby = "ALL";
  if (!sortby.empty()) req->set_sortby(sortby);

  if (!cgi("srcdst").empty()) req->set_srcdst(cgi("srcdst")); 
  if (req->srcdst() != "" && req->srcdst() != "src" && req->srcdst() != "dst" &&
      req->srcdst() != "srcdst") {//validate
    cerr << "Invalid srcdst: " << req->srcdst() << endl;
    return false;
  }
  if (!cgi("step").empty()) req->set_step(atoi(cgi("step").c_str()));
  if (!cgi("limit").empty()) req->set_limit(atoi(cgi("limit").c_str()));
  if (req->has_limit()) req->set_limit(MAX(req->limit(), 0));//validate
  
  if (!cgi("ip").empty()) {
    if (is_valid_ip(cgi("ip")) == IPV4)
      req->set_ip(cgi("ip"));
    else if (is_valid_ip(cgi("ip")) == IPV6)
      req->set_ip(ipv6_zero_compress(cgi("ip")));
    else {
      cerr << "Invalid ip: " << cgi("ip") << endl;
      return false;
    }
  }
  if (!cgi("ip1").empty()) { 
    if (is_valid_ip(cgi("ip1")) == IPV4)
      req->set_ip(cgi("ip1"));
    else if (is_valid_ip(cgi("ip1")) == IPV6)
      req->set_ip(ipv6_zero_compress(cgi("ip1")));
    else {
      cerr << "Invalid ip1: " << cgi("ip1") << endl;
      return false;
    }
  }
  if (!cgi("ip2").empty()) {
    if (is_valid_ip(cgi("ip2")) == IPV4)
      req->set_ip(cgi("ip2"));
    else if (is_valid_ip(cgi("ip2")) == IPV6)
      req->set_ip(ipv6_zero_compress(cgi("ip2")));
    else {
      cerr << "Invalid ip2: " << cgi("ip2") << endl;
      return false;
    }
  }
  if (!cgi("proto").empty()) req->set_proto(atoi(cgi("proto").c_str()));
  if (!cgi("port").empty()) req->set_port(atoi(cgi("port").c_str()));
  if (!cgi("port1").empty()) req->set_port1(atoi(cgi("port1").c_str()));
  if (!cgi("port2").empty()) req->set_port2(atoi(cgi("port2").c_str()));

  if( (!cgi("groupid").empty()) ) req->set_groupid(atoi(cgi("groupid").c_str()));

  SetOrderByByString(cgi("orderby"), req);

  if (!cgi("include").empty())  req->set_include(cgi("include"));
  if (!cgi("exclude").empty())  req->set_exclude(cgi("exclude"));

  if (!cgi("setupcache").empty()) req->set_setupcache(boost::to_upper_copy(cgi("setupcache")) == "TRUE");
  if (!cgi("app_proto").empty())  req->set_app_proto(cgi("app_proto"));
  if (!cgi("qname").empty())  req->set_qname(cgi("qname"));
  if (!cgi("qtype").empty())  req->set_qtype(atoi(cgi("qtype").c_str()));

  if (!cgi("service_type").empty())  req->set_service_type(atoi(cgi("service_type").c_str()));
  if (!cgi("service_name").empty())  req->set_service_name(cgi("service_name"));

  // return validate_request(req);
  return true;
}

} // namespace topn
