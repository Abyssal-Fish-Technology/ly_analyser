#include "feature_req.h"
#include "strings.h"
#include "log.h"
#include "datetime.h"
#include "ip.h"
#include <algorithm>
#include <iostream>
#include <Cgicc.h>
#include <cppdb/frontend.h>
// #include "boost/regex.hpp"
#include "regex_validation.hpp"
#include <string>

using namespace std;
using namespace boost;

namespace feature {
// #define IP_PATTERN "^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}$"
// #define IPV6_PATTERN "^\\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}))|:)))(%.+)?\\s*$"

////////////////////////////////////////////////////////////////////////////
// static inline bool is_valid_ip(const std::string& ip) {
//   regex pattern(IP_PATTERN, regex::nosubs);
//   // regex pattern6(IP_PATTERN, regex::nosubs);
//   smatch m;
//   struct in6_addr in6;
//   // return regex_match(ip,m,pattern);
//   // return regex_match(ip,m,pattern)?true:regex_match(ip,m,pattern6)?true:false;
//   return regex_match(ip,m,pattern)?true:inet_pton(AF_INET6, ip.c_str(), (void *)&in6)?true:false;
// }

////////////////////////////////////////////////////////////////////////////
static inline bool is_valid_port(u32 p) {
  if (p<0 || p>65535)
    return false;

  return true;
}

////////////////////////////////////////////////////////////////////////////
static void SetOrderByByString(const string& orderbystr, FeatureReq* req) {
  string orderby = boost::to_upper_copy(orderbystr);
  if (orderby == "BYTE" && req->orderby() != FeatureReq::BYTES) {
    req->set_orderby(FeatureReq::BYTES);
  } else if (orderby == "PKT" && req->orderby() != FeatureReq::PACKETS) {
    req->set_orderby(FeatureReq::PACKETS);
  } else if (orderby == "FLOW" && req->orderby() != FeatureReq::FLOWS) {
    req->set_orderby(FeatureReq::FLOWS);
  } else if (orderby == "PEER" && req->orderby() != FeatureReq::PEERS) {
    req->set_orderby(FeatureReq::PEERS);
  } else {
    req->set_orderby(FeatureReq::BYTES);
  }
}



////////////////////////////////////////////////////////////////////////////
bool validate_request(FeatureReq* req) {
  time_t now;
  time(&now);

  if (req->has_port()&&!is_valid_port(req->port()))
    return false;
  if (req->has_sport()&&!is_valid_port(req->sport()))
    return false;
  if (req->has_dport()&&!is_valid_port(req->dport()))
    return false;
  if (!req->has_valid_type())
    req->set_valid_type(FeatureReq::ALL);
  if (!req->has_endtime()){
    req->set_endtime(now - now%300);
  }
  req->set_endtime(MIN(req->endtime(), now - now%300));
  if (!req->has_starttime()){
    req->set_starttime(req->endtime() - 14400);
  }
  if (req->starttime()>req->endtime())
    return false;
  if (req->has_limit()) req->set_limit(MAX(req->limit(), 0));
  if (req->has_net() && !(req->type() == FeatureReq::ASSET_IP)) 
    return false;

  return true;
}

static void setType(const string& str, FeatureReq* req){
  if ( str=="SUS" )
    req->set_type(FeatureReq::SUS);
  else if ( str=="POP" )
    req->set_type(FeatureReq::POP);
  else if ( str=="IP_SCAN" )
    req->set_type(FeatureReq::IP_SCAN);
  else if ( str=="PORT_SCAN" )
    req->set_type(FeatureReq::PORT_SCAN);
  else if ( str=="SERVICE" )
    req->set_type(FeatureReq::SERVICE);
  else if ( str=="TCPINIT" )
    req->set_type(FeatureReq::TCPINIT);
  else if ( str=="FORCE" )
    req->set_type(FeatureReq::FORCE);
  else if ( str=="DNS_TUN" )
    req->set_type(FeatureReq::DNS_TUN);
  else if ( str=="BLACK" )
    req->set_type(FeatureReq::BLACK);
  else if ( str=="WHITE" )
    req->set_type(FeatureReq::WHITE);
  else if (str=="FLOOD")
    req->set_type(FeatureReq::FLOOD);
  else if (str=="ASSET_IP")
    req->set_type(FeatureReq::ASSET_IP);
  else if (str=="MO")
    req->set_type(FeatureReq::MO);
  else if (str=="DNS")
    req->set_type(FeatureReq::DNS);
  else if (str=="ASSET_URL")
    req->set_type(FeatureReq::ASSET_URL);
  else if (str=="ASSET_HOST")
    req->set_type(FeatureReq::ASSET_HOST);
  else if (str=="ASSET_SRV")
    req->set_type(FeatureReq::ASSET_SRV);
  else if (str=="URL_CONTENT")
    req->set_type(FeatureReq::URL_CONTENT);
  else if (str=="DGA")
    req->set_type(FeatureReq::DGA);
  else if (str=="API")
    req->set_type(FeatureReq::API);
  else
    req->set_type(FeatureReq::EMPTY);
}

////////////////////////////////////////////////////////////////////////////
static void setValidType(const string& str, FeatureReq* req){
  if ( str=="ALL" )
    req->set_valid_type(FeatureReq::ALL);
  else if ( str=="ACTIVE" )
    req->set_valid_type(FeatureReq::ACTIVE);
  else if ( str=="INACTIVE" )
    req->set_valid_type(FeatureReq::INACTIVE);
}

///////////////////////////////////////////////////////////////////////////
bool ParseFeatureReqFromCmdline(int argc, char*argv[], FeatureReq* req) {
  char c;
  while ((c = getopt(argc, argv, "a:b:c:d:e:f:g:h:i:j:k:l:m:n:o:p:q:r:s:t:u:v:x:y:z:A:B:C:D:E:S:")) != -1)
  {
    if (optarg==NULL)
        continue;

    switch (c)
    {
    case 'd':
      req->set_devid(atoi(optarg));
      break;
    case 't':
    {
      string type = optarg;
      setType(boost::to_upper_copy(type), req);
      break;
    }
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
    case 'l':
      req->set_limit(atoi(optarg));
      break;

    case 'a':
      if (is_valid_ip(optarg) == IPV4)
        req->set_ip(optarg);
      else if (is_valid_ip(optarg) == IPV6)
        req->set_ip(ipv6_zero_compress(optarg));
      break;
    case 'A':
      if (is_valid_ip(optarg) == IPV4)
        req->set_sip(optarg);
      else if (is_valid_ip(optarg) == IPV6)
        req->set_sip(ipv6_zero_compress(optarg));
      break;
    case 'B':
      if (is_valid_ip(optarg) == IPV4)
        req->set_dip(optarg);
      else if (is_valid_ip(optarg) == IPV6)
        req->set_dip(ipv6_zero_compress(optarg));
      break;

    case 'p':
      req->set_port( atoi(optarg) );
      break;      
    case 'C':
      req->set_sport( atoi(optarg) );
      break;      
    case 'D':
      req->set_dport( atoi(optarg) );
      break;      
    case 'o':
      req->set_proto( atoi(optarg) );
      break;      
    case 'c':
      req->set_peers( atoi(optarg) );
      break;      
    case 'f':
      req->set_flows( atoi(optarg) );
      break;   
    case 'b':
      SetOrderByByString(optarg, req);
      break;      
    case 'h':
    {
      string Vtype = optarg;
      setValidType(boost::to_upper_copy(Vtype), req);
      break;      
    }
    case 'n':
      req->set_net( optarg);
      break;      
    case 'm':
      req->set_moid( atoi(optarg) );
      break;      
    case 'g':
      req->set_groupid( atoi(optarg) );
      break;      
    case 'j':
      req->set_qname( optarg );
      break;      
    case 'k':
      req->set_qtype( atoi(optarg) );
      break;
    case 'i':
      if (optarg) req->set_ti_mark(true);
      else req->set_ti_mark(false);
      break;
    case 'v':
      if (optarg) req->set_srv_mark(true);
      else req->set_srv_mark(false);
      break;
    case 'u':
      req->set_url(optarg);
      break;
    case 'r':
      req->set_retcode(optarg);
      break;
    case 'x':
      req->set_host(optarg);
      break;
    case 'y':
      req->set_app_proto(optarg);
      break;
    case 'q':
      req->set_fqname(optarg);
      break;
    case 'z':
      req->set_retcode_cur(atoi(optarg));

    default:
      return false;
    }
  }
  return validate_request(req);
}

////////////////////////////////////////////////////////////////////////////
bool ParseFeatureReqFromUrlParams(cgicc::Cgicc& cgi, FeatureReq* req) {
  if (!cgi("devid").empty()) 
		req->set_devid(atol(cgi("devid").c_str()));
	else
		return false;
  if (!cgi("starttime").empty()) req->set_starttime( strtoul(cgi("starttime").c_str(), NULL, 10) );
  if (!cgi("endtime").empty()) req->set_endtime( strtoul(cgi("endtime").c_str(), NULL, 10) );
	// if (!cgi("ip").empty() && is_valid_ip(cgi("ip")) ) req->set_ip( ipstr_to_ipnum(cgi("ip")) );
	// if (!cgi("sip").empty() && is_valid_ip(cgi("sip")) ) req->set_sip( ipstr_to_ipnum(cgi("sip")) );
	// if (!cgi("dip").empty() && is_valid_ip(cgi("dip")) ) req->set_dip( ipstr_to_ipnum(cgi("dip")) );
  if (!cgi("ip").empty()){
    if (is_valid_ip(cgi("ip")) == IPV4)
      req->set_ip(cgi("ip"));
    else if (is_valid_ip(cgi("ip")) == IPV6)
      req->set_ip(ipv6_zero_compress(cgi("ip")));
  }
  if (!cgi("sip").empty()){
    if (is_valid_ip(cgi("sip")) == IPV4)
      req->set_sip(cgi("sip"));
    else if (is_valid_ip(cgi("sip")) == IPV6)
      req->set_sip(ipv6_zero_compress(cgi("sip")));
  }
  if (!cgi("dip").empty()){
    if (is_valid_ip(cgi("dip")) == IPV4)
      req->set_dip(cgi("dip"));
    else if (is_valid_ip(cgi("dip")) == IPV6)
      req->set_dip(ipv6_zero_compress(cgi("dip")));
  }
  if (!cgi("port").empty()) req->set_port( atoi(cgi("port").c_str()) );
  if (!cgi("sport").empty()) req->set_sport( atoi(cgi("sport").c_str()) );
  if (!cgi("dport").empty()) req->set_dport( atoi(cgi("dport").c_str()) );
  if (!cgi("proto").empty()) req->set_proto( atoi(cgi("proto").c_str()) );
  if (!cgi("peers").empty()) req->set_peers( atoi(cgi("peers").c_str()) );
  if (!cgi("flows").empty()) req->set_flows( atoi(cgi("flows").c_str()) );
  if (!cgi("limit").empty()) req->set_limit( atoi(cgi("limit").c_str()) );
  SetOrderByByString(cgi("orderby"), req);
  if (!cgi("valid_type").empty()) 
    setValidType(boost::to_upper_copy(cgi("valid_type")), req);
  if (!cgi("type").empty()) 
		setType(boost::to_upper_copy(cgi("type")), req);
  if (!cgi("net").empty()) req->set_net( cgi("net"));
  if (!cgi("moid").empty()) req->set_moid( atoi(cgi("moid").c_str()) );
  if (!cgi("groupid").empty()) req->set_groupid( atoi(cgi("groupid").c_str()) );
  if (!cgi("qname").empty()) req->set_qname( cgi("qname") );
  if (!cgi("qtype").empty()) req->set_qtype( atoi(cgi("qtype").c_str()) );
  if (!cgi("ti_mark").empty()) {
    if (cgi("ti_mark") == "res") req->set_ti_mark(true);
    else req->set_ti_mark(false);
  }
  if (!cgi("srv_mark").empty()) {
    if (cgi("srv_mark") == "res") req->set_srv_mark(true);
    else req->set_srv_mark(false);
  }
  if (!cgi("url").empty()) req->set_url(cgi("url"));
  if (!cgi("retcode").empty()) req->set_retcode(cgi("retcode"));
  if (!cgi("host").empty()) req->set_host(cgi("host"));
  if (!cgi("app_proto").empty()) req->set_app_proto(cgi("app_proto"));
  if (!cgi("fqname").empty()) req->set_fqname(cgi("fqname"));
  if (!cgi("srv_name").empty()) req->set_srv_name(cgi("srv_name"));
  if (!cgi("retcode_cur").empty()) req->set_retcode_cur(atoi(cgi("retcode_cur").c_str()));
  
  return validate_request(req);
}

} // namespace feature
