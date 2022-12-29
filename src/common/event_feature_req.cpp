#include "event_feature_req.h"
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

namespace eventfeature {
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
bool validate_request(EventFeatureReq* req) {
  time_t now;
  time(&now);

  if (req->has_port()&&!is_valid_port(req->port()))
    return false;
  if (req->has_sport()&&!is_valid_port(req->sport()))
    return false;
  if (req->has_dport()&&!is_valid_port(req->dport()))
    return false;
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

  return true;
}

static void setType(const string& str, EventFeatureReq* req){
  if ( str=="TI" )
    req->set_type(EventFeatureReq::TI);
  else if ( str=="PORT_SCAN" )
    req->set_type(EventFeatureReq::PORT_SCAN);
  else if ( str=="IP_SCAN" )
    req->set_type(EventFeatureReq::IP_SCAN);
  else if ( str=="SRV" )
    req->set_type(EventFeatureReq::SRV);
  else if ( str=="DNS_TUN" )
    req->set_type(EventFeatureReq::DNS_TUN);
  else if ( str=="BLACK" )
    req->set_type(EventFeatureReq::BLACK);
  else if (str=="MO")
    req->set_type(EventFeatureReq::MO);
  else if (str=="DNS")
    req->set_type(EventFeatureReq::DNS);
  else if (str=="DGA")
    req->set_type(EventFeatureReq::DGA);
  else if (str=="DNSTUN_AI")
    req->set_type(EventFeatureReq::DNSTUN_AI);
  else if (str=="ICMP_TUN")
    req->set_type(EventFeatureReq::ICMP_TUN);
  else if (str=="FRN_TRIP")
    req->set_type(EventFeatureReq::FRN_TRIP);
  else if (str=="CAP")
    req->set_type(EventFeatureReq::CAP);
  else if (str=="URL_CONTENT")
    req->set_type(EventFeatureReq::URL_CONTENT);
  else if (str=="MINING")
    req->set_type(EventFeatureReq::MINING);
  else
    req->set_type(EventFeatureReq::EMPTY);
}

///////////////////////////////////////////////////////////////////////////
bool ParseFeatureReqFromCmdline(int argc, char*argv[], EventFeatureReq* req) {
  char c;
  while ((c = getopt(argc, argv, "a:d:e:g:j:k:l:o:p:r:s:t:u:A:B:C:D:S:")) != -1)
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
    case 'j':
      req->set_domain( optarg );
      break;      
    case 'k':
      req->set_qtype( atoi(optarg) );
      break;
    case 'u':
      req->set_url(optarg);
      break;
    case 'r':
      req->set_retcode(optarg);
      break;

    default:
      return false;
    }
  }
  return validate_request(req);
}

////////////////////////////////////////////////////////////////////////////
bool ParseFeatureReqFromUrlParams(cgicc::Cgicc& cgi, EventFeatureReq* req) {
  if (!cgi("devid").empty()) 
		req->set_devid(atol(cgi("devid").c_str()));
	else
		return false;
  if (!cgi("starttime").empty()) req->set_starttime( strtoul(cgi("starttime").c_str(), NULL, 10) );
  if (!cgi("endtime").empty()) req->set_endtime( strtoul(cgi("endtime").c_str(), NULL, 10) );
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
  if (!cgi("limit").empty()) req->set_limit( atoi(cgi("limit").c_str()) );
  if (!cgi("type").empty()) 
		setType(boost::to_upper_copy(cgi("type")), req);
  if (!cgi("domain").empty()) req->set_domain( cgi("domain") );
  if (!cgi("obj").empty()) req->set_obj( cgi("obj") );
  if (!cgi("qtype").empty()) req->set_qtype( atoi(cgi("qtype").c_str()) );
  if (!cgi("url").empty()) req->set_url(cgi("url"));
  if (!cgi("retcode").empty()) req->set_retcode(cgi("retcode"));
  
  return validate_request(req);
}

} // namespace feature
