#include "evidence_req.h"
#include "strings.h"
#include "log.h"
#include "datetime.h"
#include "ip.h"
#include <algorithm>
#include <iostream>
#include <Cgicc.h>
#include <cppdb/frontend.h>
#include "regex_validation.hpp"
#include <string>

using namespace std;
using namespace boost;

namespace evidence {

////////////////////////////////////////////////////////////////////////////
static inline bool is_valid_port(u32 p) {
  if (p<0 || p>65535)
    return false;
  return true;
}

////////////////////////////////////////////////////////////////////////////
bool validate_request(EvidenceReq* req) {
  if ( !(req->has_time_sec() && req->has_time_usec()) )
    return false;
  return true;
}

///////////////////////////////////////////////////////////////////////////
bool ParseEvidenceReqFromCmdline(int argc, char*argv[], EvidenceReq* req) {
  char c;
  while ((c = getopt(argc, argv, "d:t:u:a:p:T:")) != -1) {
    if (optarg==NULL)
        continue;

    switch (c) {
      case 'd':
        req->set_devid(atoi(optarg));
        break;
      case 't':
        req->set_time_sec(atoi(optarg));
        break;
      case 'u':
        req->set_time_usec(atoi(optarg));
        break;
      case 'T':
        req->set_time_sec(datetime::parse_timestamp(optarg));
        break;

      case 'a':
        if (is_valid_ip(optarg) == IPV4)
          req->set_ip(optarg);
        else if (is_valid_ip(optarg) == IPV6)
          req->set_ip(ipv6_zero_compress(optarg));
        break;

      case 'p':
        if (is_valid_port(req->port()))
          req->set_port(atoi(optarg));
        break;

      default:
        return false;
    }
  }
  return validate_request(req);
}

////////////////////////////////////////////////////////////////////////////
bool ParseEvidenceReqFromUrlParams(cgicc::Cgicc& cgi, EvidenceReq* req) {
  if (!cgi("download").empty()) 
    req->set_download((cgi("download")=="true")?true:false);

  if (!cgi("devid").empty()) 
		req->set_devid(atol(cgi("devid").c_str()));

  if (!cgi("time").empty()){
    unsigned long int time_pre = strtoul(cgi("time").c_str(), NULL, 0);
    req->set_time_sec( time_pre/1000000 );
    req->set_time_usec( time_pre%1000000 );
  }
  if (!cgi("time_sec").empty()) req->set_time_sec( strtoul(cgi("time_sec").c_str(), NULL, 10) );
  if (!cgi("time_usec").empty()) req->set_time_usec( strtoul(cgi("time_usec").c_str(), NULL, 10) );

  if (!cgi("ip").empty()){
    if (is_valid_ip(cgi("ip")) == IPV4)
      req->set_ip(cgi("ip"));
    else if (is_valid_ip(cgi("ip")) == IPV6)
      req->set_ip(ipv6_zero_compress(cgi("ip")));
  }

  if (!cgi("port").empty())
    if (is_valid_port(req->port()))
      req->set_port(atoi(cgi("port").c_str()));
  
  return validate_request(req);
}

} // namespace evidence
