#include "mo_req.h"
#include "strings.h"
#include "log.h"
#include "datetime.h"
#include <algorithm>
#include <iostream>
#include <Cgicc.h>
#include <cppdb/frontend.h>
#include "boost/regex.hpp"
#include "regex_validation.hpp"
#include <string>

using namespace std;
using namespace boost;

namespace mo {
#define VALID_FILTER_PATTERN "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./<>= ()[]0123456789"
#define VALID_TAG_PATTERN " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz,0123456789"
#define MOID_LIST_PATTERN "^([1-9]\\d*|0)(,([1-9]\\d*|0))*$"
#define PORT_PATTERN "^(!)?(<|>)?(\\d+)$"

////////////////////////////////////////////////////////////////////////////
static inline bool is_valid_port(const std::string& port) {
  regex pattern(PORT_PATTERN);
  smatch m;
  bool rm = regex_match(port,m,pattern);

  if (rm==false)
    return false;

  if (atoi(m[3].str().c_str())>65535)
    return false;

  return true;
}

////////////////////////////////////////////////////////////////////////////
static bool is_valid_molist(const std::string& s) {
  regex pattern(MOID_LIST_PATTERN, regex::nosubs);
  smatch m;
  return regex_match(s,m,pattern);
}

////////////////////////////////////////////////////////////////////////////
static inline bool valid_ip_port(const MoReq* req) {
  if (req->moip()!="" && !is_valid_cidr(req->moip()))
    return false;
  if (req->pip()!="" && !is_valid_cidr(req->pip()))
    return false;
  if (req->moport()!="" && !is_valid_port(req->moport()))
    return false;
  if (req->pport()!="" && !is_valid_port(req->pport()))
    return false;

  return true;
}

////////////////////////////////////////////////////////////////////////////
static void setOp(const string& str, MoReq* req){
  if ( str=="ADD" )
    req->set_op(MoReq::ADD);
  else if ( str=="DEL" )
    req->set_op(MoReq::DEL);
  else if ( str=="MOD" )
    req->set_op(MoReq::MOD);
  else if ( str=="GET" )
    req->set_op(MoReq::GET);
  else if ( str=="GADD" )
    req->set_op(MoReq::GADD);
  else if ( str=="GDEL" )
    req->set_op(MoReq::GDEL);
  else if ( str=="GGET" )
    req->set_op(MoReq::GGET);
  else if ( str=="GETFILTER" )
    req->set_op(MoReq::GET_FILTER);
}

////////////////////////////////////////////////////////////////////////////
bool validate_request(MoReq* req) {
  if (!req->has_op())
    return false;
  if ( req->has_moid() && !is_valid_molist(req->moid()) )
    return false;
  if (req->has_tag() &&
      req->tag().size() != strspn(req->tag().c_str(), VALID_TAG_PATTERN)) {
    return false;
  }
  if ( req->devid()!="" && req->devid().size() != strspn(req->devid().c_str(), "0123456789") ) 
    return false;
  if ( req->has_direction() && req->direction()!="IN" && req->direction()!="OUT" && req->direction()!="ALL" )
    return false;

  //防止protocol为非传输层协议，导致filter匹配失效indexer不能正常运行
  if (req->has_protocol() && req->protocol() != "") {
    if (req->protocol() != "TCP" && req->protocol() != "UDP" && req->protocol() != "6" && req->protocol() != "17") 
      return false;
  }

  switch (req->op()){
    case MoReq::MOD:
      if ( !req->has_moid() )
        return false;
      if ( req->filter()=="" && req->has_moip() && req->moip()=="" && req->has_moport() && req->moport()=="" )
        return false;
      if ( req->filter()=="" && !valid_ip_port(req))
          return false;
      return true;
      break;
    case MoReq::ADD:
      if ( req->filter()=="" && req->moip()==""&&req->moport()=="" )
        return false;
      if ( req->filter()=="" && !valid_ip_port(req))
          return false;
      if ( !req->has_direction() )
        req->set_direction("ALL");
      if (!req->has_mogid())
        req->set_mogid(1);
      break;
    case MoReq::DEL:
      if ( !req->has_moid()&&req->moip()==""&&req->moport()==""&&req->protocol()==""&&req->pip()==""&&req->pport()=="" )
        return false;
      break;

    case MoReq::GADD:
      if ( req->mogroup()=="" || req->mogroup()=="unclassified" )
        return false;
      break;
    case MoReq::GDEL:
      if ( req->mogid()==1 || req->mogroup()=="unclassified" )
        return false;
      if ( !req->has_mogid() && req->mogroup()=="" )
        return false;
      break;
    case MoReq::GMOD:
      if ( req->mogid()<=1 || req->mogroup()=="" )
        return false;
      break;
    case MoReq::GGET:
    case MoReq::GET:
    case MoReq::GET_FILTER:
      break;
    default:return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////
std::string ipAddSuffix(const std::string& ip){
  if (ip==""||ip.find('/')!=string::npos)
    return ip;
  else
    return ip+"/32";
}

////////////////////////////////////////////////////////////////////////////
void ParseMoReqFromUrlParams(cgicc::Cgicc& cgi, MoReq* req) {
  if (!cgi("moip").empty()) req->set_moip( cgi("moip")=="null"?"":cgi("moip") );
  if (!cgi("moport").empty()) req->set_moport( cgi("moport")=="null"?"":cgi("moport") );
  if (!cgi("protocol").empty()) req->set_protocol( cgi("protocol")=="null"?"":boost::to_upper_copy(cgi("protocol")) );
  if (!cgi("pip").empty()) req->set_pip( cgi("pip")=="null"?"":cgi("pip") );
  if (!cgi("pport").empty()) req->set_pport( cgi("pport")=="null"?"":cgi("pport") );
  if (!cgi("desc").empty()) req->set_desc( cgi("desc")=="null"?"":cgi("desc") );
  if (!cgi("tag").empty()) req->set_tag( cgi("tag")=="null"?"":cgi("tag") );
  if (!cgi("mogroup").empty()) req->set_mogroup( cgi("mogroup") );  
  if ( !cgi("op").empty() )
    setOp(boost::to_upper_copy(cgi("op")), req);
  if (!cgi("moid").empty()) req->set_moid( cgi("moid") );
  if (!cgi("id").empty()) req->set_mogid( atoi(cgi("id").c_str()) );
  if (!cgi("groupid").empty()) req->set_mogid( atoi(cgi("groupid").c_str()) );
  if (!cgi("devid").empty()) req->set_devid( cgi("devid")=="null"?"":cgi("devid") );
  if (!cgi("direction").empty()) req->set_direction( boost::to_upper_copy(cgi("direction")) );
  if (!cgi("filter").empty()) req->set_filter( cgi("filter") );
}

////////////////////////////////////////////////////////////////////////////
std::string genMoFilter(MoReq* req){
  if (req->filter()!="")
    return req->filter();

  string mosrc, modst;
  string tmp;

  mosrc="(";
  modst="(";

  string moip, not_moip;
  if (req->moip()!="" && req->moip()[0]=='!') {
    not_moip = "not ";
    moip = req->moip().substr(1, req->moip().size() - 1);
  }
  else
    moip = req->moip();

  string pip, not_pip;
  if (req->pip()!="" && req->pip()[0]=='!') {
    not_pip = "not ";
    pip = req->pip().substr(1, req->pip().size() - 1);
  }
  else
    pip = req->pip();

  string moport, not_moport;
  if (req->moport()!="" && req->moport()[0]=='!') {
    not_moport = "not ";
    moport = req->moport().substr(1, req->moport().size() - 1);
  }
  else
    moport = req->moport();

  string pport, not_pport;
  if (req->pport()!="" && req->pport()[0]=='!') {
    not_pport = "not ";
    pport = req->pport().substr(1, req->pport().size() - 1);
  }
  else
    pport = req->pport();

  if (req->direction()=="ALL"){
    vector<string> v;

    if (req->moip()!=""){
      if (is_valid_ip(req->moip()))
        v.push_back(not_moip + "ip "+moip);
      else
        v.push_back(not_moip + "net "+moip);
    }
    if (req->moport()!="")
      v.push_back(not_moport + "port "+moport);
    if (req->pip()!=""){
      if (is_valid_ip(req->pip()))
        v.push_back(not_pip + "ip " + pip);
      else
        v.push_back(not_pip + "net " + pip);
    }
    if (req->pport()!="")
      v.push_back(not_pport + "port "+pport);

    tmp = v[0];
    for (unsigned int i=1;i<v.size();i++)
      tmp+=" and "+v[i];
    if (req->protocol()!="")
      tmp+=" and proto " + req->protocol();

    return tmp;
  }

  if (req->moip()!="" && req->moport()!=""){
    if (is_valid_ip(req->moip())){
      mosrc += not_moip + " src ip " + moip + " and " + not_moport + "src port " + moport;
      modst += not_moip + " dst ip " + moip + " and " + not_moport + "dst port " + moport;
    }
    else{
      mosrc += not_moip + " src net " + moip + " and " + not_moport + "src port " + moport;
      modst += not_moip + " dst net " + moip + " and " + not_moport + "dst port " + moport;
    }
  }
  else if (req->moip()!=""){
    if (is_valid_ip(req->moip())){
      mosrc += not_moip + " src ip " + moip;
      modst += not_moip + " dst ip " + moip;
    }
    else{
      mosrc += not_moip + " src net " + moip;
      modst += not_moip + " dst net " + moip;
    }
  }
  else{
    mosrc += not_moport + " src port " + moport;
    modst += not_moport + " dst port " + moport;
  }

  if (req->pip()!="" && req->pport()!=""){
    if (is_valid_ip(req->pip())){
      mosrc+=" and ( " + not_pip + "dst ip " + pip + " ) and (" + not_pport + "dst port " + pport + ")";
      modst+=" and ( " + not_pip + "src ip " + pip + " ) and (" + not_pport + "src port " + pport + ")";
    }
    else{
      mosrc+=" and ( " + not_pip + "dst net " + pip + " ) and (" + not_pport + "dst port " + pport + ")";
      modst+=" and ( " + not_pip + "src net " + pip + " ) and (" + not_pport + "src port " + pport + ")";
    }
  }
  else if (req->pip()!=""){
    if (is_valid_ip(req->pip())){
      mosrc+=" and " + not_pip + "dst ip " + pip;
      modst+=" and " + not_pip + "src ip " + pip;
    }
    else{
      mosrc+=" and " + not_pip + "dst net " + pip;
      modst+=" and " + not_pip + "src net " + pip;
    }
  }
  else if (req->pport()!=""){
    mosrc+=" and (" + not_pport + "dst port " + pport + ")";
    modst+=" and (" + not_pport + "src port " + pport + ")";
  }

  mosrc+=" )";
  modst+=" )";

  if (req->direction()=="IN")
    tmp = modst;
  else if (req->direction()=="OUT")
    tmp = mosrc;

  if (req->protocol()!="")
    return "( " + tmp + " ) and proto " + req->protocol();

  return tmp;
}

////////////////////////////////////////////////////////////////////////////
void stAddUpdateSet(string& str, const string s){
  static bool first=true;

  if (first){
    str+=s;
    first=false;
  }
  else
    str+=", "+s;
}

void stAddWhere(string& str, const string s){
  static bool first=true;

  if (first){
    str+=s;
    first=false;
  }
  else
    str+=" and "+s;
}

void composeWhereSt(string& str, MoReq* req){
  if (req->has_moip())
    stAddWhere(str,"moip = ?");
  if (req->has_moport()){
    if (req->moport()=="")
      stAddWhere(str,"moport is null");
    else
      stAddWhere(str,"moport = ?");
  }
  if (req->has_protocol())
    stAddWhere(str,"protocol = ?");
  if (req->has_pip())
    stAddWhere(str,"pip = ?");
  if (req->has_pport()){
    if (req->pport()=="")
      stAddWhere(str,"pport is null");
    else
      stAddWhere(str,"pport = ?");
  }
  if (req->has_tag()){
    if (req->tag()=="")
      stAddWhere(str, "tag = ''");
    else{
      std::stringstream tags(req->tag());
      string tag;
      while (std::getline(tags, tag, ','))
        stAddWhere(str,string("tag REGEXP '^") + tag + "$|^" + tag + ",|," + tag + "$|," + tag + ",'");
    }
  }
}

void bindWhereSt(cppdb::statement& st, MoReq* req){
  if (req->has_moip())
    st<<req->moip();
  if (req->moport()!="")
      st<<req->moport();
  if (req->has_protocol())
    st<<req->protocol();
  if (req->has_pip())
    st<<req->pip();
  if (req->pport()!="")
    st<<req->pport();
}

/*vector<u32> getMoIDs(cppdb::session* sql, MoReq* req){
	u32 id;
	vector<u32> ids;
	cppdb::result res;

	try{
		if (req->has_mogroup())
			res = *sql << "select t1.id from t_mo t1, t_mogroup t2 where ( t1.mogroupid = t2.id and t2.name = ? )" << req->mogroup();
		else{
			string str;
			str="select t1.id from t_mo t1, t_mogroup t2 where ( ";
			stAddWhere(str,"t1.mogroupid = t2.id");
			composeWhereSt(str, req);
			str+=" )";

			cppdb::statement st = *sql << str;
			bindWhereSt(st, req);

			res = st;
		}

		while (res.next()){
			res>>id;
			ids.push_back(id);
		}
	} catch ( cppdb::cppdb_error const &e ){
		log_err("%s\n", e.what());
	}

	return ids;
}

vector<u32> getMoIDs(cppdb::session* sql, const u32 groupid, u32 devid){
  u32 id;
  vector<u32> ids;
  cppdb::result res;

  try{
    if ( groupid==0 ){
      if (devid>0)
        res = *sql << "select id from t_mo where ( devid = ? OR devid IS NULL )"<<devid;
      else
        res = *sql << "select id from t_mo";
    }
    else{
      if (devid>0)
        res = *sql << "select id from t_mo where ( mogroupid = ? and ( devid = ? OR devid IS NULL) )"<<groupid<<devid;
      else
        res = *sql << "select id from t_mo where ( mogroupid = ? )"<<groupid;
    }

    while (res.next()){
      res>>id;
      ids.push_back(id);
    }
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s", e.what());
  }

  return ids;
}*/

/*string filterMoIDsWithDevid(cppdb::session* sql, string moid, u32 devid){
  u32 id;
  string result="";
  cppdb::result res;

  if (devid==0)
    return moid;

  try{
    bool first = true;
    res = *sql << "select id from t_mo where ( id in (?) and (devid = ? OR devid IS NULL) )" << moid << devid;

    while (res.next()){
      res>>id;
      if (first){
        result = to_string(id);
        first = false;
      }
      else
        result+=( ","+to_string(id) );
    }
  } catch ( cppdb::cppdb_error const &e ){
    log_err("%s\n", e.what());
  }

  return result;
}*/

} // namespace mo
