#include "nf_scanner.h"

#include <utility>
#include <mutex>
#include <google/protobuf/text_format.h>
#include "../../common/common.h"
#include "../../common/ip.h"
#include "../../common/datetime.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../../common/stringutil.h"
#include "../data/dbctx.h"
#include "../data/web_cache.h"
#include "../define.h"
#include "../utils/time_util.h"

enum SortByType {
  SORTBY_ALL = 0,
  SORTBY_IP = 1,
  SORTBY_AS = 2,
  SORTBY_PROTO = 3,
  SORTBY_PORT = 4,
  SORTBY_INIF = 5,
  SORTBY_OUTIF = 6,
  SORTBY_CONV = 7,
  SORTBY_NONE = 8
};

enum Direction {
  DIR_SRC_OR_DST = 0,
  DIR_SRC = 1,
  DIR_DST = 2,
  DIR_SRC_AND_DST = 3
};

static std::mutex mtx;
static char kNFDump[] = "/Agent/bin/nfdump";
static std::string kSortBys[] = {"ALL", "IP", "AS", "PROTO", "PORT", "INIF", "OUTIF", "CONV", "NONE"};
static std::string kSortStrs[] = {"inif", "ip", "as", "proto", "port:p", "inif", "outif", "record", ""};

static void inline output_u64(stringstream& out, const string& name, u64 value)
{
  out << '"' << name << "\":" << value;
}
static void inline output_string(stringstream& out, const string& name, const string& value)
{
  out << '"' << name << "\":\"" << value << '"';
}

////////////////////////////////////////////////////////////////////////////
static SortByType GetSortByType(const TopnReq& req) {
  for (u32 i = 0; i < sizeof(kSortBys) / sizeof(kSortBys[0]); ++i) {
    if (req.sortby() == kSortBys[i]) return static_cast<SortByType>(i);
  }
  return SORTBY_ALL;
}

////////////////////////////////////////////////////////////////////////////
static Direction GetDirection(const TopnReq& req, SortByType st) {
  switch (st) {
    case SORTBY_IP:
    case SORTBY_AS:
    case SORTBY_PORT:
      if (req.srcdst() == "src") return DIR_SRC;
      if (req.srcdst() == "dst") return DIR_DST;
      if (req.srcdst() == "srcdst") return DIR_SRC_AND_DST;
      // fallthrough
    default:
      return DIR_SRC_OR_DST;
  }
}

////////////////////////////////////////////////////////////////////////////
static string BuildSortByFlag(SortByType st, Direction direction,
                              TopnReq::OrderBy orderby){
  string orderby_suffix;
  if (orderby == TopnReq::Bytes) {
    orderby_suffix = "/bytes";
  } else if (orderby == TopnReq::Packets) {
    orderby_suffix = "/pkts";
  } else if (orderby == TopnReq::Flows) {
    orderby_suffix = "/flows";
  } else {
    log_warning("Unknown orderby. use default value - bytes\n");
    orderby_suffix = "/bytes";
  }

  string sortstr = kSortStrs[st];
  if (!sortstr.empty()) {
    switch (direction) {
      case DIR_SRC: return "-s src" + sortstr + orderby_suffix;
      case DIR_DST: return "-s dst" + sortstr + orderby_suffix;
      case DIR_SRC_AND_DST:
        return "-s src" + sortstr + orderby_suffix +
               " -s dst" + sortstr + orderby_suffix;
      // DIR_SRC_OR_DST
      default: return "-s " + sortstr + orderby_suffix;
    }
  }
  return string();
}

////////////////////////////////////////////////////////////////////////////
static string BuildIncludeExcludeFlag(bool exclude, string labels) {
  if (labels.empty()) return string();
  return (exclude ? "-S exclude=" : "-S include=") + labels;
}

////////////////////////////////////////////////////////////////////////////
string BuildFlowFilesFlag(const string& flow_dir, const string& flow_file_prefix,
                          u32 starttime, u32 endtime) {
  std::string starttimestr;
  std::string endtimestr;
  datetime::format_timestamp(starttime, &starttimestr);
  datetime::format_timestamp(endtime, &endtimestr);
  return "-R " + flow_dir + "/" + flow_file_prefix + starttimestr + ":" +
         flow_file_prefix + endtimestr;
}

////////////////////////////////////////////////////////////////////////////
static string BuildFilterFlag(const string& flow_filter) {
  return '"' + flow_filter + '"';
}

////////////////////////////////////////////////////////////////////////////
static void AddFlag(const string& flag, std::vector<string>* flags) {
  if (!flag.empty()) flags->push_back(flag);
}

////////////////////////////////////////////////////////////////////////////
static string Join(const std::vector<string>& parts, const char* delim) {
  std::ostringstream stream;
  std::copy(parts.begin(), parts.end(),
            std::ostream_iterator<std::string>(stream, delim));
  return stream.str();
}

////////////////////////////////////////////////////////////////////////////
static FILE* popen_nfdump(u32 devid, const std::string& cmd)
{
  if (DEBUG) log_info("DEVID=%u %s\n", devid, cmd.c_str());
  setenv("DEVID", to_string(devid).c_str(), 1); 
  return popen(cmd.c_str(), "r");
}

////////////////////////////////////////////////////////////////////////////
static bool FlowFileExists(const string& flow_file) {
  struct stat statbuf;
  bool exists = stat(flow_file.c_str(), &statbuf) == 0;
  if (DEBUG && !exists) {
    log_info("flow file not found: %s\n", flow_file.c_str());
  }
  return exists;
}

////////////////////////////////////////////////////////////////////////////
static bool ValidateFlowFiles(
  const string& flow_dir, const string& prefix, u32 step, u32* starttime,
  u32* endtime) {

  string flow_file_base = flow_dir + '/' + prefix;
  bool start_file_found = false;
  bool end_file_found = false;
  while (*starttime <= *endtime)
  {
    string starttimestr;
    string endtimestr;
    datetime::format_timestamp(*starttime, &starttimestr);
    datetime::format_timestamp(*endtime, &endtimestr);
    if (DEBUG) {
      log_info("Checking time range [%u,%u] - [%s,%s]\n", *starttime, *endtime,
                starttimestr.c_str(), endtimestr.c_str());
    }
    if (!start_file_found) {
      if (FlowFileExists(flow_file_base + starttimestr)) start_file_found = true;
      else *starttime += step;
    }
    if (*starttime <= *endtime && !end_file_found) {
      if (FlowFileExists(flow_file_base + endtimestr)) end_file_found = true;
      else *endtime -= step;
    }
    if (start_file_found && end_file_found) return true;
  }
  return false;
}

////////////////////////////////////////////////////////////////////////////
bool NFScanner::ScanFlowFiles(const TopnReq& req, TopnResponse* rsp, string* error) {

  DBCtxOptions options;
  options.set_read_only(false);
  std::unique_ptr<DBBuilder> db_builder(new DBBuilder(options, AGENT_CACHE_DIR));

  u32 starttime = req.starttime();
  u32 endtime = req.endtime();
  if (!ValidateFlowFiles(flow_dir_, flow_file_prefix_, req.step(), &starttime,
                         &endtime)) {
    *error = "Can't find flow files of request" + req.DebugString();
    return false;
  }

  SortByType sortby = GetSortByType(req);
  Direction direction = GetDirection(req, sortby);
  std::vector<string> cmdline_parts({kNFDump});
  AddFlag(BuildSortByFlag(sortby, direction, req.orderby()), &cmdline_parts);
  AddFlag(BuildFlowFilesFlag(flow_dir_, flow_file_prefix_, starttime, endtime),
          &cmdline_parts);
  AddFlag("-n " + to_string(req.limit()), &cmdline_parts);
  AddFlag("-p " + to_string(req.step()), &cmdline_parts);

  if (req.has_app_proto())
    AddFlag("-P " + req.app_proto(), &cmdline_parts);
  if (req.has_qname())
    AddFlag("-Q" + req.qname(), &cmdline_parts);
  if (req.has_qtype())
    AddFlag("-C" + to_string(req.qtype()), &cmdline_parts);

  AddFlag("-o pipe", &cmdline_parts);
  AddFlag("-N", &cmdline_parts);
  AddFlag(BuildFilterFlag(req.filter()), &cmdline_parts);
  if (req.has_include() && !req.include().empty())
     AddFlag(BuildIncludeExcludeFlag(false, req.include()), &cmdline_parts);
  if (req.has_exclude() && !req.exclude().empty())
     AddFlag(BuildIncludeExcludeFlag(true, req.exclude()), &cmdline_parts);
  string cmd = Join(cmdline_parts, " ");
  FILE* fp_flow = popen_nfdump(req.devid(), cmd);
  if (fp_flow == NULL) {
    *error = "Can't invoke nfdump";
    return false;
  }

  int statitem = direction == DIR_SRC_AND_DST ? 2 : 1;
  u32 ut = starttime;
  bool print_summary = false;
  int cur_statitem = 0;
  static char line[LINE_MAX];
  TopnResponse batch;
  string tmp_str;
  bool line_change = false;

  while (fgets(line, sizeof(line), fp_flow))
  {
    char * s;
    s = strtok(line, "\r\n");
    if ((s == NULL) || (s[0] == '\0'))
    {
      cur_statitem++;
      if (cur_statitem == statitem)
      {
        print_summary = true;
      }
      else if (cur_statitem > statitem)
      {
        TopnReq req_to_update(req);
        req_to_update.set_starttime(ut);
        req_to_update.set_endtime(ut);
        WebCache cache(db_builder.get());
        cache.Update(ut, req_to_update, batch);
        rsp->MergeFrom(batch);
        batch.Clear();

        print_summary = false;
        cur_statitem = 0;
        ut += req.step();
      }
      continue;
    }

    int af;
    u32 first, msec_first, last, msec_last, proto, port, as, tos,
        sa[4], sport, da[4], dport, inif, outif, sas, das, flags,
        popular_service, service, scanner, whitelist, blacklist;
    u64 flows,pkts,bytes,pps,bps,bpp;
    char str[1024];
    u32 qtype, qclass;
    vector<string> res;

    bool add_record = false;
    TopnRecord rec;
    if (!print_summary)
    {
      if (sortby == SORTBY_IP)
      {
        if (16 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
            &af,&first,&msec_first,&last,&msec_last,&proto, &sa[0],&sa[1],&sa[2],&sa[3],
            &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
        string ip;
        if (af == 10) {
          struct in6_addr ip6;
          std::copy(sa, sa+4, ip6.s6_addr32);
          ip = ipnum_to_ipstr_v6(ip6);
        } else {
          ip = ipnum_to_ipstr(sa[3]);
        }

        if ((direction == DIR_SRC_OR_DST) && (statitem == 1)) {
          add_record = true;
          rec.set_type("IP");
          rec.set_ip(ip);
        } else if (((direction == DIR_SRC) || (direction == DIR_SRC_AND_DST))
                   && (cur_statitem == 0)) {
          add_record = true;
          rec.set_type("SIP");
          rec.set_sip(ip);
        } else if (((direction == DIR_DST) && (cur_statitem == 0)) ||
                   ((direction == DIR_SRC_AND_DST) && (cur_statitem == 1))) {
          add_record = true;
          rec.set_type("DIP");
          rec.set_dip(ip);
        }
      }
      else if (sortby == SORTBY_AS)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto, &as,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
        if ((direction == DIR_SRC_OR_DST) && (statitem == 1)) {
          add_record = true;
          rec.set_type("AS");
          //rec.set_as(as);
        } else if (((direction == DIR_SRC) || (direction == DIR_SRC_AND_DST))
                   && (cur_statitem == 0)) {
          add_record = true;
          rec.set_type("SAS");
          //rec.set_sas(as);
        } else if (((direction == DIR_DST) && (cur_statitem == 0)) || 
                   ((direction == DIR_SRC_AND_DST) && (cur_statitem == 1)))
          add_record = true;
          rec.set_type("DAS");
          //rec.set_das(as);
      }
      else if (sortby == SORTBY_PORT)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto, &port,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        rec.set_protocol(proto);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
        if ((direction == DIR_SRC_OR_DST) && (statitem == 1)) {
          add_record = true;
          rec.set_type("PORT");
          rec.set_port(port);
        } else if (((direction == DIR_SRC) || (direction == DIR_SRC_AND_DST))
                   && (cur_statitem == 0)) {
          add_record = true;
          rec.set_type("SPORT");
          rec.set_sport(port);
        } else if (((direction == DIR_DST) && (cur_statitem == 0)) ||
                   ((direction == DIR_SRC_AND_DST) && (cur_statitem == 1))) {
          add_record = true;
          rec.set_type("DPORT");
          rec.set_dport(port);
        }
      }
      else if (sortby == SORTBY_PROTO)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto, &proto,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        add_record = true;
        rec.set_type("PROTO");
        rec.set_protocol(proto);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
      }
      else if (sortby == SORTBY_INIF)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto,&inif,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        add_record = true;
        rec.set_type("INIF");
        rec.set_inif(inif);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
      }
      else if (sortby == SORTBY_OUTIF)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto,&outif,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        add_record = true;
        rec.set_type("OUTIF");
        rec.set_inif(outif);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
      }
      else if (sortby == SORTBY_CONV)
      {
        if (line_change)
          tmp_str += s;
        else
          tmp_str = s;

        if (33 != sscanf(tmp_str.c_str(), "%d|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%u|%u|%u|%u|%u|%u|%u|%[^\n]", 
             &af,&first,&msec_first,&last,&msec_last,&proto, 
             &sa[0],&sa[1],&sa[2],&sa[3], &sport,
             &da[0],&da[1],&da[2],&da[3], &dport,
             &sas, &das, &inif, &outif, &flags, &tos,
             &pkts,&bytes,&flows,&popular_service,&service,&scanner, &whitelist, &blacklist, 
             &qtype, &qclass, str)) continue;
        //qname|l7_proto|http_url|http_host|http_req_method|http_mime|http_user_agent|http_cookie|http_ret_code|service_type|service_name|service_info1|
        //service_info2|icmp_data|icmp_seq_num|icmp_payload_len
        int num = count(tmp_str.begin(), tmp_str.end(), '|');
        if (num < 43) {
          line_change = true;
          continue;
        }
        line_change = false;
        tmp_str.clear();
      
        string sstr = str;
        if (count(sstr.begin(), sstr.end(), '|') < 15) continue; 

        string context, app_proto;
        size_t pos = sstr.find("|");
        while (pos != std::string::npos) {
          string tmp = sstr.substr(0, pos);
          res.push_back(tmp);
          sstr = sstr.substr(pos+1);
          pos = sstr.find("|");
        }
        res.push_back(sstr);
        app_proto = res[1];
        if (!res[0].empty()) {
          context = escape_back_slash(res[0])+","+qtype_to_str(qtype);
        }
        if (!res[2].empty() || !res[3].empty() || !res[4].empty() || !res[5].empty() || !res[6].empty() || !res[7].empty()) {
          context = escape_back_slash(res[2])+","+escape_back_slash(res[3])+","+res[4]+","+res[5]+","+res[6]+","+res[7]+","+res[8];
        }

        add_record = true;
        rec.set_type("CONV");
        //rec.set_first(first);
        //rec.set_duration(last-first);
        rec.set_protocol(proto);
        string sip, dip;
        if (af == 10) {
          struct in6_addr sip6, dip6;
          std::copy(sa, sa+4, sip6.s6_addr32);
          std::copy(da, da+4, dip6.s6_addr32);
          sip = ipnum_to_ipstr_v6(sip6);
          dip = ipnum_to_ipstr_v6(dip6);
        } else {
          sip = ipnum_to_ipstr(sa[3]);
          dip = ipnum_to_ipstr(da[3]);
        }
        rec.set_sip(sip);
        rec.set_dip(dip);
        rec.set_sport(sport);
        rec.set_dport(dport);
        rec.set_inif(inif);
        rec.set_outif(outif);
        rec.set_flags(flags);
        rec.set_tos(tos);
        rec.set_popular_service(popular_service);
        rec.set_service(service);
        rec.set_scanner(scanner);
        rec.set_whitelist(whitelist);
        rec.set_blacklist(blacklist);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
        rec.set_app_proto(app_proto);
        rec.set_context(context);
        rec.set_service_type(atoi(res[9].c_str()));
        rec.set_service_name(res[10]);
        rec.set_service_info1(res[11]);
        rec.set_service_info2(res[12]);
      }
      else if (sortby == SORTBY_NONE)
      {
        if (25 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto, 
             &sa[0],&sa[1],&sa[2],&sa[3], &sport,
             &da[0],&da[1],&da[2],&da[3], &dport,
             &sas, &das, &inif, &outif, &flags, &tos,
             &pkts,&bytes,&flows)) continue;
        add_record = true;
        rec.set_type("RAW");
        UNUSED(first);
        UNUSED(last);
        rec.set_protocol(proto);
         string sip, dip;
        if (af == 10) {
          struct in6_addr sip6, dip6;
          std::copy(sa, sa+4, sip6.s6_addr32);
          std::copy(da, da+4, dip6.s6_addr32);
          sip = ipnum_to_ipstr_v6(sip6);
          dip = ipnum_to_ipstr_v6(dip6);
        } else {
          sip = ipnum_to_ipstr(sa[3]);
          dip = ipnum_to_ipstr(da[3]);
        }
        rec.set_sip(sip);
        rec.set_dip(dip);
        rec.set_sport(sport);
        rec.set_dport(dport);
        rec.set_inif(inif);
        rec.set_outif(outif);
        rec.set_flags(flags);
        rec.set_tos(tos);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
      }
      if (add_record) batch.add_records()->Swap(&rec);
    }
    else // print_summary
    {
      if (strncmp(s, "Summary", 7) == 0)
        if (3 == sscanf(s, "Summary: total flows: %ju, total bytes: %ju, total packets: %ju", &flows, &bytes, &pkts)) {
          rec.set_type("ALL");
          rec.set_time(ut);
          rec.set_flows(flows);
          rec.set_pkts(pkts);
          rec.set_bytes(bytes);
          batch.add_records()->Swap(&rec);
        }
    }
  }
  pclose(fp_flow);
  if (batch.records_size() > 0) {
    TopnReq req_to_update(req);
    req_to_update.set_starttime(ut);
    req_to_update.set_endtime(ut);
    WebCache cache(db_builder.get());
    cache.Update(ut, req_to_update, batch);
    rsp->MergeFrom(batch);

    batch.Clear();
  }
  return true;
}

struct cache_pair NFScanner::ScanFlowFilesCache(const TopnReq& req, TopnResponse& rsp, string* error) {

  u32 starttime = req.starttime();
  u32 endtime = req.endtime();
  struct cache_pair rsp_pair;
  if (!ValidateFlowFiles(flow_dir_, flow_file_prefix_, req.step(), &starttime,
                         &endtime)) {
    *error = "Can't find flow files of request" + req.DebugString();
    return rsp_pair;
  }

  SortByType sortby = GetSortByType(req);
  Direction direction = GetDirection(req, sortby);
  std::vector<string> cmdline_parts({kNFDump});
  AddFlag(BuildSortByFlag(sortby, direction, req.orderby()), &cmdline_parts);
  AddFlag(BuildFlowFilesFlag(flow_dir_, flow_file_prefix_, starttime, endtime),
          &cmdline_parts);
  AddFlag("-n " + to_string(req.limit()), &cmdline_parts);
  AddFlag("-p " + to_string(req.step()), &cmdline_parts);

  if (req.has_app_proto())
    AddFlag("-P " + req.app_proto(), &cmdline_parts);
  if (req.has_qname())
    AddFlag("-Q" + req.qname(), &cmdline_parts);
  if (req.has_qtype())
    AddFlag("-C" + to_string(req.qtype()), &cmdline_parts);

  AddFlag("-o pipe", &cmdline_parts);
  AddFlag("-N", &cmdline_parts);
  AddFlag(BuildFilterFlag(req.filter()), &cmdline_parts);
  if (req.has_include() && !req.include().empty())
     AddFlag(BuildIncludeExcludeFlag(false, req.include()), &cmdline_parts);
  if (req.has_exclude() && !req.exclude().empty())
     AddFlag(BuildIncludeExcludeFlag(true, req.exclude()), &cmdline_parts);
  string cmd = Join(cmdline_parts, " ");
  mtx.lock();
  FILE* fp_flow = popen_nfdump(req.devid(), cmd);
  if (fp_flow == NULL) {
    *error = "Can't invoke nfdump";
    return rsp_pair;
  }

  int statitem = direction == DIR_SRC_AND_DST ? 2 : 1;
  u32 ut = starttime;
  bool print_summary = false;
  int cur_statitem = 0;
  static char line[LINE_MAX];
  TopnResponse batch;
  
  while (fgets(line, sizeof(line), fp_flow))
  {
    char * s;
    s = strtok(line, "\r\n");
    if ((s == NULL) || (s[0] == '\0'))
    {
      cur_statitem++;
      if (cur_statitem == statitem)
      {
        print_summary = true;
      }
      else if (cur_statitem > statitem)
      {
        break;
      }
      continue;
    }

    int af;
    u32 first, msec_first, last, msec_last, proto, port, as, tos,
        sa[4], sport, da[4], dport, inif, outif, sas, das, flags,
        popular_service, service, scanner, whitelist, blacklist;
    u64 flows,pkts,bytes,pps,bps,bpp;
    char str[1024];
    u32 qtype, qclass;
    vector<string> res;

    bool add_record = false;
    TopnRecord rec;
    if (!print_summary)
    {
      if (sortby == SORTBY_IP)
      {
        if (16 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
            &af,&first,&msec_first,&last,&msec_last,&proto, &sa[0],&sa[1],&sa[2],&sa[3],
            &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
        string ip;
        if (af == 10) {
          struct in6_addr ip6;
          std::copy(sa, sa+4, ip6.s6_addr32);
          ip = ipnum_to_ipstr_v6(ip6);
        } else {
          ip = ipnum_to_ipstr(sa[3]);
        }

        if ((direction == DIR_SRC_OR_DST) && (statitem == 1)) {
          add_record = true;
          rec.set_type("IP");
          rec.set_ip(ip);
        } else if (((direction == DIR_SRC) || (direction == DIR_SRC_AND_DST))
                   && (cur_statitem == 0)) {
          add_record = true;
          rec.set_type("SIP");
          rec.set_sip(ip);
        } else if (((direction == DIR_DST) && (cur_statitem == 0)) ||
                   ((direction == DIR_SRC_AND_DST) && (cur_statitem == 1))) {
          add_record = true;
          rec.set_type("DIP");
          rec.set_dip(ip);
        }
      }
      else if (sortby == SORTBY_AS)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto, &as,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
        if ((direction == DIR_SRC_OR_DST) && (statitem == 1)) {
          add_record = true;
          rec.set_type("AS");
          //rec.set_as(as);
        } else if (((direction == DIR_SRC) || (direction == DIR_SRC_AND_DST))
                   && (cur_statitem == 0)) {
          add_record = true;
          rec.set_type("SAS");
          //rec.set_sas(as);
        } else if (((direction == DIR_DST) && (cur_statitem == 0)) || 
                   ((direction == DIR_SRC_AND_DST) && (cur_statitem == 1)))
          add_record = true;
          rec.set_type("DAS");
          //rec.set_das(as);
      }
      else if (sortby == SORTBY_PORT)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto, &port,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        rec.set_protocol(proto);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
        if ((direction == DIR_SRC_OR_DST) && (statitem == 1)) {
          add_record = true;
          rec.set_type("PORT");
          rec.set_port(port);
        } else if (((direction == DIR_SRC) || (direction == DIR_SRC_AND_DST))
                   && (cur_statitem == 0)) {
          add_record = true;
          rec.set_type("SPORT");
          rec.set_sport(port);
        } else if (((direction == DIR_DST) && (cur_statitem == 0)) ||
                   ((direction == DIR_SRC_AND_DST) && (cur_statitem == 1))) {
          add_record = true;
          rec.set_type("DPORT");
          rec.set_dport(port);
        }
      }
      else if (sortby == SORTBY_PROTO)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto, &proto,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        add_record = true;
        rec.set_type("PROTO");
        rec.set_protocol(proto);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
      }
      else if (sortby == SORTBY_INIF)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto,&inif,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        add_record = true;
        rec.set_type("INIF");
        rec.set_inif(inif);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
      }
      else if (sortby == SORTBY_OUTIF)
      {
        if (13 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto,&outif,
             &flows,&pkts,&bytes,&pps,&bps,&bpp)) continue;
        add_record = true;
        rec.set_type("OUTIF");
        rec.set_inif(outif);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
      }
      else if (sortby == SORTBY_CONV)
      {
        if (33 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju|%u|%u|%u|%u|%u|%u|%u|%s", 
             &af,&first,&msec_first,&last,&msec_last,&proto, 
             &sa[0],&sa[1],&sa[2],&sa[3], &sport,
             &da[0],&da[1],&da[2],&da[3], &dport,
             &sas, &das, &inif, &outif, &flags, &tos,
             &pkts,&bytes,&flows,&popular_service,&service,&scanner, &whitelist, &blacklist, 
             &qtype, &qclass, str)) continue;
        //qname|l7_proto|http_url|http_host|http_req_method|http_mime|http_user_agent|http_cookiee|http_ret_code
       
        string context, app_proto;
        string sstr = str;
        size_t pos = sstr.find("|");
        while (pos != std::string::npos) {
          string tmp = sstr.substr(0, pos);
          res.push_back(tmp);
          sstr = sstr.substr(pos+1);
          pos = sstr.find("|");
        }
        res.push_back(sstr);
        app_proto = res[1];
        if (!res[0].empty()) {
          context = escape_back_slash(res[0])+","+qtype_to_str(qtype);
        }
        if (!res[2].empty() || !res[3].empty() || !res[4].empty() || !res[5].empty() || !res[6].empty() || !res[7].empty()) {
          context = escape_back_slash(res[2])+","+escape_back_slash(res[3])+","+res[4]+","+res[5]+","+res[6]+","+res[7]+","+res[8];
        }

        add_record = true;
        rec.set_type("CONV");
        //rec.set_first(first);
        //rec.set_duration(last-first);
        rec.set_protocol(proto);
         string sip, dip;
        if (af == 10) {
          struct in6_addr sip6, dip6;
          std::copy(sa, sa+4, sip6.s6_addr32);
          std::copy(da, da+4, dip6.s6_addr32);
          sip = ipnum_to_ipstr_v6(sip6);
          dip = ipnum_to_ipstr_v6(dip6);
        } else {
          sip = ipnum_to_ipstr(sa[3]);
          dip = ipnum_to_ipstr(da[3]);
        }
        rec.set_sip(sip);
        rec.set_dip(dip);
        rec.set_sport(sport);
        rec.set_dport(dport);
        rec.set_inif(inif);
        rec.set_outif(outif);
        rec.set_flags(flags);
        rec.set_tos(tos);
        rec.set_popular_service(popular_service);
        rec.set_service(service);
        rec.set_scanner(scanner);
        rec.set_whitelist(whitelist);
        rec.set_blacklist(blacklist);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
        rec.set_app_proto(app_proto);
        rec.set_context(context);
      }
      else if (sortby == SORTBY_NONE)
      {
        if (25 != sscanf(s, "%d|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%ju|%ju|%ju", 
             &af,&first,&msec_first,&last,&msec_last,&proto, 
             &sa[0],&sa[1],&sa[2],&sa[3], &sport,
             &da[0],&da[1],&da[2],&da[3], &dport,
             &sas, &das, &inif, &outif, &flags, &tos,
             &pkts,&bytes,&flows)) continue;
        add_record = true;
        rec.set_type("RAW");
        UNUSED(first);
        UNUSED(last);
        rec.set_protocol(proto);
        string sip, dip;
        if (af == 10) {
          struct in6_addr sip6, dip6;
          std::copy(sa, sa+4, sip6.s6_addr32);
          std::copy(da, da+4, dip6.s6_addr32);
          sip = ipnum_to_ipstr_v6(sip6);
          dip = ipnum_to_ipstr_v6(dip6);
        } else {
          sip = ipnum_to_ipstr(sa[3]);
          dip = ipnum_to_ipstr(da[3]);
        }
        rec.set_sip(sip);
        rec.set_dip(dip);
        rec.set_sport(sport);
        rec.set_dport(dport);
        rec.set_inif(inif);
        rec.set_outif(outif);
        rec.set_flags(flags);
        rec.set_tos(tos);
        rec.set_time(ut);
        rec.set_flows(flows);
        rec.set_pkts(pkts);
        rec.set_bytes(bytes);
      }
      if (add_record) batch.add_records()->Swap(&rec);
    } else {
      if (strncmp(s, "Summary", 7) == 0) {
        if (3 == sscanf(s, "Summary: total flows: %ju, total bytes: %ju, total packets: %ju", &flows, &bytes, &pkts)) {
          rec.set_type("ALL");
          rec.set_time(ut);
          rec.set_flows(flows);
          rec.set_pkts(pkts);
          rec.set_bytes(bytes);
          batch.add_records()->Swap(&rec);
        }
      }
    }
  }
  pclose(fp_flow);
  mtx.unlock();
  if (batch.records_size() > 0) {
    rsp.MergeFrom(batch);
    batch.Clear();
  }

  rsp_pair.req = req;
  rsp_pair.rsp = rsp;
  return rsp_pair;
}
