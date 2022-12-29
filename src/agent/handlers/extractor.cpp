#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <set>
#include <map>
#include <sstream>
#include <iostream>

#include "../../common/common.h"
#include "../../common/config.h"
#include "../../common/config.pb.h"
#include "../../common/datetime.h"
#include "../../common/http.h"
#include "../dump/libnfdump.h"
#include "../../common/log.h"
#include "../../common/strings.h"
#include "../define.h"

using namespace std;

static int verbose = 0;
static u32 timestamp = 0;
static config::Config cfg;
static string indexer = INDEXER;

////////////////////////////////////////////////////////////////////////////
static bool read_config(void) 
{
  ConfigReader cfg_reader(AGENT_CFG_FILE);
  if (!cfg_reader.LoadFromFile()) return false;
  cfg.Swap(cfg_reader.mutable_config());
  return true;
}

////////////////////////////////////////////////////////////////////////////
static string exec_command(u32 devid, u32 starttime, u32 endtime, const string& cmd)
{
  log_info("%s\n", cmd.c_str());
  setenv("DEVID", to_string(devid).c_str(), 1);
  setenv("STARTTIME", to_string(starttime).c_str(), 1);
  setenv("ENDTIME", to_string(endtime).c_str(), 1);
  FILE *in;
  char buff[4096];
  string result;
  if (!(in = popen(cmd.c_str(), "r"))){
    log_err("Failed to exec %s\n", cmd.c_str());
    return result;
  }
  while (fgets(buff, sizeof(buff), in)) {
    result += buff;
  }
  pclose(in);
  return result;
}

////////////////////////////////////////////////////////////////////////////
/*static void process()
{
  if (!read_config()) return;
  if (!timestamp) timestamp = datetime::latest_flow_time();
  auto timestr = datetime::format_timestamp(timestamp);
  ostringstream os;
  pid_t pid;
  for (auto i = 0; i < cfg.dev_size(); ++i) {
    pid = fork();
    if (pid < 0)
      return;
    else if (pid > 0)
      continue;
    else {
      auto& dev = cfg.dev(i);
      if (dev.disabled()) return;
      string flow_capd;
      if (dev.flowtype() == "netflow") {
        flow_capd = "nfcapd";
      } else if (dev.flowtype() == "sflow") {
        flow_capd = "sfcapd";
      } else {
        flow_capd = "nfcapd";
      }
      auto flow_file =
        AGENT_FLOW_DIR"/" + to_string(dev.id()) + '/' + flow_capd + '.' + timestr;
      stringstream is(exec_command(dev.id(), timestamp, timestamp, indexer + " -r " + flow_file));
      string line;
      while (!is.eof()) {
        getline(is, line);
        if (line.empty() || trim(line)=="No matched flows") continue;
        os << timestamp << '\t' << dev.id() << '\t' << line << '\n';
      }
      return;
    }
  }
  wait();
}*/





static void process()
{
  if (!read_config()) return;
  if (!timestamp) timestamp = datetime::latest_flow_time();
  auto timestr = datetime::format_timestamp(timestamp);
  ostringstream os;
  for (auto i = 0; i < cfg.dev_size(); ++i) {
    auto& dev = cfg.dev(i);
    if (dev.disabled()) continue;
    string flow_capd;
    if (dev.flowtype() == "netflow") {
      flow_capd = "nfcapd";
    } else if (dev.flowtype() == "sflow") {
      flow_capd = "sfcapd";
    } else {
      flow_capd = "nfcapd";
    }
    auto flow_file =
      AGENT_FLOW_DIR"/" + to_string(dev.id()) + '/' + flow_capd + '.' + timestr;
    stringstream is(exec_command(dev.id(), timestamp, timestamp, indexer + " -r " + flow_file));
    string line;
    while (!is.eof()) {
      getline(is, line);
      if (line.empty() || trim(line)=="No matched flows") continue;
      os << timestamp << '\t' << dev.id() << '\t' << line << '\n';
    }
  }
  if (verbose) cout << os.str();
}

////////////////////////////////////////////////////////////////////////////
static void usage(char * pn)
{
  fprintf(stderr, "usage %s [-v <verbose>] [-t <timestamp>] [-i <indexer_binary>] [-r]\n", pn);
  exit(1);
}

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  if (DEBUG) log_info("DEBUG mode is on.\n");
  char c;
  while ((c = getopt(argc, argv, "i:v:t:")) != -1) 
  {
    switch (c) 
    {   
    case 'v':
      verbose = atoi(optarg);
      verbose = verbose < 0 ? 0 : verbose;
      break;
    case 't':
      timestamp = atoll(optarg);
      timestamp -= timestamp % 300;
      break;
    case 'i':
      indexer = optarg;
      break;
    default:
      usage(argv[0]);
    }   
  }
 
  if (optind < argc) 
  {
    fprintf(stderr, "non-option ARGV-elements: ");
    while (optind < argc)
      fprintf(stderr, "%s ", argv[optind++]);
    fprintf(stderr, "\n");
    usage(argv[0]);
  }

  try {
    process();
  } catch (std::exception const &e) {
    log_err("%s\n", e.what());
  }
  return 0;
}
