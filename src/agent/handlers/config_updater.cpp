
#include <fstream>
#include <sstream>
#include <Cgicc.h>

#include "../../common/common.h"
#include "../../common/log.h"
#include "../../common/http.h"
#include "../../common/file.h"
#include "../../common/config.h"
#include "../define.h"

using namespace std;

static bool is_http = false;

////////////////////////////////////////////////////////////////////////////
static void process() 
{
  if (is_http) printf("Content-Type: application/json; charset=UTF-8\r\n\r\n");

  ConfigReader original_cfg_reader(AGENT_CFG_FILE);
  original_cfg_reader.LoadFromFile();

  cgicc::Cgicc cgi;
  const cgicc::CgiEnvironment &cgienv = cgi.getEnvironment();
  const string& method = cgienv.getRequestMethod();
  if (method == "PUT" || method == "POST") {
    const string config_str = cgienv.getPostData();
    ConfigReader new_cfg_reader;
    if (!new_cfg_reader.LoadFromString(config_str) || 
        original_cfg_reader.config().DebugString() ==
        new_cfg_reader.config().DebugString()) {
      return;
    }

//    system(FLOW_CAPD_LAUNCHER);
     
    ConfigWriter writer(AGENT_CFG_FILE);
    *writer.mutable_config() = new_cfg_reader.config();
    if (writer.WriteToFile(true)) {
      log_info("Successfully updated config file.\n");
    } else {
      log_err("Updating config file failed.\n");
    }
  } else if (method == "GET") {
    std::cout << original_cfg_reader.config().DebugString();
  }
}

////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[])
{
  is_http = getenv("REMOTE_ADDR") != NULL;

  try {
    process();
  } catch (std::exception const &e) {
   log_err("%s\n", e.what());
  }
  return 0;
}
      
