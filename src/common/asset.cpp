#include "asset.h"
#include "strings.h"
#include "log.h"

void LoadAssetFromFile(const string& file_name, std::unordered_set<string>* ips) {
  u32 loaded = 0;
  try {
    ifstream ifs(file_name);
    string line;
    while (getline(ifs, line)) {
      trim(line);
      if (line.empty() || line[0] == '#') continue;
      ips->insert(line);
      ++loaded;
    }
  } catch (...) {
    log_warning("Could not load asset from file %s\n", file_name.c_str());
  }
}

