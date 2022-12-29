#include "config.h"
#include "common.h"
#include "file.h"
#include "log.h"
#include <iostream>
#include <sstream>
#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>


using namespace std;
using google::protobuf::io::IstreamInputStream;
using google::protobuf::io::OstreamOutputStream;

bool ConfigReader::LoadFromStream(istream* stream) {
  IstreamInputStream is(stream);
  return google::protobuf::TextFormat::Parse(&is, &config_)
      || config_.ParseFromIstream(stream);
}

bool ConfigReader::LoadFromString(const string& config) {
  istringstream is(config);
  if (!LoadFromStream(&is)) {
    log_err("Error parsing config string %s\n", config.c_str());
    return false;
  }
  return true;
}
  
bool ConfigReader::LoadFromFile(const string& config_file) {
  if (config_file.empty()) {
    log_err("Config file name empty.");
    return false;
  }
  ifstream is(config_file, ios_base::in);
  if (!LoadFromStream(&is)) {
    log_err("Error parsing config file %s\n", config_file.c_str());
    return false;
  }
  return true;
}

bool ConfigWriter::WriteToStream(ostream* stream, bool text_format) const {
  OstreamOutputStream os(stream);
  if (text_format) {
    return google::protobuf::TextFormat::Print(config_, &os);
  } else {
    return config_.SerializeToOstream(stream);
  }
}

bool ConfigWriter::WriteToString(string* output, bool text_format) const {
  if (text_format) {
    ostringstream os;
    if (WriteToStream(&os, true)) {
      *output = os.str();
      return true;
    }
    return false;
  }
  return config_.SerializeToString(output);
}

bool ConfigWriter::WriteToFile(const string& file_path, bool text_format) const {
  if (file_path.empty()) {
    log_err("Config file name empty.\n");
    return false;
  }
  ofstream os(file_path, ios_base::out);
  if (!WriteToStream(&os, text_format)) {
    log_err("Error writing config to file %s\n", file_path.c_str());
    return false;
  }
  return true;
}
