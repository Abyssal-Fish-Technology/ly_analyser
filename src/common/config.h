#ifndef __COMMON_CONFIG_H__
#define __COMMON_CONFIG_H__

#include "config.pb.h"

class ConfigReader {
 public:
  ConfigReader() {}
  explicit ConfigReader(const std::string& config_file)
    : config_file_(config_file) {}

  bool LoadFromFile() {return LoadFromFile(config_file_);}
  bool LoadFromFile(const std::string& config_file);
  bool LoadFromString(const std::string& config);

  const config::Config& config() const {return config_;}
  config::Config* mutable_config() {return &config_;}

 private:
  bool LoadFromStream(std::istream* stream);

  std::string config_file_;
  config::Config config_;
};

class ConfigWriter {
 public:
  ConfigWriter() {}
  explicit ConfigWriter(const std::string& config_file)
    : config_file_(config_file) {}

  bool WriteToFile(bool text_format) const {
    return WriteToFile(config_file_, text_format);
  }
  bool WriteToFile(const std::string& file_path, bool text_format) const;
  bool WriteToString(std::string* output, bool text_format) const;

  const config::Config& config() const { return config_; }
  config::Config* mutable_config() { return &config_; }

 private:
  bool WriteToStream(std::ostream* stream, bool text_format) const;

  std::string config_file_;
  config::Config config_;
};

#endif // __COMMON_CONFIG_H__
