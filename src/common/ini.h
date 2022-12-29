#ifndef __COMMON_INI_H
#define __COMMON_INI_H

#include <string>
#include <map>
#include "common.h"

class Ini {
 public:
  Ini(bool auto_save = false):auto_save_(auto_save) {};
  Ini(const std::string& ini_file, bool auto_save = false)
    : ini_file_(ini_file), auto_save_(auto_save) {
    LoadFromFile(ini_file);
  }
  
  bool LoadFromFile(const std::string& ini_file);
  bool SaveToFile(const std::string& ini_file);
  bool SaveToFile();
  void Set(const std::string& key, s64 value);
  void Set(const std::string& key, std::string value);
  s32 GetInt(const std::string& key, s32 default_value);
  s32 GetInt(const std::string& key);
  u32 GetUInt(const std::string& key, u32 default_value);
  u32 GetUInt(const std::string& key);
  s64 GetInt64(const std::string& key, s64 default_value);
  s64 GetInt64(const std::string& key);
  u64 GetUInt64(const std::string& key, u64 default_value);
  u64 GetUInt64(const std::string& key);
  const std::string& Get(const std::string& key, const std::string& default_value);
  const std::string& Get(const std::string& key);
  void Delete(const std::string& key);
  void Clear();

 private:
  std::string ini_file_;
  bool auto_save_;
  std::map<std::string, std::string> map_;
};

#endif  // __COMMON_INI_H
