#ifndef __AGENT_MODEL_POLICY_H__
#define __AGENT_MODEL_POLICY_H__

#include "../common/config.pb.h"
#include "../common/policy.pb.h"

class Policy {
 public:
  // Create by label
  static Policy* Create(const config::Config* config, const std::string& label);
  // Create by type(only first matching policy will be used. This is for legacy usage).
  static Policy* Create(const config::Config* config, const policy::PolicyName type);

  const std::string& label() const { return label_; }
  const policy::PolicyIndex& index() const { return *index_; }
  const policy::PolicyData* data() const { return data_; }

 private:
  explicit Policy(const config::Config* config) : config_(config) {}

  const config::Config* config_;
  std::string label_;
  // For real case. index can't be nullptr
  const policy::PolicyIndex* index_ = nullptr;
  // Some policy doesn't have data.
  const policy::PolicyData* data_ = nullptr;
};

#endif // __AGENT_MODEL_POLICY_H__
