/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <chrono>
#include <mutex>
#include <random>

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <config.h>
#include <registry.h>
#include <packs.h>

namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief Config plugin registry.
 *
 * This creates an osquery registry for "config" which may implement
 * ConfigPlugin. A ConfigPlugin's call API should make use of a genConfig
 * after reading JSON data in the plugin implementation.
 */
CREATE_REGISTRY(ConfigPlugin, "config");

/**
 * @brief ConfigParser plugin registry.
 *
 * This creates an osquery registry for "config_parser" which may implement
 * ConfigParserPlugin. A ConfigParserPlugin should not export any call actions
 * but rather have a simple property tree-accessor API through Config.
 */
CREATE_LAZY_REGISTRY(ConfigParserPlugin, "config_parser");


/**
 * @brief The backing store key name for the executing query.
 *
 * The config maintains schedule statistics and tracks failed executions.
 * On process or worker resume an initializer or config may check if the
 * resume was the result of a failure during an executing query.
 */
const std::string kExecutingQuery{"executing_query"};
const std::string kFailedQueries{"failed_queries"};

// The config may be accessed and updated asynchronously; use mutexes.
Mutex config_hash_mutex_;
Mutex config_valid_mutex_;

/// Several config methods require enumeration via predicate lambdas.
RecursiveMutex config_schedule_mutex_;
RecursiveMutex config_files_mutex_;
RecursiveMutex config_performance_mutex_;

using PackRef = std::shared_ptr<Pack>;

/**
 * The schedule is an iterable collection of Packs. When you iterate through
 * a schedule, you only get the packs that should be running on the host that
 * you're currently operating on.
 */
class Schedule : private boost::noncopyable {
 public:
  /// Under the hood, the schedule is just a list of the Pack objects
  using container = std::list<PackRef>;

  /**
   * @brief Create a schedule maintained by the configuration.
   *
   * This will check for previously executing queries. If any query was
   * executing it is considered in a 'dirty' state and should generate logs.
   * The schedule may also choose to blacklist this query.
   */
  Schedule();

  /**
   * @brief This class' iteration function
   *
   * Our step operation will be called on each element in packs_. It is
   * responsible for determining if that element should be returned as the
   * next iterator element or skipped.
   */
  struct Step {
    bool operator()(PackRef& pack) {
      return pack->shouldPackExecute();
    }
  };

  /// Add a pack to the schedule
  void add(PackRef&& pack) {
    remove(pack->getName(), pack->getSource());
    packs_.push_back(pack);
  }

  /// Remove a pack, by name.
  void remove(const std::string& pack) {
    remove(pack, "");
  }

  /// Remove a pack by name and source.
  void remove(const std::string& pack, const std::string& source) {
  }

  /// Remove all packs by source.
  void removeAll(const std::string& source) {
  }

  /// Boost gives us a nice template for maintaining the state of the iterator
  using iterator = boost::filter_iterator<Step, container::iterator>;

  iterator begin() {
    return iterator(packs_.begin(), packs_.end());
  }

  iterator end() {
    return iterator(packs_.end(), packs_.end());
  }

  PackRef& last() {
    return packs_.back();
  }

 private:
  /// Underlying storage for the packs
  container packs_;

  /**
   * @brief The schedule will check and record previously executing queries.
   *
   * If a query is found on initialization, the name will be recorded, it is
   * possible to skip previously failed queries.
   */
  std::string failed_query_;

  /**
   * @brief List of blacklisted queries.
   *
   * A list of queries that are blacklisted from executing due to prior
   * failures. If a query caused a worker to fail it will be recorded during
   * the next execution and saved to the blacklist.
   */
  std::map<std::string, size_t> blacklist_;

 private:
  friend class Config;
};

void restoreScheduleBlacklist(std::map<std::string, size_t>& blacklist) {
}

void saveScheduleBlacklist(const std::map<std::string, size_t>& blacklist) {
}

Schedule::Schedule() {
}

Config::Config()
    : schedule_(std::make_shared<Schedule>()),
      valid_(false),
      start_time_(std::time(nullptr)) {}

void Config::addPack(const std::string& name,
                     const std::string& source,
                     const pt::ptree& tree) {
}

void Config::removePack(const std::string& pack) {
}

void Config::addFile(const std::string& source,
                     const std::string& category,
                     const std::string& path) {
}

void Config::removeFiles(const std::string& source) {
}

void Config::scheduledQueries(
    std::function<void(const std::string& name, const ScheduledQuery& query)>
        predicate) {
}

void Config::packs(std::function<void(PackRef& pack)> predicate) {
}

Status Config::load() {
  return Status(1, "Missing config plugin ");
}

void stripConfigComments(std::string& json) {
}

Status Config::updateSource(const std::string& source,
                            const std::string& json) {
  return Status(0, "OK");
}

Status Config::genPack(const std::string& name,
                       const std::string& source,
                       const std::string& target) {
  return Status(0);
}

void Config::applyParsers(const std::string& source,
                          const pt::ptree& tree,
                          bool pack) {
}

Status Config::update(const std::map<std::string, std::string>& config) {
  return Status(0, "OK");
}

void Config::purge() {
}

void Config::reset() {
}

void ConfigParserPlugin::reset() {
  // Resets will clear all top-level keys from the parser's data store.
  for (auto& category : data_) {
    boost::property_tree::ptree().swap(category.second);
  }
}

void Config::recordQueryPerformance(const std::string& name,
                                    size_t delay,
                                    size_t size,
                                    const Row& r0,
                                    const Row& r1) {
}

void Config::recordQueryStart(const std::string& name) {
}

void Config::getPerformanceStats(
    const std::string& name,
    std::function<void(const QueryPerformance& query)> predicate) {
}

void Config::hashSource(const std::string& source, const std::string& content) {
}

Status Config::genHash(std::string& hash) {

  return Status(0, "OK");
}

const std::shared_ptr<ConfigParserPlugin> Config::getParser(
    const std::string& parser) {
  if (!RegistryFactory::get().exists("config_parser", parser, true)) {
    return nullptr;
  }

  auto plugin = RegistryFactory::get().plugin("config_parser", parser);
  // This is an error, need to check for existance (and not nullptr).
  return std::dynamic_pointer_cast<ConfigParserPlugin>(plugin);
}

void Config::files(
    std::function<void(const std::string& category,
                       const std::vector<std::string>& files)> predicate) {
}

Status ConfigPlugin::genPack(const std::string& name,
                             const std::string& value,
                             std::string& pack) {
  return Status(1, "Not implemented");
}

Status ConfigPlugin::call(const PluginRequest& request,
                          PluginResponse& response) {
  return Status(1, "Config plugin action unknown: ");
}

Status ConfigParserPlugin::setUp() {
  return Status(0, "OK");
}
}
