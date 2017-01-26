/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <csignal>
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>
#include <map>

#include <status.h>

// clang-format off
#ifndef STR
#define STR_OF(x) #x
#define STR(x) STR_OF(x)
#endif

#ifdef WIN32
#define STR_EX(...) __VA_ARGS__
#else
#define STR_EX(x) x
#endif
#define CONCAT(x, y) STR(STR_EX(x)STR_EX(y))

#ifndef FRIEND_TEST
#define FRIEND_TEST(test_case_name, test_name) \
  friend class test_case_name##_##test_name##_Test
#endif
// clang-format on

#ifdef WIN32
#define USED_SYMBOL
#define EXPORT_FUNCTION __declspec(dllexport)
#else
#define USED_SYMBOL __attribute__((used))
#define EXPORT_FUNCTION
#endif

/**
 * @brief Platform specific code isolation and define-based conditionals.
 *
 * The following preprocessor defines are expected to be available for all
 * osquery code. Please use them sparingly and prefer the run-time detection
 * methods first. See the %PlatformType class and %isPlatform method.
 *
 * OSQUERY_BUILD_PLATFORM: For Linux, this is the distro name, for OS X this is
 *   darwin, and on Windows it is windows. The set of potential values comes
 *   the ./tools/platform scripts and may be overridden.
 * OSQUERY_BUILD_DISTRO: For Linux, this is the version, for OS X this is the
 *   version (10.10, 10.11, 10.12), for Windows this is Win10.
 *
 * OSQUERY_BUILD_VERSION: available as kVersion, the version of osquery.
 * OSQUERY_SDK_VERSION: available as kSDKVersion, the most recent tag.
 * OSQUERY_PLATFORM: available as kSDKPlatform, a OSQUERY_BUILD_PLATFORM string.
 * OSQUERY_PLATFORM_MASK: a mask of platform features for runtime detection.
 *   See below for PlatformDetector-related methods.
 */

/**
 * @brief A series of platform-specific home folders.
 *
 * There are several platform-specific folders where osquery reads and writes
 * content. Most of the variance is due to legacy support.
 *
 * OSQUERY_HOME: Configuration, flagfile, extensions and module autoload.
 * OSQUERY_DB_HOME: Location of RocksDB persistent storage.
 * OSQUERY_LOG_HOME: Location of log data when the filesystem plugin is used.
 */
#if defined(__linux__)
#define OSQUERY_HOME "/etc/osquery"
#define OSQUERY_DB_HOME "/var/osquery"
#define OSQUERY_SOCKET OSQUERY_DB_HOME "/"
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#elif defined(WIN32)
#define OSQUERY_HOME "\\ProgramData\\osquery"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_SOCKET "\\\\.\\pipe\\"
#define OSQUERY_LOG_HOME "\\ProgramData\\osquery\\log\\"
#else
#define OSQUERY_HOME "/var/osquery"
#define OSQUERY_DB_HOME OSQUERY_HOME
#define OSQUERY_SOCKET OSQUERY_DB_HOME "/"
#define OSQUERY_LOG_HOME "/var/log/osquery/"
#endif

/// A configuration error is catastrophic and should exit the watcher.
#define EXIT_CATASTROPHIC 78

namespace osquery {

using ModuleHandle = void*;

/**
 * @brief A helpful tool type to report when logging, print help, or debugging.
 *
 * The Initializer class attempts to detect the ToolType using the tool name
 * and some compile time options.
 */
enum class ToolType {
  UNKNOWN = 0,
  SHELL,
  DAEMON,
  TEST,
  EXTENSION,
};

/**
 * @brief A helpful runtime-detection enumeration of platform configurations.
 *
 * CMake, or the build tooling, will generate a OSQUERY_PLATFORM_MASK and pass
 * it to the library compile only.
 */
enum class PlatformType {
  TYPE_POSIX = 0x01,
  TYPE_WINDOWS = 0x02,
  TYPE_BSD = 0x04,
  TYPE_LINUX = 0x08,
  TYPE_OSX = 0x10,
  TYPE_FREEBSD = 0x20,
};

inline PlatformType operator|(PlatformType a, PlatformType b) {
  return static_cast<PlatformType>(static_cast<int>(a) | static_cast<int>(b));
}

/// The version of osquery, includes the git revision if not tagged.
extern const std::string kVersion;

/// The SDK version removes any git revision hash (1.6.1-g0000 becomes 1.6.1).
extern const std::string kSDKVersion;

/**
 * @brief Compare osquery SDK/extenion/core version strings.
 *
 * SDK versions are in major.minor.patch-commit-hash form. We provide a helper
 * method for performing version comparisons to allow gating and compatibility
 * checks throughout the code.
 *
 * @param v version to check
 * @param sdk (optional) the SDK version to check against.
 * return true if the input version is at least the SDK version.
 */
bool versionAtLeast(const std::string& v, const std::string& sdk = kSDKVersion);

/// Identifies the build platform of either the core extension.
extern const std::string kSDKPlatform;

/// The osquery tool type for runtime decisions.
extern ToolType kToolType;

/// The build-defined set of platform types.
extern const PlatformType kPlatformType;

/// Helper method for platform type detection.
inline bool isPlatform(PlatformType a, const PlatformType& t = kPlatformType) {
  return (static_cast<int>(t) & static_cast<int>(a)) != 0;
}

/// Helper alias for defining mutexes.
using Mutex = std::shared_timed_mutex;

/// Helper alias for write locking a mutex.
using WriteLock = std::unique_lock<Mutex>;

/// Helper alias for read locking a mutex.
using ReadLock = std::shared_lock<Mutex>;

/// Helper alias for defining recursive mutexes.
using RecursiveMutex = std::recursive_mutex;

/// Helper alias for write locking a recursive mutex.
using RecursiveLock = std::lock_guard<std::recursive_mutex>;
using RowData = std::string;

/**
 * @brief A single row from a database query
 *
 * Row is a simple map where individual column names are keys, which map to
 * the Row's respective value
 */
using Row = std::map<std::string, RowData>;
using QueryData = std::vector<Row>;

/**
 * @brief A vector of column names associated with a query
 *
 * ColumnNames is a vector of the column names, in order, returned by a query.
 */
using ColumnNames = std::vector<std::string>;
struct ScheduledQuery {
  /// The SQL query.
  std::string query;

  /// How often the query should be executed, in second.
  size_t interval;

  /// A temporary splayed internal.
  size_t splayed_interval;

  /// Set of query options.
  std::map<std::string, bool> options;

  ScheduledQuery() : interval(0), splayed_interval(0) {}

  /// equals operator
  bool operator==(const ScheduledQuery& comp) const {
    return (comp.query == query) && (comp.interval == interval);
  }

  /// not equals operator
  bool operator!=(const ScheduledQuery& comp) const {
    return !(*this == comp);
  }
};
struct QueryPerformance {
  /// Number of executions.
  size_t executions;

  /// Last UNIX time in seconds the query was executed successfully.
  size_t last_executed;

  /// Total wall time taken
  unsigned long long int wall_time;

  /// Total user time (cycles)
  unsigned long long int user_time;

  /// Total system time (cycles)
  unsigned long long int system_time;

  /// Average memory differentials. This should be near 0.
  unsigned long long int average_memory;

  /// Total characters, bytes, generated by query.
  unsigned long long int output_size;

  QueryPerformance()
      : executions(0),
        last_executed(0),
        wall_time(0),
        user_time(0),
        system_time(0),
        average_memory(0),
        output_size(0) {}
};
}
