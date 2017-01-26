/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <cstdlib>
#include <sstream>
#include <iostream>

#include <registry.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace pt = boost::property_tree;

namespace osquery {

void registryAndPluginInit() {
  for (const auto& it : AutoRegisterInterface::registries()) {
    it->run();
  }

  for (const auto& it : AutoRegisterInterface::plugins()) {
    it->run();
  }

  AutoRegisterSet().swap(AutoRegisterInterface::registries());
  AutoRegisterSet().swap(AutoRegisterInterface::plugins());
}


void RegistryInterface::remove(const std::string& item_name) {
  if (items_.count(item_name) > 0) {
    items_[item_name]->tearDown();
    items_.erase(item_name);
  }

  // Populate list of aliases to remove (those that mask item_name).
  std::vector<std::string> removed_aliases;
  for (const auto& alias : aliases_) {
    if (alias.second == item_name) {
      removed_aliases.push_back(alias.first);
    }
  }

  for (const auto& alias : removed_aliases) {
    aliases_.erase(alias);
  }
}

bool RegistryInterface::isInternal(const std::string& item_name) const {
  if (std::find(internal_.begin(), internal_.end(), item_name) ==
      internal_.end()) {
    return false;
  }
  return true;
}

Status RegistryInterface::setActive(const std::string& item_name) {
  // Default support multiple active plugins.

  Status status(0, "OK");
  return status;
}

RegistryRoutes RegistryInterface::getRoutes() const {
  RegistryRoutes route_table;
  for (const auto& item : items_) {
    if (isInternal(item.first)) {
      // This is an internal plugin, do not include the route.
      continue;
    }

    bool has_alias = false;
    for (const auto& alias : aliases_) {
      if (alias.second == item.first) {
        // If the item name is masked by at least one alias, it will not
        // broadcast under the internal item name.
        route_table[alias.first] = item.second->routeInfo();
        has_alias = true;
      }
    }

    if (!has_alias) {
      route_table[item.first] = item.second->routeInfo();
    }
  }
  return route_table;
}

Status RegistryInterface::call(const std::string& item_name,
                               const PluginRequest& request,
                               PluginResponse& response) {
  // Search local plugins (items) for the plugin.
  if (items_.count(item_name) > 0) {
    return items_.at(item_name)->call(request, response);
  }

  return Status(1, "Cannot call registry item: " + item_name);
}

Status RegistryInterface::addAlias(const std::string& item_name,
                                   const std::string& alias) {
  if (aliases_.count(alias) > 0) {
    return Status(1, "Duplicate alias: " + alias);
  }
  aliases_[alias] = item_name;
  return Status(0, "OK");
}

std::string RegistryInterface::getAlias(const std::string& alias) const {
  if (aliases_.count(alias) == 0) {
    return alias;
  }
  return aliases_.at(alias);
}

Status RegistryInterface::addPlugin(const std::string& plugin_name,
                                    const PluginRef& plugin_item,
                                    bool internal) {
  if (items_.count(plugin_name) > 0) {
    return Status(1, "Duplicate registry item exists: " + plugin_name);
  }

  plugin_item->setName(plugin_name);
  items_.emplace(std::make_pair(plugin_name, plugin_item));

  // The item can be listed as internal, meaning it does not broadcast.
  if (internal) {
    internal_.push_back(plugin_name);
  }

  // The item may belong to a module.
  if (RegistryFactory::get().usingModule()) {
    modules_[plugin_name] = RegistryFactory::get().getModule();
  }

  return Status(0, "OK");
}

void RegistryInterface::setUp() {
  // If this registry does not auto-setup do NOT setup the registry items.
  if (!auto_setup_) {
    return;
  }

  // If the registry is using a single 'active' plugin, setUp that plugin.
  // For config and logger, only setUp the selected plugin.
  if (active_.size() != 0 && exists(active_, true)) {
    items_.at(active_)->setUp();
    return;
  }

  // Try to set up each of the registry items.
  // If they fail, remove them from the registry.
  std::vector<std::string> failed;
  for (auto& item : items_) {
    if (!item.second->setUp().ok()) {
      failed.push_back(item.first);
    }
  }

  for (const auto& failed_item : failed) {
    remove(failed_item);
  }
}

void RegistryInterface::configure() {
  if (!active_.empty() && exists(active_, true)) {
    items_.at(active_)->configure();
  } else {
    for (auto& item : items_) {
      item.second->configure();
    }
  }
}

Status RegistryInterface::addExternal(const RouteUUID& uuid,
                                      const RegistryRoutes& routes) {
  // Add each route name (item name) to the tracking.
  for (const auto& route : routes) {
    // Keep the routes info assigned to the registry.
    routes_[route.first] = route.second;
    auto status = addExternalPlugin(route.first, route.second);
    external_[route.first] = uuid;
    if (!status.ok()) {
      return status;
    }
  }
  return Status(0, "OK");
}

/// Remove all the routes for a given uuid.
void RegistryInterface::removeExternal(const RouteUUID& uuid) {
  std::vector<std::string> removed_items;
  for (const auto& item : external_) {
    if (item.second == uuid) {
      removeExternalPlugin(item.first);
      removed_items.push_back(item.first);
    }
  }

  // Remove items belonging to the external uuid.
  for (const auto& item : removed_items) {
    external_.erase(item);
    routes_.erase(item);
  }
}

/// Facility method to check if a registry item exists.
bool RegistryInterface::exists(const std::string& item_name, bool local) const {
  bool has_local = (items_.count(item_name) > 0);
  bool has_external = (external_.count(item_name) > 0);
  bool has_route = (routes_.count(item_name) > 0);
  return (local) ? has_local : has_local || has_external || has_route;
}

/// Facility method to list the registry item identifiers.
std::vector<std::string> RegistryInterface::names() const {
  std::vector<std::string> names;
  for (const auto& item : items_) {
    names.push_back(item.first);
  }

  // Also add names of external plugins.
  for (const auto& item : external_) {
    names.push_back(item.first);
  }
  return names;
}

void RegistryFactory::add(const std::string& name, RegistryInterfaceRef reg) {
  if (exists(name)) {
    throw std::runtime_error("Cannot add duplicate registry: " + name);
  }
  registries_[name] = std::move(reg);
}

RegistryInterfaceRef RegistryFactory::registry(const std::string& t) const {
  if (!exists(t)) {
    throw std::runtime_error("Unknown registry requested: " + t);
  }
  return registries_.at(t);
}

std::map<std::string, RegistryInterfaceRef> RegistryFactory::all() const {
  return registries_;
}

std::map<std::string, PluginRef> RegistryFactory::plugins(
    const std::string& registry_name) const {
  return registry(registry_name)->plugins();
}

PluginRef RegistryFactory::plugin(const std::string& registry_name,
                                  const std::string& item_name) const {
  return registry(registry_name)->plugin(item_name);
}

RegistryBroadcast RegistryFactory::getBroadcast() {
  RegistryBroadcast broadcast;
  for (const auto& registry : registries_) {
    broadcast[registry.first] = registry.second->getRoutes();
  }
  return broadcast;
}

Status RegistryFactory::addBroadcast(const RouteUUID& uuid,
                                     const RegistryBroadcast& broadcast) {
  return Status(1, "Duplicate extension UUID:");
}

Status RegistryFactory::removeBroadcast(const RouteUUID& uuid) {
  WriteLock lock(mutex_);
  if (extensions_.count(uuid) == 0) {
    return Status(1, "Unknown extension UUID: " + std::to_string(uuid));
  }

  for (const auto& registry : registries_) {
    registry.second->removeExternal(uuid);
  }
  extensions_.erase(uuid);
  return Status(0, "OK");
}

/// Adds an alias for an internal registry item. This registry will only
/// broadcast the alias name.
Status RegistryFactory::addAlias(const std::string& registry_name,
                                 const std::string& item_name,
                                 const std::string& alias) {
  if (!exists(registry_name)) {
    return Status(1, "Unknown registry: " + registry_name);
  }
  return registries_.at(registry_name)->addAlias(item_name, alias);
}

/// Returns the item_name or the item alias if an alias exists.
std::string RegistryFactory::getAlias(const std::string& registry_name,
                                      const std::string& alias) const {
  if (!exists(registry_name)) {
    return alias;
  }
  return registries_.at(registry_name)->getAlias(alias);
}

Status RegistryFactory::call(const std::string& registry_name,
                             const std::string& item_name,
                             const PluginRequest& request,
                             PluginResponse& response) {
  // Forward factory call to the registry.
  try {
    if (item_name.find(",") != std::string::npos) {
      // Call is multiplexing plugins (usually for multiple loggers).
      // All multiplexed items are called without regard for statuses.
      return Status(0);
    }
    return get().registry(registry_name)->call(item_name, request, response);
  } catch (const std::exception& e) {
    return Status(1, e.what());
  } catch (...) {
    return Status(2, "Unknown exception");
  }
}

Status RegistryFactory::call(const std::string& registry_name,
                             const std::string& item_name,
                             const PluginRequest& request) {
  PluginResponse response;
  // Wrapper around a call expecting a response.
  return call(registry_name, item_name, request, response);
}

Status RegistryFactory::call(const std::string& registry_name,
                             const PluginRequest& request,
                             PluginResponse& response) {
  auto& plugin = get().registry(registry_name)->getActive();
  return call(registry_name, plugin, request, response);
}

Status RegistryFactory::call(const std::string& registry_name,
                             const PluginRequest& request) {
  PluginResponse response;
  return call(registry_name, request, response);
}

Status RegistryFactory::callTable(const std::string& table_name,
                                  QueryContext& context,
                                  PluginResponse& response) {
  return Status(0, "OK");
}

Status RegistryFactory::setActive(const std::string& registry_name,
                                  const std::string& item_name) {
  WriteLock lock(mutex_);
  return registry(registry_name)->setActive(item_name);
}

std::string RegistryFactory::getActive(const std::string& registry_name) const {
  return registry(registry_name)->getActive();
}

void RegistryFactory::setUp() {
  for (const auto& registry : get().all()) {
    registry.second->setUp();
  }
}

bool RegistryFactory::exists(const std::string& registry_name,
                             const std::string& item_name,
                             bool local) const {
  if (!exists(registry_name)) {
    return false;
  }

  // Check the registry.
  return registry(registry_name)->exists(item_name, local);
}

std::vector<std::string> RegistryFactory::names() const {
  std::vector<std::string> names;
  for (const auto& registry : all()) {
    names.push_back(registry.second->getName());
  }
  return names;
}

std::vector<std::string> RegistryFactory::names(
    const std::string& registry_name) const {
  if (registries_.at(registry_name) == 0) {
    std::vector<std::string> names;
    return names;
  }
  return registry(registry_name)->names();
}

std::vector<RouteUUID> RegistryFactory::routeUUIDs() const {
    return std::vector<RouteUUID>();
}

size_t RegistryFactory::count(const std::string& registry_name) const {
  if (!exists(registry_name)) {
    return 0;
  }
  return registry(registry_name)->count();
}

std::map<RouteUUID, ModuleInfo> RegistryFactory::getModules() const {
  return modules_;
}

RouteUUID RegistryFactory::getModule() {
  return module_uuid_;
}

bool RegistryFactory::usingModule() {
  // Check if the registry is allowing a module's registrations.
  return (!locked() && module_uuid_ != 0);
}

void RegistryFactory::shutdownModule() {
  locked(true);
  module_uuid_ = 0;
}

void RegistryFactory::initModule(const std::string& path) {
  // Begin a module initialization, lock until the module is determined
  // appropriate by requesting a call to `declareModule`.
  module_uuid_ = (RouteUUID)rand();
  modules_[getModule()].path = path;
  locked(true);
}

void RegistryFactory::declareModule(const std::string& name,
                                    const std::string& version,
                                    const std::string& min_sdk_version,
                                    const std::string& sdk_version) {
  // Check the min_sdk_version against the Registry's SDK version.
  auto& module = modules_[module_uuid_];
  module.name = name;
  module.version = version;
  module.sdk_version = sdk_version;
  locked(false);
}

RegistryModuleLoader::RegistryModuleLoader(const std::string& path)
    : handle_(nullptr), path_(path) {
  // Tell the registry that we are attempting to construct a module.
  // Locking the registry prevents the module's global initialization from
  // adding or creating registry items.
}

void RegistryModuleLoader::init() {
  if (handle_ == nullptr || RegistryFactory::get().locked()) {
    handle_ = nullptr;
    return;
  }
}

RegistryModuleLoader::~RegistryModuleLoader() {
  auto& rf = RegistryFactory::get();
  if (handle_ == nullptr) {
    // The module was not loaded or did not initalize.
    rf.modules_.erase(rf.getModule());
  }

  // We do not close the module, and thus are OK with losing a reference to the
  // module's handle. Attempting to close and clean up is very expensive for
  // very little value/features.
  if (!rf.locked()) {
    rf.shutdownModule();
  }
  // No need to clean this resource.
  handle_ = nullptr;
}

void Plugin::getResponse(const std::string& key,
                         const PluginResponse& response,
                         boost::property_tree::ptree& tree) {
  for (const auto& item : response) {
    boost::property_tree::ptree child;
    for (const auto& item_detail : item) {
      child.put(item_detail.first, item_detail.second);
    }
    tree.add_child(key, child);
  }
}

void Plugin::setResponse(const std::string& key,
                         const boost::property_tree::ptree& tree,
                         PluginResponse& response) {
  std::ostringstream output;
  try {
    boost::property_tree::write_json(output, tree, false);
  } catch (const pt::json_parser::json_parser_error& /* e */) {
    // The plugin response could not be serialized.
  }
  response.push_back({{key, output.str()}});
}
}

int main(int argc, const char *argv[]) {
    std::cout << "Starting it up...\n" << std::endl;
    osquery::registryAndPluginInit();
    std::cout << "Finishing...\n" << std::endl;
}

