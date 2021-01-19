
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/ClusterClient.hxx>
#include <vnx/Module.h>
#include <vnx/ModuleInterface_vnx_get_config.hxx>
#include <vnx/ModuleInterface_vnx_get_config_return.hxx>
#include <vnx/ModuleInterface_vnx_get_config_object.hxx>
#include <vnx/ModuleInterface_vnx_get_config_object_return.hxx>
#include <vnx/ModuleInterface_vnx_get_module_info.hxx>
#include <vnx/ModuleInterface_vnx_get_module_info_return.hxx>
#include <vnx/ModuleInterface_vnx_get_type_code.hxx>
#include <vnx/ModuleInterface_vnx_get_type_code_return.hxx>
#include <vnx/ModuleInterface_vnx_restart.hxx>
#include <vnx/ModuleInterface_vnx_restart_return.hxx>
#include <vnx/ModuleInterface_vnx_self_test.hxx>
#include <vnx/ModuleInterface_vnx_self_test_return.hxx>
#include <vnx/ModuleInterface_vnx_set_config.hxx>
#include <vnx/ModuleInterface_vnx_set_config_return.hxx>
#include <vnx/ModuleInterface_vnx_set_config_object.hxx>
#include <vnx/ModuleInterface_vnx_set_config_object_return.hxx>
#include <vnx/ModuleInterface_vnx_stop.hxx>
#include <vnx/ModuleInterface_vnx_stop_return.hxx>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Entry.hxx>
#include <vnx/keyvalue/Storage_cancel_sync_job.hxx>
#include <vnx/keyvalue/Storage_cancel_sync_job_return.hxx>
#include <vnx/keyvalue/Storage_delete_value.hxx>
#include <vnx/keyvalue/Storage_delete_value_return.hxx>
#include <vnx/keyvalue/Storage_get_key.hxx>
#include <vnx/keyvalue/Storage_get_key_return.hxx>
#include <vnx/keyvalue/Storage_get_keys.hxx>
#include <vnx/keyvalue/Storage_get_keys_return.hxx>
#include <vnx/keyvalue/Storage_get_value.hxx>
#include <vnx/keyvalue/Storage_get_value_return.hxx>
#include <vnx/keyvalue/Storage_get_value_locked.hxx>
#include <vnx/keyvalue/Storage_get_value_locked_return.hxx>
#include <vnx/keyvalue/Storage_get_values.hxx>
#include <vnx/keyvalue/Storage_get_values_return.hxx>
#include <vnx/keyvalue/Storage_store_value.hxx>
#include <vnx/keyvalue/Storage_store_value_return.hxx>
#include <vnx/keyvalue/Storage_store_value_delay.hxx>
#include <vnx/keyvalue/Storage_store_value_delay_return.hxx>
#include <vnx/keyvalue/Storage_store_values.hxx>
#include <vnx/keyvalue/Storage_store_values_return.hxx>
#include <vnx/keyvalue/Storage_store_values_delay.hxx>
#include <vnx/keyvalue/Storage_store_values_delay_return.hxx>
#include <vnx/keyvalue/Storage_sync_all.hxx>
#include <vnx/keyvalue/Storage_sync_all_return.hxx>
#include <vnx/keyvalue/Storage_sync_all_keys.hxx>
#include <vnx/keyvalue/Storage_sync_all_keys_return.hxx>
#include <vnx/keyvalue/Storage_sync_from.hxx>
#include <vnx/keyvalue/Storage_sync_from_return.hxx>
#include <vnx/keyvalue/Storage_sync_range.hxx>
#include <vnx/keyvalue/Storage_sync_range_return.hxx>
#include <vnx/keyvalue/Storage_unlock.hxx>
#include <vnx/keyvalue/Storage_unlock_return.hxx>

#include <vnx/Generic.hxx>
#include <vnx/vnx.h>


namespace vnx {
namespace keyvalue {

ClusterClient::ClusterClient(const std::string& service_name)
	:	Client::Client(vnx::Hash64(service_name))
{
}

ClusterClient::ClusterClient(vnx::Hash64 service_addr)
	:	Client::Client(service_addr)
{
}

::vnx::Object ClusterClient::vnx_get_config_object() {
	auto _method = ::vnx::ModuleInterface_vnx_get_config_object::create();
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_config_object_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<::vnx::Object>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

::vnx::Variant ClusterClient::vnx_get_config(const std::string& name) {
	auto _method = ::vnx::ModuleInterface_vnx_get_config::create();
	_method->name = name;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_config_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<::vnx::Variant>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

void ClusterClient::vnx_set_config_object(const ::vnx::Object& config) {
	auto _method = ::vnx::ModuleInterface_vnx_set_config_object::create();
	_method->config = config;
	vnx_request(_method, false);
}

void ClusterClient::vnx_set_config_object_async(const ::vnx::Object& config) {
	auto _method = ::vnx::ModuleInterface_vnx_set_config_object::create();
	_method->config = config;
	vnx_request(_method, true);
}

void ClusterClient::vnx_set_config(const std::string& name, const ::vnx::Variant& value) {
	auto _method = ::vnx::ModuleInterface_vnx_set_config::create();
	_method->name = name;
	_method->value = value;
	vnx_request(_method, false);
}

void ClusterClient::vnx_set_config_async(const std::string& name, const ::vnx::Variant& value) {
	auto _method = ::vnx::ModuleInterface_vnx_set_config::create();
	_method->name = name;
	_method->value = value;
	vnx_request(_method, true);
}

::vnx::TypeCode ClusterClient::vnx_get_type_code() {
	auto _method = ::vnx::ModuleInterface_vnx_get_type_code::create();
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_type_code_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<::vnx::TypeCode>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

std::shared_ptr<const ::vnx::ModuleInfo> ClusterClient::vnx_get_module_info() {
	auto _method = ::vnx::ModuleInterface_vnx_get_module_info::create();
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_module_info_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<std::shared_ptr<const ::vnx::ModuleInfo>>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

void ClusterClient::vnx_restart() {
	auto _method = ::vnx::ModuleInterface_vnx_restart::create();
	vnx_request(_method, false);
}

void ClusterClient::vnx_restart_async() {
	auto _method = ::vnx::ModuleInterface_vnx_restart::create();
	vnx_request(_method, true);
}

void ClusterClient::vnx_stop() {
	auto _method = ::vnx::ModuleInterface_vnx_stop::create();
	vnx_request(_method, false);
}

void ClusterClient::vnx_stop_async() {
	auto _method = ::vnx::ModuleInterface_vnx_stop::create();
	vnx_request(_method, true);
}

vnx::bool_t ClusterClient::vnx_self_test() {
	auto _method = ::vnx::ModuleInterface_vnx_self_test::create();
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_self_test_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<vnx::bool_t>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

std::shared_ptr<const ::vnx::keyvalue::Entry> ClusterClient::get_value(const ::vnx::Variant& key) {
	auto _method = ::vnx::keyvalue::Storage_get_value::create();
	_method->key = key;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_value_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<std::shared_ptr<const ::vnx::keyvalue::Entry>>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

std::shared_ptr<const ::vnx::keyvalue::Entry> ClusterClient::get_value_locked(const ::vnx::Variant& key, const int32_t& timeout_ms) {
	auto _method = ::vnx::keyvalue::Storage_get_value_locked::create();
	_method->key = key;
	_method->timeout_ms = timeout_ms;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_value_locked_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<std::shared_ptr<const ::vnx::keyvalue::Entry>>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>> ClusterClient::get_values(const std::vector<::vnx::Variant>& keys) {
	auto _method = ::vnx::keyvalue::Storage_get_values::create();
	_method->keys = keys;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_values_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>>>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

::vnx::Variant ClusterClient::get_key(const uint64_t& version) {
	auto _method = ::vnx::keyvalue::Storage_get_key::create();
	_method->version = version;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_key_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<::vnx::Variant>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

std::vector<std::pair<uint64_t, ::vnx::Variant>> ClusterClient::get_keys(const std::vector<uint64_t>& versions) {
	auto _method = ::vnx::keyvalue::Storage_get_keys::create();
	_method->versions = versions;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_keys_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<std::vector<std::pair<uint64_t, ::vnx::Variant>>>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

void ClusterClient::unlock(const ::vnx::Variant& key) {
	auto _method = ::vnx::keyvalue::Storage_unlock::create();
	_method->key = key;
	vnx_request(_method, false);
}

void ClusterClient::unlock_async(const ::vnx::Variant& key) {
	auto _method = ::vnx::keyvalue::Storage_unlock::create();
	_method->key = key;
	vnx_request(_method, true);
}

int64_t ClusterClient::sync_from(const ::vnx::TopicPtr& topic, const uint64_t& version) {
	auto _method = ::vnx::keyvalue::Storage_sync_from::create();
	_method->topic = topic;
	_method->version = version;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_from_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<int64_t>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

int64_t ClusterClient::sync_range(const ::vnx::TopicPtr& topic, const uint64_t& begin, const uint64_t& end) {
	auto _method = ::vnx::keyvalue::Storage_sync_range::create();
	_method->topic = topic;
	_method->begin = begin;
	_method->end = end;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_range_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<int64_t>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

int64_t ClusterClient::sync_all(const ::vnx::TopicPtr& topic) {
	auto _method = ::vnx::keyvalue::Storage_sync_all::create();
	_method->topic = topic;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_all_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<int64_t>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

int64_t ClusterClient::sync_all_keys(const ::vnx::TopicPtr& topic) {
	auto _method = ::vnx::keyvalue::Storage_sync_all_keys::create();
	_method->topic = topic;
	auto _return_value = vnx_request(_method, false);
	if(auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_all_keys_return>(_return_value)) {
		return _result->_ret_0;
	} else if(_return_value && !_return_value->is_void()) {
		return _return_value->get_field_by_index(0).to<int64_t>();
	} else {
		throw std::logic_error("ClusterClient: invalid return value");
	}
}

void ClusterClient::cancel_sync_job(const int64_t& job_id) {
	auto _method = ::vnx::keyvalue::Storage_cancel_sync_job::create();
	_method->job_id = job_id;
	vnx_request(_method, false);
}

void ClusterClient::cancel_sync_job_async(const int64_t& job_id) {
	auto _method = ::vnx::keyvalue::Storage_cancel_sync_job::create();
	_method->job_id = job_id;
	vnx_request(_method, true);
}

void ClusterClient::store_value(const ::vnx::Variant& key, std::shared_ptr<const ::vnx::Value> value) {
	auto _method = ::vnx::keyvalue::Storage_store_value::create();
	_method->key = key;
	_method->value = value;
	vnx_request(_method, false);
}

void ClusterClient::store_value_async(const ::vnx::Variant& key, std::shared_ptr<const ::vnx::Value> value) {
	auto _method = ::vnx::keyvalue::Storage_store_value::create();
	_method->key = key;
	_method->value = value;
	vnx_request(_method, true);
}

void ClusterClient::store_values(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values) {
	auto _method = ::vnx::keyvalue::Storage_store_values::create();
	_method->values = values;
	vnx_request(_method, false);
}

void ClusterClient::store_values_async(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values) {
	auto _method = ::vnx::keyvalue::Storage_store_values::create();
	_method->values = values;
	vnx_request(_method, true);
}

void ClusterClient::store_value_delay(const ::vnx::Variant& key, std::shared_ptr<const ::vnx::Value> value, const int32_t& delay_ms) {
	auto _method = ::vnx::keyvalue::Storage_store_value_delay::create();
	_method->key = key;
	_method->value = value;
	_method->delay_ms = delay_ms;
	vnx_request(_method, false);
}

void ClusterClient::store_value_delay_async(const ::vnx::Variant& key, std::shared_ptr<const ::vnx::Value> value, const int32_t& delay_ms) {
	auto _method = ::vnx::keyvalue::Storage_store_value_delay::create();
	_method->key = key;
	_method->value = value;
	_method->delay_ms = delay_ms;
	vnx_request(_method, true);
}

void ClusterClient::store_values_delay(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values, const int32_t& delay_ms) {
	auto _method = ::vnx::keyvalue::Storage_store_values_delay::create();
	_method->values = values;
	_method->delay_ms = delay_ms;
	vnx_request(_method, false);
}

void ClusterClient::store_values_delay_async(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values, const int32_t& delay_ms) {
	auto _method = ::vnx::keyvalue::Storage_store_values_delay::create();
	_method->values = values;
	_method->delay_ms = delay_ms;
	vnx_request(_method, true);
}

void ClusterClient::delete_value(const ::vnx::Variant& key) {
	auto _method = ::vnx::keyvalue::Storage_delete_value::create();
	_method->key = key;
	vnx_request(_method, false);
}

void ClusterClient::delete_value_async(const ::vnx::Variant& key) {
	auto _method = ::vnx::keyvalue::Storage_delete_value::create();
	_method->key = key;
	vnx_request(_method, true);
}


} // namespace vnx
} // namespace keyvalue
