
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/ClusterAsyncClient.hxx>
#include <vnx/Module.h>
#include <vnx/ModuleInterface_vnx_get_type_code.hxx>
#include <vnx/ModuleInterface_vnx_get_type_code_return.hxx>
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
#include <vnx/keyvalue/Storage_get_value_locked.hxx>
#include <vnx/keyvalue/Storage_get_value_locked_return.hxx>
#include <vnx/keyvalue/Storage_get_value_return.hxx>
#include <vnx/keyvalue/Storage_get_values.hxx>
#include <vnx/keyvalue/Storage_get_values_return.hxx>
#include <vnx/keyvalue/Storage_store_value.hxx>
#include <vnx/keyvalue/Storage_store_value_return.hxx>
#include <vnx/keyvalue/Storage_store_values.hxx>
#include <vnx/keyvalue/Storage_store_values_return.hxx>
#include <vnx/keyvalue/Storage_sync_all.hxx>
#include <vnx/keyvalue/Storage_sync_all_keys.hxx>
#include <vnx/keyvalue/Storage_sync_all_keys_return.hxx>
#include <vnx/keyvalue/Storage_sync_all_return.hxx>
#include <vnx/keyvalue/Storage_sync_from.hxx>
#include <vnx/keyvalue/Storage_sync_from_return.hxx>
#include <vnx/keyvalue/Storage_sync_range.hxx>
#include <vnx/keyvalue/Storage_sync_range_return.hxx>
#include <vnx/keyvalue/Storage_unlock.hxx>
#include <vnx/keyvalue/Storage_unlock_return.hxx>

#include <vnx/vnx.h>


namespace vnx {
namespace keyvalue {

ClusterAsyncClient::ClusterAsyncClient(const std::string& service_name)
	:	AsyncClient::AsyncClient(vnx::Hash64(service_name))
{
}

ClusterAsyncClient::ClusterAsyncClient(vnx::Hash64 service_addr)
	:	AsyncClient::AsyncClient(service_addr)
{
}

uint64_t ClusterAsyncClient::vnx_get_type_code(const std::function<void(::vnx::TypeCode)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::ModuleInterface_vnx_get_type_code::create();
	const auto _request_id = vnx_request(_method);
	vnx_queue_vnx_get_type_code[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::get_value(const ::vnx::Variant& key, const std::function<void(std::shared_ptr<const ::vnx::keyvalue::Entry>)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_get_value::create();
	_method->key = key;
	const auto _request_id = vnx_request(_method);
	vnx_queue_get_value[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::get_value_locked(const ::vnx::Variant& key, const int32_t& timeout_ms, const std::function<void(std::shared_ptr<const ::vnx::keyvalue::Entry>)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_get_value_locked::create();
	_method->key = key;
	_method->timeout_ms = timeout_ms;
	const auto _request_id = vnx_request(_method);
	vnx_queue_get_value_locked[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::get_values(const std::vector<::vnx::Variant>& keys, const std::function<void(std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>>)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_get_values::create();
	_method->keys = keys;
	const auto _request_id = vnx_request(_method);
	vnx_queue_get_values[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::get_key(const uint64_t& version, const std::function<void(::vnx::Variant)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_get_key::create();
	_method->version = version;
	const auto _request_id = vnx_request(_method);
	vnx_queue_get_key[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::get_keys(const std::vector<uint64_t>& versions, const std::function<void(std::vector<std::pair<uint64_t, ::vnx::Variant>>)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_get_keys::create();
	_method->versions = versions;
	const auto _request_id = vnx_request(_method);
	vnx_queue_get_keys[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::unlock(const ::vnx::Variant& key, const std::function<void()>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_unlock::create();
	_method->key = key;
	const auto _request_id = vnx_request(_method);
	vnx_queue_unlock[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::sync_from(const ::vnx::TopicPtr& topic, const uint64_t& version, const std::function<void(int64_t)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_sync_from::create();
	_method->topic = topic;
	_method->version = version;
	const auto _request_id = vnx_request(_method);
	vnx_queue_sync_from[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::sync_range(const ::vnx::TopicPtr& topic, const uint64_t& begin, const uint64_t& end, const std::function<void(int64_t)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_sync_range::create();
	_method->topic = topic;
	_method->begin = begin;
	_method->end = end;
	const auto _request_id = vnx_request(_method);
	vnx_queue_sync_range[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::sync_all(const ::vnx::TopicPtr& topic, const std::function<void(int64_t)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_sync_all::create();
	_method->topic = topic;
	const auto _request_id = vnx_request(_method);
	vnx_queue_sync_all[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::sync_all_keys(const ::vnx::TopicPtr& topic, const std::function<void(int64_t)>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_sync_all_keys::create();
	_method->topic = topic;
	const auto _request_id = vnx_request(_method);
	vnx_queue_sync_all_keys[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::cancel_sync_job(const int64_t& job_id, const std::function<void()>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_cancel_sync_job::create();
	_method->job_id = job_id;
	const auto _request_id = vnx_request(_method);
	vnx_queue_cancel_sync_job[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::store_value(const ::vnx::Variant& key, const std::shared_ptr<const ::vnx::Value>& value, const std::function<void()>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_store_value::create();
	_method->key = key;
	_method->value = value;
	const auto _request_id = vnx_request(_method);
	vnx_queue_store_value[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::store_values(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values, const std::function<void()>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_store_values::create();
	_method->values = values;
	const auto _request_id = vnx_request(_method);
	vnx_queue_store_values[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

uint64_t ClusterAsyncClient::delete_value(const ::vnx::Variant& key, const std::function<void()>& _callback, const std::function<void(const std::exception&)>& _error_callback) {
	auto _method = ::vnx::keyvalue::Storage_delete_value::create();
	_method->key = key;
	const auto _request_id = vnx_request(_method);
	vnx_queue_delete_value[_request_id] = std::make_pair(_callback, _error_callback);
	vnx_num_pending++;
	return _request_id;
}

std::vector<uint64_t> ClusterAsyncClient::vnx_get_pending_ids() const {
	std::vector<uint64_t> _list;
	for(const auto& entry : vnx_queue_vnx_get_type_code) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_get_value) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_get_value_locked) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_get_values) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_get_key) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_get_keys) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_unlock) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_sync_from) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_sync_range) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_sync_all) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_sync_all_keys) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_cancel_sync_job) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_store_value) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_store_values) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_delete_value) {
		_list.push_back(entry.first);
	}
	return _list;
}

void ClusterAsyncClient::vnx_purge_request(uint64_t _request_id, const std::exception& _ex) {
	{
		const auto _iter = vnx_queue_vnx_get_type_code.find(_request_id);
		if(_iter != vnx_queue_vnx_get_type_code.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_vnx_get_type_code.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_get_value.find(_request_id);
		if(_iter != vnx_queue_get_value.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_get_value.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_get_value_locked.find(_request_id);
		if(_iter != vnx_queue_get_value_locked.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_get_value_locked.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_get_values.find(_request_id);
		if(_iter != vnx_queue_get_values.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_get_values.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_get_key.find(_request_id);
		if(_iter != vnx_queue_get_key.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_get_key.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_get_keys.find(_request_id);
		if(_iter != vnx_queue_get_keys.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_get_keys.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_unlock.find(_request_id);
		if(_iter != vnx_queue_unlock.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_unlock.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_sync_from.find(_request_id);
		if(_iter != vnx_queue_sync_from.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_sync_from.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_sync_range.find(_request_id);
		if(_iter != vnx_queue_sync_range.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_sync_range.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_sync_all.find(_request_id);
		if(_iter != vnx_queue_sync_all.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_sync_all.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_sync_all_keys.find(_request_id);
		if(_iter != vnx_queue_sync_all_keys.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_sync_all_keys.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_cancel_sync_job.find(_request_id);
		if(_iter != vnx_queue_cancel_sync_job.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_cancel_sync_job.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_store_value.find(_request_id);
		if(_iter != vnx_queue_store_value.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_store_value.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_store_values.find(_request_id);
		if(_iter != vnx_queue_store_values.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_store_values.erase(_iter);
			vnx_num_pending--;
		}
	}
	{
		const auto _iter = vnx_queue_delete_value.find(_request_id);
		if(_iter != vnx_queue_delete_value.end()) {
			if(_iter->second.second) {
				_iter->second.second(_ex);
			}
			vnx_queue_delete_value.erase(_iter);
			vnx_num_pending--;
		}
	}
}

void ClusterAsyncClient::vnx_callback_switch(uint64_t _request_id, std::shared_ptr<const vnx::Value> _value) {
	const auto _type_hash = _value->get_type_hash();
	if(_type_hash == vnx::Hash64(0x9f4322ca83b0d1ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_type_code_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_vnx_get_type_code.find(_request_id);
		if(_iter != vnx_queue_vnx_get_type_code.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_vnx_get_type_code.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x4a92482e1381ab01ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_value_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_get_value.find(_request_id);
		if(_iter != vnx_queue_get_value.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_get_value.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x9cc2e6345ebe66aeull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_value_locked_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_get_value_locked.find(_request_id);
		if(_iter != vnx_queue_get_value_locked.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_get_value_locked.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0xe59fbd8a92b4aaf7ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_values_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_get_values.find(_request_id);
		if(_iter != vnx_queue_get_values.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_get_values.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x5e35e7e9fb0c828ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_key_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_get_key.find(_request_id);
		if(_iter != vnx_queue_get_key.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_get_key.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x5a68455b9ce7b40full)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_keys_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_get_keys.find(_request_id);
		if(_iter != vnx_queue_get_keys.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_get_keys.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x64b5d034680b0fb1ull)) {
		const auto _iter = vnx_queue_unlock.find(_request_id);
		if(_iter != vnx_queue_unlock.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_unlock.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0xc2e2a98c4fda747ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_from_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_sync_from.find(_request_id);
		if(_iter != vnx_queue_sync_from.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_sync_from.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0xa373940430d0fa20ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_range_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_sync_range.find(_request_id);
		if(_iter != vnx_queue_sync_range.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_sync_range.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x68518904fdf771c7ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_all_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_sync_all.find(_request_id);
		if(_iter != vnx_queue_sync_all.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_sync_all.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x69af743aa67ea377ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_all_keys_return>(_value);
		if(!_result) {
			throw std::logic_error("ClusterAsyncClient: !_result");
		}
		const auto _iter = vnx_queue_sync_all_keys.find(_request_id);
		if(_iter != vnx_queue_sync_all_keys.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_sync_all_keys.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x8e03e14a8636511dull)) {
		const auto _iter = vnx_queue_cancel_sync_job.find(_request_id);
		if(_iter != vnx_queue_cancel_sync_job.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_cancel_sync_job.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0x5f02038d66b3d8b5ull)) {
		const auto _iter = vnx_queue_store_value.find(_request_id);
		if(_iter != vnx_queue_store_value.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_store_value.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0xd19a5a98ea9c632eull)) {
		const auto _iter = vnx_queue_store_values.find(_request_id);
		if(_iter != vnx_queue_store_values.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_store_values.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else if(_type_hash == vnx::Hash64(0xd20199c7d67361d7ull)) {
		const auto _iter = vnx_queue_delete_value.find(_request_id);
		if(_iter != vnx_queue_delete_value.end()) {
			const auto _callback = std::move(_iter->second.first);
			vnx_queue_delete_value.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		} else {
			throw std::runtime_error("ClusterAsyncClient: invalid return received");
		}
	}
	else {
		throw std::runtime_error("ClusterAsyncClient: unknown return type");
	}
}


} // namespace vnx
} // namespace keyvalue
