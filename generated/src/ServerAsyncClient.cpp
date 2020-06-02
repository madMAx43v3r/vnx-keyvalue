
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/ServerAsyncClient.hxx>
#include <vnx/Input.h>
#include <vnx/Output.h>
#include <vnx/Module.h>
#include <vnx/TopicPtr.h>
#include <vnx/Value.h>
#include <vnx/Variant.h>
#include <vnx/keyvalue/Server__sync_finished.hxx>
#include <vnx/keyvalue/Server__sync_finished_return.hxx>
#include <vnx/keyvalue/Server_delete_value.hxx>
#include <vnx/keyvalue/Server_delete_value_return.hxx>
#include <vnx/keyvalue/Server_get_value.hxx>
#include <vnx/keyvalue/Server_get_value_return.hxx>
#include <vnx/keyvalue/Server_get_values.hxx>
#include <vnx/keyvalue/Server_get_values_return.hxx>
#include <vnx/keyvalue/Server_store_value.hxx>
#include <vnx/keyvalue/Server_store_value_return.hxx>
#include <vnx/keyvalue/Server_store_values.hxx>
#include <vnx/keyvalue/Server_store_values_return.hxx>
#include <vnx/keyvalue/Server_sync_all.hxx>
#include <vnx/keyvalue/Server_sync_all_keys.hxx>
#include <vnx/keyvalue/Server_sync_all_keys_return.hxx>
#include <vnx/keyvalue/Server_sync_all_return.hxx>
#include <vnx/keyvalue/Server_sync_from.hxx>
#include <vnx/keyvalue/Server_sync_from_return.hxx>
#include <vnx/keyvalue/Server_sync_range.hxx>
#include <vnx/keyvalue/Server_sync_range_return.hxx>



namespace vnx {
namespace keyvalue {

ServerAsyncClient::ServerAsyncClient(const std::string& service_name)
	:	AsyncClient::AsyncClient(vnx::Hash64(service_name))
{
}

ServerAsyncClient::ServerAsyncClient(vnx::Hash64 service_addr)
	:	AsyncClient::AsyncClient(service_addr)
{
}

uint64_t ServerAsyncClient::_sync_finished(const int64_t& job_id, const std::function<void()>& _callback) {
	auto _method = ::vnx::keyvalue::Server__sync_finished::create();
	_method->job_id = job_id;
	const auto _request_id = vnx_request(_method);
	vnx_queue__sync_finished[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::delete_value(const ::vnx::Variant& key, const std::function<void()>& _callback) {
	auto _method = ::vnx::keyvalue::Server_delete_value::create();
	_method->key = key;
	const auto _request_id = vnx_request(_method);
	vnx_queue_delete_value[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::get_value(const ::vnx::Variant& key, const std::function<void(std::shared_ptr<const ::vnx::Value>)>& _callback) {
	auto _method = ::vnx::keyvalue::Server_get_value::create();
	_method->key = key;
	const auto _request_id = vnx_request(_method);
	vnx_queue_get_value[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::get_values(const std::vector<::vnx::Variant>& keys, const std::function<void(std::vector<std::shared_ptr<const ::vnx::Value>>)>& _callback) {
	auto _method = ::vnx::keyvalue::Server_get_values::create();
	_method->keys = keys;
	const auto _request_id = vnx_request(_method);
	vnx_queue_get_values[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::store_value(const ::vnx::Variant& key, const std::shared_ptr<const ::vnx::Value>& value, const std::function<void()>& _callback) {
	auto _method = ::vnx::keyvalue::Server_store_value::create();
	_method->key = key;
	_method->value = value;
	const auto _request_id = vnx_request(_method);
	vnx_queue_store_value[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::store_values(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values, const std::function<void()>& _callback) {
	auto _method = ::vnx::keyvalue::Server_store_values::create();
	_method->values = values;
	const auto _request_id = vnx_request(_method);
	vnx_queue_store_values[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::sync_all(const ::vnx::TopicPtr& topic, const std::function<void(int64_t)>& _callback) {
	auto _method = ::vnx::keyvalue::Server_sync_all::create();
	_method->topic = topic;
	const auto _request_id = vnx_request(_method);
	vnx_queue_sync_all[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::sync_all_keys(const ::vnx::TopicPtr& topic, const std::function<void(int64_t)>& _callback) {
	auto _method = ::vnx::keyvalue::Server_sync_all_keys::create();
	_method->topic = topic;
	const auto _request_id = vnx_request(_method);
	vnx_queue_sync_all_keys[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::sync_from(const ::vnx::TopicPtr& topic, const uint64_t& version, const std::function<void(int64_t)>& _callback) {
	auto _method = ::vnx::keyvalue::Server_sync_from::create();
	_method->topic = topic;
	_method->version = version;
	const auto _request_id = vnx_request(_method);
	vnx_queue_sync_from[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

uint64_t ServerAsyncClient::sync_range(const ::vnx::TopicPtr& topic, const uint64_t& begin, const uint64_t& end, const std::function<void(int64_t)>& _callback) {
	auto _method = ::vnx::keyvalue::Server_sync_range::create();
	_method->topic = topic;
	_method->begin = begin;
	_method->end = end;
	const auto _request_id = vnx_request(_method);
	vnx_queue_sync_range[_request_id] = _callback;
	vnx_num_pending++;
	return _request_id;
}

std::vector<uint64_t> ServerAsyncClient::vnx_get_pending_ids() const {
	std::vector<uint64_t> _list;
	for(const auto& entry : vnx_queue__sync_finished) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_delete_value) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_get_value) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_get_values) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_store_value) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_store_values) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_sync_all) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_sync_all_keys) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_sync_from) {
		_list.push_back(entry.first);
	}
	for(const auto& entry : vnx_queue_sync_range) {
		_list.push_back(entry.first);
	}
	return _list;
}

void ServerAsyncClient::vnx_purge_request(uint64_t _request_id) {
	vnx_num_pending -= vnx_queue__sync_finished.erase(_request_id);
	vnx_num_pending -= vnx_queue_delete_value.erase(_request_id);
	vnx_num_pending -= vnx_queue_get_value.erase(_request_id);
	vnx_num_pending -= vnx_queue_get_values.erase(_request_id);
	vnx_num_pending -= vnx_queue_store_value.erase(_request_id);
	vnx_num_pending -= vnx_queue_store_values.erase(_request_id);
	vnx_num_pending -= vnx_queue_sync_all.erase(_request_id);
	vnx_num_pending -= vnx_queue_sync_all_keys.erase(_request_id);
	vnx_num_pending -= vnx_queue_sync_from.erase(_request_id);
	vnx_num_pending -= vnx_queue_sync_range.erase(_request_id);
}

void ServerAsyncClient::vnx_callback_switch(uint64_t _request_id, std::shared_ptr<const vnx::Value> _value) {
	const auto _type_hash = _value->get_type_hash();
	if(_type_hash == vnx::Hash64(0x4039b73e1e85b062ull)) {
		const auto _iter = vnx_queue__sync_finished.find(_request_id);
		if(_iter != vnx_queue__sync_finished.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue__sync_finished.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0x6b26b84842654d71ull)) {
		const auto _iter = vnx_queue_delete_value.find(_request_id);
		if(_iter != vnx_queue_delete_value.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_delete_value.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0x2eda7f8d6761272dull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Server_get_value_return>(_value);
		if(!_result) {
			throw std::logic_error("AsyncClient: !_result");
		}
		const auto _iter = vnx_queue_get_value.find(_request_id);
		if(_iter != vnx_queue_get_value.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_get_value.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0x92bdf340933764bcull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Server_get_values_return>(_value);
		if(!_result) {
			throw std::logic_error("AsyncClient: !_result");
		}
		const auto _iter = vnx_queue_get_values.find(_request_id);
		if(_iter != vnx_queue_get_values.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_get_values.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0x8bc8f7e913889f88ull)) {
		const auto _iter = vnx_queue_store_value.find(_request_id);
		if(_iter != vnx_queue_store_value.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_store_value.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0x68bd7b177e8a4f88ull)) {
		const auto _iter = vnx_queue_store_values.find(_request_id);
		if(_iter != vnx_queue_store_values.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_store_values.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback();
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0x964de09bdefcfc87ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Server_sync_all_return>(_value);
		if(!_result) {
			throw std::logic_error("AsyncClient: !_result");
		}
		const auto _iter = vnx_queue_sync_all.find(_request_id);
		if(_iter != vnx_queue_sync_all.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_sync_all.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0xd419b32d0bc488e3ull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Server_sync_all_keys_return>(_value);
		if(!_result) {
			throw std::logic_error("AsyncClient: !_result");
		}
		const auto _iter = vnx_queue_sync_all_keys.find(_request_id);
		if(_iter != vnx_queue_sync_all_keys.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_sync_all_keys.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0x68661d3bb01d2b6bull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Server_sync_from_return>(_value);
		if(!_result) {
			throw std::logic_error("AsyncClient: !_result");
		}
		const auto _iter = vnx_queue_sync_from.find(_request_id);
		if(_iter != vnx_queue_sync_from.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_sync_from.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		}
	}
	else if(_type_hash == vnx::Hash64(0xd451dace3153346bull)) {
		auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Server_sync_range_return>(_value);
		if(!_result) {
			throw std::logic_error("AsyncClient: !_result");
		}
		const auto _iter = vnx_queue_sync_range.find(_request_id);
		if(_iter != vnx_queue_sync_range.end()) {
			const auto _callback = std::move(_iter->second);
			vnx_queue_sync_range.erase(_iter);
			vnx_num_pending--;
			if(_callback) {
				_callback(_result->_ret_0);
			}
		}
	}
	else {
		throw std::runtime_error("unknown return value");
	}
}


} // namespace vnx
} // namespace keyvalue
