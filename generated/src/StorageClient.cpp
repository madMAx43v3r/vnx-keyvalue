
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/StorageClient.hxx>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Entry.hxx>
#include <vnx/keyvalue/Storage_cancel_sync_job.hxx>
#include <vnx/keyvalue/Storage_cancel_sync_job_return.hxx>
#include <vnx/keyvalue/Storage_delete_value.hxx>
#include <vnx/keyvalue/Storage_delete_value_return.hxx>
#include <vnx/keyvalue/Storage_get_value.hxx>
#include <vnx/keyvalue/Storage_get_value_locked.hxx>
#include <vnx/keyvalue/Storage_get_value_locked_return.hxx>
#include <vnx/keyvalue/Storage_get_value_return.hxx>
#include <vnx/keyvalue/Storage_get_values.hxx>
#include <vnx/keyvalue/Storage_get_values_return.hxx>
#include <vnx/keyvalue/Storage_get_version_key.hxx>
#include <vnx/keyvalue/Storage_get_version_key_return.hxx>
#include <vnx/keyvalue/Storage_get_version_keys.hxx>
#include <vnx/keyvalue/Storage_get_version_keys_return.hxx>
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

StorageClient::StorageClient(const std::string& service_name)
	:	Client::Client(vnx::Hash64(service_name))
{
}

StorageClient::StorageClient(vnx::Hash64 service_addr)
	:	Client::Client(service_addr)
{
}

std::shared_ptr<const ::vnx::keyvalue::Entry> StorageClient::get_value(const ::vnx::Variant& key) {
	auto _method = ::vnx::keyvalue::Storage_get_value::create();
	_method->key = key;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_value_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

std::shared_ptr<const ::vnx::keyvalue::Entry> StorageClient::get_value_locked(const ::vnx::Variant& key, const int32_t& timeout_ms) {
	auto _method = ::vnx::keyvalue::Storage_get_value_locked::create();
	_method->key = key;
	_method->timeout_ms = timeout_ms;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_value_locked_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>> StorageClient::get_values(const std::vector<::vnx::Variant>& keys) {
	auto _method = ::vnx::keyvalue::Storage_get_values::create();
	_method->keys = keys;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_values_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

::vnx::Variant StorageClient::get_version_key(const uint64_t& version) {
	auto _method = ::vnx::keyvalue::Storage_get_version_key::create();
	_method->version = version;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_version_key_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

std::vector<std::pair<uint64_t, ::vnx::Variant>> StorageClient::get_version_keys(const std::vector<uint64_t>& versions) {
	auto _method = ::vnx::keyvalue::Storage_get_version_keys::create();
	_method->versions = versions;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_version_keys_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

void StorageClient::unlock(const ::vnx::Variant& key) {
	auto _method = ::vnx::keyvalue::Storage_unlock::create();
	_method->key = key;
	auto _return_value = vnx_request(_method);
}

void StorageClient::unlock_async(const ::vnx::Variant& key) {
	vnx_is_async = true;
	unlock(key);
}

int64_t StorageClient::sync_from(const ::vnx::TopicPtr& topic, const uint64_t& version) {
	auto _method = ::vnx::keyvalue::Storage_sync_from::create();
	_method->topic = topic;
	_method->version = version;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_from_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

int64_t StorageClient::sync_range(const ::vnx::TopicPtr& topic, const uint64_t& begin, const uint64_t& end) {
	auto _method = ::vnx::keyvalue::Storage_sync_range::create();
	_method->topic = topic;
	_method->begin = begin;
	_method->end = end;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_range_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

int64_t StorageClient::sync_all(const ::vnx::TopicPtr& topic) {
	auto _method = ::vnx::keyvalue::Storage_sync_all::create();
	_method->topic = topic;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_all_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

int64_t StorageClient::sync_all_keys(const ::vnx::TopicPtr& topic) {
	auto _method = ::vnx::keyvalue::Storage_sync_all_keys::create();
	_method->topic = topic;
	auto _return_value = vnx_request(_method);
	auto _result = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_all_keys_return>(_return_value);
	if(!_result) {
		throw std::logic_error("StorageClient: !_result");
	}
	return _result->_ret_0;
}

void StorageClient::cancel_sync_job(const int64_t& job_id) {
	auto _method = ::vnx::keyvalue::Storage_cancel_sync_job::create();
	_method->job_id = job_id;
	auto _return_value = vnx_request(_method);
}

void StorageClient::cancel_sync_job_async(const int64_t& job_id) {
	vnx_is_async = true;
	cancel_sync_job(job_id);
}

void StorageClient::store_value(const ::vnx::Variant& key, const std::shared_ptr<const ::vnx::Value>& value) {
	auto _method = ::vnx::keyvalue::Storage_store_value::create();
	_method->key = key;
	_method->value = value;
	auto _return_value = vnx_request(_method);
}

void StorageClient::store_value_async(const ::vnx::Variant& key, const std::shared_ptr<const ::vnx::Value>& value) {
	vnx_is_async = true;
	store_value(key, value);
}

void StorageClient::store_values(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values) {
	auto _method = ::vnx::keyvalue::Storage_store_values::create();
	_method->values = values;
	auto _return_value = vnx_request(_method);
}

void StorageClient::store_values_async(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values) {
	vnx_is_async = true;
	store_values(values);
}

void StorageClient::delete_value(const ::vnx::Variant& key) {
	auto _method = ::vnx::keyvalue::Storage_delete_value::create();
	_method->key = key;
	auto _return_value = vnx_request(_method);
}

void StorageClient::delete_value_async(const ::vnx::Variant& key) {
	vnx_is_async = true;
	delete_value(key);
}


} // namespace vnx
} // namespace keyvalue
