
// AUTO GENERATED by vnxcppcodegen

#ifndef INCLUDE_vnx_keyvalue_Cluster_ASYNC_CLIENT_HXX_
#define INCLUDE_vnx_keyvalue_Cluster_ASYNC_CLIENT_HXX_

#include <vnx/AsyncClient.h>
#include <vnx/Hash64.hpp>
#include <vnx/Module.h>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Entry.hxx>


namespace vnx {
namespace keyvalue {

class ClusterAsyncClient : public vnx::AsyncClient {
public:
	ClusterAsyncClient(const std::string& service_name);
	
	ClusterAsyncClient(vnx::Hash64 service_addr);
	
	uint64_t vnx_get_config_object(
			const std::function<void(const ::vnx::Object&)>& _callback = std::function<void(const ::vnx::Object&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t vnx_get_config(const std::string& name, 
			const std::function<void(const ::vnx::Variant&)>& _callback = std::function<void(const ::vnx::Variant&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t vnx_set_config_object(const ::vnx::Object& config, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t vnx_set_config(const std::string& name, const ::vnx::Variant& value, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t vnx_get_type_code(
			const std::function<void(const ::vnx::TypeCode&)>& _callback = std::function<void(const ::vnx::TypeCode&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t vnx_get_module_info(
			const std::function<void(std::shared_ptr<const ::vnx::ModuleInfo>)>& _callback = std::function<void(std::shared_ptr<const ::vnx::ModuleInfo>)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t vnx_restart(
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t vnx_stop(
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t vnx_self_test(
			const std::function<void(const vnx::bool_t&)>& _callback = std::function<void(const vnx::bool_t&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t get_value(const ::vnx::Variant& key, 
			const std::function<void(std::shared_ptr<const ::vnx::keyvalue::Entry>)>& _callback = std::function<void(std::shared_ptr<const ::vnx::keyvalue::Entry>)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t get_value_locked(const ::vnx::Variant& key, const int32_t& timeout_ms, 
			const std::function<void(std::shared_ptr<const ::vnx::keyvalue::Entry>)>& _callback = std::function<void(std::shared_ptr<const ::vnx::keyvalue::Entry>)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t get_values(const std::vector<::vnx::Variant>& keys, 
			const std::function<void(const std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>>&)>& _callback = std::function<void(const std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>>&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t get_key(const uint64_t& version, 
			const std::function<void(const ::vnx::Variant&)>& _callback = std::function<void(const ::vnx::Variant&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t get_keys(const std::vector<uint64_t>& versions, 
			const std::function<void(const std::vector<std::pair<uint64_t, ::vnx::Variant>>&)>& _callback = std::function<void(const std::vector<std::pair<uint64_t, ::vnx::Variant>>&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t unlock(const ::vnx::Variant& key, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t sync_from(const ::vnx::TopicPtr& topic, const uint64_t& version, 
			const std::function<void(const int64_t&)>& _callback = std::function<void(const int64_t&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t sync_range(const ::vnx::TopicPtr& topic, const uint64_t& begin, const uint64_t& end, 
			const std::function<void(const int64_t&)>& _callback = std::function<void(const int64_t&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t sync_all(const ::vnx::TopicPtr& topic, 
			const std::function<void(const int64_t&)>& _callback = std::function<void(const int64_t&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t sync_all_keys(const ::vnx::TopicPtr& topic, 
			const std::function<void(const int64_t&)>& _callback = std::function<void(const int64_t&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t sync_all_private(const ::vnx::Hash64& dst_mac, 
			const std::function<void(const int64_t&)>& _callback = std::function<void(const int64_t&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t sync_all_keys_private(const ::vnx::Hash64& dst_mac, 
			const std::function<void(const int64_t&)>& _callback = std::function<void(const int64_t&)>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t cancel_sync_job(const int64_t& job_id, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t store_value(const ::vnx::Variant& key, std::shared_ptr<const ::vnx::Value> value, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t store_values(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t store_value_delay(const ::vnx::Variant& key, std::shared_ptr<const ::vnx::Value> value, const int32_t& delay_ms, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t store_values_delay(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values, const int32_t& delay_ms, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
	uint64_t delete_value(const ::vnx::Variant& key, 
			const std::function<void()>& _callback = std::function<void()>(),
			const std::function<void(const vnx::exception&)>& _error_callback = std::function<void(const vnx::exception&)>());
	
protected:
	int32_t vnx_purge_request(uint64_t _request_id, const vnx::exception& _ex) override;
	
	int32_t vnx_callback_switch(uint64_t _request_id, std::shared_ptr<const vnx::Value> _value) override;
	
private:
	std::unordered_map<uint64_t, std::pair<std::function<void(const ::vnx::Object&)>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_get_config_object;
	std::unordered_map<uint64_t, std::pair<std::function<void(const ::vnx::Variant&)>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_get_config;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_set_config_object;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_set_config;
	std::unordered_map<uint64_t, std::pair<std::function<void(const ::vnx::TypeCode&)>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_get_type_code;
	std::unordered_map<uint64_t, std::pair<std::function<void(std::shared_ptr<const ::vnx::ModuleInfo>)>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_get_module_info;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_restart;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_stop;
	std::unordered_map<uint64_t, std::pair<std::function<void(const vnx::bool_t&)>, std::function<void(const vnx::exception&)>>> vnx_queue_vnx_self_test;
	std::unordered_map<uint64_t, std::pair<std::function<void(std::shared_ptr<const ::vnx::keyvalue::Entry>)>, std::function<void(const vnx::exception&)>>> vnx_queue_get_value;
	std::unordered_map<uint64_t, std::pair<std::function<void(std::shared_ptr<const ::vnx::keyvalue::Entry>)>, std::function<void(const vnx::exception&)>>> vnx_queue_get_value_locked;
	std::unordered_map<uint64_t, std::pair<std::function<void(const std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>>&)>, std::function<void(const vnx::exception&)>>> vnx_queue_get_values;
	std::unordered_map<uint64_t, std::pair<std::function<void(const ::vnx::Variant&)>, std::function<void(const vnx::exception&)>>> vnx_queue_get_key;
	std::unordered_map<uint64_t, std::pair<std::function<void(const std::vector<std::pair<uint64_t, ::vnx::Variant>>&)>, std::function<void(const vnx::exception&)>>> vnx_queue_get_keys;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_unlock;
	std::unordered_map<uint64_t, std::pair<std::function<void(const int64_t&)>, std::function<void(const vnx::exception&)>>> vnx_queue_sync_from;
	std::unordered_map<uint64_t, std::pair<std::function<void(const int64_t&)>, std::function<void(const vnx::exception&)>>> vnx_queue_sync_range;
	std::unordered_map<uint64_t, std::pair<std::function<void(const int64_t&)>, std::function<void(const vnx::exception&)>>> vnx_queue_sync_all;
	std::unordered_map<uint64_t, std::pair<std::function<void(const int64_t&)>, std::function<void(const vnx::exception&)>>> vnx_queue_sync_all_keys;
	std::unordered_map<uint64_t, std::pair<std::function<void(const int64_t&)>, std::function<void(const vnx::exception&)>>> vnx_queue_sync_all_private;
	std::unordered_map<uint64_t, std::pair<std::function<void(const int64_t&)>, std::function<void(const vnx::exception&)>>> vnx_queue_sync_all_keys_private;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_cancel_sync_job;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_store_value;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_store_values;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_store_value_delay;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_store_values_delay;
	std::unordered_map<uint64_t, std::pair<std::function<void()>, std::function<void(const vnx::exception&)>>> vnx_queue_delete_value;
	
};


} // namespace vnx
} // namespace keyvalue

#endif // INCLUDE_vnx_keyvalue_Cluster_ASYNC_CLIENT_HXX_
