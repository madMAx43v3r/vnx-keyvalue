
// AUTO GENERATED by vnxcppcodegen

#ifndef INCLUDE_vnx_keyvalue_Cache_CLIENT_HXX_
#define INCLUDE_vnx_keyvalue_Cache_CLIENT_HXX_

#include <vnx/Client.h>
#include <vnx/Hash64.hpp>
#include <vnx/Module.h>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Entry.hxx>


namespace vnx {
namespace keyvalue {

class CacheClient : public vnx::Client {
public:
	CacheClient(const std::string& service_name);
	
	CacheClient(vnx::Hash64 service_addr);
	
	::vnx::Object vnx_get_config_object();
	
	::vnx::Variant vnx_get_config(const std::string& name = "");
	
	void vnx_set_config_object(const ::vnx::Object& config = ::vnx::Object());
	
	void vnx_set_config_object_async(const ::vnx::Object& config = ::vnx::Object());
	
	void vnx_set_config(const std::string& name = "", const ::vnx::Variant& value = ::vnx::Variant());
	
	void vnx_set_config_async(const std::string& name = "", const ::vnx::Variant& value = ::vnx::Variant());
	
	::vnx::TypeCode vnx_get_type_code();
	
	std::shared_ptr<const ::vnx::ModuleInfo> vnx_get_module_info();
	
	void vnx_restart();
	
	void vnx_restart_async();
	
	void vnx_stop();
	
	void vnx_stop_async();
	
	vnx::bool_t vnx_self_test();
	
	std::shared_ptr<const ::vnx::keyvalue::Entry> get_value(const ::vnx::Variant& key = ::vnx::Variant());
	
	std::shared_ptr<const ::vnx::keyvalue::Entry> get_value_locked(const ::vnx::Variant& key = ::vnx::Variant(), const int32_t& timeout_ms = 0);
	
	std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>> get_values(const std::vector<::vnx::Variant>& keys = {});
	
	::vnx::Variant get_key(const uint64_t& version = 0);
	
	std::vector<std::pair<uint64_t, ::vnx::Variant>> get_keys(const std::vector<uint64_t>& versions = {});
	
	void unlock(const ::vnx::Variant& key = ::vnx::Variant());
	
	void unlock_async(const ::vnx::Variant& key = ::vnx::Variant());
	
	int64_t sync_from(const ::vnx::TopicPtr& topic = ::vnx::TopicPtr(), const uint64_t& version = 0);
	
	int64_t sync_range(const ::vnx::TopicPtr& topic = ::vnx::TopicPtr(), const uint64_t& begin = 0, const uint64_t& end = 0);
	
	int64_t sync_all(const ::vnx::TopicPtr& topic = ::vnx::TopicPtr());
	
	int64_t sync_all_keys(const ::vnx::TopicPtr& topic = ::vnx::TopicPtr());
	
	int64_t sync_all_private(const ::vnx::Hash64& dst_mac = ::vnx::Hash64());
	
	int64_t sync_all_keys_private(const ::vnx::Hash64& dst_mac = ::vnx::Hash64());
	
	void cancel_sync_job(const int64_t& job_id = 0);
	
	void cancel_sync_job_async(const int64_t& job_id = 0);
	
	void store_value(const ::vnx::Variant& key = ::vnx::Variant(), std::shared_ptr<const ::vnx::Value> value = nullptr);
	
	void store_value_async(const ::vnx::Variant& key = ::vnx::Variant(), std::shared_ptr<const ::vnx::Value> value = nullptr);
	
	void store_values(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values = {});
	
	void store_values_async(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values = {});
	
	void store_value_delay(const ::vnx::Variant& key = ::vnx::Variant(), std::shared_ptr<const ::vnx::Value> value = nullptr, const int32_t& delay_ms = 0);
	
	void store_value_delay_async(const ::vnx::Variant& key = ::vnx::Variant(), std::shared_ptr<const ::vnx::Value> value = nullptr, const int32_t& delay_ms = 0);
	
	void store_values_delay(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values = {}, const int32_t& delay_ms = 0);
	
	void store_values_delay_async(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values = {}, const int32_t& delay_ms = 0);
	
	void delete_value(const ::vnx::Variant& key = ::vnx::Variant());
	
	void delete_value_async(const ::vnx::Variant& key = ::vnx::Variant());
	
};


} // namespace vnx
} // namespace keyvalue

#endif // INCLUDE_vnx_keyvalue_Cache_CLIENT_HXX_
