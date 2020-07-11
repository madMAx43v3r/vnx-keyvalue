
// AUTO GENERATED by vnxcppcodegen

#ifndef INCLUDE_vnx_keyvalue_Cache_CLIENT_HXX_
#define INCLUDE_vnx_keyvalue_Cache_CLIENT_HXX_

#include <vnx/Client.h>
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
	
	::vnx::TypeCode vnx_get_type_code();
	
	std::shared_ptr<const ::vnx::keyvalue::Entry> get_value(const ::vnx::Variant& key);
	
	std::shared_ptr<const ::vnx::keyvalue::Entry> get_value_locked(const ::vnx::Variant& key, const int32_t& timeout_ms);
	
	std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>> get_values(const std::vector<::vnx::Variant>& keys);
	
	::vnx::Variant get_version_key(const uint64_t& version);
	
	std::vector<std::pair<uint64_t, ::vnx::Variant>> get_version_keys(const std::vector<uint64_t>& versions);
	
	void unlock(const ::vnx::Variant& key);
	
	void unlock_async(const ::vnx::Variant& key);
	
	int64_t sync_from(const ::vnx::TopicPtr& topic, const uint64_t& version);
	
	int64_t sync_range(const ::vnx::TopicPtr& topic, const uint64_t& begin, const uint64_t& end);
	
	int64_t sync_all(const ::vnx::TopicPtr& topic);
	
	int64_t sync_all_keys(const ::vnx::TopicPtr& topic);
	
	void cancel_sync_job(const int64_t& job_id);
	
	void cancel_sync_job_async(const int64_t& job_id);
	
	void store_value(const ::vnx::Variant& key, const std::shared_ptr<const ::vnx::Value>& value);
	
	void store_value_async(const ::vnx::Variant& key, const std::shared_ptr<const ::vnx::Value>& value);
	
	void store_values(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values);
	
	void store_values_async(const std::vector<std::pair<::vnx::Variant, std::shared_ptr<const ::vnx::Value>>>& values);
	
	void delete_value(const ::vnx::Variant& key);
	
	void delete_value_async(const ::vnx::Variant& key);
	
};


} // namespace vnx
} // namespace keyvalue

#endif // INCLUDE_vnx_keyvalue_Cache_CLIENT_HXX_