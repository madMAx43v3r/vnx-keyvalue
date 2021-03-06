
// AUTO GENERATED by vnxcppcodegen

#ifndef INCLUDE_vnx_keyvalue_Storage_CLIENT_HXX_
#define INCLUDE_vnx_keyvalue_Storage_CLIENT_HXX_

#include <vnx/Client.h>
#include <vnx/Hash64.hpp>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Entry.hxx>


namespace vnx {
namespace keyvalue {

class StorageClient : public vnx::Client {
public:
	StorageClient(const std::string& service_name);
	
	StorageClient(vnx::Hash64 service_addr);
	
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

#endif // INCLUDE_vnx_keyvalue_Storage_CLIENT_HXX_
