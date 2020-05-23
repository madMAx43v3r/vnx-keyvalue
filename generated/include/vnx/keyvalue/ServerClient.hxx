
// AUTO GENERATED by vnxcppcodegen

#ifndef INCLUDE_vnx_keyvalue_Server_CLIENT_HXX_
#define INCLUDE_vnx_keyvalue_Server_CLIENT_HXX_

#include <vnx/Client.h>
#include <vnx/Module.h>
#include <vnx/TopicPtr.h>
#include <vnx/Value.h>
#include <vnx/Variant.h>


namespace vnx {
namespace keyvalue {

class ServerClient : public vnx::Client {
public:
	ServerClient(const std::string& service_name);
	
	ServerClient(vnx::Hash64 service_addr);
	
	void _sync_finished(const ::int64_t& job_id);
	
	void _sync_finished_async(const ::int64_t& job_id);
	
	void delete_value(const ::vnx::Variant& key);
	
	void delete_value_async(const ::vnx::Variant& key);
	
	::std::shared_ptr<const ::vnx::Value> get_value(const ::vnx::Variant& key);
	
	::std::vector<::std::shared_ptr<const ::vnx::Value>> get_values(const ::std::vector<::vnx::Variant>& keys);
	
	void store_value(const ::vnx::Variant& key, const ::std::shared_ptr<const ::vnx::Value>& value);
	
	void store_value_async(const ::vnx::Variant& key, const ::std::shared_ptr<const ::vnx::Value>& value);
	
	void store_values(const ::std::vector<::std::pair<::vnx::Variant, ::std::shared_ptr<const ::vnx::Value>>>& values);
	
	void store_values_async(const ::std::vector<::std::pair<::vnx::Variant, ::std::shared_ptr<const ::vnx::Value>>>& values);
	
	::int64_t sync_all(const ::vnx::TopicPtr& topic);
	
	::int64_t sync_all_keys(const ::vnx::TopicPtr& topic);
	
	::int64_t sync_from(const ::vnx::TopicPtr& topic, const ::uint64_t& version);
	
	::int64_t sync_range(const ::vnx::TopicPtr& topic, const ::uint64_t& begin, const ::uint64_t& end);
	
};


} // namespace vnx
} // namespace keyvalue

#endif // INCLUDE_vnx_keyvalue_Server_CLIENT_HXX_
