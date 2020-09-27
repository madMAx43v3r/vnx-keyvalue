
// AUTO GENERATED by vnxcppcodegen

#ifndef INCLUDE_vnx_keyvalue_SyncModule_CLIENT_HXX_
#define INCLUDE_vnx_keyvalue_SyncModule_CLIENT_HXX_

#include <vnx/Client.h>
#include <vnx/Hash64.hpp>
#include <vnx/Module.h>
#include <vnx/TopicPtr.hpp>
#include <vnx/keyvalue/SyncInfo.hxx>
#include <vnx/keyvalue/SyncUpdate.hxx>


namespace vnx {
namespace keyvalue {

class SyncModuleClient : public vnx::Client {
public:
	SyncModuleClient(const std::string& service_name);
	
	SyncModuleClient(vnx::Hash64 service_addr);
	
	::vnx::Object vnx_get_config_object();
	
	::vnx::Variant vnx_get_config(const std::string& name);
	
	void vnx_set_config_object(const ::vnx::Object& config);
	
	void vnx_set_config_object_async(const ::vnx::Object& config);
	
	void vnx_set_config(const std::string& name, const ::vnx::Variant& value);
	
	void vnx_set_config_async(const std::string& name, const ::vnx::Variant& value);
	
	::vnx::TypeCode vnx_get_type_code();
	
	void vnx_restart();
	
	void vnx_restart_async();
	
	void vnx_close();
	
	void vnx_close_async();
	
};


} // namespace vnx
} // namespace keyvalue

#endif // INCLUDE_vnx_keyvalue_SyncModule_CLIENT_HXX_
