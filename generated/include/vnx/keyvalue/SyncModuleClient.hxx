
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
	
	::vnx::TypeCode vnx_get_type_code();
	
};


} // namespace vnx
} // namespace keyvalue

#endif // INCLUDE_vnx_keyvalue_SyncModule_CLIENT_HXX_