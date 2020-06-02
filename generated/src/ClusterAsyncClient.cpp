
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/ClusterAsyncClient.hxx>
#include <vnx/Input.h>
#include <vnx/Output.h>
#include <vnx/Module.h>



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

std::vector<uint64_t> ClusterAsyncClient::vnx_get_pending_ids() const {
	std::vector<uint64_t> _list;
	return _list;
}

void ClusterAsyncClient::vnx_purge_request(uint64_t _request_id) {
}

void ClusterAsyncClient::vnx_callback_switch(uint64_t _request_id, std::shared_ptr<const vnx::Value> _value) {
	{
		throw std::runtime_error("unknown return value");
	}
}


} // namespace vnx
} // namespace keyvalue
