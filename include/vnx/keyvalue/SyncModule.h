/*
 * SyncModule.h
 *
 *  Created on: Jul 3, 2020
 *      Author: mad
 */

#ifndef VNX_KEYVALUE_SYNCMODULE_H_
#define VNX_KEYVALUE_SYNCMODULE_H_

#include <vnx/keyvalue/SyncModuleBase.hxx>
#include <vnx/keyvalue/ServerClient.hxx>


namespace vnx {
namespace keyvalue {

class SyncModule : public SyncModuleBase {
public:
	SyncModule(const std::string& _vnx_name);
	
protected:
	void main() override;
	
	void handle(std::shared_ptr<const SyncUpdate> value) override;
	
	void handle(std::shared_ptr<const SyncInfo> value) override;
	
private:
	void flush();
	
	void print_stats();
	
private:
	std::shared_ptr<keyvalue::ServerClient> src;
	std::shared_ptr<keyvalue::ServerClient> dst;
	
	std::vector<std::pair<Variant, std::shared_ptr<const Value>>> buffer;
	
	size_t num_copied = 0;
	size_t num_failed = 0;
	
};

} // keyvalue
} // vnx

#endif /* VNX_KEYVALUE_SYNCMODULE_H_ */
