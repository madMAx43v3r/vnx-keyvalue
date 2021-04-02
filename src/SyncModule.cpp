/*
 * SyncModule.cpp
 *
 *  Created on: Jul 3, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/SyncModule.h>


namespace vnx {
namespace keyvalue {

SyncModule::SyncModule(const std::string& _vnx_name)
	:	SyncModuleBase(_vnx_name)
{
	src_addr = vnx::Hash64::rand();
	dst_addr = vnx::Hash64::rand();
}

void SyncModule::main()
{
	subscribe(input_sync, 1000);
	
	stream = std::make_shared<Stream>(src_name);
	stream->connect(this, 100, 1000);
	
	src = std::make_shared<StorageClient>(src_name);
	dst = std::make_shared<StorageClient>(dst_name);
	
	src->vnx_set_tunnel(src_addr);
	dst->vnx_set_tunnel(dst_addr);
	
	src->sync_all_private(stream->get_src_mac());
	
	if(stats_interval_ms) {
		set_timer_millis(stats_interval_ms, std::bind(&SyncModule::print_stats, this));
	}
	
	Super::main();
}

void SyncModule::handle(std::shared_ptr<const SyncUpdate> value)
{
	if(!add_only || value->value) {
		buffer.emplace_back(value->key, value->value);
	}
	if(buffer.size() >= buffer_size) {
		flush();
	}
}

void SyncModule::handle(std::shared_ptr<const SyncInfo> value)
{
	if(value->code == SyncInfo::END)
	{
		flush();
		log(INFO) << "Finished '" << value->collection << "' sync: " << num_copied << " values, "
				<< num_failed << " failed, version = " << value->version;
		exit();
	}
}

void SyncModule::flush()
{
	try {
		dst->store_values(buffer);
		num_copied += buffer.size();
	} catch(const std::exception& ex) {
		num_failed += buffer.size();
		log(WARN) << "flush(): " << ex.what();
	}
	buffer.clear();
}

void SyncModule::print_stats()
{
	log(INFO) << num_copied << " entries, " << num_failed << " failed";
}


} // keyvalue
} // vnx
