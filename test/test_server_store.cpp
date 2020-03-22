/*
 * test_server_store.cpp
 *
 *  Created on: Mar 22, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/ServerClient.hxx>

#include <vnx/Config.h>
#include <vnx/Process.h>
#include <vnx/Terminal.h>
#include <vnx/Proxy.h>

#include <unistd.h>


int main(int argc, char** argv)
{
	std::map<std::string, std::string> options;
	options["n"] = "node";
	options["node"] = "server url";
	
	vnx::init("test_server_store", argc, argv, options);
	
	std::string server = ".vnx_keyvalue_server.sock";
	vnx::read_config("node", server);
	
	{
		vnx::Handle<vnx::Terminal> terminal = new vnx::Terminal("Terminal");
		terminal.start_detached();
	}
	{
		vnx::Handle<vnx::Proxy> proxy = new vnx::Proxy("Proxy", vnx::Endpoint::from_url(server));
		proxy->forward_list.push_back("StorageServer");
		proxy.start_detached();
	}
	
	vnx::keyvalue::ServerClient client("StorageServer");
	
	vnx::Object value;
	value["id"] = 12323443;
	value["vector"] = std::vector<uint64_t>(512);
	value["test"] = "sdkfjnskdjnfskdjnfskdjfnsdjnfkjsdnfjsndjkfsdjnf";
	
	uint64_t counter = 0;
	while(vnx::do_run())
	{
		const uint64_t key = counter % 65536;
		client.store_value(key, value.clone());
		counter++;
		::usleep(1 * 1000);
	}
	
	vnx::wait();
}

