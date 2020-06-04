/*
 * test_server_delete.cpp
 *
 *  Created on: Mar 22, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/ServerClient.hxx>

#include <vnx/vnx.h>
#include <vnx/Terminal.h>
#include <vnx/Proxy.h>

#include <unistd.h>


int main(int argc, char** argv)
{
	std::map<std::string, std::string> options;
	options["n"] = "node";
	options["node"] = "server url";
	
	vnx::init("test_server_delete", argc, argv, options);
	
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
	
	uint64_t counter = 0;
	while(vnx::do_run())
	{
		const uint64_t key = counter % 65536;
		client.delete_value(vnx::Variant(key));
		counter++;
//		::usleep(1 * 1000);
	}
	
	vnx::wait();
}

