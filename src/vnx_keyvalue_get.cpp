/*
 * vnx_keyvalue_get.cpp
 *
 *  Created on: May 17, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/ServerClient.hxx>

#include <vnx/vnx.h>
#include <vnx/Terminal.h>
#include <vnx/Proxy.h>


int main(int argc, char** argv)
{
	std::map<std::string, std::string> options;
	options["s"] = "server";
	options["n"] = "name";
	options["k"] = "key";
	options["server"] = "server url";
	options["name"] = "module name";
	options["key"] = "key";
	
	vnx::init("vnx_keyvalue_get", argc, argv, options);
	
	std::string server = ".vnx_keyvalue_server.sock";
	std::string name = "StorageServer";
	vnx::Variant key;
	vnx::read_config("server", server);
	vnx::read_config("name", name);
	vnx::read_config("key", key);
	
	{
		vnx::Handle<vnx::Proxy> proxy = new vnx::Proxy("Proxy", vnx::Endpoint::from_url(server));
		proxy->forward_list.push_back(name);
		proxy.start_detached();
	}
	
	vnx::keyvalue::ServerClient client(name);
	
	auto value = client.get_value(key);
	
	vnx::PrettyPrinter printer(std::cout);
	vnx::accept(printer, value);
	std::cout << std::endl;
	
	vnx::close();
}

