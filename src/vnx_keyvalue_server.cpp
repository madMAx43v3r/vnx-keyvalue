/*
 * vnx_keyvalue_server.cpp
 *
 *  Created on: Mar 22, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/Server.h>

#include <vnx/Config.h>
#include <vnx/Process.h>
#include <vnx/Terminal.h>
#include <vnx/Server.h>


int main(int argc, char** argv)
{
	std::map<std::string, std::string> options;
	options["s"] = "server";
	options["server"] = "server name";
	options["n"] = "name";
	options["name"] = "collection name";
	
	vnx::init("vnx_keyvalue_server", argc, argv, options);
	
	std::string server_name = "StorageServer";
	vnx::read_config("server", server_name);
	
	{
		vnx::Handle<vnx::Terminal> terminal = new vnx::Terminal("Terminal");
		terminal.start_detached();
	}
	{
		vnx::Handle<vnx::Server> server = new vnx::Server("Server", vnx::Endpoint::from_url(".vnx_keyvalue_server.sock"));
		server.start_detached();
	}
	{
		vnx::Handle<vnx::keyvalue::Server> module = new vnx::keyvalue::Server(server_name);
		vnx::read_config("name", module->collection);
		module.start_detached();
	}
	
	vnx::wait();
}


