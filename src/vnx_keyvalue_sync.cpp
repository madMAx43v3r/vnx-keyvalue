/*
 * vnx_keyvalue_sync.cpp
 *
 *  Created on: Jul 3, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/SyncModule.h>

#include <vnx/vnx.h>
#include <vnx/Terminal.h>
#include <vnx/Proxy.h>


int main(int argc, char** argv)
{
	std::map<std::string, std::string> options;
	options["f"] = "from";
	options["t"] = "to";
	options["n"] = "src";
	options["m"] = "dst";
	options["a"] = "add";
	options["from"] = "src server url";
	options["to"] = "dst server url";
	options["src"] = "src module name";
	options["dst"] = "dst module name";
	options["add"] = "add only (ignore null values)";
	
	vnx::init("vnx_keyvalue_sync", argc, argv, options);
	
	std::string from;
	std::string to;
	std::string src;
	vnx::read_config("from", from);
	vnx::read_config("to", to);
	vnx::read_config("src", src);
	std::string dst = src;
	vnx::read_config("dst", dst);
	
	vnx::Handle<vnx::keyvalue::SyncModule> module = new vnx::keyvalue::SyncModule("SyncModule");
	vnx::read_config("add", module->add_only);
	
	{
		vnx::Handle<vnx::Proxy> proxy = new vnx::Proxy("SrcProxy", vnx::Endpoint::from_url(from));
		proxy->import_list.push_back(module->input_sync->get_name());
		proxy->tunnel_map[module->src_addr] = src;
		proxy.start_detached();
	}
	{
		vnx::Handle<vnx::Proxy> proxy = new vnx::Proxy("DstProxy", vnx::Endpoint::from_url(to));
		proxy->tunnel_map[module->dst_addr] = dst;
		proxy.start_detached();
	}
	
	module.start();
	module.wait();
	
	vnx::close();
}


