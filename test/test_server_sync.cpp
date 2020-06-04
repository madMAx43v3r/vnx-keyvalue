/*
 * test_server_sync.cpp
 *
 *  Created on: Mar 29, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/ServerClient.hxx>
#include <vnx/keyvalue/SyncInfo.hxx>
#include <vnx/keyvalue/KeyValuePair.hxx>

#include <vnx/vnx.h>
#include <vnx/Terminal.h>
#include <vnx/Proxy.h>

#include <unistd.h>

class TestThread : public vnx::Thread {
public:
	TestThread() : Thread("TestThread") {}
	
	std::string server_name = "StorageServer";
	vnx::TopicPtr sync_topic = "test.sync_update";
	
protected:
	void main() override
	{
		subscribe(sync_topic, 0);
		
		vnx::keyvalue::ServerClient client(server_name);
		client.sync_all(sync_topic);
		
		uint64_t counter = 0;
		while(vnx::do_run())
		{
			auto msg = read_blocking();
			if(msg) {
				auto sample = std::dynamic_pointer_cast<const vnx::Sample>(msg);
				if(sample) {
					auto info = std::dynamic_pointer_cast<const vnx::keyvalue::SyncInfo>(sample->value);
					if(info) {
						if(info->code == vnx::keyvalue::SyncInfo::BEGIN) {
							vnx::log_info().out << "Sync BEGIN";
						}
						if(info->code == vnx::keyvalue::SyncInfo::END) {
							vnx::log_info().out << "Sync END";
							break;
						}
					}
					auto pair = std::dynamic_pointer_cast<const vnx::keyvalue::KeyValuePair>(sample->value);
					if(pair) {
						counter++;
						if(counter % 1000 == 0) {
							vnx::log_info().out << "Got " << counter << " values";
						}
					}
				}
			} else {
				break;
			}
		}
		vnx::log_info().out << "Got " << counter << " values total.";
	}
	
};


int main(int argc, char** argv)
{
	std::map<std::string, std::string> options;
	options["n"] = "node";
	options["node"] = "server url";
	
	vnx::init("test_server_sync", argc, argv, options);
	
	std::string server = ".vnx_keyvalue_server.sock";
	vnx::read_config("node", server);
	
	{
		vnx::Handle<vnx::Terminal> terminal = new vnx::Terminal("Terminal");
		terminal.start_detached();
	}
	
	TestThread thread;
	
	{
		vnx::Handle<vnx::Proxy> proxy = new vnx::Proxy("Proxy", vnx::Endpoint::from_url(server));
		proxy->forward_list.push_back(thread.server_name);
		proxy->import_list.push_back(thread.sync_topic->get_name());
		proxy.start_detached();
	}
	
	thread.start();
	
	vnx::wait();
}

