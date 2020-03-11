/*
 * Server.cpp
 *
 *  Created on: Mar 11, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/Server.h>
#include <vnx/keyvalue/IndexEntry.hxx>


namespace vnx {
namespace keyvalue {

void Server::main()
{
	coll_index = vnx::read_from_file<Collection>(get_file_path("index", 0));
	
	if(!coll_index) {
		coll_index = Collection::create();
		coll_index->name = collection;
	}
	
	// TODO: load blocks
	
	if(block_map.empty()) {
		add_new_block();
	}
	
	write_index();
	
	Super::main();
}

std::string Server::get_file_path(const std::string& name, int64_t index) const
{
	return storage_path + collection + "." + name + "." + std::to_string(index) + ".dat";
}

std::shared_ptr<Server::block_t> Server::get_current_block() const
{
	if(block_map.empty()) {
		return 0;
	}
	return *block_map.rbegin();
}

std::shared_ptr<Server::block_t> Server::add_new_block()
{
	auto curr_block = get_current_block();
	if(curr_block) {
		curr_block->key_file.close();
		curr_block->value_file.open("rb");
	}
	
	auto block = std::make_shared<block_t>();
	block->index = curr_block ? curr_block->index + 1 : 0;
	block->key_file.open(get_file_path("key", block->index), "wb");
	block->value_file.open(get_file_path("value", block->index), "wb");
	block->key_file.write_header();
	block->value_file.write_header();
	block->key_file.flush();
	block->value_file.flush();
	block_map[block->index] = block;
	write_index();
	return block;
}

void Server::write_index()
{
	coll_index->block_list.clear();
	for(const auto& entry : block_map) {
		coll_index->block_list.push_back(entry.first);
	}
	for(int i = 0; i < 3; ++i) {
		vnx::write_to_file(get_file_path("index", i), coll_index);
	}
}


} // keyvalue
} // vnx
