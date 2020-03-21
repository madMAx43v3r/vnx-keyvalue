/*
 * Server.cpp
 *
 *  Created on: Mar 11, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/Server.h>
#include <vnx/keyvalue/IndexEntry.hxx>
#include <vnx/keyvalue/TypeEntry.hxx>
#include <vnx/keyvalue/DeleteEntry.hxx>

#include <sys/mman.h>
#include <unistd.h>


namespace vnx {
namespace keyvalue {

void Server::main()
{
	for(int i = 0; i < 3; ++i) {
		coll_index = vnx::read_from_file<Collection>(get_file_path("index", i));
		if(coll_index) {
			break;
		}
	}
	
	if(!coll_index) {
		coll_index = Collection::create();
		coll_index->name = collection;
	}
	
	// TODO: load blocks
	
	if(block_map.empty()) {
		add_new_block();
	}
	
	write_index();
	
	read_threads.resize(num_read_threads);
	for(int i = 0; i < num_read_threads; ++i) {
		read_threads[i] = std::thread(&Server::read_loop, this);
	}
	
	Super::main();
	
	read_condition.notify_all();
	for(auto& thread : read_threads) {
		if(thread.joinable()) {
			thread.join();
		}
	}
}

void Server::get_value_async(	const Variant& key,
								const std::function<void(const std::shared_ptr<const Value>&)>& callback,
								const vnx::request_id_t& request_id) const
{
	auto index = get_key_index(key);
	auto block = get_block(index.block_index);
	
	auto result = std::make_shared<read_result_t>();
	result->callback = callback;
	
	read_item_t item;
	item.fd = ::fileno(block->value_file.get_handle());
	item.offset = index.block_offset;
	item.num_bytes = index.num_bytes;
	item.result = result;
	{
		std::lock_guard<std::mutex> lock(read_mutex);
		read_queue.push(item);
	}
	read_condition.notify_one();
}

void Server::get_values_async(	const std::vector<Variant>& keys,
								const std::function<void(const std::vector<std::shared_ptr<const Value>>&)>& callback,
								const vnx::request_id_t& request_id) const
{
	auto result = std::make_shared<read_result_many_t>();
	result->callback = callback;
	result->num_left = keys.size();
	result->values.resize(keys.size());
	
	for(size_t i = 0; i < keys.size(); ++i)
	{
		key_index_t index;
		std::shared_ptr<block_t> block;
		try {
			index = get_key_index(keys[i]);
			block = get_block(index.block_index);
		}
		catch(...) {
			continue;
		}
		
		read_item_t item;
		item.index = i;
		item.fd = ::fileno(block->value_file.get_handle());
		item.offset = index.block_offset;
		item.num_bytes = index.num_bytes;
		item.result = result;
		{
			std::lock_guard<std::mutex> lock(read_mutex);
			read_queue.push(item);
		}
		read_condition.notify_one();
	}
}

void Server::store_value(const Variant& key, const std::shared_ptr<const Value>& value)
{
	auto block = get_current_block();
	if(block) {
		auto& key_out = block->key_file.out;
		auto& value_out = block->value_file.out;
		if(!value_out.type_code_map.count(value->get_type_hash())) {
			TypeEntry entry;
			entry.block_offset = value_out.get_output_pos();
			vnx::write(key_out, entry);
			vnx::write(value_out, value->get_type_code());
		}
		
		IndexEntry entry;
		entry.key = key;
		entry.block_offset = value_out.get_output_pos();
		vnx::write(value_out, value);
		entry.num_bytes = value_out.get_output_pos() - entry.block_offset;
		vnx::write(key_out, entry);
		block->key_file.flush();
		block->value_file.flush();
		
		key_index_t& index = key_map[key];
		block->num_bytes_used += entry.num_bytes - index.num_bytes;
		block->num_bytes_total += entry.num_bytes;
		
		index.block_index = block->index;
		index.block_offset = entry.block_offset;
		index.num_bytes = entry.num_bytes;
		
		if(block->num_bytes_total >= max_block_size) {
			add_new_block();
		}
	}
}

void Server::delete_value(const Variant& key)
{
	auto iter = key_map.find(key);
	if(iter == key_map.end()) {
		throw std::runtime_error("unknown key");
	}
	const auto& index = iter->second;
	
	auto block = get_block(index.block_index);
	if(block) {
		DeleteEntry entry;
		entry.key = key;
		vnx::write(block->key_file.out, entry);
		block->key_file.flush();
		block->num_bytes_used -= index.num_bytes;
	}
	key_map.erase(iter);
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
	return block_map.rbegin()->second;
}

std::shared_ptr<Server::block_t> Server::get_block(int64_t index) const
{
	auto iter = block_map.find(index);
	if(iter == block_map.end()) {
		throw std::runtime_error("unknown block");
	}
	return iter->second;
}

Server::key_index_t Server::get_key_index(const Variant& key) const
{
	auto iter = key_map.find(key);
	if(iter == key_map.end()) {
		throw std::runtime_error("unknown key");
	}
	return iter->second;
}

std::shared_ptr<Server::block_t> Server::add_new_block()
{
	auto curr_block = get_current_block();
	if(curr_block) {
		curr_block->value_file.open("rb");
	}
	
	auto block = std::make_shared<block_t>();
	block->index = curr_block ? curr_block->index + 1 : 0;
	block->key_file.open(get_file_path("key", block->index), "ab+");
	block->value_file.open(get_file_path("value", block->index), "ab+");
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

void Server::read_loop()
{
	const int page_size = ::sysconf(_SC_PAGE_SIZE);
	
	while(vnx_do_run())
	{
		read_item_t request;
		{
			std::unique_lock<std::mutex> lock(read_mutex);
			while(vnx_do_run() && read_queue.empty()) {
				read_condition.wait(lock);
			}
			if(vnx_do_run()) {
				request = read_queue.front();
				read_queue.pop();
			} else {
				break;
			}
		}
		std::shared_ptr<Value> value;
		
		const size_t offset = request.offset % page_size;
		const size_t length = request.num_bytes + offset;
		
		const char* p_map = (const char*)::mmap(0, length, PROT_READ, MAP_PRIVATE,
								request.fd, request.offset - offset);
		
		if(p_map != MAP_FAILED)
		{
			PointerInputStream stream(p_map + offset, request.num_bytes);
			TypeInput in(&stream);
			try {
				value = vnx::read(in);
			}
			catch(...) {
				// ignore for now
			}
			::munmap((void*)p_map, length);
			num_bytes_read += request.num_bytes;
		}
		if(request.result) {
			request.result->callback(value);
		}
		if(request.result_many) {
			request.result_many->values[request.index] = value;
			if(++request.result_many->num_left == 0) {
				request.result_many->callback(request.result_many->values);
			}
		}
	}
}


} // keyvalue
} // vnx
