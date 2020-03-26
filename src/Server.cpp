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
#include <vnx/keyvalue/CloseEntry.hxx>

#include <sys/mman.h>
#include <unistd.h>


namespace vnx {
namespace keyvalue {

Server::Server(const std::string& _vnx_name)
	:	ServerBase(_vnx_name)
{
}

void Server::init()
{
	vnx::open_pipe(vnx_name, this, UNLIMITED);
}

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
	
	for(const auto block_index : coll_index->delete_list)
	{
		try {
			File file(get_file_path("key", block_index));
			file.remove();
			log(INFO).out << "Deleted old key file from block " << block_index;
		} catch(...) {
			// ignore
		}
		try {
			File file(get_file_path("value", block_index));
			file.remove();
			log(INFO).out << "Deleted old value file from block " << block_index;
		} catch(...) {
			// ignore
		}
	}
	
	for(const auto block_index : coll_index->block_list)
	{
		log(INFO).out << "Reading block " << block_index << " ...";
		
		auto block = std::make_shared<block_t>();
		block->index = block_index;
		block->key_file.open(get_file_path("key", block_index), "rb+");
		block->value_file.open(get_file_path("value", block_index), "rb");
		block_map[block_index] = block;
		
		auto& key_in = block->key_file.in;
		auto& value_in = block->value_file.in;
		
		bool is_error = false;
		int64_t prev_key_pos = 0;
		int64_t value_end_pos = -1;
		
		while(vnx_do_run())
		{
			prev_key_pos = key_in.get_input_pos();
			try {
				auto entry = vnx::read(key_in);
				{
					auto index_entry = std::dynamic_pointer_cast<IndexEntry>(entry);
					if(index_entry) {
						auto& index = key_map[index_entry->key];
						if(index.block_index >= 0) {
							auto old_block = get_block(index.block_index);
							old_block->num_bytes_used -= index_entry->num_bytes;
						}
						index.block_index = block_index;
						index.block_offset = index_entry->block_offset;
						index.num_bytes = index_entry->num_bytes;
						block->num_bytes_used += index_entry->num_bytes;
						block->num_bytes_total += index_entry->num_bytes;
					}
				}
				{
					auto delete_entry = std::dynamic_pointer_cast<DeleteEntry>(entry);
					if(delete_entry) {
						auto iter = key_map.find(delete_entry->key);
						if(iter != key_map.end()) {
							block->num_bytes_used -= iter->second.num_bytes;
							key_map.erase(iter);
						}
					}
				}
				{
					auto type_entry = std::dynamic_pointer_cast<TypeEntry>(entry);
					if(type_entry) {
						value_in.reset();
						block->value_file.seek_to(type_entry->block_offset);
						while(vnx_do_run()) {
							try {
								uint16_t code = 0;
								vnx::read(value_in, code);
								if(code == CODE_TYPE_CODE || code == CODE_ALT_TYPE_CODE) {
									vnx::read_type_code(value_in);
								} else {
									break;
								}
							} catch(const std::underflow_error& ex) {
								break;
							} catch(const std::exception& ex) {
								log(WARN).out << "Error while reading type codes from block "
										<< block_index << ": " << ex.what();
								break;
							}
						}
					}
				}
				{
					auto close_entry = std::dynamic_pointer_cast<CloseEntry>(entry);
					if(close_entry) {
						value_end_pos = close_entry->block_offset;
						break;
					}
				}
			}
			catch(const std::exception& ex) {
				log(WARN).out << "Error reading block " << block_index << " key file: " << ex.what();
				is_error = true;
				break;
			}
		}
		
		if(is_error) {
			log(INFO).out << "Verifying block " << block->index << " ...";
			value_in.reset();
			block->value_file.seek_begin();
			while(vnx_do_run())
			{
				value_end_pos = value_in.get_input_pos();
				try {
					vnx::skip(value_in);
				} catch(...) {
					break;
				}
			}
			log(INFO).out << "Done verifying block " << block->index << ": " << value_end_pos << " bytes";
		}
		
		block->key_file.seek_to(prev_key_pos);
		block->value_file.seek_to(value_end_pos);
	}
	
	for(const auto& entry : block_map) {
		auto block = entry.second;
		log(INFO).out << "Block " << block->index << ": " << block->num_bytes_used << " bytes used, "
				<< block->num_bytes_total << " bytes total, "
				<< 100 * float(block->num_bytes_used) / block->num_bytes_total << " % use factor";
	}
	
	if(block_map.empty()) {
		add_new_block();
	} else {
		auto block = get_current_block();
		const auto out_pos = block->value_file.get_output_pos();
		block->value_file.open("rb+");
		block->value_file.seek_to(out_pos);
	}
	
	write_index();
	
	read_threads.resize(num_read_threads);
	for(int i = 0; i < num_read_threads; ++i) {
		read_threads[i] = std::thread(&Server::read_loop, this);
	}
	
	set_timer_millis(1000, std::bind(&Server::print_stats, this));
	set_timer_millis(10 * 1000, std::bind(&Server::check_rewrite, this));
	
	rewrite.timer = add_timer(std::bind(&Server::rewrite_func, this));
	
	Super::main();
	
	read_condition.notify_all();
	for(auto& thread : read_threads) {
		if(thread.joinable()) {
			thread.join();
		}
	}
	
	for(const auto& entry : block_map)
	{
		auto block = entry.second;
		try {
			CloseEntry entry;
			entry.block_offset = block->value_file.get_output_pos();
			vnx::write(block->key_file.out, entry);
			block->key_file.flush();
		}
		catch(const std::exception& ex) {
			log(ERROR).out << "Failed to close block " << block->index << ": " << ex.what();
		}
		block->key_file.close();
		block->value_file.close();
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
	item.block = block;
	item.fd = ::fileno(block->value_file.get_handle());
	item.offset = index.block_offset;
	item.num_bytes = index.num_bytes;
	item.result = result;
	{
		std::lock_guard<std::mutex> lock(read_mutex);
		read_queue.push(item);
		block->num_pending++;
	}
	read_condition.notify_one();
	num_bytes_read += index.num_bytes;
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
		item.block = block;
		item.result_index = i;
		item.fd = ::fileno(block->value_file.get_handle());
		item.offset = index.block_offset;
		item.num_bytes = index.num_bytes;
		item.result_many = result;
		{
			std::lock_guard<std::mutex> lock(read_mutex);
			read_queue.push(item);
			block->num_pending++;
		}
		read_condition.notify_one();
		num_bytes_read += index.num_bytes;
	}
}

void Server::store_value(const Variant& key, const std::shared_ptr<const Value>& value)
{
	auto block = get_current_block();
	if(!block) {
		throw std::runtime_error("storage closed");
	}
	
	auto& key_out = block->key_file.out;
	auto& value_out = block->value_file.out;
	
	const int64_t prev_key_pos = key_out.get_output_pos();
	const int64_t prev_value_pos = value_out.get_output_pos();
	
	IndexEntry entry;
	try {
		auto type_code = value->get_type_code();
		if(type_code) {
			TypeEntry entry;
			entry.block_offset = value_out.get_output_pos();
			if(value_out.write_type_code(type_code)) {
				vnx::write(key_out, entry);
			}
		}
		entry.key = key;
		entry.block_offset = value_out.get_output_pos();
		vnx::write(value_out, value);
		block->value_file.flush();
		
		entry.num_bytes = value_out.get_output_pos() - entry.block_offset;
		vnx::write(key_out, entry);
		block->key_file.flush();	// key file last
	}
	catch(const std::exception& ex)
	{
		block->key_file.seek_to(prev_key_pos);
		block->value_file.seek_to(prev_value_pos);
		log(WARN).out << "store_value(): " << ex.what();
		throw;
	}
	
	key_index_t& index = key_map[key];
	
	if(index.block_index >= 0) {
		try {
			auto old_block = get_block(index.block_index);
			old_block->num_bytes_used -= index.num_bytes;
		} catch(...) {
			// ignore
		}
	}
	
	index.block_index = block->index;
	index.block_offset = entry.block_offset;
	index.num_bytes = entry.num_bytes;
	
	block->num_bytes_used += entry.num_bytes;
	block->num_bytes_total += entry.num_bytes;
	
	write_counter++;
	num_bytes_written += entry.num_bytes;
	
	if(block->num_bytes_total >= max_block_size) {
		add_new_block();
	}
}

void Server::delete_value(const Variant& key)
{
	auto iter = key_map.find(key);
	if(iter == key_map.end()) {
		throw std::runtime_error("unknown key");
	}
	delete_value(key, iter->second);
	key_map.erase(iter);
}

void Server::delete_value(const Variant& key, const key_index_t& index)
{
	auto block = get_block(index.block_index);
	auto& key_out = block->key_file.out;
	const int64_t prev_key_pos = key_out.get_output_pos();
	try {
		DeleteEntry entry;
		entry.key = key;
		vnx::write(key_out, entry);
		block->key_file.flush();
		block->num_bytes_used -= index.num_bytes;
	}
	catch(const std::exception& ex) {
		block->key_file.seek_to(prev_key_pos);
		log(WARN).out << "delete_value(): " << ex.what();
		throw;
	}
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
		throw std::runtime_error("unknown block: " + std::to_string(index));
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
	
	std::shared_ptr<block_t> block = std::make_shared<block_t>();
	try {
		block->index = curr_block ? curr_block->index + 1 : 0;
		block->key_file.open(get_file_path("key", block->index), "wb");
		block->value_file.open(get_file_path("value", block->index), "wb");
		block->key_file.write_header();
		block->value_file.write_header();
		block->key_file.open("rb+");
		block->value_file.open("rb+");
		block->key_file.seek_end();
		block->value_file.seek_end();
		
		block_map[block->index] = block;
		write_index();
	}
	catch(const std::exception& ex) {
		log(ERROR).out << "Failed to write new block " << block->index << ": " << ex.what();
		return curr_block;
	}
	log(INFO).out << "Added new block " << block->index;
	return block;
}

void Server::check_rewrite()
{
	if(!rewrite.block) {
		for(auto entry : block_map) {
			if(entry.first != get_current_block()->index) {
				auto block = entry.second;
				const double use_factor = double(block->num_bytes_used) / block->num_bytes_total;
				if(use_factor < rewrite_threshold)
				{
					log(INFO).out << "Rewriting block " << block->index << " with use factor " << float(100 * use_factor) << " % ...";
					rewrite.block = block;
					rewrite.timer->set_millis(0);
					break;
				}
			}
		}
	}
	
	auto iter = delete_list.begin();
	while(iter != delete_list.end()) {
		auto block = *iter;
		if(block->num_pending == 0) {
			block->key_file.remove();
			block->value_file.remove();
			iter = delete_list.erase(iter);
		} else {
			iter++;
		}
	}
}

void Server::rewrite_func()
{
	auto block = rewrite.block;
	if(!block) {
		return;
	}
	if(!rewrite.key_stream) {
		auto stream = block->key_file.mmap_read();
		if(!stream->is_valid()) {
			log(ERROR).out << "Block " << block->index << " rewrite: mmap() failed!";
			return;
		}
		rewrite.key_stream = stream;
		rewrite.key_in = std::make_shared<TypeInput>(stream.get());
	}
	try {
		for(int i = 0; i < 100; ++i) {
			auto entry = vnx::read(*rewrite.key_in);
			{
				auto index_entry = std::dynamic_pointer_cast<IndexEntry>(entry);
				if(index_entry) {
					auto iter = key_map.find(index_entry->key);
					if(iter != key_map.end()) {
						if(iter->second.block_index == block->index) {
							auto stream = block->value_file.mmap_read(index_entry->block_offset, index_entry->num_bytes);
							TypeInput value_in(stream.get());
							auto value = vnx::read(value_in);
							store_value(index_entry->key, value);
							break;
						}
					}
				}
			}
		}
		rewrite.timer->set_millis(0);
	}
	catch(const std::underflow_error& ex)
	{
		if(do_verify_rewrite) {
			bool is_fail = false;
			for(const auto& entry : key_map) {
				if(entry.second.block_index == block->index) {
					log(ERROR).out << "Key '" << entry.first << "' still points to block " << block->index;
					is_fail = true;
				}
			}
			if(is_fail) {
				log(ERROR).out << "Rewrite of block " << block->index << " failed.";
				return;
			}
		}
		log(INFO).out << "Rewrite of block " << block->index << " finished.";
		
		block_map.erase(block->index);
		coll_index->delete_list.push_back(block->index);
		write_index();
		
		delete_list.push_back(block);
		rewrite.key_in = 0;
		rewrite.key_stream = 0;
		rewrite.block = 0;
	}
	catch(const std::exception& ex) {
		log(ERROR).out << "Block " << block->index << " rewrite: " << ex.what();
	}
	check_rewrite();
}

void Server::write_index()
{
	coll_index->block_list.clear();
	for(const auto& entry : block_map) {
		coll_index->block_list.push_back(entry.first);
	}
	for(int i = 0; i < 3; ++i) {
		try {
			vnx::write_to_file(get_file_path("index", i), coll_index);
		} catch(const std::exception& ex) {
			log(ERROR).out << "Failed to write collection index " << i << ": " << ex.what();
		}
	}
}

void Server::print_stats()
{
	log(INFO).out << read_counter << " reads/s, " << num_bytes_read/1024 << " KB/s read, "
			<< write_counter << " writes/s, " << num_bytes_written/1024 << " KB/s write";
	read_counter = 0;
	write_counter = 0;
	num_bytes_read = 0;
	num_bytes_written = 0;
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
		{
			MappedMemoryInputStream stream(request.fd, request.num_bytes, request.offset);
			if(stream.is_valid()) {
				TypeInput in(&stream);
				try {
					value = vnx::read(in);
				}
				catch(...) {
					// ignore for now
				}
			}
		}
		request.block->num_pending--;
		
		if(request.result) {
			request.result->callback(value);
		}
		if(request.result_many) {
			request.result_many->values[request.result_index] = value;
			if(++request.result_many->num_left == 0) {
				request.result_many->callback(request.result_many->values);
			}
		}
	}
}


} // keyvalue
} // vnx
