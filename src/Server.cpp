/*
 * Server.cpp
 *
 *  Created on: Mar 11, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/Server.h>
#include <vnx/keyvalue/IndexEntry.hxx>
#include <vnx/keyvalue/TypeEntry.hxx>
#include <vnx/keyvalue/CloseEntry.hxx>
#include <vnx/keyvalue/KeyValuePair.hxx>
#include <vnx/keyvalue/SyncInfo.hxx>
#include <vnx/keyvalue/ServerClient.hxx>

#include <sys/mman.h>
#include <sys/file.h>
#include <unistd.h>


namespace vnx {
namespace keyvalue {

Server::Server(const std::string& _vnx_name)
	:	ServerBase(_vnx_name)
{
}

void Server::init()
{
	vnx::open_pipe(vnx_name, this, max_queue_ms);
}

void Server::main()
{
	for(int i = 0; i < NUM_INDEX; ++i) {
		const auto path = get_file_path("index", i);
		coll_index = vnx::read_from_file<Collection>(path);
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
	coll_index->delete_list.clear();
	
	for(const auto block_index : coll_index->block_list)
	{
		log(INFO).out << "Reading block " << block_index << " ...";
		
		auto block = std::make_shared<block_t>();
		block->index = block_index;
		block->key_file.open(get_file_path("key", block_index), "rb");
		block->value_file.open(get_file_path("value", block_index), "rb");
		lock_file_exclusive(block->key_file);
		lock_file_exclusive(block->value_file);
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
						auto& key_version = key_map[index_entry->key];
						if(index_entry->version > key_version) {
							if(key_version) {
								delete_version(key_version);
							}
							key_version = index_entry->version;
							
							auto& index = index_map[index_entry->version];
							index.block_index = block_index;
							index.block_offset = index_entry->block_offset;
							index.block_offset_key = prev_key_pos;
							index.num_bytes = index_entry->num_bytes;
							index.num_bytes_key = key_in.get_input_pos() - prev_key_pos;
							
							curr_version = std::max(curr_version, index_entry->version);
							block->num_bytes_used += index_entry->num_bytes;
							block->num_bytes_total += index_entry->num_bytes;
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
			{
				// TODO: test this
				block->key_file.open("rb+");
				block->key_file.seek_to(prev_key_pos);
				block->value_file.seek_to(value_end_pos);
				close_block(block);
				block->key_file.open("rb");
				lock_file_exclusive(block->key_file);
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
		{
			const auto out_pos = block->key_file.get_output_pos();
			block->key_file.open("rb+");
			block->key_file.seek_to(out_pos);
		}
		{
			const auto out_pos = block->value_file.get_output_pos();
			block->value_file.open("rb+");
			block->value_file.seek_to(out_pos);
		}
		lock_file_exclusive(block->key_file);
		lock_file_exclusive(block->value_file);
		log(INFO).out << "Got " << key_map.size() << " entries.";
	}
	
	write_index();
	
	read_threads.resize(num_read_threads);
	for(int i = 0; i < num_read_threads; ++i) {
		read_threads[i] = std::thread(&Server::read_loop, this);
	}
	
	if(update_topic) {
		update_thread = std::thread(&Server::update_loop, this);
	}
	
	set_timer_millis(1000, std::bind(&Server::print_stats, this));
	set_timer_millis(rewrite_interval * 1000, std::bind(&Server::check_rewrite, this, false));
	set_timer_millis(idle_rewrite_interval * 1000, std::bind(&Server::check_rewrite, this, true));
	
	rewrite.timer = add_timer(std::bind(&Server::rewrite_func, this));
	
	Super::main();
	
	close_block(get_current_block());
	
	for(auto& entry : sync_jobs) {
		if(entry.second.joinable()) {
			entry.second.join();
		}
	}
	
	update_condition.notify_all();
	if(update_thread.joinable()) {
		update_thread.join();
	}
	
	read_condition.notify_all();
	for(auto& thread : read_threads) {
		if(thread.joinable()) {
			thread.join();
		}
	}
}

void Server::enqueue_read(	std::shared_ptr<block_t> block,
							const key_index_t& index,
							std::shared_ptr<read_result_t> result,
							std::shared_ptr<read_result_many_t> result_many,
							uint32_t result_index) const
{
	read_item_t item;
	item.block = block;
	item.result_index = result_index;
	item.fd = ::fileno(block->value_file.get_handle());
	item.offset = index.block_offset;
	item.num_bytes = index.num_bytes;
	item.result = result;
	item.result_many = result_many;
	{
		std::unique_lock<std::mutex> lock(read_mutex);
		read_queue.emplace(std::move(item));
		block->num_pending++;
	}
	read_condition.notify_one();
	
	read_counter++;
	num_bytes_read += index.num_bytes;
}

void Server::get_value_async(	const Variant& key,
								const std::function<void(const std::shared_ptr<const Value>&)>& callback,
								const vnx::request_id_t& request_id) const
{
	try {
		auto index = get_key_index(key);
		auto block = get_block(index.block_index);
		
		auto result = std::make_shared<read_result_t>();
		result->callback = callback;
		
		enqueue_read(block, index, result);
	}
	catch(const std::exception& ex) {
		callback(0);	// return null
	}
}

void Server::get_values_async(	const std::vector<Variant>& keys,
								const std::function<void(const std::vector<std::shared_ptr<const Value>>&)>& callback,
								const vnx::request_id_t& request_id) const
{
	auto result = std::make_shared<read_result_many_t>();
	result->callback = callback;
	result->num_left = keys.size();
	result->values.resize(keys.size());
	
	for(size_t i = 0; i < keys.size(); ++i) {
		try {
			auto index = get_key_index(keys[i]);
			auto block = get_block(index.block_index);
			
			enqueue_read(block, index, 0, result, i);
		}
		catch(...) {
			// ignore
		}
	}
}

void Server::sync_from(const TopicPtr& topic, const uint64_t& version)
{
	sync_range(topic, version, 0);
}

void Server::sync_range(const TopicPtr& topic, const uint64_t& begin, const uint64_t& end)
{
	const auto job_id = next_sync_id++;
	sync_jobs[job_id] = std::thread(&Server::sync_loop, this, job_id, topic, begin, end);
	
	log(INFO).out << "Started sync job " << job_id << " ...";
}

void Server::sync_all(const TopicPtr& topic)
{
	sync_range(topic, 0, 0);
}

void Server::block_sync_finished(const int64_t& job_id)
{
	auto iter = sync_jobs.find(job_id);
	if(iter != sync_jobs.end()) {
		if(iter->second.joinable()) {
			iter->second.detach();
		}
		sync_jobs.erase(iter);
		
		log(INFO).out << "Finished sync job " << job_id;
	}
}

Server::key_index_t Server::store_value_internal(const Variant& key, const std::shared_ptr<const Value>& value, uint64_t version)
{
	auto block = get_current_block();
	if(!block) {
		throw std::runtime_error("storage closed");
	}
	
	auto& key_out = block->key_file.out;
	auto& value_out = block->value_file.out;
	
	auto prev_key_pos = key_out.get_output_pos();
	auto prev_value_pos = value_out.get_output_pos();
	
	try {
		if(value) {
			auto type_code = value->get_type_code();
			if(type_code) {
				TypeEntry entry;
				entry.block_offset = value_out.get_output_pos();
				if(value_out.write_type_code(type_code)) {
					vnx::write(key_out, entry);
					block->key_file.flush();
					block->value_file.flush();
				}
			}
		}
	}
	catch(const std::exception& ex)
	{
		block->key_file.seek_to(prev_key_pos);
		block->value_file.seek_to(prev_value_pos);
		log(WARN).out << "store_value(): " << ex.what();
		throw;
	}
	
	prev_key_pos = key_out.get_output_pos();
	prev_value_pos = value_out.get_output_pos();
	
	IndexEntry entry;
	try {
		entry.key = key;
		entry.version = version;
		entry.block_offset = prev_value_pos;
		vnx::write(value_out, value);
		block->value_file.flush();
		
		entry.num_bytes = value_out.get_output_pos() - entry.block_offset;
		vnx::write(key_out, entry);
		block->key_file.flush();
	}
	catch(const std::exception& ex)
	{
		block->key_file.seek_to(prev_key_pos);
		block->value_file.seek_to(prev_value_pos);
		log(WARN).out << "store_value(): " << ex.what();
		throw;
	}
	
	key_index_t ret;
	{
		std::lock_guard<std::mutex> lock(index_mutex);
		
		auto& key_version = key_map[key];
		if(key_version) {
			delete_version(key_version);
		}
		key_version = version;
		
		key_index_t& index = index_map[version];
		index.block_index = block->index;
		index.block_offset = entry.block_offset;
		index.block_offset_key = prev_key_pos;
		index.num_bytes = entry.num_bytes;
		index.num_bytes_key = key_out.get_output_pos() - prev_key_pos;
		ret = index;
	}
	block->num_bytes_used += entry.num_bytes;
	block->num_bytes_total += entry.num_bytes;
	
	if(block->num_bytes_total >= max_block_size) {
		add_new_block();
	}
	return ret;
}

void Server::store_value(const Variant& key, const std::shared_ptr<const Value>& value)
{
	const auto index = store_value_internal(key, value, curr_version + 1);
	curr_version++;
	
	if(update_topic) {
		auto pair = KeyValuePair::create();
		pair->collection = collection;
		pair->version = curr_version;
		pair->key = key;
		pair->value = value;
		{
			std::unique_lock<std::mutex> lock(update_mutex);
			update_queue.push(pair);
		}
		update_condition.notify_one();
	}
	write_counter++;
	num_bytes_written += index.num_bytes;
}

void Server::delete_value(const Variant& key)
{
	store_value(key, 0);
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
	auto iter2 = index_map.find(iter->second);
	if(iter2 == index_map.end()) {
		throw std::runtime_error("unknown version: " + std::to_string(iter->second));
	}
	return iter2->second;
}

void Server::delete_version(uint64_t version)
{
	// index_mutex needs to be locked by caller
	auto iter = index_map.find(version);
	if(iter != index_map.end()) {
		const auto& index = iter->second;
		if(index.block_index >= 0) {
			try {
				auto old_block = get_block(index.block_index);
				old_block->num_bytes_used -= index.num_bytes;
			} catch(...) {
				// ignore
			}
		}
		index_map.erase(iter);
	}
}

void Server::close_block(std::shared_ptr<block_t> block)
{
	try {
		CloseEntry entry;
		entry.block_offset = block->value_file.get_output_pos();
		vnx::write(block->key_file.out, entry);
		block->key_file.flush();
	}
	catch(const std::exception& ex) {
		log(ERROR).out << "Failed to close block " << block->index << ": " << ex.what();
	}
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
		
		lock_file_exclusive(block->key_file);
		lock_file_exclusive(block->value_file);
		{
			std::lock_guard<std::mutex> lock(index_mutex);
			block_map[block->index] = block;
		}
		write_index();
	}
	catch(const std::exception& ex) {
		log(ERROR).out << "Failed to write new block " << block->index << ": " << ex.what();
		return curr_block;
	}
	if(curr_block) {
		close_block(curr_block);
	}
	log(INFO).out << "Added new block " << block->index;
	return block;
}

void Server::check_rewrite(bool is_idle)
{
	if(!rewrite.block) {
		for(const auto& entry : block_map) {
			if(entry.first != get_current_block()->index) {
				auto block = entry.second;
				const double use_factor = double(block->num_bytes_used) / block->num_bytes_total;
				if(use_factor < rewrite_threshold || (is_idle && use_factor < idle_rewrite_threshold))
				{
					log(INFO).out << "Rewriting block " << block->index << " with use factor " << float(100 * use_factor) << " % ...";
					rewrite.block = block;
					rewrite.timer->set_millis(0);
					break;
				}
			}
		}
	}
	{
		std::lock_guard<std::mutex> lock(index_mutex);
		
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
		uint64_t num_bytes = 0;
		for(int i = 0; i < 100; ++i) {
			auto entry = vnx::read(*rewrite.key_in);
			auto index_entry = std::dynamic_pointer_cast<IndexEntry>(entry);
			if(index_entry) {
				auto iter = key_map.find(index_entry->key);
				if(iter != key_map.end()) {
					if(index_entry->version == iter->second)
					{
						auto stream = block->value_file.mmap_read(index_entry->block_offset, index_entry->num_bytes);
						TypeInput value_in(stream.get());
						auto value = vnx::read(value_in);
						store_value_internal(index_entry->key, value, index_entry->version);
						
						num_bytes += index_entry->num_bytes;
						if(num_bytes >= 16384) {
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
			for(const auto& entry : index_map) {
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
		
		{
			std::lock_guard<std::mutex> lock(index_mutex);
			block_map.erase(block->index);
			delete_list.push_back(block);
		}
		coll_index->delete_list.push_back(block->index);
		write_index();
		
		rewrite.key_in = 0;
		rewrite.key_stream = 0;
		rewrite.block = 0;
		check_rewrite(false);
	}
	catch(const std::exception& ex) {
		log(ERROR).out << "Block " << block->index << " rewrite: " << ex.what();
	}
}

void Server::write_index()
{
	coll_index->block_list.clear();
	for(const auto& entry : block_map) {
		coll_index->block_list.push_back(entry.first);
	}
	for(int i = 0; i < NUM_INDEX; ++i) {
		try {
			vnx::write_to_file(get_file_path("index", i), coll_index);
		} catch(const std::exception& ex) {
			log(ERROR).out << "Failed to write collection index " << i << ": " << ex.what();
		}
	}
}

void Server::lock_file_exclusive(const File& file)
{
	while(::flock(::fileno(file.get_handle()), LOCK_EX | LOCK_NB)) {
		log(WARN).out << "Cannot lock file: '" << file.get_name() << "'";
		::usleep(1000 * 1000);
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

void Server::read_loop() const
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
			TypeInput in(&stream);
			try {
				value = vnx::read(in);
			} catch(...) {
				// ignore for now
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

void Server::update_loop() const
{
	Publisher publisher;
	
	while(vnx_do_run())
	{
		std::shared_ptr<KeyValuePair> value;
		{
			std::unique_lock<std::mutex> lock(update_mutex);
			while(vnx_do_run() && update_queue.empty()) {
				update_condition.wait(lock);
			}
			if(vnx_do_run()) {
				value = update_queue.front();
				update_queue.pop();
			} else {
				break;
			}
		}
		publisher.publish(value, update_topic);
	}
}

void Server::sync_loop(int64_t job_id, TopicPtr topic, uint64_t begin, uint64_t end) const
{
	Publisher publisher;
	uint64_t version = begin;
	uint64_t previous = begin;
	
	auto info = SyncInfo::create();
	info->collection = collection;
	info->version = begin;
	info->code = SyncInfo::BEGIN;
	publisher.publish(info, topic, BLOCKING);
	
	struct entry_t {
		uint64_t version;
		key_index_t index;
		std::shared_ptr<block_t> block;
	};
	
	std::vector<entry_t> list;
	
	while(vnx_do_run())
	{
		list.clear();
		{
			std::unique_lock<std::mutex> lock(index_mutex);
			
			auto iter = index_map.upper_bound(version);
			for(int i = 0; iter != index_map.end() && i < 100; ++iter, ++i)
			{
				version = iter->first;
				if(end > 0 && version >= end) {
					break;
				}
				try {
					entry_t entry;
					entry.version = version;
					entry.index = iter->second;
					entry.block = get_block(entry.index.block_index);
					entry.block->num_pending++;
					list.emplace_back(std::move(entry));
				}
				catch(...) {
					// ignore
				}
			}
		}
		if(list.empty()) {
			break;
		}
		for(const auto& entry : list)
		{
			const auto& block = entry.block;
			const auto& index = entry.index;
			std::shared_ptr<IndexEntry> index_entry;
			{
				auto stream = block->key_file.mmap_read(index.block_offset_key, index.num_bytes_key);
				TypeInput in(stream.get());
				try {
					index_entry = std::dynamic_pointer_cast<IndexEntry>(vnx::read(in));
				} catch(...) {
					// ignore
				}
			}
			if(index_entry) {
				std::shared_ptr<Value> value;
				{
					auto stream = block->value_file.mmap_read(index.block_offset, index.num_bytes);
					TypeInput in(stream.get());
					try {
						value = vnx::read(in);
					} catch(...) {
						// ignore
					}
				}
				auto pair = KeyValuePair::create();
				pair->collection = collection;
				pair->version = entry.version;
				pair->previous = previous;
				pair->key = index_entry->key;
				pair->value = value;
				publisher.publish(pair, topic, BLOCKING);
				previous = entry.version;
			}
			block->num_pending--;
			read_counter++;
			num_bytes_read += index.num_bytes_key + index.num_bytes;
		}
	}
	if(vnx_do_run())
	{
		auto info = SyncInfo::create();
		info->collection = collection;
		info->version = version;
		info->code = SyncInfo::END;
		publisher.publish(info, topic, BLOCKING);
		
		ServerClient client(vnx_name);
		client.block_sync_finished(job_id);
	}
}


} // keyvalue
} // vnx
