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

void Server::lock_file_exclusive(const File& file)
{
	while(::flock(::fileno(file.get_handle()), LOCK_EX | LOCK_NB)) {
		log(WARN).out << "Cannot lock file: '" << file.get_name() << "'";
		::usleep(1000 * 1000);
	}
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
						auto& index = key_map[index_entry->key];
						if(index.block_index >= 0) {
							auto old_block = get_block(index.block_index);
							old_block->num_bytes_used -= index_entry->num_bytes;
						}
						index.block_index = block_index;
						index.block_offset = index_entry->block_offset;
						index.num_bytes = index_entry->num_bytes;
						
						curr_version = std::max(curr_version, index_entry->version);
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
		log(INFO).out << "Got " << key_map.size() << " entries.";
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
	
	close_block(get_current_block());
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

void Server::sync_all(const TopicPtr& topic)
{
	if(block_map.empty()) {
		throw std::runtime_error("collection empty");
	}
	
	auto job = std::make_shared<sync_job_t>();
	job->id = next_sync_id++;
	job->topic = topic;
	job->curr_block = block_map.begin()->second;
	sync_jobs[job->id] = job;
	
	auto info = SyncInfo::create();
	info->collection = collection;
	info->code = SyncInfo::BEGIN;
	publish(info, topic, BLOCKING);
	
	block_sync_start(job);
	log(INFO).out << "Started sync job " << job->id << " ...";
}

void Server::block_sync_start(std::shared_ptr<sync_job_t> job)
{
	auto block = job->curr_block;
	job->items.clear();
	{
		auto key_stream = block->key_file.mmap_read();
		TypeInput key_in(key_stream.get());
		try {
			while(vnx_do_run())
			{
				auto entry = vnx::read(key_in);
				{
					auto index_entry = std::dynamic_pointer_cast<IndexEntry>(entry);
					if(index_entry) {
						auto iter = key_map.find(index_entry->key);
						if(iter != key_map.end()) {
							if(iter->second.block_index == block->index
								&& iter->second.block_offset == index_entry->block_offset)
							{
								job->items.push_back(index_entry);
							}
						}
					}
				}
			}
		} catch(const std::underflow_error& ex) {
			// all good
		}
	}
	block->num_pending++;
	job->fd = ::fileno(block->value_file.get_handle());
	job->thread = std::thread(&Server::sync_loop, this, job);
}

void Server::block_sync_finished(const int64_t& job_id)
{
	auto iter = sync_jobs.find(job_id);
	if(iter == sync_jobs.end()) {
		return;
	}
	auto job = iter->second;
	if(job->thread.joinable()) {
		job->thread.join();
	}
	auto next = block_map.upper_bound(job->curr_block->index);
	if(next != block_map.end()) {
		job->curr_block = next->second;
		block_sync_start(job);
	} else {
		auto info = SyncInfo::create();
		info->collection = collection;
		info->code = SyncInfo::END;
		publish(info, job->topic, BLOCKING);
		
		log(INFO).out << "Finished sync job " << job->id;
		sync_jobs.erase(iter);
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
		entry.version = version;
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
	
	if(block->num_bytes_total >= max_block_size) {
		add_new_block();
	}
	return index;
}

void Server::store_value(const Variant& key, const std::shared_ptr<const Value>& value)
{
	if(value)
	{
		const auto index = store_value_internal(key, value, curr_version + 1);
		curr_version++;
		
		if(update_topic) {
			auto pair = KeyValuePair::create();
			pair->collection = collection;
			pair->version = curr_version;
			pair->key = key;
			pair->value = value;
			publish(pair, update_topic, BLOCKING);
		}
		write_counter++;
		num_bytes_written += index.num_bytes;
	}
	else {
		delete_value(key);
	}
}

void Server::delete_value(const Variant& key)
{
	auto iter = key_map.find(key);
	if(iter == key_map.end()) {
		throw std::runtime_error("unknown key");
	}
	delete_value_internal(key, iter->second, curr_version + 1);
	curr_version++;
	
	if(update_topic) {
		auto pair = KeyValuePair::create();
		pair->collection = collection;
		pair->version = curr_version;
		pair->key = key;
		pair->value = 0;
		publish(pair, update_topic, BLOCKING);
	}
	key_map.erase(iter);
}

void Server::delete_value_internal(const Variant& key, const key_index_t& index, uint64_t version)
{
	auto block = get_current_block();
	auto& key_out = block->key_file.out;
	const int64_t prev_key_pos = key_out.get_output_pos();
	try {
		DeleteEntry entry;
		entry.key = key;
		entry.version = version;
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
		
		block_map[block->index] = block;
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
						if(iter->second.block_index == block->index
							&& iter->second.block_offset == index_entry->block_offset)
						{
							auto stream = block->value_file.mmap_read(index_entry->block_offset, index_entry->num_bytes);
							TypeInput value_in(stream.get());
							auto value = vnx::read(value_in);
							store_value_internal(index_entry->key, value, index_entry->version);
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
	for(int i = 0; i < NUM_INDEX; ++i) {
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

void Server::sync_loop(std::shared_ptr<const sync_job_t> job)
{
	Publisher publisher;
	
	for(const auto& entry : job->items)
	{
		std::shared_ptr<Value> value;
		{
			MappedMemoryInputStream stream(job->fd, entry->num_bytes, entry->block_offset);
			TypeInput in(&stream);
			try {
				value = vnx::read(in);
			} catch(...) {
				// ignore for now
			}
		}
		
		auto pair = KeyValuePair::create();
		pair->collection = collection;
		pair->version = entry->version;
		pair->key = entry->key;
		pair->value = value;
		publisher.publish(pair, job->topic, BLOCKING);
	}
	job->curr_block->num_pending--;
	
	ServerClient client(vnx_name);
	client.block_sync_finished_async(job->id);
}


} // keyvalue
} // vnx
