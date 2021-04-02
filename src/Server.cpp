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
#include <vnx/keyvalue/SyncInfo.hxx>
#include <vnx/keyvalue/SyncUpdate.hxx>
#include <vnx/keyvalue/ServerClient.hxx>

#include <vnx/addons/DeflatedValue.hxx>
#include <vnx/Stream.h>

#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_BLOCK_SIZE int64_t(UINT32_MAX)
#define MAX_KEY_SIZE int64_t(UINT32_MAX)
#define MAX_VALUE_SIZE int64_t(UINT32_MAX)


namespace vnx {
namespace keyvalue {

Server::Server(const std::string& _vnx_name)
	:	ServerBase(_vnx_name)
{
}

void Server::init()
{
	vnx::open_pipe(vnx_name, this, max_queue_ms);
	vnx::open_pipe(domain + collection, this, max_queue_ms);
}

void Server::main()
{
	if(max_block_size > 0xFFFFFFFF) {
		throw std::logic_error("max_block_size > 0xFFFFFFFF");
	}
	if(collection.empty()) {
		throw std::logic_error("invalid collection config");
	}
	
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
			log(INFO) << "Deleted old key file from block " << block_index;
		} catch(...) {
			// ignore
		}
		try {
			File file(get_file_path("value", block_index));
			file.remove();
			log(INFO) << "Deleted old value file from block " << block_index;
		} catch(...) {
			// ignore
		}
	}
	coll_index->delete_list.clear();
	
	for(const auto block_index : coll_index->block_list)
	{
		log(INFO) << "Reading block " << block_index << " ...";
		try {
			auto block = std::make_shared<block_t>();
			block->index = block_index;
			block->key_file.open(get_file_path("key", block_index), "rb");
			block->value_file.open(get_file_path("value", block_index), "rb");
			lock_file_exclusive(block->key_file);
			lock_file_exclusive(block->value_file);
			block_map[block_index] = block;
			
			auto& key_in = block->key_file.in;
			auto& value_in = block->value_file.in;
			const auto value_block_size = block->value_file.file_size();
			
			bool is_error = false;
			int64_t prev_key_pos = 0;
			int64_t value_end_pos = -1;
			
			try {
				block->key_file.fadvise(POSIX_FADV_SEQUENTIAL);
			} catch(...) {
				// ignore
			}
			
			while(vnx_do_run())
			{
				prev_key_pos = key_in.get_input_pos();
				try {
					auto entry = vnx::read(key_in);
					{
						auto index_entry = std::dynamic_pointer_cast<IndexEntry>(entry);
						if(index_entry) {
							if(index_entry->block_offset + index_entry->num_bytes <= value_block_size)
							{
								const auto value_index = get_value_index(index_entry->key);
								const auto key_iter = value_index.key_iter;
								
								if(key_iter == keyhash_map.cend() || index_entry->version >= key_iter->second)
								{
									delete_internal(value_index);
									keyhash_map.emplace(value_index.key_hash, index_entry->version);
									
									auto& index = index_map[index_entry->version];
									index.block_index = block_index;
									index.block_offset = prev_key_pos;
									index.num_bytes = key_in.get_input_pos() - prev_key_pos;
									
									curr_version = std::max(curr_version, index_entry->version);
									block->num_bytes_used += index_entry->num_bytes;
								}
								block->num_bytes_total += index_entry->num_bytes;
							}
							else {
								log(WARN) << "Lost value for key '" << index_entry->key.to_string_value() << "'";
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
									const auto offset = value_in.get_input_pos();
									uint16_t code = 0;
									vnx::read(value_in, code);
									if(code == CODE_TYPE_CODE || code == CODE_ALT_TYPE_CODE) {
										const auto* type_code = vnx::read_type_code(value_in, &code);
										block->value_file.out.type_code_map[type_code->code_hash] = offset;
									} else {
										break;
									}
								} catch(const std::underflow_error& ex) {
									break;
								} catch(const std::exception& ex) {
									log(WARN) << "Error while reading type codes from block "
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
					log(WARN) << "Error reading block " << block_index << " key file: " << ex.what();
					is_error = true;
					break;
				}
			}
			
			if(is_error) {
				log(INFO) << "Verifying block " << block->index << " ...";
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
					block->key_file.open("rb+");
					block->key_file.seek_to(prev_key_pos);
					block->value_file.seek_to(value_end_pos);
					close_block(block);
					block->key_file.open("rb");
					lock_file_exclusive(block->key_file);
				}
				log(INFO) << "Done verifying block " << block->index << ": " << value_end_pos << " bytes";
			}
			
			block->key_file.seek_to(prev_key_pos);
			block->value_file.seek_to(value_end_pos);
		}
		catch(const std::exception& ex) {
			if(ignore_errors) {
				log(ERROR) << "Failed to read block " << block_index << ": " << ex.what();
			} else {
				throw;
			}
		}
	}
	
	for(const auto& entry : block_map) {
		auto block = entry.second;
		log(INFO) << "Block " << block->index << ": " << block->num_bytes_used << " bytes used, "
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
		log(INFO) << "Got " << keyhash_map.size() << " entries.";
	}
	
	write_index();
	
	threads = std::make_shared<ThreadPool>(num_threads, max_num_pending);
	rewrite_threads = std::make_shared<ThreadPool>(num_threads_rewrite, UNLIMITED);
	sync_threads = std::make_shared<ThreadPool>(-1);
	
	update_thread = std::thread(&Server::update_loop, this);
	
	set_timer_millis(timeout_interval_ms, std::bind(&Server::check_timeouts, this));
	set_timer_millis(rewrite_interval * 1000, std::bind(&Server::check_rewrite, this, false));
	if(idle_rewrite_interval) {
		set_timer_millis(idle_rewrite_interval * 1000, std::bind(&Server::check_rewrite, this, true));
	}
	if(stats_interval_ms) {
		set_timer_millis(stats_interval_ms, std::bind(&Server::print_stats, this));
	}
	
	Super::main();
	
	threads->close();
	sync_threads->close();
	rewrite_threads->close();
	
	update_condition.notify_all();
	if(update_thread.joinable()) {
		update_thread.join();
	}
	
	close_block(get_current_block());
	
	for(const auto& entry : block_map)
	{
		const auto block = entry.second;
		try {
			block->key_file.close();
		} catch(const std::exception& ex) {
			log(ERROR) << "Failed to close key file " << block->index << ": " << ex.what();
		}
		try {
			block->value_file.close();
		} catch(const std::exception& ex) {
			log(ERROR) << "Failed to close value file " << block->index << ": " << ex.what();
		}
	}
}

void Server::get_value_async(const Variant& key, const request_id_t& req_id) const
{
	threads->add_task(std::bind(&Server::read_job, this, key, req_id));
}

void Server::get_value_locked_async(const Variant& key, const int32_t& timeout_ms, const request_id_t& req_id) const
{
	const auto ret = lock_map.emplace(key, lock_entry_t());
	const auto iter = ret.first;
	if(ret.second) {
		aquire_lock(iter, timeout_ms);
		threads->add_task(std::bind(&Server::read_job_locked, this, key, req_id));
	} else {
		auto& entry = iter->second;
		entry.waiting.push_back(std::bind(&Server::get_value_locked_async, this, key, timeout_ms, req_id));
	}
}

void Server::get_values_async(const std::vector<Variant>& keys, const request_id_t& req_id) const
{
	if(keys.empty()) {
		get_values_async_return(req_id, {});
		return;
	}
	auto job = std::make_shared<multi_read_job_t>();
	job->req_id = req_id;
	job->num_left = keys.size();
	job->entries.resize(keys.size());
	
	for(size_t i = 0; i < keys.size(); ++i) {
		threads->add_task(std::bind(&Server::multi_read_job, this, keys[i], i, job));
	}
}

void Server::get_key_async(const uint64_t& version, const vnx::request_id_t& req_id) const
{
	threads->add_task(std::bind(&Server::read_key_job, this, version, req_id));
}

void Server::get_keys_async(const std::vector<uint64_t>& versions, const vnx::request_id_t& req_id) const
{
	if(versions.empty()) {
		get_keys_async_return(req_id, {});
		return;
	}
	auto job = std::make_shared<multi_read_key_job_t>();
	job->req_id = req_id;
	job->num_left = versions.size();
	job->result.resize(versions.size());
	
	for(size_t i = 0; i < versions.size(); ++i) {
		threads->add_task(std::bind(&Server::multi_read_key_job, this, versions[i], i, job));
	}
}

void Server::unlock(const Variant& key)
{
	release_lock(key);
}

void Server::aquire_lock(lock_map_t::iterator iter, int32_t timeout_ms) const
{
	auto& entry = iter->second;
	if(timeout_ms > 0) {
		const auto deadline_ms = vnx::get_wall_time_millis() + timeout_ms;
		entry.queue_iter = lock_queue.emplace(deadline_ms, iter);
	}
	else if(timeout_ms < 0) {
		entry.queue_iter = lock_queue.end();
	}
	else {
		lock_map.erase(iter);
	}
}

void Server::release_lock(lock_map_t::iterator iter)
{
	const auto& entry = iter->second;
	for(const auto& func : entry.waiting) {
		add_task(func);
	}
	if(entry.queue_iter != lock_queue.end()) {
		lock_queue.erase(entry.queue_iter);
	}
	lock_map.erase(iter);
}

void Server::release_lock(const Variant& key)
{
	const auto iter = lock_map.find(key);
	if(iter != lock_map.end()) {
		release_lock(iter);
	}
}

void Server::check_timeouts()
{
	const auto now_ms = vnx::get_wall_time_millis();
	while(!lock_queue.empty())
	{
		const auto iter = lock_queue.begin();
		if(iter->first <= now_ms) {
			release_lock(iter->second);
			num_lock_timeouts++;
		} else {
			break;
		}
	}
	while(!delay_queue.empty())
	{
		const auto iter = delay_queue.begin();
		if(iter->first <= now_ms)
		{
			const auto iter2 = delay_cache.find(iter->second);
			if(iter2 != delay_cache.end())
			{
				const auto& cached = iter2->second;
				if(cached.deadline_ms == iter->first)
				{
					auto entry = cached.entry;
					store_value_version(entry->key, entry->value, entry->version);
				}
			}
			delay_queue.erase(iter);
		} else {
			break;
		}
	}
}

std::shared_ptr<const Entry> Server::read_value(const Variant& key) const
{
	auto entry = Entry::create();
	entry->key = key;
	
	value_index_t index;
	std::shared_ptr<block_t> block;
	{
		std::shared_lock lock(index_mutex);
		{
			const auto iter = delay_cache.find(key);
			if(iter != delay_cache.end()) {
				return iter->second.entry;
			}
		}
		{
			const auto iter = write_cache.find(key);
			if(iter != write_cache.end()) {
				return iter->second;
			}
		}
		index = get_value_index(key);
		if(index.block_index >= 0) {
			block = get_block(index.block_index);
			if(block) {
				block->num_pending++;
			}
			if(index.key_iter != keyhash_map.cend()) {
				entry->version = index.key_iter->second;
			}
		}
	}
	if(!block) {
		return entry;
	}
	if(index.num_bytes > 65536) {
		try {
			block->value_file.fadvise(POSIX_FADV_SEQUENTIAL, index.block_offset, index.num_bytes);
		} catch(...) {
			// ignore
		}
	}
	try {
		FileSectionInputStream stream(block->value_file.get_handle(), index.block_offset, index.num_bytes);
		TypeInput in(&stream);
		entry->value = vnx::read(in);
		num_bytes_read += index.num_bytes;
	} catch(...) {
		// ignore
	}
	block->num_pending--;
	read_counter++;
	if(entry->value) {
		auto decompressed = entry->value->vnx_decompress();
		if(decompressed) {
			entry->value = decompressed;
		}
	}
	return entry;
}

void Server::read_job(const Variant& key, const request_id_t& req_id) const
{
	std::shared_ptr<const Entry> entry;
	try {
		entry = read_value(key);
	} catch(...) {
		// ignore
	}
	get_value_async_return(req_id, entry);
}

void Server::read_job_locked(const Variant& key, const request_id_t& req_id) const
{
	std::shared_ptr<const Entry> entry;
	try {
		entry = read_value(key);
	} catch(...) {
		// ignore
	}
	get_value_locked_async_return(req_id, entry);
}

void Server::multi_read_job(const Variant& key, size_t index, std::shared_ptr<multi_read_job_t> job) const
{
	try {
		job->entries[index] = read_value(key);
	} catch(...) {
		// ignore
	}
	if(job->num_left-- == 1) {
		get_values_async_return(job->req_id, job->entries);
	}
}

void Server::read_key_job(uint64_t version, const request_id_t& req_id) const
{
	std::shared_lock lock(index_mutex);
	
	const auto version_index = get_version_index(version);
	get_key_async_return(req_id, version_index.key);
}

void Server::multi_read_key_job(uint64_t version, size_t index, std::shared_ptr<multi_read_key_job_t> job) const
{
	std::shared_lock lock(index_mutex);
	
	try {
		const auto version_index = get_version_index(version);
		job->result[index] = std::make_pair(version, version_index.key);
	} catch(...) {
		// ignore
	}
	if(job->num_left-- == 1) {
		get_keys_async_return(job->req_id, job->result);
	}
}

void Server::store_compress_job(std::shared_ptr<const Entry> entry)
{
	auto compressed = addons::DeflatedValue::compress_ex(entry->value, compress_level);
	add_task(std::bind(&Server::store_value_version_ex, this, entry->key, entry->value, compressed, entry->version));
}

int64_t Server::sync_range_ex(TopicPtr topic, Hash64 dst_mac, uint64_t begin, uint64_t end, bool key_only) const
{
	auto job = std::make_shared<sync_job_t>();
	job->id = next_sync_id++;
	job->topic = topic;
	job->dst_mac = dst_mac;
	job->begin = begin;
	job->end = end;
	job->key_only = key_only;
	{
		std::lock_guard lock(sync_mutex);
		sync_jobs[job->id] = job;
	}
	sync_threads->add_task(std::bind(&Server::sync_loop, this, job));
	
	log(INFO) << "Started sync job " << job->id << " ...";
	return job->id;
}

int64_t Server::sync_from(const TopicPtr& topic, const uint64_t& version) const
{
	return sync_range(topic, version, 0);
}

int64_t Server::sync_range(const TopicPtr& topic, const uint64_t& begin, const uint64_t& end) const
{
	return sync_range_ex(topic, Hash64(), begin, end, false);
}

int64_t Server::sync_all(const TopicPtr& topic) const
{
	return sync_range_ex(topic, Hash64(), 0, 0, false);
}

int64_t Server::sync_all_keys(const TopicPtr& topic) const
{
	return sync_range_ex(topic, Hash64(), 0, 0, true);
}

int64_t Server::sync_all_private(const Hash64& dst_mac) const
{
	return sync_range_ex(nullptr, dst_mac, 0, 0, false);
}

int64_t Server::sync_all_keys_private(const Hash64& dst_mac) const
{
	return sync_range_ex(nullptr, dst_mac, 0, 0, true);
}

void Server::cancel_sync_job(const int64_t& job_id)
{
	std::lock_guard lock(sync_mutex);
	
	const auto iter = sync_jobs.find(job_id);
	if(iter != sync_jobs.end()) {
		iter->second->do_run = false;
	}
}

void Server::store_value_internal(	const Variant& key,
									std::shared_ptr<const Value> value,
									const uint64_t version)
{
	auto block = get_current_block();
	if(!block) {
		throw std::runtime_error("storage closed");
	}
	auto& key_out = block->key_file.out;
	auto& value_out = block->value_file.out;
	
	auto prev_key_pos = key_out.get_output_pos();
	auto prev_value_pos = value_out.get_output_pos();
	
	if(prev_key_pos >= MAX_BLOCK_SIZE) {
		throw std::runtime_error("key file overflow (MAX_BLOCK_SIZE)");
	}
	if(prev_value_pos >= MAX_BLOCK_SIZE) {
		throw std::runtime_error("value file overflow (MAX_BLOCK_SIZE)");
	}
	try {
		if(value) {
			auto type_code = value->get_type_code();
			if(type_code) {
				TypeEntry entry;
				entry.block_offset = prev_value_pos;
				if(value_out.write_type_code(type_code)) {
					vnx::write(key_out, entry);
					prev_key_pos = key_out.get_output_pos();
					prev_value_pos = value_out.get_output_pos();
				}
			}
		}
	}
	catch(const std::exception& ex)
	{
		block->key_file.seek_to(prev_key_pos);
		block->value_file.seek_to(prev_value_pos);
		log(WARN) << "store_value(): " << ex.what();
		throw;
	}
	
	IndexEntry index;
	int64_t num_bytes_key = 0;
	try {
		index.key = key;
		index.version = version;
		index.block_offset = prev_value_pos;
		vnx::write(value_out, value);
		block->value_file.flush();
		
		const auto num_bytes = value_out.get_output_pos() - prev_value_pos;
		if(num_bytes > MAX_VALUE_SIZE) {
			throw std::runtime_error("num_bytes > MAX_VALUE_SIZE");
		}
		index.num_bytes = num_bytes;
		vnx::write(key_out, index);
		block->key_file.flush();
		
		num_bytes_key = key_out.get_output_pos() - prev_key_pos;
		if(num_bytes_key > MAX_KEY_SIZE) {
			throw std::runtime_error("num_bytes_key > MAX_KEY_SIZE");
		}
	}
	catch(const std::exception& ex)
	{
		block->key_file.seek_to(prev_key_pos);
		block->value_file.seek_to(prev_value_pos);
		log(WARN) << "store_value(): " << ex.what();
		throw;
	}
	{
		const auto prev_value_index = get_value_index(key);
		const auto prev_key_iter = prev_value_index.key_iter;
		const auto key_hash = prev_value_index.key_hash;
		
		std::unique_lock lock(index_mutex);
		
		if(prev_key_iter == keyhash_map.cend() || version >= prev_key_iter->second)
		{
			delete_internal(prev_value_index);
			keyhash_map.emplace(key_hash, version);
			
			index_t& key_index = index_map[version];
			key_index.block_index = block->index;
			key_index.block_offset = prev_key_pos;
			key_index.num_bytes = num_bytes_key;
		}
		{
			const auto iter = delay_cache.find(key);
			if(iter != delay_cache.end() && version >= iter->second.entry->version) {
				delay_cache.erase(key);
			}
		}
		{
			const auto iter = write_cache.find(key);
			if(iter != write_cache.end() && version >= iter->second->version) {
				write_cache.erase(iter);
			}
		}
	}
	block->num_bytes_used += index.num_bytes;
	block->num_bytes_total += index.num_bytes;
	num_bytes_written += index.num_bytes + num_bytes_key;
	write_counter++;
	
	if(block->num_bytes_total >= max_block_size) {
		add_new_block();
	}
}

void Server::store_value(const Variant& key, std::shared_ptr<const Value> value)
{
	if(key.is_null()) {
		return;
	}
	store_value_version(key, value, ++curr_version);
	release_lock(key);
}

void Server::store_value_version(	const Variant& key,
									std::shared_ptr<const Value> value,
									const uint64_t version)
{
	if(do_compress) {
		auto entry = Entry::create();
		entry->key = key;
		entry->value = value;
		entry->version = version;
		{
			std::unique_lock lock(index_mutex);
			write_cache[key] = entry;
		}
		threads->add_task(std::bind(&Server::store_compress_job, this, entry));
	} else {
		store_value_version_ex(key, value, value, version);
	}
}

void Server::store_value_version_ex(const Variant& key,
									std::shared_ptr<const Value> value,
									std::shared_ptr<const Value> store_value,
									const uint64_t version)
{
	store_value_internal(key, store_value, version);
	
	auto pair = SyncUpdate::create();
	pair->collection = collection;
	pair->version = version;
	pair->key = key;
	pair->value = value;
	{
		std::lock_guard lock(update_mutex);
		update_queue.push(pair);
	}
	update_condition.notify_one();
}

void Server::store_values(const std::vector<std::pair<Variant, std::shared_ptr<const Value>>>& values)
{
	for(const auto& entry : values) {
		try {
			store_value(entry.first, entry.second);
		} catch(const std::exception& ex) {
			log(WARN) << "store_values(): " << ex.what();
		}
	}
}

void Server::store_value_delay(const Variant& key, std::shared_ptr<const Value> value, const int32_t& delay_ms)
{
	if(key.is_null()) {
		return;
	}
	if(delay_ms > 0) {
		const auto deadline_ms = vnx::get_wall_time_millis() + delay_ms;
		
		auto entry = Entry::create();
		entry->key = key;
		entry->value = value;
		entry->version = ++curr_version;
		{
			std::unique_lock lock(index_mutex);
			
			auto& cached = delay_cache[key];
			cached.deadline_ms = deadline_ms;
			cached.entry = entry;
		}
		release_lock(key);
		delay_queue.emplace(deadline_ms, key);
	} else {
		store_value(key, value);
	}
}

void Server::store_values_delay(const std::vector<std::pair<Variant, std::shared_ptr<const Value>>>& values, const int32_t& delay_ms)
{
	for(const auto& entry : values) {
		try {
			store_value_delay(entry.first, entry.second, delay_ms);
		} catch(const std::exception& ex) {
			log(WARN) << "store_values_delay(): " << ex.what();
		}
	}
}

void Server::delete_value(const Variant& key)
{
	const auto index = get_value_index(key);
	if(index.key_iter != keyhash_map.cend()) {
		store_value(key, nullptr);
	} else {
		release_lock(key);
	}
}

std::string Server::get_file_path(const std::string& name, uint32_t index) const
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

std::shared_ptr<Server::block_t> Server::get_block(uint32_t index) const
{
	auto iter = block_map.find(index);
	if(iter != block_map.end()) {
		return iter->second;
	}
	return nullptr;
}


Server::version_index_t Server::get_version_index(const uint64_t& version) const
{
	version_index_t result;
	if(auto* key_index = index_map.find(version))
	{
		const auto block = get_block(key_index->block_index);
		std::shared_ptr<IndexEntry> entry;
		if(block) {
			FileSectionInputStream stream(block->key_file.get_handle(), key_index->block_offset, key_index->num_bytes);
			TypeInput in(&stream);
			try {
				entry = std::dynamic_pointer_cast<IndexEntry>(vnx::read(in));
				num_bytes_read += key_index->num_bytes;
			} catch(...) {
				// ignore
			}
		}
		if(entry) {
			result.key = std::move(entry->key);
			result.block_index = key_index->block_index;
			result.block_offset = entry->block_offset;
			result.num_bytes = entry->num_bytes;
		}
	}
	return result;
}

Server::value_index_t Server::get_value_index(const Variant& key) const
{
	value_index_t result;
	result.key_hash = key.get_hash();
	const auto range = keyhash_map.equal_range(result.key_hash);
	for(auto entry = range.first; entry != range.second; ++entry)
	{
		const auto version_index = get_version_index(entry->second);
		if(version_index.key == key) {
			result.index_t::operator=(version_index);
			result.key_iter = entry;
			return result;
		}
	}
	result.key_iter = keyhash_map.cend();
	return result;
}

void Server::delete_internal(const value_index_t& index)
{
	// index_mutex needs to be unique locked by caller
	const auto key_iter = index.key_iter;
	if(key_iter != keyhash_map.cend()) {
		auto block = get_block(index.block_index);
		if(block) {
			block->num_bytes_used -= index.num_bytes;
		}
		index_map.erase(key_iter->second);
		keyhash_map.erase(key_iter);
	}
}

void Server::close_block(std::shared_ptr<block_t> block)
{
	try {
		CloseEntry entry;
		entry.block_offset = block->value_file.get_output_pos();
		vnx::write(block->key_file.out, entry);
		block->key_file.flush();
		block->value_file.flush();
	}
	catch(const std::exception& ex) {
		log(ERROR) << "Failed to close block " << block->index << ": " << ex.what();
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
			std::unique_lock lock(index_mutex);
			block_map[block->index] = block;
		}
		write_index();
	}
	catch(const std::exception& ex) {
		log(ERROR) << "Failed to write new block " << block->index << ": " << ex.what();
		return curr_block;
	}
	if(curr_block) {
		close_block(curr_block);
	}
	log(INFO) << "Added new block " << block->index;
	return block;
}

void Server::check_rewrite(bool is_idle)
{
	const auto current = get_current_block();
	
	for(const auto& entry : block_map) {
		auto block = entry.second;
		if(block != current) {
			const double use_factor = double(block->num_bytes_used) / block->num_bytes_total;
			if(use_factor < rewrite_threshold || (is_idle && use_factor < idle_rewrite_threshold))
			{
				rewrite_threads->add_task(std::bind(&Server::rewrite_task, this, block));
				log(INFO) << "Rewriting block " << block->index << " with use factor " << float(100 * use_factor) << " % ...";
				break;
			}
		}
	}
	{
		std::unique_lock lock(index_mutex);
		
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

void Server::finish_rewrite(std::shared_ptr<block_t> block, std::vector<std::shared_ptr<const Entry>> entries)
{
	size_t num_rewrite = 0;
	try {
		for(const auto& entry : entries) {
			if(index_map.find(entry->version)) {
				store_value_internal(entry->key, entry->value, entry->version);
				num_rewrite++;
			}
		}
	}
	catch(const std::exception& ex) {
		log(ERROR) << "Block " << block->index << " (store) rewrite: " << ex.what();
		return;		// stop rewriting in case storage fails
	}
	
	log(INFO) << "Rewrite of block " << block->index << " finished with " << num_rewrite << " / " << entries.size() << " entries";
	{
		std::unique_lock lock(index_mutex);
		block_map.erase(block->index);
		delete_list.push_back(block);
	}
	coll_index->delete_list.push_back(block->index);
	write_index();
	check_rewrite(false);
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
			log(ERROR) << "Failed to write collection index " << i << ": " << ex.what();
		}
	}
}

void Server::lock_file_exclusive(const File& file)
{
	while(::flock(::fileno(file.get_handle()), LOCK_EX | LOCK_NB)) {
		log(WARN) << "Cannot lock file: '" << file.get_name() << "'";
		::usleep(1000 * 1000);
	}
}

void Server::print_stats()
{
	log(INFO) << (1000 * read_counter) / stats_interval_ms << " reads/s, "
			<< (1000 * num_bytes_read) / 1024 / stats_interval_ms << " KB/s read, "
			<< (1000 * write_counter) / stats_interval_ms << " writes/s, "
			<< (1000 * num_bytes_written) / 1024 / stats_interval_ms << " KB/s write, "
			<< lock_map.size() << " locks, " << num_lock_timeouts << " timeout, "
			<< delay_cache.size() << " cached, " << keyhash_map.size() << " entries, "
			<< sync_jobs.size() << " sync jobs, "
			<< rewrite_threads->get_num_pending() << " brw pending";
	
	read_counter = 0;
	write_counter = 0;
	num_bytes_read = 0;
	num_bytes_written = 0;
}

void Server::update_loop() const noexcept
{
	uint64_t previous = 0;
	
	while(vnx_do_run())
	{
		std::shared_ptr<SyncUpdate> value;
		{
			std::unique_lock lock(update_mutex);
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
		value->previous = previous;
		
		publish(value, update_topic, BLOCKING);
		{
			auto copy = vnx::clone(value);
			copy->value = nullptr;
			publish(copy, update_topic_keys, BLOCKING);
		}
		previous = value->version;
	}
}

void Server::rewrite_task(std::shared_ptr<block_t> block) noexcept
{
	FileSectionInputStream key_stream(block->key_file.get_handle());
	TypeInput key_in(&key_stream);
	
	std::vector<std::shared_ptr<IndexEntry>> all_keys;
	while(true) {
		try {
			auto value = vnx::read(key_in);
			if(auto index = std::dynamic_pointer_cast<IndexEntry>(value)) {
				all_keys.push_back(index);
			} else if(std::dynamic_pointer_cast<CloseEntry>(value)) {
				break;
			}
		} catch(const std::underflow_error& ex) {
			log(WARN) << "Block " << block->index << " (key) rewrite: unexpected end of file";
			break;
		} catch(const std::exception& ex) {
			log(ERROR) << "Block " << block->index << " (key) rewrite: " << ex.what();
			break;
		}
	}
	
	std::vector<std::shared_ptr<IndexEntry>> keys;
	{
		std::shared_lock lock(index_mutex);
		
		for(const auto& entry : all_keys) {
			if(auto index = index_map.find(entry->version)) {
				if(index->block_index == block->index) {
					keys.push_back(entry);
				}
			}
		}
	}
	
	FileSectionInputStream stream;
	TypeInput in(&stream);
	const auto value_file = block->value_file.get_handle();
	
	std::vector<std::shared_ptr<const Entry>> entries;
	for(const auto& entry : keys) {
		try {
			in.reset();
			stream.reset(value_file, entry->block_offset, entry->num_bytes);
			
			auto out = Entry::create();
			out->value = vnx::read(in);
			out->version = entry->version;
			out->key = std::move(entry->key);
			entries.push_back(out);
			
			read_counter++;
			num_bytes_read += entry->num_bytes;
		}
		catch(const std::exception& ex) {
			log(ERROR) << "Block " << block->index << " (value) rewrite: " << ex.what();
			// keep going, since we are not reading the file as a stream
		}
	}
	
	add_task(std::bind(&Server::finish_rewrite, this, block, entries));
}

void Server::sync_loop(std::shared_ptr<sync_job_t> job) const noexcept
{
	std::shared_ptr<Stream> stream;
	if(job->dst_mac) {
		stream = std::make_shared<Stream>(job->dst_mac);
		stream->open();
	}
	{
		auto info = SyncInfo::create();
		info->collection = collection;
		info->version = job->begin;
		info->job_id = job->id;
		info->code = SyncInfo::BEGIN;
		if(stream) {
			stream->send(info);
		}
		if(job->topic) {
			publish(info, job->topic, BLOCKING);
		}
	}
	
	struct entry_t {
		uint64_t version;
		index_t key_index;
		std::shared_ptr<block_t> block;
		std::shared_ptr<IndexEntry> index;
		std::shared_ptr<const Value> value;
	};
	
	bool is_done = false;
	std::vector<entry_t> list;
	uint64_t version = job->begin;
	uint64_t previous = version;
	
	while(vnx_do_run() && job->do_run && !is_done)
	{
		list.clear();
		{
			std::shared_lock lock(index_mutex);
			
			for(int i = 0; i < sync_chunk_count; ++i)
			{
				const auto* iter = index_map.find_next(version);
				if(!iter) {
					is_done = true;
					break;
				}
				if(job->end > 0 && version >= job->end) {
					is_done = true;
					break;
				}
				try {
					entry_t entry;
					entry.version = version;
					entry.key_index = *iter;
					entry.block = get_block(entry.key_index.block_index);
					if(entry.block) {
						entry.block->num_pending++;
						list.push_back(entry);
					}
				}
				catch(...) {
					// ignore
				}
			}
		}
		job->num_left = list.size();
		
		for(auto& entry : list)
		{
			threads->add_task([this, job, &entry]() {
				FileSectionInputStream stream;
				TypeInput in(&stream);
				const auto& block = entry.block;
				const auto& key_index = entry.key_index;
				{
					in.reset();
					stream.reset(block->key_file.get_handle(), key_index.block_offset, key_index.num_bytes);
					try {
						entry.index = std::dynamic_pointer_cast<IndexEntry>(vnx::read(in));
						num_bytes_read += key_index.num_bytes;
					} catch(...) {
						// ignore
					}
				}
				const auto& index = entry.index;
				
				if(index && !job->key_only)
				{
					in.reset();
					stream.reset(block->value_file.get_handle(), index->block_offset, index->num_bytes);
					try {
						std::shared_ptr<const Value> value = vnx::read(in);
						if(value) {
							auto decompressed = value->vnx_decompress();
							if(decompressed) {
								value = decompressed;
							}
						}
						entry.value = value;
						num_bytes_read += index->num_bytes;
						read_counter++;
					} catch(...) {
						// ignore
					}
				}
				block->num_pending--;
				{
					std::lock_guard lock(job->mutex);
					if(--job->num_left == 0) {
						job->condition.notify_all();
					}
				}
			});
		}
		{
			std::unique_lock lock(job->mutex);
			while(job->num_left > 0) {
				job->condition.wait(lock);
			}
		}
		for(const auto& entry : list)
		{
			if(!entry.index) {
				continue;
			}
			auto pair = SyncUpdate::create();
			pair->collection = collection;
			pair->version = entry.version;
			pair->previous = previous;
			pair->key = entry.index->key;
			pair->value = entry.value;
			if(stream) {
				stream->send(pair);
			}
			if(job->topic) {
				publish(pair, job->topic, BLOCKING);
			}
			previous = entry.version;
		}
	}
	if(vnx_do_run() && job->do_run)
	{
		auto info = SyncInfo::create();
		info->collection = collection;
		info->version = version;
		info->job_id = job->id;
		info->code = SyncInfo::END;
		if(stream) {
			stream->send(info);
		}
		if(job->topic) {
			publish(info, job->topic, BLOCKING);
		}
	}
	{
		std::lock_guard lock(sync_mutex);
		sync_jobs.erase(job->id);
		log(INFO) << "Finished sync job " << job->id;
	}
}


} // keyvalue
} // vnx
