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
			
			block->key_file.fadvise(POSIX_FADV_SEQUENTIAL);
			
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
								log(WARN).out << "Lost value for key '" << index_entry->key.to_string_value() << "'";
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
		catch(const std::exception& ex) {
			if(ignore_errors) {
				log(ERROR).out << "Failed to read block " << block_index << ": " << ex.what();
			} else {
				throw;
			}
		}
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
		log(INFO).out << "Got " << keyhash_map.size() << " entries.";
	}
	
	write_index();
	
	read_threads = std::make_shared<ThreadPool>(num_read_threads, 1000);
	sync_threads = std::make_shared<ThreadPool>(-1);
	
	update_thread = std::thread(&Server::update_loop, this);
	
	set_timer_millis(timeout_interval_ms, std::bind(&Server::check_timeouts, this));
	set_timer_millis(rewrite_interval * 1000, std::bind(&Server::check_rewrite, this, false));
	set_timer_millis(idle_rewrite_interval * 1000, std::bind(&Server::check_rewrite, this, true));
	if(stats_interval_ms) {
		set_timer_millis(stats_interval_ms, std::bind(&Server::print_stats, this));
	}
	
	rewrite.timer = add_timer(std::bind(&Server::rewrite_func, this));
	
	Super::main();
	
	read_threads->close();
	sync_threads->close();
	
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
			log(ERROR).out << "Failed to close key file " << block->index << ": " << ex.what();
		}
		try {
			block->value_file.close();
		} catch(const std::exception& ex) {
			log(ERROR).out << "Failed to close value file " << block->index << ": " << ex.what();
		}
	}
}

void Server::get_value_async(const Variant& key, const request_id_t& req_id) const
{
	const auto iter = lock_map.find(key);
	if(iter != lock_map.end()) {
		auto& entry = iter->second;
		entry.waiting.push_back(std::bind(&Server::get_value_async, this, key, req_id));
	} else {
		read_threads->add_task(std::bind(&Server::read_job, this, key, req_id));
	}
}

void Server::get_value_locked_async(const Variant& key, const int32_t& timeout_ms, const request_id_t& req_id) const
{
	const auto ret = lock_map.emplace(key, lock_entry_t());
	const auto& iter = ret.first;
	if(ret.second) {
		aquire_lock(iter, timeout_ms);
		read_threads->add_task(std::bind(&Server::read_job_locked, this, key, req_id));
	} else {
		auto& entry = iter->second;
		entry.waiting.push_back(std::bind(&Server::get_value_locked_async, this, key, timeout_ms, req_id));
	}
}

void Server::get_value_multi_async(	const Variant& key,
									size_t index,
									std::shared_ptr<multi_read_job_t> job,
									const request_id_t& req_id) const
{
	const auto iter = lock_map.find(key);
	if(iter != lock_map.end()) {
		auto& entry = iter->second;
		entry.waiting.push_back(std::bind(&Server::get_value_multi_async, this, key, index, job, req_id));
	} else {
		read_threads->add_task(std::bind(&Server::multi_read_job, this, key, index, job));
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
	
	for(size_t i = 0; i < keys.size(); ++i)
	{
		const auto iter = lock_map.find(keys[i]);
		if(iter != lock_map.end()) {
			auto& entry = iter->second;
			entry.waiting.push_back(std::bind(&Server::get_value_multi_async, this, keys[i], i, job, req_id));
		} else {
			read_threads->add_task(std::bind(&Server::multi_read_job, this, keys[i], i, job));
		}
	}
}

void Server::get_version_key_async(const uint64_t& version, const vnx::request_id_t& req_id) const
{
	read_threads->add_task(std::bind(&Server::read_version_key_job, this, version, req_id));
}

void Server::get_version_keys_async(const std::vector<uint64_t>& versions, const vnx::request_id_t& req_id) const
{
	if(versions.empty()) {
		get_version_keys_async_return(req_id, {});
		return;
	}
	auto job = std::make_shared<multi_read_version_key_job_t>();
	job->req_id = req_id;
	job->num_left = versions.size();
	job->result.resize(versions.size());
	
	for(size_t i = 0; i < versions.size(); ++i) {
		read_threads->add_task(std::bind(&Server::multi_read_version_key_job, this, versions[i], i, job));
	}
}

void Server::unlock(const Variant& key)
{
	release_lock(key);
}

void Server::aquire_lock(const lock_map_t::iterator& iter, int32_t timeout_ms) const
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

void Server::release_lock(const lock_map_t::iterator& iter)
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
}

std::shared_ptr<const Entry> Server::read_value(const Variant& key) const
{
	value_index_t index;
	std::shared_ptr<block_t> block;
	{
		std::shared_lock lock(index_mutex);
		
		index = get_value_index(key);
		if(index.block_index >= 0)
		{
			try {
				block = get_block(index.block_index);
				block->num_pending++;
			} catch(...) {
				// ignore
			}
		}
	}
	if(!block) {
		return 0;
	}
	if(index.num_bytes > 65536) {
		block->value_file.fadvise(POSIX_FADV_SEQUENTIAL, index.block_offset, index.num_bytes);
	}
	FileSectionInputStream stream(block->value_file.get_handle(), index.block_offset, index.num_bytes);
	TypeInput in(&stream);
	
	auto entry = Entry::create();
	entry->key = key;
	entry->version = index.key_iter->second;
	try {
		entry->value = vnx::read(in);
		num_bytes_read += index.num_bytes;
	} catch(...) {
		// ignore
	}
	block->num_pending--;
	read_counter++;
	{
		auto compressed = std::dynamic_pointer_cast<const addons::CompressedValue>(entry->value);
		if(compressed) {
			entry->value = compressed->decompress();
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

void Server::read_version_key_job(uint64_t version, const request_id_t& req_id) const
{
	std::shared_lock lock(index_mutex);
	
	const auto version_index = get_version_index(version);
	get_version_key_async_return(req_id, version_index.key);
}

void Server::multi_read_version_key_job(uint64_t version, size_t index, std::shared_ptr<multi_read_version_key_job_t> job) const
{
	std::shared_lock lock(index_mutex);
	
	try {
		const auto version_index = get_version_index(version);
		job->result[index] = std::make_pair(version, version_index.key);
	} catch(...) {
		// ignore
	}
	if(job->num_left-- == 1) {
		get_version_keys_async_return(job->req_id, job->result);
	}
}

int64_t Server::sync_range_ex(TopicPtr topic, uint64_t begin, uint64_t end, bool key_only) const
{
	auto job = std::make_shared<sync_job_t>();
	job->id = next_sync_id++;
	job->topic = topic;
	job->begin = begin;
	job->end = end;
	job->key_only = key_only;
	{
		std::lock_guard lock(sync_mutex);
		sync_jobs[job->id] = job;
	}
	sync_threads->add_task(std::bind(&Server::sync_loop, this, job));
	
	log(INFO).out << "Started sync job " << job->id << " ...";
	return job->id;
}

int64_t Server::sync_from(const TopicPtr& topic, const uint64_t& version) const
{
	return sync_range(topic, version, 0);
}

int64_t Server::sync_range(const TopicPtr& topic, const uint64_t& begin, const uint64_t& end) const
{
	return sync_range_ex(topic, begin, end, false);
}

int64_t Server::sync_all(const TopicPtr& topic) const
{
	return sync_range(topic, 0, 0);
}

int64_t Server::sync_all_keys(const TopicPtr& topic) const
{
	return sync_range_ex(topic, 0, 0, true);
}

void Server::cancel_sync_job(const int64_t& job_id)
{
	std::lock_guard lock(sync_mutex);
	
	const auto iter = sync_jobs.find(job_id);
	if(iter != sync_jobs.end()) {
		iter->second->do_run = false;
	}
}

void Server::store_value_internal(const Variant& key, const std::shared_ptr<const Value>& value, uint64_t version)
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
		log(WARN).out << "store_value(): " << ex.what();
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
		log(WARN).out << "store_value(): " << ex.what();
		throw;
	}
	
	const auto value_index = get_value_index(key);
	{
		std::unique_lock lock(index_mutex);
		
		delete_internal(value_index);
		keyhash_map.emplace(value_index.key_hash, version);
		
		index_t& key_index = index_map[version];
		key_index.block_index = block->index;
		key_index.block_offset = prev_key_pos;
		key_index.num_bytes = num_bytes_key;
		num_bytes_written += index.num_bytes + key_index.num_bytes;
	}
	block->num_bytes_used += index.num_bytes;
	block->num_bytes_total += index.num_bytes;
	write_counter++;
	
	if(block->num_bytes_total >= max_block_size) {
		add_new_block();
	}
}

void Server::store_value(const Variant& key, const std::shared_ptr<const Value>& value)
{
	release_lock(key);
	
	if(key.is_null()) {
		return;
	}
	store_value_internal(key, do_compress ? addons::DeflatedValue::compress(value) : value, curr_version + 1);
	curr_version++;
	
	auto pair = SyncUpdate::create();
	pair->collection = collection;
	pair->version = curr_version;
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
			log(WARN).out << "store_values(): " << ex.what();
		}
	}
}

void Server::delete_value(const Variant& key)
{
	const auto index = get_value_index(key);
	if(index.key_iter != keyhash_map.end()) {
		store_value(key, 0);
	} else {
		release_lock(key);
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


Server::version_index_t Server::get_version_index(const uint64_t& version) const
{
	version_index_t result;
	auto iter = index_map.find(version);
	if(iter != index_map.end()) {
		const auto& key_index = iter->second;
		const auto block = get_block(key_index.block_index);
		
		std::shared_ptr<IndexEntry> entry;
		{
			FileSectionInputStream stream(block->key_file.get_handle(), key_index.block_offset, key_index.num_bytes);
			TypeInput in(&stream);
			try {
				entry = std::dynamic_pointer_cast<IndexEntry>(vnx::read(in));
				num_bytes_read += key_index.num_bytes;
			} catch(...) {
				// ignore
			}
		}
		if(entry) {
			result.key = std::move(entry->key);
			result.block_index = key_index.block_index;
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
	result.key_iter = keyhash_map.end();
	return result;
}

void Server::delete_internal(const value_index_t& index)
{
	// index_mutex needs to be locked by caller
	if(index.key_iter != keyhash_map.end()) {
		try {
			auto block = get_block(index.block_index);
			block->num_bytes_used -= index.num_bytes;
		} catch(...) {
			// ignore
		}
		index_map.erase(index.key_iter->second);
		keyhash_map.erase(index.key_iter);
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
			std::unique_lock lock(index_mutex);
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

void Server::rewrite_func()
{
	auto block = rewrite.block;
	if(!block) {
		return;
	}
	
	// TODO: rewrite in own thread
	
	if(!rewrite.is_run) {
		rewrite.is_run = true;
		rewrite.key_in.reset();
		rewrite.key_stream.reset(block->key_file.get_handle());
		block->key_file.fadvise(POSIX_FADV_SEQUENTIAL);
		block->value_file.fadvise(POSIX_FADV_SEQUENTIAL);
	}
	
	struct pair_t {
		std::shared_ptr<IndexEntry> index;
		std::shared_ptr<Value> value;
	};
	
	bool is_done = false;
	int64_t num_bytes = 0;
	std::vector<pair_t> list;
	
	for(int i = 0; i < rewrite_chunk_count; ++i) {
		try {
			const auto index = std::dynamic_pointer_cast<IndexEntry>(vnx::read(rewrite.key_in));
			if(index) {
				const auto iter = index_map.find(index->version);
				if(iter != index_map.end())
				{
					const auto& key_index = iter->second;
					if(key_index.block_index == rewrite.block->index)
					{
						list.emplace_back(pair_t{index, 0});
						num_bytes += index->num_bytes + key_index.num_bytes;
						if(num_bytes > rewrite_chunk_size) {
							break;
						}
					}
				}
			}
		}
		catch(const std::underflow_error& ex) {
			is_done = true;
			break;
		}
		catch(const std::exception& ex) {
			log(ERROR).out << "Block " << block->index << " rewrite: " << ex.what();
			return;
		}
	}
	read_counter += list.size();
	num_bytes_read += num_bytes;
	
	try {
		FileSectionInputStream stream;
		TypeInput in(&stream);
		const auto fd = block->value_file.get_handle();
		
		for(auto& entry : list) {
			in.reset();
			stream.reset(fd, entry.index->block_offset, entry.index->num_bytes);
			entry.value = vnx::read(in);
		}
		for(const auto& entry : list) {
			store_value_internal(entry.index->key, entry.value, entry.index->version);
		}
	}
	catch(const std::exception& ex) {
		log(ERROR).out << "Block " << block->index << " rewrite: " << ex.what();
		return;
	}
	
	if(is_done) {
		log(INFO).out << "Rewrite of block " << block->index << " finished.";
		{
			std::unique_lock lock(index_mutex);
			block_map.erase(block->index);
			delete_list.push_back(block);
		}
		coll_index->delete_list.push_back(block->index);
		write_index();
		
		rewrite.block = 0;
		rewrite.is_run = false;
		check_rewrite(false);
	} else {
		rewrite.timer->set_millis(0);
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
	log(INFO).out << (1000 * read_counter) / stats_interval_ms << " reads/s, "
			<< (1000 * num_bytes_read) / 1024 / stats_interval_ms << " KB/s read, "
			<< (1000 * write_counter) / stats_interval_ms << " writes/s, "
			<< (1000 * num_bytes_written) / 1024 / stats_interval_ms << " KB/s write, "
			<< lock_map.size() << " locks, " << num_lock_timeouts << " timeout, "
			<< index_map.size() << " entries, "
			<< sync_jobs.size() << " sync jobs" << (rewrite.block ? ", rewriting " : "")
			<< (rewrite.block ? std::to_string(rewrite.block->index) : "");
	
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
			copy->value = 0;
			publish(copy, update_topic_keys, BLOCKING);
		}
		previous = value->version;
	}
}

void Server::sync_loop(std::shared_ptr<sync_job_t> job) const noexcept
{
	Publisher publisher;
	uint64_t version = job->begin;
	uint64_t previous = job->begin;
	{
		auto info = SyncInfo::create();
		info->collection = collection;
		info->version = job->begin;
		info->job_id = job->id;
		info->code = SyncInfo::BEGIN;
		publisher.publish(info, job->topic, BLOCKING);
	}
	
	struct entry_t {
		uint64_t version;
		index_t key_index;
		std::shared_ptr<block_t> block;
		std::shared_ptr<IndexEntry> index;
	};
	
	bool is_done = false;
	std::vector<entry_t> list;
	
	while(vnx_do_run() && job->do_run && !is_done)
	{
		list.clear();
		{
			std::shared_lock lock(index_mutex);
			
			auto iter = index_map.upper_bound(version);
			for(int i = 0; i < sync_chunk_count; ++iter, ++i)
			{
				if(iter == index_map.end()) {
					is_done = true;
					break;
				}
				version = iter->first;
				if(job->end > 0 && version >= job->end) {
					is_done = true;
					break;
				}
				try {
					entry_t entry;
					entry.version = version;
					entry.key_index = iter->second;
					entry.block = get_block(entry.key_index.block_index);
					entry.block->num_pending++;
					list.push_back(entry);
				}
				catch(...) {
					// ignore
				}
			}
		}
		FileSectionInputStream stream;
		TypeInput in(&stream);
		
		for(auto& entry : list)
		{
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
		}
		for(const auto& entry : list)
		{
			const auto& block = entry.block;
			const auto& index = entry.index;
			
			if(index) {
				std::shared_ptr<Value> value;
				if(!job->key_only) {
					in.reset();
					stream.reset(block->value_file.get_handle(), index->block_offset, index->num_bytes);
					try {
						value = vnx::read(in);
						num_bytes_read += index->num_bytes;
					} catch(...) {
						// ignore
					}
				}
				auto pair = SyncUpdate::create();
				pair->collection = collection;
				pair->version = entry.version;
				pair->previous = previous;
				pair->key = index->key;
				pair->value = value;
				publisher.publish(pair, job->topic, BLOCKING);
				previous = entry.version;
			}
			block->num_pending--;
			read_counter++;
		}
	}
	if(vnx_do_run() && job->do_run)
	{
		auto info = SyncInfo::create();
		info->collection = collection;
		info->version = version;
		info->job_id = job->id;
		info->code = SyncInfo::END;
		publisher.publish(info, job->topic, BLOCKING);
	}
	{
		std::lock_guard lock(sync_mutex);
		sync_jobs.erase(job->id);
		log(INFO).out << "Finished sync job " << job->id;
	}
}


} // keyvalue
} // vnx
