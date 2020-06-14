/*
 * Server.h
 *
 *  Created on: Mar 9, 2020
 *      Author: mad
 */

#ifndef INCLUDE_VNX_KEYVALUE_SERVER_H_
#define INCLUDE_VNX_KEYVALUE_SERVER_H_

#include <vnx/keyvalue/ServerBase.hxx>
#include <vnx/keyvalue/Collection.hxx>

#include <vnx/File.h>
#include <vnx/ThreadPool.h>

#include <atomic>
#include <shared_mutex>
#include <unordered_map>


namespace vnx {
namespace keyvalue {

class Server : public ServerBase {
public:
	Server(const std::string& _vnx_name);
	
protected:
	void init() override;
	
	void main() override;
	
	void get_value_async(const Variant& key, const request_id_t& req_id) const override;
	
	void get_value_locked_async(const Variant& key, const int32_t& timeout_ms, const request_id_t& req_id) const override;
	
	void get_values_async(const std::vector<Variant>& keys, const request_id_t& req_id) const override;
	
	int64_t sync_from(const TopicPtr& topic, const uint64_t& version) const override;
	
	int64_t sync_range(const TopicPtr& topic, const uint64_t& begin, const uint64_t& end) const override;
	
	int64_t sync_all(const TopicPtr& topic) const override;
	
	int64_t sync_all_keys(const TopicPtr& topic) const override;
	
	void store_value(const Variant& key, const std::shared_ptr<const Value>& value) override;
	
	void store_values(const std::vector<std::pair<Variant, std::shared_ptr<const Value>>>& values) override;
	
	void delete_value(const Variant& key) override;
	
private:
	struct index_t {
		int64_t block_index = -1;
		uint32_t block_offset = 0;
		uint32_t num_bytes = 0;
	};
	
	struct value_index_t : index_t {
		uint64_t key_hash = 0;
		std::unordered_multimap<uint64_t, uint64_t>::const_iterator key_iter;
	};
	
	struct block_t {
		File key_file;
		File value_file;
		int64_t index = -1;
		int64_t num_bytes_used = 0;
		int64_t num_bytes_total = 0;
		std::atomic<size_t> num_pending {0};
	};
	
	struct multi_read_job_t {
		request_id_t req_id;
		std::atomic<size_t> num_left {0};
		std::vector<std::shared_ptr<const Value>> values;
	};
	
	struct lock_entry_t {
		std::vector<std::function<void()>> waiting;
		std::multimap<int64_t, std::map<Variant, lock_entry_t>::iterator>::iterator queue_iter;
	};
	
	typedef std::map<Variant, lock_entry_t> lock_map_t;
	
	void get_value_multi_async(	const Variant& key,
								size_t index,
								std::shared_ptr<multi_read_job_t> job,
								const request_id_t& req_id) const;
	
	void aquire_lock(const lock_map_t::iterator& iter, int32_t timeout_ms) const;
	
	void release_lock(const lock_map_t::iterator& iter);
	
	void release_lock(const Variant& key);
	
	void check_timeouts();
	
	std::shared_ptr<Value> read_value(const Variant& key) const;
	
	void read_job(const Variant& key, const request_id_t& req_id) const;
	
	void multi_read_job(const Variant& key, size_t index, std::shared_ptr<multi_read_job_t> job) const;
	
	void lock_file_exclusive(const File& file);
	
	std::string get_file_path(const std::string& name, int64_t index) const;
	
	std::shared_ptr<block_t> get_current_block() const;
	
	std::shared_ptr<block_t> get_block(int64_t index) const;
	
	Server::value_index_t get_value_index(const Variant& key) const;
	
	void delete_internal(const value_index_t& index);
	
	void close_block(std::shared_ptr<block_t> block);
	
	std::shared_ptr<block_t> add_new_block();
	
	void store_value_internal(const Variant& key, const std::shared_ptr<const Value>& value, uint64_t version);
	
	int64_t sync_range_ex(TopicPtr topic, uint64_t begin, uint64_t end, bool key_only) const;
	
	void check_rewrite(bool is_idle);
	
	void rewrite_func();
	
	void write_index();
	
	void print_stats();
	
	void update_loop() const noexcept;
	
	void sync_loop(int64_t job_id, TopicPtr topic, uint64_t begin, uint64_t end, bool key_only) const noexcept;
	
private:
	Hash64 private_addr;
	uint64_t curr_version = 0;
	std::shared_ptr<Collection> coll_index;
	std::shared_ptr<ThreadPool> read_threads;
	std::shared_ptr<ThreadPool> sync_threads;
	
	mutable std::shared_mutex index_mutex;
	
	// protected by index_mutex, only main thread may modify
	std::map<int64_t, std::shared_ptr<block_t>> block_map;
	std::map<uint64_t, index_t> index_map;							// [version => index_t]
	std::unordered_multimap<uint64_t, uint64_t> keyhash_map;		// [key hash => version]
	std::list<std::shared_ptr<block_t>> delete_list;
	
	// accessed by main thread only
	mutable lock_map_t lock_map;											// [key => lock_entry_t]
	mutable std::multimap<int64_t, lock_map_t::iterator> lock_queue;		// [deadline => lock_map iter]
	
	mutable std::mutex update_mutex;
	mutable std::condition_variable update_condition;
	mutable std::queue<std::shared_ptr<KeyValuePair>> update_queue;
	std::thread update_thread;
	
	mutable std::mutex sync_mutex;
	mutable std::set<int64_t> sync_jobs;
	mutable int64_t next_sync_id = 0;
	
	mutable std::atomic<uint64_t> read_counter {0};
	mutable std::atomic<uint64_t> write_counter {0};
	mutable std::atomic<uint64_t> num_bytes_read {0};
	mutable std::atomic<uint64_t> num_bytes_written {0};
	mutable std::atomic<uint64_t> num_lock_timeouts {0};
	
	struct rewrite_t {
		std::shared_ptr<block_t> block;
		std::shared_ptr<Timer> timer;
		FileSectionInputStream key_stream;
		TypeInput key_in;
		bool is_run = false;
		rewrite_t() : key_in(&key_stream) {}
	} rewrite;
	
	static const int NUM_INDEX = 3;
	
};


} // keyvalue
} // vnx

#endif /* INCLUDE_VNX_KEYVALUE_SERVER_H_ */
