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
#include <vnx/keyvalue/btree_index_map.h>

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
	
	void get_key_async(const uint64_t& version, const vnx::request_id_t& req_id) const override;
	
	void get_keys_async(const std::vector<uint64_t>& versions, const vnx::request_id_t& req_id) const override;
	
	void unlock(const Variant& key) override;
	
	int64_t sync_from(const TopicPtr& topic, const uint64_t& version) const override;
	
	int64_t sync_range(const TopicPtr& topic, const uint64_t& begin, const uint64_t& end) const override;
	
	int64_t sync_all(const TopicPtr& topic) const override;
	
	int64_t sync_all_keys(const TopicPtr& topic) const override;
	
	int64_t sync_all_private(const Hash64& dst_mac) const override;
	
	int64_t sync_all_keys_private(const Hash64& dst_mac) const override;
	
	void cancel_sync_job(const int64_t& job_id) override;
	
	void store_value(const Variant& key, std::shared_ptr<const Value> value) override;
	
	void store_values(const std::vector<std::pair<Variant, std::shared_ptr<const Value>>>& values) override;
	
	void store_value_delay(const Variant& key, std::shared_ptr<const Value> value, const int32_t& delay_ms) override;
	
	void store_values_delay(const std::vector<std::pair<Variant, std::shared_ptr<const Value>>>& values, const int32_t& delay_ms) override;
	
	void delete_value(const Variant& key) override;
	
private:
	struct index_t {
		uint32_t block_index = -1;
		uint32_t block_offset = 0;
		uint32_t num_bytes = 0;
		operator bool() const { return block_index != uint32_t(-1); }
	};
	
	struct value_index_t : index_t {
		uint64_t key_hash = 0;
		std::unordered_multimap<uint64_t, uint64_t>::const_iterator key_iter;
	};
	
	struct version_index_t : index_t {
		Variant key;
	};
	
	struct block_t {
		File key_file;
		File value_file;
		uint32_t index = -1;
		bool is_rewrite = false;
		int64_t num_bytes_used = 0;
		int64_t num_bytes_total = 0;
	};
	
	struct multi_read_job_t {
		request_id_t req_id;
		std::atomic<size_t> num_left {0};
		std::vector<std::shared_ptr<const Entry>> entries;
	};
	
	struct multi_read_key_job_t {
		request_id_t req_id;
		std::atomic<size_t> num_left {0};
		std::vector<std::pair<uint64_t, Variant>> result;
	};
	
	struct sync_job_t {
		int64_t id = -1;
		TopicPtr topic;
		Hash64 dst_mac;
		uint64_t begin = 0;
		uint64_t end = 0;
		bool key_only = false;
		std::atomic_bool do_run {true};
		std::atomic<size_t> num_left {0};
		std::mutex mutex;
		std::condition_variable condition;
	};
	
	struct sync_entry_t {
		uint64_t version;
		index_t key_index;
		std::shared_ptr<block_t> block;
		std::shared_ptr<IndexEntry> index;
		std::shared_ptr<const Value> value;
	};
	
	struct lock_entry_t {
		std::vector<std::function<void()>> waiting;
		std::multimap<int64_t, std::map<Variant, lock_entry_t>::iterator>::iterator queue_iter;
	};
	
	struct delay_entry_t {
		int64_t deadline_ms = 0;
		std::shared_ptr<const Entry> entry;
	};
	
	typedef std::map<Variant, lock_entry_t> lock_map_t;
	
	void aquire_lock(lock_map_t::iterator iter, int32_t timeout_ms) const;
	
	void release_lock(lock_map_t::iterator iter);
	
	void release_lock(const Variant& key);
	
	void check_timeouts();
	
	std::shared_ptr<const Entry> read_value(const Variant& key) const;
	
	void read_job(const Variant& key, const request_id_t& req_id) const;
	
	void read_job_locked(const Variant& key, const request_id_t& req_id) const;
	
	void multi_read_job(const Variant& key, size_t index, std::shared_ptr<multi_read_job_t> job) const;
	
	void read_key_job(uint64_t version, const request_id_t& req_id) const;
	
	void multi_read_key_job(uint64_t version, size_t index, std::shared_ptr<multi_read_key_job_t> job) const;
	
	void store_compress_job(std::shared_ptr<const Entry> entry);
	
	void lock_file_exclusive(const File& file);
	
	std::string get_file_path(const std::string& name, uint32_t index) const;
	
	std::shared_ptr<block_t> get_current_block() const;
	
	std::shared_ptr<block_t> get_block(uint32_t index) const;
	
	version_index_t get_version_index(const uint64_t& version) const;
	
	value_index_t get_value_index(const Variant& key) const;
	
	void delete_internal(const value_index_t& index);
	
	void close_block(std::shared_ptr<block_t> block);
	
	std::shared_ptr<block_t> add_new_block();
	
	void store_value_internal(	const Variant& key,
								std::shared_ptr<const Value> value,
								const uint64_t version,
								index_t* key_index_rewrite = nullptr);
	
	void store_value_version(	const Variant& key,
								std::shared_ptr<const Value> value,
								const uint64_t version);
	
	void store_value_version_ex(const Variant& key,
								std::shared_ptr<const Value> value,
								std::shared_ptr<const Value> store_value,
								const uint64_t version);
	
	int64_t sync_range_ex(TopicPtr topic, Hash64 dst_mac, uint64_t begin, uint64_t end, bool key_only) const;
	
	void sync_finished(std::shared_ptr<sync_job_t> job) const;
	
	void check_rewrite(bool is_idle);
	
	void check_delete();
	
	void finish_rewrite(std::shared_ptr<block_t> block, std::vector<std::shared_ptr<const Entry>> entries);
	
	void write_index();
	
	void print_stats();
	
	void update_loop() const noexcept;
	
	void rewrite_task(std::shared_ptr<block_t> block) noexcept;
	
	void sync_loop(std::shared_ptr<sync_job_t> job) const noexcept;
	
	void sync_read_task(std::shared_ptr<sync_job_t> job, sync_entry_t* entry) const noexcept;
	
private:
	uint64_t curr_version = 0;
	std::shared_ptr<Collection> coll_index;
	std::shared_ptr<ThreadPool> threads;
	std::shared_ptr<ThreadPool> sync_threads;
	std::shared_ptr<ThreadPool> rewrite_threads;
	
	mutable std::shared_mutex index_mutex;
	
	// protected by index_mutex, only main thread may modify
	std::map<int64_t, std::shared_ptr<block_t>> block_map;
	btree_index_map<index_t, 5, 4> index_map;						// [version => index_t]
	std::unordered_multimap<uint64_t, uint64_t> keyhash_map;		// [key hash => version]
	std::map<Variant, std::shared_ptr<const Entry>> write_cache;
	std::map<Variant, delay_entry_t> delay_cache;	// [key => (deadline_ms, entry)]
	std::list<std::shared_ptr<block_t>> delete_list;
	
	// accessed by main thread only
	mutable lock_map_t lock_map;											// [key => lock_entry_t]
	mutable std::multimap<int64_t, lock_map_t::iterator> lock_queue;		// [deadline_ms => lock_map iter]
	mutable std::multimap<int64_t, Variant> delay_queue;					// [deadline_ms => key]
	
	mutable std::mutex update_mutex;
	mutable std::condition_variable update_condition;
	mutable std::queue<std::shared_ptr<SyncUpdate>> update_queue;
	std::thread update_thread;
	
	mutable std::mutex sync_mutex;
	mutable std::map<int64_t, std::shared_ptr<sync_job_t>> sync_jobs;
	mutable int64_t next_sync_id = 0;
	
	mutable std::atomic<uint64_t> read_counter {0};
	mutable std::atomic<uint64_t> write_counter {0};
	mutable std::atomic<uint64_t> num_bytes_read {0};
	mutable std::atomic<uint64_t> num_bytes_written {0};
	mutable std::atomic<uint64_t> num_lock_timeouts {0};
	
	static const int NUM_INDEX = 3;
	
};


} // keyvalue
} // vnx

#endif /* INCLUDE_VNX_KEYVALUE_SERVER_H_ */
