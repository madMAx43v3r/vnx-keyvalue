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

#include <atomic>
#include <unordered_map>


namespace vnx {
namespace keyvalue {

class Server : public ServerBase {
public:
	Server(const std::string& _vnx_name);
	
protected:
	void init() override;
	
	void main() override;
	
	std::shared_ptr<const Value> get_value(const Variant& key) const override;
	
	std::vector<std::shared_ptr<const Value>> get_values(const std::vector<Variant>& keys) const override;
	
	int64_t sync_from(const TopicPtr& topic, const uint64_t& version) const override;
	
	int64_t sync_range(const TopicPtr& topic, const uint64_t& begin, const uint64_t& end) const override;
	
	int64_t sync_all(const TopicPtr& topic) const override;
	
	int64_t sync_all_keys(const TopicPtr& topic) const override;
	
	void store_value(const Variant& key, const std::shared_ptr<const Value>& value) override;
	
	void store_values(const std::vector<std::pair<Variant, std::shared_ptr<const Value>>>& values) override;
	
	void delete_value(const Variant& key) override;
	
	void _sync_finished(const int64_t& job_id) override;
	
private:
	struct key_index_t {
		int64_t block_index = -1;
		int64_t block_offset = 0;
		int64_t block_offset_key = 0;
		int64_t num_bytes = 0;
		int64_t num_bytes_key = 0;
	};
	
	struct block_t {
		File key_file;
		File value_file;
		int64_t index = -1;
		int64_t num_bytes_used = 0;
		int64_t num_bytes_total = 0;
		std::atomic<size_t> num_pending {0};
	};
	
	std::shared_ptr<Value> read_value(const key_index_t& index) const;
	
	void lock_file_exclusive(const File& file);
	
	std::string get_file_path(const std::string& name, int64_t index) const;
	
	std::shared_ptr<block_t> get_current_block() const;
	
	std::shared_ptr<block_t> get_block(int64_t index) const;
	
	std::unordered_multimap<uint64_t, uint64_t>::const_iterator get_key_iter(const Variant& key, uint64_t& key_hash) const;
	
	const key_index_t* get_key_index(const Variant& key) const;
	
	const key_index_t* get_key_index(	const Variant& key,
										std::unordered_multimap<uint64_t, uint64_t>::const_iterator& key_iter,
										uint64_t& key_hash) const;
	
	void delete_internal(std::unordered_multimap<uint64_t, uint64_t>::const_iterator key_iter);
	
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
	
	mutable std::mutex index_mutex;		// needs to be locked when modifying index, other threads only read
	std::map<int64_t, std::shared_ptr<block_t>> block_map;
	std::map<uint64_t, key_index_t> index_map;
	std::unordered_multimap<uint64_t, uint64_t> keyhash_map;
	std::list<std::shared_ptr<block_t>> delete_list;
	
	mutable std::mutex update_mutex;
	mutable std::condition_variable update_condition;
	mutable std::queue<std::shared_ptr<KeyValuePair>> update_queue;
	std::thread update_thread;
	
	mutable std::atomic<uint64_t> read_counter {0};
	mutable std::atomic<uint64_t> num_bytes_read {0};
	
	mutable std::atomic<uint64_t> write_counter {0};
	mutable std::atomic<uint64_t> num_bytes_written {0};
	
	struct rewrite_t {
		std::shared_ptr<block_t> block;
		std::shared_ptr<Timer> timer;
		FileSectionInputStream key_stream;
		TypeInput key_in;
		int64_t value_block_size = -1;
		rewrite_t() : key_in(&key_stream) {}
	} rewrite;
	
	mutable int64_t next_sync_id = 0;
	mutable std::map<int64_t, std::thread> sync_jobs;
	
	static const int NUM_INDEX = 3;
	
};


} // keyvalue
} // vnx

#endif /* INCLUDE_VNX_KEYVALUE_SERVER_H_ */
