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
	
	void get_value_async(	const Variant& key,
							const std::function<void(const std::shared_ptr<const Value>&)>& callback,
							const vnx::request_id_t& request_id) const override;
	
	void get_values_async(	const std::vector<Variant>& keys,
							const std::function<void(const std::vector<std::shared_ptr<const Value>>&)>& callback,
							const vnx::request_id_t& request_id) const override;
	
	void store_value(const Variant& key, const std::shared_ptr<const Value>& value) override;
	
	void delete_value(const Variant& key) override;
	
private:
	struct key_index_t {
		int64_t block_index = -1;
		int64_t block_offset = -1;
		int64_t num_bytes = 0;
	};
	
	struct block_t {
		File key_file;
		File value_file;
		int64_t index = -1;
		int64_t num_bytes_used = 0;
		int64_t num_bytes_total = 0;
		std::atomic<size_t> num_pending;
	};
	
	struct read_result_t {
		std::function<void(const std::shared_ptr<const Value>&)> callback;
	};
	
	struct read_result_many_t {
		std::atomic<size_t> num_left;
		std::vector<std::shared_ptr<const Value>> values;
		std::function<void(const std::vector<std::shared_ptr<const Value>>&)> callback;
	};
	
	struct read_item_t {
		std::shared_ptr<block_t> block;
		uint32_t result_index = 0;
		int fd = 0;
		int64_t offset = 0;
		size_t num_bytes = 0;
		std::shared_ptr<read_result_t> result;
		std::shared_ptr<read_result_many_t> result_many;
	};
	
	std::string get_file_path(const std::string& name, int64_t index) const;
	
	std::shared_ptr<block_t> get_current_block() const;
	
	std::shared_ptr<block_t> get_block(int64_t index) const;
	
	key_index_t get_key_index(const Variant& key) const;
	
	std::shared_ptr<block_t> add_new_block();
	
	void delete_value(const Variant& key, const key_index_t& index);
	
	void check_rewrite();
	
	void rewrite_func();
	
	void write_index();
	
	void print_stats();
	
	void read_loop();
	
private:
	std::shared_ptr<Collection> coll_index;
	
	std::map<int64_t, std::shared_ptr<block_t>> block_map;
	
	std::unordered_map<Variant, key_index_t> key_map;
	
	mutable std::mutex read_mutex;
	mutable std::condition_variable read_condition;
	
	std::vector<std::thread> read_threads;
	mutable std::queue<read_item_t> read_queue;
	
	mutable uint64_t read_counter = 0;
	mutable uint64_t num_bytes_read = 0;
	
	uint64_t write_counter = 0;
	uint64_t num_bytes_written = 0;
	
	struct rewrite_t {
		std::shared_ptr<block_t> block;
		std::shared_ptr<Timer> timer;
		std::shared_ptr<PointerInputStream> key_stream;
		std::shared_ptr<TypeInput> key_in;
	} rewrite;
	
	std::list<std::shared_ptr<block_t>> delete_list;
	
};


} // keyvalue
} // vnx

#endif /* INCLUDE_VNX_KEYVALUE_SERVER_H_ */
