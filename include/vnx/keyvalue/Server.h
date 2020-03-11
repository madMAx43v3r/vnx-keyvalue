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

#include <unordered_map>


namespace vnx {
namespace keyvalue {

class Server : public ServerBase {
public:
	Server(const std::string& _vnx_name);
	
protected:
	void main() override;
	
	Variant get_value(const Variant& key) const override;
	
	void store_value(const Variant& key, const Variant& value) override;
	
	void delete_value(const Variant& key) override;
	
private:
	typedef std::vector<uint8_t> key_t;
	
	struct key_map_t {
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
	};
	
	std::string get_file_path(const std::string& name, int64_t index) const;
	
	std::shared_ptr<block_t> get_current_block() const;
	
	std::shared_ptr<block_t> add_new_block();
	
	void write_index();
	
private:
	std::shared_ptr<Collection> coll_index;
	
	std::map<int64_t, std::shared_ptr<block_t>> block_map;
	
	std::unordered_map<key_t, key_map_t> key_map;
	
};


} // keyvalue
} // vnx

#endif /* INCLUDE_VNX_KEYVALUE_SERVER_H_ */
