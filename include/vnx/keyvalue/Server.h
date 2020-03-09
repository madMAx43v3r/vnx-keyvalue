/*
 * Server.h
 *
 *  Created on: Mar 9, 2020
 *      Author: mad
 */

#ifndef INCLUDE_VNX_KEYVALUE_SERVER_H_
#define INCLUDE_VNX_KEYVALUE_SERVER_H_

#include <vnx/keyvalue/ServerBase.hxx>

#include <unordered_map>


namespace vnx {
namespace keyvalue {

class Server : public ServerBase {
public:
	
	
protected:
	void main() override;
	
	Variant get_value(const Variant& key) const override;
	
	void store_value(const Variant& key, const Variant& value) override;
	
	void delete_value(const Variant& key) override;
	
private:
	typedef std::vector<uint8_t> key_t;
	
	struct key_map_t {
		int32_t block_num = -1;
		uint32_t num_bytes = 0;
		int64_t block_offset = -1;
	};
	
private:
	std::unordered_map<key_t, key_map_t> key_map;
	
};


} // keyvalue
} // vnx

#endif /* INCLUDE_VNX_KEYVALUE_SERVER_H_ */
