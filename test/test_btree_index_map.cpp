/*
 * test_btree_index_map.cpp
 *
 *  Created on: Nov 21, 2020
 *      Author: mad
 */

#include <vnx/keyvalue/btree_index_map.h>

#include <assert.h>
#include <random>
#include <iostream>
#include <map>


int main()
{
	{
		std::map<size_t, size_t> ref;
		btree_index_map<size_t, 5, 2> map;
		
		for(int i = 1; i < 1024; ++i) {
			const auto r = i * 8 + rand() % 8;
			ref[i] = r;
			map[r] = i;
		}
		
		for(int i = 1; i < 1024; ++i) {
			assert(map.find(ref[i]) != nullptr);
			assert(*map.find(ref[i]) == i);
			assert(map[ref[i]] == i);
		}
		
		size_t k = 0;
		size_t count = 0;
		for(auto* it = map.begin(k); it != nullptr; it = map.find_next(k)) {
//			std::cout << *it << std::endl;
			count++;
		}
//		std::cout << "count = " << count << std::endl;
		assert(count == ref.size());
		
		for(int i = 1; i < 1024; i += 2) {
			map.erase(ref[i]);
			assert(map.find(ref[i]) == nullptr);
		}
		
		for(int i = 1; i < 512; ++i) {
			map.erase(ref[i]);
			assert(map.find(ref[i]) == nullptr);
		}
		
		map.clear();
		for(int i = 1; i < 1024; ++i) {
			assert(map.find(ref[i]) == nullptr);
		}
	}
	return 0;
}


