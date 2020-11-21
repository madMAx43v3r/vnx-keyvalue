/*
 * btree_index_map.h
 *
 *  Created on: Nov 21, 2020
 *      Author: mad
 */

#ifndef VNX_KEYVALUE_BTREE_INDEX_MAP_H_
#define VNX_KEYVALUE_BTREE_INDEX_MAP_H_

#include <array>
#include <vector>


template<typename T, size_t M = 5, size_t N = 4>
class btree_index_map {
protected:
	typedef std::array<void*, (1 << N)> node_t;
	typedef std::array<T, (1 << N)> block_t;

public:
	btree_index_map() {}
	
	btree_index_map(btree_index_map&) = delete;
	
	~btree_index_map() {
		clear();
	}
	
	btree_index_map& operator=(btree_index_map&) = delete;
	
	T& operator[](const size_t i)
	{
		const auto i_block = i >> (N * M);
		if(i_block >= m_index.size()) {
			m_index.resize(i_block + 1);
		}
		node_t*& p_block = m_index[i_block];
		if(!p_block) {
			p_block = new node_t();
		}
		return get_ex(i, M - 1, p_block);
	}
	
	void insert(const size_t i, const T& value) {
		(*this)[i] = value;
	}
	
	T* find(const size_t i) const
	{
		const auto i_block = i >> (N * M);
		if(i_block < m_index.size()) {
			if(node_t* p_block = m_index[i_block]) {
				return find_ex(i, M - 1, p_block);
			}
		}
		return nullptr;
	}
	
	T* find_next(size_t& i) const
	{
		auto j = i + 1;
		for(auto i_block = j >> (N * M); i_block < m_index.size(); ++i_block) {
			if(node_t* p_block = m_index[i_block]) {
				if(T* p_value = find_next_ex(i, j, M - 1, p_block)) {
					return p_value;
				} else {
					continue;
				}
			}
			j = ((j >> (N * M)) + 1) << (N * M);
		}
		return nullptr;
	}
	
	T* begin(size_t& i) const {
		return find_next(i = -1);
	}
	
	void erase(const size_t i)
	{
		const auto i_block = i >> (N * M);
		if(i_block < m_index.size()) {
			if(node_t*& p_block = m_index[i_block]) {
				if(erase_ex(i, M - 1, p_block)) {
					for(auto v : *((node_t*)p_block)) {
						if(v) {
							return;
						}
					}
					delete p_block;
					p_block = nullptr;
				}
			}
		}
	}
	
	void clear()
	{
		for(auto& p_block : m_index) {
			if(p_block) {
				delete_ex(M - 1, p_block);
				delete p_block;
				p_block = nullptr;
			}
		}
		m_index.clear();
	}
	
private:
	T& get_ex(const size_t i, const size_t level, node_t* node)
	{
		const auto i_block = (i >> (N * level)) & ((1 << N) - 1);
		void*& p_block = (*node)[i_block];
		if(!p_block) {
			if(level > 1) {
				p_block = new node_t();
			} else {
				p_block = new block_t();
			}
		}
		if(level > 1) {
			return get_ex(i, level - 1, (node_t*)p_block);
		} else {
			const auto k_block = i & ((1 << N) - 1);
			return (*((block_t*)p_block))[k_block];
		}
	}
	
	T* find_ex(const size_t i, const size_t level, node_t* node) const
	{
		const auto i_block = (i >> (N * level)) & ((1 << N) - 1);
		if(void* p_block = (*node)[i_block]) {
			if(level > 1) {
				return find_ex(i, level - 1, (node_t*)p_block);
			} else {
				const auto k_block = i & ((1 << N) - 1);
				if(T& value = (*((block_t*)p_block))[k_block]) {
					return &value;
				}
			}
		}
		return nullptr;
	}
	
	T* find_next_ex(size_t& i, size_t& j, const size_t level, node_t* node) const
	{
		auto i_block = (j >> (N * level)) & ((1 << N) - 1);
		for(; i_block < (1 << N); ++i_block) {
			if(level > 1) {
				if(node_t* p_block = (node_t*)(*node)[i_block]) {
					if(T* p_value = find_next_ex(i, j, level - 1, p_block)) {
						return p_value;
					} else {
						continue;
					}
				}
			} else {
				if(block_t* p_block = (block_t*)(*node)[i_block]) {
					const auto k_block = j & ((1 << N) - 1);
					for(auto k = k_block; k < (1 << N); ++k) {
						if(T& value = (*p_block)[k]) {
							i = j + (k - k_block);
							return &value;
						}
					}
				}
			}
			j = ((j >> (N * level)) + 1) << (N * level);
		}
		return nullptr;
	}
	
	bool erase_ex(const size_t i, const size_t level, node_t* node)
	{
		const auto i_block = (i >> (N * level)) & ((1 << N) - 1);
		if(void*& p_block = (*node)[i_block]) {
			if(level > 1) {
				if(erase_ex(i, level - 1, (node_t*)p_block)) {
					for(auto v : *((node_t*)p_block)) {
						if(v) {
							return false;
						}
					}
					delete (node_t*)p_block;
					p_block = nullptr;
					return true;
				}
			} else {
				const auto k_block = i & ((1 << N) - 1);
				if(T& value = (*((block_t*)p_block))[k_block]) {
					value = T();
					for(auto v : *((block_t*)p_block)) {
						if(v) {
							return false;
						}
					}
					delete (block_t*)p_block;
					p_block = nullptr;
					return true;
				}
			}
		}
		return false;
	}
	
	void delete_ex(const size_t level, node_t* node)
	{
		for(auto& v : *node) {
			if(v) {
				if(level > 1) {
					delete_ex(level - 1, (node_t*)v);
					delete (node_t*)v;
				} else {
					delete (block_t*)v;
				}
				v = nullptr;
			}
		}
	}
	
private:
	std::vector<node_t*> m_index;
	
};


#endif /* VNX_KEYVALUE_BTREE_INDEX_MAP_H_ */
