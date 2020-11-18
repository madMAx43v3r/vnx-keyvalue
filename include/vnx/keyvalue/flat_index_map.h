/*
 * flat_index_map.h
 *
 *  Created on: Nov 18, 2020
 *      Author: mad
 */

#ifndef VNX_KEYVALUE_FLAT_INDEX_MAP_H_
#define VNX_KEYVALUE_FLAT_INDEX_MAP_H_

#include <array>
#include <vector>


template<typename T, size_t N = 256>
class flat_index_map {
protected:
	typedef std::array<T, N> block_t;

public:
	flat_index_map() {}
	
	flat_index_map(flat_index_map&) = delete;
	
	~flat_index_map() {
		for(auto& p_block : m_index) {
			delete p_block;
			p_block = nullptr;
		}
	}
	
	flat_index_map& operator=(flat_index_map&) = delete;
	
	T& operator[](size_t i) {
		const auto i_block = i / N;
		const auto k_block = i % N;
		if(i_block >= m_index.size()) {
			m_index.resize(i_block + 1);
		}
		block_t*& p_block = m_index[i_block];
		if(!p_block) {
			p_block = new block_t();
		}
		return (*p_block)[k_block];
	}
	
	void insert(size_t i, const T& value) {
		(*this)[i] = value;
	}
	
	T* find(size_t i) const {
		const auto i_block = i / N;
		const auto k_block = i % N;
		if(i_block < m_index.size()) {
			if(block_t* p_block = m_index[i_block]) {
				if(T& value = (*p_block)[k_block]) {
					return &value;
				}
			}
		}
		return nullptr;
	}
	
	T* find_next(size_t& i) const {
		auto j = i;
		auto k_block = ++j % N;
		for(auto i_block = j / N; i_block < m_index.size(); ++i_block) {
			if(block_t* p_block = m_index[i_block]) {
				for(auto k = k_block; k < N; ++k) {
					if(T& value = (*p_block)[k]) {
						i = j + (k - k_block);
						return &value;
					}
				}
			}
			j += N - k_block;
			k_block = 0;
		}
		return nullptr;
	}
	
	T* begin(size_t& i) const {
		return find_next(i = -1);
	}
	
	void erase(size_t i) {
		const auto i_block = i / N;
		const auto k_block = i % N;
		if(i_block < m_index.size()) {
			block_t*& p_block = m_index[i_block];
			if(p_block) {
				if(T& value = (*p_block)[k_block]) {
					value = T();
					for(size_t k = 0; k < N; ++k) {
						if((*p_block)[k]) {
							return;
						}
					}
					delete p_block;
					p_block = nullptr;
				}
			}
		}
	}
	
private:
	std::vector<block_t*> m_index;
	
};


#endif /* VNX_KEYVALUE_FLAT_INDEX_MAP_H_ */
