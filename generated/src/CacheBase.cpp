
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/CacheBase.hxx>
#include <vnx/NoSuchMethod.hxx>
#include <vnx/Module.h>
#include <vnx/ModuleInterface_vnx_get_config.hxx>
#include <vnx/ModuleInterface_vnx_get_config_return.hxx>
#include <vnx/ModuleInterface_vnx_get_config_object.hxx>
#include <vnx/ModuleInterface_vnx_get_config_object_return.hxx>
#include <vnx/ModuleInterface_vnx_get_module_info.hxx>
#include <vnx/ModuleInterface_vnx_get_module_info_return.hxx>
#include <vnx/ModuleInterface_vnx_get_type_code.hxx>
#include <vnx/ModuleInterface_vnx_get_type_code_return.hxx>
#include <vnx/ModuleInterface_vnx_restart.hxx>
#include <vnx/ModuleInterface_vnx_restart_return.hxx>
#include <vnx/ModuleInterface_vnx_self_test.hxx>
#include <vnx/ModuleInterface_vnx_self_test_return.hxx>
#include <vnx/ModuleInterface_vnx_set_config.hxx>
#include <vnx/ModuleInterface_vnx_set_config_return.hxx>
#include <vnx/ModuleInterface_vnx_set_config_object.hxx>
#include <vnx/ModuleInterface_vnx_set_config_object_return.hxx>
#include <vnx/ModuleInterface_vnx_stop.hxx>
#include <vnx/ModuleInterface_vnx_stop_return.hxx>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Entry.hxx>
#include <vnx/keyvalue/Storage_cancel_sync_job.hxx>
#include <vnx/keyvalue/Storage_cancel_sync_job_return.hxx>
#include <vnx/keyvalue/Storage_delete_value.hxx>
#include <vnx/keyvalue/Storage_delete_value_return.hxx>
#include <vnx/keyvalue/Storage_get_key.hxx>
#include <vnx/keyvalue/Storage_get_key_return.hxx>
#include <vnx/keyvalue/Storage_get_keys.hxx>
#include <vnx/keyvalue/Storage_get_keys_return.hxx>
#include <vnx/keyvalue/Storage_get_value.hxx>
#include <vnx/keyvalue/Storage_get_value_return.hxx>
#include <vnx/keyvalue/Storage_get_value_locked.hxx>
#include <vnx/keyvalue/Storage_get_value_locked_return.hxx>
#include <vnx/keyvalue/Storage_get_values.hxx>
#include <vnx/keyvalue/Storage_get_values_return.hxx>
#include <vnx/keyvalue/Storage_store_value.hxx>
#include <vnx/keyvalue/Storage_store_value_return.hxx>
#include <vnx/keyvalue/Storage_store_value_delay.hxx>
#include <vnx/keyvalue/Storage_store_value_delay_return.hxx>
#include <vnx/keyvalue/Storage_store_values.hxx>
#include <vnx/keyvalue/Storage_store_values_return.hxx>
#include <vnx/keyvalue/Storage_store_values_delay.hxx>
#include <vnx/keyvalue/Storage_store_values_delay_return.hxx>
#include <vnx/keyvalue/Storage_sync_all.hxx>
#include <vnx/keyvalue/Storage_sync_all_return.hxx>
#include <vnx/keyvalue/Storage_sync_all_keys.hxx>
#include <vnx/keyvalue/Storage_sync_all_keys_return.hxx>
#include <vnx/keyvalue/Storage_sync_from.hxx>
#include <vnx/keyvalue/Storage_sync_from_return.hxx>
#include <vnx/keyvalue/Storage_sync_range.hxx>
#include <vnx/keyvalue/Storage_sync_range_return.hxx>
#include <vnx/keyvalue/Storage_unlock.hxx>
#include <vnx/keyvalue/Storage_unlock_return.hxx>

#include <vnx/vnx.h>


namespace vnx {
namespace keyvalue {


const vnx::Hash64 CacheBase::VNX_TYPE_HASH(0xce1232a3eb35ccf9ull);
const vnx::Hash64 CacheBase::VNX_CODE_HASH(0x810536ba00ca71b3ull);

CacheBase::CacheBase(const std::string& _vnx_name)
	:	Module::Module(_vnx_name)
{
}

vnx::Hash64 CacheBase::get_type_hash() const {
	return VNX_TYPE_HASH;
}

std::string CacheBase::get_type_name() const {
	return "vnx.keyvalue.Cache";
}

const vnx::TypeCode* CacheBase::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_CacheBase;
}

void CacheBase::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_CacheBase;
	_visitor.type_begin(*_type_code);
	_visitor.type_end(*_type_code);
}

void CacheBase::write(std::ostream& _out) const {
	_out << "{";
	_out << "}";
}

void CacheBase::read(std::istream& _in) {
	if(auto _json = vnx::read_json(_in)) {
		from_object(_json->to_object());
	}
}

vnx::Object CacheBase::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.Cache";
	return _object;
}

void CacheBase::from_object(const vnx::Object& _object) {
}

vnx::Variant CacheBase::get_field(const std::string& _name) const {
	return vnx::Variant();
}

void CacheBase::set_field(const std::string& _name, const vnx::Variant& _value) {
	throw std::logic_error("no such field: '" + _name + "'");
}

/// \private
std::ostream& operator<<(std::ostream& _out, const CacheBase& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, CacheBase& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* CacheBase::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> CacheBase::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Cache";
	type_code->type_hash = vnx::Hash64(0xce1232a3eb35ccf9ull);
	type_code->code_hash = vnx::Hash64(0x810536ba00ca71b3ull);
	type_code->is_native = true;
	type_code->methods.resize(25);
	type_code->methods[0] = ::vnx::ModuleInterface_vnx_get_config_object::static_get_type_code();
	type_code->methods[1] = ::vnx::ModuleInterface_vnx_get_config::static_get_type_code();
	type_code->methods[2] = ::vnx::ModuleInterface_vnx_set_config_object::static_get_type_code();
	type_code->methods[3] = ::vnx::ModuleInterface_vnx_set_config::static_get_type_code();
	type_code->methods[4] = ::vnx::ModuleInterface_vnx_get_type_code::static_get_type_code();
	type_code->methods[5] = ::vnx::ModuleInterface_vnx_get_module_info::static_get_type_code();
	type_code->methods[6] = ::vnx::ModuleInterface_vnx_restart::static_get_type_code();
	type_code->methods[7] = ::vnx::ModuleInterface_vnx_stop::static_get_type_code();
	type_code->methods[8] = ::vnx::ModuleInterface_vnx_self_test::static_get_type_code();
	type_code->methods[9] = ::vnx::keyvalue::Storage_get_value::static_get_type_code();
	type_code->methods[10] = ::vnx::keyvalue::Storage_get_value_locked::static_get_type_code();
	type_code->methods[11] = ::vnx::keyvalue::Storage_get_values::static_get_type_code();
	type_code->methods[12] = ::vnx::keyvalue::Storage_get_key::static_get_type_code();
	type_code->methods[13] = ::vnx::keyvalue::Storage_get_keys::static_get_type_code();
	type_code->methods[14] = ::vnx::keyvalue::Storage_unlock::static_get_type_code();
	type_code->methods[15] = ::vnx::keyvalue::Storage_sync_from::static_get_type_code();
	type_code->methods[16] = ::vnx::keyvalue::Storage_sync_range::static_get_type_code();
	type_code->methods[17] = ::vnx::keyvalue::Storage_sync_all::static_get_type_code();
	type_code->methods[18] = ::vnx::keyvalue::Storage_sync_all_keys::static_get_type_code();
	type_code->methods[19] = ::vnx::keyvalue::Storage_cancel_sync_job::static_get_type_code();
	type_code->methods[20] = ::vnx::keyvalue::Storage_store_value::static_get_type_code();
	type_code->methods[21] = ::vnx::keyvalue::Storage_store_values::static_get_type_code();
	type_code->methods[22] = ::vnx::keyvalue::Storage_store_value_delay::static_get_type_code();
	type_code->methods[23] = ::vnx::keyvalue::Storage_store_values_delay::static_get_type_code();
	type_code->methods[24] = ::vnx::keyvalue::Storage_delete_value::static_get_type_code();
	type_code->build();
	return type_code;
}

void CacheBase::vnx_handle_switch(std::shared_ptr<const vnx::Sample> _sample) {
}

std::shared_ptr<vnx::Value> CacheBase::vnx_call_switch(std::shared_ptr<const vnx::Value> _method, const vnx::request_id_t& _request_id) {
	const auto _type_hash = _method->get_type_hash();
	if(_type_hash == vnx::Hash64(0x17f58f68bf83abc0ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_config_object>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_get_config_object_return::create();
		_return_value->_ret_0 = vnx_get_config_object();
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0xbbc7f1a01044d294ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_config>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_get_config_return::create();
		_return_value->_ret_0 = vnx_get_config(_args->name);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0xca30f814f17f322full)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_set_config_object>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_set_config_object_return::create();
		vnx_set_config_object(_args->config);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x362aac91373958b7ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_set_config>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_set_config_return::create();
		vnx_set_config(_args->name, _args->value);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x305ec4d628960e5dull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_type_code>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_get_type_code_return::create();
		_return_value->_ret_0 = vnx_get_type_code();
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0xf6d82bdf66d034a1ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_module_info>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_get_module_info_return::create();
		_return_value->_ret_0 = vnx_get_module_info();
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x9e95dc280cecca1bull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_restart>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_restart_return::create();
		vnx_restart();
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x7ab49ce3d1bfc0d2ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_stop>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_stop_return::create();
		vnx_stop();
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x6ce3775b41a42697ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_self_test>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_self_test_return::create();
		_return_value->_ret_0 = vnx_self_test();
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x8f47587c24580111ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_value>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		get_value_async(_args->key, _request_id);
		return 0;
	} else if(_type_hash == vnx::Hash64(0xfd0f1035b160c34full)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_value_locked>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		get_value_locked_async(_args->key, _args->timeout_ms, _request_id);
		return 0;
	} else if(_type_hash == vnx::Hash64(0x7427b9c6f9a68c30ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_values>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		get_values_async(_args->keys, _request_id);
		return 0;
	} else if(_type_hash == vnx::Hash64(0xc7c81afb9921d76ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_key>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		get_key_async(_args->version, _request_id);
		return 0;
	} else if(_type_hash == vnx::Hash64(0xd75f52c837f6ac18ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_keys>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		get_keys_async(_args->versions, _request_id);
		return 0;
	} else if(_type_hash == vnx::Hash64(0x25041c8bd6ea1977ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_unlock>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_unlock_return::create();
		unlock(_args->key);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0xacb686150d0602a6ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_from>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_sync_from_return::create();
		_return_value->_ret_0 = sync_from(_args->topic, _args->version);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x57e04cb98c5e5698ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_range>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_sync_range_return::create();
		_return_value->_ret_0 = sync_range(_args->topic, _args->begin, _args->end);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x973bf802c6c0aaabull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_all>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_sync_all_return::create();
		_return_value->_ret_0 = sync_all(_args->topic);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0xba52cec87e1556e5ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_sync_all_keys>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_sync_all_keys_return::create();
		_return_value->_ret_0 = sync_all_keys(_args->topic);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x79f19daa5278fbc0ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_cancel_sync_job>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_cancel_sync_job_return::create();
		cancel_sync_job(_args->job_id);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0xa1b7f9743ce3a0f1ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_store_value>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_store_value_return::create();
		store_value(_args->key, _args->value);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x22e477486f9c73e0ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_store_values>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_store_values_return::create();
		store_values(_args->values);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x8e78c89a3ce01406ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_store_value_delay>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_store_value_delay_return::create();
		store_value_delay(_args->key, _args->value, _args->delay_ms);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0xd00ca16a73abf985ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_store_values_delay>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_store_values_delay_return::create();
		store_values_delay(_args->values, _args->delay_ms);
		return _return_value;
	} else if(_type_hash == vnx::Hash64(0x28e40902541d1c63ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_delete_value>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::keyvalue::Storage_delete_value_return::create();
		delete_value(_args->key);
		return _return_value;
	}
	auto _ex = vnx::NoSuchMethod::create();
	_ex->dst_mac = vnx_request ? vnx_request->dst_mac : vnx::Hash64();
	_ex->method = _method->get_type_name();
	return _ex;
}

void CacheBase::get_value_async_return(const vnx::request_id_t& _request_id, const std::shared_ptr<const ::vnx::keyvalue::Entry>& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_value_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_return(_request_id, _return_value);
}

void CacheBase::get_value_locked_async_return(const vnx::request_id_t& _request_id, const std::shared_ptr<const ::vnx::keyvalue::Entry>& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_value_locked_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_return(_request_id, _return_value);
}

void CacheBase::get_values_async_return(const vnx::request_id_t& _request_id, const std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>>& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_values_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_return(_request_id, _return_value);
}

void CacheBase::get_key_async_return(const vnx::request_id_t& _request_id, const ::vnx::Variant& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_key_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_return(_request_id, _return_value);
}

void CacheBase::get_keys_async_return(const vnx::request_id_t& _request_id, const std::vector<std::pair<uint64_t, ::vnx::Variant>>& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_keys_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_return(_request_id, _return_value);
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::CacheBase& value, const TypeCode* type_code, const uint16_t* code) {
	if(code) {
		switch(code[0]) {
			case CODE_OBJECT:
			case CODE_ALT_OBJECT: {
				Object tmp;
				vnx::read(in, tmp, type_code, code);
				value.from_object(tmp);
				return;
			}
			case CODE_DYNAMIC:
			case CODE_ALT_DYNAMIC:
				vnx::read_dynamic(in, value);
				return;
		}
	}
	if(!type_code) {
		vnx::skip(in, type_code, code);
		return;
	}
	if(code) {
		switch(code[0]) {
			case CODE_STRUCT: type_code = type_code->depends[code[1]]; break;
			case CODE_ALT_STRUCT: type_code = type_code->depends[vnx::flip_bytes(code[1])]; break;
			default: {
				vnx::skip(in, type_code, code);
				return;
			}
		}
	}
	if(type_code->is_matched) {
	}
	for(const vnx::TypeField* _field : type_code->ext_fields) {
		switch(_field->native_index) {
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::CacheBase& value, const TypeCode* type_code, const uint16_t* code) {
	if(code && code[0] == CODE_OBJECT) {
		vnx::write(out, value.to_object(), nullptr, code);
		return;
	}
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_CacheBase;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::CacheBase>(out);
	}
	else if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
}

void read(std::istream& in, ::vnx::keyvalue::CacheBase& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::CacheBase& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::CacheBase& value) {
	value.accept(visitor);
}

} // vnx
