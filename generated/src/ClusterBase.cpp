
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/ClusterBase.hxx>
#include <vnx/NoSuchMethod.hxx>
#include <vnx/Module.h>
#include <vnx/ModuleInterface_vnx_get_type_code.hxx>
#include <vnx/ModuleInterface_vnx_get_type_code_return.hxx>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Entry.hxx>
#include <vnx/keyvalue/Storage_cancel_sync_job.hxx>
#include <vnx/keyvalue/Storage_cancel_sync_job_return.hxx>
#include <vnx/keyvalue/Storage_delete_value.hxx>
#include <vnx/keyvalue/Storage_delete_value_return.hxx>
#include <vnx/keyvalue/Storage_get_value.hxx>
#include <vnx/keyvalue/Storage_get_value_locked.hxx>
#include <vnx/keyvalue/Storage_get_value_locked_return.hxx>
#include <vnx/keyvalue/Storage_get_value_return.hxx>
#include <vnx/keyvalue/Storage_get_values.hxx>
#include <vnx/keyvalue/Storage_get_values_return.hxx>
#include <vnx/keyvalue/Storage_get_version_key.hxx>
#include <vnx/keyvalue/Storage_get_version_key_return.hxx>
#include <vnx/keyvalue/Storage_get_version_keys.hxx>
#include <vnx/keyvalue/Storage_get_version_keys_return.hxx>
#include <vnx/keyvalue/Storage_store_value.hxx>
#include <vnx/keyvalue/Storage_store_value_return.hxx>
#include <vnx/keyvalue/Storage_store_values.hxx>
#include <vnx/keyvalue/Storage_store_values_return.hxx>
#include <vnx/keyvalue/Storage_sync_all.hxx>
#include <vnx/keyvalue/Storage_sync_all_keys.hxx>
#include <vnx/keyvalue/Storage_sync_all_keys_return.hxx>
#include <vnx/keyvalue/Storage_sync_all_return.hxx>
#include <vnx/keyvalue/Storage_sync_from.hxx>
#include <vnx/keyvalue/Storage_sync_from_return.hxx>
#include <vnx/keyvalue/Storage_sync_range.hxx>
#include <vnx/keyvalue/Storage_sync_range_return.hxx>
#include <vnx/keyvalue/Storage_unlock.hxx>
#include <vnx/keyvalue/Storage_unlock_return.hxx>

#include <vnx/vnx.h>


namespace vnx {
namespace keyvalue {


const vnx::Hash64 ClusterBase::VNX_TYPE_HASH(0xd15d8542fc63cb26ull);
const vnx::Hash64 ClusterBase::VNX_CODE_HASH(0x9679d083a6f600b0ull);

ClusterBase::ClusterBase(const std::string& _vnx_name)
	:	Module::Module(_vnx_name)
{
}

vnx::Hash64 ClusterBase::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* ClusterBase::get_type_name() const {
	return "vnx.keyvalue.Cluster";
}
const vnx::TypeCode* ClusterBase::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_ClusterBase;
}

void ClusterBase::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_ClusterBase;
	_visitor.type_begin(*_type_code);
	_visitor.type_end(*_type_code);
}

void ClusterBase::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Cluster\"";
	_out << "}";
}

void ClusterBase::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
}

vnx::Object ClusterBase::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.Cluster";
	return _object;
}

void ClusterBase::from_object(const vnx::Object& _object) {
}

/// \private
std::ostream& operator<<(std::ostream& _out, const ClusterBase& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, ClusterBase& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* ClusterBase::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> ClusterBase::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Cluster";
	type_code->type_hash = vnx::Hash64(0xd15d8542fc63cb26ull);
	type_code->code_hash = vnx::Hash64(0x9679d083a6f600b0ull);
	type_code->is_native = true;
	type_code->methods.resize(15);
	type_code->methods[0] = ::vnx::ModuleInterface_vnx_get_type_code::static_get_type_code();
	type_code->methods[1] = ::vnx::keyvalue::Storage_get_value::static_get_type_code();
	type_code->methods[2] = ::vnx::keyvalue::Storage_get_value_locked::static_get_type_code();
	type_code->methods[3] = ::vnx::keyvalue::Storage_get_values::static_get_type_code();
	type_code->methods[4] = ::vnx::keyvalue::Storage_get_version_key::static_get_type_code();
	type_code->methods[5] = ::vnx::keyvalue::Storage_get_version_keys::static_get_type_code();
	type_code->methods[6] = ::vnx::keyvalue::Storage_unlock::static_get_type_code();
	type_code->methods[7] = ::vnx::keyvalue::Storage_sync_from::static_get_type_code();
	type_code->methods[8] = ::vnx::keyvalue::Storage_sync_range::static_get_type_code();
	type_code->methods[9] = ::vnx::keyvalue::Storage_sync_all::static_get_type_code();
	type_code->methods[10] = ::vnx::keyvalue::Storage_sync_all_keys::static_get_type_code();
	type_code->methods[11] = ::vnx::keyvalue::Storage_cancel_sync_job::static_get_type_code();
	type_code->methods[12] = ::vnx::keyvalue::Storage_store_value::static_get_type_code();
	type_code->methods[13] = ::vnx::keyvalue::Storage_store_values::static_get_type_code();
	type_code->methods[14] = ::vnx::keyvalue::Storage_delete_value::static_get_type_code();
	type_code->build();
	return type_code;
}

void ClusterBase::vnx_handle_switch(std::shared_ptr<const vnx::Sample> _sample) {
}

std::shared_ptr<vnx::Value> ClusterBase::vnx_call_switch(std::shared_ptr<const vnx::Value> _method, const vnx::request_id_t& _request_id) {
	const auto _type_hash = _method->get_type_hash();
	if(_type_hash == vnx::Hash64(0x305ec4d628960e5dull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::ModuleInterface_vnx_get_type_code>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		auto _return_value = ::vnx::ModuleInterface_vnx_get_type_code_return::create();
		_return_value->_ret_0 = vnx_get_type_code();
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
	} else if(_type_hash == vnx::Hash64(0xb99ad29183ddd3feull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_version_key>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		get_version_key_async(_args->version, _request_id);
		return 0;
	} else if(_type_hash == vnx::Hash64(0xe9276407215550f2ull)) {
		auto _args = std::dynamic_pointer_cast<const ::vnx::keyvalue::Storage_get_version_keys>(_method);
		if(!_args) {
			throw std::logic_error("vnx_call_switch(): !_args");
		}
		get_version_keys_async(_args->versions, _request_id);
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
	_ex->dst_mac = vnx_request ? vnx_request->dst_mac : 0;
	_ex->method = _method->get_type_name();
	return _ex;
}

void ClusterBase::get_value_async_return(const vnx::request_id_t& _request_id, const std::shared_ptr<const ::vnx::keyvalue::Entry>& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_value_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_callback(_request_id, _return_value);
}

void ClusterBase::get_value_locked_async_return(const vnx::request_id_t& _request_id, const std::shared_ptr<const ::vnx::keyvalue::Entry>& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_value_locked_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_callback(_request_id, _return_value);
}

void ClusterBase::get_values_async_return(const vnx::request_id_t& _request_id, const std::vector<std::shared_ptr<const ::vnx::keyvalue::Entry>>& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_values_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_callback(_request_id, _return_value);
}

void ClusterBase::get_version_key_async_return(const vnx::request_id_t& _request_id, const ::vnx::Variant& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_version_key_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_callback(_request_id, _return_value);
}

void ClusterBase::get_version_keys_async_return(const vnx::request_id_t& _request_id, const std::vector<std::pair<uint64_t, ::vnx::Variant>>& _ret_0) const {
	auto _return_value = ::vnx::keyvalue::Storage_get_version_keys_return::create();
	_return_value->_ret_0 = _ret_0;
	vnx_async_callback(_request_id, _return_value);
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::ClusterBase& value, const TypeCode* type_code, const uint16_t* code) {
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
		throw std::logic_error("read(): type_code == 0");
	}
	if(code) {
		switch(code[0]) {
			case CODE_STRUCT: type_code = type_code->depends[code[1]]; break;
			case CODE_ALT_STRUCT: type_code = type_code->depends[vnx::flip_bytes(code[1])]; break;
			default: vnx::skip(in, type_code, code); return;
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

void write(TypeOutput& out, const ::vnx::keyvalue::ClusterBase& value, const TypeCode* type_code, const uint16_t* code) {
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_ClusterBase;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::ClusterBase>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
}

void read(std::istream& in, ::vnx::keyvalue::ClusterBase& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::ClusterBase& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::ClusterBase& value) {
	value.accept(visitor);
}

} // vnx
