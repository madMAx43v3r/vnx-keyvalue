
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/Storage_delete_value.hxx>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Storage_delete_value_return.hxx>

#include <vnx/vnx.h>


namespace vnx {
namespace keyvalue {


const vnx::Hash64 Storage_delete_value::VNX_TYPE_HASH(0x28e40902541d1c63ull);
const vnx::Hash64 Storage_delete_value::VNX_CODE_HASH(0xdd080e4b59198313ull);

vnx::Hash64 Storage_delete_value::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* Storage_delete_value::get_type_name() const {
	return "vnx.keyvalue.Storage.delete_value";
}

const vnx::TypeCode* Storage_delete_value::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_Storage_delete_value;
}

std::shared_ptr<Storage_delete_value> Storage_delete_value::create() {
	return std::make_shared<Storage_delete_value>();
}

std::shared_ptr<vnx::Value> Storage_delete_value::clone() const {
	return std::make_shared<Storage_delete_value>(*this);
}

void Storage_delete_value::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void Storage_delete_value::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void Storage_delete_value::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Storage_delete_value;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, key);
	_visitor.type_end(*_type_code);
}

void Storage_delete_value::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Storage.delete_value\"";
	_out << ", \"key\": "; vnx::write(_out, key);
	_out << "}";
}

void Storage_delete_value::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "key") {
			vnx::from_string(_entry.second, key);
		}
	}
}

vnx::Object Storage_delete_value::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.Storage.delete_value";
	_object["key"] = key;
	return _object;
}

void Storage_delete_value::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "key") {
			_entry.second.to(key);
		}
	}
}

vnx::Variant Storage_delete_value::get_field(const std::string& _name) const {
	if(_name == "key") {
		return vnx::Variant(key);
	}
	return vnx::Variant();
}

void Storage_delete_value::set_field(const std::string& _name, const vnx::Variant& _value) {
	if(_name == "key") {
		_value.to(key);
	} else {
		throw std::logic_error("no such field: '" + _name + "'");
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const Storage_delete_value& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, Storage_delete_value& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* Storage_delete_value::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> Storage_delete_value::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Storage.delete_value";
	type_code->type_hash = vnx::Hash64(0x28e40902541d1c63ull);
	type_code->code_hash = vnx::Hash64(0xdd080e4b59198313ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->is_method = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<Storage_delete_value>(); };
	type_code->return_type = ::vnx::keyvalue::Storage_delete_value_return::static_get_type_code();
	type_code->fields.resize(1);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.is_extended = true;
		field.name = "key";
		field.code = {17};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::Storage_delete_value& value, const TypeCode* type_code, const uint16_t* code) {
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
			case 0: vnx::read(in, value.key, type_code, _field->code.data()); break;
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::Storage_delete_value& value, const TypeCode* type_code, const uint16_t* code) {
	if(code && code[0] == CODE_OBJECT) {
		vnx::write(out, value.to_object(), nullptr, code);
		return;
	}
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_Storage_delete_value;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::Storage_delete_value>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	vnx::write(out, value.key, type_code, type_code->fields[0].code.data());
}

void read(std::istream& in, ::vnx::keyvalue::Storage_delete_value& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::Storage_delete_value& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::Storage_delete_value& value) {
	value.accept(visitor);
}

} // vnx
