
// AUTO GENERATED by vnxcppcodegen

#include <vnx/vnx.h>
#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/Server_get_values.hxx>
#include <vnx/Value.h>
#include <vnx/Variant.hpp>
#include <vnx/keyvalue/Server_get_values_return.hxx>



namespace vnx {
namespace keyvalue {


const vnx::Hash64 Server_get_values::VNX_TYPE_HASH(0x29edfe1764d9e55ull);
const vnx::Hash64 Server_get_values::VNX_CODE_HASH(0x230ae063f42d4098ull);

vnx::Hash64 Server_get_values::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* Server_get_values::get_type_name() const {
	return "vnx.keyvalue.Server.get_values";
}
const vnx::TypeCode* Server_get_values::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_Server_get_values;
}

std::shared_ptr<Server_get_values> Server_get_values::create() {
	return std::make_shared<Server_get_values>();
}

std::shared_ptr<vnx::Value> Server_get_values::clone() const {
	return std::make_shared<Server_get_values>(*this);
}

void Server_get_values::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void Server_get_values::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void Server_get_values::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_get_values;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, keys);
	_visitor.type_end(*_type_code);
}

void Server_get_values::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Server.get_values\"";
	_out << ", \"keys\": "; vnx::write(_out, keys);
	_out << "}";
}

void Server_get_values::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "keys") {
			vnx::from_string(_entry.second, keys);
		}
	}
}

vnx::Object Server_get_values::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.Server.get_values";
	_object["keys"] = keys;
	return _object;
}

void Server_get_values::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "keys") {
			_entry.second.to(keys);
		}
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const Server_get_values& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, Server_get_values& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* Server_get_values::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> Server_get_values::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Server.get_values";
	type_code->type_hash = vnx::Hash64(0x29edfe1764d9e55ull);
	type_code->code_hash = vnx::Hash64(0x230ae063f42d4098ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->is_method = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<Server_get_values>(); };
	type_code->return_type = ::vnx::keyvalue::Server_get_values_return::static_get_type_code();
	type_code->fields.resize(1);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.is_extended = true;
		field.name = "keys";
		field.code = {12, 17};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::Server_get_values& value, const TypeCode* type_code, const uint16_t* code) {
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
	const char* const _buf = in.read(type_code->total_field_size);
	if(type_code->is_matched) {
	}
	for(const vnx::TypeField* _field : type_code->ext_fields) {
		switch(_field->native_index) {
			case 0: vnx::read(in, value.keys, type_code, _field->code.data()); break;
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::Server_get_values& value, const TypeCode* type_code, const uint16_t* code) {
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_Server_get_values;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::Server_get_values>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	vnx::write(out, value.keys, type_code, type_code->fields[0].code.data());
}

void read(std::istream& in, ::vnx::keyvalue::Server_get_values& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::Server_get_values& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::Server_get_values& value) {
	value.accept(visitor);
}

} // vnx
