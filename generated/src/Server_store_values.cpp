
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/Server_store_values.hxx>
#include <vnx/Input.h>
#include <vnx/Output.h>
#include <vnx/Visitor.h>
#include <vnx/Object.h>
#include <vnx/Struct.h>
#include <vnx/Value.h>
#include <vnx/Variant.h>
#include <vnx/keyvalue/Server_store_values_return.hxx>



namespace vnx {
namespace keyvalue {


const vnx::Hash64 Server_store_values::VNX_TYPE_HASH(0xfff6bea692aee101ull);
const vnx::Hash64 Server_store_values::VNX_CODE_HASH(0xe0ce45007dcc7f21ull);

vnx::Hash64 Server_store_values::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* Server_store_values::get_type_name() const {
	return "vnx.keyvalue.Server.store_values";
}
const vnx::TypeCode* Server_store_values::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_Server_store_values;
}

std::shared_ptr<Server_store_values> Server_store_values::create() {
	return std::make_shared<Server_store_values>();
}

std::shared_ptr<vnx::Value> Server_store_values::clone() const {
	return std::make_shared<Server_store_values>(*this);
}

void Server_store_values::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void Server_store_values::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void Server_store_values::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_store_values;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, values);
	_visitor.type_end(*_type_code);
}

void Server_store_values::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Server.store_values\"";
	_out << ", \"values\": "; vnx::write(_out, values);
	_out << "}";
}

void Server_store_values::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "values") {
			vnx::from_string(_entry.second, values);
		}
	}
}

vnx::Object Server_store_values::to_object() const {
	vnx::Object _object;
	_object["values"] = values;
	return _object;
}

void Server_store_values::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "values") {
			_entry.second.to(values);
		}
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const Server_store_values& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, Server_store_values& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* Server_store_values::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> Server_store_values::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Server.store_values";
	type_code->type_hash = vnx::Hash64(0xfff6bea692aee101ull);
	type_code->code_hash = vnx::Hash64(0xe0ce45007dcc7f21ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->is_method = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<Server_store_values>(); };
	type_code->return_type = ::vnx::keyvalue::Server_store_values_return::static_get_type_code();
	type_code->fields.resize(1);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.is_extended = true;
		field.name = "values";
		field.code = {12, 23, 2, 4, 5, 17, 16};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::Server_store_values& value, const TypeCode* type_code, const uint16_t* code) {
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
			case 0: vnx::read(in, value.values, type_code, _field->code.data()); break;
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::Server_store_values& value, const TypeCode* type_code, const uint16_t* code) {
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_Server_store_values;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::Server_store_values>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	vnx::write(out, value.values, type_code, type_code->fields[0].code.data());
}

void read(std::istream& in, ::vnx::keyvalue::Server_store_values& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::Server_store_values& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::Server_store_values& value) {
	value.accept(visitor);
}

} // vnx
