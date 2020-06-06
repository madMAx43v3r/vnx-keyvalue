
// AUTO GENERATED by vnxcppcodegen

#include <vnx/vnx.h>
#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/Server_store_values_return.hxx>
#include <vnx/Value.h>



namespace vnx {
namespace keyvalue {


const vnx::Hash64 Server_store_values_return::VNX_TYPE_HASH(0x68bd7b177e8a4f88ull);
const vnx::Hash64 Server_store_values_return::VNX_CODE_HASH(0x211c465799a09fd7ull);

vnx::Hash64 Server_store_values_return::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* Server_store_values_return::get_type_name() const {
	return "vnx.keyvalue.Server.store_values.return";
}
const vnx::TypeCode* Server_store_values_return::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_Server_store_values_return;
}

std::shared_ptr<Server_store_values_return> Server_store_values_return::create() {
	return std::make_shared<Server_store_values_return>();
}

std::shared_ptr<vnx::Value> Server_store_values_return::clone() const {
	return std::make_shared<Server_store_values_return>(*this);
}

void Server_store_values_return::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void Server_store_values_return::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void Server_store_values_return::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_store_values_return;
	_visitor.type_begin(*_type_code);
	_visitor.type_end(*_type_code);
}

void Server_store_values_return::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Server.store_values.return\"";
	_out << "}";
}

void Server_store_values_return::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
	}
}

vnx::Object Server_store_values_return::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.Server.store_values.return";
	return _object;
}

void Server_store_values_return::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const Server_store_values_return& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, Server_store_values_return& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* Server_store_values_return::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> Server_store_values_return::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Server.store_values.return";
	type_code->type_hash = vnx::Hash64(0x68bd7b177e8a4f88ull);
	type_code->code_hash = vnx::Hash64(0x211c465799a09fd7ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->is_return = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<Server_store_values_return>(); };
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::Server_store_values_return& value, const TypeCode* type_code, const uint16_t* code) {
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
	for(const vnx::TypeField* _field : type_code->ext_fields) {
		switch(_field->native_index) {
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::Server_store_values_return& value, const TypeCode* type_code, const uint16_t* code) {
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_Server_store_values_return;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::Server_store_values_return>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
}

void read(std::istream& in, ::vnx::keyvalue::Server_store_values_return& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::Server_store_values_return& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::Server_store_values_return& value) {
	value.accept(visitor);
}

} // vnx
