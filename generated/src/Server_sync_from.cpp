
// AUTO GENERATED by vnxcppcodegen

#include <vnx/vnx.h>
#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/Server_sync_from.hxx>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/keyvalue/Server_sync_from_return.hxx>



namespace vnx {
namespace keyvalue {


const vnx::Hash64 Server_sync_from::VNX_TYPE_HASH(0xc10ef313be34be0full);
const vnx::Hash64 Server_sync_from::VNX_CODE_HASH(0x8b6d1d4902c541a1ull);

vnx::Hash64 Server_sync_from::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* Server_sync_from::get_type_name() const {
	return "vnx.keyvalue.Server.sync_from";
}
const vnx::TypeCode* Server_sync_from::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_Server_sync_from;
}

std::shared_ptr<Server_sync_from> Server_sync_from::create() {
	return std::make_shared<Server_sync_from>();
}

std::shared_ptr<vnx::Value> Server_sync_from::clone() const {
	return std::make_shared<Server_sync_from>(*this);
}

void Server_sync_from::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void Server_sync_from::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void Server_sync_from::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_sync_from;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, topic);
	_visitor.type_field(_type_code->fields[1], 1); vnx::accept(_visitor, version);
	_visitor.type_end(*_type_code);
}

void Server_sync_from::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Server.sync_from\"";
	_out << ", \"topic\": "; vnx::write(_out, topic);
	_out << ", \"version\": "; vnx::write(_out, version);
	_out << "}";
}

void Server_sync_from::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "topic") {
			vnx::from_string(_entry.second, topic);
		} else if(_entry.first == "version") {
			vnx::from_string(_entry.second, version);
		}
	}
}

vnx::Object Server_sync_from::to_object() const {
	vnx::Object _object;
	_object["topic"] = topic;
	_object["version"] = version;
	return _object;
}

void Server_sync_from::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "topic") {
			_entry.second.to(topic);
		} else if(_entry.first == "version") {
			_entry.second.to(version);
		}
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const Server_sync_from& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, Server_sync_from& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* Server_sync_from::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> Server_sync_from::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Server.sync_from";
	type_code->type_hash = vnx::Hash64(0xc10ef313be34be0full);
	type_code->code_hash = vnx::Hash64(0x8b6d1d4902c541a1ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->is_method = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<Server_sync_from>(); };
	type_code->return_type = ::vnx::keyvalue::Server_sync_from_return::static_get_type_code();
	type_code->fields.resize(2);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.is_extended = true;
		field.name = "topic";
		field.code = {12, 5};
	}
	{
		vnx::TypeField& field = type_code->fields[1];
		field.name = "version";
		field.code = {4};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::Server_sync_from& value, const TypeCode* type_code, const uint16_t* code) {
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
		{
			const vnx::TypeField* const _field = type_code->field_map[1];
			if(_field) {
				vnx::read_value(_buf + _field->offset, value.version, _field->code.data());
			}
		}
	}
	for(const vnx::TypeField* _field : type_code->ext_fields) {
		switch(_field->native_index) {
			case 0: vnx::read(in, value.topic, type_code, _field->code.data()); break;
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::Server_sync_from& value, const TypeCode* type_code, const uint16_t* code) {
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_Server_sync_from;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::Server_sync_from>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	char* const _buf = out.write(8);
	vnx::write_value(_buf + 0, value.version);
	vnx::write(out, value.topic, type_code, type_code->fields[0].code.data());
}

void read(std::istream& in, ::vnx::keyvalue::Server_sync_from& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::Server_sync_from& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::Server_sync_from& value) {
	value.accept(visitor);
}

} // vnx