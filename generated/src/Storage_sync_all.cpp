
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/Storage_sync_all.hxx>
#include <vnx/TopicPtr.hpp>
#include <vnx/Value.h>
#include <vnx/keyvalue/Storage_sync_all_return.hxx>

#include <vnx/vnx.h>


namespace vnx {
namespace keyvalue {


const vnx::Hash64 Storage_sync_all::VNX_TYPE_HASH(0x973bf802c6c0aaabull);
const vnx::Hash64 Storage_sync_all::VNX_CODE_HASH(0x6dcfedecd43a701ull);

vnx::Hash64 Storage_sync_all::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* Storage_sync_all::get_type_name() const {
	return "vnx.keyvalue.Storage.sync_all";
}

const vnx::TypeCode* Storage_sync_all::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_Storage_sync_all;
}

std::shared_ptr<Storage_sync_all> Storage_sync_all::create() {
	return std::make_shared<Storage_sync_all>();
}

std::shared_ptr<vnx::Value> Storage_sync_all::clone() const {
	return std::make_shared<Storage_sync_all>(*this);
}

void Storage_sync_all::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void Storage_sync_all::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void Storage_sync_all::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Storage_sync_all;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, topic);
	_visitor.type_end(*_type_code);
}

void Storage_sync_all::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Storage.sync_all\"";
	_out << ", \"topic\": "; vnx::write(_out, topic);
	_out << "}";
}

void Storage_sync_all::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "topic") {
			vnx::from_string(_entry.second, topic);
		}
	}
}

vnx::Object Storage_sync_all::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.Storage.sync_all";
	_object["topic"] = topic;
	return _object;
}

void Storage_sync_all::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "topic") {
			_entry.second.to(topic);
		}
	}
}

vnx::Variant Storage_sync_all::get_field(const std::string& _name) const {
	if(_name == "topic") {
		return vnx::Variant(topic);
	}
	return vnx::Variant();
}

void Storage_sync_all::set_field(const std::string& _name, const vnx::Variant& _value) {
	if(_name == "topic") {
		_value.to(topic);
	} else {
		throw std::logic_error("no such field: '" + _name + "'");
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const Storage_sync_all& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, Storage_sync_all& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* Storage_sync_all::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> Storage_sync_all::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Storage.sync_all";
	type_code->type_hash = vnx::Hash64(0x973bf802c6c0aaabull);
	type_code->code_hash = vnx::Hash64(0x6dcfedecd43a701ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->is_method = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<Storage_sync_all>(); };
	type_code->return_type = ::vnx::keyvalue::Storage_sync_all_return::static_get_type_code();
	type_code->fields.resize(1);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.is_extended = true;
		field.name = "topic";
		field.code = {12, 5};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::Storage_sync_all& value, const TypeCode* type_code, const uint16_t* code) {
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
			case 0: vnx::read(in, value.topic, type_code, _field->code.data()); break;
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::Storage_sync_all& value, const TypeCode* type_code, const uint16_t* code) {
	if(code && code[0] == CODE_OBJECT) {
		vnx::write(out, value.to_object(), nullptr, code);
		return;
	}
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_Storage_sync_all;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::Storage_sync_all>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	vnx::write(out, value.topic, type_code, type_code->fields[0].code.data());
}

void read(std::istream& in, ::vnx::keyvalue::Storage_sync_all& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::Storage_sync_all& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::Storage_sync_all& value) {
	value.accept(visitor);
}

} // vnx
