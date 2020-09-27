
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/Collection.hxx>
#include <vnx/Value.h>

#include <vnx/vnx.h>


namespace vnx {
namespace keyvalue {


const vnx::Hash64 Collection::VNX_TYPE_HASH(0xf1b6072fecc4ebf8ull);
const vnx::Hash64 Collection::VNX_CODE_HASH(0x131a332e6e934729ull);

vnx::Hash64 Collection::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* Collection::get_type_name() const {
	return "vnx.keyvalue.Collection";
}

const vnx::TypeCode* Collection::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_Collection;
}

std::shared_ptr<Collection> Collection::create() {
	return std::make_shared<Collection>();
}

std::shared_ptr<vnx::Value> Collection::clone() const {
	return std::make_shared<Collection>(*this);
}

void Collection::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void Collection::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void Collection::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Collection;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, name);
	_visitor.type_field(_type_code->fields[1], 1); vnx::accept(_visitor, block_list);
	_visitor.type_field(_type_code->fields[2], 2); vnx::accept(_visitor, delete_list);
	_visitor.type_end(*_type_code);
}

void Collection::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Collection\"";
	_out << ", \"name\": "; vnx::write(_out, name);
	_out << ", \"block_list\": "; vnx::write(_out, block_list);
	_out << ", \"delete_list\": "; vnx::write(_out, delete_list);
	_out << "}";
}

void Collection::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "block_list") {
			vnx::from_string(_entry.second, block_list);
		} else if(_entry.first == "delete_list") {
			vnx::from_string(_entry.second, delete_list);
		} else if(_entry.first == "name") {
			vnx::from_string(_entry.second, name);
		}
	}
}

vnx::Object Collection::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.Collection";
	_object["name"] = name;
	_object["block_list"] = block_list;
	_object["delete_list"] = delete_list;
	return _object;
}

void Collection::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "block_list") {
			_entry.second.to(block_list);
		} else if(_entry.first == "delete_list") {
			_entry.second.to(delete_list);
		} else if(_entry.first == "name") {
			_entry.second.to(name);
		}
	}
}

vnx::Variant Collection::get_field(const std::string& _name) const {
	if(_name == "name") {
		return vnx::Variant(name);
	}
	if(_name == "block_list") {
		return vnx::Variant(block_list);
	}
	if(_name == "delete_list") {
		return vnx::Variant(delete_list);
	}
	return vnx::Variant();
}

void Collection::set_field(const std::string& _name, const vnx::Variant& _value) {
	if(_name == "name") {
		_value.to(name);
	} else if(_name == "block_list") {
		_value.to(block_list);
	} else if(_name == "delete_list") {
		_value.to(delete_list);
	} else {
		throw std::logic_error("no such field: '" + _name + "'");
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const Collection& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, Collection& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* Collection::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> Collection::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Collection";
	type_code->type_hash = vnx::Hash64(0xf1b6072fecc4ebf8ull);
	type_code->code_hash = vnx::Hash64(0x131a332e6e934729ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<Collection>(); };
	type_code->fields.resize(3);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.is_extended = true;
		field.name = "name";
		field.code = {32};
	}
	{
		vnx::TypeField& field = type_code->fields[1];
		field.is_extended = true;
		field.name = "block_list";
		field.code = {12, 8};
	}
	{
		vnx::TypeField& field = type_code->fields[2];
		field.is_extended = true;
		field.name = "delete_list";
		field.code = {12, 8};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::Collection& value, const TypeCode* type_code, const uint16_t* code) {
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
			case 0: vnx::read(in, value.name, type_code, _field->code.data()); break;
			case 1: vnx::read(in, value.block_list, type_code, _field->code.data()); break;
			case 2: vnx::read(in, value.delete_list, type_code, _field->code.data()); break;
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::Collection& value, const TypeCode* type_code, const uint16_t* code) {
	if(code && code[0] == CODE_OBJECT) {
		vnx::write(out, value.to_object(), nullptr, code);
		return;
	}
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_Collection;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::Collection>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	vnx::write(out, value.name, type_code, type_code->fields[0].code.data());
	vnx::write(out, value.block_list, type_code, type_code->fields[1].code.data());
	vnx::write(out, value.delete_list, type_code, type_code->fields[2].code.data());
}

void read(std::istream& in, ::vnx::keyvalue::Collection& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::Collection& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::Collection& value) {
	value.accept(visitor);
}

} // vnx
