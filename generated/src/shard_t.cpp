
// AUTO GENERATED by vnxcppcodegen

#include <vnx/vnx.h>
#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/shard_t.hxx>



namespace vnx {
namespace keyvalue {


const vnx::Hash64 shard_t::VNX_TYPE_HASH(0x2d052c83abce314dull);
const vnx::Hash64 shard_t::VNX_CODE_HASH(0xa515192297853714ull);

vnx::Hash64 shard_t::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* shard_t::get_type_name() const {
	return "vnx.keyvalue.shard_t";
}
const vnx::TypeCode* shard_t::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_shard_t;
}

std::shared_ptr<shard_t> shard_t::create() {
	return std::make_shared<shard_t>();
}

std::shared_ptr<shard_t> shard_t::clone() const {
	return std::make_shared<shard_t>(*this);
}

void shard_t::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void shard_t::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void shard_t::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_shard_t;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, index);
	_visitor.type_field(_type_code->fields[1], 1); vnx::accept(_visitor, size);
	_visitor.type_end(*_type_code);
}

void shard_t::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.shard_t\"";
	_out << ", \"index\": "; vnx::write(_out, index);
	_out << ", \"size\": "; vnx::write(_out, size);
	_out << "}";
}

void shard_t::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "index") {
			vnx::from_string(_entry.second, index);
		} else if(_entry.first == "size") {
			vnx::from_string(_entry.second, size);
		}
	}
}

vnx::Object shard_t::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.shard_t";
	_object["index"] = index;
	_object["size"] = size;
	return _object;
}

void shard_t::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "index") {
			_entry.second.to(index);
		} else if(_entry.first == "size") {
			_entry.second.to(size);
		}
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const shard_t& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, shard_t& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* shard_t::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> shard_t::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.shard_t";
	type_code->type_hash = vnx::Hash64(0x2d052c83abce314dull);
	type_code->code_hash = vnx::Hash64(0xa515192297853714ull);
	type_code->is_native = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<vnx::Struct<shard_t>>(); };
	type_code->fields.resize(2);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.name = "index";
		field.code = {2};
	}
	{
		vnx::TypeField& field = type_code->fields[1];
		field.name = "size";
		field.code = {2};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::shard_t& value, const TypeCode* type_code, const uint16_t* code) {
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
			const vnx::TypeField* const _field = type_code->field_map[0];
			if(_field) {
				vnx::read_value(_buf + _field->offset, value.index, _field->code.data());
			}
		}
		{
			const vnx::TypeField* const _field = type_code->field_map[1];
			if(_field) {
				vnx::read_value(_buf + _field->offset, value.size, _field->code.data());
			}
		}
	}
	for(const vnx::TypeField* _field : type_code->ext_fields) {
		switch(_field->native_index) {
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::shard_t& value, const TypeCode* type_code, const uint16_t* code) {
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_shard_t;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::shard_t>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	char* const _buf = out.write(4);
	vnx::write_value(_buf + 0, value.index);
	vnx::write_value(_buf + 2, value.size);
}

void read(std::istream& in, ::vnx::keyvalue::shard_t& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::shard_t& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::shard_t& value) {
	value.accept(visitor);
}

} // vnx
