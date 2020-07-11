
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/SyncInfo.hxx>
#include <vnx/Value.h>

#include <vnx/vnx.h>


namespace vnx {
namespace keyvalue {

const uint32_t SyncInfo::BEGIN;
const uint32_t SyncInfo::END;

const vnx::Hash64 SyncInfo::VNX_TYPE_HASH(0x4f9820ae95813502ull);
const vnx::Hash64 SyncInfo::VNX_CODE_HASH(0x14df919a6f68ff58ull);

vnx::Hash64 SyncInfo::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* SyncInfo::get_type_name() const {
	return "vnx.keyvalue.SyncInfo";
}
const vnx::TypeCode* SyncInfo::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_SyncInfo;
}

std::shared_ptr<SyncInfo> SyncInfo::create() {
	return std::make_shared<SyncInfo>();
}

std::shared_ptr<vnx::Value> SyncInfo::clone() const {
	return std::make_shared<SyncInfo>(*this);
}

void SyncInfo::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void SyncInfo::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void SyncInfo::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_SyncInfo;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, collection);
	_visitor.type_field(_type_code->fields[1], 1); vnx::accept(_visitor, version);
	_visitor.type_field(_type_code->fields[2], 2); vnx::accept(_visitor, job_id);
	_visitor.type_field(_type_code->fields[3], 3); vnx::accept(_visitor, code);
	_visitor.type_end(*_type_code);
}

void SyncInfo::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.SyncInfo\"";
	_out << ", \"collection\": "; vnx::write(_out, collection);
	_out << ", \"version\": "; vnx::write(_out, version);
	_out << ", \"job_id\": "; vnx::write(_out, job_id);
	_out << ", \"code\": "; vnx::write(_out, code);
	_out << "}";
}

void SyncInfo::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "code") {
			vnx::from_string(_entry.second, code);
		} else if(_entry.first == "collection") {
			vnx::from_string(_entry.second, collection);
		} else if(_entry.first == "job_id") {
			vnx::from_string(_entry.second, job_id);
		} else if(_entry.first == "version") {
			vnx::from_string(_entry.second, version);
		}
	}
}

vnx::Object SyncInfo::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.SyncInfo";
	_object["collection"] = collection;
	_object["version"] = version;
	_object["job_id"] = job_id;
	_object["code"] = code;
	return _object;
}

void SyncInfo::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "code") {
			_entry.second.to(code);
		} else if(_entry.first == "collection") {
			_entry.second.to(collection);
		} else if(_entry.first == "job_id") {
			_entry.second.to(job_id);
		} else if(_entry.first == "version") {
			_entry.second.to(version);
		}
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const SyncInfo& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, SyncInfo& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* SyncInfo::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> SyncInfo::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.SyncInfo";
	type_code->type_hash = vnx::Hash64(0x4f9820ae95813502ull);
	type_code->code_hash = vnx::Hash64(0x14df919a6f68ff58ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<SyncInfo>(); };
	type_code->fields.resize(4);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.is_extended = true;
		field.name = "collection";
		field.code = {12, 5};
	}
	{
		vnx::TypeField& field = type_code->fields[1];
		field.name = "version";
		field.code = {4};
	}
	{
		vnx::TypeField& field = type_code->fields[2];
		field.name = "job_id";
		field.code = {8};
	}
	{
		vnx::TypeField& field = type_code->fields[3];
		field.name = "code";
		field.code = {3};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::SyncInfo& value, const TypeCode* type_code, const uint16_t* code) {
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
	const char* const _buf = in.read(type_code->total_field_size);
	if(type_code->is_matched) {
		{
			const vnx::TypeField* const _field = type_code->field_map[1];
			if(_field) {
				vnx::read_value(_buf + _field->offset, value.version, _field->code.data());
			}
		}
		{
			const vnx::TypeField* const _field = type_code->field_map[2];
			if(_field) {
				vnx::read_value(_buf + _field->offset, value.job_id, _field->code.data());
			}
		}
		{
			const vnx::TypeField* const _field = type_code->field_map[3];
			if(_field) {
				vnx::read_value(_buf + _field->offset, value.code, _field->code.data());
			}
		}
	}
	for(const vnx::TypeField* _field : type_code->ext_fields) {
		switch(_field->native_index) {
			case 0: vnx::read(in, value.collection, type_code, _field->code.data()); break;
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::SyncInfo& value, const TypeCode* type_code, const uint16_t* code) {
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_SyncInfo;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::SyncInfo>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	char* const _buf = out.write(20);
	vnx::write_value(_buf + 0, value.version);
	vnx::write_value(_buf + 8, value.job_id);
	vnx::write_value(_buf + 16, value.code);
	vnx::write(out, value.collection, type_code, type_code->fields[0].code.data());
}

void read(std::istream& in, ::vnx::keyvalue::SyncInfo& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::SyncInfo& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::SyncInfo& value) {
	value.accept(visitor);
}

} // vnx
