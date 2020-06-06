
// AUTO GENERATED by vnxcppcodegen

#include <vnx/vnx.h>
#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/Server__sync_finished.hxx>
#include <vnx/Value.h>
#include <vnx/keyvalue/Server__sync_finished_return.hxx>



namespace vnx {
namespace keyvalue {


const vnx::Hash64 Server__sync_finished::VNX_TYPE_HASH(0x2d6328ce038814bbull);
const vnx::Hash64 Server__sync_finished::VNX_CODE_HASH(0x23dab889349d3bf1ull);

vnx::Hash64 Server__sync_finished::get_type_hash() const {
	return VNX_TYPE_HASH;
}

const char* Server__sync_finished::get_type_name() const {
	return "vnx.keyvalue.Server._sync_finished";
}
const vnx::TypeCode* Server__sync_finished::get_type_code() const {
	return vnx::keyvalue::vnx_native_type_code_Server__sync_finished;
}

std::shared_ptr<Server__sync_finished> Server__sync_finished::create() {
	return std::make_shared<Server__sync_finished>();
}

std::shared_ptr<vnx::Value> Server__sync_finished::clone() const {
	return std::make_shared<Server__sync_finished>(*this);
}

void Server__sync_finished::read(vnx::TypeInput& _in, const vnx::TypeCode* _type_code, const uint16_t* _code) {
	vnx::read(_in, *this, _type_code, _code);
}

void Server__sync_finished::write(vnx::TypeOutput& _out, const vnx::TypeCode* _type_code, const uint16_t* _code) const {
	vnx::write(_out, *this, _type_code, _code);
}

void Server__sync_finished::accept(vnx::Visitor& _visitor) const {
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server__sync_finished;
	_visitor.type_begin(*_type_code);
	_visitor.type_field(_type_code->fields[0], 0); vnx::accept(_visitor, job_id);
	_visitor.type_end(*_type_code);
}

void Server__sync_finished::write(std::ostream& _out) const {
	_out << "{\"__type\": \"vnx.keyvalue.Server._sync_finished\"";
	_out << ", \"job_id\": "; vnx::write(_out, job_id);
	_out << "}";
}

void Server__sync_finished::read(std::istream& _in) {
	std::map<std::string, std::string> _object;
	vnx::read_object(_in, _object);
	for(const auto& _entry : _object) {
		if(_entry.first == "job_id") {
			vnx::from_string(_entry.second, job_id);
		}
	}
}

vnx::Object Server__sync_finished::to_object() const {
	vnx::Object _object;
	_object["__type"] = "vnx.keyvalue.Server._sync_finished";
	_object["job_id"] = job_id;
	return _object;
}

void Server__sync_finished::from_object(const vnx::Object& _object) {
	for(const auto& _entry : _object.field) {
		if(_entry.first == "job_id") {
			_entry.second.to(job_id);
		}
	}
}

/// \private
std::ostream& operator<<(std::ostream& _out, const Server__sync_finished& _value) {
	_value.write(_out);
	return _out;
}

/// \private
std::istream& operator>>(std::istream& _in, Server__sync_finished& _value) {
	_value.read(_in);
	return _in;
}

const vnx::TypeCode* Server__sync_finished::static_get_type_code() {
	const vnx::TypeCode* type_code = vnx::get_type_code(VNX_TYPE_HASH);
	if(!type_code) {
		type_code = vnx::register_type_code(static_create_type_code());
	}
	return type_code;
}

std::shared_ptr<vnx::TypeCode> Server__sync_finished::static_create_type_code() {
	std::shared_ptr<vnx::TypeCode> type_code = std::make_shared<vnx::TypeCode>();
	type_code->name = "vnx.keyvalue.Server._sync_finished";
	type_code->type_hash = vnx::Hash64(0x2d6328ce038814bbull);
	type_code->code_hash = vnx::Hash64(0x23dab889349d3bf1ull);
	type_code->is_native = true;
	type_code->is_class = true;
	type_code->is_method = true;
	type_code->create_value = []() -> std::shared_ptr<vnx::Value> { return std::make_shared<Server__sync_finished>(); };
	type_code->return_type = ::vnx::keyvalue::Server__sync_finished_return::static_get_type_code();
	type_code->fields.resize(1);
	{
		vnx::TypeField& field = type_code->fields[0];
		field.name = "job_id";
		field.code = {8};
	}
	type_code->build();
	return type_code;
}


} // namespace vnx
} // namespace keyvalue


namespace vnx {

void read(TypeInput& in, ::vnx::keyvalue::Server__sync_finished& value, const TypeCode* type_code, const uint16_t* code) {
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
				vnx::read_value(_buf + _field->offset, value.job_id, _field->code.data());
			}
		}
	}
	for(const vnx::TypeField* _field : type_code->ext_fields) {
		switch(_field->native_index) {
			default: vnx::skip(in, type_code, _field->code.data());
		}
	}
}

void write(TypeOutput& out, const ::vnx::keyvalue::Server__sync_finished& value, const TypeCode* type_code, const uint16_t* code) {
	if(!type_code || (code && code[0] == CODE_ANY)) {
		type_code = vnx::keyvalue::vnx_native_type_code_Server__sync_finished;
		out.write_type_code(type_code);
		vnx::write_class_header<::vnx::keyvalue::Server__sync_finished>(out);
	}
	if(code && code[0] == CODE_STRUCT) {
		type_code = type_code->depends[code[1]];
	}
	char* const _buf = out.write(8);
	vnx::write_value(_buf + 0, value.job_id);
}

void read(std::istream& in, ::vnx::keyvalue::Server__sync_finished& value) {
	value.read(in);
}

void write(std::ostream& out, const ::vnx::keyvalue::Server__sync_finished& value) {
	value.write(out);
}

void accept(Visitor& visitor, const ::vnx::keyvalue::Server__sync_finished& value) {
	value.accept(visitor);
}

} // vnx
