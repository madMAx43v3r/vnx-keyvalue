
// AUTO GENERATED by vnxcppcodegen

#include <vnx/keyvalue/package.hxx>
#include <vnx/keyvalue/ServerClient.hxx>
#include <vnx/Input.h>
#include <vnx/Output.h>


namespace vnx {
namespace keyvalue {

ServerClient::ServerClient(const std::string& service_name)
	:	Client::Client(vnx::Hash64(service_name))
{
}

ServerClient::ServerClient(vnx::Hash64 service_addr)
	:	Client::Client(service_addr)
{
}

void ServerClient::_sync_finished(const ::int64_t& job_id) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server__sync_finished;
	{
		char* const _buf = _out.write(8);
		vnx::write_value(_buf + 0, job_id);
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
}

void ServerClient::_sync_finished_async(const ::int64_t& job_id) {
	vnx_is_async = true;
	_sync_finished(job_id);
}

void ServerClient::delete_value(const ::vnx::Variant& key) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_delete_value;
	{
		vnx::write(_out, key, _type_code, _type_code->fields[0].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
}

void ServerClient::delete_value_async(const ::vnx::Variant& key) {
	vnx_is_async = true;
	delete_value(key);
}

::std::shared_ptr<const ::vnx::Value> ServerClient::get_value(const ::vnx::Variant& key) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_get_value;
	{
		vnx::write(_out, key, _type_code, _type_code->fields[0].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
	
	vnx::BinaryInputStream _stream_in(vnx_return_data.get());
	vnx::TypeInput _in(&_stream_in);
	const vnx::TypeCode* _return_type = _type_code->return_type;
	::std::shared_ptr<const ::vnx::Value> _ret_0;
	{
		const char* const _buf = _in.read(_return_type->total_field_size);
		if(_return_type->is_matched) {
		}
		for(const vnx::TypeField* _field : _return_type->ext_fields) {
			switch(_field->native_index) {
				case 0: vnx::read(_in, _ret_0, _return_type, _field->code.data()); break;
				default: vnx::skip(_in, _return_type, _field->code.data());
			}
		}
	}
	return _ret_0;
}

::std::vector<::std::shared_ptr<const ::vnx::Value>> ServerClient::get_values(const ::std::vector<::vnx::Variant>& keys) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_get_values;
	{
		vnx::write(_out, keys, _type_code, _type_code->fields[0].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
	
	vnx::BinaryInputStream _stream_in(vnx_return_data.get());
	vnx::TypeInput _in(&_stream_in);
	const vnx::TypeCode* _return_type = _type_code->return_type;
	::std::vector<::std::shared_ptr<const ::vnx::Value>> _ret_0;
	{
		const char* const _buf = _in.read(_return_type->total_field_size);
		if(_return_type->is_matched) {
		}
		for(const vnx::TypeField* _field : _return_type->ext_fields) {
			switch(_field->native_index) {
				case 0: vnx::read(_in, _ret_0, _return_type, _field->code.data()); break;
				default: vnx::skip(_in, _return_type, _field->code.data());
			}
		}
	}
	return _ret_0;
}

void ServerClient::store_value(const ::vnx::Variant& key, const ::std::shared_ptr<const ::vnx::Value>& value) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_store_value;
	{
		vnx::write(_out, key, _type_code, _type_code->fields[0].code.data());
		vnx::write(_out, value, _type_code, _type_code->fields[1].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
}

void ServerClient::store_value_async(const ::vnx::Variant& key, const ::std::shared_ptr<const ::vnx::Value>& value) {
	vnx_is_async = true;
	store_value(key, value);
}

void ServerClient::store_values(const ::std::vector<::std::pair<::vnx::Variant, ::std::shared_ptr<const ::vnx::Value>>>& values) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_store_values;
	{
		vnx::write(_out, values, _type_code, _type_code->fields[0].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
}

void ServerClient::store_values_async(const ::std::vector<::std::pair<::vnx::Variant, ::std::shared_ptr<const ::vnx::Value>>>& values) {
	vnx_is_async = true;
	store_values(values);
}

::int64_t ServerClient::sync_all(const ::vnx::TopicPtr& topic) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_sync_all;
	{
		vnx::write(_out, topic, _type_code, _type_code->fields[0].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
	
	vnx::BinaryInputStream _stream_in(vnx_return_data.get());
	vnx::TypeInput _in(&_stream_in);
	const vnx::TypeCode* _return_type = _type_code->return_type;
	::int64_t _ret_0 = 0;
	{
		const char* const _buf = _in.read(_return_type->total_field_size);
		if(_return_type->is_matched) {
			{
				const vnx::TypeField* const _field = _return_type->field_map[0];
				if(_field) {
					vnx::read_value(_buf + _field->offset, _ret_0, _field->code.data());
				}
			}
		}
		for(const vnx::TypeField* _field : _return_type->ext_fields) {
			switch(_field->native_index) {
				default: vnx::skip(_in, _return_type, _field->code.data());
			}
		}
	}
	return _ret_0;
}

::int64_t ServerClient::sync_all_keys(const ::vnx::TopicPtr& topic) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_sync_all_keys;
	{
		vnx::write(_out, topic, _type_code, _type_code->fields[0].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
	
	vnx::BinaryInputStream _stream_in(vnx_return_data.get());
	vnx::TypeInput _in(&_stream_in);
	const vnx::TypeCode* _return_type = _type_code->return_type;
	::int64_t _ret_0 = 0;
	{
		const char* const _buf = _in.read(_return_type->total_field_size);
		if(_return_type->is_matched) {
			{
				const vnx::TypeField* const _field = _return_type->field_map[0];
				if(_field) {
					vnx::read_value(_buf + _field->offset, _ret_0, _field->code.data());
				}
			}
		}
		for(const vnx::TypeField* _field : _return_type->ext_fields) {
			switch(_field->native_index) {
				default: vnx::skip(_in, _return_type, _field->code.data());
			}
		}
	}
	return _ret_0;
}

::int64_t ServerClient::sync_from(const ::vnx::TopicPtr& topic, const ::uint64_t& version) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_sync_from;
	{
		char* const _buf = _out.write(8);
		vnx::write_value(_buf + 0, version);
		vnx::write(_out, topic, _type_code, _type_code->fields[0].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
	
	vnx::BinaryInputStream _stream_in(vnx_return_data.get());
	vnx::TypeInput _in(&_stream_in);
	const vnx::TypeCode* _return_type = _type_code->return_type;
	::int64_t _ret_0 = 0;
	{
		const char* const _buf = _in.read(_return_type->total_field_size);
		if(_return_type->is_matched) {
			{
				const vnx::TypeField* const _field = _return_type->field_map[0];
				if(_field) {
					vnx::read_value(_buf + _field->offset, _ret_0, _field->code.data());
				}
			}
		}
		for(const vnx::TypeField* _field : _return_type->ext_fields) {
			switch(_field->native_index) {
				default: vnx::skip(_in, _return_type, _field->code.data());
			}
		}
	}
	return _ret_0;
}

::int64_t ServerClient::sync_range(const ::vnx::TopicPtr& topic, const ::uint64_t& begin, const ::uint64_t& end) {
	std::shared_ptr<vnx::Binary> _argument_data = vnx::Binary::create();
	vnx::BinaryOutputStream _stream_out(_argument_data.get());
	vnx::TypeOutput _out(&_stream_out);
	const vnx::TypeCode* _type_code = vnx::keyvalue::vnx_native_type_code_Server_sync_range;
	{
		char* const _buf = _out.write(16);
		vnx::write_value(_buf + 0, begin);
		vnx::write_value(_buf + 8, end);
		vnx::write(_out, topic, _type_code, _type_code->fields[0].code.data());
	}
	_out.flush();
	_argument_data->type_code = _type_code;
	vnx_request(_argument_data);
	
	vnx::BinaryInputStream _stream_in(vnx_return_data.get());
	vnx::TypeInput _in(&_stream_in);
	const vnx::TypeCode* _return_type = _type_code->return_type;
	::int64_t _ret_0 = 0;
	{
		const char* const _buf = _in.read(_return_type->total_field_size);
		if(_return_type->is_matched) {
			{
				const vnx::TypeField* const _field = _return_type->field_map[0];
				if(_field) {
					vnx::read_value(_buf + _field->offset, _ret_0, _field->code.data());
				}
			}
		}
		for(const vnx::TypeField* _field : _return_type->ext_fields) {
			switch(_field->native_index) {
				default: vnx::skip(_in, _return_type, _field->code.data());
			}
		}
	}
	return _ret_0;
}


} // namespace vnx
} // namespace keyvalue
