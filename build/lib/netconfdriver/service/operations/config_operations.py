import sys
import logging
import uuid
from ncclient import manager
from ignition.service.logging import logging_context
logger = logging.getLogger(__name__)
    
class NetconfConfigError(Exception):
    pass

class ConfigOperations():
    def netconf_connect(host, port, user, password,rsa_key_path,kwargs):
        logger.debug(f'host:{host},port:{port},user:{user},password:{password},rsa_key_path:{rsa_key_path},kwargs:{kwargs}')
        try:
            for key in kwargs:
                key = kwargs[key]
            conn =  manager.connect(host=host,
                                port=port,
                                username=user,
                                password=password,
                                key_filename=rsa_key_path,
                                hostkey_verify=False,
                                **kwargs)
            logger.debug('Connected ...')
            return conn
        except Exception as e:
            logger.error('Unexpected exception {0}'.format(e))
            raise NetconfConfigError(str(e)) from e
        
    def netconf_edit(conn,package_properties,default_operation,request_id):
        try:
            external_request_id = str(uuid.uuid4())
            ConfigOperations._generate_additional_logs(package_properties, 'sent',external_request_id,'application/xml',
                                       'request', 'netconf', {'default-operation' : default_operation}, request_id)
            edit_config_details = conn.edit_config(config=package_properties, target="running", default_operation=default_operation)
            ConfigOperations._generate_additional_logs(edit_config_details, 'received', external_request_id,'application/xml',
                                       'response', 'netconf', {'error' : '','errors' : edit_config_details.errors,'ok' : edit_config_details.ok }, request_id)
            logger.debug('config_details = %s', edit_config_details)
            return edit_config_details
        except Exception as e:
            ConfigOperations._generate_additional_logs(e, 'received',external_request_id,'plain/text',
                                       'response', 'netconf', {'error-tag' : e.tag,'error-info' : '','error-severity' : e.severity,'error-path' : e.path,'error-type' : e.type}, request_id)
            logger.error('Unexpected exception {0}'.format(e))
            raise NetconfConfigError(str(e)) from e
        
    def netconf_disconnect(conn):
        try:
            logger.debug('Close session...')
            conn.close_session()
        except Exception as e:
            logger.error('Unexpected exception {0}'.format(e))
            raise NetconfConfigError(str(e)) from e

    def _generate_additional_logs(message_data, message_direction, external_request_id,content_type,
                                  message_type, protocol, protocol_metadata, driver_request_id):
        try: 
            
            logging_context_dict = {'message_direction' : message_direction, 'tracectx.externalrequestid' : external_request_id,
                                    'message_type' : message_type, 'content_type' : content_type, 'protocol' : protocol, 'protocol_metadata' : str(protocol_metadata).replace("'", '\"'), 'tracectx.driverrequestid' : driver_request_id}
            logging_context.set_from_dict(logging_context_dict)
            logger.info(str(message_data).replace("'",'\"'))
        finally:
            if('message_direction' in logging_context.data):
                logging_context.data.pop("message_direction")
            if('tracectx.externalrequestid' in logging_context.data):
                logging_context.data.pop("tracectx.externalrequestid")
            if('message_type' in logging_context.data):
                logging_context.data.pop("message_type")
            if('protocol' in logging_context.data):
                logging_context.data.pop("protocol")
            if('protocol_metadata' in logging_context.data):
                logging_context.data.pop("protocol_metadata")
            if('tracectx.driverrequestid' in logging_context.data):
                logging_context.data.pop("tracectx.driverrequestid")

                