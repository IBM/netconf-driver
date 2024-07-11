import unittest
import logging
import os
from unittest.mock import MagicMock, Mock, patch
from netconfdriver.service.resourcedriver import ResourceDriverHandler
from netconfdriver.service.location.deployment_location import NetConfDeploymentLocation
from netconfdriver.service.operations.config_operations import ConfigOperations
import netconfdriver.service.jinja_conversion as jinja_conversion
import netconfdriver.service.common as common
from ignition.utils.file import DirectoryTree
from ignition.utils.propvaluemap import PropValueMap
from ignition.model.associated_topology import AssociatedTopology
from ignition.model.lifecycle import LifecycleExecuteResponse

EXPECTED_CONTENT_CREATE = '''<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
<netconflist xmlns="urn:mynetconf:test"><netconf nc:operation="create"><netconf-id>500</netconf-id><netconf-param>100</netconf-param></netconf></netconflist>
</nc:config>'''
EXPECTED_CONTENT_DELETE = '''<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
<netconflist xmlns="urn:mynetconf:test"><netconf><netconf-id>500</netconf-id><netconf-param nc:operation="delete"/></netconf></netconflist>
</nc:config>'''
EXPECTED_CONTENT_UPDATE = '''<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
<netconflist xmlns="urn:mynetconf:test"><netconf><netconf-id>500</netconf-id><netconf-param nc:operation="replace">100</netconf-param></netconf></netconflist>
</nc:config>'''


class TestLifecycleController(unittest.TestCase):
    
    def setUp(self):
        self.job_queue = Mock()
        self.lifecycle_messaging_service = Mock()
        self.resource_driver = ResourceDriverHandler(self.job_queue, self.lifecycle_messaging_service)
        
    def __resource_properties(self):
        props = {}
        props['config_list_map'] = {'type': 'list', 'value': [{'netconfId': 500},{'netconfParam': 100}]}
        props['netconfParam'] = {'type': 'string', 'value': '100'}
        props['netconfId'] = {'type': 'string', 'value': '500'}
        props['config_map'] = {'type': 'map', 'value': {'netconfParam': 100,'netconfId': 500}}
        props['defaultOperation'] = {'type': 'string', 'value': 'merge'}
        props['infraKey'] = {'type': 'key', 'keyName': 'test_key', 'privateKey': '***obfuscated private key***\\n', 'value': 'test_key'}
        return PropValueMap(props)
        
    def __deployment_location(self):
        PROPERTIES = 'properties'
        PORT = 'port'
        HOST = 'host'
        USERNAME = 'username'
        PASSWORD = 'password'
        TIMEOUT = 'timeout'
        HOSTKEY_VERIFY = 'hostkey_verify'
        return {
            PROPERTIES: {
                PORT: "22",
                HOST: "10.10.10.10",
                USERNAME: "user",
                PASSWORD: "password",
                TIMEOUT: 30,
                HOSTKEY_VERIFY: 'False'
            }
        }
        
    def __request_properties(self):
        props = {}
        return PropValueMap(props)
    
    def __driver_files(self):
        path = os.path.abspath(os.getcwd())
        path = path + '/tests/unit/netconf'
        return DirectoryTree(path)
    
    def test_template_create(self):
        driver_files = self.__driver_files()
        method_name = ['create','update','delete']
        resource_properties = self.__resource_properties()
        for method_name in method_name:
            template_content = jinja_conversion.from_pkg(resource_properties, driver_files, method_name)
            self.contentTest(method_name, template_content)
            
            
    def contentTest(self, method_name, template_content):
        if method_name == 'create':
            self.assertEqual(template_content,EXPECTED_CONTENT_CREATE)
        if method_name == 'delete':
            self.assertEqual(template_content,EXPECTED_CONTENT_DELETE)
        if method_name == 'update':
            self.assertEqual(template_content,EXPECTED_CONTENT_UPDATE)
        

    def test_driver(self):
        system_properties = {}
        request_properties = self.__request_properties()
        deployment_location = self.__deployment_location()
        resource_properties = self.__resource_properties()
        associated_topology = AssociatedTopology()
        path = os.path.abspath(os.getcwd())
        path = path + '/tests/unit/netconf'
        logging.info(path)
        driver_files = self.__driver_files()
        lifecycle = ['Create','Upgrade','Delete']
        for lifecycle in lifecycle:
            request_id = self.resource_driver.execute_lifecycle(lifecycle, driver_files,
                                    system_properties, resource_properties, 
                                 request_properties, associated_topology, deployment_location)
            
            self.assertIsInstance(request_id,  LifecycleExecuteResponse)

    @patch.object(NetConfDeploymentLocation, 'operation')
    def test_handler(self, mock_operation):
        system_properties = {}
        request_properties = self.__request_properties()
        deployment_location = self.__deployment_location()
        resource_properties = self.__resource_properties()
        associated_topology = AssociatedTopology()
        path = os.path.abspath(os.getcwd())
        path = path + '/tests/unit/netconf'
        logging.info(path)
        driver_files = self.__driver_files()
        
        lifecycle = ['Create','Upgrade','Delete']
        for lifecycle in lifecycle:
        
            method_name = lifecycle.lower()
            if(method_name == 'upgrade'):
                method_name = 'update'
            package_properties = jinja_conversion.from_pkg(resource_properties, driver_files, method_name)
            if package_properties is None:
                raise ResourceDriverError('Templating Exception')
            default_operation = jinja_conversion.get_default_operation(resource_properties)
            if method_name == 'delete':
                default_operation = 'none'
            if default_operation is None:
                default_operation = 'merge'
            rsa_key_path = jinja_conversion.to_rsa_path(resource_properties)
            print('rsa_key_path : %s', rsa_key_path)
            if rsa_key_path is None:
                print("rsa_key_path is None!")
            request_id = common.build_request_id(method_name)
            
            my_job={'job_type' : 'NetconfJob',
                    'request_id' : request_id,
                    'package_properties' : package_properties,
                    'default_operation' : default_operation,
                    'rsa_key_path' : rsa_key_path,
                    'deployment_location' : deployment_location}

            finished = False
            finished = self.resource_driver.netconfjob_handler(my_job)
            print(finished)
            
            self.assertTrue(finished)    
            mock_operation.assert_called()

    @patch.object(ConfigOperations, 'netconf_connect')
    @patch.object(ConfigOperations, '_generate_additional_logs')
    def test_ConfigOperation(self, mock_logs, mock_connect):
        system_properties = {}
        request_properties = self.__request_properties()
        deployment_location = self.__deployment_location()
        resource_properties = self.__resource_properties()
        associated_topology = AssociatedTopology()
        path = os.path.abspath(os.getcwd())
        path = path + '/tests/unit/netconf'
        logging.info(path)
        driver_files = self.__driver_files()
        lifecycle = ['Create','Upgrade','Delete']
        for lifecycle in lifecycle:
            method_name = lifecycle.lower()
            if(method_name == 'upgrade'):
                method_name = 'update'
            package_properties = jinja_conversion.from_pkg(resource_properties, driver_files, method_name)
            if package_properties is None:
                raise ResourceDriverError('Templating Exception')
            default_operation = jinja_conversion.get_default_operation(resource_properties)
            if method_name == 'delete':
                default_operation = 'none'
            if default_operation is None:
                default_operation = 'merge'
            rsa_key_path = jinja_conversion.to_rsa_path(resource_properties)
            print('rsa_key_path : %s', rsa_key_path)
            if rsa_key_path is None:
                print("rsa_key_path is None!")
            request_id = common.build_request_id(method_name)
            
            netconf_location = None
            netconf_location = NetConfDeploymentLocation.from_dict(deployment_location)
            
            print('REQUEST: %s :- Before Executing Operation', request_id)
            edit_config_details = netconf_location.operation(package_properties, default_operation, rsa_key_path, request_id)
            print('RESPONSE: %s :- After Executing Operation , Result : %s', request_id, edit_config_details)
            
            mock_logs.assert_called()
            mock_connect.assert_called()
            