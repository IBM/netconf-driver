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
        

    @patch.object(ConfigOperations, 'netconf_connect')
    @patch.object(ConfigOperations, '_generate_additional_logs')
    def test_driver(self,mock_request, mock_logs):
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
            self.resource_driver.execute_lifecycle(lifecycle, driver_files,
                                    system_properties, resource_properties, 
                                    request_properties, associated_topology, deployment_location)
            # mock_request.assert_called()
            # assert ConfigOperations._generate_additional_logs.called