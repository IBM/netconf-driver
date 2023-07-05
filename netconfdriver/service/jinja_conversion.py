import os
import logging
from ignition.service.templating import ResourceTemplateContextService, Jinja2TemplatingService
from ignition.utils.propvaluemap import PropValueMap

from tempfile import NamedTemporaryFile
import jinja2 as jinja

logger = logging.getLogger(__name__)

TEMPLATE_PATH = "/template/"
DEFAULT_OPERATION = "merge"

def from_pkg(resource_properties, driver_files, method_name):
    try:
        template_path = driver_files.root_path
        template_path = driver_files.root_path + TEMPLATE_PATH
        template_files = os.listdir(template_path)
        for template in template_files:
            split_template = template.split('.')[0].lower()
            if(split_template == method_name):
                template_path = template_path + template
        f = open(template_path, "r")
        content = f.read()
        resource_context_service = ResourceTemplateContextService()
        templating_service = Jinja2TemplatingService()
        context = resource_context_service.build(system_properties={}, 
                resource_properties=resource_properties,
                request_properties={}, deployment_location={})
        return templating_service.render(content, context, 
                        settings = {'undefined': jinja.StrictUndefined})
    except Exception as e:
        logger.error('Unexpected exception {0}'.format(e))
        raise PropertyError(str(e)) from e

def process_list_maps(value):
    for item in value:
        logger.info('item is %s', item)                    
        item_type = type(item)
        logger.info('type of item is %s', item_type)
        if type(item) is dict:
            logger.info('item type is %s', type(item))
            value = {k:v for element in value for k,v in element.items()}
            return value

def get_default_operation(resource_properties):
    try:
        value = None
        default = DEFAULT_OPERATION
        for item in list(resource_properties.keys()):
            if item == 'defaultOperation':
                value = resource_properties[item]
        logging.info('value: %s', value)
        if value == "" or value is None:
            return default
        else:
            return value
    except Exception as e:
        logger.error('Unexpected exception {0}'.format(e))
        raise PropertyError(str(e)) from e
    
def to_rsa_path(resource_properties):
    try:
        key_property_processor = KeyPropertyProcessor(resource_properties)
        key_path = key_property_processor.process_key_properties()
        if key_path is not None:
            return key_path
        elif key_path is None:
            return None
    except Exception as e:
        logger.error('Unexpected exception {0}'.format(e))
        raise PropertyError(str(e)) from e
    
class PropertyError(Exception):
    pass

class KeyPropertyProcessor():
    def __init__(self, resource_properties):
        self.properties = resource_properties
        self.key_files = []

#   Process (input) key properties by writing the private key out to a file in tmp

    def process_key_properties(self):
        key_path = self.process_keys(self.properties)
        return key_path

    def process_keys(self, properties):
        properties = self.properties 
        for prop in properties.get_keys().items_with_types():
            key_path = self.write_private_key(properties, prop[0], prop[1])
            return key_path

    def write_private_key(self, properties, key_prop_name, private_key):
        
        with NamedTemporaryFile(delete=False, mode='w') as private_key_file:
            private_key_value = private_key.get('privateKey', None)
            private_key_file.write(private_key_value)
            private_key_file.flush()
            self.key_files.append(private_key_file)
            return private_key_file.name