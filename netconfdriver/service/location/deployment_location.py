import logging

from netconfdriver.service.common import DATASTORE_CANDIDATE, DATASTORE_RUNNING, DATASTORE_STARTUP
from ignition.utils.propvaluemap import PropValueMap
from ignition.locations.exceptions import InvalidDeploymentLocationError
from ignition.locations.utils import get_property_or_default
from netconfdriver.service.operations.config_operations import *

logger = logging.getLogger(__name__)

class NetConfDeploymentLocation:
    """
    Netconf deployment location

    Attributes:
      name (str): name of the location
    """

    HOST = 'host'
    PORT = 'port'
    PROPERTIES = 'properties'
    USERNAME = 'username'
    PASSWORD = 'password'
    TIMEOUT = 'timeout'
    TARGET = 'target'

    @staticmethod
    def from_dict(dl_data):
        """
        Creates an Netconf deployment location to dictionary format

        Args:
            dl_data (dict): the deployment location data.
        Returns:
            an NetConfDeploymentLocation instance
        """
        properties = dl_data.get(NetConfDeploymentLocation.PROPERTIES)
        if properties is None:
            raise InvalidDeploymentLocationError(f'Deployment location Properties missing \'{NetConfDeploymentLocation.PROPERTIES}\' value')
        timeout = get_property_or_default(
            properties, NetConfDeploymentLocation.TIMEOUT, error_if_not_found=False)
        host = get_property_or_default(properties, NetConfDeploymentLocation.HOST, error_if_not_found=True)
        port = get_property_or_default(properties, NetConfDeploymentLocation.PORT, error_if_not_found=True)
        username = get_property_or_default(properties, NetConfDeploymentLocation.USERNAME, error_if_not_found=True)
        password = get_property_or_default(properties, NetConfDeploymentLocation.PASSWORD, error_if_not_found=True)
        target = get_property_or_default(properties, NetConfDeploymentLocation.TARGET, default_provider=DATASTORE_RUNNING, error_if_not_found=False)
        if target not in [DATASTORE_CANDIDATE, DATASTORE_RUNNING, DATASTORE_STARTUP]:
            target = DATASTORE_RUNNING
        kwargs = {}
        if timeout is not None:
            kwargs['timeout'] = timeout
        return NetConfDeploymentLocation(host, username, password, port, target, **kwargs)

    def __init__(self, host, username, password, port, target,**kwargs):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.target = target
        self.kwargs = kwargs
        self.timeout = kwargs.get('timeout')

    def to_dict(self):
        """
        Produces a dictionary copy of the deployment location

        Returns:
            the deployment location configuration as a dictionary. For example:

            {
                'name': 'Test',
                'properties': {
                    ...
                }
            }
        """
        return {
            NetConfDeploymentLocation.HOST: self.host,
            NetConfDeploymentLocation.USERNAME: self.username,
            NetConfDeploymentLocation.PASSWORD: self.password,
            NetConfDeploymentLocation.PORT: self.port,
            NetConfDeploymentLocation.TIMEOUT: self.timeout,
            NetConfDeploymentLocation.TARGET: self.target
        }

    def operation(self,package_properties,default_operation,rsa_key_path,request_id):
        response = ConfigOperations.netconf_connect(self.host, self.port, self.username, self.password, rsa_key_path, self.kwargs)
        ConfigOperations.netconf_lock(response)
        edit_config_details = ConfigOperations.netconf_edit(response,package_properties,default_operation, self.target,request_id)        
        # Only candidate datastore configuration are allowed to commit
        if self.target == DATASTORE_CANDIDATE:
            ConfigOperations.netconf_commit(response)
        ConfigOperations.netconf_unlock(response)
        ConfigOperations.netconf_disconnect(response)
        return edit_config_details

    def close(self):
        pass