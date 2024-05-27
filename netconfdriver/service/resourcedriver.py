from ignition.model.failure import FAILURE_CODE_INTERNAL_ERROR, FailureDetails
from ignition.model.lifecycle import STATUS_FAILED, LifecycleExecution, STATUS_COMPLETE
from ignition.service.framework import Service
from ignition.service.resourcedriver import ResourceDriverHandlerCapability, ResourceDriverError, InvalidRequestError
from ignition.service.framework import Service
from netconfdriver.service.location.deployment_location import *
from netconfdriver.service import jinja_conversion
import netconfdriver.service.common as common
from netconfdriver.service.operations.config_operations import *
import os

logger = logging.getLogger(__name__)

class ResourceDriverHandler(Service, ResourceDriverHandlerCapability):

    def execute_lifecycle(self, lifecycle_name, driver_files, system_properties, resource_properties, request_properties, associated_topology, deployment_location):
        """
        Execute a lifecycle transition/operation for a Resource.
        This method should return immediate response of the request being accepted,
        it is expected that the ResourceDriverService will poll get_lifecycle_execution on this driver to determine when the request has completed (or devise your own method).
        :param str lifecycle_name: name of the lifecycle transition/operation to execute
        :param ignition.utils.file.DirectoryTree driver_files: object for navigating the directory intended for this driver from the Resource package. The user should call "remove_all" when the files are no longer needed
        :param ignition.utils.propvaluemap.PropValueMap system_properties: properties generated by LM for this Resource: resourceId, resourceName, requestId, metricKey, resourceManagerId, deploymentLocation, resourceType
        :param ignition.utils.propvaluemap.PropValueMap resource_properties: property values of the Resource
        :param ignition.utils.propvaluemap.PropValueMap request_properties: property values of this request
        :param ignition.model.associated_topology.AssociatedTopology associated_topology: 3rd party resources associated to the Resource, from any previous transition/operation requests
        :param dict deployment_location: the deployment location the Resource is assigned to
        :return: an ignition.model.lifecycle.LifecycleExecuteResponse
        :raises:
            ignition.service.resourcedriver.InvalidDriverFilesError: if the scripts are not valid
            ignition.service.resourcedriver.InvalidRequestError: if the request is invalid e.g. if no script can be found to execute the transition/operation given by lifecycle_name
            ignition.service.resourcedriver.TemporaryResourceDriverError: there is an issue handling this request at this time
            ignition.service.resourcedriver.ResourceDriverError: there was an error handling this request
        """
        netconf_location = None
        
        try:
            netconf_location = NetConfDeploymentLocation.from_dict(deployment_location)
            method_name = lifecycle_name.lower()
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
            logger.debug('rsa_key_path : %s', rsa_key_path)
            if rsa_key_path is None:
                logger.warn("rsa_key_path is None!")
            request_id = common.build_request_id(method_name)
            logger.info('REQUEST: %s :- Before Executing Operation', request_id)
            edit_config_details = netconf_location.operation(package_properties,default_operation,rsa_key_path,request_id)
            logger.info('RESPONSE: %s :- After Executing Operation , Result : %s', request_id, edit_config_details)
        except NetconfConfigError as e:
            failure_reason = f'Error related to Netconf Connection or Configuration. {e}'
            return LifecycleExecution(request_id, STATUS_FAILED, FailureDetails(FAILURE_CODE_INTERNAL_ERROR, failure_reason), outputs={})
        except jinja_conversion.PropertyError as e:
            failure_reason = f'Error related to jinja_conversion. {e}'
            return LifecycleExecution(request_id, STATUS_FAILED, FailureDetails(FAILURE_CODE_INTERNAL_ERROR, failure_reason), outputs={})
        else:
            if (rsa_key_path != None):
                os.unlink(rsa_key_path)
            os.unlink(rsa_key_path)
            logger.info("Lifecycle Execution is successful.")
            return LifecycleExecution(request_id, STATUS_COMPLETE, failure_details=None, outputs={})

    def get_lifecycle_execution(self, request_id, deployment_location):
        """
        Retrieve the status of a lifecycle transition/operation request
        :param str request_id: identifier of the request to check
        :param dict deployment_location: the deployment location the Resource is assigned to
        :return: an ignition.model.lifecycle.LifecycleExecution
        :raises:
            ignition.service.resourcedriver.RequestNotFoundError: if no request with the given request_id exists
            ignition.service.resourcedriver.TemporaryResourceDriverError: there is an issue handling this request at this time, an attempt should be made again at a later time
            ignition.service.resourcedriver.ResourceDriverError: there was an error handling this request
        """

    def find_reference(self, instance_name, driver_files, deployment_location):
        """
        Find a Resource, returning the necessary property output values and internal resources from those instances
        :param str instance_name: name used to filter the Resource to find
        :param ignition.utils.file.DirectoryTree driver_files: object for navigating the directory intended for this driver from the Resource package. The user should call "remove_all" when the files are no longer needed
        :param dict deployment_location: the deployment location to find the instance in
        :return: an ignition.model.references.FindReferenceResponse
        :raises:
            ignition.service.resourcedriver.InvalidDriverFilesError: if the scripts are not valid
            ignition.service.resourcedriver.InvalidRequestError: if the request is invalid e.g. if no script can be found to execute the transition/operation given by lifecycle_name
            ignition.service.resourcedriver.TemporaryResourceDriverError: there is an issue handling this request at this time
            ignition.service.resourcedriver.ResourceDriverError: there was an error handling this request
        """
        print("Finding a reference")