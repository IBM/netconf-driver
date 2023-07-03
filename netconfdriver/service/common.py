import uuid
from datetime import datetime
from ignition.utils.propvaluemap import PropValueMap


CREATE_REQUEST_PREFIX = 'Create'
DELETE_REQUEST_PREFIX = 'Delete'
UPDATE_REQUEST_PREFIX = 'Update'

SUCCESS_RESULT = 'Success'
FAILURE_RESULT = 'Failure'

REQUEST_ID_SEPARATOR = '::'


def build_request_id(method_name):
    if method_name == CREATE_REQUEST_PREFIX.lower():
        request_id = CREATE_REQUEST_PREFIX
        request_id += REQUEST_ID_SEPARATOR
        request_id += str(uuid.uuid4())
        return request_id
    
    if method_name == DELETE_REQUEST_PREFIX.lower():
        request_id = DELETE_REQUEST_PREFIX
        request_id += REQUEST_ID_SEPARATOR
        request_id += str(uuid.uuid4())
        return request_id
    
    if method_name == UPDATE_REQUEST_PREFIX.lower():
        request_id = UPDATE_REQUEST_PREFIX
        request_id += REQUEST_ID_SEPARATOR
        request_id += str(uuid.uuid4())
        return request_id
    
DATASTORE_RUNNING = 'running'
DATASTORE_CANDIDATE = 'candidate'
DATASTORE_STARTUP = 'startup'    