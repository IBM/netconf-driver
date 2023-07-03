# netconf-driver

## Overview

CP4NA supports integration of netconf devices using Netconf-Driver.
Netconf driver implements following lifecycle methods to operate network configurations of a network device.

	1. Create
	2. Upgrade
	3. Delete

-  It uses Ignition framework (https://github.com/IBM/ignition) to communicate 
	with Brent/CP4NA.

-  It is a wrapper on ncclient open source library (https://github.com/ncclient/ncclient)  
	to call operations on netconf device.


-  For all the above lifecycle methods, driver uses ncclient librariy’s edit_config() method 
	with default-operation as one of ‘merge’, ‘replace’ or ‘none’.

-  Resource properties can pass the default-operation property value as ‘merge’ or ‘replace’ 
      for Create and Upgrade lifecycles. For Delete lifecycle 'none' is used by default.
	
## Configuration

-  Configuration details for the Create/Upgrade/Delete lifecycle methods are passed through xml template files 
	as part of the resource package as follows.

	  1. For Create lifecycle, create.xml  
	  2. For Upgrade lifecycle, update.xml
	  3. For Delete lifecycle, delete.xml

-  For each lifecycle, configurations are generated in the driver by parsing the properties in the corresponding 
	template file and replaces these property names with corresponding values received from resource properties.    

-  The configuration content in xml file along with operations must be specific to the lifecycle that is 
	being invoked. 

- The driver does not validate if there are any inappropriate operations defined in xml for a lifecycle method 

```
For example: 
	1. replace or merge operations for Delete lifecycle
	2. delete or remove operations for Create lifecycle
```

- Following deployment location properties will have the values for connecting to the Netconf server:

```
{
	"host": "9.30.XX.XX",
	"port": "830",
	"username": "netconf",
	"password": "netconf",
	"timeout": 30,
	"target": "running"
}
```
```
Note: 
   1. candidate or startup datastore type can be specified as target in the deployment location
   2. By default target uses running datastore type, if no value specified or any other value specified
```
- For ssh communication with the network device, the ssh keys must be added to Brent using Infrastructure Keys: https://www.ibm.com/docs/en/cloud-paks/cp-network-auto/2.2.x?topic=using-infrastructure-keys

- In the resource package, in the resource.yaml file , make sure to add a property 'infraKey' with type as 'key' and push the resource package to cp4na. Example shown below : 

```
infraKey:
  type: key
  required: true
```

- Once the Infrastructure key is created, make sure to add its name in resource properties under 'infraKey' while creating an instance in cp4na


## Onboarding Netconf driver

For information on how to onboard Netconf driver to a CP4NA cluster, please see [Onboarding Guide](docs/Onboarding.md)