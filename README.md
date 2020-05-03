# AVD Pipeline
---
A Distributed Pipeline, which aims to provide an infrastructure to connect the hardware resources and divide the ’pipelinable tasks’ into stages and process them in parallel and in order, synonymous to an assembly line of a software task.

## Build
---
To build the project, execute the following commands at the `src` drirectory the project directory  
```   
	make clean        
	make
```  
This will generate binaries for all the components in the `build` directory

## Usage
---
There are three components of the system. Each component will run on seperate machines.

### Server
To run the server follow the given steps.  

1. Create a config file ```server.json``` from the template
	*	**_log_level_** : There are 5 level of logs namely DEBUG=0, INFO=1, WARN=2, ERROR=3, FATAL=4
	*	**_log_quiet_** : Set this to false if you want to print the logs in the console along with the file
	*	**_addr_** : Ip address on which the server will be running
	*	**_uport_** : Port number for user server
	*	**_wport_** : Port number for worker server
	*	A worker config template is given below
```
			{
				"server": {
					"log_user_file": "<log_file>",
					"log_worker_file": "<log_file>",
					"log_level": 1,
					"log_quiet": true,
					"addr": "<ip_address>",
					"uport": <user_port>,
					"wport": <worker_port>
				}
			}
```

Run the server using `./avd_server <config_file>`

### User
To run the user application on pipeline user needs to follow the given steps.  

1.  Compile the application in form of shared object.
    *  Create a Makefile in the application directory
    *  Set the following mandatary variables
		*	**_ROOT_** : Set the relative path to the `src` directory of the project
		*	**_TARGETS_** : Set the name of binary you want to generate. Keep the extension as **_.so_**
	*	Set following optional variables if required
		* 	**_LIB_DIR_** : set this with directory of source files if residing outside the current directory
		*	**_CUSTOM_LIBS_** : List down the source files in the directories in *LIB_DIR*
		*	**_LIBS_** : libraries to be linked dynamically, e.g -lm or -pthread
		*	**_INCLUDE_** : Set this to directory where header files are residing, only if outside current directory
	*	In the end of file add the line `include $(ROOT)/common.mk`
	*	When you run make in the `src` directory, application will also be build along with other components and stored in `build` directory
2. Create a config file ```user.json``` from the template
	*	**_uname_** : username chosen by user
	*	**_log_level_** : There are 5 level of logs namely DEBUG=0, INFO=1, WARN=2, ERROR=3, FATAL=4
	*	**_log_quiet_** : Set this to false if you want to print the logs in the console along with the file
	*	**_file_** : binary file of the application
	*	**_input_** : input file for the application
	*	**_output_** : file where output is to be stored
	*	**_num_** : number of stage in the chain, First worker being num=1, second being num=2 and so on 
	*	**_func_** : This is the name of function for the stage in the shared object binary
	*	A user config template is given below
```
			{
				"user" : {
					"uname": "<username>",  
					"log_file": "<log_file>",  
					"log_level": 1,  
					"log_quiet": true,  
					"srvr_addr": "<server_ip_address>",  
					"srvr_port": <server_user_port>,  
					"num_tasks": 1,  
					"tasks": [{
						"name": "<task name>",
						"file" : "<task binary file>",
						"input" : "<task input file>",
						"output" : "<task output file>",
						"num_stages": 2,
						"stages": [{
							"num": 1,
							"func": "<stage 1 function>"
						}, {
							"num": 2,
							"func": "<stage 2 function>"
						}]
					}]
				}
			}
```

Run the user using `./avd_user <config_file>`

### Worker
To run the worker follow the given steps.  

1. Create a config file ```worker.json``` from the template
	*	**_uname_** : username chosen by user
	*	**_log_level_** : There are 5 level of logs namely DEBUG=0, INFO=1, WARN=2, ERROR=3, FATAL=4
	*	**_log_quiet_** : Set this to false if you want to print the logs in the console along with the file
	*	**_addr_** : Ip address on which the peer server will be running
	*	**_peer_port_** : Port number for peer server
	*	A worker config template is given below
```
			{
				"worker" : {
					"uname": "<username>",
					"log_file": "<log_file>",
					"log_level": 1,
					"log_quiet": true,
					"addr" : "<peer_server_ip_address>",
					"peer_port": <peer_server_port>,
					"srvr_addr": "<server_ip_address>",
					"srvr_port": <server_worker_port>
				}
			}
```

Run the worker using `./avd_worker <config_file>`



