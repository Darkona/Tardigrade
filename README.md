# (꒰֎꒱)  
# -TARDIGRADE-  
```  
( ꒰֎꒱ )
උ( ___ )づ  
 උ( ___ )づ  
  උ( ___ )づ  
 උ( ___ )づ  
```

## What is it  

Tardigrade is a small python HTTP server that runs in the command line. It's meant to be a dev tool to quickly spin up a useful small server.  
  
Devised principally to be an auxiliary application to Postman, until some day in the far future when **[7210](https://github.com/postmanlabs/postman-app-support/issues/7210)** is finally addressed.  

Tardigrade can connect to another Tardigrade instance via web logging to log the other's events, or any application using python's **[HHTPHandler](https://docs.python.org/3/library/logging.handlers.html#logging.handlers.HTTPHandler)**  

## Install & Run

```bash
python -m pip install git+https://github.com/Darkona/Tardigrade.git
```
```bash
python -m tardigrade
```

## Features  
  
### HTTP Server Mode  
  
Tardigrade operates as a normal HTTP Server, receiving HTTP requests and responding in kind.
  
### Log Server Mode  
  
Tardigrade operates as an HTTP Server with the sole purpose of serving as a logging utility for other applications sending GET requests with the structure used  by **[logging.handlers.HTTPHandler](https://docs.python.org/3/library/logging.handlers.html#logging.handlers.HTTPHandler)**  
  
## HTTP Server Mode  (Normal mode)
  
### HTTP GET  
  
GET requests serve files from the input directory, relative to where Tardigrade is running. It extends **[SimpleHTTPRequestHandler](https://docs.python.org/3/library/http.server.html)** to accomplish this.  
  
If a request is for a directory instead, it will serve either an existing "index.htm(l)" file or generate a page with a list of files in the directory. This is very useful to check file names, if seen from a browser.  
  
##### Example call 1:  
```bash
curl -XGET 'http://localhost:8000'  
```  
##### Response:  
```html
<!DOCTYPE html>  
<html lang="en">  
	<head>  
		<meta charset="UTF-8">  
		<title>Title</title>  
	</head>  
	<body>  
		Tardigrade test page  
	</body>  
</html>
```   
##### Example call 2:  
```http request  
curl -XGET 'localhost:8000/other.html'  
```  
##### Response:  
```html
<!DOCTYPE html>  
<html lang="en">  
	<head>  
		<meta charset="UTF-8">  
		<title>Test file 2</title>  
	</head>  
	<body>  
		Test File 2  
	</body>  
</html>
```
##### Example call 3:
```bash 
curl -XGET 'localhost:8000/../'  
```  
##### Response:  
```html
<!DOCTYPE HTML>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<title>Directory listing for /input//../</title>
	</head>
	<body>
		<h1>Directory listing for /input//../</h1>
		<hr>
		<ul>
			<li><a href="config/">config/</a></li>
			<li><a href="input/">input/</a></li>
			<li><a href="output/">output/</a></li>
			<li><a href="README.md">README.md</a></li>
			<li><a href="requirements.txt">requirements.txt</a></li>
			<li><a href="setup.py">setup.py</a></li>
			<li><a href="tardigrade.py">tardigrade.py</a></li>
			<li><a href="venv/">venv/</a></li>
		</ul>
		<hr>
	</body>
</html>
```
----
### HTTP POST  
  
Via POST, Tardigrade listens in 5 endpoints:  "command", "mock", "log", "stop", and "write"
  
#### Mock  
Very similar to the GET response, it will return the contents of either a present "response.json" file, or a different file if the filename is sent as part of the request path.  Will not validate or process the body, but it will log it.  
##### Call
```bash 
curl -XPOST 'localhost:8000/mock'
```  
##### Response
```json lines
{
	"response": "response.json"
}
```
----
#### Log  
Will simply log the request as it comes, headers and body, one log record per request. Will only respond with HTTP Status OK
##### call
```bash 
curl -XPOST 'localhost:8000/mock'
```  
----
#### Command  
  
Executes a command in the os terminal, and returns the output from the command. Useful for example to generate a some data or run a custom .bat or .sh via a command line utility to use in subsequent operations in Postman.  
  
##### Request contract:
```bash 
curl -XPOST 'localhost:8000/command' 
```  
```json lines  
{  
	"single_line" : "single line",  
	"cmd": "string",  
	"args": ["string", "string", "string"]  
}  
```  
##### Response contract: 
```json lines  
{  
	"error" : "string",  
	"output" : "string"  
}  
```  
Where :
- single_line is a command with all arguments included.  
- cmd is a string containing just the command  
- args is an array of strings containing every argument separately  
  
If all properties are present, the pair of cmd & args is prioritized.  
  
##### Example request 1
```json lines  
{  
	"single_line" : "echo Tardigrades are very small"  
}
```  
##### Response
```json lines  
{
	"error": "",
	"output": "\"Tardigrades are very small\"\n"
}
```  
  
##### Example request 2: Send an incorrect argument 
```json lines  
{
	"cmd": "dir",
	"args": ["/k"]
}
```  
##### Example response 2:  
```json lines  
{
	"error": "Invalid switch - \"k\".\n",
	"output": ""
}
```  

#### Running commands indefinitely
 
If Tardigrade has a set timeout of 0 or less, it will not wait for a command to finish running, but will return a response saying that the command has been executed instead. The process will run in the background, and can be stopped later by sending a request to "stop" via POST or any request via DELETE.

If the timeout is greater than 0, Tardigrade will wait that long (in seconds) for the process to finish and kill it at the end of that time.

There can be only one command running from an instance at any time, and if an attempt is made to execute a new command, the response will indicate that a process is already running.

The next example shows how to run another Tardigrade from Tardigrade, but the process can be used to run any other command that keeps running and then stop it.

##### Example 3: Running Tardigrade from Tardigrade

Run another Tardigrade. Note that if timeout is set to 0 or higher, this will kill the other Tardigrade.  
It is necessary to set a different port for the new Tardigrade instance.
Using no-color and no-banner is recommended to avoid the unicode characters  in the response, which will contain the other Tardigrade's output.

This is called a Tardigraception.

Assuming timeout of 0

##### Call 1

```bash  
curl -XPOST 'localhost:8000/command' 
```  
```json lines  
{  
	"cmd": "py",  
	"args": ["tardigrade.py", "-o", "no-color", "no-banner", "--timeout", "20", "--port", "8010"]  
}  
```  
##### Response
```json lines  
{
	"error": null,
	"output": "Process py has been started and is now running."
}
```
##### Call 2
```bash  
curl -XPOST 'localhost:8000/command' 
```  
```json lines  
{
	"error": null,
	"output": "Process py is running."
}
```
##### Response
```json lines  
{
	"error": "Another process already running: py"
}
```
##### Call 3 
```bash
curl -XDELETE 'localhost:8000'
```  
##### or
```bash
curl -XPOST 'localhost:8000/stop'
```  
```json lines  
{
	"comment" : "This must be valid json, even empty json {} works"
}
```
##### Response
```json lines  
{
	"error": "Tardigrade (꒰֎꒱) - [INFO] 2023-06-21 05:39:01,842 {run:862} - Tardigrade started\n",
	"output": "Configuration loaded\nTardigrade Server is running. Listening at: localhost:8010\nWritting files to /output, reading files from /input\nMonochromatic (boring) logging enabled. Level: INFO\n"
}
```
stdout captured normal print() output and stderr captured log output, and it was returned when the process was stopped.


#### Write

The write endpoint will write a file to the /output directory.

##### Request Contract
```json lines
	{
		"filename": "string",
		"content": "string",
		"mode": "string",
		"type": "string"
	}
```
Where: 
 - "mode": optional, if present, must have one of the following values:
   * "append" or "a" will append data to the end of the file
   * "create" or "c" will create the file if it doesn't exist, or fail
   * "overwrite" or "w" will create the file anyway. This is the default behaviour if mode is not present.
  - "type": optional, if present, must have one of the following values:
   * "text" or "t" will write data as text. This is the default behaviour if mode is not present.
   * "binary" or "b" will write data in binary form.

#####
##### Response Contract
```json lines  
{
	"message": "string",
	"filesize": "number"
}
```
Filesize is in bytes.

## Usage
First, install Tardigrade and its required dependencies with:
```bash
python -m pip install tardigrade
```

To run Tardigrade from the command line, the command is:
```bash
python tardigrade
```
This is a Tardigrade running with all its default options.

## Configuration

Configuration comes in two flavors: arguments and configuration file.
All the defaults will be changed to the values in the config file before checking the arguments. If no config file is present, these defaults will apply. This means the configuration will be used in the following order:
```
command line arguments > config.yaml > defaults
```
Running Tardigrade with the -h argument will show the following information:
```bash
py tardigrade -h
```
```
usage: Tardigrade [-h] [--port PORT] [--directory DIRECTORY] [--timeout TIMEOUT] [--output OUTPUT] [--input INPUT]
                  [--logserver] [--loglevel {q|quiet, d|debug, i|info, w|warn, e|error, c|critical, s|server}]
                  [--options [{no-color,no-request,no-response,no-header,no-body,no-console,no-banner} ...]]
                  [--extra {file,web}] [--filename FILENAME] [--maxbytes MAXBYTES] [--count FILECOUNT]
                  [--webhost WEBHOST] [--weburl WEBURL] [--method {GET,POST}] [--credentials userid password]
                  [--version]

options:
  -h, --help            show this help message and exit
  --version             show Tardigrade version

Server Configuration:
  --port PORT, -p PORT  the server port where Tardigrade will run (default: 8000)
  --directory DIRECTORY, -d DIRECTORY
                        directory to execute commands from (default: /)
  --timeout TIMEOUT, -t TIMEOUT
                        directory to serve files or execute commands from (default: 10)
  --output OUTPUT, -O OUTPUT
                        Directory where to write files to (default: /output)
  --input INPUT, -I INPUT
                        Directory to serve files from (default: /input)

Logging Configuration:
  --logserver, -L       Disables all own logging, will listen for POST logging from another Tardigrade and log its
                        messages with this Tardigrade configuration (default: False)
  --loglevel {q|quiet, d|debug, i|info, w|warn, e|error, c|critical, s|server}, -l {q|quiet, d|debug, i|info, w|warn, e|error, c|critical, s|server}
                        logging level (default: info)
  --options [{no-color,no-request,no-response,no-header,no-body,no-console,no-banner} ...], -o [{no-color,no-request,no-response,no-header,no-body,no-console,no-banner} ...]
                        remove certain attributes from logging. (default: [])
  --extra {file,web}, -e {file,web}
                        extra logger outputs (default: [])

Extra Logger Options:
  --filename FILENAME, -f FILENAME
                        only has an effect if file logger is enabled; filename for the log file (default:
                        output/logs/tardigrade.log)
  --maxbytes MAXBYTES, -x MAXBYTES
                        only has an effect if file logger is enabled;max size of each file in bytes, if 0, file grows
                        indefinitely (default: 0)
  --count FILECOUNT, -c FILECOUNT
                        only has an effect if file logger is enabled; max amount of files to keep before rolling over,
                        if 0, file grows indefinitely (default: 0)
  --webhost WEBHOST     required if web logger is enabled; host for the listening log server, can include port like
                        host:port (default: None)
  --weburl WEBURL       required if web logger is enabled; url for the listening log server (default: None)
  --method {GET,POST}, -m {GET,POST}
                        only has an effect if web logger is enabled (default: POST)
  --credentials userid password, -C userid password
                        only has an effect if web logger is enabled; enables basic authentication with Authorization
                        header (default: ('', ''))
```

### -- options or -o
Accepts any and all values indicated: "no-color", "no-request", "no-response", "no-header", "no-body", "no-console", and "no-banner"
### no-color
By default, Tardigrade logs to the console using ANSI coloring, the presence of this value turns it off.
### no-request, no-response, no-header, no-body
Logging will omit the specified parts. For example, "-o no-response no-header" will only log the request body elements. Log events above INFO will still be generated. (To disable all logging use --loglevel quiet instead.)
### no-console
Disables any and all output to stdout and stderr. If using any of the following loggers, those will write.
### no-banner
Will not show the Tardigrade ASCII art when Tardigrade starts.

### --extra or  -e
Accepts one or both values: "file" and "web"

#### file

The file logger implements [RotatingFileHandler](https://docs.python.org/3/library/logging.handlers.html#rotatingfilehandler). The arguments expose the same arguments from the handler.

#### web
Enables the web logging handler implements [WebHandler](https://docs.python.org/3/library/logging.handlers.html#httphandler)
Not all the handler's arguments are exposed as Tardigrade's arguments. Secure connection is not part of the scope of this simple tool (for now)
When enabling this logger --host and --url arguments become required.
When using --credentials, the next two values must be the username and then the password, in that order.
You can use a second Tardigrade in Log Server Mode (--logserver) to listen to this handler and log the other instance's events.

## Launch examples

##### Start with the most minimal config to be able to receive Postman requests to load files. No logging, but want to be able to tell if the application is running

Long form arguments
```
python tardigrade --loglevel quiet
```
Short form arguments
```
python tardigrade -lq
```
##### Show nothing on the console, log everything to a rotating file called "newlogs" in a directory called "grawn" and rotate the file every 5MB, keeping a maximun of 10 files. Only log WARNING or above. 

Long form arguments
```
python tardigrade -options no-console -extra file --filename newlogs.log --maxbytes 5000000 --count 10 --output /grawn --loglevel warn
```
Short form arguments
```
python tardigrade -ono-console -efile -fnewlogs.log -x5000000 -c10 -O/grawn -lw
```

##### Start as log server and send all events to a different log server listening for POST requests at someserver.com:5000/logger, which requires basic auth
Long form arguments
```
python tardigrade --logserver --extra web --webhost http://someserver.com:5000 --weburl / --method POST --credentials myusername mypassword
```
Short form arguments
```
python tardigrade -L -eweb --webhost http://someserver.com:5000 --weburl /logger -mPOST -C mysuername mypassword
```

##### Start with monochromatic console logging at level ERROR or above only, listen at port 80, and enable indefinite execution of commands
Long form arguments
```
python tardigrade --port 80 --options no-color --loglevel error --timeout 0
```
Short form arguments
```
python tardigrade -p80 -o no-color -le -t0
```

### Extra Arguments

These arguments are inherited from HTTPServer
 - --host or -h sets the http server host

## Postman Examples

The main drive for this project was to make a companion server for Postman to help in making development life easier. Postman won't let you load files (yet, and possibly never) and the use case for this and for running a command line program and get the output exist for a while now.

Included in the project is a Postman collection with a few examples like loading a text file, loading a csv, parsing the info and showing it cleanly in the Postman visualizer, etc, but more complex uses both in the pre-request and test sections can be done by anyone who needs it.


## Build Instructions

Install Poetry
```bash
python -m pip install poetry
```
Install modules with poetry

```bash
poetry install
```
Build with poetry

 ```bash
poetry build
```
   