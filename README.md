# (꒰֎꒱)
# -TARDIGRADE-

     ( ꒰֎꒱ )   
    උ( ___ )づ 
     උ( ___ )づ       
       උ( ___ )づ               
      උ( ___ )づ

## What is it
Tardigrade is a small python HTTP server that runs in the command line. It's meant to be a dev tool to quickly spin up a useful small server.

Devised principally to be an auxiliary application to Postman, until some day in the far future when **[7210](https://github.com/postmanlabs/postman-app-support/issues/7210)** is finally addressed. 

Tardigrade can connect to another Tardigrade instance via web logging to log the other's events, or any application 
using python's **[HHTPHandler](https://docs.python.org/3/library/logging.handlers.html#logging.handlers.HTTPHandler)**
------
## Features

### HTTP Server Mode

Tardigrade operates as a normal HTTP Server, receiving HTTP requests nad responding in kind. Mostly processes requests in the form of JSON.

### Log Server Mode

Tardigrade operates as an HTTP Server with the sole purpose of serving as a logging utility for other applications sending GET requests with the structure used
by **[logging.handlers.HTTPHandler](https://docs.python.org/3/library/logging.handlers.html#logging.handlers.HTTPHandler)**

------
## HTTP Server Mode

### HTTP GET

GET requests serve files from the directory where Tardigrade is running. It extends **[SimpleHTTPRequestHandler](https://docs.python.org/3/library/http.server.html)** to accomplish this.

If a request is for a directory instead, it will serve either a present "index.htm(l)" file or generate a page with a list of files in the directory. This is very useful to check file names and their relative path to where Tardigrade is running, if seen from a browser.

Example directory structure
```
.
├── venv
├── tardigrade.py
├── README.md
├── requirements.txt
├── setup.py
└── test files/
    ├── index.html
    ├── other.html
    ├── otherJSON.json
    ├── response.json
    ├── text.txt
    └── commas.csv
```

Example call 1:
```http request
    GET localhost:8000/
```
Response:

### HTTP POST

Via POST, Tardigrade listens in 3 endpoints:

### mock

Very similar to the GET response, it will return the contents of either a present "response.json" file, or a different file if the filename is sent as part of the request path.
**Call**
```http request
    POST localhost:8000/mock
```
Will not validate or process the body, but it will log it.

### log
Will simply log the request as it comes, headers and body, one log record per request.
**Call**
```http request
    POST localhost:8000/log
```


### command

Executes a command in the os terminal, and returns the output from the command. Useful for example to generate a some data or run a custom .bat or .sh via a command line utility to use in subsequent operations in Postman.

**Request contract:**
```http request
    POST localhost:8000/command
```
```json lines
{
    "single_line" : "single line ", 
    "cmd": "string",
    "args": ["string",...]
}
```
**Response contract:**
```json lines
{
  "error" : "string",
  "output" : "string"
}
```

Where 
 - single_line is a command with arguments included, as the name implies, in a single line.
 - cmd is a string containing just the command
 - args is an array of strings containing every argument separately

If all properties are present, the pair of cmd & args is prioritized.

Example request 1: Windows: list elements in Tardigrade's directory
```json lines
{
  "single_line" : "dir /b"
}
```
Example response 1:
```json lines
{
    "error": "",
    "output": "index.html\nREADME.md\nresponse.json\nsetup.py\ntardigrade.py\nvenv\n__pycache__\n"
}
```

Example request 2: Windows: repeat two phrases
```json lines
{
    "cmd": "echo",
    "args": ["long phrase", "phrase"]
}
```
Example response 2:
```json lines
{
    "error": "",
    "output": "\"long phrase\" phrase\n"
}
```

Example request 3: Run another Tardigrade. Note that if timeout is set to 0 or higher, this will kill the other Tardigrade.
Using no-color and no-banner is recommended to avoid the unicode characters
```json lines
{
    "cmd": "py",
    "args": ["tardigrade.py", "-o", "no-color", "no-banner", "--timeout", "20"]
}
```

```json lines
{
    "cmd": "py",
    "args": ["tardigrade.py", "-o", "no-color"]
}
```