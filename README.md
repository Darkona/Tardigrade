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

## Features

### Server Mode


#### HTTP GET

GET requests serve files from the directory where Tardigrade is running. It extends **[SimpleHTTPRequestHandler](https://docs.python.org/3/library/http.server.html)** to accomplish this.

If a request is for a directory instead, it will serve either a present "index.htm(l)" file or generate a page with a list of files in the directory. This is very useful to check file names and their relative path to where Tardigrade is running, if seen from a browser.

#### HTTP POST

Via POST, Tardigrade listens in 3 endpoints:

##### /mock

Very similar to the GET response, it will return the contents of either a present "response.json" file, or a different file if the filename is sent as part of the request path.

##### /log

Will simply log the request as it comes, one log record per request.

##### /command

Executes a command in the os terminal, and returns the output from the command. Useful for example to generate a some data or run a custom .bat or .sh via a command line utility to use in subsequent operations in Postman.

Request
```json lines
{
    "single_line" : "string", 
    "cmd": "string",
    "args": ["string",...]
}
```
Where 
 - single_line is a command with arguments included, as the name implies, in a single line.
 - cmd is a string containing just the command
 - args is an array of strings containing every argument separately

If all properties are present, the pair of cmd & args is prioritized.

Example 1: Run dir /b in windows to see a list of elements in tardigrade's directory
```json lines
{
  "single_line" : "dir /b"
}

```

Example 2:
```json lines
{
    "cmd": "dir",
    "args": ["C:", "/b"]
}
```

Example 3:
```json lines
{
    "cmd": "dir",
    "args": ["/a", "/b"]
}
```