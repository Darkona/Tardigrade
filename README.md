# (꒰֎꒱)
# -TARDIGRADE-

    ( ꒰֎꒱ )   
    උ( ___ )づ 
    උ( ___ )づ       
       උ( ___ )づ               
      උ( ___ )づ

## What is it
Tardigrade is a super lightweight python HTTP server that runs in the command line. 
It's meant to be a dev tool to quickly spin up a useful small server.


Specially useful to load little files to Postman until some day in the far future when 
**[7210](https://github.com/postmanlabs/postman-app-support/issues/7210)** is finally addressed. 

It also serves as a small logging utility that can log requests via GET or POST methods.

Tardigrade can connect to another Tardigrade instance via web logging to log the other's events, or any application 
using python's **[HHTPHandler](https://docs.python.org/3/library/logging.handlers.html#logging.handlers.HTTPHandler)**
## Features

### GET Requests

GET requests serve files from the directory where Tardigrade is running. 
Leverages **[SimpleHTTPRequestHandler](https://docs.python.org/3/library/http.server.html)** to accomplish this.
It will return a file with best guess of content type. 

If a request is for a directory instead, it will show either a present index.html file or a list of files in the directory.

### POST Requests

POST Requests have two uses. If the request is in JSON format, it wil expect a 
### Simple usage
