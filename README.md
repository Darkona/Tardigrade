# ,꒰ º ꒱,
# -TARDIGRADE-

    (꒰ o ꒱)   
    උ( ___ )づ 
    උ( ___ )づ       
       උ( ___ )づ               
      උ( ___ )づ

## What is it
Tardigrade is a super lightweight python HTTP server that runs in the command line.
It's capable of serving files and running commands in the console.

## What does it do

Create users in database, provide tokens, and allow login.

## Endpoints

* "/sign-up"
* "/login"
* "/check"

###  /Sign Up
Creates a user in database, provides JWT in return.

#### URL
When running locally, access via:
```http request
POST http://localhost:8080/sign-up
```

#### Contract
```json lines
{
  "name": "String",
  "email": "String",
  "password": "String",
  "phones": [
    {
      "number": "long",
      "citycode": "int",
      "contrycode": "String"
    }
  ]
}
```

#### Response Contract
```json lines
{
  "id" : "String", 
  "name": "String",
  "email": "String",
  "password": "String", 
  "created" : "String", 
  "lastLogin" : "String",
  "isActive": "Boolean",
  "token" : "String",
  "phones": [
    {
      "number": "Long",
      "citycode": "Int",
      "contrycode": "String"
    }
  ]
}
```
- ID: Generated UUID
- Created: Formatted Timestamp - MMM dd, yyyy hh:mm:ss a
- LastLogin: Formatted Timestamp - MMM dd, yyyy hh:mm:ss a
- Token: JWTToken
- Password: Encrypted input password

#### Validation
##### Password 
 - Length between 8 and 12 characters.
 - Exactly one upper case letter.
 - Exactly two numbers, can be non-consecutive.
 - Only alphanumeric characters, no symbols.

**Name** and **Phones** are optional.
**Email** must be validated for proper format.

### /Login
Attempts a login using email and password, adding the generated token.
Validates token and password and then shows the full data of the user.
Token is received via **header** with name **Bearer**

#### URL
When running locally, access via:
```http request
POST http://localhost:8080/login
```

#### Contract
**Header**
```json lines
[{
  "Bearer" : "String"
}]
```
- The string must be the JWT Token generated when creating the user with /sign-up

**Body**
```json lines
{
  "email": "String",
  "password": "String", 
}
```
- Password in plain text
#### Response
```json lines
{
  "id" : "String", 
  "name": "String",
  "email": "String",
  "password": "String", 
  "created" : "String",
  "lastLogin" : "String",
  "isActive": "Boolean",
  "token" : "String",
  "phones": [
    {
      "number": "Long",
      "citycode": "Int",
      "contrycode": "String"
    }
  ]
}
```
- Token: **Updated** New JWT token after the call
- LastLogin: **Updated** Formatted Timestamp - MMM dd, yyyy hh:mm:ss a
- Password: Encrypted version

#### /Check -- GET

A simple health check for the application running.

#### URL
When running locally, access via:
```http request
GET http://localhost:8080/
```
#### Response
```text
"ok"
```

## Changes

* 1.0.0 Initial version

##### Build with Gradle
```shell
gradlew build
```
##### Run with Gradle
```shell
gradlew bootRun
```
##### Test with Gradle
```shell
gradlew test
```
