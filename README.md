# go-http-digest-auth-client
Golang Http Digest Authentication Client

This client implements [RFC7616 HTTP Digest Access Authentication](https://www.rfc-editor.org/rfc/rfc7616.txt)
and by now the basic features should work.

# Usage

```go
// import
import dac "github.com/xinsnake/go-http-digest-auth-client"

// create a new digest authentication request
dr := dac.NewRequest(userId, userId, method, endUri, payload)
response1, err := dr.Execute()

// check error, get response

// reuse the existing digest authentication request so no extra request is needed
dr.UpdateRequest(userId, userId, "PUT", endUri, string(buf.Bytes()))
response2, err := dr.Execute()

// check error, get response
```
# Todos

* Unit testing
* Implement encoded username `username*`
* Logging and debugging message
