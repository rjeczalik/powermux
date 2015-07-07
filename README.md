# powermux
Effortless HTTP routing for REST API servers.

# example

```go
package main

import (
	"errors"

	"github.com/rjeczalik/powermux"
)

type Service struct{}

type EchoArg struct {
	Text string `query:"text"`
}

type EchoReply struct {
	Text string `json:"text"`
}

func (Service) Echo(arg *EchoArg, reply *EchoReply) error {
	if arg.Text == "" {
		return powermux.NewError(40001, errors.New("text cannot be empty"))
	}
	reply.Text = arg.Text
	return nil
}

var routes = powermux.Routes{{
	Method:  "GET",
	Path:    "/echo",
	Handler: (Service).Echo,
}}

func main() {
	srv := powermux.NewServer(":8080", Service{}, routes)

	if err := srv.ListenAndServe(); err != nil {
		panic(err)
	}
}
```
```
~ $ go run example.go
2015/07/08 08:19:59 powermux: using TCP keep-alive for [::]:8080
2015/07/08 08:21:25 powermux: 127.0.0.1:61155: 400 GET /v1/echo arg=&main.EchoArg{Text:""} reply=&main.EchoReply{Text:""} err=text cannot be empty (code 40001)
2015/07/08 08:21:37 powermux: 127.0.0.1:61156: 200 GET /v1/echo arg=&main.EchoArg{Text:"XD"} reply=&main.EchoReply{Text:"XD"}
```
