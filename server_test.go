package powermux_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"testing"

	"github.com/rjeczalik/powermux"

	"github.com/julienschmidt/httprouter"
)

type ReqHello struct {
	Where  string `json:"where" query:"where"`
	Who    string `json:"who" param:"who"`
	Custom string `json:"custom"`
}

type RespHello struct {
	Text string `json:"text"`
}

type HelloService struct {
	Blacklist string
	Format    string
}

func (srvc *HelloService) Hello(arg *ReqHello, reply *RespHello) error {
	if arg.Who == srvc.Blacklist {
		return powermux.NewError(40123, errors.New("blacklisted: "+arg.Who))
	}
	reply.Text = fmt.Sprintf(srvc.Format, arg.Who, arg.Where, arg.Custom)
	return nil
}

func (srvc *HelloService) HelloRaw(w http.ResponseWriter, req *http.Request, param httprouter.Params) {
	var arg ReqHello
	err := json.NewDecoder(req.Body).Decode(&arg)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if v := param.ByName("who"); v != "" {
		arg.Who = v
	}
	if v := req.URL.Query().Get("where"); v != "" {
		arg.Where = v
	}
	w.Header().Set("Content-Type", "application/json")
	resp := &RespHello{
		Text: fmt.Sprintf(srvc.Format, arg.Who, arg.Where, arg.Custom),
	}
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}
}

var routes = powermux.Routes{{
	Method:  "POST",
	Path:    "/hello/:who/get",
	Handler: (*HelloService).Hello,
}, {
	Method:        "POST",
	Path:          "/hello/:who",
	Handler:       (*HelloService).Hello,
	DanglingParam: "who",
}, {
	Method:  "POST",
	Path:    "/raw/:who",
	Handler: (*HelloService).HelloRaw,
}}

func parseError(resp *http.Response, c powermux.Codec) error {
	p, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var e powermux.Error
	if err = c.Unmarshal(p, &e); err != nil {
		return err
	}
	return &e
}

func TestServer(t *testing.T) {
	srvc := &HelloService{Blacklist: "twoja_stara", Format: "who=%s, where=%s, custom=%s"}
	srv := powermux.NewServer("", srvc, routes)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen=%s", err)
	}
	defer lis.Close()
	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(lis)
	}()
	cases := [...]struct {
		Path  string
		Req   *ReqHello
		Resp  *RespHello
		Error error
		Type  string
		Code  int
	}{{ // i=0
		Path: "/v1/hello/ja?where=tutej",
		Req:  &ReqHello{Custom: "srustom"},
		Resp: &RespHello{Text: "who=ja, where=tutej, custom=srustom"},
		Type: "application/json",
		Code: 200,
	}, { // i=1
		Path: "/v1/hello/lol/get?where=wut&XD=true",
		Req:  &ReqHello{Custom: "wai"},
		Resp: &RespHello{Text: "who=lol, where=wut, custom=wai"},
		Type: "application/json",
		Code: 200,
	}, { // i=2
		Path: "/v1/hello/ja.json?where=tutej",
		Req:  &ReqHello{Custom: "srustom"},
		Resp: &RespHello{Text: "who=ja, where=tutej, custom=srustom"},
		Type: "application/json",
		Code: 200,
	}, { // i=3
		Path: "/v1/hello/ja.json?where=tutej",
		Req:  &ReqHello{Custom: "srustom"},
		Resp: &RespHello{Text: "who=ja, where=tutej, custom=srustom"},
		Type: "application/json",
		Code: 200,
	}, { // i=4
		Path: "/v1/hello/lol/get.json?where=wut&XD=true",
		Req:  &ReqHello{Custom: "wai"},
		Resp: &RespHello{Text: "who=lol, where=wut, custom=wai"},
		Type: "application/json",
		Code: 200,
	}, { // i=5
		Path: "/v1/hello/lol/get.json?where=wut&XD=true",
		Req:  &ReqHello{Custom: "wai"},
		Resp: &RespHello{Text: "who=lol, where=wut, custom=wai"},
		Type: "application/json",
		Code: 200,
	}, { // i=6
		Path:  "/v1/hello/twoja_stara/get.json?where=pierze&w=rzece",
		Req:   &ReqHello{},
		Error: &powermux.Error{Code: 40123, Err: errors.New("blacklisted: twoja_stara")},
		Type:  "application/json",
		Code:  401,
	}, { // i=7
		Path: "/v1/raw/twoja_stara?where=w_rzece",
		Req:  &ReqHello{Custom: "XD"},
		Resp: &RespHello{Text: "who=twoja_stara, where=w_rzece, custom=XD"},
		Type: "application/json",
		Code: 200,
	}}
	for i, cas := range cases {
		url := "http://" + lis.Addr().String() + cas.Path
		codec := powermux.Codecs[cas.Type]
		p, err := codec.Marshal(cas.Req)
		if err != nil {
			t.Errorf("powermux.Codecs.Marshal=%s (i=%d)", err, i)
			continue
		}
		resp, err := http.Post(url, cas.Type, bytes.NewReader(p))
		if err != nil {
			t.Errorf("http.Post=%s (i=%d)", err, i)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != cas.Code {
			t.Errorf("want resp.StatusCode=%d; got %d: %s (i=%d)", cas.Code,
				resp.StatusCode, parseError(resp, codec), i)
			continue
		}
		if cas.Code > 299 {
			if err := parseError(resp, codec); !reflect.DeepEqual(err, cas.Error) {
				t.Errorf("want err=%v; got %v (i=%d)", cas.Error, err, i)
			}
			continue
		}
		if typ := resp.Header.Get("Content-Type"); typ != cas.Type {
			t.Errorf("want Content-Type=%s; got %s (i=%d)", cas.Type, typ, i)
			continue
		}
		p, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll=%s (i=%d)", err, i)
			continue
		}
		var respBody RespHello
		if err := codec.Unmarshal(p, &respBody); err != nil {
			t.Fatalf("powermux.Codecs.Unmarshal=%s (i=%d)", err, i)
			continue
		}
		if !reflect.DeepEqual(cas.Resp, &respBody) {
			t.Fatalf("want respBody=%v; got %v (i=%d)", cas.Resp, &respBody, i)
			continue
		}
	}
	select {
	case err := <-done:
		t.Fatalf("srv.Serve=%s", err)
	default:
	}
}
