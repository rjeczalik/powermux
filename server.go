package powermux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"time"

	"github.com/julienschmidt/httprouter"
)

type Route struct {
	Method  string
	Path    string
	Handler interface{}

	// DanglingParam is the name of the param that ends closes the Path, e.g.
	//
	//   - for GET /resource/:id DanglingParam will be "id"
	//   - for GET /resource/:id/detail there's no DanglingParam
	//
	// This workaround is needed for the router package.
	DanglingParam string
}

type Routes []Route

type Server struct {
	// required parameters:
	Routes  map[string]Routes // versionned routing tables for HTTP requests
	Service interface{}       // service context which is passed to route handlers

	// optional http.Server parameters:
	Server       *http.Server  // when non-nil use it for serving HTTP requests; Server.Handler will be overwritten
	Addr         string        // network address to listen on; overwrites Server.Addr
	ReadTimeout  time.Duration // maximum duration before timing out a read; overwrite Server.ReadTimout; default 30s
	WriteTimeout time.Duration // maximum duration before timeout out a write; overwrites Server.WriteTimeout; default 30s

	// optional powermux.Server parameters:
	Name       string // when non-empty sets the Server HTTP header
	HomeURL    string // when non-empty redirect GET / to this URL
	MaxBodyLen int    // upper limit of the request / response body length
	NoSafe     bool   // when true does not add "safe" headers
	NoCORS     bool   // when true does not handle preflight requests
	NoAccess   bool   // when true does not log API access

	// optional parameters for controlling behavior of the server:
	ErrorFunc func(error) error // when non-nil used to instrument errors
	ErrorLog  *log.Logger       // when non-nil used to log errors

	wired  bool
	router *httprouter.Router
}

func NewServer(addr string, service interface{}, routes ...Routes) *Server {
	if len(routes) == 0 {
		panic(errors.New("powermux: called NewServer with no routes"))
	}
	r := make(map[string]Routes, len(routes))
	for i, route := range routes {
		r["v"+strconv.Itoa(i+1)] = route
	}
	return &Server{
		Routes:  r,
		Service: service,
		Addr:    addr,
	}
}

func (srv *Server) maxBodyLen() int {
	if srv.MaxBodyLen != 0 {
		return srv.MaxBodyLen
	}
	return 32 * 1024 * 1024
}

func (srv *Server) instrument(err error) error {
	if srv.ErrorFunc != nil {
		return srv.ErrorFunc(err)
	}
	return err
}

func (srv *Server) uninstrument(err error) error {
	if err, ok := err.(*Error); ok && err != nil {
		return err
	}
	return err
}

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (srv *Server) Serve(l net.Listener) error {
	return srv.serve(l)
}

func (srv *Server) ListenAndServe() error {
	lis, err := net.Listen("tcp", srv.server().Addr)
	if err != nil {
		return srv.instrument(err)
	}
	return srv.serve(lis)
}

func (srv *Server) serve(l net.Listener) error {
	if ln, ok := l.(*net.TCPListener); ok {
		srv.logf("powermux: using TCP keep-alive for %s", l.Addr())
		l = tcpKeepAliveListener{ln}
	}
	return srv.server().Serve(l)
}

func (srv *Server) server() *http.Server {
	srv.wire()
	return srv.Server
}

func handle(fn http.HandlerFunc) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		fn(w, req)
	}
}

func (srv *Server) wire() {
	if srv.wired {
		return
	}
	// Build HTTP server.
	if srv.Server == nil {
		srv.Server = &http.Server{
			Addr:         srv.Addr,
			ReadTimeout:  srv.ReadTimeout,
			WriteTimeout: srv.WriteTimeout,
		}
	}
	if srv.Addr != "" {
		srv.Server.Addr = srv.Addr
	}
	if srv.ReadTimeout != 0 {
		srv.Server.ReadTimeout = srv.ReadTimeout
	}
	if srv.WriteTimeout != 0 {
		srv.Server.WriteTimeout = srv.WriteTimeout
	}
	if srv.Server.ReadTimeout == 0 {
		srv.Server.ReadTimeout = 30 * time.Second
	}
	if srv.Server.WriteTimeout == 0 {
		srv.Server.WriteTimeout = 30 * time.Second
	}
	// Build REST service routing.
	srv.router = httprouter.New()
	srv.router.RedirectTrailingSlash = true
	srv.router.HandleMethodNotAllowed = true
	srv.router.RedirectFixedPath = true
	srv.router.NotFound = http.HandlerFunc(srv.notFound)
	srv.router.MethodNotAllowed = http.HandlerFunc(srv.methodNotAllowed)
	srv.router.PanicHandler = srv.panicHandler
	if srv.HomeURL != "" {
		srv.router.GET("/", func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
			http.Redirect(w, req, srv.HomeURL, 307)
		})
	}
	for version, routes := range srv.Routes {
		for _, route := range routes {
			path := "/" + version + route.Path
			register := srv.routerFunc(route.Method)
			// Register HTTP handler.
			switch handler := route.Handler.(type) {
			case http.HandlerFunc:
				register(path, handle(handler))
				continue
			case func(http.ResponseWriter, *http.Request):
				register(path, handle(http.HandlerFunc(handler)))
				continue
			case httprouter.Handle:
				register(path, handler)
				continue
			case func(http.ResponseWriter, *http.Request, httprouter.Params):
				register(path, httprouter.Handle(handler))
				continue
			}
			// Register RPC service handler.
			var handler httprouter.Handle
			switch srv.detectType(route.Handler) {
			case serviceHTTP:
				register(path, srv.buildServiceHTTP(route.Handler))
				continue
			case serviceHTTPParam:
				register(path, srv.buildServiceHTTPParam(route.Handler))
				continue
			case serviceRPC:
				handler = srv.buildServiceHandler(route.Handler)
				if route.DanglingParam != "" {
					handler = srv.strippingHandler(handler, route.DanglingParam)
					register(path, handler)
					continue
				}
				register(path, handler)
				register(path+".json", handler)
			default:
				panic(fmt.Sprintf("unsupported handler type: %T", route.Handler))
			}
		}
	}
	srv.Server.Handler = http.HandlerFunc(srv.serveHTTP)
	srv.wired = true
	return
}

// readRequest is like Read, but for HTTP request. Upon return, the body is
// replaced wit a buffer and can be read again.
func (srv *Server) readRequest(req *http.Request) ([]byte, error) {
	p, err := srv.read(req.Body, req.ContentLength)
	req.Body.Close()
	switch e := srv.uninstrument(err); {
	case e == io.EOF || e == io.ErrUnexpectedEOF || len(p) == 0:
		req.Body = ioutil.NopCloser(eofReader{})
		return nil, io.EOF
	case err != nil:
		return nil, err
	case len(p) != 0:
		req.Body = ioutil.NopCloser(bytes.NewReader(p))
	}
	return p, nil
}

// readResponse is like Read, but for HTTP response. Upon return, the body is
// replaced wit a buffer and can be read again.
func (srv *Server) readResponse(resp *http.Response) ([]byte, error) {
	p, err := srv.read(resp.Body, resp.ContentLength)
	resp.Body.Close()
	switch e := srv.uninstrument(err); {
	case e == io.EOF || e == io.ErrUnexpectedEOF || len(p) == 0:
		resp.Body = ioutil.NopCloser(eofReader{})
		return nil, io.EOF
	case err != nil:
		return nil, err
	case len(p) != 0:
		resp.Body = ioutil.NopCloser(bytes.NewReader(p))
	}
	return p, nil
}

// read attempts to read the body in one-shot pre-allocating needed space.
// It reads up to max bytes. It does not close the body, just to let you
// handle the case when max bytes was read and you want to peek what's left.
// The returned error is, if non-nil, *Error.
func (srv *Server) read(r io.Reader, approxLen int64) ([]byte, error) {
	if approxLen > int64(srv.maxBodyLen()) {
		return nil, srv.instrument(&Error{Code: 41300})
	}
	if approxLen <= 0 {
		approxLen = int64(srv.maxBodyLen() / 8)
	}
	p := make([]byte, approxLen)
	m, err := io.Copy(sliceWriter(p), io.LimitReader(r, int64(srv.maxBodyLen())))
	switch {
	case err != nil:
		return nil, srv.instrument(&Error{Code: 40000, Err: err})
	case m == 0:
		// Most of the times io.ErrUnexpectedEOF is expected condiation.
		// The reason it's not io.EOF to be able to distinguish io.EOF from
		// empty body. Do not trace the error, as Sentry put a quota on it alredy:
		//
		//   trace.go:107: Sentry: failed sending error to server: raven: got http status 429
		//
		return nil, &Error{Code: 40014, Err: io.ErrUnexpectedEOF}
	case m < approxLen/3:
		// Shrink p if it's a good deal too large. This covers the case when
		// we did not receive Content-Length header.
		q := make([]byte, m)
		copy(q, p)
		return q, nil
	default:
		return p, nil
	}
}

func (srv *Server) notFound(w http.ResponseWriter, req *http.Request) {
	err := &Error{
		Code: 40499,
		Err:  errors.New("no route for " + req.Method + " " + req.URL.String()),
	}
	srv.fatal(w, Detect(req), err)
	srv.logAccess(req, nil, status(err), err)
}

func (srv *Server) methodNotAllowed(w http.ResponseWriter, req *http.Request) {
	err := &Error{
		Code: 40599,
		Err:  errors.New("method " + req.Method + " not allowed for " + req.URL.String()),
	}
	srv.fatal(w, Detect(req), err)
	srv.logAccess(req, nil, status(err), err)
}

func (srv *Server) panicHandler(w http.ResponseWriter, req *http.Request, v interface{}) {
	err := &Error{
		Code: 50099,
		Err:  fmt.Errorf("panic while handling %s for %s: %v", req.Method, req.URL, v),
	}
	srv.fatal(w, Detect(req), err)
	srv.logAccess(req, nil, status(err), err)
}

func (srv *Server) strippingHandler(handler httprouter.Handle, param string) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, p httprouter.Params) {
		for i := range p {
			if p[i].Key == param {
				p[i].Value = strip(p[i].Value, ".json")
			}
		}
		handler(w, req, p)
	}
}

var errorType = reflect.TypeOf((*error)(nil)).Elem()

func status(err error) int {
	if err, ok := err.(*Error); ok {
		return err.Status()
	}
	return 500
}

func (srv *Server) logAccess(req *http.Request, args []reflect.Value, code int, err error) {
	if srv.NoAccess {
		return
	}
	switch {
	case args == nil && err == nil:
		srv.logf("powermux: %s: %d %s %s", req.RemoteAddr, code, req.Method, req.URL.Path)
	case args == nil:
		srv.logf("powermux: %s: %d %s %s err=%s", req.RemoteAddr, code, req.Method,
			req.URL.Path, err)
	case err == nil:
		srv.logf("powermux: %s: %d %s %s arg=%#v reply=%#v", req.RemoteAddr, code,
			req.Method, req.URL.Path, args[0].Interface(), args[1].Interface())
	default:
		srv.logf("powermux: %s: %d %s %s arg=%#v reply=%#v err=%s", req.RemoteAddr,
			code, req.Method, req.URL.Path, args[0].Interface(), args[1].Interface(), err)
	}
}

func (srv *Server) buildServiceHTTP(v interface{}) httprouter.Handle {
	vsrv := reflect.ValueOf(srv.Service)
	method := reflect.ValueOf(v)
	return func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		args := []reflect.Value{
			vsrv,
			reflect.ValueOf(w),
			reflect.ValueOf(req),
		}
		method.Call(args)
	}
}

func (srv *Server) buildServiceHTTPParam(v interface{}) httprouter.Handle {
	vsrv := reflect.ValueOf(srv.Service)
	method := reflect.ValueOf(v)
	return func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		paramsMap := make(map[string]string, len(params))
		for _, param := range params {
			paramsMap[param.Key] = param.Value
		}
		args := []reflect.Value{
			vsrv,
			reflect.ValueOf(w),
			reflect.ValueOf(req),
			reflect.ValueOf(paramsMap),
		}
		method.Call(args)
	}
}

func (srv *Server) buildServiceHandler(v interface{}) httprouter.Handle {
	methodType := reflect.TypeOf(v)
	method := reflect.ValueOf(v)
	argType := methodType.In(1)
	replyType := methodType.In(2).Elem()
	queryFields := buildTagMap(argType, "query", true)
	paramFields := buildTagMap(argType, "param", true)
	headerFields := buildTagMap(argType, "header", true)
	return func(w http.ResponseWriter, req *http.Request, param httprouter.Params) {
		codec := Detect(req)
		args, reply, err := srv.buildArgs(argType, replyType, req, param, queryFields, paramFields, headerFields)
		if err != nil {
			err = NewError(40099, err)
			srv.fatal(w, codec, err)
			srv.logAccess(req, nil, status(err), err)
			return
		}
		switch err := method.Call(args)[0].Interface().(type) {
		case nil:
		case error:
			if err != nil {
				srv.fatal(w, codec, err)
				srv.logAccess(req, args[1:], status(err), err)
				return
			}
		}
		srv.response(w, codec, 200, reply)
		srv.logAccess(req, args[1:], 200, nil)
	}
}

func buildTagMap(typ reflect.Type, tag string, doembed bool) map[string]string {
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil
	}
	m := make(map[string]string)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if doembed && field.Type.Kind() == reflect.Struct && field.Anonymous {
			for k, v := range buildTagMap(field.Type, tag, false) {
				m[k] = v
			}
			continue
		}
		tagValue := field.Tag.Get(tag)
		if tagValue != "" {
			m[field.Name] = tagValue
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func (srv *Server) fieldSet(field reflect.Value, value string) error {
	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return srv.instrument(err)
		}
		field.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return srv.instrument(err)
		}
		field.SetUint(n)
	default:
		return srv.instrument(fmt.Errorf("incompatible type for param: %s", field.Type()))
	}
	return nil
}

var genericType = reflect.TypeOf((*map[string]interface{})(nil)).Elem()

func (srv *Server) expandQueryParamFields(obj reflect.Value, query url.Values, header http.Header, param httprouter.Params, queryFields, paramFields, headerFields map[string]string, doembed bool) error {
	if reflect.TypeOf(obj).ConvertibleTo(genericType) {
		m := obj.Convert(genericType)
		for k := range header {
			m.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(query.Get(k)))
		}
		for k := range query {
			m.SetMapIndex(reflect.ValueOf(k), reflect.ValueOf(query.Get(k)))
		}
		for _, v := range param {
			m.SetMapIndex(reflect.ValueOf(v.Key), reflect.ValueOf(v.Value))
		}
		return nil
	}
	if obj.Kind() == reflect.Ptr {
		obj = obj.Elem()
	}
	if obj.Kind() != reflect.Struct {
		return nil
	}
	for i := 0; i < obj.NumField(); i++ {
		field := obj.Field(i)
		fieldName := obj.Type().Field(i).Name
		switch field.Type().Kind() {
		case reflect.Map, reflect.Slice:
			continue // Ignore non-comparable model fields.
		case reflect.Struct:
			if doembed && obj.Type().Field(i).Anonymous {
				err := srv.expandQueryParamFields(field, query, header, param, queryFields, paramFields, headerFields, false)
				if err != nil {
					return srv.instrument(err)
				}
			}
			continue
		}
		if paramName, ok := paramFields[fieldName]; ok {
			if value := param.ByName(paramName); value != "" {
				if err := srv.fieldSet(field, value); err != nil {
					return srv.instrument(err)
				}
				continue
			}
		}
		if field.Interface() != reflect.Zero(field.Type()).Interface() {
			continue
		}
		if queryName, ok := queryFields[fieldName]; ok {
			if value := query.Get(queryName); value != "" {
				if err := srv.fieldSet(field, value); err != nil {
					return srv.instrument(err)
				}
				continue
			}
		}
		if field.Interface() != reflect.Zero(field.Type()).Interface() {
			continue
		}
		if headerName, ok := headerFields[fieldName]; ok {
			if value := header.Get(headerName); value != "" {
				if err := srv.fieldSet(field, value); err != nil {
					return srv.instrument(err)
				}
			}
		}
	}
	return nil
}

func (srv *Server) buildArgs(argType, replyType reflect.Type, req *http.Request,
	param httprouter.Params, queryFields, paramFields, headerFields map[string]string) ([]reflect.Value, interface{}, error) {
	ptr := false
	if argType.Kind() == reflect.Ptr {
		argType = argType.Elem()
		ptr = true
	}
	arg := reflect.New(argType)
	switch p, err := srv.readRequest(req); srv.uninstrument(err) {
	case io.EOF:
		// no body - ignore
	case nil:
		err = Detect(req).Unmarshal(p, arg.Interface())
		if err != nil {
			// TODO(rjeczalik): make codec always return *Error
			return nil, nil, srv.instrument(NewError(40000, err))
		}
	default:
		if err != nil {
			return nil, nil, srv.instrument(err)
		}
	}
	if validator, ok := arg.Interface().(interface {
		Err() error
	}); ok {
		if err := validator.Err(); err != nil {
			return nil, nil, &Error{Code: 40000, Err: err}
		}
	}
	if len(queryFields)+len(paramFields)+len(headerFields) != 0 {
		srv.expandQueryParamFields(arg, req.URL.Query(), req.Header, param, queryFields, paramFields, headerFields, true)
	}
	if !ptr {
		arg = arg.Elem()
	}
	reply := reflect.New(replyType)
	args := []reflect.Value{reflect.ValueOf(srv.Service), arg, reply}
	return args, reply.Interface(), nil
}

func (srv *Server) addSafe(_ *http.Request, header http.Header) {
	header.Set("X-XSS-Protection", "1; mode=block")
	header.Set("X-Frame-Options", "SAMEORIGIN")
}

// TODO(rjeczalik): make it work on actual routing table
func (srv *Server) addCORS(req *http.Request, header http.Header) {
	header.Set("Access-Control-Allow-Methods", "HEAD, CONNECT, GET, POST, PUT, DELETE")
	if v := req.Header.Get("Access-Control-Request-Headers"); v != "" {
		header.Set("Access-Control-Allow-Headers", v)
	}
}

const (
	serviceInvalid   = iota
	serviceHTTP      // func(T, http.ResponseWriter, *http.Request)
	serviceHTTPParam // func(T, http.ResponseWriter, *http.Request, httprouter.Params)
	serviceRPC       // func(T, arg S, reply *V) error
)

var (
	responseWriterType = reflect.TypeOf((*http.ResponseWriter)(nil)).Elem()
	requestType        = reflect.TypeOf((*http.Request)(nil))
	paramsType         = reflect.TypeOf((*map[string]string)(nil)).Elem()
)

func (srv *Server) detectType(v interface{}) int {
	typ := reflect.TypeOf(v)
	if typ.Kind() != reflect.Func {
		panic("powermux: handler is not a function")
	}
	if typ.NumIn() == 0 {
		return serviceInvalid
	}
	if typ.In(0) != reflect.TypeOf(srv.Service) {
		panic("powermux: handler has incompatible first argument")
	}
	switch typ.NumIn() {
	case 3:
		if typ.In(1) == responseWriterType && typ.In(2) == requestType {
			return serviceHTTP
		}
		if typ.NumOut() == 1 && typ.Out(0) == errorType && typ.In(2).Kind() == reflect.Ptr {
			return serviceRPC
		}
	case 4:
		if typ.In(1) == responseWriterType && typ.In(2) == requestType && typ.In(3) == paramsType {
			return serviceHTTPParam
		}
	}
	return serviceInvalid
}

func (srv *Server) serveHTTP(w http.ResponseWriter, req *http.Request) {
	if srv.Name != "" {
		w.Header().Add("Server", srv.Name)
	}
	if !srv.NoSafe {
		srv.addSafe(req, w.Header())
	}
	if !srv.NoCORS {
		// TODO(rjeczalik): make it configurable
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", Detect(req).ContentType())
		if req.Method == "OPTIONS" {
			srv.addCORS(req, w.Header())
			w.WriteHeader(200)
			return
		}
	}
	srv.router.ServeHTTP(w, req)
}

func (srv *Server) fatal(w http.ResponseWriter, c Codec, err error) {
	e := NewError(50000, err).(*Error)
	srv.response(w, c, e.Status(), e)
}

func (srv *Server) response(w http.ResponseWriter, c Codec, status int, v interface{}) {
	switch p, err := c.Marshal(v); err {
	case nil:
		w.Header().Set("Content-Type", c.ContentType())
		w.Header().Set("Content-Length", strconv.Itoa(len(p)))
		w.WriteHeader(status)
		w.Write(p)
	default:
		p = []byte(err.Error())
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(p)))
		w.WriteHeader(500)
		w.Write(p)
	}
}

func (srv *Server) routerFunc(method string) func(string, httprouter.Handle) {
	switch method {
	case "GET":
		return srv.router.GET
	case "POST":
		return srv.router.POST
	case "PUT":
		return srv.router.PUT
	case "DELETE":
		return srv.router.DELETE
	case "OPTIONS":
		return srv.router.OPTIONS
	case "PATCH":
		return srv.router.PATCH
	case "HEAD":
		return srv.router.HEAD
	default:
		return nil
	}
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
//
// NOTE(rjeczalik): Stolen from $GOROOT/src/net/http/server.go
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
