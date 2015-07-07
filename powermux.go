package powermux

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func min(i, j int) int {
	if i < j {
		return i
	}
	return j
}

func max(i, j int) int {
	if i > j {
		return i
	}
	return j
}

func toMinutes(d time.Duration) int {
	return min(12*60, max(1, int((d+time.Duration(0.5*float64(time.Minute)))/time.Minute)))
}

func nonempty(s ...string) string {
	for _, s := range s {
		if s != "" {
			return s
		}
	}
	return ""
}

func strip(s string, suffixes ...string) string {
	for _, suffix := range suffixes {
		if i := strings.Index(s, suffix); i != -1 {
			return s[:i]
		}
	}
	return s
}

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) {
	return 0, io.EOF
}

type pWriter struct {
	p []byte
	n int
}

// Write implements the io.Writer interface.
func (w *pWriter) Write(p []byte) (int, error) {
	if len(p) > len(w.p)-w.n {
		return 0, io.ErrShortWrite
	}
	copy(w.p[w.n:w.n+len(p)], p)
	w.n += len(p)
	return len(p), nil
}

// sliceWriter gives a writer to writes to the given slice, starting at 0.
// If a write is attempted that exceeds the range of p, io.ErrShortWrite is
// returned.
func sliceWriter(p []byte) io.Writer {
	return &pWriter{p: p}
}

type Error struct {
	Code int   `json:"code" yaml:"code"`
	Err  error `json:"error" yaml:"error"`
}

var _ json.Marshaler = (*Error)(nil)
var _ json.Unmarshaler = (*Error)(nil)

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s (code %d)", e.Err, e.Code)
	} else {
		return fmt.Sprintf("%s (code %d)", http.StatusText(e.Status()), e.Code)
	}
}

func (e *Error) Status() int {
	switch n := e.Code / 100; {
	case n == 0:
		return 200
	case n > 99 && n < 600:
		return n
	default:
		return 500
	}
}

type httpErr struct {
	Code int    `json:"code"`
	Err  string `json:"error"`
}

func (e *Error) MarshalJSON() ([]byte, error) {
	v := &httpErr{Code: e.Code}
	if e.Err != nil {
		v.Err = e.Err.Error()
	} else {
		v.Err = http.StatusText(e.Status())
	}
	return json.Marshal(v)
}

func (e *Error) UnmarshalJSON(p []byte) error {
	v := &httpErr{}
	if err := json.Unmarshal(p, v); err != nil {
		return err
	}
	e.Code = v.Code
	e.Err = errors.New(v.Err)
	return nil
}

func NewError(code int, err error) error {
	if _, ok := err.(*Error); ok {
		return err
	}
	if p, err := json.Marshal(err); err == nil {
		var he httpErr
		if err := json.Unmarshal(p, &he); err == nil && he.Code != 0 {
			e := &Error{Code: he.Code}
			if he.Err != "" {
				e.Err = errors.New(he.Err)
			}
			return e
		}
	}
	return &Error{
		Code: code,
		Err:  err,
	}
}
