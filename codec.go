package powermux

import (
	"encoding/json"
	"net/http"
	"strings"
)

var Codecs = map[string]Codec{
	"application/json": {
		MarshalFunc:   json.Marshal,
		UnmarshalFunc: json.Unmarshal,
		Type:          "application/json",
	},
	// "application/yaml": {
	//   MarshalFunc:   yaml.Marshal,
	//   UnmarshalFunc: yaml.Unmarshal,
	//   Type:          "application/yaml",
	// },
}

func Detect(req *http.Request) Codec {
	switch typ := nonempty(req.Header.Get("Content-Type"), req.Header.Get("Accept")); {
	case strings.HasSuffix(req.URL.Path, ".json"):
		return Codecs["application/json"]
	case strings.HasSuffix(req.URL.Path, ".yaml"):
		return Codecs["application/yaml"]
	default:
		return Codecs[typ]
	}
}

type Codec struct {
	MarshalFunc   func(interface{}) ([]byte, error)
	UnmarshalFunc func([]byte, interface{}) error
	Type          string
}

func (c Codec) Marshal(v interface{}) (p []byte, err error) {
	if c.MarshalFunc != nil {
		return c.MarshalFunc(v)
	}
	return json.Marshal(v)
}

func (c Codec) Unmarshal(p []byte, v interface{}) error {
	if c.UnmarshalFunc != nil {
		return c.UnmarshalFunc(p, v)
	}
	return json.Unmarshal(p, v)
}

func (c Codec) ContentType() string {
	if c.Type != "" {
		return c.Type
	}
	return "application/json"
}
