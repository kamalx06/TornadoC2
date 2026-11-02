package features

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ShapingSpec struct {
	CheckinResponse *ShapeSpec `json:"checkin_response,omitempty"`
	TasksResponse   *ShapeSpec `json:"tasks_response,omitempty"`
	ResultsRequest  *ShapeSpec `json:"results_request,omitempty"`
}

type ShapeSpec struct {
	Template json.RawMessage `json:"template"`
	Extract  string          `json:"extract"`
	Encoding string `json:"encoding,omitempty"`
	Placement *Placement `json:"placement,omitempty"`
}

type Placement struct {
	Kind string `json:"kind,omitempty"`
	Name string `json:"name,omitempty"`
}

var placeholderRe = regexp.MustCompile(`^\{\{(\w+)\}\}$`)

func renderShaping(node interface{}, ctx map[string]interface{}) interface{} {
	switch v := node.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, sub := range v {
			out[k] = renderShaping(sub, ctx)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, sub := range v {
			out[i] = renderShaping(sub, ctx)
		}
		return out
	case string:
		m := placeholderRe.FindStringSubmatch(v)
		if m != nil {
			if val, ok := ctx[m[1]]; ok {
				return val
			}
		}
		return v
	}
	return node
}

func ShapeWrap(spec *ShapeSpec, payload interface{}) ([]byte, error) {
    inner, err := json.Marshal(payload)
    if err != nil {
        return nil, err
    }

    var nb [8]byte
    if _, rerr := crand.Read(nb[:]); rerr != nil {
        binary.BigEndian.PutUint64(nb[:], uint64(time.Now().UnixNano()))
    }

    ctx := map[string]interface{}{
        "payload": encodePayload(inner, spec.Encoding),
        "ts":      time.Now().Unix(),
        "nonce":   hex.EncodeToString(nb[:]),
    }
    var tmpl interface{}
    if err := json.Unmarshal(spec.Template, &tmpl); err != nil {
        return nil, err
    }
    out := renderShaping(tmpl, ctx)
    return json.Marshal(out)
}

func ShapeUnwrap(body []byte, spec *ShapeSpec) ([]byte, error) {
	var obj interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, err
	}
	value, err := walkPath(obj, spec.Extract)
	if err != nil {
		return nil, err
	}
	s, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("extracted value is %T, not string", value)
	}
	raw, err := decodePayload(s, spec.Encoding)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func encodePayload(raw []byte, encoding string) string {
	switch strings.ToLower(encoding) {
	case "base64url":
		return base64.RawURLEncoding.EncodeToString(raw)
	case "hex":
		return hex.EncodeToString(raw)
	case "netbios":
		var sb strings.Builder
		for _, b := range raw {
			sb.WriteByte(byte('a' + (b & 0x0f)))
			sb.WriteByte(byte('a' + ((b >> 4) & 0x0f)))
		}
		return sb.String()
	default:
		return base64.StdEncoding.EncodeToString(raw)
	}
}

func decodePayload(encoded string, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "base64url":
		return base64.RawURLEncoding.DecodeString(encoded)
	case "hex":
		return hex.DecodeString(encoded)
	case "netbios":
		if len(encoded)%2 != 0 {
			return nil, fmt.Errorf(
				"netbios payload has odd length")
		}
		out := make([]byte, len(encoded)/2)
		for i := 0; i < len(encoded); i += 2 {
			low := int(encoded[i] - 'a')
			high := int(encoded[i+1] - 'a')
			if low < 0 || low > 15 || high < 0 || high > 15 {
				return nil, fmt.Errorf(
					"netbios payload out of range at %d", i)
			}
			out[i/2] = byte(low) | byte(high<<4)
		}
		return out, nil
	default:
		return base64.StdEncoding.DecodeString(encoded)
	}
}

var pathSegRe = regexp.MustCompile(`^(\w+)(?:\[(\d+)\])?$`)

func walkPath(obj interface{}, path string) (interface{}, error) {
	cur := obj
	for _, part := range strings.Split(path, ".") {
		m := pathSegRe.FindStringSubmatch(part)
		if m == nil {
			return nil, fmt.Errorf("bad path segment: %q", part)
		}
		key := m[1]
		idxStr := m[2]
		m2, ok := cur.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf(
				"not a map at %q (got %T)", part, cur)
		}
		next, ok := m2[key]
		if !ok {
			return nil, fmt.Errorf(
				"extract path segment %q not present "+
					"in body", part)
		}
		cur = next
		if idxStr != "" {
			idx, _ := strconv.Atoi(idxStr)
			arr, ok := cur.([]interface{})
			if !ok || idx >= len(arr) {
				return nil, errors.New("bad index at " + part)
			}
			cur = arr[idx]
		}
	}
	return cur, nil
}

func ValidateShapingSpec(spec *ShapingSpec) error {
    checks := []struct {
        name string
        s    *ShapeSpec
    }{
        {"checkin_response", spec.CheckinResponse},
        {"tasks_response",   spec.TasksResponse},
        {"results_request",  spec.ResultsRequest},
    }
    for _, c := range checks {
        if c.s == nil {
            continue
        }
        if len(c.s.Template) == 0 {
            return fmt.Errorf("%s: template is empty", c.name)
        }
        if c.s.Extract == "" {
            return fmt.Errorf("%s: extract is required", c.name)
        }
        probe := map[string]interface{}{
            "__probe__": "ok",
            "n":         float64(1),
        }
        rendered, err := ShapeWrap(c.s, probe)
        if err != nil {
            return fmt.Errorf("%s: template render: %w", c.name, err)
        }
        recovered, err := ShapeUnwrap(rendered, c.s)
        if err != nil {
            return fmt.Errorf("%s: extract %q: %w",
                c.name, c.s.Extract, err)
        }
        var got interface{}
        if err := json.Unmarshal(recovered, &got); err != nil {
            return fmt.Errorf("%s: probe decode: %w", c.name, err)
        }
        if !reflect.DeepEqual(got, probe) {
            return fmt.Errorf(
                "%s: round-trip mismatch (got %#v, want %#v)",
                c.name, got, probe)
        }
    }
    return nil
}