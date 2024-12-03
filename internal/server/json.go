package server

import (
	"reflect"

	"github.com/bytedance/sonic"
)

var jsonHandler = sonic.Config{
	UseNumber:  true,
	EscapeHTML: true,
}.Froze()

func init() {
	// Initialize SIMD JSON handler
	// Just pretouch the JSONResponse type without options
	sonic.Pretouch(reflect.TypeOf(JSONResponse{}))
}

type JSONResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func fastJSONMarshal(v interface{}) []byte {
	data, _ := jsonHandler.Marshal(v)
	return data
}

func fastJSONUnmarshal(data []byte, v interface{}) error {
	return jsonHandler.Unmarshal(data, v)
}
