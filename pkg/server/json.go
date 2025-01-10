package server

import (
	"log"
	"reflect"

	"github.com/bytedance/sonic"
)

func init() {
	if err := sonic.Pretouch(reflect.TypeOf(JSONResponse{})); err != nil {
		log.Printf("Failed to pretouch JSONResponse type: %v", err)
	}
}

type JSONResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
