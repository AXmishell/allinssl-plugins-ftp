package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// ActionInfo 定义插件动作信息
type ActionInfo struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Params      []map[string]any `json:"params,omitempty"`
}

type Request struct {
	Action string                 `json:"action"`
	Params map[string]interface{} `json:"params"`
}

type Response struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Result  map[string]interface{} `json:"result"`
}

// pluginMeta 插件元数据，主程序通过 get_metadata 获取
var pluginMeta = map[string]interface{}{
	"name":        "ftp",
	"description": "上传证书到 FTP 服务器",
	"version":     "1.0.0",
	"author":      "ALLinSSL",
	"config": []map[string]interface{}{
		{
			"name":        "host",
			"type":        "string",
			"description": "FTP 服务器地址",
			"required":    true,
		},
		{
			"name":        "port",
			"type":        "number",
			"description": "FTP 端口，默认 21",
			"required":    false,
		},
		{
			"name":        "username",
			"type":        "string",
			"description": "FTP 用户名",
			"required":    true,
		},
		{
			"name":        "password",
			"type":        "string",
			"description": "FTP 密码",
			"required":    true,
		},
		{
			"name":        "remote_path",
			"type":        "string",
			"description": "远程上传目录路径",
			"required":    true,
		},
		{
			"name":        "use_tls",
			"type":        "string",
			"description": "是否启用 FTPS (显式 TLS)，默认 false",
			"required":    false,
		},
	},
	"actions": []ActionInfo{
		{
			Name:        "upload",
			Description: "上传证书到 FTP 服务器",
			Params: []map[string]any{
				{
					"name":        "cert_filename",
					"type":        "string",
					"description": "证书文件名，默认 fullchain.pem",
					"required":    false,
				},
				{
					"name":        "key_filename",
					"type":        "string",
					"description": "私钥文件名，默认 privkey.pem",
					"required":    false,
				},
			},
		},
	},
}

func outputJSON(resp *Response) {
	_ = json.NewEncoder(os.Stdout).Encode(resp)
}

func outputError(msg string, err error) {
	outputJSON(&Response{
		Status:  "error",
		Message: fmt.Sprintf("%s: %v", msg, err),
	})
}

func main() {
	var req Request
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		outputError("读取输入失败", err)
		return
	}

	if err := json.Unmarshal(input, &req); err != nil {
		outputError("解析请求失败", err)
		return
	}

	switch req.Action {
	case "get_metadata":
		outputJSON(&Response{
			Status:  "success",
			Message: "插件信息",
			Result:  pluginMeta,
		})
	case "list_actions":
		outputJSON(&Response{
			Status:  "success",
			Message: "支持的动作",
			Result:  map[string]interface{}{"actions": pluginMeta["actions"]},
		})
	case "upload":
		rep, err := Upload(req.Params)
		if err != nil {
			outputError("FTP 上传失败", err)
			return
		}
		outputJSON(rep)

	default:
		outputJSON(&Response{
			Status:  "error",
			Message: "未知 action: " + req.Action,
		})
	}
}
