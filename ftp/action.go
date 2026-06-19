package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// ftpConn wraps a net.Conn with FTP protocol helpers.
type ftpConn struct {
	conn net.Conn
}

const ftpIOTimeout = 30 * time.Second

func (c *ftpConn) readResponse() (int, string, error) {
	c.conn.SetReadDeadline(time.Now().Add(ftpIOTimeout))
	var buf [4096]byte
	n, err := c.conn.Read(buf[:])
	if err != nil {
		return 0, "", fmt.Errorf("读取 FTP 响应失败: %w", err)
	}
	data := string(buf[:n])
	lines := strings.Split(strings.TrimSpace(data), "\r\n")
	lastLine := lines[len(lines)-1]

	if len(lastLine) < 4 {
		return 0, "", fmt.Errorf("无效的 FTP 响应: %s", data)
	}
	code, err := strconv.Atoi(lastLine[:3])
	if err != nil {
		return 0, "", fmt.Errorf("解析 FTP 响应码失败: %s", data)
	}
	return code, data, nil
}

func (c *ftpConn) sendCommand(cmd string) error {
	c.conn.SetWriteDeadline(time.Now().Add(ftpIOTimeout))
	_, err := fmt.Fprintf(c.conn, "%s\r\n", cmd)
	return err
}

func (c *ftpConn) cmd(cmd string, expectedCode int) (int, string, error) {
	if err := c.sendCommand(cmd); err != nil {
		return 0, "", err
	}
	code, msg, err := c.readResponse()
	if err != nil {
		return 0, "", err
	}
	if code != expectedCode {
		return code, msg, fmt.Errorf("FTP 命令 %q 返回 %d (期望 %d): %s", cmd, code, expectedCode, msg)
	}
	return code, msg, nil
}

func (c *ftpConn) close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// ftpClient manages an FTP session.
type ftpClient struct {
	ctrl *ftpConn
	host string
}

// connect establishes a TCP connection and reads the welcome banner.
func connectFTP(host string, port int, useTLS bool) (*ftpClient, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	rawConn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接 FTP 服务器失败: %w", err)
	}

	client := &ftpClient{
		ctrl: &ftpConn{conn: rawConn},
		host: host,
	}

	// Read welcome banner
	code, msg, err := client.ctrl.readResponse()
	if err != nil {
		client.ctrl.close()
		return nil, fmt.Errorf("读取欢迎信息失败: %w", err)
	}
	if code != 220 {
		client.ctrl.close()
		return nil, fmt.Errorf("FTP 服务器返回异常欢迎码 %d: %s", code, msg)
	}

	if useTLS {
		if err := client.upgradeToTLS(host); err != nil {
			client.ctrl.close()
			return nil, err
		}
	}

	return client, nil
}

// upgradeToTLS performs explicit FTPS (AUTH TLS).
func (c *ftpClient) upgradeToTLS(host string) error {
	if _, _, err := c.ctrl.cmd("AUTH TLS", 234); err != nil {
		return fmt.Errorf("AUTH TLS 失败: %w", err)
	}

	tlsConn := tls.Client(c.ctrl.conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})

	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS 握手失败: %w", err)
	}
	c.ctrl.conn = tlsConn
	return nil
}

// login authenticates with USER and PASS commands.
func (c *ftpClient) login(user, pass string) error {
	if _, _, err := c.ctrl.cmd("USER "+user, 331); err != nil {
		return fmt.Errorf("USER 命令失败: %w", err)
	}
	if _, _, err := c.ctrl.cmd("PASS "+pass, 230); err != nil {
		return fmt.Errorf("PASS 命令失败: %w", err)
	}
	return nil
}

// setBinary sets transfer mode to binary.
func (c *ftpClient) setBinary() error {
	if _, _, err := c.ctrl.cmd("TYPE I", 200); err != nil {
		return fmt.Errorf("TYPE I 命令失败: %w", err)
	}
	return nil
}

// pasv enters passive mode and returns the data connection address.
func (c *ftpClient) pasv() (string, int, error) {
	_, msg, err := c.ctrl.cmd("PASV", 227)
	if err != nil {
		return "", 0, fmt.Errorf("PASV 命令失败: %w", err)
	}
	return parsePasv(msg)
}

// parsePasv extracts IP and port from PASV response like "227 Entering Passive Mode (127,0,0,1,195,80)"
func parsePasv(response string) (string, int, error) {
	start := strings.Index(response, "(")
	end := strings.LastIndex(response, ")")
	if start == -1 || end == -1 || end <= start {
		return "", 0, fmt.Errorf("无法解析 PASV 响应: %s", response)
	}
	parts := strings.Split(response[start+1:end], ",")
	if len(parts) != 6 {
		return "", 0, fmt.Errorf("PASV 响应格式错误: %s", response)
	}
	nums := make([]int, 6)
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return "", 0, fmt.Errorf("PASV 解析数字失败: %s", p)
		}
		nums[i] = n
	}
	ip := fmt.Sprintf("%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3])
	port := nums[4]*256 + nums[5]
	return ip, port, nil
}

// store uploads data to a remote file via STOR command.
func (c *ftpClient) store(remotePath string, data []byte) error {
	dataHost, dataPort, err := c.pasv()
	if err != nil {
		return err
	}

	dataAddr := net.JoinHostPort(dataHost, strconv.Itoa(dataPort))
	dataConn, err := net.DialTimeout("tcp", dataAddr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("连接 FTP 数据端口失败: %w", err)
	}

	if err := c.ctrl.sendCommand("STOR " + remotePath); err != nil {
		dataConn.Close()
		return err
	}

	// Read the preliminary response (150)
	code, msg, err := c.ctrl.readResponse()
	if err != nil {
		dataConn.Close()
		return err
	}
	if code != 125 && code != 150 {
		dataConn.Close()
		return fmt.Errorf("STOR 命令失败: %d %s", code, msg)
	}

	// Write file data
	dataConn.SetWriteDeadline(time.Now().Add(ftpIOTimeout))
	if _, err := dataConn.Write(data); err != nil {
		dataConn.Close()
		return fmt.Errorf("上传数据失败: %w", err)
	}

	// 必须先关闭数据连接，服务器才会发送 226 响应
	dataConn.Close()

	// Read the transfer-complete response (226)
	code, msg, err = c.ctrl.readResponse()
	if err != nil {
		return err
	}
	if code != 226 && code != 250 {
		return fmt.Errorf("上传完成确认失败: %d %s", code, msg)
	}
	return nil
}

// cwd changes the working directory.
func (c *ftpClient) cwd(dir string) error {
	_, _, err := c.ctrl.cmd("CWD "+dir, 250)
	if err != nil {
		return fmt.Errorf("切换目录 %q 失败: %w", dir, err)
	}
	return nil
}

// quit sends the QUIT command.
func (c *ftpClient) quit() {
	_ = c.ctrl.sendCommand("QUIT")
	c.ctrl.close()
}

// ensureDir attempts to create the remote directory chain.
func (c *ftpClient) ensureDir(path string) error {
	dirs := strings.Split(strings.Trim(path, "/"), "/")
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		// Try CWD first; if it fails, try MKD then CWD
		if err := c.ctrl.sendCommand("CWD " + dir); err != nil {
			return err
		}
		code, _, _ := c.ctrl.readResponse()
		if code == 550 {
			// Directory doesn't exist, create it
			if err := c.ctrl.sendCommand("MKD " + dir); err != nil {
				return err
			}
			code, msg, err := c.ctrl.readResponse()
			if err != nil {
				return err
			}
			if code != 257 {
				return fmt.Errorf("创建目录 %q 失败: %d %s", dir, code, msg)
			}
			// Now CWD into it
			if _, _, err := c.ctrl.cmd("CWD "+dir, 250); err != nil {
				return err
			}
		} else if code == 250 {
			// Already exists and switched - that's fine
		} else {
			return fmt.Errorf("切换目录 %q 失败: 响应码 %d", dir, code)
		}
	}
	return nil
}

// Upload is the main action handler for FTP certificate upload.
func Upload(cfg map[string]any) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// --- Required: certificate data ---
	certPEM, ok := cfg["cert"].(string)
	if !ok || certPEM == "" {
		return nil, fmt.Errorf("cert is required and must be a non-empty string")
	}
	keyPEM, ok := cfg["key"].(string)
	if !ok || keyPEM == "" {
		return nil, fmt.Errorf("key is required and must be a non-empty string")
	}

	// --- Required: FTP connection params ---
	host, ok := cfg["host"].(string)
	if !ok || host == "" {
		return nil, fmt.Errorf("host is required and must be a non-empty string")
	}
	username, ok := cfg["username"].(string)
	if !ok || username == "" {
		return nil, fmt.Errorf("username is required and must be a non-empty string")
	}
	password, ok := cfg["password"].(string)
	if !ok || password == "" {
		return nil, fmt.Errorf("password is required and must be a non-empty string")
	}
	remotePath, ok := cfg["remote_path"].(string)
	if !ok || remotePath == "" {
		return nil, fmt.Errorf("remote_path is required and must be a non-empty string")
	}

	// --- Optional: port, default 21 ---
	port := 21
	if rawPort, exists := cfg["port"]; exists {
		switch v := rawPort.(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		case string:
			p, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("port 参数格式错误: %v", v)
			}
			port = p
		}
	}

	// --- Optional: TLS ---
	useTLS := false
	if rawTLS, exists := cfg["use_tls"]; exists {
		switch v := rawTLS.(type) {
		case bool:
			useTLS = v
		case string:
			useTLS = strings.EqualFold(v, "true") || v == "1"
		}
	}

	// --- Optional: filenames ---
	certFilename := "fullchain.pem"
	if v, ok := cfg["cert_filename"].(string); ok && v != "" {
		certFilename = v
	}
	keyFilename := "privkey.pem"
	if v, ok := cfg["key_filename"].(string); ok && v != "" {
		keyFilename = v
	}

	// --- Connect to FTP server ---
	client, err := connectFTP(host, port, useTLS)
	if err != nil {
		return nil, err
	}
	defer client.quit()

	// --- Login ---
	if err := client.login(username, password); err != nil {
		return nil, err
	}

	// --- Set binary mode ---
	if err := client.setBinary(); err != nil {
		return nil, err
	}

	// --- Navigate to / ensure remote directory ---
	if err := client.ensureDir("/"); err != nil {
		return nil, fmt.Errorf("无法进入根目录: %w", err)
	}
	if err := client.ensureDir(remotePath); err != nil {
		return nil, fmt.Errorf("无法进入远程目录 %q: %w", remotePath, err)
	}

	// --- Upload cert file ---
	if err := client.store(certFilename, []byte(certPEM)); err != nil {
		return nil, fmt.Errorf("上传证书文件 %q 失败: %w", certFilename, err)
	}

	// --- Upload key file ---
	if err := client.store(keyFilename, []byte(keyPEM)); err != nil {
		return nil, fmt.Errorf("上传私钥文件 %q 失败: %w", keyFilename, err)
	}

	return &Response{
		Status:  "success",
		Message: "证书上传成功",
		Result: map[string]interface{}{
			"host":          host,
			"remote_path":   remotePath,
			"cert_filename": certFilename,
			"key_filename":  keyFilename,
		},
	}, nil
}
