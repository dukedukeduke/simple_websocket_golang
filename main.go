package main

import (
	"io"
	"log"
	"net"
	"fmt"
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"crypto/sha1"
	"encoding/json"
	"encoding/base64"
	"encoding/binary"
)

type WebSocket struct {
	Listener    net.Listener
	Clients     []*Client
}

type Client struct {
	Conn        net.Conn
	Nickname    string
	Shook       bool
	Server      *WebSocket
	Id          int
}

type Msg struct {
	Data        string
	Num         int
}


func (self *Client) Handle() {
	// 握手
	if !self.Handshake() {
		return
	}
	//读取客户端发送的数据
	self.Read()
}

func (self *Client) Read() {
	var (
		buf     []byte
		err     error
		fin     byte
		opcode  byte
		mask    byte
		mKey    []byte
		length  uint64
		l       uint16
		payload byte
		msg     *Msg
	)
	for {
		// 首先取出两个字节数据
		buf = make([]byte, 2)
		_, err = io.ReadFull(self.Conn, buf)
		if err != nil {
			self.Close()
			break
		}
		// 取得Fin， 判定是否是最后一帧，这里没有实际意义
		fin = buf[0] >> 7
		if fin == 0 {

		}
		// 按位与取得高四位， 判定是否是连接关闭的命令
		opcode = buf[0] & 0xf
		if opcode == 8 {
			log.Print("Connection closed")
			self.Close()
			break
		}
		// 取得MASK位，判定是否经过掩码处理
		mask = buf[1] >> 7
		// 按位与获得高七位的的值
		payload = buf[1] & 0x7f

		switch {
		case payload < 126:
			// 如果小于126， 则表示当前七位数值即为payload真实长度
			length = uint64(payload)

		case payload == 126:
			// 如果等于126， 则表示接下来后面两字节是16位无符号整型数，即为payload的长度
			buf = make([]byte, 2)
			io.ReadFull(self.Conn, buf)
			binary.Read(bytes.NewReader(buf), binary.BigEndian, &l)
			length = uint64(l)

		case payload == 127:
			// 如果等于127， 则表示接下来后面八字节是64位无符号整型数，即为payload的长度
			buf = make([]byte, 8)
			io.ReadFull(self.Conn, buf)
			binary.Read(bytes.NewReader(buf), binary.BigEndian, &length)
		}
		if mask == 1 {
			// 如果经过了掩码处理，Masking-key域的数据即是掩码密钥，
			// 用于解码PayloadData
			mKey = make([]byte, 4)
			io.ReadFull(self.Conn, mKey)
		}
		fmt.Printf("fin: %d, opcode: %d, mask: %d, length: %d\n", fin, opcode, mask, length)
		buf = make([]byte, length)
		io.ReadFull(self.Conn, buf)
		if mask == 1 {
			// 掩码处理还原
			for i, v := range buf {
				buf[i] = v ^ mKey[i % 4]
			}
		}
		// 根据Nickname 来判定是否是新加入
		if self.Nickname == "" {
			self.Nickname = string(buf)
			msg = &Msg{
				self.Nickname + "，加入",
				len(self.Server.Clients),
			}
		} else {
			msg = &Msg{
				string(buf),
				len(self.Server.Clients),
			}
		}
		buf, err = json.Marshal(msg)
		if err != nil {
			log.Fatal(err)
		}
		// 将收到的message发送给所有的客户端
		self.WriteAll(buf)
	}
	self.Conn.Close()
}

func (self *Client) WriteAll(data []byte) {
	for _, client := range self.Server.Clients {
		client.Write(data)
	}
}

func (self *Client) Close() {
	for i, client := range self.Server.Clients {
		if self == client {
			msg := &Msg{
				self.Nickname + "，离开",
				len(self.Server.Clients) - 1,
			}
			buf, err := json.Marshal(msg)
			if err != nil {
				log.Fatal(err)
			}
			// 从client列表剔除close的客户端连接
			self.Server.Clients = append(self.Server.Clients[:i], self.Server.Clients[i+1:]...)
			self.WriteAll(buf)
			break
		}
	}
}

func (self *Client) Write(data []byte) bool {
	length := len(data)
	// 根据websocket协议构造数据
	frame := []byte{129}
	switch {
	case length < 126:
		frame = append(frame, byte(length))
	case length <= 0xffff:
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(length))
		frame = append(frame, byte(126))
		frame = append(frame, buf...)
	case uint64(length) <= 0xffffffffffffffff:
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(length))
		frame = append(frame, byte(127))
		frame = append(frame, buf...)
	default:
		log.Fatal("Data too large")
		return false
	}
	frame = append(frame, data...)
	// 发送数据
	self.Conn.Write(frame)
	return true
}

func (self *Client) Handshake() bool {
	if self.Shook {
		return true
	}
	reader := bufio.NewReader(self.Conn)
	key := ""
	str := ""
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			log.Fatal(err)
			return false
		}
		if len(line) == 0 {
			break
		}
		str = string(line)
		if strings.HasPrefix(str, "Sec-WebSocket-Key") {
			key = str[19:43]
		}
	}
	sha := sha1.New()
	// 构造握手响应头信息
	io.WriteString(sha, key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	key = base64.StdEncoding.EncodeToString(sha.Sum(nil))

	header := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Accept: " + key + "\r\n" +
		"Upgrade: websocket\r\n\r\n"
	self.Conn.Write([]byte(header))
	self.Shook = true
	self.Server.Clients = append(self.Server.Clients, self)
	return true
}

// 定义websocket连接和客户端列表
func NewWebSocket(addr string) *WebSocket {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	return &WebSocket{l, make([]*Client, 0)}
}


func (self *WebSocket) Loop() {
	for {
		// 等待客户端发起连接
		conn, err := self.Listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		s := conn.RemoteAddr().String()
		// 客户端连接ip作为id
		i, _ := strconv.Atoi(strings.Split(s, ":")[1])
		//初始化连接的客户端信息
		client := &Client{conn, "", false, self, i}
		//开启协程处理客户端连接， 一个客户端一个协程
		go client.Handle()
	}
}

func main() {
	ch := make(chan int)
	fmt.Println("123")
	go func() {
		fmt.Println("消费",<-ch)
		ch <- 2
	}()
	ch <- 1
	fmt.Println("1234")
	fmt.Println(<-ch)
}
