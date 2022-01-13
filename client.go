package crisp

import (
	"bufio"
	"crisp/main/magma"
	"encoding/json"
	"fmt"
	"net"
)

type Client struct {
	ip   string
	port string
}

func (c *Client) Client() {
	conn, _ := net.Dial("tcp", "localhost:8080")

	err := handleFunc(conn, masterKey)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func handleFunc(conn net.Conn, key []byte) error {
	s, _ := magma.GenSubKeys(masterKey)
	var mes = &crispMessage{}
	rc := make([]byte, 8)
	for {
		conn.Write([]byte{1})
		msg, err := bufio.NewReader(conn).ReadBytes('\n')

		if string(msg) == "STOP" {
			fmt.Println("---------final-----------")
			conn.Close()
			break
			return nil
		}
		err = json.Unmarshal(msg, mes)
		if err != nil {
			fmt.Println(err)
		}

		iv := mes.Icv
		if count == mes.SeqNum {
			key, err = magma.ChangeOldKeyToNewKey(key)
			if err != nil {
				fmt.Println(err)
			}
			s, err = magma.GenSubKeys(key)
			if err != nil {
				fmt.Println(err)
			}
		}
		s, rc, err = magma.RoundCipher(s, mes.Payload, iv, uint32(mes.SeqNum))
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(rc))
	}
	return nil
}
