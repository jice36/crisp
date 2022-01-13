package crisp

import (
	"crisp/main/magma"
	"crisp/main/randomNumber"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"time"
)

const (
	count = 100
)

var masterKey = []byte{0xc, 0xf, 0xd, 0x13, 0x2, 0xa, 0xf, 0xc, 0x4, 0x1, 0xe, 0xf, 0x9, 0x1, 0x11, 0x33, 0x15, 0xd, 0x4, 0xd,
	0x9, 0x1, 0x12, 0x15, 0xa, 0xb, 0x0, 0x13, 0xc, 0xf, 0x7, 0x2}

var text = "In the evening, I often watch TV with my family and discuss my plans for the next day. On weekends, I often meet my friends or stay at home and read books. I like novels by Dariya Dontsova."

type crispMessage struct {
	KeyIdFlag bool   `json:"keyIdFlag"`
	Version   byte   `json:"version"`
	Cs        byte   `json:"cs"`
	KeyId     byte   `json:"keyId"`
	SeqNum    byte   `json:"seqNum"`
	Payload   []byte `json:"payload"`
	Icv       []byte `json:"icv"`
}

type Server struct {
	ip   string
	port string
}

func (s *Server) Server() {
	listener, _ := net.Listen("tcp", "localhost:8080")
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		errC := make(chan error)

		go handleClient(conn, errC)

		if err = <-errC ; err != nil {
			fmt.Println(err.Error())
		}
	}
}

func handleClient(conn net.Conn, errC chan error) {
	data := make([]byte, 8)
	var counter byte
	defer conn.Close()
	testData := make([]byte, len(text)+1)
	copy(testData, text)
	r := randomNumber.ISAAC{}

	iv := r.GenSeq()
	key := masterKey
	s, err := magma.GenSubKeys(masterKey)
	if err != nil {
		errC <- err
	}
	for {
		if err = keepAlive(conn); err == io.EOF {
			errC <- errors.New("---------close socket-----------")
			runtime.Goexit()
		}

		if len(testData) < int(counter)*8+len(testData)%8 {
			conn.Write([]byte("STOP"))
			errC <- errors.New("---------final-----------")
			runtime.Goexit()
		}

		if counter == 255{
			counter = 0
		}

		time.Sleep(1 * time.Second)
		var enc []byte
		data = copyData(testData, int(counter))
		fmt.Println(string(data))
		if count == counter {
			key, err := magma.ChangeOldKeyToNewKey(key)
			if err != nil {
				errC <- err
			}
			s, err = magma.GenSubKeys(key)
			if err != nil {
				errC <- err
			}
		}

		s, enc, err = magma.RoundCipher(s, data, iv, uint32(counter))
		if err != nil {
			errC <- err
		}

		m := &crispMessage{
			KeyIdFlag: false,
			Version:   0,
			Cs:        0xf4,
			KeyId:     64,
			SeqNum:    counter,
			Payload:   enc,
			Icv:       iv,
		}
		mes, err := json.Marshal(&m)
		if err != nil {
			errC <- err
		}
		mes = append(mes, byte('\n'))
		conn.Write(mes)
		counter++
	}
}

func keepAlive(conn net.Conn) error {
	b := make([]byte, 1)
	_, err := conn.Read(b)
	if err != nil {
		return err
	}
	return nil
}

func copyData(src []byte, pos int) []byte {
	dst := make([]byte, 8)
	if (pos+1)*8 <= len(src) {
		dst = src[pos*8 : (pos+1)*8]
	} else {
		j := 0
		for i := pos * 8; i < pos*8+len(src)%8; i++ {
			dst[j] = src[i]
			j++
		}
	}
	return dst
}
