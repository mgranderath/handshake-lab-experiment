package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

type bufferedWriteCloser struct {
	*bufio.Writer
	io.Closer
}

// NewBufferedWriteCloser creates an io.WriteCloser from a bufio.Writer and an io.Closer
func NewBufferedWriteCloser(writer *bufio.Writer, closer io.Closer) io.WriteCloser {
	return &bufferedWriteCloser{
		Writer: writer,
		Closer: closer,
	}
}

func (h bufferedWriteCloser) Close() error {
	if err := h.Writer.Flush(); err != nil {
		return err
	}
	return h.Closer.Close()
}

const addr = "0.0.0.0:784"
const targetAddr = "173.212.205.233:784"

var clientFlag = flag.Bool("client", false, "")
var tcpFlag = flag.Bool("tcp", false, "")
var tlsFlag = flag.Bool("tls", false, "")

var quicLog *os.File
var tlsLog *os.File
var tcpLog *os.File

func main() {
	flag.Parse()

	if *tcpFlag {
		if *clientFlag {
			log.Println("Running client")
			for i := 0; i < 10000; i++ {
				clientMainTCP()
				time.Sleep(20 * time.Millisecond)
			}
		} else {
			log.Println("Running server")
			log.Fatal(echoServerTCP())
		}
	} else if *tlsFlag {
		if *clientFlag {
			log.Println("Running client")
			for i := 0; i < 10000; i++ {
				clientMainTLS()
				time.Sleep(20 * time.Millisecond)
			}
		} else {
			log.Println("Running server")
			log.Fatal(echoServerTLS())
		}
	} else {
		if *clientFlag {
			log.Println("Running client")
			for i := 0; i < 10000; i++ {
				clientMain()
				time.Sleep(20 * time.Millisecond)
			}
		} else {
			log.Println("Running server")
			log.Fatal(echoServer())
		}
	}

	if tcpLog != nil {
		tcpLog.Close()
	}
	if tlsLog != nil {
		tlsLog.Close()
	}
	if quicLog != nil {
		quicLog.Close()
	}
}

func echoServerTCP() error {
	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go func() {
			time.Sleep(time.Second * 3)
			conn.Close()
		}()
	}
}

func echoServerTLS() error {
	listener, err := tls.Listen("tcp", addr, generateTLSConfig())
	if err != nil {
		return err
	}

	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Println(err)
			return
		}
		println(msg)
	}
}

func clientMainTLS() error {
	if tlsLog == nil {
		f, err := os.OpenFile("tls_durations.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		tlsLog = f
	}

	start := time.Now()
	session, err := tls.Dial("tcp", targetAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	taken := time.Since(start)
	tlsLog.WriteString(strconv.FormatInt(taken.Nanoseconds(), 10) + "\n")

	defer session.Close()

	return nil
}

func clientMainTCP() error {
	if tcpLog == nil {
		f, err := os.OpenFile("tcp_durations.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		tcpLog = f
	}

	start := time.Now()
	session, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return err
	}
	taken := time.Since(start)

	_, err = tcpLog.WriteString(strconv.FormatInt(taken.Nanoseconds(), 10) + "\n")
	if err != nil {
		log.Println(err)
	}

	session.Close()

	return nil
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), &quic.Config{
		AcceptToken: func(clientAddr net.Addr, token *quic.Token) bool {
			return true
		},
	})
	if err != nil {
		return err
	}

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}

		_, err = session.AcceptStream(context.Background())

		if err != nil {
			_ = session.CloseWithError(0, "")
		}
	}
}

func clientMain() error {
	if quicLog == nil {
		f, err := os.OpenFile("quic_durations.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		quicLog = f
	}

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-test"},
	}
	start := time.Now()
	session, err := quic.DialAddr(targetAddr, tlsConf, &quic.Config{
		//Tracer: qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
		//	filename := fmt.Sprintf("results/%x.qlog", connID)
		//	f, err := os.Create(filename)
		//	if err != nil {
		//		log.Fatal(err)
		//	}
		//	log.Printf("Creating qlog file %s.\n", filename)
		//	return NewBufferedWriteCloser(bufio.NewWriter(f), f)
		//}),
	})
	if err != nil {
		return err
	}
	taken := time.Since(start)
	quicLog.WriteString(strconv.FormatInt(taken.Nanoseconds(), 10) + "\n")

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}

	time.Sleep(time.Millisecond * 50)

	defer stream.Close()

	defer session.CloseWithError(0, "")

	return nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-test"},
		InsecureSkipVerify: true,
	}
}
