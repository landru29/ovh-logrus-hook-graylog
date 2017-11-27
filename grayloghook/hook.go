package grayloghook

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"time"

	"github.com/sirupsen/logrus"
)

const retries = 5

// GraylogMessage is a message for graylog
type GraylogMessage struct {
	Version string       `json:"version"`
	Full    string       `json:"full_message"`
	Message string       `json:"message"`
	Token   string       `json:"X-OVH-TOKEN"`
	Host    string       `json:"host"`
	Title   string       `json:"title"`
	Level   logrus.Level `json:"level"`
	Time    int64        `json:"timestamp"`
}

// GraylogHook is a writer for graylog
type GraylogHook struct {
	conn   io.WriteCloser
	addr   string
	token  string
	host   string
	tlsCfg *tls.Config
	Level  logrus.Level
}

func (hook *GraylogHook) connect() error {
	if hook.conn != nil {
		return nil
	}
	var err error

	for i := 0; i < retries; i++ {
		hook.conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", hook.addr, hook.tlsCfg)
		if err == nil {
			return nil
		}
		time.Sleep(time.Duration(200) * time.Millisecond)
	}
	return err
}

// NewGraylogHook creates a Writer
func NewGraylogHook(addr string, token string, host string, tlsCfg *tls.Config) *GraylogHook {
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	return &GraylogHook{
		token:  token,
		host:   host,
		addr:   addr,
		tlsCfg: tlsCfg,
		Level:  logrus.DebugLevel,
	}
}

//Fire is invoked each time a log is thrown
func (hook *GraylogHook) Fire(entry *logrus.Entry) error {
	var err error
	title := ""
	messageBytes := []byte{}

	// extract title
	regexTitle := regexp.MustCompile(`\[(.*?)\]`)
	matches := regexTitle.FindStringSubmatch(entry.Message)
	if len(matches) > 1 {
		title = matches[1]
	}

	// clean title
	regexMessage := regexp.MustCompile(`\[.*?\]`)
	msg := regexMessage.ReplaceAllString(entry.Message, "")

	messageBytes, err = json.Marshal(GraylogMessage{
		Version: "1.1",
		Full:    entry.Message,
		Message: msg,
		Token:   hook.token,
		Host:    hook.host,
		Title:   title,
		Level:   entry.Level,
		Time:    entry.Time.Unix(),
	})
	if err != nil {
		return err
	}

	messageBytes = append(messageBytes, byte(0))

	if err := hook.connect(); err != nil {
		return err
	}

	for i := 0; i < retries; i++ {
		_, err = io.Copy(hook.conn, bytes.NewBuffer(messageBytes))
		if err == nil {
			return nil
		}
		if err = hook.connect(); err != nil {
			return err
		}
	}

	if err != nil {
		fmt.Printf("[graylog] Error while sending message: %s\n", err.Error())
	}

	return err
}

// Levels returns the available logging levels.
func (hook *GraylogHook) Levels() []logrus.Level {
	levels := []logrus.Level{}
	for _, level := range logrus.AllLevels {
		if level <= hook.Level {
			levels = append(levels, level)
		}
	}
	return levels
}
