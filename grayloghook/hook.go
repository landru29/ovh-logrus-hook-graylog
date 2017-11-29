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

func enrich(fields logrus.Fields, hook *GraylogHook) logrus.Fields {
	result := make(logrus.Fields)
	for index, data := range fields {
		result[index] = data
	}
	result["X-OVH-TOKEN"] = hook.token
	result["host"] = hook.host
	result["version"] = "1.1"
	return result
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

	logData := enrich(entry.Data, hook)
	logData["level"] = entry.Level
	logData["msg"] = msg
	logData["timestamp"] = entry.Time.Unix()

	if len(title) > 0 {
		logData["title"] = title
	}

	messageBytes, err = json.Marshal(logData)
	if err != nil {
		return err
	}

	messageBytes = append(messageBytes, byte(0))

	for i := 0; i < retries; i++ {
		if err = hook.connect(); err != nil {
			continue
		}

		_, err = io.Copy(hook.conn, bytes.NewBuffer(messageBytes))
		if err == nil {
			return nil
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
