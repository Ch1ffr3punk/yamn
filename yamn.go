// vim: tabstop=2 shiftwidth=2

package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/luksen/maildir"
	"io/ioutil"
	"os"
)

const (
	version        string = "0.2b"
	dayLength      int    = 24 * 60 * 60 // Day in seconds
	maxFragLength         = 17910
	maxCopies             = 5
	base64LineWrap        = 64
	rfc5322date           = "Mon, 2 Jan 2006 15:04:05 -0700"
	shortdate             = "2 Jan 2006"
)

var (
	log     = logrus.New()
	Pubring *keymgr.Pubring
	IdDb    *idlog.IDLog
	ChunkDb *Chunk
)

func logInit() {
	if cfg.Remailer.Loglevel == "trace" {
		cfg.Remailer.Loglevel = "debug"
	}
	level, err := logrus.ParseLevel(cfg.Remailer.Loglevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	log.Level = level
	customFormatter := new(logrus.TextFormatter)
	customFormatter.FullTimestamp = true
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.Formatter = customFormatter
	if cfg.Remailer.Logfile == "" {
		log.Out = os.Stdout
	} else {
		logfile, err := os.OpenFile(
			cfg.Remailer.Logfile,
			os.O_WRONLY|os.O_CREATE,
			0640,
		)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		log.Out = logfile
	}
}

func main() {
	var err error
	flags()
	logInit()
	if flag_client {
		mixprep()
	} else if flag_stdin {
		dir := maildir.Dir(cfg.Files.Maildir)
		newmsg, err := dir.NewDelivery()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		stdin, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		newmsg.Write(stdin)
		newmsg.Close()
	} else if flag_remailer {
		err = loopServer()
		if err != nil {
			panic(err)
		}
	} else if flag_dummy {
		injectDummy()
	}
	if flag_send {
		// Flush the outbound pool
		poolOutboundSend()
	}
}
