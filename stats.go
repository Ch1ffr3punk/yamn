package main

import (
	"github.com/Sirupsen/logrus"
)

type statistics struct {
	inDummy    int
	inMail     int
	inRemFoo   int
	inYamn     int
	outDummy   int
	outMail    int
	outYamn    int
	outLoop    int
	outRandhop int
	outPlain   int
}

func (s *statistics) reset() {
	s.inDummy = 0
	s.inMail = 0
	s.inYamn = 0
	s.inRemFoo = 0
	s.outDummy = 0
	s.outMail = 0
	s.outYamn = 0
	s.outLoop = 0
	s.outRandhop = 0
	s.outPlain = 0
	log.Info("Daily stats reset")
}

func (s *statistics) report() {
	log.WithFields(logrus.Fields{
		"MailIn":  s.inMail,
		"RemFoo":  s.inRemFoo,
		"YamnIn":  s.inYamn,
		"DummyIn": s.inDummy,
	}).Info("Inbound stats")
	log.WithFields(logrus.Fields{
		"MailOut":  s.outMail,
		"YamnOut":  s.outYamn,
		"YamnLoop": s.outLoop,
		"RandHop":  s.outRandhop,
		"TextOut":  s.outPlain,
		"DummyOut": s.outDummy,
	}).Info("Outbound stats")
}

var stats = new(statistics)
