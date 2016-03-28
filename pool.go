// vim: tabstop=2 shiftwidth=2

package main

import (
	"encoding/hex"
	"errors"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"net/mail"
	"os"
	"path"
	"strings"
	"time"
	//"github.com/codahale/blake2"
	"github.com/crooks/yamn/keymgr"
	"github.com/luksen/maildir"
)

// serverPoolOutboundSend is intended to be run concurrently with the server
// daemon.  It sends messages from the pool at timed intervals.
func serverPoolOutboundSend() {
	if cfg.Pool.Loop < 120 {
		log.WithFields(logrus.Fields{
			"Loop": cfg.Pool.Loop,
		}).Warn("Configured Pool loop is too short. " +
			"Adjusting to minimum of 120 Seconds.")
		cfg.Pool.Loop = 120
	}
	sleepFor := time.Duration(cfg.Pool.Loop) * time.Second
	for {
		// Read dynamic mix of outbound files from the Pool
		// filenames = dynamicMix()
		// Read binomialMix of outbound files from the Pool
		filenames := binomialMix()
		for _, filename := range filenames {
			emailPoolFile(filename)
		}
		time.Sleep(sleepFor)
	}
}

// poolOutboundSend flushes the outbound pool.  This should only be performed
// on clients, where all messages should be sent instantly after creation.
func poolOutboundSend() {
	var err error
	if cfg.Remailer.Daemon || flag_daemon {
		// This should never happen.  If the server is started as a
		// daemon, the serverPoolOutboundSend process is initiated and
		// runs in an endless loop.  This function would conflict with
		// it.
		err = errors.New("Cannot flush pool when running as a Daemon")
		panic(err)
	}
	var filenames []string
	// Read all the pool files
	filenames, err = readDir(cfg.Files.Pooldir, "m")
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   cfg.Files.Pooldir,
			"Error": err,
		}).Error("Reading pool failed.")
		return
	}
	if flag_remailer {
		// During normal operation, the pool shouldn't be flushed.
		log.Warn("Flushing outbound remailer pool")
	}
	for _, filename := range filenames {
		emailPoolFile(filename)
	}
}

// emailPoolFile tries to email a given file from the Pool.  If conditions are
// met, the file is then deleted.
func emailPoolFile(filename string) {
	delFlag, err := mailPoolFile(path.Join(cfg.Files.Pooldir, filename))
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":      cfg.Files.Pooldir,
			"Filename": filename,
			"Error":    err,
		}).Warn("Pool mailing failed.")
		if delFlag {
			// If delFlag is true, we delete the file, even though
			// mailing failed.
			log.WithFields(logrus.Fields{
				"Filename": filename,
			}).Debug("Deleting pool file")
			poolDelete(filename)
		}
	} else {
		stats.outMail++
		poolDelete(filename)
	}
}

// dynamicMix returns a dynamic Mix of filenames from the outbound pool.
func dynamicMix() []string {
	var empty []string
	poolFiles, err := readDir(cfg.Files.Pooldir, "m")
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   cfg.Files.Pooldir,
			"Error": err,
		}).Warn("Failed to obtain list of Pool files.")
		return empty
	}
	poolSize := len(poolFiles)
	if poolSize < cfg.Pool.Size || poolSize == 0 {
		// Pool isn't sufficiently populated
		log.WithFields(logrus.Fields{
			"Trigger":    cfg.Pool.Size,
			"Population": poolSize,
		}).Debug("Dynamic Pool insufficiently populated to trigger sending.")
		return empty
	}
	// Shuffle the slice of filenames now as we're going to return a
	// setset of the overall pool.
	shuffle(poolFiles)
	// Normal pool processing condition
	numToSend := int((float32(poolSize) / 100.0) * float32(cfg.Pool.Rate))
	log.WithFields(logrus.Fields{
		"Trigger":  cfg.Pool.Size,
		"Messages": poolSize,
		"Sending":  numToSend,
	}).Debug("Processing outbound pool.")
	return poolFiles[:numToSend]
}

// getBatchSize takes a Pool size and returns a corresponding batch size.  This
// is intended for use with Binomial Mix Pools.
func getBatchSize(poolSize int) int {
	/*
		poolSize         -  Number of files in the pool
		cfg.Pool.Size    -  Minimum messages to keep in pool
		cfg.Pool.MinSend -  Minimum number of messages to consider sending
		cfg.Pool.Rate    -  Percentage of Pool in the batch
	*/
	if poolSize < (cfg.Pool.Size + cfg.Pool.MinSend) {
		return 0
	}
	sendable := poolSize - cfg.Pool.Size
	rate := float32(cfg.Pool.Rate) / 100
	maxSend := max(1, int(float32(poolSize)*rate))
	return min(sendable, maxSend)
}

// binomialMix returns a batched subset of Pool files to send using a
// Probability B/P method of selecting each file.
func binomialMix() (batch []string) {
	poolFiles, err := readDir(cfg.Files.Pooldir, "m")
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   cfg.Files.Pooldir,
			"Error": err,
		}).Warn("Failed to obtain list of Pool files.")
		return
	}
	poolSize := len(poolFiles)
	batchSize := getBatchSize(poolSize)
	if batchSize == 0 {
		log.WithFields(logrus.Fields{
			"Trigger":    cfg.Pool.Size,
			"MinSend":    cfg.Pool.MinSend,
			"Population": poolSize,
		}).Debug("Binomial Pool insufficiently populated.")
		// If the batch is empty, don't bother to process it.
		return
	}
	// Shuffle the slice of filenames now as we're only going to consider a
	// subset in the following loop.
	shuffle(poolFiles)
	// Multiply probability by 255 as dice() returns 0-255.
	prob := int((float32(batchSize) / float32(poolSize)) * 255)
	// Test each pool filename against a biased coin-toss
	for _, s := range poolFiles[:batchSize] {
		if prob >= dice() {
			batch = append(batch, s)
		}
	}
	log.WithFields(logrus.Fields{
		"Population":  poolSize,
		"Batch":       batchSize,
		"Probability": prob,
		"Sending":     len(batch),
	}).Info("Processing Binomial Mix Pool.")
	return
}

// Delete a given file from the pool
func poolDelete(filename string) {
	// Delete a pool file
	err := os.Remove(path.Join(cfg.Files.Pooldir, filename))
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":      cfg.Files.Pooldir,
			"Filename": filename,
			"Error":    err,
		}).Error("Pool file deletion failed.")
	} else {
		log.WithFields(logrus.Fields{
			"Filename": filename,
		}).Debug("Deleted Pool file.")
	}
}

// processMail reads the Remailer's Maildir and processes the content
func processMail(secret *keymgr.Secring) (err error) {
	dir := maildir.Dir(cfg.Files.Maildir)
	// Get a list of Maildir keys from the directory
	keys, err := dir.Unseen()
	if err != nil {
		return
	}
	newMsgs := len(keys)
	if newMsgs == 0 {
		// Nothing to do, move along!
		return
	}
	log.WithFields(logrus.Fields{
		"Dir":      cfg.Files.Maildir,
		"Messages": newMsgs,
	}).Debug("Reading Maildir.")
	// Increment inbound Email counter
	stats.inMail += newMsgs
	// Fetch headers for each Maildir key
	var head mail.Header
	for _, key := range keys {
		head, err = dir.Header(key)
		if err != nil {
			log.WithFields(logrus.Fields{
				"Key":   key,
				"Error": err,
			}).Warn("Reading SMTP headers failed.")
			continue
		}
		// The Subject determines if the message needs remailer-foo handling
		subject := strings.TrimSpace(strings.ToLower(head.Get("Subject")))
		if strings.HasPrefix(subject, "remailer-") {
			// It's a remailer-foo request
			err = remailerFoo(subject, head.Get("From"))
			if err == nil {
				// Increments stats counter
				stats.inRemFoo++
			} else {
				log.Info(err)
			}
			err = dir.Purge(key)
			if err != nil {
				log.WithFields(logrus.Fields{
					"Key":     key,
					"Subject": subject,
					"Error":   err,
				}).Warn("Cannot delete Remailer-Foo message.")
			}
			// Nothing else to do, move on to the next message
			continue
		}
		// It's not a remailer-foo request so assume a remailer message
		var mailMsg *mail.Message
		mailMsg, err := dir.Message(key)
		if err != nil {
			log.WithFields(logrus.Fields{
				"Key":   key,
				"Error": err,
			}).Warn("Reading Maildir message failed.")
			continue
		}
		var msg []byte
		// Convert the armored Yamn message to its byte components
		msg, err = stripArmor(mailMsg.Body)
		if err != nil {
			log.Println(err)
			continue
		}
		if msg == nil {
			log.Warn("Dearmor returned zero bytes")
			continue
		}
		err = decodeMsg(msg, secret)
		if err != nil {
			log.Info(err)
		}
		err = dir.Purge(key)
		if err != nil {
			log.WithFields(logrus.Fields{
				"Key":   key,
				"Error": err,
			}).Warn("Cannot delete Yamn mail message.")
		}
	} // Maildir keys loop
	return
}

// processInpool is similar to processMail but reads the Inbound Pool
func processInpool(prefix string, secret *keymgr.Secring) {
	poolFiles, err := readDir(cfg.Files.Pooldir, prefix)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":    cfg.Files.Pooldir,
			"Prefix": prefix,
			"Error":  err,
		}).Warn("Unable to access inbound Pool.")
		return
	}
	poolSize := len(poolFiles)
	processed := 0
	for _, f := range poolFiles {
		filename := path.Join(cfg.Files.Pooldir, f)
		msg := make([]byte, messageBytes)
		msg, err = ioutil.ReadFile(filename)
		if err != nil {
			log.WithFields(logrus.Fields{
				"Dir":      cfg.Files.Pooldir,
				"Filename": f,
				"Error":    err,
			}).Warn("Failed to read file from Pool.")
			continue
		}
		err = decodeMsg(msg, secret)
		if err != nil {
			log.Warn(err)
		}
		poolDelete(f)
		processed++
	}
	if poolSize > 0 {
		log.WithFields(logrus.Fields{
			"Population": poolSize,
			"Decoded":    processed,
		}).Debug("Inbound Pool processing complete.")
	}
}

// randPoolFilename returns a random filename with a given prefix.  This should
// be used in all instances where a new pool file is required.
func randPoolFilename(prefix string) (fqfn string) {
	for {
		outfileName := prefix + hex.EncodeToString(randbytes(7))
		fqfn = path.Join(cfg.Files.Pooldir, outfileName)
		_, err := os.Stat(fqfn)
		if err != nil {
			// For once we want an error (indicating the file
			// doesn't exist)
			break
		}
	}
	return
}

// newPoolFile opens a new file in Write mode and sets user-only permissions
func newPoolFile(prefix string) (f *os.File, err error) {
	/*
		Currently supported prefixs are:-
		[ m              Oubound message (final or intermediate) ]
		[ i          Inbound message (destined for this remailer ]
		[ p               Partial message chunk needing assembly ]
	*/
	fqfn := randPoolFilename(prefix)
	f, err = os.OpenFile(fqfn, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	return
}

// writeMessageToPool requires a recipient address (another remailer) and a
// payload (that gets Base64 armored).
func writeMessageToPool(sendTo string, payload []byte) {
	f, err := newPoolFile("m")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	// Add mail headers to the pool file
	writeInternalHeader(f)
	writeMailHeaders(f, sendTo)
	// Armor the payload
	armor(f, payload)
}

// writePlainToPool writes a plaintext file to the pool and returns the filename
func writePlainToPool(payload []byte, prefix string) (filename string) {
	f, err := newPoolFile(prefix)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	writeInternalHeader(f)
	f.Write(payload)
	_, filename = path.Split(f.Name())
	return
}
