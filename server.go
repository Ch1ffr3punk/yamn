// vim: tabstop=2 shiftwidth=2

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/crooks/yamn/idlog"
	"github.com/crooks/yamn/keymgr"
	"github.com/crooks/yamn/quickmail"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"
	//"github.com/codahale/blake2"
)

// Start the server process.  If run with --daemon, this will loop forever.
func loopServer() (err error) {
	// Initialize the Public Keyring
	Pubring = keymgr.NewPubring(
		cfg.Files.Pubring,
		cfg.Files.Mlist2,
	)
	// Fetch keyring and stats URLs
	timedURLFetch(cfg.Urls.Pubring, cfg.Files.Pubring)
	timedURLFetch(cfg.Urls.Mlist2, cfg.Files.Mlist2)
	// Initialize the Secret Keyring
	secret := keymgr.NewSecring(cfg.Files.Secring, cfg.Files.Pubkey)
	Pubring.ImportPubring()
	secret.ImportSecring()
	// Tell the secret keyring some basic info about this remailer
	secret.SetName(cfg.Remailer.Name)
	secret.SetMailto(cfg.Remailer.Address)
	if cfg.Remailer.HttpAddr == "" {
		log.Info(
			"No HTTP address specified. ",
			"Not configuring transport.",
		)
	} else {
		log.WithFields(logrus.Fields{
			"Address": cfg.Remailer.HttpAddr,
			"Port":    cfg.Remailer.HttpPort,
		}).Info("Defining Remailer HTTP address")
		secret.SetHttp(cfg.Remailer.HttpAddr, cfg.Remailer.HttpPort)
	}
	secret.SetExit(cfg.Remailer.Exit)
	secret.SetValidity(cfg.Remailer.Keylife, cfg.Remailer.Keygrace)
	secret.SetVersion(version)
	// Create some dirs if they don't already exist
	createDirs()

	// Open the IDlog
	log.WithFields(logrus.Fields{
		"Filename": cfg.Files.IDlog,
	}).Debug("Opening ID Log")
	// NewInstance takes the filename and entry validity in days
	IdDb = idlog.NewIDLog(cfg.Files.IDlog, cfg.Remailer.IDexp)
	defer IdDb.Close()
	// Open the chunk DB
	log.WithFields(logrus.Fields{
		"Filename": cfg.Files.ChunkDB,
	}).Debug("Opening Chunk Database")
	ChunkDb = OpenChunk(cfg.Files.ChunkDB)
	ChunkDb.SetExpire(cfg.Remailer.ChunkExpire)

	// Expire old entries in the ID Log
	idLogExpire()
	// Clean the chunk DB
	chunkClean()
	// Complain about poor configs
	nagOperator()
	// Run a key purge
	if purgeSecring(secret) == 0 {
		// If there are zero active keys, generate a new one.
		generateKeypair(secret)
	} else {
		/*
			If the operator changes his configuration, (such as
			upgrading to a new version or switching from exit to
			middleman), the published key will not match the
			configuration.  This element of code writes a new
			key.txt file with current settings.  This only needs to
			be done if we haven't generated a new key.
		*/
		refreshPubkey(secret)
	}
	log.WithFields(logrus.Fields{
		"SecKeys": secret.Count(),
	}).Info("Secret Keyring purge completed.")

	// Define triggers for timed events
	daily := time.Now()
	hourly := time.Now()
	dayOfMonth := time.Now().Day()
	oneDay := time.Duration(dayLength) * time.Second

	// Determine if this is a single run or the start of a Daemon
	runAsDaemon := cfg.Remailer.Daemon || flag_daemon

	// Actually start the server loop
	if runAsDaemon {
		log.WithFields(logrus.Fields{
			"Remailer": cfg.Remailer.Name,
			"Address":  cfg.Remailer.Address,
		}).Info("Starting YAMN server.")
		log.Info("Detaching Pool processing.")
		go serverPoolOutboundSend()
	} else {
		log.WithFields(logrus.Fields{
			"Remailer": cfg.Remailer.Name,
			"Address":  cfg.Remailer.Address,
		}).Info("Performing routine remailer functions.")
	}
	for {
		// Panic if the pooldir doesn't exist
		assertIsPath(cfg.Files.Pooldir)
		// Process the inbound Pool
		processInpool("i", secret)
		// Process the Maildir
		processMail(secret)

		// Midnight events
		if time.Now().Day() != dayOfMonth {
			log.Info("Performing midnight events")
			// Remove expired keys from memory and rewrite a
			// secring file without expired keys.
			if purgeSecring(secret) == 0 {
				generateKeypair(secret)
			}
			// Expire entries in the ID Log
			idLogExpire()
			// Expire entries in the chunker
			chunkClean()
			// Report daily throughput and reset to zeros
			stats.report()
			stats.reset()
			// Reset dayOfMonth to today
			dayOfMonth = time.Now().Day()
		}
		// Daily events
		if time.Since(daily) > oneDay {
			log.Info("Performing daily events")
			// Complain about poor configs
			nagOperator()
			// Reset today so we don't do these tasks for the next
			// 24 hours.
			daily = time.Now()
		}
		// Hourly events
		if time.Since(hourly) > time.Hour {
			log.Debug("Performing hourly events")
			/*
				The following two conditions try to import new
				pubring and mlist2 URLs.  If they fail, a
				warning is logged but no further action is
				taken.  It's better to have old keys/stats than
				none.
			*/
			// Retrieve Mlist2 and Pubring URLs
			if cfg.Urls.Fetch {
				timedURLFetch(
					cfg.Urls.Pubring,
					cfg.Files.Pubring,
				)
				timedURLFetch(
					cfg.Urls.Mlist2,
					cfg.Files.Mlist2,
				)
			}
			// Test to see if the pubring.mix file has been updated
			if Pubring.KeyRefresh() {
				log.WithFields(logrus.Fields{
					"PubRing": cfg.Files.Pubring,
				}).Debug("Reimporting Public Keyring.")
				Pubring.ImportPubring()
			}
			// Report throughput
			stats.report()
			hourly = time.Now()
		}

		// Break out of the loop if we're not running as a daemon
		if !runAsDaemon {
			break
		}

		// And rest a while
		time.Sleep(60 * time.Second)
	} // End of server loop
	return
}

// refreshPubkey updates an existing Public key file
func refreshPubkey(secret *keymgr.Secring) {
	tmpKey := cfg.Files.Pubkey + ".tmp"
	keyidstr := secret.WriteMyKey(tmpKey)
	log.WithFields(logrus.Fields{
		"KeyID": keyidstr,
	}).Info("Advertising Public Key.")
	log.WithFields(logrus.Fields{
		"TempPubFile": tmpKey,
	}).Debug("Wrote Public Key to temp file.")
	// Overwrite the published key with the refreshed version
	log.WithFields(logrus.Fields{
		"OldName": tmpKey,
		"NewName": cfg.Files.Pubkey,
	}).Debug("Renaming temporary key file.")
	err := os.Rename(tmpKey, cfg.Files.Pubkey)
	if err != nil {
		log.Warn(err)
	}
}

// purgeSecring deletes old keys and counts active ones.  If no active keys
// are found, it triggers a generation.
func purgeSecring(secret *keymgr.Secring) (active int) {
	active, expiring, expired, purged := secret.Purge()
	log.WithFields(logrus.Fields{
		"Active":   active,
		"Expiring": expiring,
		"Expired":  expired,
		"Purged":   purged,
	}).Info("Secret Key purge completed.")
	return
}

// generateKeypair creates a new keypair and publishes it
func generateKeypair(secret *keymgr.Secring) {
	log.Info("Generating and advertising a new key pair")
	pub, sec := eccGenerate()
	keyidstr := secret.Insert(pub, sec)
	log.WithFields(logrus.Fields{
		"KeyID": keyidstr,
	}).Info("Generated new key pair.")
	log.Debug("Writing new Public Key to disc")
	secret.WritePublic(pub, keyidstr)
	log.Debug("Inserting Secret Key into Secring")
	secret.WriteSecret(keyidstr)
}

// idLogExpire deletes old entries in the ID Log
func idLogExpire() {
	count, deleted := IdDb.Expire()
	log.WithFields(logrus.Fields{
		"Expired":  deleted,
		"Contains": count,
	}).Info("ID Log expiry complete.")
}

// chunkClean expires entries from the chunk DB and deletes any stranded files
func chunkClean() {
	cret, cexp := ChunkDb.Expire()
	if cexp > 0 {
		log.WithFields(logrus.Fields{
			"Expired":  cexp,
			"Contains": cret,
		}).Info("Chunk expiry complete.")
	}
	fret, fdel := ChunkDb.Housekeep()
	if fdel > 0 {
		log.WithFields(logrus.Fields{
			"Deleted":  fdel,
			"Retained": fret,
		}).Info("Stranded chunk deletion complete.")
	}
}

// nagOperator prompts a remailer operator about poor practices.
func nagOperator() {
	// Complain about excessively small loop values.
	if cfg.Pool.Loop < 60 {
		log.WithFields(logrus.Fields{
			"LoopSecs": cfg.Pool.Loop,
		}).Warn("Pool loop time of is excessively low. Will loop " +
			"every 60 seconds. A higher setting is recommended.")
	}
	// Complain about high pool rates.
	if cfg.Pool.Rate > 90 && !flag_send {
		log.WithFields(logrus.Fields{
			"Rate": cfg.Pool.Rate,
		}).Warn("Pool rate is excessively high. Unless " +
			"testing, a lower setting is recommended.")
	}
	// Complain about running a remailer with flag_send
	if flag_send && flag_remailer {
		log.WithFields(logrus.Fields{
			"LoopSecs": cfg.Pool.Loop,
		}).Warn("Your remailer will flush the outbound pool every " +
			"cycle. Unless you're testing, this is probably " +
			"not what you want.")
	}
}

func createDirs() {
	var err error
	err = os.MkdirAll(cfg.Files.IDlog, 0700)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   cfg.Files.IDlog,
			"Error": err,
		}).Fatal("Failed to create ID Log directory.")
	}
	err = os.MkdirAll(cfg.Files.Pooldir, 0700)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   cfg.Files.Pooldir,
			"Error": err,
		}).Fatal("Failed to create Pool directory.")
	}
	err = os.MkdirAll(cfg.Files.ChunkDB, 0700)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   cfg.Files.ChunkDB,
			"Error": err,
		}).Fatal("Failed to create Chunk DB directory.")
	}
	err = os.MkdirAll(cfg.Files.Maildir, 0700)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   cfg.Files.Maildir,
			"Error": err,
		}).Fatal("Failed to create Maildir directory.")
	}
	mdirnew := path.Join(cfg.Files.Maildir, "new")
	err = os.MkdirAll(mdirnew, 0700)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   mdirnew,
			"Error": err,
		}).Fatal("Failed to create Maildir directory.")
	}
	mdircur := path.Join(cfg.Files.Maildir, "cur")
	err = os.MkdirAll(mdircur, 0700)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   mdircur,
			"Error": err,
		}).Fatal("Failed to create Maildir directory.")
	}
	mdirtmp := path.Join(cfg.Files.Maildir, "tmp")
	err = os.MkdirAll(mdirtmp, 0700)
	if err != nil {
		log.WithFields(logrus.Fields{
			"Dir":   mdirtmp,
			"Error": err,
		}).Fatal("Failed to create Maildir directory.")
	}
}

// decodeMsg is the actual YAMN message decoder.  It's output is always a
// pooled file, either in the Inbound or Outbound queue.
func decodeMsg(rawMsg []byte, secret *keymgr.Secring) (err error) {

	// At this point, rawMsg should always be messageBytes in length
	err = lenCheck(len(rawMsg), messageBytes)
	if err != nil {
		log.Error(err)
		return
	}

	d := newDecMessage(rawMsg)
	// Extract the top header
	header := newDecodeHeader(d.getHeader())
	recipientKeyID := header.getRecipientKeyID()
	recipientSK, err := secret.GetSK(recipientKeyID)
	if err != nil {
		log.WithFields(logrus.Fields{
			"KeyID": recipientKeyID,
			"Error": err,
		}).Warn("Failed to ascertain recipient Secret Key")
		return
	}
	header.setRecipientSK(recipientSK)

	slotDataBytes, packetVersion, err := header.decode()
	if err != nil {
		log.WithFields(logrus.Fields{
			"Error": err,
		}).Warn("Header decode failed.")
		return
	}
	switch packetVersion {
	case 2:
		err = decodeV2(d, slotDataBytes)
		return
	default:
		err = fmt.Errorf(
			"Cannot decode packet version %d",
			packetVersion,
		)
		return
	}
	return
}

func decodeV2(d *decMessage, slotDataBytes []byte) (err error) {
	// Convert the raw Slot Data Bytes to meaningful slotData.
	slotData := decodeSlotData(slotDataBytes)
	// Test uniqueness of packet ID
	if !IdDb.Unique(slotData.getPacketID()) {
		log.WithFields(logrus.Fields{
			"PacketID": hex.EncodeToString(slotData.getPacketID()),
		}).Debug("Packet ID collision")
		err = errors.New("Packet ID collision")
		return
	}
	if !d.testAntiTag(slotData.getTagHash()) {
		log.Warn("Anti-tag digest mismatch")
		return
	}
	if slotData.ageTimestamp() > cfg.Remailer.MaxAge {
		log.WithFields(logrus.Fields{
			"Days":    slotData.ageTimestamp(),
			"MaxDays": cfg.Remailer.MaxAge,
		}).Warn("Maximum packet age exceeded.")
		return
	}
	if slotData.ageTimestamp() < 0 {
		log.Warn("Packet timestamp is in the future. Rejecting it.")
		return
	}
	if slotData.getPacketType() == 0 {
		d.shiftHeaders()
		// Decode Intermediate
		inter := decodeIntermediate(slotData.packetInfo)
		d.decryptAll(slotData.aesKey, inter.aesIV12)
		/*
			The following conditional tests if we are the next hop
			in addition to being the current hop.  If we are, then
			it's better to store the message in the inbound pool.
			This prevents it being emailed back to us.
		*/
		if inter.getNextHop() == cfg.Remailer.Address {
			log.Info("Message loops back to us. " +
				"Storing in pool instead of sending it.")
			outfileName := randPoolFilename("i")
			err = ioutil.WriteFile(
				outfileName,
				d.getPayload(),
				0600,
			)
			if err != nil {
				log.WithFields(logrus.Fields{
					"Filename": outfileName,
					"Error":    err,
				}).Error("Failed to write file to pool.")
				return
			}
			stats.outLoop++
		} else {
			writeMessageToPool(inter.getNextHop(), d.getPayload())
			stats.outYamn++
			// Decide if we want to inject a dummy
			if !flag_nodummy && dice() < 55 {
				dummy()
				stats.outDummy++
			}
		} // End of local or remote delivery
	} else if slotData.getPacketType() == 1 {
		// Decode Exit
		final := decodeFinal(slotData.packetInfo)
		if final.getDeliveryMethod() == 255 {
			log.Debug("Discarding dummy message")
			stats.inDummy++
			return
		}
		// Decrypt the payload body
		// This could be done under Delivery Method 0 but, future
		// delivery methods (other than dummies) will require a
		// decrypted body.
		plain := d.decryptBody(
			slotData.getAesKey(),
			final.getAesIV(),
			final.getBodyBytes(),
		)
		// Test delivery methods
		switch final.getDeliveryMethod() {
		case 0:
			stats.inYamn++
			if !cfg.Remailer.Exit {
				if final.numChunks == 1 {
					// Need to randhop as we're not an exit
					// remailer
					randhop(plain)
				} else {
					log.Warn("Randhopping doesn't support " +
						"multi-chunk messages.")
				}
				return
			}
			smtpMethod(plain, final)
		default:
			log.WithFields(logrus.Fields{
				"Method": final.getDeliveryMethod(),
			}).Warn("Unsupported Delivery Method.")
			return
		}
	} else {
		log.WithFields(logrus.Fields{
			"PacketType": slotData.getPacketType(),
		}).Warn("Unknown Packet Type.")
		return
	}
	return
}

// smtpMethod is concerned with final-hop processing.
func smtpMethod(plain []byte, final *slotFinal) {
	var err error
	if final.getNumChunks() == 1 {
		// If this is a single chunk message, pool it and get out.
		writePlainToPool(plain, "m")
		stats.outPlain++
		return
	}
	// We're an exit and this is a multi-chunk message
	chunkFilename := writePlainToPool(plain, "p")
	log.WithFields(logrus.Fields{
		"MsgID":    final.getMessageID(),
		"ChunkNum": final.getChunkNum(),
		"Chunks":   final.getNumChunks(),
		"Filename": chunkFilename,
	}).Info("Pooled partial message chunk.")
	// Fetch the chunks info from the DB for the given message ID
	chunks := ChunkDb.Get(final.getMessageID(), final.getNumChunks())
	// This saves losts of -1's as slices start at 0 and chunks at 1
	cslot := final.getChunkNum() - 1
	// Test that the slot for this chunk is empty
	if chunks[cslot] != "" {
		log.WithFields(logrus.Fields{
			"MsgID":    final.getMessageID(),
			"ChunkNum": final.getChunkNum(),
		}).Warn("Duplicate partial message chunk.")
	}
	// Insert the new chunk into the slice
	chunks[cslot] = chunkFilename
	log.WithFields(logrus.Fields{
		"Chunks": strings.Join(chunks, ","),
	}).Debug("Partial message construction status.")
	// Test if all chunk slots are populated
	if IsPopulated(chunks) {
		newPoolFile := randPoolFilename("m")
		log.WithFields(logrus.Fields{
			"Filename": newPoolFile,
		}).Info("Reconstructing chunked message.")
		err = ChunkDb.Assemble(newPoolFile, chunks)
		if err != nil {
			log.WithFields(logrus.Fields{
				"Filename": newPoolFile,
				"Error":    err,
			}).Warn("Chunked reconstruction failed")
			// Don't return here or the bad chunk will remain in
			// the DB.
		}
		// Now the message is assembled into the Pool, the DB record
		// can be deleted
		ChunkDb.Delete(final.getMessageID())
		stats.outPlain++
	} else {
		// Write the updated chunk status to
		// the DB
		ChunkDb.Insert(final.getMessageID(), chunks)
	}
}

// randhop is a simplified client function that does single-hop encodings
func randhop(plainMsg []byte) {
	var err error
	if len(plainMsg) == 0 {
		log.Info("Zero-byte message during randhop. Ignoring it.")
		return
	}
	// Make a single hop chain with a random node
	in_chain := []string{"*"}
	final := newSlotFinal()
	var chain []string
	chain, err = makeChain(in_chain)
	if err != nil {
		log.Warn(err)
		return
	}
	sendTo := chain[0]
	if len(chain) != 1 {
		log.WithFields(logrus.Fields{
			"Chain":    strings.Join(chain, ","),
			"ChainLen": len(chain),
		}).Fatal("Randhop chain must be single hop.")
	}
	log.WithFields(logrus.Fields{
		"Remailer": chain[0],
	}).Info("Randhop to Exit Remailer.")
	yamnMsg := encodeMsg(plainMsg, chain, *final)
	writeMessageToPool(sendTo, yamnMsg)
	stats.outRandhop++
	return
}

// remailerFoo responds to requests for remailer-* info
func remailerFoo(subject, sender string) (err error) {
	m := quickmail.NewMessage()
	m.Set("From", cfg.Remailer.Address)
	m.Set("To", sender)
	if len(subject) > 20 {
		// Trim the Subject, we only need a "remailer-foo"
		subject = subject[:20]
	}
	if strings.HasPrefix(subject, "remailer-key") {
		// remailer-key
		log.WithFields(logrus.Fields{
			"Sender": sender,
		}).Debug("Remailer-Key request")
		m.Set("Subject", fmt.Sprintf("Remailer key for %s", cfg.Remailer.Name))
		m.Filename = cfg.Files.Pubkey
		m.Prefix = "Here is the Mixmaster key:\n\n=-=-=-=-=-=-=-=-=-=-=-="
	} else if strings.HasPrefix(subject, "remailer-conf") {
		// remailer-conf
		log.WithFields(logrus.Fields{
			"Sender": sender,
		}).Debug("Remailer-Conf request")
		m.Set(
			"Subject",
			fmt.Sprintf("Capabilities of the %s remailer", cfg.Remailer.Name))
		m.Text(fmt.Sprintf("Remailer-Type: Mixmaster %s\n", version))
		m.Text("Supported Formats:\n   Mixmaster\n")
		m.Text(fmt.Sprintf("Pool size: %d\n", cfg.Pool.Size))
		m.Text(fmt.Sprintf("Maximum message size: %d kB\n", cfg.Remailer.MaxSize))
		m.Text("The following header lines will be filtered:\n")
		m.Text(
			fmt.Sprintf("\n$remailer{\"%s\"} = \"<%s>",
				cfg.Remailer.Name, cfg.Remailer.Address))
		if !cfg.Remailer.Exit {
			m.Text(" middle")
		}
		packetVersions := []string{"v2"}
		for _, v := range packetVersions {
			m.Text(fmt.Sprintf(" %s", v))
		}
		m.Text("\";\n")
		m.Text("\nSUPPORTED MIXMASTER (TYPE II) REMAILERS")
		var pubList []string
		pubList, err := keymgr.Headers(cfg.Files.Pubring)
		if err != nil {
			log.WithFields(logrus.Fields{
				"Pubring": cfg.Files.Pubring,
			}).Info("Could not read Public Keyring")
		} else {
			m.List(pubList)
		}
	} else if strings.HasPrefix(subject, "remailer-adminkey") {
		// remailer-adminkey
		log.WithFields(logrus.Fields{
			"Sender": sender,
		}).Debug("Remailer-AdminKey request")
		m.Set(
			"Subject",
			fmt.Sprintf("Admin key for the %s remailer", cfg.Remailer.Name))
		m.Filename = cfg.Files.Adminkey
	} else if strings.HasPrefix(subject, "remailer-help") {
		// remailer-help
		log.WithFields(logrus.Fields{
			"Sender": sender,
		}).Debug("Remailer-AdminKey request")
		m.Set(
			"Subject",
			fmt.Sprintf("Your help request for the %s Anonymous Remailer",
				cfg.Remailer.Name))
		m.Filename = cfg.Files.Help
	} else {
		log.WithFields(logrus.Fields{
			"Sender":  sender,
			"Subject": subject,
		}).Info("Ignoring unknown info request.")
		err = fmt.Errorf("Ignoring request for %s", subject)
		return
	}
	var msg []byte
	msg, err = m.Compile()
	if err != nil {
		log.WithFields(logrus.Fields{
			"Subject": subject,
			"Error":   err,
		}).Error("Construction of info request failed.")
		return
	}
	err = mailBytes(msg, []string{sender})
	if err != nil {
		log.WithFields(logrus.Fields{
			"Subject": subject,
			"Sender":  sender,
			"Error":   err,
		}).Warn("Failed to reply to info request.")
		return
	}
	return
}
