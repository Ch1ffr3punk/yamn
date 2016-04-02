package keymgr

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	expiringDays int = 48 // Treat keys as expiring n hours before expired
	maxAddyLen   int = 52 // Max chars in remailer address
)

type secret struct {
	keyid []byte    // keyid
	sk    []byte    // Secret Key
	from  time.Time // Valid from
	until time.Time // Valid Until
}

type Secring struct {
	secringFile string // Filename of secret keyring
	pubkeyFile  string // Public keyfile (key.txt)
	sec         map[string]secret
	name        string        // Local remailer's name
	mailto      string        // Local remailer's email address
	http        string        // Local remailer's http address
	myKeyid     []byte        // Keyid this remailer is advertising
	validity    time.Duration // Period of key validity
	grace       time.Duration // Period of grace after key expiry
	exit        bool          // Is this an Exit type remailer?
	version     string        // Yamn version string
}

// OpenAppend opens a file in Append mode and sets user-only permissions
func OpenAppend(name string) (f *os.File, err error) {
	f, err = os.OpenFile(name, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	return
}

// OpenCreate opens a new file in Write mode and sets user-only permissions
func OpenCreate(name string) (f *os.File, err error) {
	f, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	return
}

// NewSecring is a constructor for the Secret Keyring
func NewSecring(secfile, pubkey string) *Secring {
	return &Secring{
		secringFile: secfile,
		pubkeyFile:  pubkey,
		sec:         make(map[string]secret),
	}
}

// ListKeyids returns a string slice of all in-memory secret keyids
func (s *Secring) ListKeyids() (keyids []string) {
	keyids = make([]string, 0, len(s.sec))
	for k := range s.sec {
		keyids = append(keyids, k)
	}
	return
}

// SetName validates and sets the remailer name
func (s *Secring) SetName(name string) {
	var err error
	l := len(name)
	if l < 2 || l > 12 {
		err = fmt.Errorf(
			"Remailer name must be 2 to 12 chars, not %d.",
			l,
		)
		panic(err)
	}
	s.name = strings.ToLower(name)
}

// SetAddress validates and sets the remailer address
func (s *Secring) SetMailto(addy string) {
	var err error
	l := len(addy)
	if l < 3 || l > maxAddyLen {
		err = fmt.Errorf(
			"Remailer mailto address must be 2 to 52 chars, "+
				"not %d.",
			l,
		)
		panic(err)
	}
	index := strings.Index(addy, "@")
	if index == -1 {
		err = fmt.Errorf(
			"%s: Remailer mailto address doesn't contain an @.",
			addy,
		)
		panic(err)
	} else if index == 0 || l-index < 3 {
		err = fmt.Errorf("%s: Invalid remailer address.", addy)
		panic(err)
	}
	s.mailto = strings.ToLower(addy)
}

// SetHttp validates and defines the remailer's http url.
func (s *Secring) SetHttp(addy string, port int) {
	l := len(addy)
	if l > maxAddyLen {
		err := fmt.Errorf(
			"Remailer HTTP address exceeds max length: %d",
			l,
		)
		panic(err)
	}
	if strings.HasPrefix(addy, "http://") {
		// HTTP is alright and certainly better than nothing.
	} else if strings.HasPrefix(addy, "https://") {
		// We like HTTPS.  Yum yum!
	} else {
		panic("Unknown HTTP URL format")
	}
	s.http = fmt.Sprintf("%s:%d", addy, port)
}

// SetExit defines if this is a Middle or Exit remailer
func (s *Secring) SetExit(exit bool) {
	s.exit = exit
}

// SetValidity defines the time duration over which a key is deemed valid
func (s *Secring) SetValidity(valid, grace int) {
	s.validity = time.Duration(24*valid) * time.Hour
	s.grace = time.Duration(24*grace) * time.Hour
}

// SetVersion sets the version string used on keys
func (s *Secring) SetVersion(v string) {
	s.version = "4:" + v
}

// Count returns the number of secret keys in memory
func (s *Secring) Count() int {
	return len(s.sec)
}

// Insert puts a new secret key into memory and returns its keyid
func (s *Secring) Insert(pub, sec []byte) (keyidstr string) {
	var err error
	if len(pub) != 32 {
		err = fmt.Errorf(
			"Invalid pubkey length. Wanted=32, Got=%d",
			len(pub),
		)
		panic(err)
	}
	if len(sec) != 32 {
		err = fmt.Errorf(
			"Invalid seckey length. Wanted=32, Got=%d",
			len(sec),
		)
		panic(err)
	}
	key := new(secret)
	/*
		Keyids are arbitrary, they only server to link public and
		secret keys in a manner that enables clients to know which
		public key to encrypt to and servers to know which secret key
		to use for decryption.  Using a truncated SHA256 of the public
		key provides the means for some, perhaps, useful validation
		that the client-held public key is not corrupt.
	*/
	key.keyid = makeKeyID(pub)
	keyidstr = hex.EncodeToString(key.keyid)
	// Validity dates
	key.from = time.Now()
	key.until = time.Now().Add(s.validity)
	// The secret key itself
	key.sk = sec
	s.sec[keyidstr] = *key
	return
}

// WritePublic writes the Public Key to disk.
func (s *Secring) WritePublic(pub []byte, keyidstr string) {
	var err error
	if len(pub) != 32 {
		err = fmt.Errorf(
			"Invalid pubkey length. Wanted=32, Got=%d",
			len(pub),
		)
		panic(err)
	}

	var capstring string
	// M = Middle, E = Exit
	if s.exit {
		capstring += "E"
	} else {
		capstring += "M"
	}

	key, exists := s.sec[keyidstr]
	if !exists {
		err = fmt.Errorf("%s: Keyid does not exist", keyidstr)
		panic(err)
	}

	header := s.name + " "
	header += keyidstr + " "
	header += s.version + " "
	header += capstring + " "
	header += key.from.UTC().Format(date_format) + " "
	header += key.until.UTC().Format(date_format)

	// Open the file for writing
	f, err := os.Create(s.pubkeyFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, header)
	if s.mailto != "" {
		fmt.Fprintf(w, "mailto:%s\n", s.mailto)
	}
	if s.http != "" {
		fmt.Fprintln(w, s.http)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "-----Begin Mix Key-----")
	fmt.Fprintln(w, keyidstr)
	fmt.Fprintln(w, hex.EncodeToString(pub))
	fmt.Fprintln(w, "-----End Mix Key-----")
	err = w.Flush()
	if err != nil {
		panic(err)
	}
}

// WriteSecret adds the selected secret key to the secret keyring file
func (s *Secring) WriteSecret(keyidstr string) {
	var err error
	key, exists := s.sec[keyidstr]
	if !exists {
		err = fmt.Errorf("%s: Keyid does not exist", keyidstr)
		panic(err)
	}
	f, err := OpenAppend(s.secringFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	keydata := "\n-----Begin Mixmaster Secret Key-----\n"
	keydata += fmt.Sprintf(
		"Created: %s\n",
		key.from.UTC().Format(date_format),
	)
	keydata += fmt.Sprintf(
		"Expires: %s\n",
		key.until.UTC().Format(date_format),
	)
	keydata += keyidstr + "\n"
	keydata += hex.EncodeToString(key.sk) + "\n"
	keydata += "-----End Mixmaster Secret Key-----\n"
	_, err = f.WriteString(keydata)
	if err != nil {
		panic(err)
	}
}

func (s *Secring) headerHelper(elements []string) (keyidstr, outHead string) {
	var err error
	// The header format mandates six fields.
	if len(elements) != 6 {
		err = fmt.Errorf(
			"Expected 6 header elements, got %d",
			len(elements),
		)
		panic(err)
	}

	var capstring string
	// M = Middle, E = Exit
	if s.exit {
		capstring += "E"
	} else {
		capstring += "M"
	}

	// Extract the keyid so we can return it
	keyidstr = elements[1]
	if len(keyidstr) != 32 {
		err = fmt.Errorf(
			"Invalid public keyid length.  Expected=32, Got=%d.",
			len(keyidstr),
		)
		panic(err)
	}

	outHead = s.name + " "
	outHead += keyidstr + " "
	outHead += s.version + " "
	outHead += capstring + " "
	outHead += elements[4] + " " // Valid From date
	outHead += elements[5]       // Valid To date
	return
}

// WriteMyKey writes the local public key to filename with current
// configurtaion settings.
func (s *Secring) WriteMyKey(filename string) (keyidstr string) {
	infile, err := os.Open(s.pubkeyFile)
	if err != nil {
		panic(err)
	}
	defer infile.Close()

	// Create a tmp file rather than overwriting directly
	out, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0660)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	// Define some variables we'll populate during scanning.
	var gotHeader bool // True once header processed
	var header string  // Content of header
	var gotPubKey bool // True once pubkey processed
	var pubKey string  // Public key string

	// Prep the scanning loop
	in := bufio.NewScanner(infile)
	var line string // Content of each scanned line
	/*
		yamntest 3e1c9f713e9058253bcb335d3dd82b8a 4:0.2b E 2016-04-01 2016-04-06
		mailto:yamntest@mixmin.net
		http://yamntest.mixmin.net:8087

		-----Begin Mix Key-----
		3e1c9f713e9058253bcb335d3dd82b8a
		1b96226bd89d42e9bc338c03bb67154c62959dad4b1e4baed314265f5c6e1a58
		-----End Mix Key-----
	*/
	for in.Scan() {
		line = in.Text()
		// Test for the header line
		elements := strings.Fields(line)
		if !gotHeader && len(elements) == 6 {
			keyidstr, header = s.headerHelper(elements)
			gotHeader = true
			continue
		}
		if gotHeader && len(elements) == 1 && len(line) == 64 {
			pubKey = line
			gotPubKey = true
			break
		}
	}
	if !gotHeader || !gotPubKey {
		panic("Malformed Public key file")
	}

	// We should now have the header, keyidstr and pubkey.
	// Write the header line
	fmt.Fprintln(out, header)
	// If we have a mail addr, write it under the header.
	if s.mailto != "" {
		fmt.Fprintf(out, "mailto:%s\n", s.mailto)
	}
	// If we have an http addr, write that next.
	if s.http != "" {
		fmt.Fprintln(out, s.http)
	}
	fmt.Fprintln(out, "\n-----Begin Mix Key-----")
	fmt.Fprintln(out, keyidstr)
	fmt.Fprintln(out, pubKey)
	fmt.Fprintln(out, "-----End Mix Key-----")
	return
}

// Return the Secret struct that corresponds to the requested Keyid
func (s *Secring) Get(keyid string) (sec secret, err error) {
	var exists bool
	sec, exists = s.sec[keyid]
	if !exists {
		err = fmt.Errorf(
			"%s: Keyid not found in secret keyring",
			keyid,
		)
		return
	}
	return
}

// Return the Secret Key that corresponds to the requested Keyid
func (s *Secring) GetSK(keyid string) (sk []byte, err error) {
	sec, exists := s.sec[keyid]
	if !exists {
		err = fmt.Errorf(
			"%s: Keyid not found in secret keyring",
			keyid,
		)
		return
	}
	sk = sec.sk
	return
}

// Purge deletes expired keys and writes current ones to a backup secring
func (s *Secring) Purge() (active, expiring, expired, purged int) {
	/*
		Keys exist in four possible states:-

		active  - Keys that are valid and not yet expiring
		expiring - Active keys that will expire soon
		expired - Expired keys, not yet purged from the Secring
		purged  - Keys that have just been deleted from the Secring
	*/

	// Running Purge with undefined validity parameters would probably
	// trash the Secret Keyring.  This tests prevents that unfortunate
	// circumstance.
	if s.validity == 0 || s.grace == 0 {
		err := errors.New("Cannot purge without validity parameters")
		panic(err)
	}

	// Rename the secring file to a tmp name, just in case this screws up.
	err := os.Rename(s.secringFile, s.secringFile+".tmp")
	if err != nil {
		// The implication is that no secring file exists yet
		return
	}

	// Create a new secring file. At this point, secringFile must not
	// exist.
	f, err := OpenCreate(s.secringFile)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Set the duration prior to expired that we consider "expiring".
	expirePeriod := time.Duration(-expiringDays) * time.Hour

	now := time.Now()
	// Iterate key and value of Secring in memory
	for k, m := range s.sec {
		purgeDate := m.until.Add(s.grace)
		if now.After(purgeDate) {
			// Key has expired. Purge from memory and don't write
			// it back to disk.
			delete(s.sec, k)
			purged++
			continue
		}
		keydata := "-----Begin Mixmaster Secret Key-----\n"
		keydata += fmt.Sprintf(
			"Created: %s\n",
			m.from.Format(date_format),
		)
		keydata += fmt.Sprintf(
			"Expires: %s\n",
			m.until.Format(date_format),
		)
		keydata += hex.EncodeToString(m.keyid) + "\n"
		keydata += hex.EncodeToString(m.sk) + "\n"
		keydata += "-----End Mixmaster Secret Key-----\n\n"
		_, err = f.WriteString(keydata)
		if err != nil {
			panic(err)
		}
		// If a key is expiring in the next 48 hours, treat it as
		// expiring rather than active.
		expiringThreshold := m.until.Add(expirePeriod)
		if now.After(m.until) {
			expired++
		} else if now.After(expiringThreshold) {
			expiring++
		} else {
			active++
		}
	}
	return
}

// ImportSecring reads a YAML secring.mix file into memory
func (s *Secring) ImportSecring() (err error) {
	var f *os.File
	f, err = os.Open(s.secringFile)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var line string        //Each line within secring.mix
	var skdata []byte      // Decoded secret key
	var keyidMapKey string // String representation of keyid to key map with
	var valid time.Time
	var expire time.Time
	var sec *secret
	now := time.Now().UTC()
	key_phase := 0
	/* Key phases are:
	0 Expecting Begin cutmark
	1 Expecting Valid-from date
	2 Expecting Valid-to date
	3 Expecting Keyid line
	4	Expecting secret key
	5 Got End cutmark
	*/

	for scanner.Scan() {
		line = scanner.Text()
		switch key_phase {
		case 0:
			// Expecting begin cutmark
			if line == "-----Begin Mixmaster Secret Key-----" {
				sec = new(secret)
				key_phase = 1
			}
		case 1:
			// Valid-from date
			if line[:9] == "Created: " {
				valid, err = time.Parse(date_format, line[9:])
				if err != nil {
					fmt.Fprintln(
						os.Stderr,
						"Malformed Created date",
					)
					key_phase = 0
					continue
				}
			} else {
				fmt.Fprintln(
					os.Stderr,
					"Expected Created line",
				)
				key_phase = 0
				continue
			}
			if valid.After(now) {
				// Key is not yet valid
				fmt.Fprintln(
					os.Stderr,
					"Key is not valid yet",
				)
				key_phase = 0
				continue
			}
			sec.from = valid
			key_phase = 2
		case 2:
			// Expire date
			if line[:9] == "Expires: " {
				expire, err = time.Parse(date_format, line[9:])
				if err != nil {
					fmt.Fprintln(
						os.Stderr,
						"Malformed Expires date",
					)
					key_phase = 0
					continue
				}
			} else {
				fmt.Fprintln(
					os.Stderr,
					"Expected Expires line",
				)
				key_phase = 0
				continue
			}
			if expire.Before(now) {
				// Key has expired (but we don't care)
			}
			sec.until = expire
			key_phase = 3
		case 3:
			if len(line) != 32 {
				// Invalid keyid length
				key_phase = 0
				continue
			}
			var keyid []byte
			keyid, err = hex.DecodeString(line)
			if err != nil {
				// Non hex keyid
				fmt.Fprintln(os.Stderr, err)
				key_phase = 0
				continue
			}
			sec.keyid = keyid
			// Retain a textual representation to key the secring
			// map with
			keyidMapKey = line
			key_phase = 4
		case 4:
			// Expecting Private key
			skdata, err = hex.DecodeString(line)
			if err != nil {
				// Non hex Private key
				fmt.Fprintln(os.Stderr, err)
				key_phase = 0
			}
			if len(skdata) != 32 {
				fmt.Fprintln(os.Stderr, "Incorrect key length")
				key_phase = 0
				continue
			}
			sec.sk = skdata
			key_phase = 5
		case 5:
			// Expecting end cutmark
			if line == "-----End Mixmaster Secret Key-----" {
				// Add the key to the Keyring
				s.sec[keyidMapKey] = *sec
				key_phase = 0
			}
		} // End of switch
	} // End of file lines loop
	return
}
