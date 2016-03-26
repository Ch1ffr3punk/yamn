package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/dchest/blake2s"
	"io"
	"mime/multipart"
	"net/http"
	"os"
)

func multipartHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32768)
	file, handler, err := r.FormFile("yamn")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	fmt.Fprintf(w, "%v", handler.Header)
	digest, err := blake2s.New(nil)
	if err != nil {
		panic(err)
	}
	// Firstly, copy the file to the digest for checksum comparison.
	io.Copy(digest, file)
	checksum, err := hex.DecodeString(r.FormValue("checksum"))
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(digest.Sum(nil), checksum) {
		fmt.Println("Checksum failure")
		os.Exit(1)
	}
	// Checksum is good, now write the embedded file to the pool.
	f, err := newPoolFile("i")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = file.Seek(0, 0)
	if err != nil {
		panic(err)
	}
	io.Copy(f, file)
}

func home(w http.ResponseWriter, req *http.Request) {
	fmt.Println("Serving home")
	http.ServeFile(w, req, "homepage.html")
}

// ----- This section is all about client-side functionality

// Creates a new file upload http request with optional extra params
func newfileUploadRequest(url string, filename string) (req *http.Request, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	// Open and insert the file
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	part, err := writer.CreateFormFile("yamn", filename)
	if err != nil {
		panic(err)
	}
	// Copy the file opject to the Forms Part.
	_, err = io.Copy(part, f)
	if err != nil {
		panic(err)
	}
	// Next we create a Blake2 Hash Form Part as a checksum.
	// Seek to the beginning of the file to get a complete checksum.
	_, err = f.Seek(0, 0)
	if err != nil {
		panic(err)
	}
	digest, err := blake2s.New(nil)
	if err != nil {
		return nil, err
	}
	// Copy the file content to the digest
	io.Copy(digest, f)
	// Write the digest in Hex format
	err = writer.WriteField(
		"checksum",
		hex.EncodeToString(digest.Sum(nil)),
	)
	if err != nil {
		panic(err)
	}

	writer.Close()

	// Create the actual HTTP request.
	req, err = http.NewRequest("POST", url, body)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return
}

func client(filename string) {
	request, err := newfileUploadRequest(
		"http://www.mixmin.net:8080/upload",
		filename,
	)
	if err != nil {
		panic(err)
	}
	//fmt.Println(request)
	//os.Exit(0)
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	//Trace.Printf("Transferred %s via HTTP", filename)

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("%d: Status OK\n", resp.StatusCode)
	}
}

func server() {
	mux := http.NewServeMux()
	//mux.HandleFunc("/", home)
	mux.HandleFunc("/upload", multipartHandler)
	http.ListenAndServe(":8080", mux)
}
