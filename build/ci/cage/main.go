package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

type RequestData map[string]interface{}

type ResponseData struct {
	Message string                 `json:"message"`
	Body    map[string]interface{} `json:"body"`
}

const (
	readTimeout  = 5 * time.Second
	writeTimeout = 10 * time.Second
)

func main() {
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	http.HandleFunc("/", handleRequest)
	log.Print("Starting server on :8080")
	log.Fatal(server.ListenAndServe())
}

func handleRequest(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer request.Body.Close()

	var requestData RequestData

	if len(body) > 0 {
		err = json.Unmarshal(body, &requestData)
		if err != nil {
			http.Error(writer, "Error parsing JSON", http.StatusBadRequest)
			return
		}
	} else {
		requestData = make(map[string]interface{})
	}

	responseData := ResponseData{
		Message: "Hello! I'm writing to you from within an enclave",
		Body:    requestData,
	}

	responseBody, err := json.Marshal(responseData)
	if err != nil {
		http.Error(writer, "Error creating response JSON", http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/json")

	if _, err = writer.Write(responseBody); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}
