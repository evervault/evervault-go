package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

// RequestData represents the structure of the request body.
type RequestData map[string]any

// ResponseData represents the structure of the response body.
type ResponseData struct {
	Message string         `json:"message"`
	Body    map[string]any `json:"body"`
}

const (
	readTimeout  = 5 * time.Second
	writeTimeout = 10 * time.Second
)

func main() {
	// Create an HTTP server with specified timeouts
	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	// Register the handler for the root path
	http.HandleFunc("/", handleRequest)

	// Start the server and listen for incoming connections
	log.Print("Starting server on :8080")
	log.Fatal(server.ListenAndServe())
}

// handleRequest handles the HTTP requests and echoes back the request body in the response.
func handleRequest(writer http.ResponseWriter, request *http.Request) {
	// Read the request body
	body, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer request.Body.Close()

	var requestData RequestData

	// Parse the request body if it is not empty
	if len(body) > 0 {
		err = json.Unmarshal(body, &requestData)
		if err != nil {
			http.Error(writer, "Error parsing JSON", http.StatusBadRequest)
			return
		}
	} else {
		// Set an empty request body if the original request had an empty body
		requestData = make(map[string]interface{})
	}

	// Prepare the response data with the echoed message and the original request body
	responseData := ResponseData{
		Message: "Hello! I'm writing to you from within an enclave",
		Body:    requestData,
	}

	// Convert the response data to JSON
	responseBody, err := json.Marshal(responseData)
	if err != nil {
		http.Error(writer, "Error creating response JSON", http.StatusInternalServerError)
		return
	}

	// Set the response headers
	writer.Header().Set("Content-Type", "application/json")

	// Write the response body
	if _, err = writer.Write(responseBody); err != nil {
		log.Printf("Error writing response: %v", err)
	}
}
