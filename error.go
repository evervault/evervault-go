package evervault

import "strconv"

type APIError struct {
	StatusCode int
	Message    string
	Details    map[string]interface{}
}

func (e APIError) Error() string {
	return "Status code received " + strconv.Itoa(e.StatusCode) + ", " + e.Message
}
