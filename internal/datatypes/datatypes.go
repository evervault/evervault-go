package datatypes

type Datatype int

const (
	String = iota
	Number
	Boolean
	Bytes
)

type TokenResponse struct {
	Token  string `json:"token"`
	Expiry string `json:"expiry"`
}