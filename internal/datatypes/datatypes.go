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
	Expiry int64 `json:"expiry"`
}