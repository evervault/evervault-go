package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2EEncryptString(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := "hello world"

	encrypted, err := client.EncryptString(payload)
	require.NoError(t, err)

	decrypted, err := client.DecryptString(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %s %s", payload, decrypted)
		return
	}
}

func TestE2EEncryptStringWithPermittedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := "hello world"

	encrypted, err := client.EncryptStringWithDataRole(payload, "permit-all")
	require.NoError(t, err)

	decrypted, err := client.DecryptString(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %s %s", payload, decrypted)
		return
	}
}

func TestE2EEncryptStringWithDeniedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := "hello world"

	encrypted, err := client.EncryptStringWithDataRole(payload, "deny-all")
	require.NoError(t, err)

	_, err = client.DecryptString(encrypted)
	if err == nil {
		t.Errorf("expected error decrypting data")
		return
	}
}

func TestE2EEncryptBoolTrue(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := true

	encrypted, err := client.EncryptBool(payload)
	require.NoError(t, err)

	decrypted, err := client.DecryptBool(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %t %t", payload, decrypted)
		return
	}
}

func TestE2EEncryptBoolTrueWithPermittedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := true

	encrypted, err := client.EncryptBoolWithDataRole(payload, "permit-all")
	require.NoError(t, err)

	decrypted, err := client.DecryptBool(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %t %t", payload, decrypted)
		return
	}
}

func TestE2EEncryptBoolTrueWithDeniedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := true

	encrypted, err := client.EncryptBoolWithDataRole(payload, "deny-all")
	require.NoError(t, err)

	_, err = client.DecryptBool(encrypted)
	if err == nil {
		t.Errorf("expected error decrypting data")
		return
	}
}

func TestE2EEncryptBoolFalse(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := false

	encrypted, err := client.EncryptBool(payload)
	require.NoError(t, err)

	decrypted, err := client.DecryptBool(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %t %t", payload, decrypted)
		return
	}
}

func TestE2EEncryptBoolFalseWithPermittedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := false

	encrypted, err := client.EncryptBoolWithDataRole(payload, "permit-all")
	require.NoError(t, err)

	decrypted, err := client.DecryptBool(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %t %t", payload, decrypted)
		return
	}
}

func TestE2EEncryptBoolFalseWithDeniedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := false

	encrypted, err := client.EncryptBoolWithDataRole(payload, "deny-all")
	require.NoError(t, err)

	_, err = client.DecryptBool(encrypted)
	if err == nil {
		t.Errorf("expected error decrypting data")
		return
	}
}

func TestE2EEncryptInt(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1

	encrypted, err := client.EncryptInt(payload)
	require.NoError(t, err)

	decrypted, err := client.DecryptInt(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %d %d", payload, decrypted)
		return
	}
}

func TestE2EEncryptIntWithPermittedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1

	encrypted, err := client.EncryptIntWithDataRole(payload, "permit-all")
	require.NoError(t, err)

	decrypted, err := client.DecryptInt(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %d %d", payload, decrypted)
		return
	}
}

func TestE2EEncryptIntWithDeniedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1

	encrypted, err := client.EncryptIntWithDataRole(payload, "deny-all")
	require.NoError(t, err)

	_, err = client.DecryptInt(encrypted)
	if err == nil {
		t.Errorf("expected error decrypting data")
		return
	}
}

func TestE2EEncryptFloat(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1.5

	encrypted, err := client.EncryptFloat64(payload)
	require.NoError(t, err)

	decrypted, err := client.DecryptFloat64(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %f %f", payload, decrypted)
		return
	}
}

func TestE2EEncryptFloatWithPermittedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1.5

	encrypted, err := client.EncryptFloat64WithDataRole(payload, "permit-all")
	require.NoError(t, err)

	decrypted, err := client.DecryptFloat64(encrypted)
	require.NoError(t, err)

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %f %f", payload, decrypted)
		return
	}
}
func TestE2EEncryptFloatWithDeniedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1.5

	encrypted, err := client.EncryptFloat64WithDataRole(payload, "deny-all")
	require.NoError(t, err)

	_, err = client.DecryptFloat64(encrypted)
	if err == nil {
		t.Errorf("expected error decrypting data")
		return
	}
}

func TestE2EEncryptBytes(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := []byte{97, 98, 99, 100, 101, 102}

	encrypted, err := client.EncryptByteArray(payload)
	require.NoError(t, err)

	decrypted, err := client.DecryptByteArray(encrypted)
	require.NoError(t, err)

	if string(payload) != string(decrypted) {
		t.Errorf("decrypted data does not match the original %s %s", string(payload), string(decrypted))
		return
	}
}

func TestE2EEncryptBytesWithPermittedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := []byte{97, 98, 99, 100, 101, 102}

	encrypted, err := client.EncryptByteArrayWithDataRole(payload, "permit-all")
	require.NoError(t, err)

	decrypted, err := client.DecryptByteArray(encrypted)
	require.NoError(t, err)

	if string(payload) != string(decrypted) {
		t.Errorf("decrypted data does not match the original %s %s", string(payload), string(decrypted))
		return
	}
}

func TestE2EEncryptBytesWithDeniedRole(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := []byte{97, 98, 99, 100, 101, 102}

	encrypted, err := client.EncryptByteArrayWithDataRole(payload, "deny-all")
	require.NoError(t, err)

	_, err = client.DecryptByteArray(encrypted)
	if err == nil {
		t.Errorf("expected error decrypting data")
		return
	}
}
