package crypto

import (
	"fmt"
	"testing"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestCase struct {
	name      string
	algorithm domain.Algorithm[domain.KeyPair]
}

var (
	rsaAlgorithm = RSAAlgorithm{}
	eccAlgorithm = ECCAlgorithm{}
	testCases    = []TestCase{
		{"RSA", rsaAlgorithm},
		{"ECC", eccAlgorithm},
	}
)

func TestCreateKeyPair(t *testing.T) {
	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("%v: Test CreateKeyPair", testCase.name), func(t *testing.T) {
			_, err := testCase.algorithm.CreateKeyPair()
			assert.Nil(t, err)
		})
	}
}

func TestSignData(t *testing.T) {
	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("%v: Test SignData doesn't fail", testCase.name), func(t *testing.T) {
			keyPair, err := testCase.algorithm.CreateKeyPair()
			require.Nil(t, err)
			_, err = testCase.algorithm.SignData("hello fiskaly", keyPair)
			assert.Nil(t, err)
		})
	}
}

func TestMarshalAndUnmarshal(t *testing.T) {
	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("%v: Test Marshal and Unmarshal", testCase.name), func(t *testing.T) {
			keyPair, err := testCase.algorithm.CreateKeyPair()
			require.Nil(t, err)
			_, privateKeyByte, err := testCase.algorithm.Marshal(keyPair)
			assert.Nil(t, err)
			gotKeyPair, err := testCase.algorithm.Unmarshal(privateKeyByte)
			assert.Nil(t, err)
			assert.Equal(t, keyPair, gotKeyPair)
		})
	}
}
