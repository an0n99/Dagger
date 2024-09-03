package encryption

import (
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"errors"
)


func EncryptPGP(plainText []byte, publicKey string) (string, error) {
	keyObj, err := crypto.NewKeyFromArmored(publicKey)
	if err != nil {
		return "", err
	}

	keyRing, err := crypto.NewKeyRing(keyObj)
	if err != nil {
		return "", err
	}

	message := crypto.NewPlainMessage(plainText)
	encryptedMessage, err := keyRing.Encrypt(message, nil)
	if err != nil {
		return "", err
	}

	return encryptedMessage.GetArmored(), nil
}


func DecryptPGP(cipherText string, privateKey string, passphrase []byte) ([]byte, error) {
	keyObj, err := crypto.NewKeyFromArmored(privateKey)
	if err != nil {
		return nil, err
	}

	err = keyObj.Unlock(passphrase)
	if err != nil {
		return nil, errors.New("incorrect passphrase")
	}

	keyRing, err := crypto.NewKeyRing(keyObj)
	if err != nil {
		return nil, err
	}

	encryptedMessage, err := crypto.NewPGPMessageFromArmored(cipherText)
	if err != nil {
		return nil, err
	}

	plainMessage, err := keyRing.Decrypt(encryptedMessage, nil, 0)
	if err != nil {
		return nil, err
	}

	return plainMessage.GetBinary(), nil
}
