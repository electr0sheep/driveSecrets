/*
Copyright © 2019 electr0sheep <electr0sheep@electr0sheep.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func GenerateKey() {
	_, err := ioutil.ReadFile("key.aes")
	if err != nil {
		key := make([]byte, 32)

		_, err := rand.Read(key)
		if err != nil {
			log.Fatalf("Error generating key: %v", err)
		}

		fmt.Printf("Saving credential file to: %s\n", "key.aes")
		f, err := os.OpenFile("key.aes", os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalf("Unable to create aes key file: %v", err)
		}
		defer f.Close()
		f.Write(key)
	} else {
		working_dir, _ := os.Getwd()
		log.Printf("WARNING: You already have a key set up. Generating a new key will possibly cause you to permanently lose access to your data. To proceed anyway, remove the key file (rm %s/key.aes) and rerun the command.",
			working_dir)
	}
}

func readKey() []byte {
	file, err := ioutil.ReadFile("key.aes")
	if err != nil {
		log.Fatalf("Unable to read aes key file, run driveSecrets generateKey: %v", err)
	}

	return file
}

func Encrypt(plaintext_string string) string {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key := readKey()
	// key, _ := hex.DecodeString(readKey())
	// key, _ := hex.DecodeString("6368616e676520746869732070617373")
	plaintext := []byte(plaintext_string)

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	plaintext = padByteArrayForEncryption(plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	return string(ciphertext)
}

func Decrypt(ciphertext_string string) string {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	key := readKey()
	// key, err := hex.DecodeString(read_key)
	// if err != nil {
	// 	panic(err)
	// }
	ciphertext := []byte(ciphertext_string)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	// Output: exampleplaintext
	return string(ciphertext)
}

func padByteArrayForEncryption(byteArray []byte) []byte {
	if len(byteArray)%aes.BlockSize != 0 {
		return append(byteArray, make([]byte, aes.BlockSize-(len(byteArray)%aes.BlockSize))...)
	} else {
		return byteArray
	}
}
