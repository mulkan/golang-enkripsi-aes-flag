package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

const JUMLAH_HEADING int = 10
const NILAI_HEADING byte = 100

func main() {
	/*
		-run {1,2} 1:enkripsi; 2:dekripsi
		-i file.doc
		-o file.doc
		-key key.txt
	*/
	var run int
	var input string
	var output string
	var key string
	var help string
	flag.IntVar(&run, "run", 1, "isikan 1: enkripsi; 2: dekripsi")
	flag.StringVar(&input, "input", "file1.doc", "lokasi file input")
	flag.StringVar(&output, "output", "file2.doc", "lokasi file output")
	flag.StringVar(&key, "key", "key.txt", "lokasi file key")
	flag.StringVar(&help, "help", "", "")
	flag.Parse()
	if help == "" {
		fmt.Println("https://softscients.com\n\t\t-run {1,2} 1:enkripsi; 2:dekripsi\n\t\t-input file.doc\n\t\t-output file2.doc\n\t\t-key key.txt")
	}
	// check if cli params match
	if run == 1 || run == 2 {
		//cek semua lokasi file
		_, err1 := os.Stat(input)
		if err1 != nil {
			fmt.Println("input : ", input, " tidak ada!")
			return
		}
		_, err3 := os.Stat(key)
		if err3 != nil {
			fmt.Println("key : ", key, " tidak ada!")
			return
		}
		key_byte, _ := ioutil.ReadFile(key)
		if len(key_byte) != 16 {
			fmt.Println("key : ", key, " harus mempunyai ukuran 16 karakter!")
			return
		}
		fmt.Println("Proses")
		if run == 1 {
			//enkripsi
			if CekFile(input) == false { //artinya tidak ada heading
				//lakukan enkripsi
				EnkripsiFile(input, key, output)
				fmt.Println("Enkripsi selesai")
			} else {
				fmt.Println("Maaf, file sudah dilakukan enkripsi!")
			}
		} else {
			//dekripsi
			if CekFile(input) { //artinya ada enkripsi
				DekripsiFile(input, key, output)
				fmt.Println("Dekripsi selesai")
			} else {
				fmt.Println("Maaf, file tidak ada enkripsi!")
			}
		}
	} else {
		fmt.Printf("silahkan ketikan -run")
	}

}
func EnkripsiFile(file1 string, file_kunci string, file2 string) {
	plaintext, _ := ioutil.ReadFile(file1)
	key, _ := ioutil.ReadFile(file_kunci)
	enkrip_no_header := encrypt(plaintext, key) // enkripsi
	final_byte := AddHeading(enkrip_no_header)  //tambah AddHeading
	if file1 == file2 {
		os.Remove(file1) //hapus file1 dulu
	}
	ioutil.WriteFile(file2, []byte(final_byte), 777)
}

func DekripsiFile(file2 string, file_kunci string, file3 string) {
	key, _ := ioutil.ReadFile(file_kunci)
	plaintext2, _ := ioutil.ReadFile(file2)
	dekrip_heading := decrypt(plaintext2[JUMLAH_HEADING:len(plaintext2)], key) //buang heading nya dulu
	if file2 == file3 {
		os.Remove(file2) //hapus dulu saja
	}
	ioutil.WriteFile(file3, (dekrip_heading), 777)
}

func CekFile(file string) bool {
	plaintext, _ := ioutil.ReadFile(file)
	return CekHeading(plaintext)
}

func CekHeading(a []byte) bool {
	var batas int = JUMLAH_HEADING * int(NILAI_HEADING)
	var total int = 0
	for i := 0; i < JUMLAH_HEADING; i++ {
		total = total + int(a[i])
	}
	var cek bool = false
	if total == batas {
		cek = true
	}
	return cek
}

func AddHeading(b []byte) []byte {
	/*
		untuk menambahkan byte sebanyak JUMLAH_HEADING
	*/
	var a [JUMLAH_HEADING]byte
	for i := 0; i < JUMLAH_HEADING; i++ {
		a[i] = NILAI_HEADING
	}
	slice1 := a[:]                      //jadikan slice
	slice2 := b[:]                      //jadikan slice
	slice3 := append(slice1, slice2...) //lakukan append
	return []byte(slice3)               //balikan lagi ke array
}

func decrypt(cipherstring, keystring []byte) []byte {
	// Byte array of the string
	ciphertext := cipherstring //[]byte(cipherstring)
	// Key
	key := keystring //[]byte(keystring)
	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// Before even testing the decryption,
	// if the text is too small, then it is incorrect
	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}
	// Get the 16 byte IV
	iv := ciphertext[:aes.BlockSize]
	// Remove the IV from the ciphertext
	ciphertext = ciphertext[aes.BlockSize:]
	// Return a decrypted stream
	stream := cipher.NewCFBDecrypter(block, iv)
	// Decrypt bytes from ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)
	return (ciphertext)
}

func encrypt(plainstring, keystring []byte) []byte {
	// Byte array of the string
	plaintext := plainstring //[]byte(plainstring)
	// Key
	key := keystring //[]byte(keystring)
	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// Empty array of 16 + plaintext length
	// Include the IV at the beginning
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	// Slice of first 16 bytes
	iv := ciphertext[:aes.BlockSize]
	// Write 16 rand bytes to fill iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	// Return an encrypted stream
	stream := cipher.NewCFBEncrypter(block, iv)
	// Encrypt bytes from plaintext to ciphertext
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext
}
