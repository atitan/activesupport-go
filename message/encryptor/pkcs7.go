package encryptor

func AddPKCS7Padding(src []byte, blockSize int) []byte {
	pad := blockSize - (len(src) % blockSize)

	for i := 0; i < pad; i++ {
		src = append(src, byte(pad))
	}

	return src
}

func RemovePKCS7Padding(src []byte) []byte {
	if len(src) == 0 {
		return src
	}

	pad := src[len(src)-1]

	return src[:len(src)-int(pad)]
}
