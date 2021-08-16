package algorithm

import (
  "fmt"
  "strconv"
  "hash/fnv"
  "hash/crc32"
  "hash/crc64"
  "hash/adler32"
  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "crypto/sha512"
  "encoding/base32"
  "encoding/base64"

  "golang.org/x/crypto/md4"
  "golang.org/x/crypto/blake2s"
  "golang.org/x/crypto/blake2b"
  "golang.org/x/crypto/ripemd160"
  "golang.org/x/crypto/sha3"

  "github.com/cxmcc/tiger"
  "github.com/ebfe/keccak"
  "github.com/htruong/go-md2"
)

func FoundSHA3_224(input_string string) string {
  return fmt.Sprintf("SHA3_224 :: %x", sha3.Sum224([]byte(input_string)))
}

func FoundSHA3_256(input_string string) string {
  return fmt.Sprintf("SHA3_256 :: %x", sha3.Sum256([]byte(input_string)))
}

func FoundSHA3_384(input_string string) string {
  return fmt.Sprintf("SHA3_384 :: %x", sha3.Sum384([]byte(input_string)))
}

func FoundSHA3_512(input_string string) string {
  return fmt.Sprintf("SHA3_512 :: %x", sha3.Sum512([]byte(input_string)))
}

func FoundTIGER192(input_string string) string {
  f_tiger192 := tiger.New()
  f_tiger192.Write([]byte(input_string))
  return fmt.Sprintf("TIGER192,3 :: %x", f_tiger192.Sum(nil))
}

func FoundRIPEMD160(input_string string) string {
  f_ripemd := ripemd160.New()
  f_ripemd.Write([]byte(input_string))
  return fmt.Sprintf("RIPEMD160 :: %x", f_ripemd.Sum(nil))
}

func FoundBLAKE2s256(input_string string) string {
  return fmt.Sprintf("BLAKE2s256 :: %x", blake2s.Sum256([]byte(input_string)))
}

func FoundBLAKE2b256(input_string string) string {
  return fmt.Sprintf("BLAKE2b256 :: %x", blake2b.Sum256([]byte(input_string)))
}

func FoundBLAKE2b384(input_string string) string {
  return fmt.Sprintf("BLAKE2b384 :: %x", blake2b.Sum384([]byte(input_string)))
}

func FoundBLAKE2b512(input_string string) string {
  return fmt.Sprintf("BLAKE2b512 :: %x", blake2b.Sum512([]byte(input_string)))
}

func FoundKECCAK224(input_string string) string {
  newkeccak224 := keccak.New224()
  newkeccak224.Write([]byte(input_string))
  return fmt.Sprintf("KECCAK224 :: %x", newkeccak224.Sum(nil))
}

func FoundKECCAK256(input_string string) string {
  newkeccak256 := sha3.NewLegacyKeccak256()
  newkeccak256.Write([]byte(input_string))
  return fmt.Sprintf("KECCAK256 :: %x", newkeccak256.Sum(nil))
}

func FoundKECCAK384(input_string string) string {
  newkeccak384 := keccak.New384()
  newkeccak384.Write([]byte(input_string))
  return fmt.Sprintf("KECCAK384 :: %x", newkeccak384.Sum(nil))
}

func FoundKECCAK512(input_string string) string {
  newkeccak512 := sha3.NewLegacyKeccak512()
  newkeccak512.Write([]byte(input_string))
  return fmt.Sprintf("KECCAK512 :: %x", newkeccak512.Sum(nil))
}

func FoundADLER32(input_string string) string {
  f_adler32 := adler32.Checksum([]byte(input_string))
  return fmt.Sprintf("ADLER32 :: %s", strconv.FormatUint(uint64(f_adler32), 16))
}

func FoundCRC32ieee(input_string string) string {
  f_crc32ieee := crc32.ChecksumIEEE([]byte(input_string))
  return fmt.Sprintf("CRC32-ieee :: %s", strconv.FormatUint(uint64(f_crc32ieee), 16))
}

func FoundCRC64ecma(input_string string) string {
  f_crc64ecma := crc64.New(crc64.MakeTable(crc64.ECMA))
  f_crc64ecma.Write([]byte(input_string))
  return fmt.Sprintf("CRC64-ecma :: %x", f_crc64ecma.Sum(nil))
}

func FoundCRC64iso(input_string string) string {
  f_crc64iso := crc64.New(crc64.MakeTable(crc64.ISO))
  f_crc64iso.Write([]byte(input_string))
  return fmt.Sprintf("CRC64-iso :: %x", f_crc64iso.Sum(nil))
}

func FoundSHAKE128_224(input_string string) string {
  f_Shake128_224 := keccak.NewSHAKE128(28)
  f_Shake128_224.Write([]byte(input_string))
  return fmt.Sprintf("SHAKE128_224 :: %x", f_Shake128_224.Sum(nil))
}

func FoundSHAKE128_256(input_string string) string {
  f_Shake128_256 := keccak.NewSHAKE128(32)
  f_Shake128_256.Write([]byte(input_string))
  return fmt.Sprintf("SHAKE128_256 :: %x", f_Shake128_256.Sum(nil))
}

func FoundSHAKE128_384(input_string string) string {
  f_Shake128_384 := keccak.NewSHAKE128(48)
  f_Shake128_384.Write([]byte(input_string))
  return fmt.Sprintf("SHAKE128_384 :: %x", f_Shake128_384.Sum(nil))
}

func FoundSHAKE128_512(input_string string) string {
  f_Shake128_512 := keccak.NewSHAKE128(64)
  f_Shake128_512.Write([]byte(input_string))
  return fmt.Sprintf("SHAKE128_512 :: %x", f_Shake128_512.Sum(nil))
}

func FoundSHAKE256_224(input_string string) string {
  f_SHAKE256_224 := keccak.NewSHAKE256(28)
  f_SHAKE256_224.Write([]byte(input_string))
  return fmt.Sprintf("SHAKE256_224 :: %x", f_SHAKE256_224.Sum(nil))
}

func FoundSHAKE256_256(input_string string) string {
  f_SHAKE256_256 := keccak.NewSHAKE256(32)
  f_SHAKE256_256.Write([]byte(input_string))
  return fmt.Sprintf("SHAKE256_256 :: %x", f_SHAKE256_256.Sum(nil))
}

func FoundSHAKE256_384(input_string string) string {
  f_SHAKE256_384 := keccak.NewSHAKE256(48)
  f_SHAKE256_384.Write([]byte(input_string))
  return fmt.Sprintf("SHAKE256_384 :: %x", f_SHAKE256_384.Sum(nil))
}

func FoundSHAKE256_512(input_string string) string {
  f_SHAKE256_512 := keccak.NewSHAKE256(64)
  f_SHAKE256_512.Write([]byte(input_string))
  return fmt.Sprintf("SHAKE256_512 :: %x", f_SHAKE256_512.Sum(nil))
}

func FoundMD2(input_string string) string {
  f_MD2 := md2.New()
  f_MD2.Write([]byte(input_string))
  return fmt.Sprintf("MD2 :: %x", f_MD2.Sum([]byte(nil)))
}

func FoundMD4(input_string string) string {
  f_MD4 := md4.New()
  f_MD4.Write([]byte(input_string))
  return fmt.Sprintf("MD4 :: %x", f_MD4.Sum([]byte(nil)))
}

func FoundMD5(input_string string) string {
  return fmt.Sprintf("MD5 :: %x", md5.Sum([]byte(input_string)))
}

func FoundFNV32(input_string string) string {
  f_fnv32 := fnv.New32()
  f_fnv32.Write([]byte(input_string))
  return fmt.Sprintf("FNV32 :: %x", f_fnv32.Sum(nil))
}

func FoundFNV32a(input_string string) string {
  f_fnv32a := fnv.New32a()
  f_fnv32a.Write([]byte(input_string))
  return fmt.Sprintf("FNV32a :: %x", f_fnv32a.Sum(nil))
}

func FoundFNV64(input_string string) string {
  f_fnv64 := fnv.New64()
  f_fnv64.Write([]byte(input_string))
  return fmt.Sprintf("FNV64 :: %x", f_fnv64.Sum(nil))
}

func FoundFNV64a(input_string string) string {
  f_fnv64a := fnv.New64a()
  f_fnv64a.Write([]byte(input_string))
  return fmt.Sprintf("FNV64a :: %x", f_fnv64a.Sum(nil))
}

func FoundFNV128(input_string string) string {
  f_fnv128 := fnv.New128()
  f_fnv128.Write([]byte(input_string))
  return fmt.Sprintf("FNV128 :: %x", f_fnv128.Sum(nil))
}

func FoundFNV128a(input_string string) string {
  f_fnv128a := fnv.New128a()
  f_fnv128a.Write([]byte(input_string))
  return fmt.Sprintf("FNV128a :: %x", f_fnv128a.Sum(nil))
}

func FoundSHA1(input_string string) string {
  return fmt.Sprintf("SHA1 :: %x", sha1.Sum([]byte(input_string)))
}

func FoundSHA224(input_string string) string {
  return fmt.Sprintf("SHA224 :: %x", sha256.Sum224([]byte(input_string)))
}

func FoundSHA256(input_string string) string {
  return fmt.Sprintf("SHA256 :: %x", sha256.Sum256([]byte(input_string)))
}

func FoundSHA384(input_string string) string {
  return fmt.Sprintf("SHA384 :: %x", sha512.Sum384([]byte(input_string)))
}

func FoundSHA512(input_string string) string {
  return fmt.Sprintf("SHA512 :: %x", sha512.Sum512([]byte(input_string)))
}

func FoundSHA512_224(input_string string) string {
  return fmt.Sprintf("SHA512_224 :: %x", sha512.Sum512_224([]byte(input_string)))
}

func FoundSHA512_256(input_string string) string {
  return fmt.Sprintf("SHA512_256 :: %x", sha512.Sum512_256([]byte(input_string)))
}

func FoundBASE32(input_string string) string {
  return fmt.Sprintf("BASE32 :: %s", base32.StdEncoding.EncodeToString([]byte(input_string)))
}

func FoundBASE64(input_string string) string {
  return fmt.Sprintf("BASE64 :: %s", base64.StdEncoding.EncodeToString([]byte(input_string)))
}
