package main

import (
  "log"
  "fmt"
  "flag"
  "io/ioutil"
  "strings"

  "github.com/vexilology/hashgosum/output"
)

var (
  isHelp        = flag.Bool("help", false, "help")
  saveResult    = flag.Bool("save", false, "save output")
  createFile    = flag.String("c", "", "create file")
  stringFound   = flag.String("s", "", "string")
  fileFound     = flag.String("f", "", "file")
  algorithmName = flag.String("a", "", "algorithm")
)

var algorithm_list = []string{
  "sha3_224", "sha3_256", "sha3_384", "sha3_512",
  "tiger192", "ripemd160", "adler32",
  "blake2s256", "blake2b256", "blake2b384", "blake2b512",
  "keccak224", "keccak256", "keccak384", "keccak512",
  "crc32ieee", "crc64ecma", "crc64iso",
  "shake128_224", "shake128_256", "shake128_384", "shake128_512",
  "shake256_224", "shake256_256", "shake256_384", "shake256_512",
  "md2", "md4", "md5",
  "fnv32", "fnv32a", "fnv64", "fnv64a", "fnv128", "fnv128a",
  "sha1", "sha224", "sha256", "sha384", "sha512",
  "sha512_224", "sha512_256",
  "base32", "base64",
}

const q_alert = "[!] Only use single quotes. Other quotes can cause errors. [!]"

func fileToString(foundFile string) string {
  f_file, err := ioutil.ReadFile(foundFile)
  if err != nil {
    log.Fatal("File not found.")
  }
  return string(f_file)
}

func main() {
  flag.Parse()

  if *isHelp {
    convert := strings.Join(algorithm_list, ", ")
    fmt.Printf("%s\n\n", q_alert)
    fmt.Println("Available:", convert)
    flag.PrintDefaults()
  } else if *fileFound != "" {
    if _, ok := h[*algorithmName]; ok {
      if *saveResult {
        output.CreateAndSave(h[*algorithmName](fileToString(*fileFound)), *createFile)
      } else {
        resultF := h[*algorithmName](fileToString(*fileFound))
        fmt.Println(resultF)
      }
    } else {
      log.Fatal("Unknown algorithm, try again.")
    }
  } else if *stringFound != "" {
    if _, ok := h[*algorithmName]; ok {
      if *saveResult {
        output.CreateAndSave(h[*algorithmName](*stringFound), *createFile)
      } else {
        resultS := h[*algorithmName](*stringFound)
        fmt.Println(resultS)
      }
    } else {
      log.Fatal("Unknown algorithm, try again.")
    }
  } else {
    log.Fatal("Empty message, try again.")
  }
}
