package output

import (
  "os"
  "testing"
)

var (
  input  = "input"
  create = "create.txt"
)

func TestFile(t *testing.T) {
  CreateAndSave(input, create)

  if _, err := os.Stat(create); err != nil {
    if os.IsNotExist(err) {
      t.Errorf("File '%v' not found", create)
    }
  } else {
    t.Logf("found '%v' file", create)
    os.Remove(create)
  }
}
