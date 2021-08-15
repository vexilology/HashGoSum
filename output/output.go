package output

import (
  "os"
  "fmt"
)

func CreateAndSave(input, create string) error {
  if create != "" {
    file, err := os.Create(create)
    if err != nil {
      return fmt.Errorf("%w", err)
    }

    _, err = file.WriteString(input)
    if err != nil {
      return fmt.Errorf("%w", err)
    }

    file.Close()
  } else {
    file, err := os.Create("log.txt")
    if err != nil {
      return fmt.Errorf("%w", err)
    }

    _, err = file.WriteString(input)
    if err != nil {
      return fmt.Errorf("%w", err)
    }

    file.Close()
  }

  return nil
}
