package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
)

const casesPerKind = 25

var kinds = []string{"v3.local", "v3.public", "v4.local", "v4.public"}

type tokenCase struct {
	Kind              string `json:"kind"`
	Key               string `json:"key"`
	Token             string `json:"token"`
	Footer            string `json:"footer"`
	ImplicitAssertion string `json:"implicit_assertion"`
	Data              string `json:"data"`
}

func main() {
	if len(os.Args) != 3 {
		fail("usage: go run . make|check <file>")
	}
	switch os.Args[1] {
	case "make":
		makeTokens(os.Args[2])
	case "check":
		checkTokens(os.Args[2])
	default:
		fail("unknown command " + os.Args[1])
	}
}

func makeTokens(path string) {
	var cases []tokenCase
	for _, kind := range kinds {
		for index := range casesPerKind {
			cases = append(cases, makeToken(kind, index))
		}
	}
	encoded, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		fail(err.Error())
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		fail(err.Error())
	}
	fmt.Printf("go-paseto made %d tokens\n", len(cases))
}

func makeToken(kind string, index int) tokenCase {
	now := time.Now()
	token := paseto.NewToken()
	token.SetIssuer("go-paseto")
	token.SetAudience("gaseto")
	token.SetSubject(fmt.Sprintf("user-%d", index))
	token.SetJti(fmt.Sprintf("interop-%d", index))
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetExpiration(now.Add(time.Hour))
	data := randomText(rand.IntN(600))
	token.SetString("data", data)
	footer := randomFooter(index)
	token.SetFooter([]byte(footer))
	implicitAssertion := randomText(rand.IntN(3) * 10)
	implicit := []byte(implicitAssertion)

	result := tokenCase{
		Kind:              kind,
		Footer:            footer,
		ImplicitAssertion: implicitAssertion,
		Data:              data,
	}
	switch kind {
	case "v3.local":
		key := paseto.NewV3SymmetricKey()
		result.Key, result.Token = key.ExportHex(), token.V3Encrypt(key, implicit)
	case "v3.public":
		key := paseto.NewV3AsymmetricSecretKey()
		result.Key, result.Token = key.Public().ExportHex(), token.V3Sign(key, implicit)
	case "v4.local":
		key := paseto.NewV4SymmetricKey()
		result.Key, result.Token = key.ExportHex(), token.V4Encrypt(key, implicit)
	case "v4.public":
		key := paseto.NewV4AsymmetricSecretKey()
		result.Key, result.Token = key.Public().ExportHex(), token.V4Sign(key, implicit)
	}
	return result
}

func checkTokens(path string) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		fail(err.Error())
	}
	var cases []tokenCase
	if err := json.Unmarshal(encoded, &cases); err != nil {
		fail(err.Error())
	}
	if len(cases) == 0 {
		fail("no tokens to check")
	}
	failures := 0
	for index, tokenCase := range cases {
		if err := checkToken(tokenCase); err != nil {
			failures++
			fmt.Printf("token %d (%s): %s\n", index, tokenCase.Kind, err)
		}
	}
	if failures > 0 {
		fail(fmt.Sprintf("go-paseto refused %d of %d tokens", failures, len(cases)))
	}
	fmt.Printf("go-paseto accepted all %d tokens\n", len(cases))
}

func checkToken(tokenCase tokenCase) error {
	parser := paseto.NewParser()
	parser.AddRule(paseto.IssuedBy("gaseto"), paseto.ForAudience("go-paseto"))
	implicit := []byte(tokenCase.ImplicitAssertion)

	var token *paseto.Token
	var err error
	switch tokenCase.Kind {
	case "v3.local":
		key, keyErr := paseto.V3SymmetricKeyFromHex(tokenCase.Key)
		if keyErr != nil {
			return keyErr
		}
		token, err = parser.ParseV3Local(key, tokenCase.Token, implicit)
	case "v3.public":
		key, keyErr := paseto.NewV3AsymmetricPublicKeyFromHex(tokenCase.Key)
		if keyErr != nil {
			return keyErr
		}
		token, err = parser.ParseV3Public(key, tokenCase.Token, implicit)
	case "v4.local":
		key, keyErr := paseto.V4SymmetricKeyFromHex(tokenCase.Key)
		if keyErr != nil {
			return keyErr
		}
		token, err = parser.ParseV4Local(key, tokenCase.Token, implicit)
	case "v4.public":
		key, keyErr := paseto.NewV4AsymmetricPublicKeyFromHex(tokenCase.Key)
		if keyErr != nil {
			return keyErr
		}
		token, err = parser.ParseV4Public(key, tokenCase.Token, implicit)
	default:
		return fmt.Errorf("unknown kind")
	}
	if err != nil {
		return err
	}
	data, err := token.GetString("data")
	if err != nil {
		return err
	}
	if data != tokenCase.Data {
		return fmt.Errorf("data claim is %q, expected %q", data, tokenCase.Data)
	}
	if string(token.Footer()) != tokenCase.Footer {
		return fmt.Errorf("footer is %q, expected %q", token.Footer(), tokenCase.Footer)
	}
	return nil
}

var characters = []rune("abcXYZ019 \"\\/\n\t<>&'é€😀 ")

func randomText(length int) string {
	var builder strings.Builder
	for range length {
		builder.WriteRune(characters[rand.IntN(len(characters))])
	}
	return builder.String()
}

func randomFooter(index int) string {
	if index%2 == 0 {
		return ""
	}
	return fmt.Sprintf(`{"kid":"go-key-%d"}`, index)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
