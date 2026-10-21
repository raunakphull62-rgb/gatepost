// Password unit test: round-trip and rejection (no DB needed).
package password

import "testing"

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(h, "correct horse battery staple")
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	ok, _ = Verify(h, "wrong horse")
	if ok {
		t.Fatal("wrong password verified")
	}
	ok, _ = Verify(h, "different length key")
	if ok {
		t.Fatal("different-length password verified")
	}
}
