package jcs

import (
	"math"
	"testing"
)

// Vectors from RFC 8785, section 3.2.2.3 and appendix B.
func TestNumbers(t *testing.T) {
	cases := map[float64]string{
		0:                      "0",
		math.Copysign(0, -1):   "0",
		1:                      "1",
		-1:                     "-1",
		4.5:                    "4.5",
		0.002:                  "0.002",
		1e30:                   "1e+30",
		1e21:                   "1e+21",
		1e20:                   "100000000000000000000",
		1e-27:                  "1e-27",
		1e-7:                   "1e-7",
		1e-6:                   "0.000001",
		333333333.33333329:     "333333333.3333333",
		9007199254740992:       "9007199254740992",
		295147905179352830000:  "295147905179352830000",
		5e-324:                 "5e-324",
		1.7976931348623157e308: "1.7976931348623157e+308",
		-1.5e-10:               "-1.5e-10",
		123456789012345680000:  "123456789012345680000",
	}
	for in, want := range cases {
		got, err := FormatNumber(in)
		if err != nil || got != want {
			t.Errorf("FormatNumber(%v) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := FormatNumber(math.NaN()); err == nil {
		t.Error("NaN accepted")
	}
}

func TestCanonicalize(t *testing.T) {
	cases := map[string]string{
		// RFC 8785 section 3.2.4 example.
		`{
		  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
		  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
		  "literals": [null, true, false]
		}`: `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		// Sorting by UTF-16 code units (RFC 8785 section 3.2.3 example).
		`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`: "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		`[ 1 , {"b":{"d":1,"c":[]},"a":"x"} ]`: `[1,{"a":"x","b":{"c":[],"d":1}}]`,
	}
	for in, want := range cases {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("Canonicalize(%s)\n got %s (%v)\nwant %s", in, got, err, want)
		}
	}
	for _, bad := range []string{`{`, `{} {}`, `[1,]`} {
		if _, err := Canonicalize([]byte(bad)); err == nil {
			t.Errorf("Canonicalize(%s) succeeded", bad)
		}
	}
}

func TestMarshal(t *testing.T) {
	got, err := Marshal(map[string]any{"z": 1.0, "a": []int{3, 2}})
	if err != nil || string(got) != `{"a":[3,2],"z":1}` {
		t.Errorf("got %s, %v", got, err)
	}
}
