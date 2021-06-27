package coronaqr

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// From https://github.com/eu-digital-green-certificates/dgc-testdata/blob/main/CH/png/1.png
const qr = `HC1:NCFK60DG0/3WUWGSLKH47GO0Y%5S.PK%96L79CK-500XK0JCV494F3TJMP:92F3%EQ*8QY50.FK6ZK7:EDOLOPCO8F6%E3.DA%EOPC1G72A6YM88G7ZA71S8WA7N46.G8DM8-Q6RG8I:66:63Y8WY8UPC0JCZ69FVCPD0LVC6JD846Y96C463W5307+EDG8F3I80/D6$CBECSUER:C2$NS346$C2%E9VC- CSUE145GB8JA5B$D% D3IA4W5646646-96:96.JCP9EJY8L/5M/5546.96SF63KC.SC4KCD3DX47B46IL6646H*6Z/ER2DD46JH8946JPCT3E5JDLA7$Q69464W51S6..DX%DZJC2/DYOA$$E5$C JC3/D9Z95LEZED1ECW.C8WE2OA3ZAGY8MPCG/DU2DRB8MTA8+9$PC5$CUZC $5Z$5FBBS20I8MRXI1VMCJCRM8BGJZ+FQ5G%V3H4RRC7L56BV5H3N6+9VDKW UU EI+K8KHAXSCMRBG0MEQCKGKBPEYIA2K8FB3MQ9Z875H06C+$53.CX3F4YFKAFUFC7/4$C98A2FPNFD8*MLTI3Z/BZ2IWT4 9L THNN1+9N89NMW306JNI353IG6U7:8GG7MFI$P9LWQ8UNOXPVJ7U*SWSOEDH4ES%3ULH2F*7K4F9V7RYSZ$7G U3BIZ3HE42RI19D2R9TYQ2WZ94LM0/MBO9 53OO0WLLRIAVXFD/VD5GI P/U8 HKPPTRADR+H3SC6KQAG4 HUPHFZPBK%50+3L:1065K/E91W*-D35SI%V3L3J%MO+4USO-AILPI4IMA.1Q0V0HVVV8P4`

func TestDecode(t *testing.T) {
	decoded, err := Decode(qr)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded.Cert
	want := CovidCert{
		Version: "1.2.1",
		PersonalName: Name{
			FamilyName:    "Studer",
			FamilyNameStd: "STUDER",
			GivenName:     "Martina",
			GivenNameStd:  "MARTINA",
		},
		DateOfBirth: "1964-03-14",
		VaccineRecords: []VaccineRecord{
			VaccineRecord{
				Target:        "840539006",
				Vaccine:       "J07BX03",
				Product:       "EU/1/20/1525",
				Manufacturer:  "ORG-100001417",
				Doses:         2,
				DoseSeries:    2,
				Date:          "2021-06-07",
				Country:       "CH",
				Issuer:        "Bundesamt für Gesundheit (BAG)",
				CertificateID: "urn:uvci:01:CH:79DD59A0ABBC341B37D78EEE",
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("unexpected Decode() output: diff (-want +got):\n%s", diff)
	}
}
