// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package payload

import (
	"bytes"
	"encoding/gob"
	"io"
	"testing"

	"github.com/cilium/cilium/pkg/comparator"
	"github.com/pquerna/ffjson/ffjson"
	. "gopkg.in/check.v1"
)

func init() {
	var (
		err       error
		buf       bytes.Buffer
		jsonBytes []byte
	)

	buf.Reset()
	payloadEnc := gob.NewEncoder(&buf)
	if err = payloadEnc.Encode(&samplePayload); err != nil {
		panic(err)
	}
	gobEncodedPayload = append([]byte(nil), buf.Bytes()...)

	buf.Reset()
	sampleMeta.Size = uint32(len(gobEncodedPayload))
	metaEnc := gob.NewEncoder(&buf)
	if err = metaEnc.Encode(&sampleMeta); err != nil {
		panic(err)
	}
	gobEncodedMeta = append([]byte(nil), buf.Bytes()...)

	jsonBytes, err = ffjson.Marshal(&sampleMeta)
	if err != nil {
		panic(err)
	}
	jsonEncodedMeta = append([]byte(nil), jsonBytes...)

	jsonBytes, err = ffjson.Marshal(&samplePayload)
	if err != nil {
		panic(err)
	}
	jsonEncodedPayload = append([]byte(nil), jsonBytes...)
}

var (
	sampleMeta    = Meta{Size: 1234}
	samplePayload = Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	gobEncodedMeta     []byte
	gobEncodedPayload  []byte
	jsonEncodedMeta    []byte
	jsonEncodedPayload []byte
)

func Test(t *testing.T) { TestingT(t) }

type PayloadSuite struct{}

var _ = Suite(&PayloadSuite{})

func (s *PayloadSuite) TestMeta_UnMarshalBinary(c *C) {
	meta1 := Meta{Size: 1234}
	buf, err := meta1.MarshalBinary()
	c.Assert(err, Equals, nil)

	var meta2 Meta
	err = meta2.UnmarshalBinary(buf)
	c.Assert(err, Equals, nil)

	c.Assert(meta1, comparator.DeepEquals, meta2)
}

func (s *PayloadSuite) TestPayload_UnMarshalBinary(c *C) {
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}
	buf, err := payload1.Encode()
	c.Assert(err, Equals, nil)

	var payload2 Payload
	err = payload2.Decode(buf)
	c.Assert(err, Equals, nil)

	c.Assert(payload1, comparator.DeepEquals, payload2)
}

func (s *PayloadSuite) TestWriteReadMetaPayload(c *C) {
	meta1 := Meta{Size: 1234}
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	var buf bytes.Buffer
	err := WriteMetaPayload(&buf, &meta1, &payload1)
	c.Assert(err, Equals, nil)

	var meta2 Meta
	var payload2 Payload
	err = ReadMetaPayload(&buf, &meta2, &payload2)
	c.Assert(err, Equals, nil)

	c.Assert(meta1, comparator.DeepEquals, meta2)
	c.Assert(payload1, comparator.DeepEquals, payload2)
}

func BenchmarkWriteMetaPayload(b *testing.B) {
	meta := Meta{Size: 1234}
	pl := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	// Do a first dry run to pre-allocate the buffer capacity.
	var buf bytes.Buffer
	err := WriteMetaPayload(&buf, &meta, &pl)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		buf.Reset()
		err := WriteMetaPayload(&buf, &meta, &pl)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadMetaPayload(b *testing.B) {
	meta1 := Meta{Size: 1234}
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	var buf bytes.Buffer
	err := WriteMetaPayload(&buf, &meta1, &payload1)
	if err != nil {
		b.Fatal(err)
	}

	var meta2 Meta
	var payload2 Payload
	for i := 0; i < b.N; i++ {
		readBuf := bytes.NewBuffer(buf.Bytes())
		err = ReadMetaPayload(readBuf, &meta2, &payload2)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeMetaPayload(b *testing.B) {
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}

	for i := 0; i < b.N; i++ {
		_, err := payload1.Encode()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeMetaPayload(b *testing.B) {
	payload1 := Payload{
		Data: []byte{1, 2, 3, 4},
		Lost: 5243,
		CPU:  12,
		Type: 9,
	}
	buf, err := payload1.Encode()
	if err != nil {
		b.Fatal(err)
	}

	var payload2 Payload
	for i := 0; i < b.N; i++ {
		err = payload2.Decode(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMetaGobEncode(b *testing.B) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	for i := 0; i < b.N; i++ {
		buf.Reset()
		err := enc.Encode(&sampleMeta)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMetaGobDecode(b *testing.B) {
	reader := bytes.NewReader(gobEncodedMeta)

	var meta Meta
	for i := 0; i < b.N; i++ {
		if _, err := reader.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}
		dec := gob.NewDecoder(reader)
		if err := dec.Decode(&meta); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPayloadGobEncode(b *testing.B) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := enc.Encode(&samplePayload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPayloadGobDecode(b *testing.B) {
	reader := bytes.NewReader(gobEncodedPayload)

	var pl Payload
	for i := 0; i < b.N; i++ {
		if _, err := reader.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}
		dec := gob.NewDecoder(reader)
		if err := dec.Decode(&pl); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPayloadJsonEncode(b *testing.B) {
	var buf bytes.Buffer
	enc := ffjson.NewEncoder(&buf)
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := enc.Encode(&samplePayload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPayloadJsonDecode(b *testing.B) {
	dec := ffjson.NewDecoder()

	var pl Payload
	for i := 0; i < b.N; i++ {
		if err := dec.Decode(jsonEncodedPayload, &pl); err != nil {
			b.Fatal(err)
		}
	}
}
