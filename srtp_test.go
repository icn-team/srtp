package srtp

import (
	"bytes"
	"errors"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

const (
	profileCTR  = ProtectionProfileAes128CmHmacSha1_80
	profileGCM  = ProtectionProfileAeadAes128Gcm
	defaultSsrc = 0
)

type rtpTestCase struct {
	sequenceNumber uint16
	encryptedCTR   []byte
	encryptedGCM   []byte
}

func (tc rtpTestCase) encrypted(profile ProtectionProfile) []byte {
	switch profile {
	case profileCTR:
		return tc.encryptedCTR
	case profileGCM:
		return tc.encryptedGCM
	default:
		panic("unknown profile")
	}
}

func testKeyLen(t *testing.T, profile ProtectionProfile) {
	keyLen, err := profile.keyLen()
	assert.NoError(t, err)

	saltLen, err := profile.saltLen()
	assert.NoError(t, err)

	if _, err := CreateContext([]byte{}, make([]byte, saltLen), profile); err == nil {
		t.Errorf("CreateContext accepted a 0 length key")
	}

	if _, err := CreateContext(make([]byte, keyLen), []byte{}, profile); err == nil {
		t.Errorf("CreateContext accepted a 0 length salt")
	}

	if _, err := CreateContext(make([]byte, keyLen), make([]byte, saltLen), profile); err != nil {
		t.Errorf("CreateContext failed with a valid length key and salt: %v", err)
	}
}

func TestKeyLen(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testKeyLen(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testKeyLen(t, profileGCM) })
}

func TestValidPacketCounter(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	srtpSessionSalt, err := aesCmKeyDerivation(labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt))
	assert.NoError(t, err)

	s := &srtpSSRCState{ssrc: 4160032510}
	counter := generateCounter(32846, uint32(s.index>>16), s.ssrc, srtpSessionSalt)
	if !bytes.Equal(srtpSessionSalt, counter[:len(srtpSessionSalt)]) {
		t.Errorf("Session Key % 02x does not match expected % 02x", counter[:len(srtpSessionSalt)], srtpSessionSalt)
	}
}

func TestRolloverCount(t *testing.T) {
	s := &srtpSSRCState{ssrc: defaultSsrc}

	// Set initial seqnum
	roc, diff, ovf := s.nextRolloverCount(65530)
	if roc != 0 {
		t.Errorf("Initial rolloverCounter must be 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65530, diff)

	// Invalid packets never update ROC
	s.nextRolloverCount(0)
	s.nextRolloverCount(0x4000)
	s.nextRolloverCount(0x8000)
	s.nextRolloverCount(0xFFFF)
	s.nextRolloverCount(0)

	// We rolled over to 0
	roc, diff, ovf = s.nextRolloverCount(0)
	if roc != 1 {
		t.Errorf("rolloverCounter was not updated after it crossed 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(0, diff)

	roc, diff, ovf = s.nextRolloverCount(65530)
	if roc != 0 {
		t.Errorf("rolloverCounter was not updated when it rolled back, failed to handle out of order")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65530, diff)

	roc, diff, ovf = s.nextRolloverCount(5)
	if roc != 1 {
		t.Errorf("rolloverCounter was not updated when it rolled over initial, to handle out of order")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(5, diff)

	_, diff, _ = s.nextRolloverCount(6)
	s.updateRolloverCount(6, diff)
	_, diff, _ = s.nextRolloverCount(7)
	s.updateRolloverCount(7, diff)
	roc, diff, _ = s.nextRolloverCount(8)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	s.updateRolloverCount(8, diff)

	// valid packets never update ROC
	roc, diff, ovf = s.nextRolloverCount(0x4000)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(0x4000, diff)
	roc, diff, ovf = s.nextRolloverCount(0x8000)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(0x8000, diff)
	roc, diff, ovf = s.nextRolloverCount(0xFFFF)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(0xFFFF, diff)
	roc, _, ovf = s.nextRolloverCount(0)
	if roc != 2 {
		t.Errorf("rolloverCounter must be incremented after wrapping, got %d", roc)
	}
	if ovf {
		t.Error("Should not overflow")
	}
}

func TestRolloverCountOverflow(t *testing.T) {
	s := &srtpSSRCState{
		ssrc:  defaultSsrc,
		index: maxROC << 16,
	}
	s.updateRolloverCount(0xFFFF, 0)
	_, _, ovf := s.nextRolloverCount(0)
	if !ovf {
		t.Error("Should overflow")
	}
}

func buildTestContext(profile ProtectionProfile, opts ...ContextOption) (*Context, error) {
	keyLen, err := profile.keyLen()
	if err != nil {
		return nil, err
	}
	saltLen, err := profile.saltLen()
	if err != nil {
		return nil, err
	}

	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterKey = masterKey[:keyLen]
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}
	masterSalt = masterSalt[:saltLen]

	return CreateContext(masterKey, masterSalt, profile, opts...)
}

func TestRTPInvalidAuth(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	invalidSalt := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	encryptContext, err := buildTestContext(profileCTR)
	if err != nil {
		t.Fatal(err)
	}

	invalidContext, err := CreateContext(masterKey, invalidSalt, profileCTR)
	if err != nil {
		t.Errorf("CreateContext failed: %v", err)
	}

	for _, testCase := range rtpTestCases() {
		pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		pktRaw, err := pkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		out, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := invalidContext.DecryptRTP(nil, out, nil); err == nil {
			t.Errorf("Managed to decrypt with incorrect salt for packet with SeqNum: %d", testCase.sequenceNumber)
		}
	}
}

func rtpTestCaseDecrypted() []byte { return []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05} }

func rtpTestCases() []rtpTestCase {
	return []rtpTestCase{
		{
			sequenceNumber: 5000,
			encryptedCTR:   []byte{0x10, 0x85, 0x4b, 0xfb, 0x4d, 0x70, 0xef, 0x9c, 0x1c, 0x65, 0xa0, 0x54, 0x34, 0x13, 0x90, 0x5d},
			encryptedGCM:   []byte{0x9a, 0x41, 0x9f, 0x44, 0x25, 0xb9, 0x6c, 0xdf, 0xe0, 0xb1, 0x5f, 0xd5, 0xd4, 0x2f, 0x10, 0x20, 0x48, 0x4, 0xe, 0x3d, 0x0, 0xd9},
		},
		{
			sequenceNumber: 5001,
			encryptedCTR:   []byte{0x10, 0x85, 0x4b, 0xfb, 0x4d, 0x70, 0xc1, 0x57, 0xed, 0x79, 0x0e, 0x83, 0x4f, 0x0a, 0x30, 0x8b},
			encryptedGCM:   []byte{0x9a, 0x41, 0x9f, 0x44, 0x25, 0xb9, 0x99, 0x5a, 0xf2, 0x34, 0xf2, 0x1a, 0x77, 0xb, 0x8c, 0xb0, 0xce, 0xe7, 0x65, 0x5f, 0x97, 0xdb},
		},
		{
			sequenceNumber: 5002,
			encryptedCTR:   []byte{0x10, 0x85, 0x4b, 0xfb, 0x4d, 0x70, 0x4c, 0xb2, 0x46, 0x94, 0x0e, 0x65, 0x1d, 0x68, 0x0e, 0xd1},
			encryptedGCM:   []byte{0x9a, 0x41, 0x9f, 0x44, 0x25, 0xb9, 0x45, 0xd5, 0xc5, 0xba, 0x4, 0x4a, 0x92, 0x66, 0x29, 0x1, 0x45, 0xc2, 0xd8, 0xf8, 0x2e, 0xdc},
		},
		{
			sequenceNumber: 5003,
			encryptedCTR:   []byte{0x10, 0x85, 0x4b, 0xfb, 0x4d, 0x70, 0x3f, 0x01, 0xb5, 0x90, 0x67, 0x46, 0xe5, 0x51, 0xbb, 0x02},
			encryptedGCM:   []byte{0x9a, 0x41, 0x9f, 0x44, 0x25, 0xb9, 0xb0, 0x50, 0xd7, 0x3f, 0xa9, 0x85, 0x31, 0x42, 0xb5, 0x91, 0xc3, 0x21, 0xb3, 0x9a, 0xb9, 0xde},
		},
		{
			sequenceNumber: 5004,
			encryptedCTR:   []byte{0x10, 0x85, 0x4b, 0xfb, 0x4d, 0x70, 0x44, 0xee, 0x91, 0x13, 0xc2, 0x7f, 0xbc, 0xa3, 0xc2, 0xe3},
			encryptedGCM:   []byte{0x9a, 0x41, 0x9f, 0x44, 0x25, 0xb9, 0x3e, 0xcb, 0xaa, 0xa7, 0xe8, 0xeb, 0x58, 0xbd, 0x62, 0x62, 0x53, 0x89, 0xa3, 0xb7, 0x5c, 0xd3},
		},
		{
			sequenceNumber: 65535, // upper boundary
			encryptedCTR:   []byte{0x10, 0x85, 0x4b, 0xfb, 0x4d, 0x70, 0xde, 0xf2, 0x8b, 0xd6, 0x13, 0x6c, 0x4d, 0xa1, 0x98, 0x1e},
			encryptedGCM:   []byte{0x9a, 0x41, 0x9f, 0x44, 0x25, 0xb9, 0x2, 0x9e, 0x77, 0x59, 0x86, 0xf7, 0x6e, 0x45, 0xc, 0xd3, 0x46, 0xde, 0x3e, 0x8b, 0x11, 0xc9},
		},
	}
}

func testRTPLifecyleNewAlloc(t *testing.T, profile ProtectionProfile) {
	assert := assert.New(t)

	authTagLen, err := profile.rtpAuthTagLen()
	assert.NoError(err)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted(profile), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		actualEncrypted, err := encryptContext.EncryptRTP(nil, decryptedRaw, nil)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equalf(encryptedRaw, actualEncrypted, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		actualDecrypted, err := decryptContext.DecryptRTP(nil, encryptedRaw, nil)
		if err != nil {
			t.Fatal(err)
		} else if bytes.Equal(encryptedRaw[:len(encryptedRaw)-authTagLen], actualDecrypted) {
			t.Fatal("DecryptRTP improperly encrypted in place")
		}

		assert.Equalf(decryptedRaw, actualDecrypted, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)
	}
}

func TestRTPLifecycleNewAlloc(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPLifecyleNewAlloc(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPLifecyleNewAlloc(t, profileGCM) })
}

func testRTPLifecyleInPlace(t *testing.T, profile ProtectionProfile) {
	assert := assert.New(t)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptHeader := &rtp.Header{}
		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptHeader := &rtp.Header{}
		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted(profile), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		// Copy packet, asserts that everything was done in place
		slack := 10
		if profile == profileGCM {
			slack = 16
		}
		encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+slack)
		copy(encryptInput, decryptedRaw)

		actualEncrypted, err := encryptContext.EncryptRTP(encryptInput, encryptInput, encryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &encryptInput[0] != &actualEncrypted[0]:
			t.Errorf("EncryptRTP failed to encrypt in place")
		case encryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Errorf("EncryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualEncrypted, encryptedRaw, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		// Copy packet, asserts that everything was done in place
		decryptInput := make([]byte, len(encryptedRaw))
		copy(decryptInput, encryptedRaw)

		actualDecrypted, err := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &decryptInput[0] != &actualDecrypted[0]:
			t.Errorf("DecryptRTP failed to decrypt in place")
		case decryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Errorf("DecryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualDecrypted, decryptedRaw, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)
	}
}

func TestRTPLifecycleInPlace(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPLifecyleInPlace(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPLifecyleInPlace(t, profileGCM) })
}

func testRTPReplayProtection(t *testing.T, profile ProtectionProfile) {
	assert := assert.New(t)

	for _, testCase := range rtpTestCases() {
		encryptContext, err := buildTestContext(profile)
		if err != nil {
			t.Fatal(err)
		}

		decryptContext, err := buildTestContext(
			profile, SRTPReplayProtection(64),
		)
		if err != nil {
			t.Fatal(err)
		}

		decryptHeader := &rtp.Header{}
		decryptedPkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		decryptedRaw, err := decryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		encryptHeader := &rtp.Header{}
		encryptedPkt := &rtp.Packet{Payload: testCase.encrypted(profile), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
		encryptedRaw, err := encryptedPkt.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		// Copy packet, asserts that everything was done in place
		slack := 10
		if profile == profileGCM {
			slack = 16
		}
		encryptInput := make([]byte, len(decryptedRaw), len(decryptedRaw)+slack)
		copy(encryptInput, decryptedRaw)

		actualEncrypted, err := encryptContext.EncryptRTP(encryptInput, encryptInput, encryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &encryptInput[0] != &actualEncrypted[0]:
			t.Errorf("EncryptRTP failed to encrypt in place")
		case encryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Fatal("EncryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualEncrypted, encryptedRaw, "RTP packet with SeqNum invalid encryption: %d", testCase.sequenceNumber)

		// Copy packet, asserts that everything was done in place
		decryptInput := make([]byte, len(encryptedRaw))
		copy(decryptInput, encryptedRaw)

		actualDecrypted, err := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		switch {
		case err != nil:
			t.Fatal(err)
		case &decryptInput[0] != &actualDecrypted[0]:
			t.Errorf("DecryptRTP failed to decrypt in place")
		case decryptHeader.SequenceNumber != testCase.sequenceNumber:
			t.Errorf("DecryptRTP failed to populate input rtp.Header")
		}
		assert.Equalf(actualDecrypted, decryptedRaw, "RTP packet with SeqNum invalid decryption: %d", testCase.sequenceNumber)

		_, errReplay := decryptContext.DecryptRTP(decryptInput, decryptInput, decryptHeader)
		if !errors.Is(errReplay, errDuplicated) {
			t.Errorf("Replayed packet must be errored with %v, got %v", errDuplicated, errReplay)
		}
	}
}

func TestRTPReplayProtection(t *testing.T) {
	t.Run("CTR", func(t *testing.T) { testRTPReplayProtection(t, profileCTR) })
	t.Run("GCM", func(t *testing.T) { testRTPReplayProtection(t, profileGCM) })
}

func benchmarkEncryptRTP(b *testing.B, profile ProtectionProfile, size int) {
	encryptContext, err := buildTestContext(profile)
	if err != nil {
		b.Fatal(err)
	}

	pkt := &rtp.Packet{Payload: make([]byte, size)}
	pktRaw, err := pkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(pktRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err = encryptContext.EncryptRTP(nil, pktRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptRTP(b *testing.B) {
	b.Run("CTR-100", func(b *testing.B) {
		benchmarkEncryptRTP(b, profileCTR, 100)
	})
	b.Run("CTR-1000", func(b *testing.B) {
		benchmarkEncryptRTP(b, profileCTR, 1000)
	})
	b.Run("GCM-100", func(b *testing.B) {
		benchmarkEncryptRTP(b, profileGCM, 100)
	})
	b.Run("GCM-1000", func(b *testing.B) {
		benchmarkEncryptRTP(b, profileGCM, 1000)
	})
}

func benchmarkEncryptRTPInPlace(b *testing.B, profile ProtectionProfile, size int) {
	encryptContext, err := buildTestContext(profile)
	if err != nil {
		b.Fatal(err)
	}

	pkt := &rtp.Packet{Payload: make([]byte, size)}
	pktRaw, err := pkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	buf := make([]byte, 0, len(pktRaw)+10)

	b.SetBytes(int64(len(pktRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf, err = encryptContext.EncryptRTP(buf[:0], pktRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptRTPInPlace(b *testing.B) {
	b.Run("CTR-100", func(b *testing.B) {
		benchmarkEncryptRTPInPlace(b, profileCTR, 100)
	})
	b.Run("CTR-1000", func(b *testing.B) {
		benchmarkEncryptRTPInPlace(b, profileCTR, 1000)
	})
	b.Run("GCM-100", func(b *testing.B) {
		benchmarkEncryptRTPInPlace(b, profileGCM, 100)
	})
	b.Run("GCM-1000", func(b *testing.B) {
		benchmarkEncryptRTPInPlace(b, profileGCM, 1000)
	})
}

func benchmarkDecryptRTP(b *testing.B, profile ProtectionProfile) {
	sequenceNumber := uint16(5000)
	encrypted := rtpTestCases()[0].encrypted(profile)

	encryptedPkt := &rtp.Packet{
		Payload: encrypted,
		Header: rtp.Header{
			SequenceNumber: sequenceNumber,
		},
	}

	encryptedRaw, err := encryptedPkt.Marshal()
	if err != nil {
		b.Fatal(err)
	}

	context, err := buildTestContext(profile)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(len(encryptedRaw)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := context.DecryptRTP(nil, encryptedRaw, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptRTP(b *testing.B) {
	b.Run("CTR", func(b *testing.B) { benchmarkDecryptRTP(b, profileCTR) })
	b.Run("GCM", func(b *testing.B) { benchmarkDecryptRTP(b, profileGCM) })
}

func TestRolloverCount2(t *testing.T) {
	s := &srtpSSRCState{ssrc: defaultSsrc}

	roc, diff, ovf := s.nextRolloverCount(30123)
	if roc != 0 {
		t.Errorf("Initial rolloverCounter must be 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(30123, diff)

	roc, diff, ovf = s.nextRolloverCount(62892) // 30123 + (1 << 15) + 1
	if roc != 0 {
		t.Errorf("Initial rolloverCounter must be 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(62892, diff)
	roc, diff, ovf = s.nextRolloverCount(204)
	if roc != 1 {
		t.Errorf("rolloverCounter was not updated after it crossed 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(62892, diff)
	roc, diff, ovf = s.nextRolloverCount(64535)
	if roc != 0 {
		t.Errorf("rolloverCounter was not updated when it rolled back, failed to handle out of order")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(64535, diff)
	roc, diff, ovf = s.nextRolloverCount(205)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(205, diff)
	roc, diff, ovf = s.nextRolloverCount(1)
	if roc != 1 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(1, diff)

	roc, diff, ovf = s.nextRolloverCount(64532)
	if roc != 0 {
		t.Errorf("rolloverCounter was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(64532, diff)
	roc, diff, ovf = s.nextRolloverCount(65534)
	if roc != 0 {
		t.Errorf("index was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65534, diff)
	roc, diff, ovf = s.nextRolloverCount(64532)
	if roc != 0 {
		t.Errorf("index was improperly updated for non-significant packets")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65532, diff)
	roc, diff, ovf = s.nextRolloverCount(205)
	if roc != 1 {
		t.Errorf("index was not updated after it crossed 0")
	}
	if ovf {
		t.Error("Should not overflow")
	}
	s.updateRolloverCount(65532, diff)
}

func TestProtectionProfileAes128CmHmacSha1_32(t *testing.T) {
	masterKey := []byte{0x0d, 0xcd, 0x21, 0x3e, 0x4c, 0xbc, 0xf2, 0x8f, 0x01, 0x7f, 0x69, 0x94, 0x40, 0x1e, 0x28, 0x89}
	masterSalt := []byte{0x62, 0x77, 0x60, 0x38, 0xc0, 0x6d, 0xc9, 0x41, 0x9f, 0x6d, 0xd9, 0x43, 0x3e, 0x7c}

	encryptContext, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
	if err != nil {
		t.Fatal(err)
	}

	decryptContext, err := CreateContext(masterKey, masterSalt, ProtectionProfileAes128CmHmacSha1_32)
	if err != nil {
		t.Fatal(err)
	}

	pkt := &rtp.Packet{Payload: rtpTestCaseDecrypted(), Header: rtp.Header{SequenceNumber: 5000}}
	pktRaw, err := pkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	out, err := encryptContext.EncryptRTP(nil, pktRaw, nil)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := decryptContext.DecryptRTP(nil, out, nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, pktRaw) {
		t.Errorf("Decrypted % 02x does not match original % 02x", decrypted, pktRaw)
	}
}

func TestRTPDecryptShotenedPacket(t *testing.T) {
	profiles := map[string]ProtectionProfile{
		"CTR": profileCTR,
		"GCM": profileGCM,
	}
	for name, profile := range profiles {
		profile := profile
		t.Run(name, func(t *testing.T) {
			for _, testCase := range rtpTestCases() {
				decryptContext, err := buildTestContext(profile)
				if err != nil {
					t.Fatal(err)
				}

				encryptedPkt := &rtp.Packet{Payload: testCase.encrypted(profile), Header: rtp.Header{SequenceNumber: testCase.sequenceNumber}}
				encryptedRaw, err := encryptedPkt.Marshal()
				if err != nil {
					t.Fatal(err)
				}

				for i := 1; i < len(encryptedRaw)-1; i++ {
					packet := encryptedRaw[:i]
					assert.NotPanics(t, func() {
						_, _ = decryptContext.DecryptRTP(nil, packet, nil)
					}, "Panic on length %d/%d", i, len(encryptedRaw))
				}
			}
		})
	}
}

func TestRTPMaxPackets(t *testing.T) {
	profiles := map[string]ProtectionProfile{
		"CTR": profileCTR,
		"GCM": profileGCM,
	}
	for name, profile := range profiles {
		profile := profile
		t.Run(name, func(t *testing.T) {
			context, err := buildTestContext(profile)
			if err != nil {
				t.Fatal(err)
			}

			context.SetROC(1, (1<<32)-1)

			pkt0 := &rtp.Packet{
				Header: rtp.Header{
					SSRC:           1,
					SequenceNumber: 0xffff,
				},
				Payload: []byte{0, 1},
			}
			raw0, err0 := pkt0.Marshal()
			if err0 != nil {
				t.Fatal(err0)
			}
			if _, errEnc := context.EncryptRTP(nil, raw0, nil); errEnc != nil {
				t.Fatal(errEnc)
			}

			pkt1 := &rtp.Packet{
				Header: rtp.Header{
					SSRC:           1,
					SequenceNumber: 0x0,
				},
				Payload: []byte{0, 1},
			}
			raw1, err1 := pkt1.Marshal()
			if err1 != nil {
				t.Fatal(err1)
			}
			if _, errEnc := context.EncryptRTP(nil, raw1, nil); !errors.Is(errEnc, errExceededMaxPackets) {
				t.Fatalf("Expected error '%v', got '%v'", errExceededMaxPackets, errEnc)
			}
		})
	}
}
