package srtp

const labelExtractorDtlsSrtp = "EXTRACTOR-dtls_srtp"
const labelExtractorSharedSrtp = "EXTRACTOR-shared_srtp"

// KeyingMaterialExporter allows package SRTP to extract keying material
type KeyingMaterialExporter interface {
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// ExtractSessionKeysFromDTLS allows setting the Config SessionKeys by
// extracting them from DTLS. This behavior is defined in RFC5764:
// https://tools.ietf.org/html/rfc5764
func (c *Config) ExtractSessionKeysFromDTLS(exporter KeyingMaterialExporter, isClient bool) error {
	keyLen, err := c.Profile.keyLen()
	if err != nil {
		return err
	}

	saltLen, err := c.Profile.saltLen()
	if err != nil {
		return err
	}

	keyingMaterial, err := exporter.ExportKeyingMaterial(labelExtractorDtlsSrtp, nil, (keyLen*2)+(saltLen*2))
	if err != nil {
		return err
	}

	offset := 0
	clientWriteKey := append([]byte{}, keyingMaterial[offset:offset+keyLen]...)
	offset += keyLen

	serverWriteKey := append([]byte{}, keyingMaterial[offset:offset+keyLen]...)
	offset += keyLen

	clientWriteKey = append(clientWriteKey, keyingMaterial[offset:offset+saltLen]...)
	offset += saltLen

	serverWriteKey = append(serverWriteKey, keyingMaterial[offset:offset+saltLen]...)

	if isClient {
		c.Keys.LocalMasterKey = clientWriteKey[0:keyLen]
		c.Keys.LocalMasterSalt = clientWriteKey[keyLen:]
		c.Keys.RemoteMasterKey = serverWriteKey[0:keyLen]
		c.Keys.RemoteMasterSalt = serverWriteKey[keyLen:]
		return nil
	}

	c.Keys.LocalMasterKey = serverWriteKey[0:keyLen]
	c.Keys.LocalMasterSalt = serverWriteKey[keyLen:]
	c.Keys.RemoteMasterKey = clientWriteKey[0:keyLen]
	c.Keys.RemoteMasterSalt = clientWriteKey[keyLen:]
	return nil
}

func (c *Config) ExtractSessionKeysFromShared(exporter KeyingMaterialExporter) error {
	keyLen, err := c.Profile.keyLen()
	if err != nil {
		return err
	}

	saltLen, err := c.Profile.saltLen()
	if err != nil {
		return err
	}

	keyingMaterial, err := exporter.ExportKeyingMaterial(labelExtractorSharedSrtp, nil, keyLen+saltLen)
	if err != nil {
		return err
	}

	key := append([]byte{}, keyingMaterial[0:keyLen]...)
	salt := append([]byte{}, keyingMaterial[keyLen:keyLen+saltLen]...)

	c.Keys.LocalMasterKey = key
	c.Keys.LocalMasterSalt = salt
	c.Keys.RemoteMasterKey = key
	c.Keys.RemoteMasterSalt = salt

	return nil
}
