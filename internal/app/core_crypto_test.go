package app

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := []byte("GoRelay backup payload: 包含中文与二进制 \x00\x01 bytes")
	enc, err := encryptBackup(plain, "a-strong-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, plain) {
		t.Fatal("密文中出现明文")
	}
	dec, err := decryptBackup(enc, "a-strong-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatal("解密结果与原文不一致")
	}
}

func TestDecryptRejectsWrongPassphraseAndTampering(t *testing.T) {
	enc, err := encryptBackup([]byte("sensitive settings"), "right-pass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptBackup(enc, "wrong-pass"); err == nil {
		t.Fatal("错误口令必须解密失败")
	}
	tampered := append([]byte(nil), enc...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := decryptBackup(tampered, "right-pass"); err == nil {
		t.Fatal("被篡改的密文必须通过 GCM 校验失败")
	}
	if _, err := decryptBackup(enc[:10], "right-pass"); err == nil {
		t.Fatal("过短文件必须被拒绝")
	}
	badMagic := append([]byte(nil), enc...)
	copy(badMagic, "XXXXXXXXXX")
	if _, err := decryptBackup(badMagic, "right-pass"); err == nil {
		t.Fatal("错误 magic 必须被拒绝")
	}
}

func TestEncryptRejectsEmptyPassphrase(t *testing.T) {
	if _, err := encryptBackup([]byte("x"), ""); err == nil {
		t.Fatal("空口令不应生成备份")
	}
}
