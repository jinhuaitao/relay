// crypto.go — 云备份的加密原语：scrypt 派生密钥 + AES-256-GCM 认证加密
//
// 备份内容即使被第三方（Telegram / 对象存储）拿到，也无法在没有口令的情况下读取，
// 且任何篡改都会在解密时被 GCM 的认证标签检出。

package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// deriveBackupKey 用 scrypt 把口令扩展为 32 字节密钥。
// 参数 N=1<<15 / r=8 / p=1 约消耗 32MB 内存，对单机备份足够且不会明显拖慢面板。
func deriveBackupKey(passphrase string, salt []byte) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("备份口令为空")
	}
	return scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, BackupKeySize)
}

// encryptBackup 输出格式：magic | salt | nonce | ciphertext+tag
func encryptBackup(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, BackupSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := deriveBackupKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, BackupNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(BackupMagic)+len(salt)+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, []byte(BackupMagic)...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, []byte(BackupMagic))
	return out, nil
}

// decryptBackup 校验 magic 与 GCM 标签；口令错误或数据被改动都会返回错误。
func decryptBackup(data []byte, passphrase string) ([]byte, error) {
	head := len(BackupMagic) + BackupSaltSize + BackupNonceSize
	if len(data) < head+16 {
		return nil, errors.New("备份文件过短或格式不正确")
	}
	if subtle.ConstantTimeCompare(data[:len(BackupMagic)], []byte(BackupMagic)) != 1 {
		return nil, errors.New("不是 GoRelay 加密备份文件")
	}
	salt := data[len(BackupMagic) : len(BackupMagic)+BackupSaltSize]
	nonce := data[len(BackupMagic)+BackupSaltSize : head]
	ciphertext := data[head:]

	key, err := deriveBackupKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(BackupMagic))
	if err != nil {
		return nil, fmt.Errorf("解密失败：口令错误或文件已被篡改 (%w)", err)
	}
	return plain, nil
}
