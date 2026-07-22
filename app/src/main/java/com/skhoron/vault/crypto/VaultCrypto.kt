package com.skhoron.vault.crypto

import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.SecureRandom

/**
 * VaultCrypto — ядро шифрования Skhoron Vault.
 *
 * АРХИТЕКТУРНЫЙ ИНВАРИАНТ: этот пакет (vault.crypto) не содержит и не должен
 * содержать сетевых вызовов. Проверяется CI-lint шагом (см. README.md).
 *
 * masterKey существует только в оперативной памяти, никогда не сериализуется
 * на диск. zeroize() вызывается при блокировке vault'а.
 *
 * Реализация на чистом BouncyCastle (JVM), без нативного Rust-кода — это
 * сознательный компромисс для быстрой сборки в Android Studio без NDK.
 * У чистого JVM есть ограничение: GC может скопировать байты массива до того,
 * как мы вызовем fill(0). Для продакшен-версии рекомендуется миграция на
 * Rust-крейт (например, существующий smn-crypto-core) через UniFFI —
 * тогда zeroize гарантирован на уровне памяти процесса.
 */

object Argon2Params {
    const val MEMORY_KB = 65536   // 64 MB
    const val ITERATIONS = 3
    const val PARALLELISM = 4
    const val SALT_LEN = 16
    const val KEY_LEN = 32        // 256 бит
    const val NONCE_LEN = 12      // BC ChaCha20Poly1305 API работает с 12-байтовым nonce (RFC 7539)
}

class DerivedKey(val keyBytes: ByteArray, val salt: ByteArray) {
    fun zeroize() { keyBytes.fill(0) }
}

data class EncryptedBlob(val ciphertext: ByteArray, val nonce: ByteArray)

class VaultCryptoException(message: String, cause: Throwable? = null) : Exception(message, cause)

class VaultCrypto {

    private val secureRandom = SecureRandom()

    fun generateSalt(): ByteArray = ByteArray(Argon2Params.SALT_LEN).also { secureRandom.nextBytes(it) }

    fun generateNonce(): ByteArray = ByteArray(Argon2Params.NONCE_LEN).also { secureRandom.nextBytes(it) }

    /** Argon2id: пароль юзера + соль -> 256-битный ключ. Работает в фоновом потоке
     *  (вызывающая сторона должна использовать Dispatchers.Default, т.к. это ~0.5-1.5 сек). */
    fun deriveMasterKey(password: ByteArray, salt: ByteArray): DerivedKey {
        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(Argon2Params.ITERATIONS)
            .withMemoryAsKB(Argon2Params.MEMORY_KB)
            .withParallelism(Argon2Params.PARALLELISM)
            .withSalt(salt)

        val generator = Argon2BytesGenerator()
        generator.init(builder.build())

        val out = ByteArray(Argon2Params.KEY_LEN)
        generator.generateBytes(password, out)
        return DerivedKey(out, salt)
    }

    /** Шифрует данные записи. aad (например, entryId) защищён от подмены, но не шифруется. */
    fun encryptEntry(masterKey: DerivedKey, plaintext: ByteArray, aad: ByteArray? = null): EncryptedBlob {
        val nonce = generateNonce()
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(masterKey.keyBytes), 128, nonce, aad))

        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var len = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        try {
            len += cipher.doFinal(out, len)
        } catch (e: Exception) {
            throw VaultCryptoException("Ошибка шифрования записи", e)
        }
        return EncryptedBlob(out.copyOf(len), nonce)
    }

    /** Расшифровывает запись. Бросает VaultCryptoException при неверном мастер-пароле
     *  или при попытке подмены ciphertext (Poly1305 tag mismatch). */
    fun decryptEntry(masterKey: DerivedKey, blob: EncryptedBlob, aad: ByteArray? = null): ByteArray {
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(masterKey.keyBytes), 128, blob.nonce, aad))

        val out = ByteArray(cipher.getOutputSize(blob.ciphertext.size))
        var len = cipher.processBytes(blob.ciphertext, 0, blob.ciphertext.size, out, 0)
        try {
            len += cipher.doFinal(out, len)
        } catch (e: Exception) {
            throw VaultCryptoException("Неверный мастер-пароль или повреждённые данные", e)
        }
        return out.copyOf(len)
    }
}