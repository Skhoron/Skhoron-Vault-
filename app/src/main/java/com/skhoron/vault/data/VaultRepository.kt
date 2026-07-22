package com.skhoron.vault.data

import android.content.Context
import android.net.Uri
import android.util.Base64
import com.skhoron.vault.crypto.DerivedKey
import com.skhoron.vault.crypto.EncryptedBlob
import com.skhoron.vault.crypto.VaultCrypto
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.util.UUID

sealed class UnlockResult {
    object Success : UnlockResult()
    object NoVaultYet : UnlockResult()
    data class WrongPassword(val attemptsLeft: Int) : UnlockResult()
    object WipedOut : UnlockResult()
    object VaultAlreadyExists : UnlockResult()
}

/**
 * Разделение ключей через HKDF (доменное разделение по контексту).
 * Компрометация одного подключа не даёт доступ ко второму слою защиты —
 * иначе "двойной слой шифрования" (SQLCipher + поля) был бы фикцией,
 * так как оба слоя опирались бы на один и тот же байтовый ключ.
 */
private object KeyContext {
    val SQLCIPHER = "skhoron-vault-sqlcipher-v1".toByteArray()
    val FIELD_ENCRYPTION = "skhoron-vault-field-encryption-v1".toByteArray()
}

private fun hkdfExpand(masterKeyBytes: ByteArray, context: ByteArray, outLen: Int = 32): ByteArray {
    val hkdf = HKDFBytesGenerator(SHA256Digest())
    hkdf.init(HKDFParameters(masterKeyBytes, null, context))
    val out = ByteArray(outLen)
    hkdf.generateBytes(out, 0, outLen)
    return out
}

data class DecryptedEntry(
    val id: String,
    val label: String,
    val username: String?,
    val password: String,
    val domainHint: String?
)

/**
 * VaultRepository — единственная точка входа для UI и AutofillService.
 * Держит master key только в памяти на время разблокированной сессии.
 * Работает с одним и тем же процессом ":vault" (см. AndroidManifest) —
 * MainActivity и SkhoronAutofillService используют общий инстанс через
 * SkhoronVaultApp, так как оба объявлены в этом процессе.
 *
 * АРХИТЕКТУРНЫЙ ИНВАРИАНТ: ни один метод этого класса не выполняет сетевых
 * вызовов. Бэкап — это чтение/запись локального файла через SAF (Uri),
 * не сеть.
 */
class VaultRepository(private val appContext: Context) {

    private val crypto = VaultCrypto()
    private val prefs by lazy { PreferencesStore.get(appContext) }

    @Volatile private var masterKey: DerivedKey? = null
    @Volatile private var database: VaultDatabase? = null

    val isUnlocked: Boolean get() = masterKey != null && database != null
    val hasVault: Boolean get() = prefs.contains(PreferencesStore.KEY_SALT)

    // ---------- Создание / разблокировка / блокировка ----------

    suspend fun createVault(password: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        if (hasVault) return@withContext UnlockResult.VaultAlreadyExists

        val passwordBytes = String(password).toByteArray(Charsets.UTF_8)
        var derived: DerivedKey? = null
        try {
            val salt = crypto.generateSalt()
            derived = crypto.deriveMasterKey(passwordBytes, salt)

            val sqlCipherKey = hkdfExpand(derived.keyBytes, KeyContext.SQLCIPHER)
            val fieldKey = hkdfExpand(derived.keyBytes, KeyContext.FIELD_ENCRYPTION)
            val fieldDerivedKey = DerivedKey(fieldKey, salt)

            prefs.edit()
                .putString(PreferencesStore.KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                .putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0)
                .apply()

            val db = VaultDatabase.build(appContext, sqlCipherKey)
            db.openHelper.writableDatabase // форсируем открытие, ловим ошибку сразу
            sqlCipherKey.fill(0)

            database = db
            masterKey = fieldDerivedKey
            UnlockResult.Success
        } finally {
            passwordBytes.fill(0)
            password.fill('0')
            // derived.keyBytes (сырой Argon2id-выход) больше не нужен после HKDF-расщепления —
            // затираем его отдельно от fieldDerivedKey, который остаётся в masterKey на сессию.
            derived?.keyBytes?.fill(0)
        }
    }

    suspend fun unlock(password: CharArray): UnlockResult = withContext(Dispatchers.Default) {
        val saltB64 = prefs.getString(PreferencesStore.KEY_SALT, null)
            ?: return@withContext UnlockResult.NoVaultYet

        val passwordBytes = String(password).toByteArray(Charsets.UTF_8)
        val salt = Base64.decode(saltB64, Base64.NO_WRAP)
        var derived: DerivedKey? = null

        try {
            derived = crypto.deriveMasterKey(passwordBytes, salt)
            val sqlCipherKey = hkdfExpand(derived.keyBytes, KeyContext.SQLCIPHER)
            val fieldKey = hkdfExpand(derived.keyBytes, KeyContext.FIELD_ENCRYPTION)

            return@withContext try {
                val candidate = VaultDatabase.build(appContext, sqlCipherKey)
                candidate.openHelper.writableDatabase // бросит исключение при неверном ключе
                sqlCipherKey.fill(0)

                database?.close()
                database = candidate
                masterKey = DerivedKey(fieldKey, salt)
                prefs.edit().putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0).apply()
                UnlockResult.Success
            } catch (e: Exception) {
                sqlCipherKey.fill(0)
                fieldKey.fill(0)
                val attempts = prefs.getInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0) + 1
                if (attempts >= PreferencesStore.PANIC_WIPE_THRESHOLD) {
                    panicWipe()
                    UnlockResult.WipedOut
                } else {
                    prefs.edit().putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, attempts).apply()
                    UnlockResult.WrongPassword(PreferencesStore.PANIC_WIPE_THRESHOLD - attempts)
                }
            }
        } finally {
            passwordBytes.fill(0)
            password.fill('0')
            derived?.keyBytes?.fill(0)
        }
    }

    /** Обычная блокировка (по таймауту или вручную) — не стирает данные, просто
     *  затирает ключ из памяти. Для разблокировки снова нужен мастер-пароль. */
    fun lock() {
        masterKey?.zeroize()
        masterKey = null
        database?.close()
        database = null
    }

    /** Panic wipe — необратимое удаление всего: файла БД, соли, счётчиков.
     *  Триггерится либо автоматически (N неверных попыток), либо вручную из UI. */
    fun panicWipe() {
        lock()
        appContext.getDatabasePath("skhoron_vault.db").delete()
        appContext.getDatabasePath("skhoron_vault.db-wal").delete()
        appContext.getDatabasePath("skhoron_vault.db-shm").delete()
        PreferencesStore.wipe(appContext)
    }

    // ---------- Работа с записями ----------

    fun observeEntries(): Flow<List<VaultEntryRow>> {
        val db = database ?: throw IllegalStateException("Vault заблокирован")
        return db.vaultEntryDao().observeAll()
    }

    suspend fun addEntry(label: String, username: String?, password: String, domainHint: String?) {
        val key = masterKey ?: throw IllegalStateException("Vault заблокирован")
        val db = database ?: throw IllegalStateException("Vault заблокирован")
        val id = UUID.randomUUID().toString()
        val blob = crypto.encryptEntry(key, password.toByteArray(Charsets.UTF_8), aad = id.toByteArray())
        db.vaultEntryDao().insert(
            VaultEntryRow(
                id = id,
                label = label,
                username = username,
                passwordCiphertext = blob.ciphertext,
                passwordNonce = blob.nonce,
                domainHint = domainHint,
                createdAt = System.currentTimeMillis()
            )
        )
    }

    suspend fun deleteEntry(row: VaultEntryRow) {
        database?.vaultEntryDao()?.delete(row)
    }

    fun decryptPassword(row: VaultEntryRow): String {
        val key = masterKey ?: throw IllegalStateException("Vault заблокирован")
        val plaintext = crypto.decryptEntry(
            key,
            EncryptedBlob(row.passwordCiphertext, row.passwordNonce),
            aad = row.id.toByteArray()
        )
        return String(plaintext, Charsets.UTF_8)
    }

    /**
     * Поиск для автозаполнения. ВАЖНО (anti-phishing invariant): совпадение
     * ТОЛЬКО по точному domainHint, никогда по похожести label. Если атакующий
     * домен не совпадает побайтово с сохранённым — совпадений не будет,
     * автозаполнение не сработает. Это и есть защита от фишинга на этом уровне.
     */
    suspend fun findByExactDomain(domain: String): List<VaultEntryRow> {
        val db = database ?: return emptyList()
        return db.vaultEntryDao().findByDomain(domain)
    }

    // ---------- Auto-lock ----------

    fun getAutolockMinutes(): Int =
        prefs.getInt(PreferencesStore.KEY_AUTOLOCK_MINUTES, PreferencesStore.DEFAULT_AUTOLOCK_MINUTES)

    fun setAutolockMinutes(minutes: Int) {
        val clamped = minutes.coerceIn(PreferencesStore.MIN_AUTOLOCK_MINUTES, PreferencesStore.MAX_AUTOLOCK_MINUTES)
        prefs.edit().putInt(PreferencesStore.KEY_AUTOLOCK_MINUTES, clamped).apply()
    }

    fun onAppBackgrounded() {
        prefs.edit().putLong(PreferencesStore.KEY_LAST_BACKGROUND_TS, System.currentTimeMillis()).apply()
    }

    /** Вызывается при возврате в приложение. Если прошло больше таймаута — блокирует. */
    fun checkAutolockOnForeground() {
        val lastBg = prefs.getLong(PreferencesStore.KEY_LAST_BACKGROUND_TS, 0L)
        if (lastBg == 0L) return
        val elapsedMinutes = (System.currentTimeMillis() - lastBg) / 60_000
        if (elapsedMinutes >= getAutolockMinutes()) {
            lock()
        }
    }

    // ---------- Локальный зашифрованный бэкап (без сети, без облака) ----------

    /**
     * Экспорт: файл БД уже зашифрован SQLCipher-passphrase, производным от
     * того же мастер-пароля — повторное шифрование не требуется. Юзер сам
     * выбирает, куда сохранить (SD-карта, USB, файловый менеджер) через SAF.
     *
     * Формат: [4 байта: длина соли][соль][содержимое db-файла] — соль нужна
     * в бэкапе, иначе восстановление на новом устройстве невозможно (соль
     * хранится в EncryptedSharedPreferences, которая привязана к Keystore
     * этого конкретного устройства и не переносится).
     */
    fun exportBackup(destinationUri: Uri) {
        val saltB64 = prefs.getString(PreferencesStore.KEY_SALT, null)
            ?: throw IllegalStateException("Vault ещё не создан")
        val salt = Base64.decode(saltB64, Base64.NO_WRAP)
        val dbFile = appContext.getDatabasePath("skhoron_vault.db")

        appContext.contentResolver.openOutputStream(destinationUri)?.use { out ->
            val lenBytes = java.nio.ByteBuffer.allocate(4).putInt(salt.size).array()
            out.write(lenBytes)
            out.write(salt)
            dbFile.inputStream().use { input -> input.copyTo(out) }
        } ?: throw IllegalStateException("Не удалось открыть файл назначения")
    }

    /** Импорт: заменяет текущий файл БД и соль. Юзер должен ввести тот же
     *  мастер-пароль, которым был зашифрован бэкап — иначе unlock() вернёт
     *  WrongPassword. */
    fun importBackup(sourceUri: Uri) {
        lock() // закрываем текущую БД перед заменой файла
        val dbFile = appContext.getDatabasePath("skhoron_vault.db")

        appContext.contentResolver.openInputStream(sourceUri)?.use { input ->
            val lenBytes = ByteArray(4)
            if (input.read(lenBytes) != 4) throw IllegalStateException("Повреждённый файл бэкапа")
            val saltLen = java.nio.ByteBuffer.wrap(lenBytes).int
            val salt = ByteArray(saltLen)
            if (input.read(salt) != saltLen) throw IllegalStateException("Повреждённый файл бэкапа")

            prefs.edit()
                .putString(PreferencesStore.KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                .putInt(PreferencesStore.KEY_FAILED_ATTEMPTS, 0)
                .apply()

            dbFile.outputStream().use { out -> input.copyTo(out) }
        } ?: throw IllegalStateException("Не удалось открыть файл источника")
    }
}