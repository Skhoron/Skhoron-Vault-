package com.skhoron.vault.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory

/**
 * VaultDatabase — SQLCipher-зашифрованный файл БД + шифрование каждого поля
 * на уровне приложения (VaultCrypto). Двойной слой: даже если кто-то получит
 * доступ к файлу БД напрямую (root, физический доступ к устройству), поля
 * password_ciphertext всё равно зашифрованы отдельным ключом.
 *
 * passphrase для SQLCipher выводится из того же Argon2id master key, но с
 * доменным разделением (другая соль/контекст), чтобы компрометация одного
 * ключа не давала оба слоя защиты сразу.
 */
@Database(entities = [VaultEntryRow::class], version = 1, exportSchema = false)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun vaultEntryDao(): VaultEntryDao

    companion object {
        fun build(context: Context, sqlCipherPassphrase: ByteArray): VaultDatabase {
            SQLiteDatabase.loadLibs(context)
            val factory = SupportFactory(sqlCipherPassphrase)
            return Room.databaseBuilder(
                context.applicationContext,
                VaultDatabase::class.java,
                "skhoron_vault.db"
            )
                .openHelperFactory(factory)
                .fallbackToDestructiveMigration() // приемлемо для v0.1, до появления реальных миграций
                .build()
        }
    }
}