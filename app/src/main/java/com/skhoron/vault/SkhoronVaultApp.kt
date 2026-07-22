package com.skhoron.vault

import android.app.Application
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.skhoron.vault.data.VaultRepository

/**
 * SkhoronVaultApp — держит единственный на процесс инстанс VaultRepository.
 * MainActivity и SkhoronAutofillService объявлены в одном процессе (":vault",
 * см. AndroidManifest), поэтому оба видят один и тот же разблокированный
 * vault в рамках сессии — не нужно повторно вводить пароль для автозаполнения
 * сразу после того, как разблокировал через основной экран.
 */
class SkhoronVaultApp : Application() {

    lateinit var repository: VaultRepository
        private set

    override fun onCreate() {
        super.onCreate()
        repository = VaultRepository(applicationContext)

        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                // Приложение ушло в фон (свёрнуто/экран заблокирован) — фиксируем момент.
                if (repository.isUnlocked) {
                    repository.onAppBackgrounded()
                }
            }

            override fun onStart(owner: LifecycleOwner) {
                // Вернулись на передний план — проверяем, не истёк ли auto-lock таймаут.
                repository.checkAutolockOnForeground()
            }
        })
    }
}