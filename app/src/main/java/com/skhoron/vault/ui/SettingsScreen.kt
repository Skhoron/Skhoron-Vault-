package com.skhoron.vault.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.skhoron.vault.ui.theme.SkhoronDanger
import com.skhoron.vault.ui.theme.SkhoronTextDim

@Composable
fun SettingsScreen(
    autolockMinutes: Int,
    onAutolockChange: (Int) -> Unit,
    onExportBackup: () -> Unit,
    onImportBackup: () -> Unit,
    onLockNow: () -> Unit,
    onPanicWipe: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    var showWipeConfirm by remember { mutableStateOf(false) }
    var sliderValue by remember { mutableStateOf(autolockMinutes.toFloat()) }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text("Настройки") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Назад")
                    }
                }
            )
        }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp)) {

            Text("Автоблокировка", fontSize = 16.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
            Text(
                "Vault заблокируется, если приложение было в фоне дольше этого времени.",
                fontSize = 13.sp,
                color = SkhoronTextDim
            )
            Spacer(Modifier.height(8.dp))
            Slider(
                value = sliderValue,
                onValueChange = { sliderValue = it },
                onValueChangeFinished = { onAutolockChange(sliderValue.toInt()) },
                valueRange = 1f..30f,
                steps = 28
            )
            Text("${sliderValue.toInt()} мин.", fontSize = 13.sp, color = SkhoronTextDim)

            Spacer(Modifier.height(32.dp))
            Divider()
            Spacer(Modifier.height(24.dp))

            Text("Локальный бэкап", fontSize = 16.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
            Text(
                "Файл уже зашифрован тем же мастер-паролем. Никакого облака — ты сам выбираешь, куда сохранить.",
                fontSize = 13.sp,
                color = SkhoronTextDim
            )
            Spacer(Modifier.height(12.dp))
            Row {
                OutlinedButton(onClick = onExportBackup, modifier = Modifier.weight(1f)) {
                    Text("Экспорт")
                }
                Spacer(Modifier.width(12.dp))
                OutlinedButton(onClick = onImportBackup, modifier = Modifier.weight(1f)) {
                    Text("Импорт")
                }
            }

            Spacer(Modifier.height(32.dp))
            Divider()
            Spacer(Modifier.height(24.dp))

            Button(onClick = onLockNow, modifier = Modifier.fillMaxWidth()) {
                Text("Заблокировать сейчас")
            }

            Spacer(Modifier.height(32.dp))
            Text("Опасная зона", fontSize = 16.sp, color = SkhoronDanger, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
            Text(
                "Полностью и необратимо удаляет все записи и настройки с этого устройства.",
                fontSize = 13.sp,
                color = SkhoronTextDim
            )
            Spacer(Modifier.height(12.dp))
            OutlinedButton(
                onClick = { showWipeConfirm = true },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = SkhoronDanger),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Стереть всё (panic wipe)")
            }
        }
    }

    if (showWipeConfirm) {
        AlertDialog(
            onDismissRequest = { showWipeConfirm = false },
            title = { Text("Стереть всё?") },
            text = { Text("Это необратимо удалит все пароли и настройки с этого устройства. Отменить нельзя.") },
            confirmButton = {
                TextButton(onClick = {
                    showWipeConfirm = false
                    onPanicWipe()
                }) { Text("Стереть", color = SkhoronDanger) }
            },
            dismissButton = {
                TextButton(onClick = { showWipeConfirm = false }) { Text("Отмена") }
            }
        )
    }
}