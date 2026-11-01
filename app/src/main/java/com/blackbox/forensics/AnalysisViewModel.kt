package com.blackbox.forensics

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import forensics.binary.HexView
import forensics.report.AnalysisReport
import forensics.report.ReportBuilder
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface UiState {
    data object Idle : UiState
    data class Working(val what: String) : UiState
    data class Ready(val report: AnalysisReport) : UiState
    data class Failed(val message: String) : UiState
}

data class HexPage(val offset: Long, val fileSize: Long, val rows: List<HexView.Row>)

/** Holds the analysis state. All engine work runs on Dispatchers.IO; the UI never touches files directly. */
class AnalysisViewModel(application: Application) : AndroidViewModel(application) {

    private val _state = MutableStateFlow<UiState>(UiState.Idle)
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _hex = MutableStateFlow<HexPage?>(null)
    val hex: StateFlow<HexPage?> = _hex.asStateFlow()

    private var working: File? = null

    private fun evidenceRoot(): File = File(getApplication<Application>().cacheDir, "evidence")
    private fun scratchRoot(): File = File(getApplication<Application>().cacheDir, "engine-scratch")

    fun analyze(uri: Uri) {
        _state.value = UiState.Working("Copying evidence. The original is read but never written.")
        _hex.value = null
        viewModelScope.launch {
            val outcome = withContext(Dispatchers.IO) {
                runCatching {
                    val copier = EvidenceCopier(getApplication<Application>().contentResolver, evidenceRoot())
                    val copied = copier.copy(uri)
                    val scratch = scratchRoot()
                    scratch.deleteRecursively()
                    scratch.mkdirs()
                    val report = ReportBuilder.build(
                        copied.workingFile, copied.displayName, copied.sha256, copied.sizeBytes, scratch,
                    )
                    Pair(copied.workingFile, report)
                }
            }
            outcome.onSuccess { (file, report) ->
                working = file
                _state.value = UiState.Ready(report)
                loadHex(0L)
            }.onFailure { e ->
                working = null
                _state.value = UiState.Failed(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    /** Moves the hex window by [delta] bytes, clamped to the file. */
    fun moveHex(delta: Long) {
        val cur = _hex.value ?: return
        val max = maxOf(0L, cur.fileSize - 1)
        loadHex((cur.offset + delta).coerceIn(0L, max))
    }

    private fun loadHex(offset: Long) {
        val file = working ?: return
        viewModelScope.launch {
            val page = withContext(Dispatchers.IO) {
                runCatching { HexView.render(file, offset, HEX_WINDOW) }.getOrDefault(emptyList())
            }
            _hex.value = HexPage(offset, file.length(), page)
        }
    }

    companion object {
        const val HEX_WINDOW = 256
    }
}
