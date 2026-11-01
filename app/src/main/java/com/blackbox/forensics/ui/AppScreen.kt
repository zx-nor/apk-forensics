package com.blackbox.forensics.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.blackbox.forensics.AnalysisViewModel
import com.blackbox.forensics.HexPage
import com.blackbox.forensics.UiState
import forensics.report.AnalysisReport
import forensics.report.EntryLine
import forensics.report.FindingLine
import forensics.report.MetadataLine

private const val MAX_FINDINGS_SHOWN = 300
private const val MAX_METADATA_SHOWN = 400

@Composable
fun AppScreen(vm: AnalysisViewModel) {
    val state by vm.state.collectAsState()
    val hex by vm.hex.collectAsState()
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.analyze(uri)
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                Text("BLACKBOX FORENSICS", style = MaterialTheme.typography.titleLarge, color = MaterialTheme.colorScheme.primary)
            }
            item {
                Button(onClick = { picker.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Open evidence file")
                }
            }
            when (val s = state) {
                UiState.Idle -> item {
                    Text(
                        "Choose a file. The app copies it into private storage, hashes the copy, and analyzes only the copy. " +
                            "The original is never modified. Analysis runs offline.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                is UiState.Working -> item { Text(s.what, style = MaterialTheme.typography.bodyMedium) }
                is UiState.Failed -> item {
                    InfoCard { Text("Analysis failed: ${s.message}", color = MaterialTheme.colorScheme.error) }
                }
                is UiState.Ready -> reportItems(s.report, hex, vm::moveHex)
            }
        }
    }
}

private fun LazyListScope.reportItems(r: AnalysisReport, hex: HexPage?, onHexMove: (Long) -> Unit) {
    item { SectionTitle("Source and integrity") }
    item {
        InfoCard {
            KeyValue("File", r.sourceName)
            KeyValue("Size", "${r.sourceBytes} bytes")
            KeyValue("SHA-256 (acquired)", r.sourceSha256)
            KeyValue("SHA-256 (analyzed copy)", r.workingCopySha256)
            KeyValue("Analyzed bytes match acquired bytes", if (r.workingCopyMatchesSource) "yes" else "NO")
        }
    }

    item { SectionTitle("Identification") }
    item {
        InfoCard {
            KeyValue("Format", r.formatName ?: "not identified")
            KeyValue("Internal identifier", r.refinedFormat ?: "none")
            KeyValue("Confidence", r.confidence)
            KeyValue("Extension mismatch", if (r.extensionMismatch) "YES" else "no")
            r.identificationEvidence.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }

    item { SectionTitle("Findings (${r.findings.size})") }
    if (r.findings.isEmpty()) {
        item { Text("No findings.", style = MaterialTheme.typography.bodyMedium) }
    } else {
        items(r.findings.take(MAX_FINDINGS_SHOWN)) { f -> FindingRow(f) }
    }

    item { SectionTitle("Metadata: ${r.metadataStatus}") }
    if (r.metadataNotes.isNotEmpty() || r.metadataErrors.isNotEmpty()) {
        item {
            InfoCard {
                r.metadataNotes.forEach { Text("Note: $it", style = MaterialTheme.typography.bodySmall) }
                r.metadataErrors.forEach { Text("Error: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
            }
        }
    }
    items(r.metadata.take(MAX_METADATA_SHOWN)) { m -> MetadataRow(m) }

    if (r.zipKind != null) {
        item { SectionTitle("Archive: ${r.zipKind} (${r.zipConfidence})") }
        item {
            InfoCard {
                KeyValue("Entries", r.zipEntryCount.toString())
                if (r.zipEntryCount > r.zipEntriesShown) KeyValue("Shown", "first ${r.zipEntriesShown}")
                r.zipParseError?.let { Text("Structure error: $it", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        }
        items(r.zipEntries) { e -> EntryRow(e) }
    }

    item { SectionTitle("Appended and embedded data") }
    item {
        InfoCard {
            KeyValue("Bytes after the format's end", "${r.appendedBytes}${if (r.appendedIsZeroPadding) " (zero padding)" else ""}")
            if (r.embeddedHits.isEmpty()) Text("No embedded signatures.", style = MaterialTheme.typography.bodySmall)
            r.embeddedHits.take(50).forEach { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
        }
    }

    item { SectionTitle("Hex viewer") }
    if (hex != null) {
        item {
            InfoCard {
                Text("Offset 0x%08X of %d bytes".format(hex.offset, hex.fileSize), style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = { onHexMove(-AnalysisViewModel.HEX_WINDOW.toLong()) }) { Text("Previous") }
                    OutlinedButton(onClick = { onHexMove(AnalysisViewModel.HEX_WINDOW.toLong()) }) { Text("Next") }
                }
            }
        }
        items(hex.rows) { row ->
            Text("%08X  %s  %s".format(row.offset, row.hex, row.ascii), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
    }

    item { SectionTitle("Printable strings (${r.strings.size})") }
    items(r.strings) { s -> Text(s, fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
}

@Composable
private fun SectionTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 6.dp))
}

@Composable
private fun InfoCard(content: @Composable ColumnScope.() -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp), content = content)
    }
}

@Composable
private fun KeyValue(key: String, value: String) {
    Text("$key: $value", style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Default)
}

@Composable
private fun FindingRow(f: FindingLine) {
    val color = when (f.severity) {
        "ERROR", "SUSPICIOUS" -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onBackground
    }
    Column {
        Text("[${f.severity}] ${f.code}", style = MaterialTheme.typography.bodyMedium, color = color)
        Text(f.message, style = MaterialTheme.typography.bodySmall)
        f.location?.let { Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace) }
    }
}

@Composable
private fun MetadataRow(m: MetadataLine) {
    Text("${m.group} | ${m.key}: ${m.value}", style = MaterialTheme.typography.bodySmall)
}

@Composable
private fun EntryRow(e: EntryLine) {
    Column {
        Text(e.name, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
        Text(
            "method=${e.method} encryption=${e.encryption ?: "none"} measured=${e.measuredSize ?: "n/a"} " +
                "declared=${e.declaredSize} crc=${e.crcState} state=${e.measurement}" +
                (e.nested?.let { " nested=$it" } ?: ""),
            style = MaterialTheme.typography.bodySmall,
        )
        e.findings.forEach { f ->
            Text("  [${f.severity}] ${f.code}: ${f.message}", style = MaterialTheme.typography.bodySmall)
        }
    }
}
