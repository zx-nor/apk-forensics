package com.blackbox.forensics.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Scheme = darkColorScheme(
    primary = Color(0xFF4D8DFF),
    onPrimary = Color(0xFFFFFFFF),
    background = Color(0xFF16181D),
    onBackground = Color(0xFFE6E8EE),
    surface = Color(0xFF1E2129),
    onSurface = Color(0xFFE6E8EE),
    surfaceVariant = Color(0xFF262A34),
    onSurfaceVariant = Color(0xFFB8BDCB),
    error = Color(0xFFFF6B6B),
)

@Composable
fun BlackboxTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Scheme, content = content)
}
