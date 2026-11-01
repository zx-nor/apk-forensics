package com.blackbox.forensics

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import com.blackbox.forensics.ui.AppScreen
import com.blackbox.forensics.ui.BlackboxTheme

class MainActivity : ComponentActivity() {
    private val viewModel: AnalysisViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BlackboxTheme {
                AppScreen(viewModel)
            }
        }
    }
}
