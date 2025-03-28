package fan.ovo.hwsign

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import fan.ovo.hwsign.ui.theme.DbcsTheme

class MainActivity : ComponentActivity() {
    private lateinit var authService: AuthService

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        authService = AuthService(this)

        setContent {
            DbcsTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    var username by remember { mutableStateOf("") }
                    var password by remember { mutableStateOf("") }
                    var message by remember { mutableStateOf("") }
                    var securityLevel by remember { mutableStateOf("Unknown") }

                    Column(
                        modifier = Modifier
                            .padding(innerPadding)
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        OutlinedTextField(
                            value = username,
                            onValueChange = { username = it },
                            label = { Text("Username") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = password,
                            onValueChange = { password = it },
                            label = { Text("Password") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(onClick = {
                            lifecycleScope.launch {
                                val success = authService.login(username, password)
                                message = if (success) "Login successful!" else "Login failed."
                                securityLevel = authService.keyManager.getKeySecurityLevel()
                            }
                        }) {
                            Text("Login")
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(onClick = {
                            lifecycleScope.launch {
                                val success = authService.register(username, password)
                                message = if (success) "Registration successful!" else "Registration failed."
                            }
                        }) {
                            Text("Register")
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(onClick = {
                            lifecycleScope.launch {
                                val isAuthenticated = authService.checkAuthentication()
                                message = if (isAuthenticated) "Authenticated!" else "Not authenticated."
                            }
                        }) {
                            Text("Check Auth")
                        }
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("Security Level: $securityLevel", style = MaterialTheme.typography.bodyLarge)
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(message)
                    }
                }
            }
        }
    }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
    Text(
        text = "Hello $name!",
        style = MaterialTheme.typography.titleLarge,
        modifier = modifier
    )
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    DbcsTheme {
        Greeting("DBCS")
    }
}