use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config, Event, EventKind};
use std::sync::mpsc::channel;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek};
use std::path::Path;
use std::sync::Arc;
use reqwest::Client;
use dotenv::dotenv;
use std::env;
use serde::Deserialize;
use reqwest::Error;

#[derive(Deserialize, Debug)]
struct ApiResponse {
    model: String,
    created_at: String,
    message: Message,
    done_reason: String,
    done: bool,
}

#[derive(Deserialize, Debug)]
struct Message {
    role: String,
    content: String,
}

async fn read_new_lines(file: &Path, last_pos: &mut u64) -> io::Result<()> {
    dotenv().ok();
    let model = env::var("MODEL").map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("Could not open env: {}", e))
    })?;
    let mut file = File::open(file)?;

    // Seek the file to the last read position
    file.seek(std::io::SeekFrom::Start(*last_pos))?;

    let reader = BufReader::new(file);

    let mut new_logs = String::new();
    for line in reader.lines() {
        let line = line?;
        new_logs.push_str(&line);
        new_logs.push('\n');
    }

    println!("{}", new_logs);

    if new_logs.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("logs.txt was empty did not send")));
    }

    post_battle_logs(&new_logs).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other,format!("Could not connect to frontend {}", e)))?;

    // Update the last read position
    *last_pos += new_logs.len() as u64;

    // Create the first prompt
    let first_logs_prompt = serde_json::json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You will be given log files by the user which represent Snort 3 logs from the local network's IDS. Identify if an attacker is attempting to gain unauthorized access to the victim (192.168.0.20) on the local network. Respond with a thorough analysis of the logs, referencing the logs that demonstrate the intrusion."
            },
            {
                "role": "user",
                "content": new_logs
            }
        ],
        "options": {
            "temperature": 0.2,
            "num_ctx": 1024,
            "num_predict": 128
        },
        "stream": false
    });

    let client = Client::new();

    // Send the first request
    let response = client
        .post("http://192.168.0.50:11434/api/chat")
        .body(first_logs_prompt.to_string())
        .send()
        .await
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Could not connect to Ollama server: {}", e),
            )
        })?;

    if response.status().is_success() {
        let response_text = response.text().await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Could not parse response to text: {}", e),
            )
        })?;

        // Parse the response into the ApiResponse struct
        let api_response: ApiResponse = serde_json::from_str(&response_text).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to deserialize response: {}", e),
            )
        })?;
        println!("Response 1: {:#?}", api_response);

        let second_logs_prompt = serde_json::json!({
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": "You will be given an analysis of Snort 3 logs from an LLM regarding if an intrusion has occurred on the local network. You must respond with shell commands to patch the victim's OS, which is an Ubuntu 14.04 system (Metasploitable 3) intrusion. Put these shell commands on its own section all listed together."
                },
                {
                    "role": "user",
                    "content": api_response.message.content,
                }
            ],
            "options": {
                "temperature": 0.2,
            },
            "stream": false
        });

        // Send the second request
        let response = client
            .post("http://192.168.0.50:11434/api/chat")
            .body(second_logs_prompt.to_string())
            .send()
            .await
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Could not connect to Ollama server: {}", e),
                )
            })?;

        if response.status().is_success() {
            let response_text = response.text().await.map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Could not parse response to text: {}", e),
                )
            })?;

            // Parse the second response into the ApiResponse struct
            let api_response: ApiResponse = serde_json::from_str(&response_text).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to deserialize response: {}", e),
                )
            })?;

            post_patch_updates(&api_response.message.content).await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other,format!("Could not connect to frontend {}", e)))?;;

            println!("Response 2: {:#?}", api_response);
        } else {
            eprintln!("Failed to call Ollama API: {}", response.status());
        }
    } else {
        eprintln!("Failed to call Ollama API: {}", response.status());
    }
    Ok(())
}

async fn post_battle_logs(logs: &String) -> Result<(), Error> {
    let client = Client::new();

    let json_format = serde_json::json!({"message": logs, "severity": "warning".to_string()});

    let response = client.post("http://192.168.0.200:8000/battle-logs")
        .body(json_format.to_string())
        .send()
        .await?;

    if !response.status().is_success() {
        println!("DID NOT SUCCESSFULLY SEND.");
    }
    Ok(())
}

async fn post_patch_updates(patch: &String) -> Result<(), Error> {
    let client = Client::new();
    let response = client.post("http://192.168.0.200:8000/defense-action")
        .body(serde_json::json!({
            "code": patch
        }).to_string())
        .send()
        .await?;
        
    if response.status().is_success() {
        println!("Successfully sent patch");
    } else {
        println!("Failed to send patch: {:#?}", response);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> notify::Result<()> {
    let log_file = Path::new("/opt/homebrew/etc/snort/log.txt");
    let mut last_position = 0;

    // Set up a channel to receive events
    let (tx, rx) = channel();

    // Create a watcher object with configuration
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Config::default())?;
    watcher.watch(log_file, RecursiveMode::NonRecursive)?;

    println!("Watching file: {:?}", log_file);

    loop {
        match rx.recv() {
            Ok(event) => match event {
                Ok(Event {
                    kind: EventKind::Modify(_),
                    ..
                }) => {
                    match read_new_lines(log_file, &mut last_position).await {
                        Ok(()) => {
                            
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                        }
                    }
                }
                _ => (),
            },
            Err(err) => eprintln!("Watch error: {}", err),
        }
    }
}
