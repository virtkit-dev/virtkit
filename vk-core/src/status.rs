use crate::addr::SocketAddr;
use crate::net::connect;
use futures::{SinkExt, StreamExt};
use std::time::Duration;

use super::messages::{Message, Status};

pub async fn get_status(socket: &SocketAddr) -> Result<Status, Box<dyn std::error::Error>> {
    // bounded: the watchdog (and `vk-agent status`) must detect a stuck server,
    // not hang on it
    match tokio::time::timeout(Duration::from_secs(10), get_status_inner(socket)).await {
        Ok(result) => result,
        Err(_) => Err("status request timed out".into()),
    }
}

async fn get_status_inner(socket: &SocketAddr) -> Result<Status, Box<dyn std::error::Error>> {
    let (mut stream, mut sink) = connect(socket).await?;

    sink.send(Message::CmdStatus).await?;

    let Some(response) = stream.next().await else {
        return Err("no value".into());
    };

    match response? {
        Message::RespStatus { status } => Ok(status),
        _ => Err("invalid response".into()),
    }
}
