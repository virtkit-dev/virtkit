use crate::addr::SocketAddr;
use crate::net::connect;
use futures::{SinkExt, StreamExt};
use std::time::Duration;

use super::messages::{Message, Status};

pub async fn get_status(socket: &SocketAddr) -> Result<Status, Box<dyn std::error::Error>> {
    // bounded: the watchdog (and `vk-agent status`) must detect a stuck server,
    // not hang on it
    get_status_within(socket, Duration::from_secs(10)).await
}

/// How long one boot-readiness probe may take before the poll gives up on it and asks
/// again. A probe that reaches the VMM before the guest agent listens does not fail: the
/// libkrun vsock muxer accepts the host connection, the guest refuses it, and the muxer only
/// closes the host side when its reaper drops the proxy 5 s later. Waiting on that answer
/// costs every boot with an early probe those 5 s; a healthy agent answers in milliseconds.
pub const BOOT_PROBE_BUDGET: Duration = Duration::from_millis(500);

/// [`get_status`] under a caller-chosen budget, for readiness polls that retry anyway.
pub async fn get_status_within(
    socket: &SocketAddr,
    budget: Duration,
) -> Result<Status, Box<dyn std::error::Error>> {
    match tokio::time::timeout(budget, get_status_inner(socket)).await {
        Ok(result) => result,
        Err(_) => Err(format!("status request not answered within {budget:?}").into()),
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
