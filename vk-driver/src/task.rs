//! Spawned-task helpers.

/// A [`tokio::spawn`]ed task aborted on drop, including error exits.
/// Awaiting the handle awaits the task.
pub(crate) struct AbortOnDrop<T>(pub(crate) tokio::task::JoinHandle<T>);

impl<T> std::future::Future for AbortOnDrop<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0).poll(cx)
    }
}

impl<T> AbortOnDrop<T> {
    pub(crate) fn abort(&self) {
        self.0.abort();
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn awaiting_returns_the_task_output() {
        assert_eq!(AbortOnDrop(tokio::spawn(async { 7 })).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn dropping_aborts_the_task() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = AbortOnDrop(tokio::spawn(async move {
            // Holds `tx` until aborted: the receiver errors only once the task is gone.
            std::future::pending::<()>().await;
            drop(tx);
        }));
        drop(task);
        assert!(rx.await.is_err());
    }
}
