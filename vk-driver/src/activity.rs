//! What a placed job's preparation is doing — building or pulling an image, or waiting for
//! another job that does — for the hub's job pages. The node's job driver names a file in the
//! job's directory in [`ENV`] when it runs `vk gitlab prepare`; [`sink`] writes the activity
//! there — from prepare, and from the supervisor it starts, which inherits the variable: its
//! services' pulls and lock waits while the job boots are preparing too — and the node reads it
//! with the stage it reports, while that stage is preparing. Nothing happens without the
//! variable: a job of a local gitlab-runner, a `vk build`, have no one to tell.

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use vk_hub_proto::dispatch::Activity;

/// The variable naming the activity file.
pub const ENV: &str = "VK_JOB_ACTIVITY";

/// The activity file and its active reports. Nested reports, such as a pull under a build's
/// lock, show the innermost activity and restore the outer activity when it ends.
pub struct Sink {
    path: Option<PathBuf>,
    /// The last id given, and what is said, innermost last.
    said: Mutex<(u64, Vec<(u64, Activity)>)>,
}

/// This process's sink: the file named in [`ENV`], or none.
pub fn sink() -> Arc<Sink> {
    static SINK: LazyLock<Arc<Sink>> =
        LazyLock::new(|| Sink::new(std::env::var_os(ENV).map(PathBuf::from)));
    SINK.clone()
}

impl Sink {
    pub fn new(path: Option<PathBuf>) -> Arc<Sink> {
        Arc::new(Sink {
            path,
            said: Mutex::default(),
        })
    }

    /// Say `activity` until the [`Said`] returned is dropped.
    pub fn say(self: &Arc<Self>, activity: Activity) -> Said {
        let mut said = self.said.lock().unwrap_or_else(PoisonError::into_inner);
        said.0 += 1;
        let id = said.0;
        said.1.push((id, activity));
        self.write(&said.1);
        Said {
            sink: self.clone(),
            id,
        }
    }

    /// Write what shows now; best effort, the trace says it too.
    fn write(&self, said: &[(u64, Activity)]) {
        let Some(path) = &self.path else {
            return;
        };
        match said.last().and_then(|(_, a)| serde_json::to_vec(a).ok()) {
            Some(json) => {
                let _ = vk_fs::write_atomic(path, &json, 0o600);
            }
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

/// An activity said, until dropped.
pub struct Said {
    sink: Arc<Sink>,
    id: u64,
}

impl Said {
    /// Say `activity` in its place.
    pub fn change(&self, activity: Activity) {
        let mut said = self
            .sink
            .said
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = said.1.iter_mut().find(|(id, _)| *id == self.id) {
            entry.1 = activity;
        }
        self.sink.write(&said.1);
    }
}

impl Drop for Said {
    fn drop(&mut self) {
        let mut said = self
            .sink
            .said
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        said.1.retain(|(id, _)| *id != self.id);
        self.sink.write(&said.1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::jobs::journal::{ACTIVITY, read_activity};

    /// The node reads prepare's activity with the stage. Nested reports restore the outer
    /// activity when they end; the last report removes the file.
    #[test]
    fn an_activity_reaches_the_node_and_goes() {
        let dir = std::env::temp_dir().join(format!("vk-activity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sink = Sink::new(Some(dir.join(ACTIVITY)));
        let building = Activity::Building {
            image: "docker/wab/Dockerfile#builder".into(),
        };
        let pulling = Activity::Pulling {
            image: "cache".into(),
        };
        let outer = sink.say(building.clone());
        assert_eq!(read_activity(&dir), Some(building.clone()));
        let inner = sink.say(pulling.clone());
        assert_eq!(read_activity(&dir), Some(pulling.clone()));
        drop(inner);
        assert_eq!(read_activity(&dir), Some(building));
        outer.change(pulling.clone());
        assert_eq!(read_activity(&dir), Some(pulling));
        drop(outer);
        assert_eq!(read_activity(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
