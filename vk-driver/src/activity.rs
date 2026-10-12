//! What a placed job's preparation is doing — building or pulling an image, or waiting for
//! another job that does — for the hub's job pages. The node's job driver names a file in the
//! job's directory in [`ENV`] when it runs `vk gitlab prepare`; [`report`] writes the activity
//! there, and the node reads it with the stage it reports. Nothing happens without the
//! variable: a job of a local gitlab-runner, a `vk build`, have no one to tell.

use vk_hub_proto::dispatch::Activity;

/// The variable naming the activity file.
pub const ENV: &str = "VK_JOB_ACTIVITY";

/// Say what the job does now, or that it does nothing in particular (`None`). Best effort:
/// the trace says it too.
pub fn report(activity: Option<&Activity>) {
    if let Some(path) = std::env::var_os(ENV) {
        report_to(std::path::Path::new(&path), activity);
    }
}

/// [`report`] into `path`.
fn report_to(path: &std::path::Path, activity: Option<&Activity>) {
    match activity.and_then(|a| serde_json::to_vec(a).ok()) {
        Some(json) => {
            let _ = vk_fs::write_atomic(path, &json, 0o600);
        }
        None => {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What prepare writes, the node reads back with the stage; a cleared one is gone.
    #[test]
    fn an_activity_reaches_the_node_and_goes() {
        let dir = std::env::temp_dir().join(format!("vk-activity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::node::jobs::journal::ACTIVITY);
        let waiting = Activity::Waiting {
            image: "docker/wab/Dockerfile#builder".into(),
            building: true,
            holder: Some("https://gitlab.example.com/g/p/-/jobs/1".into()),
        };
        report_to(&path, Some(&waiting));
        assert_eq!(
            crate::node::jobs::journal::read_activity(&dir),
            Some(waiting)
        );
        report_to(&path, None);
        assert_eq!(crate::node::jobs::journal::read_activity(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
