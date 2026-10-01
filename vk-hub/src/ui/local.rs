//! `vk-hub local`'s pages: this machine's VMs, and each one's own page.
//!
//! A VM's ID is the one `vk workloads` derives from its state dir, sixteen hex digits, and the
//! only value of the host's that goes into a path; the router takes nothing else for one.

use hyper::{Response, StatusCode};
use vk_hub_proto::Workload;

use super::html::Html;
use super::pages::{self, dash, end_section, kv, kv_node, section};
use super::{Auth, Body, Ui};
use crate::local::Listing;

/// The page for `path`, if it is one of local mode's.
pub(super) fn get(path: &str, auth: &Auth, ui: &Ui) -> Option<Response<Body>> {
    if path == "/" {
        return Some(super::page(list(auth, &ui.local.listing())));
    }
    let id = path.strip_prefix("/vm/").filter(|id| valid_id(id))?;
    Some(match ui.local.workload(id) {
        Some((w, mem)) => super::page(vm(auth, &w, mem)),
        None => super::message(
            StatusCode::NOT_FOUND,
            "No such VM is running on this machine.",
        ),
    })
}

/// Whether `id` is a VM's ID as `vk workloads` writes one: sixteen lowercase hex digits.
fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `/`: the VMs this machine runs.
fn list(auth: &Auth, listing: &Listing) -> Html {
    let mut main = Html::new();
    main.raw("<h1>VMs on this machine</h1>")
        .html(&vms_table(listing));
    pages::layout("VMs", auth, &main)
}

/// The VMs as `vk workloads` last listed them, or why there is no list.
fn vms_table(listing: &Listing) -> Html {
    let mut h = Html::new();
    let list = match listing {
        Listing::Waiting => {
            h.raw("<p class=\"empty\">Asking <code>vk workloads</code> for the VMs…</p>");
            return h;
        }
        Listing::Failed(why) => {
            h.raw("<p class=\"notes\"><code>vk workloads</code> failed, and is run again: ")
                .node(why)
                .raw("</p>");
            return h;
        }
        Listing::Listed(list) => list,
    };
    if list.workloads.is_empty() && list.omitted == 0 {
        h.raw("<p class=\"empty\">No VM is running. <code>vk run</code>, <code>vk dev up</code> ")
            .raw("and CI jobs show up here as they start.</p>");
        return h;
    }
    h.raw("<table class=\"grid\"><thead><tr>");
    for column in crate::workloads::COLUMNS {
        h.raw("<th>").text(column).raw("</th>");
    }
    h.raw("</tr></thead><tbody>");
    for w in &list.workloads {
        let cells = cells(w, list.mem_bytes.get(&w.id).copied());
        h.raw("<tr>");
        for (i, cell) in cells.iter().enumerate() {
            h.raw("<td>");
            match i {
                // Of the hub's making: the kind's name and the figures.
                0 | 3..=7 => {
                    h.text(cell);
                }
                // The ID, leading to the VM's page; the router takes only hex for one.
                1 if valid_id(cell) => {
                    h.raw("<a href=\"/vm/")
                        .text(cell)
                        .raw("\"><code>")
                        .text(cell)
                        .raw("</code></a>");
                }
                1 => {
                    h.raw("<code>").node(cell).raw("</code>");
                }
                _ => {
                    h.node(cell);
                }
            }
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
    if list.omitted > 0 {
        h.raw("<p class=\"empty\">and ")
            .text(list.omitted)
            .raw(" more running, not listed</p>");
    }
    h
}

/// One workload's cells under [`crate::workloads::COLUMNS`], with what it holds now. What it
/// holds, which moves all the time, is to two figures, so the page changes only when it has
/// moved.
fn cells(w: &Workload, mem: Option<u64>) -> [String; 9] {
    [
        crate::workloads::kind_name(w.kind).to_string(),
        w.id.clone(),
        crate::workloads::owner(w),
        w.pid.map_or_else(dash, |p| p.to_string()),
        w.cpus.map_or_else(dash, |c| c.to_string()),
        w.mem_reserved_mib.map_or_else(dash, pages::mib),
        mem.map_or_else(dash, pages::rough_bytes),
        w.started_at.map_or_else(dash, pages::started),
        w.state_dir.clone(),
    ]
}

/// `/vm/<id>`: one VM.
fn vm(auth: &Auth, w: &Workload, mem: Option<u64>) -> Html {
    let mut main = Html::new();
    main.raw("<h1>")
        .node(&crate::workloads::owner(w))
        .raw("</h1>");
    main.html(&vm_detail(w, mem));
    pages::layout(&crate::workloads::owner(w), auth, &main)
}

/// What the page shows of a VM below its name.
fn vm_detail(w: &Workload, mem: Option<u64>) -> Html {
    let mut h = Html::new();
    section(&mut h, "VM");
    kv(&mut h, "kind", crate::workloads::kind_name(w.kind));
    kv_node(&mut h, "state dir", &w.state_dir);
    for (key, value) in [
        ("image", &w.label),
        ("project", &w.project),
        ("job", &w.job_name),
        ("job ID", &w.job_id),
        ("workspace", &w.workspace),
        ("environment", &w.environment),
    ] {
        if let Some(value) = value {
            kv_node(&mut h, key, value);
        }
    }
    kv(
        &mut h,
        "managed by pid",
        &w.pid.map_or_else(dash, |p| p.to_string()),
    );
    kv(
        &mut h,
        "vCPUs",
        &w.cpus.map_or_else(dash, |c| c.to_string()),
    );
    kv(
        &mut h,
        "memory reserved",
        &w.mem_reserved_mib.map_or_else(dash, pages::mib),
    );
    kv(
        &mut h,
        "memory held",
        &mem.map_or_else(dash, pages::rough_bytes),
    );
    kv(
        &mut h,
        "started",
        &w.started_at.map_or_else(dash, pages::started),
    );
    end_section(&mut h);
    h
}
