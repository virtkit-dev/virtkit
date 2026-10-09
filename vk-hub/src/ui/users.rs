//! OIDC sign-in grants at `/users`, for operators only. Lists every grant and the fallback
//! role (`[oidc] default_role`). Changes use the admin socket's [`ops::set_account`] as the
//! session's principal, sharing address validation, audit and termination of sessions whose
//! roles exceed what a new sign-in gets. Revocations and demotions require confirmation
//! ([`actions::ask_first`]). Demoting or revoking the last operator grant is refused: no
//! operator could then sign in through the provider. A sign-in link from the admin socket
//! restores access.
//! Without `[oidc]`, the page lists grants for future use; only the admin socket changes them.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};

use super::fleet::{self, FleetSite};
use super::html::Html;
use super::pages::{self, csrf_field};
use super::{Auth, Body, Ui, actions, blocking, field, message, page};
use crate::ops;
use crate::store::{ANYONE, AccountRow, LastOperator, Role};

/// The page, and where its forms post.
pub(super) const PATH: &str = "/users";

const OPERATORS_ONLY: &str = "Refused: this needs the operator role.";

const NO_OIDC: &str = "Refused: this hub has no [oidc] table, so nobody signs in through a \
     provider; `vk-hub accounts` keeps grants for when it has one.";

const LAST_OPERATOR: &str = "Refused: that would leave no address granted the operator role, \
     and nobody could then act on the fleet after signing in through the provider. Grant \
     another address the operator role first. Should it happen anyway, `vk-hub ui login --role \
     operator` on the hub's host prints a sign-in link that gets an operator back in.";

/// `GET /users`.
pub(super) async fn get(auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    if auth.session.role < Role::Operator {
        return Ok(message(StatusCode::FORBIDDEN, OPERATORS_ONLY));
    }
    let hub = ui.hub.clone();
    let grants = blocking(move || hub.db.accounts()).await?;
    let mut main = Html::new();
    main.raw("<h1>Users</h1>");
    match &ui.oidc {
        None => {
            main.raw("<p class=\"notes\">This hub has no <code>[oidc]</code> table: nobody ")
                .raw("signs in through a provider, only with links <code>vk-hub ui login</code> ")
                .raw("prints. The grants below take effect once OIDC is configured; until then ")
                .raw("<code>vk-hub accounts</code> changes them.</p>");
            main.html(&grants_section(&grants, None, None, false));
        }
        Some(oidc) => {
            let provider = Provider {
                host: oidc.provider(),
                default_role: ui.hub.db.oidc_default_role(),
            };
            main.raw("<div id=\"flash\"></div>").html(&grants_section(
                &grants,
                Some(&provider),
                Some(auth),
                false,
            ));
            grant_form(&mut main, auth);
        }
    }
    Ok(page(fleet::layout("Users", PATH, auth, &main)))
}

/// The OIDC provider these grants apply to.
struct Provider<'a> {
    /// Its host, which names `*`'s grant.
    host: &'a str,
    /// The role of whoever no grant names.
    default_role: Option<Role>,
}

/// Render grants with change and revoke forms when `auth` is an operator session on a hub
/// with `provider`. Actions replace this section out of band when `oob` is set.
fn grants_section(
    grants: &[(String, AccountRow)],
    provider: Option<&Provider>,
    auth: Option<&Auth>,
    oob: bool,
) -> Html {
    let mut h = Html::new();
    h.raw(if oob {
        "<section id=\"users\" hx-swap-oob=\"true\"><h2>Grants</h2>"
    } else {
        "<section id=\"users\"><h2>Grants</h2>"
    });
    if grants.is_empty() {
        h.raw("<p class=\"empty\">No address is granted a role.</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>who</th><th>role</th><th>granted by</th>")
            .raw("<th>when</th>");
        if auth.is_some() {
            h.raw("<th>change</th>");
        }
        h.raw("</tr></thead><tbody>");
        for (email, row) in grants {
            h.raw("<tr><td>");
            who(&mut h, email, provider);
            h.raw("</td><td><span class=\"badge")
                .raw(match row.role {
                    Role::Operator => " busy",
                    Role::Viewer => "",
                })
                .raw("\">")
                .raw(row.role.name())
                .raw("</span></td><td>")
                .text(&row.granted_by)
                .raw("</td><td>");
            pages::at(&mut h, row.granted_at).raw("</td>");
            if let Some(auth) = auth {
                h.raw("<td class=\"actions\">");
                if email != ANYONE {
                    change_form(&mut h, auth, email, row.role);
                }
                revoke_form(&mut h, auth, email);
                h.raw("</td>");
            }
            h.raw("</tr>");
        }
        h.raw("</tbody></table>");
    }
    if let Some(p) = provider {
        h.raw("<p class=\"sub\">Anyone else the provider signs in: ");
        if grants.iter().any(|(e, _)| e == ANYONE) {
            h.raw("<span class=\"badge\">viewer</span>, by the grant to everyone.");
        } else {
            match p.default_role {
                Some(role) => h
                    .raw("<span class=\"badge\">")
                    .raw(role.name())
                    .raw("</span> (<code>[oidc] default_role</code>)."),
                None => h.raw("<span class=\"badge bad\">refused</span>."),
            };
        }
        h.raw("</p>");
    }
    h.raw("</section>");
    h
}

/// Whom grant `email` names: an address, or everyone the provider signs in.
fn who(h: &mut Html, email: &str, provider: Option<&Provider>) {
    if email != ANYONE {
        h.text(email);
        return;
    }
    h.raw("Everyone signed in through ");
    match provider {
        Some(p) => h.text(p.host),
        None => h.raw("the provider"),
    };
}

/// The start of a form posting `op` on `email`'s grant, by htmx or as a plain form.
fn open_form(h: &mut Html, auth: &Auth, op: &'static str, email: &str) {
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"")
        .raw(op)
        .raw("\"><input type=\"hidden\" name=\"email\" value=\"")
        .text(email)
        .raw("\">");
}

/// A select of the roles, `selected` chosen.
fn role_select(h: &mut Html, selected: Role) {
    h.raw("<select name=\"role\" aria-label=\"Role\">");
    for role in [Role::Viewer, Role::Operator] {
        h.raw("<option value=\"").raw(role.name()).raw("\"");
        if role == selected {
            h.raw(" selected");
        }
        h.raw(">").raw(role.name()).raw("</option>");
    }
    h.raw("</select>");
}

fn change_form(h: &mut Html, auth: &Auth, email: &str, role: Role) {
    open_form(h, auth, "change", email);
    role_select(h, role);
    h.raw("<button>Change</button></form>");
}

fn revoke_form(h: &mut Html, auth: &Auth, email: &str) {
    open_form(h, auth, "revoke", email);
    h.raw("<button class=\"danger\">Revoke</button></form>");
}

/// The form granting an address a role.
fn grant_form(h: &mut Html, auth: &Auth) {
    h.raw("<section><h2>Grant a role</h2><form class=\"wide\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"grant\">")
        .raw("<label for=\"grant-email\">Email address</label>")
        .raw("<input id=\"grant-email\" type=\"text\" inputmode=\"email\" name=\"email\" ")
        .raw("autocomplete=\"off\" spellcheck=\"false\" required ")
        .raw("placeholder=\"name@example.com\">");
    role_select(h, Role::Viewer);
    h.raw("<button class=\"primary\">Grant</button></form>")
        .raw("<p class=\"sub\">The address the provider signs them in with, compared ignoring ")
        .raw("case; granting it again replaces its role. <code>*</code> grants everyone the ")
        .raw("provider signs in that no grant names, as a viewer only.</p></section>");
}

/// `POST /users`: set (`grant`, `change`) or revoke (`revoke`) `email`'s grant as the operator
/// session's principal, confirming demotions and revocations first. Return the status line
/// and updated grants for htmx, or redirect plain forms to `/users`. The page trims whitespace
/// around the address; the CLI preserves it.
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let Some(oidc) = &ui.oidc else {
        return Ok(actions::refused(htmx, StatusCode::CONFLICT, NO_OIDC));
    };
    let op = field(&form, "op").unwrap_or("").to_string();
    let role = match (op.as_str(), field(&form, "role")) {
        ("grant" | "change", Some("viewer")) => Some(Role::Viewer),
        ("grant" | "change", Some("operator")) => Some(Role::Operator),
        ("grant" | "change", _) => {
            return Ok(actions::refused(
                htmx,
                StatusCode::BAD_REQUEST,
                "Refused: a role is viewer or operator.",
            ));
        }
        ("revoke", _) => None,
        _ => {
            return Ok(actions::refused(
                htmx,
                StatusCode::BAD_REQUEST,
                "No such action.",
            ));
        }
    };
    let posted = field(&form, "email").unwrap_or("").trim();
    let Some(email) = crate::store::account_key(posted) else {
        return Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "Refused: that is not an email address: one with an @, and no spaces or control \
             characters.",
        ));
    };
    if email == ANYONE && role == Some(Role::Operator) {
        return Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "Refused: everyone the provider signs in may be granted the viewer role only.",
        ));
    }
    let hub = ui.hub.clone();
    let grants = blocking(move || hub.db.accounts()).await?;
    let previous = grants
        .iter()
        .find(|(e, _)| *e == email)
        .map(|(_, row)| row.role);
    // Refuse before asking for confirmation; the transaction checks again.
    let other_operator = grants
        .iter()
        .any(|(e, row)| *e != email && row.role == Role::Operator);
    if previous == Some(Role::Operator) && role != Some(Role::Operator) && !other_operator {
        return Ok(actions::refused(htmx, StatusCode::CONFLICT, LAST_OPERATOR));
    }
    if previous.is_some() && role < previous {
        let mut detail = Html::new();
        detail.raw("<p><strong>");
        who(&mut detail, &email, None);
        detail
            .raw("</strong>: ")
            .raw(previous.map_or("-", Role::name))
            .raw(" → ")
            .raw(role.map_or("no grant", Role::name))
            .raw("</p>");
        let mut asked = vec![("email", email.clone())];
        if let Some(role) = role {
            asked.push(("role", role.name().to_string()));
        }
        asked.push(("previous", previous.map_or("-", Role::name).to_string()));
        let ask = actions::Ask {
            path: PATH.to_string(),
            back: PATH.to_string(),
            op: op.clone(),
            what: if role.is_some() {
                "Lower this grant? Its sessions that hold more than a sign-in now gets end at \
                 once."
            } else {
                "Revoke this grant? Whom it admits can no longer sign in by it, and its \
                 sessions that hold more than a sign-in now gets end at once."
            },
            detail,
            asked,
        };
        if let Some(asked) =
            actions::ask_first(&site.questions, fleet::layout, htmx, &auth, &form, &ask)?
        {
            return Ok(asked);
        }
    }
    let principal = auth.session.principal();
    let hub = ui.hub.clone();
    let target = email.clone();
    let done = blocking(move || {
        let done = ops::set_account(&hub, &principal, &target, role, true);
        Ok((done, hub.db.accounts()?))
    })
    .await?;
    let (outcome, grants) = match done {
        (Ok(outcome), grants) => (outcome, grants),
        (Err(e), _) if e.is::<LastOperator>() => {
            return Ok(actions::refused(htmx, StatusCode::CONFLICT, LAST_OPERATOR));
        }
        (Err(e), _) => return Err(e),
    };
    if !htmx {
        let mut resp = Response::new(Body::default());
        *resp.status_mut() = StatusCode::SEE_OTHER;
        resp.headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static(PATH));
        return Ok(resp);
    }
    let shown = if email == ANYONE {
        format!("everyone signed in through {}", oidc.provider())
    } else {
        email.clone()
    };
    let change = outcome.change;
    let mut said = match (change.previous, role) {
        (p, r) if p == r => "Already so; nothing changed.".to_string(),
        (None, Some(r)) => format!("Granted {shown} the {} role.", r.name()),
        (Some(p), Some(r)) => format!(
            "Granted {shown} the {} role, replacing {}.",
            r.name(),
            p.name()
        ),
        (_, None) => format!("Revoked the grant of {shown}."),
    };
    if change.ended > 0 {
        said.push_str(&format!(
            " Ended {} web UI session(s) that held more than that.",
            change.ended
        ));
    }
    let provider = Provider {
        host: oidc.provider(),
        default_role: ui.hub.db.oidc_default_role(),
    };
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">")
        .text(&said)
        .raw("</div>")
        .html(&grants_section(&grants, Some(&provider), Some(&auth), true));
    Ok(actions::swap_none(super::html_response(StatusCode::OK, h)))
}
