//! Delivery over AWS SES v2 (feature `mail-ses`): rustls, no C, the standard
//! AWS credential chain. Two messages, each as plain text and a themed HTML
//! twin built from email-safe tables and inline styles:
//!
//! - the **code** ([`CodeMessage`]) — no links, nothing to phish; copy for a
//!   new account and for a sign-in;
//! - the **welcome** ([`WelcomeMessage`]) — once, after the first sign-up,
//!   with the tenant's points and an optional button.
//!
//! [`MailTheme`] carries the brand: product name, accent colours, welcome
//! points, button, footer. The default is neutral; an operator build (e.g.
//! `mata-signup`) passes its own.

use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};

use crate::seams::{BoxFuture, CodeMessage, MailError, Mailer, WelcomeMessage};

/// The look and words of the emails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailTheme {
    /// The product name in subjects and copy; `None` uses the tenant's name.
    pub product: Option<String>,
    /// The wordmark at the top (plain text, letter-spaced).
    pub wordmark: Option<String>,
    /// Accent colour (`#RRGGBB`): wordmark, top bar, button.
    pub accent: String,
    /// A second accent for the top bar's gradient.
    pub accent_end: String,
    /// A pale tint of the accent: the code panel.
    pub accent_soft: String,
    /// The welcome email's points: (title, sentence).
    pub welcome_points: Vec<(String, String)>,
    /// The welcome email's button: (label, `https://` URL).
    pub welcome_button: Option<(String, String)>,
    /// The line under every email.
    pub footer: String,
}

impl Default for MailTheme {
    fn default() -> Self {
        Self {
            product: None,
            wordmark: None,
            accent: "#4F46E5".into(),
            accent_end: "#7C3AED".into(),
            accent_soft: "#EEF0FF".into(),
            welcome_points: Vec::new(),
            welcome_button: None,
            footer: "You received this because this address was used to sign up.".into(),
        }
    }
}

/// Sends codes and welcomes through SES.
#[derive(Clone)]
pub struct SesMailer {
    client: aws_sdk_sesv2::Client,
    from: String,
    theme: MailTheme,
}

impl std::fmt::Debug for SesMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SesMailer")
            .field("from", &self.from)
            .finish_non_exhaustive()
    }
}

impl SesMailer {
    /// `Some` when `SES_FROM_ADDRESS` is set (credentials and region from
    /// the standard chain); `None` otherwise.
    pub async fn from_env() -> Option<Self> {
        let from = std::env::var("SES_FROM_ADDRESS")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        tracing::info!(%from, "SES mailer enabled");
        Some(Self::new(aws_sdk_sesv2::Client::new(&cfg), from))
    }

    /// Wrap a configured client and a verified sender, e.g.
    /// `Acme <signup@mail.acme.com>`.
    pub fn new(client: aws_sdk_sesv2::Client, from: impl Into<String>) -> Self {
        Self {
            client,
            from: from.into(),
            theme: MailTheme::default(),
        }
    }

    /// Use `theme` for every message.
    pub fn with_theme(mut self, theme: MailTheme) -> Self {
        self.theme = theme;
        self
    }

    async fn send(&self, to: &str, subject: String, text: String, html: String) -> Result<(), MailError> {
        let content = |s: String| {
            Content::builder()
                .data(s)
                .charset("UTF-8")
                .build()
                .map_err(|e| MailError::Transport(e.to_string()))
        };
        let body = Body::builder().text(content(text)?).html(content(html)?).build();
        let message = Message::builder().subject(content(subject)?).body(body).build();
        self.client
            .send_email()
            .from_email_address(&self.from)
            .destination(Destination::builder().to_addresses(to).build())
            .content(EmailContent::builder().simple(message).build())
            .send()
            .await
            .map(|_| ())
            .map_err(|e| {
                // `Display` on an SDK error is just "service error"; the context
                // form carries AWS's code and message, which an operator needs.
                let detail = aws_sdk_sesv2::error::DisplayErrorContext(&e).to_string();
                if detail.contains("MessageRejected") || detail.contains("AccountSuspended") {
                    MailError::Rejected(detail)
                } else {
                    MailError::Transport(detail)
                }
            })
    }
}

impl Mailer for SesMailer {
    fn send_code(&self, msg: CodeMessage) -> BoxFuture<'_, Result<(), MailError>> {
        Box::pin(async move {
            let (subject, text, html) = render_code(&self.theme, &msg);
            self.send(msg.to.as_str(), subject, text, html).await
        })
    }

    fn send_welcome(&self, msg: WelcomeMessage) -> BoxFuture<'_, Result<(), MailError>> {
        Box::pin(async move {
            let (subject, text, html) = render_welcome(&self.theme, &msg);
            self.send(msg.to.as_str(), subject, text, html).await
        })
    }

    fn kind(&self) -> &'static str {
        "ses"
    }
}

// ─── rendering (pure, tested) ─────────────────────────────────────────────────

/// Escape text for an HTML body.
fn esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// A theme colour, or a safe grey when it is not `#RRGGBB` (it lands in CSS).
fn colour(c: &str) -> &str {
    let ok = c.len() == 7 && c.starts_with('#') && c[1..].bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        c
    } else {
        "#555555"
    }
}

const FONT: &str = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO: &str = "'SF Mono',SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace";

/// The shared frame: preheader, card, top bar, wordmark, `inner`, footer.
fn frame(theme: &MailTheme, title: &str, preheader: &str, inner: &str) -> String {
    let accent = colour(&theme.accent);
    let accent_end = colour(&theme.accent_end);
    let wordmark = theme
        .wordmark
        .as_deref()
        .map(|w| {
            format!(
                "<tr><td style=\"padding:28px 36px 0;font:700 13px/1 {FONT};letter-spacing:0.28em;color:{accent};\">{}</td></tr>",
                esc(w)
            )
        })
        .unwrap_or_default();
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"color-scheme\" content=\"light dark\"><meta name=\"supported-color-schemes\" content=\"light dark\">\
<title>{title}</title></head>\
<body style=\"margin:0;padding:0;background:#F3F1F7;\">\
<div style=\"display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;\">{preheader}</div>\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#F3F1F7;padding:36px 12px;\">\
<tr><td align=\"center\">\
<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"max-width:480px;background:#FFFFFF;border-radius:18px;overflow:hidden;border:1px solid #E7E3EE;\">\
<tr><td style=\"height:6px;line-height:6px;font-size:0;background-color:{accent};background-image:linear-gradient(90deg,{accent},{accent_end});\">&nbsp;</td></tr>\
{wordmark}{inner}\
</table>\
<p style=\"max-width:480px;margin:18px auto 0;font:400 12px/1.6 {FONT};color:#8A8496;text-align:center;\">{footer}</p>\
</td></tr></table></body></html>",
        title = esc(title),
        preheader = esc(preheader),
        footer = esc(&theme.footer),
    )
}

/// Subject, plain text and HTML for a code.
pub fn render_code(theme: &MailTheme, msg: &CodeMessage) -> (String, String, String) {
    let product = theme.product.clone().unwrap_or_else(|| msg.tenant_name.clone());
    let minutes = msg.expires_in_secs.div_ceil(60);
    let mins = format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" });
    let code = msg.code.as_str();
    let (heading, lead) = if msg.create_user {
        (
            "Confirm your email".to_string(),
            format!("Enter this code in {product} to finish creating your account."),
        )
    } else {
        (
            "Your sign-in code".to_string(),
            format!("Enter this code in {product} to sign in."),
        )
    };
    let subject = format!("{code} is your {product} code");
    let preheader = format!("Your {product} code is {code}. It expires in {mins}.");
    let safety = format!(
        "{product} will never ask you for this code by phone, email or chat. \
         If you didn't request it, ignore this email: nothing happens without the code."
    );
    let text = format!(
        "{heading}\n\n{lead}\n\n    {code}\n\nIt expires in {mins}.\n\n{safety}\n\n--\n{footer}\n",
        footer = theme.footer
    );
    let accent_soft = colour(&theme.accent_soft);
    let inner = format!(
        "<tr><td style=\"padding:22px 36px 0;font:700 24px/1.25 {FONT};color:#16101F;\">{heading}</td></tr>\
<tr><td style=\"padding:10px 36px 0;font:400 15px/1.6 {FONT};color:#4A4458;\">{lead}</td></tr>\
<tr><td style=\"padding:24px 36px 8px;\">\
<div style=\"background:{accent_soft};border-radius:14px;padding:20px 8px;text-align:center;font:700 36px/1 {MONO};letter-spacing:0.34em;color:#16101F;\">{code}</div>\
</td></tr>\
<tr><td style=\"padding:4px 36px 0;font:400 13px/1.6 {FONT};color:#6B6578;text-align:center;\">Expires in {mins}</td></tr>\
<tr><td style=\"padding:24px 36px 32px;\">\
<div style=\"border-top:1px solid #EEEBF3;padding-top:18px;font:400 13px/1.6 {FONT};color:#6B6578;\">{safety}</div>\
</td></tr>",
        heading = esc(&heading),
        lead = esc(&lead),
        code = esc(code),
        mins = esc(&mins),
        safety = esc(&safety),
    );
    let html = frame(theme, &subject, &preheader, &inner);
    (subject, text, html)
}

/// Subject, plain text and HTML for a welcome.
pub fn render_welcome(theme: &MailTheme, msg: &WelcomeMessage) -> (String, String, String) {
    let product = theme.product.clone().unwrap_or_else(|| msg.tenant_name.clone());
    let who = msg
        .username
        .as_deref()
        .map(|u| format!(", @{u}"))
        .unwrap_or_default();
    let subject = format!("Welcome to {product}{who}");
    let heading = format!("Welcome to {product}{who}");
    let lead = "Your account is ready. Here is what you can do next.".to_string();
    let preheader = format!("Your {product} account is ready.");

    let mut text = format!("{heading}\n\n{lead}\n\n");
    for (title, line) in &theme.welcome_points {
        text.push_str(&format!("- {title}: {line}\n"));
    }
    if let Some((label, url)) = &theme.welcome_button {
        text.push_str(&format!("\n{label}: {url}\n"));
    }
    text.push_str(&format!("\n--\n{}\n", theme.footer));

    let accent = colour(&theme.accent);
    let accent_soft = colour(&theme.accent_soft);
    let points: String = theme
        .welcome_points
        .iter()
        .enumerate()
        .map(|(i, (title, line))| {
            format!(
                "<tr><td style=\"padding:0 36px 16px;\">\
<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\"><tr>\
<td valign=\"top\" style=\"width:30px;\"><div style=\"width:26px;height:26px;border-radius:13px;background:{accent_soft};color:{accent};font:700 13px/26px {FONT};text-align:center;\">{n}</div></td>\
<td valign=\"top\" style=\"padding-left:12px;font:400 14px/1.55 {FONT};color:#4A4458;\"><strong style=\"color:#16101F;\">{title}</strong><br>{line}</td>\
</tr></table></td></tr>",
                n = i + 1,
                title = esc(title),
                line = esc(line),
            )
        })
        .collect();
    let button = theme
        .welcome_button
        .as_ref()
        .filter(|(_, url)| url.starts_with("https://"))
        .map(|(label, url)| {
            format!(
                "<tr><td style=\"padding:12px 36px 8px;\">\
<a href=\"{url}\" style=\"display:inline-block;background:{accent};color:#FFFFFF;text-decoration:none;font:600 15px/1 {FONT};padding:14px 26px;border-radius:12px;\">{label}</a>\
</td></tr>",
                url = esc(url),
                label = esc(label),
            )
        })
        .unwrap_or_default();
    let inner = format!(
        "<tr><td style=\"padding:22px 36px 0;font:700 24px/1.25 {FONT};color:#16101F;\">{heading}</td></tr>\
<tr><td style=\"padding:10px 36px 22px;font:400 15px/1.6 {FONT};color:#4A4458;\">{lead}</td></tr>\
{points}{button}<tr><td style=\"padding:0 0 28px;\">&nbsp;</td></tr>",
        heading = esc(&heading),
        lead = esc(&lead),
    );
    let html = frame(theme, &subject, &preheader, &inner);
    (subject, text, html)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Code, NormalizedEmail, TenantId};

    fn code_msg(create_user: bool, tenant_name: &str) -> CodeMessage {
        CodeMessage {
            to: NormalizedEmail::parse("a@b.co").unwrap(),
            tenant: TenantId::parse("acme").unwrap(),
            tenant_name: tenant_name.into(),
            code: Code::parse("012345").unwrap(),
            expires_in_secs: 600,
            create_user,
        }
    }

    #[test]
    fn the_code_email_is_escaped_linkless_and_says_which_flow() {
        let t = MailTheme::default();
        let (subject, text, html) = render_code(&t, &code_msg(true, "<script>Acme</script>"));
        assert!(subject.starts_with("012345 is your"), "the code first, for the notification preview");
        assert!(html.contains("012345") && text.contains("012345"));
        assert!(html.contains("&lt;script&gt;Acme&lt;/script&gt;") && !html.contains("<script>"));
        assert!(!html.contains("href"), "no links in a code email");
        assert!(html.contains("Confirm your email") && html.contains("10 minutes"));
        let (_, _, signin) = render_code(&t, &code_msg(false, "Acme"));
        assert!(signin.contains("Your sign-in code"));
    }

    #[test]
    fn the_theme_brands_both_emails_and_unsafe_values_are_neutralised() {
        let t = MailTheme {
            product: Some("MATA".into()),
            wordmark: Some("MATA".into()),
            accent: "#8347B9".into(),
            accent_end: "red;}<x>".into(),
            welcome_points: vec![("Keys".into(), "Yours <b>only</b>".into())],
            welcome_button: Some(("Open".into(), "https://my.example".into())),
            ..MailTheme::default()
        };
        let (subject, _, html) = render_code(&t, &code_msg(true, "Tenant"));
        assert_eq!(subject, "012345 is your MATA code");
        assert!(html.contains("#8347B9") && !html.contains("red;}"), "a non-hex colour never reaches the CSS");
        let w = WelcomeMessage {
            to: NormalizedEmail::parse("a@b.co").unwrap(),
            tenant: TenantId::parse("acme").unwrap(),
            tenant_name: "Tenant".into(),
            username: Some("tim<".into()),
        };
        let (subject, text, html) = render_welcome(&t, &w);
        assert_eq!(subject, "Welcome to MATA, @tim<");
        assert!(html.contains("@tim&lt;") && html.contains("Yours &lt;b&gt;only&lt;/b&gt;"));
        assert!(html.contains("href=\"https://my.example\"") && text.contains("Open: https://my.example"));
        let insecure = MailTheme { welcome_button: Some(("x".into(), "javascript:alert(1)".into())), ..t };
        assert!(!render_welcome(&insecure, &w).2.contains("href"), "only https buttons");
    }
}
