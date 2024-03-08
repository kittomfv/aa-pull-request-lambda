use chrono::{DateTime, Local, Utc};
use lambda_http::{run, service_fn, Body, Error, Request, Response};

use lazy_static::lazy_static;
use serde::Deserialize;
use slack_messaging::{blocks::Section, Message};
use std::collections::HashMap;
use string_builder::Builder;
use tokio;

#[derive(Deserialize, Debug, Clone)]
struct User {
    id: u64,
    login: String,
    r#type: String,
}
#[derive(Deserialize, Debug, Clone)]
struct MyPullRequest {
    id: u64,
    title: String,
    updated_at: chrono::DateTime<chrono::Utc>,
    user: User,
    url: String,
}

lazy_static! {
    static ref MEMBERS: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("kittomfv", "U043UDK1DJ6");
        m.insert("dustinmfv", "U02J4N7C0TE");
        m.insert("pirlomnfw", "U03H8R4HF1C");
        m.insert("frankymfv", "U03ECBB3FGR");
        m
    };
}

struct PRs {
    prs: Vec<MyPullRequest>,
}

impl PRs {
    fn new() -> Self {
        PRs { prs: vec![] }
    }
    fn filter(day: i64, list_prs: Vec<MyPullRequest>) -> Self {
        let mut filter_prs = vec![];
        let now: DateTime<Utc> = Utc::now();
        for pr in list_prs {
            // println!("id:{:#?}, {:#?}, {:#?}", pr.id, pr.title, pr.updated_at);
            let delta = now.signed_duration_since(pr.updated_at);
            if delta.num_days() >= day && pr.user.r#type == "User" {
                println!(
                    "<@{}>: _{}_ last updated: {} - <{}| see more>\n ",
                    pr.user.id, pr.title, pr.updated_at, pr.url
                );

                filter_prs.push(pr);
            }
        }
        Self { prs: filter_prs }
    }
    fn convert_slack_data(&self) -> Result<String, anyhow::Error> {
        let mut builder = Builder::default();

        for pr in &self.prs {
            let local_updated_at: DateTime<Local> = DateTime::from(pr.updated_at);
            let tk = format!(
                "<@{}>: _{}_ last updated: *{}* - <{}| see more>\n ",
                MEMBERS
                    .get(pr.user.login.as_str())
                    .unwrap_or(&pr.user.login.as_str()),
                pr.title,
                local_updated_at.format("%d/%m/%Y - %H:%M VNT"),
                pr.url
            );

            builder.append(tk);
        }
        Ok(builder.string().unwrap())
    }
}
/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    println!("start main:{:#?}", event);
    // let (parts, body) = event.into_parts();
    // let body = serde_json::from_slice(&body)?;
    // let token = "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";
    let github_access_token = match std::env::var("GITHUB_ACCESS_TOKEN") {
        Ok(v) => v,
        Err(e) => panic!("Err: no config GITHUB_ACCESS_TOKEN variable: {}", e),
    };

    let slack_channel = match std::env::var("SLACK_NOTIFICATION_CHANNEL") {
        Ok(v) => v,
        Err(e) => panic!("Err: no config SLACK_NOTIFICATION_CHANNEL variable: {}", e),
    };

    let client = reqwest::Client::new();
    let list_prs = client
        .get("https://api.github.com/repos/moneyforwardvietnam/asset_accounting_backend/pulls")
        .bearer_auth(github_access_token)
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "AA Project")
        .send()
        .await?
        .json::<Vec<MyPullRequest>>()
        .await?;

    let tickets = PRs::filter(1, list_prs);
    let now: DateTime<Utc> = Utc::now();
    let message = Message::new()
        .push_block(Section::new().set_text_mrkdwn(format!(
            "*[{}] :alert: :sos: Report Pull Requests are > {} days:*",
            now.format("%d/%m/%Y"),
            2
        )))
        .push_block(Section::new().set_text_mrkdwn(tickets.convert_slack_data().unwrap()));

    let client2 = reqwest::ClientBuilder::new().build()?;
    let data = serde_json::to_string(&message)?;
    println!("{}", data);
    let _ = client2
        .post(slack_channel)
        .header("Content-type", "application/json")
        .body(data.clone())
        .send()
        .await
        .map_err(|e| {
            println!("err send to slack: {:#?}", e.to_string());
            e
        })?;
    let resp = Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body(Body::Text(data))
        .map_err(Box::new)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(function_handler)).await
}
