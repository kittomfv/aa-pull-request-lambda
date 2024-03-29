use chrono::{DateTime, Local, Utc};
use lambda_http::{run, service_fn, Body, Error, Request, RequestExt, Response};

use lazy_static::lazy_static;
use serde::Deserialize;
use slack_messaging::{
    blocks::{elements::Text, Block, Section},
    Message,
};
use std::{collections::HashMap, rc::Rc, sync::Arc};
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
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    user: User,
    html_url: String,
}

lazy_static! {
    static ref MEMBERS: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("kittomfv", "U043UDK1DJ6");
        m.insert("dustinmfv", "U02J4N7C0TE");
        m.insert("pirlomnfw", "U03H8R4HF1C");
        m.insert("frankymfv", "U03ECBB3FGR");
        m.insert("ThetaMFV", "U02QSMJ1BRQ");
        m.insert("leonmfv", "U03ALAZSSRE");
        m.insert("nicholas", "U03QJBJ951V");
        m.insert("augustmfv", "U0486QG6A9W");
        m.insert("Antom-Nguyen", "U036V63ML5Q");
        m.insert("shajMF", "U04N576LURH");
        m.insert("mfv-brian", "U02B92JJMA7");
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
            let delta = now.signed_duration_since(pr.created_at);
            if delta.num_days() >= day && pr.user.r#type == "User" {
                println!(
                    "<@{}>: *{}* days - _{}_ last updated: {} - <{}| see more>\n ",
                    pr.user.id,
                    delta.num_days(),
                    pr.title,
                    pr.updated_at,
                    pr.html_url
                );

                filter_prs.push(pr);
            }
        }
        Self { prs: filter_prs }
    }
    fn convert_slack_data(&self) -> Result<Vec<String>, anyhow::Error> {
        let now: DateTime<Utc> = Utc::now();
        let mut results: Vec<String> = vec![];
        let chunk_prs = self.prs.chunks(4);
        for chunk in chunk_prs {
            let mut builder = Builder::default();
            for pr in chunk {
                let local_updated_at: DateTime<Local> = DateTime::from(pr.updated_at);
                let delta = now.signed_duration_since(pr.created_at);
                let tk = format!(
                    "<@{}>: *{} days*  -  _{}_ last updated: *{}* - <{}| see more>\n ",
                    MEMBERS
                        .get(pr.user.login.as_str())
                        .unwrap_or(&pr.user.login.as_str()),
                    delta.num_days(),
                    pr.title,
                    local_updated_at.format("%d/%m/%Y - %H:%M VNT"),
                    pr.html_url
                );

                builder.append(tk);
            }
            results.push(builder.string().unwrap())
        }

        Ok(results)
    }
}

#[derive(Deserialize, Debug)]
struct PullRequestParams {
    max_hour: u32,
    key: String,
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    println!("start main:{:?}", event);
    let slack_channel = match std::env::var("SLACK_NOTIFICATION_CHANNEL_BE") {
        Ok(v) => v,
        Err(e) => panic!("Err: no config SLACK_NOTIFICATION_CHANNEL variable: {}", e),
    };
    let slack_channel_fe = match std::env::var("SLACK_NOTIFICATION_CHANNEL_FE") {
        Ok(v) => v,
        Err(e) => panic!("Err: no config SLACK_NOTIFICATION_CHANNEL variable: {}", e),
    };
    println!("slack channel:{}", slack_channel);
    let slack_fe = Arc::new(slack_channel_fe);

    let ops = vec![
        (
            "AA Backend",
            "https://api.github.com/repos/moneyforwardvietnam/asset_accounting_backend/pulls",
            slack_channel,
        ),
        (
            "AA Frontend",
            "https://api.github.com/repos/moneyforwardvietnam/asset_accounting_frontend/pulls",
            slack_fe.clone().to_string(),
        ),
        (
            "AA FE Common",
            "https://api.github.com/repos/moneyforwardvietnam/aa_common/pulls",
            slack_fe.clone().to_string(),
        ),
    ];
    let mut tasks = Vec::with_capacity(ops.len());
    for op in ops {
        // This call will make them start running in the background
        // immediately.
        tasks.push(tokio::spawn(run_each(
            op.0.to_string(),
            op.1.to_string(),
            op.2.to_string(),
        )));
    }
    let mut outputs = Vec::with_capacity(tasks.len());
    for task in tasks {
        outputs.push(task.await.unwrap()?);
    }
    println!("{:?}", outputs);

    Ok(Response::new(Body::Text("success".to_string())))
}

async fn run_each(
    repo_name: String,
    github_url: String,
    slack_channel: String,
) -> Result<Response<Body>, Error> {
    println!("github_url:{github_url}, slack:{slack_channel}");
    let github_access_token = match std::env::var("GITHUB_ACCESS_TOKEN") {
        Ok(v) => v,
        Err(e) => panic!("Err: no config GITHUB_ACCESS_TOKEN variable: {}", e),
    };

    let client = reqwest::Client::new();
    let list_prs = client
        .get(github_url)
        .bearer_auth(github_access_token)
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "AA Project")
        .send()
        .await?
        .json::<Vec<MyPullRequest>>()
        .await
        .map_err(|e| {
            println!("Err: can not get pull request from github {}", e);
            e
        })?;

    let tickets = PRs::filter(1, list_prs);
    let now: DateTime<Utc> = Utc::now();
    let mut message = Message::new().push_block(Section::new().set_text_mrkdwn(format!(
        "*[{}] {} :alert: :sos: Report Pull Requests are > {} days:*",
        now.format("%d/%m/%Y"),
        repo_name,
        2
    )));

    let blocks = tickets
        .convert_slack_data()
        .unwrap()
        .iter()
        .map(|block| Block::Section(Box::new(Section::new().set_text_mrkdwn(block))))
        .collect::<Vec<Block>>();

    let _ = blocks
        .iter()
        .for_each(|b| message = message.clone().push_block(b.clone()));

    let data = serde_json::to_string(&message)?;
    println!("{}", data);
    let _ = reqwest::ClientBuilder::new()
        .build()?
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
