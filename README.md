# Create a role

aws iam create-role \
  --role-name rust-role \
  --assume-role-policy-document file://rust-role.json


# Build
```rust
cargo lambda build  
```

# Deploy

cargo lambda deploy --iam-role arn:aws:iam::747194874562:role/rust-role --enable-function-url


# Setup environmnent variable 



Setup 2 variable `GITHUB_ACCESS_TOKEN` and `SLACK_NOTIFICATION_CHANNEL`