# Stash

Stash is a small, single-node object storage server. It runs as one Go binary and stores data in one local directory.

## Run locally

Requires Go 1.25 or later. Build on macOS or Linux.

```sh
go build -o stash .
umask 077
cp stash.example.json stash.json
# Edit stash.json to replace the sample secrets with unique random secrets.
./stash -config stash.json
```

Stash binds to loopback by default. For remote use, configure both `tls_cert` and `tls_key`, or terminate TLS at a reverse proxy that preserves the signed request host, path, and query. Keep the configuration readable only by the service account. To rotate a credential, add a new access key and secret, restart, migrate the client, then remove the old credential and restart again.

Each credential maps bucket names to grants. A named grant takes precedence over `*`. The `read` grant allows listing and reading, `write` adds object writes and deletes, and `admin` adds bucket creation and deletion.

## Try the API

Use the credentials from your configuration. Configure path-style addressing and use the configured region.

```sh
aws configure set s3.addressing_style path --profile stash
export AWS_PROFILE=stash
export AWS_ACCESS_KEY_ID=stash-admin
export AWS_SECRET_ACCESS_KEY='<configured secret>'
export AWS_DEFAULT_REGION=us-east-1

aws --endpoint-url http://127.0.0.1:9000 s3api create-bucket --bucket reports
aws --endpoint-url http://127.0.0.1:9000 s3api put-object --bucket reports --key example.txt --body example.txt
aws --endpoint-url http://127.0.0.1:9000 s3api list-objects-v2 --bucket reports
aws --endpoint-url http://127.0.0.1:9000 s3api get-object --bucket reports --key example.txt downloaded.txt
```

## S3 subset

- Bucket APIs include CreateBucket, ListBuckets, HeadBucket, GetBucketLocation, and DeleteBucket for empty buckets. Bucket names use 3–63 lowercase ASCII letters, digits, or hyphens, starting and ending with a letter or digit.
- Object APIs include PutObject, GetObject, HeadObject, DeleteObject, DeleteObjects, and ListObjectsV2. Listing supports prefixes, delimiters, pagination, and URL-encoded keys.
- Uploads support up to 5 GiB per request, user metadata, and checksums sent in headers. Downloads support byte ranges and ETags.
- Requests use header-based SigV4 and path-style addressing. Multipart uploads, streaming SigV4 checksum trailers, presigned URLs, versioning, server-side copy, and S3 policy APIs are outside this subset.
- Verified with AWS CLI 2.36.8 using the default checksum settings and path-style addressing. The smoke test covered checksummed uploads, Unicode keys, paginated listing, range downloads, bucket isolation, restart persistence, and batch deletion.
- Compatibility work for boto3 and the Go AWS SDK v2 is pending. The companion replication server and analytics dashboard are follow-up milestones.

## Data and backups

Run a single Stash process per data directory on a local filesystem. Stash writes uploads to temporary files and publishes complete objects using atomic rename after checksum verification. Object metadata and bytes share one file. The `v1` subdirectory identifies the format version. Bucket listings scan local object metadata and are intended for small deployments.

Stop the server before backing up or restoring. Back up the entire data directory and protect a separate copy of the configuration and TLS files. Restore the directory and configuration before restarting.

## Linux builds

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o stash-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o stash-linux-arm64 .
```
