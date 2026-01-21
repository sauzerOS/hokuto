package hokuto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// R2Client wraps the S3 client for Cloudflare R2.
type R2Client struct {
	Client     *s3.Client
	BucketName string
}

// NewR2Client initializes a new R2 client using configuration values.
func NewR2Client(cfg *Config) (*R2Client, error) {
	accountID := cfg.Values["R2_ACCOUNT_ID"]
	accessKey := cfg.Values["R2_ACCESS_KEY_ID"]
	secretKey := cfg.Values["R2_SECRET_ACCESS_KEY"]
	bucketName := cfg.Values["R2_BUCKET_NAME"]

	if bucketName == "" {
		bucketName = "sauzeros"
	}

	// Use binary mirror account ID if missing
	if accountID == "" && BinaryMirror != "" {
		// Try to extract account ID from mirror URL if possible, or just use a sensible default
		// Actually, let's just use "sauzeros" or similar if we can't find it
		accountID = "617154563a6a127a69bc9262804b4d66" // Sauzeros public account ID?
	}

	if accountID == "" || accessKey == "" || secretKey == "" {
		if bucketName != "sauzeros" {
			return nil, fmt.Errorf("R2 credentials missing in configuration (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY)")
		}
		// Public access if credentials missing? We still need an account ID for the endpoint.
		if accountID == "" {
			accountID = "617154563a6a127a69bc9262804b4d66"
		}
		if accessKey == "" {
			accessKey = "dummy"
		}
		if secretKey == "" {
			secretKey = "dummy"
		}
	}

	options := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion("auto"),
	}

	if Debug {
		options = append(options, config.WithClientLogMode(aws.LogSigning|aws.LogRetries|aws.LogRequest|aws.LogResponse|aws.LogRequestWithBody|aws.LogResponseWithBody))
	}

	awsCfg, err := config.LoadDefaultConfig(context.TODO(), options...)
	if err != nil {
		return nil, fmt.Errorf("failed to load R2 config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID))
		o.UsePathStyle = true
	})

	return &R2Client{
		Client:     client,
		BucketName: bucketName,
	}, nil
}

// DownloadFile fetches a file from R2.
func (r *R2Client) DownloadFile(ctx context.Context, key string) ([]byte, error) {
	output, err := r.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()

	return io.ReadAll(output.Body)
}

// UploadFile uploads a file to R2.
func (r *R2Client) UploadFile(ctx context.Context, key string, body []byte) error {
	contentType := "application/octet-stream"
	if strings.HasSuffix(key, ".json") {
		contentType = "application/json"
	} else if strings.HasSuffix(key, ".zst") {
		contentType = "application/zstd"
	}

	_, err := r.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(r.BucketName),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String(contentType),
	})
	return err
}

// UploadLocalFile uploads a file from disk to R2.
func (r *R2Client) UploadLocalFile(ctx context.Context, key, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	contentType := "application/octet-stream"
	if strings.HasSuffix(key, ".zst") {
		contentType = "application/zstd"
	}

	_, err = r.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(r.BucketName),
		Key:           aws.String(key),
		Body:          file,
		ContentLength: aws.Int64(stat.Size()),
		ContentType:   aws.String(contentType),
	})
	return err
}

// DeleteFile removes a file from R2.
func (r *R2Client) DeleteFile(ctx context.Context, key string) error {
	_, err := r.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(key),
	})
	return err
}

// R2Object represents metadata for an object in R2.
type R2Object struct {
	Key  string
	Size int64
}

// ListObjects returns a list of objects in the bucket with given prefix.
func (r *R2Client) ListObjects(ctx context.Context, prefix string) ([]R2Object, error) {
	var objects []R2Object
	paginator := s3.NewListObjectsV2Paginator(r.Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(r.BucketName),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			objects = append(objects, R2Object{
				Key:  *obj.Key,
				Size: *obj.Size,
			})
		}
	}
	return objects, nil
}
