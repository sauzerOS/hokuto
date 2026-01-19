package hokuto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

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

	if accountID == "" || accessKey == "" || secretKey == "" || bucketName == "" {
		return nil, fmt.Errorf("R2 credentials missing in configuration (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME)")
	}

	r2Resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID),
		}, nil
	})

	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(r2Resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load R2 config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)

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
	_, err := r.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(key),
		Body:   bytes.NewReader(body),
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

	_, err = r.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(r.BucketName),
		Key:    aws.String(key),
		Body:   file,
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
