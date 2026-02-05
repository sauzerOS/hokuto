package hokuto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/schollz/progressbar/v3"
)

// R2Client wraps the S3 client for Cloudflare R2.
type R2Client struct {
	Client     *s3.Client
	BucketName string
	Config     *Config
}

// NewR2Client initializes a new S3/R2 client using configuration values.
func NewR2Client(cfg *Config) (*R2Client, error) {
	// 1. Try to load from Active Mirror configuration first
	activeMirrorName := cfg.Values["HOKUTO_MIRROR_NAME"]
	var endpoint, accessKey, secretKey, bucketName, region string
	var usePathStyle bool

	if activeMirrorName != "" {
		// Load from mirror config
		endpoint = cfg.Values["MIRROR_"+activeMirrorName+"_URL"]
		accessKey = cfg.Values["MIRROR_"+activeMirrorName+"_ACCESS_KEY"]
		secretKey = cfg.Values["MIRROR_"+activeMirrorName+"_SECRET_KEY"]
		bucketName = cfg.Values["MIRROR_"+activeMirrorName+"_BUCKET"]
		region = cfg.Values["MIRROR_"+activeMirrorName+"_REGION"]
		mType := cfg.Values["MIRROR_"+activeMirrorName+"_TYPE"]

		if mType == "s3" || mType == "minio" {
			usePathStyle = true
		}
	}

	// 2. Fallback to Legacy R2 Environment Variables if keys missing
	// (This preserves backward compatibility for the existing R2 setup)
	if accessKey == "" || secretKey == "" {
		accountID := cfg.Values["R2_ACCOUNT_ID"]
		accessKey = cfg.Values["R2_ACCESS_KEY_ID"]
		secretKey = cfg.Values["R2_SECRET_ACCESS_KEY"]
		bucketName = cfg.Values["R2_BUCKET_NAME"]

		if accountID != "" {
			endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)
		}
	}

	// Defaults
	if bucketName == "" {
		bucketName = "sauzeros"
	}
	if region == "" {
		region = "auto"
	}

	if accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("S3/R2 credentials missing (checked active mirror '%s' and legacy R2_* vars)", activeMirrorName)
	}

	options := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion(region),
	}

	if Debug {
		options = append(options, config.WithClientLogMode(aws.LogSigning|aws.LogRetries|aws.LogRequest|aws.LogResponse))
	}

	awsCfg, err := config.LoadDefaultConfig(context.TODO(), options...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS/S3 config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		o.UsePathStyle = usePathStyle
	})

	return &R2Client{
		Client:     client,
		BucketName: bucketName,
		Config:     cfg,
	}, nil
}

// progressReadSeeker wraps an io.ReadSeeker to track progress smoothly.
type progressReadSeeker struct {
	inner io.ReadSeeker
	bar   *progressbar.ProgressBar
}

func (p *progressReadSeeker) Read(b []byte) (int, error) {
	n, err := p.inner.Read(b)
	p.bar.Add(n)
	return n, err
}

func (p *progressReadSeeker) Seek(offset int64, whence int) (int64, error) {
	return p.inner.Seek(offset, whence)
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
func (r *R2Client) UploadFile(ctx context.Context, key string, body []byte, progress ...int) error {
	contentType := "application/octet-stream"
	if strings.HasSuffix(key, ".json") {
		contentType = "application/json"
	} else if strings.HasSuffix(key, ".zst") {
		contentType = "application/zstd"
	}

	uploader := manager.NewUploader(r.Client, func(u *manager.Uploader) {
		u.PartSize = 10 * 1024 * 1024 // 10MiB (must be <= 16MiB for some mirrors)
		u.Concurrency = 1             // Disable concurrency for smooth, linear progress bar updates
	})

	// Print status line first
	sizeStr := humanReadableSize(int64(len(body)))
	colArrow.Print("-> ")
	if len(progress) >= 2 {
		colNote.Printf("[%d/%d] ", progress[0], progress[1])
	}
	colSuccess.Printf("Uploading %s (%s)\n", key, sizeStr)

	// Initialize progress bar on the next line
	bar := progressbar.NewOptions64(
		int64(len(body)),
		progressbar.OptionSetDescription("   "),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(10*time.Millisecond), // Fast update throttled at 100fps
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "▓",
			SaucerHead:    "▓",
			SaucerPadding: "░",
			BarStart:      "┃",
			BarEnd:        "┃",
		}),
	)

	_, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(r.BucketName),
		Key:         aws.String(key),
		Body:        &progressReadSeeker{inner: bytes.NewReader(body), bar: bar},
		ContentType: aws.String(contentType),
	})
	if err == nil {
		bar.Finish()
	}
	return err
}

// UploadLocalFile uploads a file from disk to R2.
func (r *R2Client) UploadLocalFile(ctx context.Context, key, filePath string, progress ...int) error {
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

	uploader := manager.NewUploader(r.Client, func(u *manager.Uploader) {
		u.PartSize = 10 * 1024 * 1024 // 10MiB
		u.Concurrency = 1             // Sequential for better progress visualization
	})

	// Print status line first
	sizeStr := humanReadableSize(stat.Size())
	colArrow.Print("-> ")
	if len(progress) >= 2 {
		colNote.Printf("[%d/%d] ", progress[0], progress[1])
	}
	colSuccess.Printf("Uploading %s (%s)\n", key, sizeStr)

	// Initialize progress bar on the next line
	bar := progressbar.NewOptions64(
		stat.Size(),
		progressbar.OptionSetDescription("   "),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(10*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "▓",
			SaucerHead:    "▓",
			SaucerPadding: "░",
			BarStart:      "┃",
			BarEnd:        "┃",
		}),
	)

	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(r.BucketName),
		Key:         aws.String(key),
		Body:        &progressReadSeeker{inner: file, bar: bar},
		ContentType: aws.String(contentType),
	})
	if err == nil {
		bar.Finish()
	}
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
