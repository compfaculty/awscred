package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"text/template"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	flag "github.com/spf13/pflag"
)

const credentialsTemplate = `[default]
aws_access_key_id = {{ .Credentials.AccessKeyId }}
aws_secret_access_key = {{ .Credentials.SecretAccessKey }}
aws_session_token = {{ .Credentials.SessionToken }}
`

var (
	mfa      string
	arn      string
	duration int64
)

func init() {
	flag.StringVar(&mfa, "mfa", "", "mfa code from auth app")
	flag.StringVar(&arn, "arn", "", "mfa device arn")
	flag.Int64Var(&duration, "duration", 21600, "access duration in seconds")
}

func main() {
	flag.Parse()
	dirname, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Program has started...")
	credentialsPath := path.Join(dirname, ".aws", "credentials")
	if _, err := os.Stat(credentialsPath); !os.IsNotExist(err) {
		if err := os.Remove(credentialsPath); err != nil {
			log.Fatalln(err)
		}
	}
	log.Printf("AWS creadentials file found %s\n : OK", credentialsPath)
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	resp, err := getToken(sess, arn, mfa, duration)
	if err != nil {
		fmt.Printf("error trying to get token %v", err.Error())
		os.Exit(1)
	}
	log.Println("get token: OK")
	t := template.Must(template.New("").Parse(credentialsTemplate))

	fd, err := os.OpenFile(credentialsPath, os.O_CREATE|os.O_WRONLY, 644)
	if err != nil {
		fmt.Printf("error open file %s %v", credentialsPath, err)
		os.Exit(1)
	}
	defer fd.Close()

	if err := t.Execute(fd, resp); err != nil {
		fmt.Println(err)
	}

	log.Printf("Expired after %v\n", *resp.Credentials.Expiration)
	log.Println("Update AWS credentials: OK")
}

func getToken(s *session.Session, arn, code string, duration int64) (*sts.GetSessionTokenOutput, error) {
	svc := sts.New(s)
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(duration),
		SerialNumber:    aws.String(arn),
		TokenCode:       aws.String(code),
	}

	result, err := svc.GetSessionToken(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case sts.ErrCodeRegionDisabledException:
				fmt.Println(sts.ErrCodeRegionDisabledException, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
		return nil, err
	}
	return result, nil
}
