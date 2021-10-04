// Code generated by "aws/internal/generators/listpages/main.go -function=ListApps github.com/aws/aws-sdk-go/service/amplify"; DO NOT EDIT.

package lister

import (
	"context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/amplify"
)

func ListAppsPages(conn *amplify.Amplify, input *amplify.ListAppsInput, fn func(*amplify.ListAppsOutput, bool) bool) error {
	return ListAppsPagesWithContext(context.Background(), conn, input, fn)
}

func ListAppsPagesWithContext(ctx context.Context, conn *amplify.Amplify, input *amplify.ListAppsInput, fn func(*amplify.ListAppsOutput, bool) bool) error {
	for {
		output, err := conn.ListAppsWithContext(ctx, input)
		if err != nil {
			return err
		}

		lastPage := aws.StringValue(output.NextToken) == ""
		if !fn(output, lastPage) || lastPage {
			break
		}

		input.NextToken = output.NextToken
	}
	return nil
}