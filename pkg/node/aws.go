/*
Copyright YEAR The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package node

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func getAWSInstanceID(ctx context.Context, client *imds.Client) (string, error) {
	identity, err := client.GetInstanceIdentityDocument(ctx, nil)
	if err != nil {
		return "", err
	}
	return identity.InstanceID, nil
}

func getAWSRegion(ctx context.Context, client *imds.Client) (string, error) {
	region, err := client.GetRegion(ctx, nil)
	if err != nil {
		return "", err
	}
	return region.Region, nil
}

func disableAWSSrcDstCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("fail to load AWS config: %w", err)
	}

	imdsClient := imds.NewFromConfig(cfg)
	region, err := getAWSRegion(ctx, imdsClient)
	if err != nil {
		return fmt.Errorf("fail to get EC2 region name: %w", err)
	}
	instanceID, err := getAWSInstanceID(ctx, imdsClient)
	if err != nil {
		return fmt.Errorf("fail to get EC2 instance ID: %w", err)
	}

	ec2Client := ec2.NewFromConfig(cfg, func(o *ec2.Options) {
		o.Region = region
	})
	attr := &ec2.ModifyInstanceAttributeInput{
		InstanceId: aws.String(instanceID),
		SourceDestCheck: &types.AttributeBooleanValue{
			Value: aws.Bool(false),
		},
	}
	_, err = ec2Client.ModifyInstanceAttribute(ctx, attr)
	if err != nil {
		return fmt.Errorf("fail to disable source/destination check on AWS instance %s: %w", instanceID, err)
	}

	return nil
}
