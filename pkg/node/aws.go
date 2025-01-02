// SPDX-License-Identifier: APACHE-2.0

package node

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func disableAWSSrcDstCheck() error {
	sess, err := session.NewSession()
	if err != nil {
		return fmt.Errorf("fail to create session: %w", err)
	}
	metadataClient := ec2metadata.New(sess)
	region, err := metadataClient.Region()
	if err != nil {
		return fmt.Errorf("fail to get EC2 region name: %v", err)
	}
	sess.Config.Region = aws.String(region)

	instanceID, err := metadataClient.GetMetadata("instance-id")
	if err != nil {
		return fmt.Errorf("fail to get EC2 instance ID: %v", err)
	}

	// Create new EC2 client
	client := ec2.New(sess)
	attr := &ec2.ModifyInstanceAttributeInput{
		InstanceId:      &instanceID,
		SourceDestCheck: &ec2.AttributeBooleanValue{Value: aws.Bool(false)},
	}

	_, err = client.ModifyInstanceAttribute(attr)
	if err != nil {
		return fmt.Errorf("fail to disable src check on AWS instance %s: %v", instanceID, err)
	}
	return nil
}
