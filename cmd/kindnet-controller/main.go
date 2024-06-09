package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	configv1alpha1 "github.com/aojea/kindnet/apis/generated/clientset/versioned/typed/config/v1alpha1"
)

func main() {
	// enable logging
	klog.InitFlags(nil)
	_ = flag.Set("logtostderr", "true")

	flag.Parse()
	flag.VisitAll(func(flag *flag.Flag) {
		log.Printf("FLAG: --%s=%q", flag.Name, flag.Value)
	})

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	// create a Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	config.UserAgent = "kindnet-controller"
	crdConfig := config // shallow copy because  CRDs does not support proto
	// use protobuf for better performance at scale
	// https://kubernetes.io/docs/reference/using-api/api-concepts/#alternate-representations-of-resources
	// npaConfig := config // shallow copy because  CRDs does not support proto
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	crdClientset, err := configv1alpha1.NewForConfig(crdConfig)
	if err != nil {
		panic(err.Error())
	}

}
