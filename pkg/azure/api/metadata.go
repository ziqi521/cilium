package api

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	metadataURL = "http://169.254.169.254/metadata"
	// current version of the metadata/instance service
	metadataAPIVersion = "2019-06-01"
)

func GetSubscriptionID(ctx context.Context) (string, error) {
	return getMetadataString(ctx, "instance/compute/subscriptionId")
}

func GetResourceGroupName(ctx context.Context) (string, error) {
	return getMetadataString(ctx, "instance/compute/resourceGroupName")
}

// getMetadataString returns the text represantation of a field from the Azure IMS (instance metadata service)
// more can be found at https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service#instance-api
func getMetadataString(ctx context.Context, path string) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	url := fmt.Sprintf("%s/%s", metadataURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil
	}

	query := req.URL.Query()
	query.Add("api-version", metadataAPIVersion)
	query.Add("format", "text")

	req.URL.RawQuery = query.Encode()
	req.Header.Add("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Errorf("failed to close body: %+v", err)
		}
	}()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBytes), nil
}
