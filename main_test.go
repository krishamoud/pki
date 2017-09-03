package main

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

const url = "http://localhost:9090"

func TestGenerateCertificate(t *testing.T) {
	t.Log("Generating a new certificate... (expected response code 200)")
	client := &http.Client{}
	req, err := http.NewRequest("POST", url+"/v1/certs", nil)
	req.Header.Add("x-user-id", "abc123")
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("Expected response code 200; got %d", resp.StatusCode)
	}
}

func TestVerifyCertificate(t *testing.T) {
	t.Log("Verifying certificate genereated by the test suite... (expected response code 200)")
	file, err := ioutil.ReadFile("ssl/abc123-crt.pem")
	if err != nil {
		t.Error(err)
	}
	header := strings.Replace(string(file), "\n", "\t", -1)
	client := &http.Client{}
	req, err := http.NewRequest("POST", url+"/v1/verify", nil)
	req.Header.Add("x-user-certificate", header)
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("Expected response code 200; got %d", resp.StatusCode)
	}
}

func TestRevokeCertificate(t *testing.T) {
	t.Log("Verifying revoked certificate genereated by the test suite... (expected response code 200)")
	file, err := ioutil.ReadFile("ssl/abc123-crt.pem")
	if err != nil {
		t.Error(err)
	}
	header := strings.Replace(string(file), "\n", "\t", -1)
	client := &http.Client{}
	user := UserRequestBody{UserId: "abc123"}
	bytes := new(bytes.Buffer)
	json.NewEncoder(bytes).Encode(user)
	req, err := http.NewRequest("DELETE", url+"/v1/certs", bytes)
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("Expected response code 200; got %d", resp.StatusCode)
	}
}
