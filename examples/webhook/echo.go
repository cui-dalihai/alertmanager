// Copyright 2018 Prometheus Team
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type InPutAlert struct {
	Fingerprint string `json:"fingerprint"`
	Labels map[string]string `json:"labels"`
}

type Resp struct {
	Alert []InPutAlert `json:"alerts"`
	Receiver string `json:"receiver"`
}

func main() {
	log.Fatal(http.ListenAndServe(":5001", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}
		ir := &Resp{}

		err = json.Unmarshal(b, &ir)
		if err != nil {
			panic(err)
		}
		defer r.Body.Close()
		for _, v := range ir.Alert {
			log.Println(v.Fingerprint, " receiver:", ir.Receiver, " ", v.Labels["alertname"])
		}
	})))
}
