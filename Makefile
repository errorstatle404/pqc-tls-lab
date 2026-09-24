.PHONY: up bench bench-wan capture smoke logs shell down clean \
        aws-test aws-up aws-status aws-smoke aws-bench aws-bench-wan aws-down

N ?= 200
DELAY_MS ?= 25

up:            ## build the image and start server + client
	docker compose up -d --build --wait

smoke: up      ## one request per endpoint through the OpenSSL 3.5 CLI
	@for p in 8443 8444 8446; do \
	  docker compose exec -T pqc-client sh -c "printf 'GET / HTTP/1.0\r\n\r\n' | openssl s_client -quiet -verify_quiet -connect pqc-server:$$p -CAfile /etc/pqc-lab/certs/ecdsa/ca.crt 2>/dev/null | tail -1"; \
	done
	@docker compose exec -T pqc-client sh -c "printf 'GET / HTTP/1.0\r\n\r\n' | openssl s_client -quiet -verify_quiet -connect pqc-server:8445 -groups MLKEM1024 -CAfile /etc/pqc-lab/certs/mldsa/ca.crt 2>/dev/null | tail -1"

bench: up      ## run all handshake scenarios (loopback) + primitive benchmarks
	docker compose exec -T -e N=$(N) pqc-client run-bench.sh

bench-wan: up  ## same scenarios with DELAY_MS added per round trip (tc netem)
	docker compose exec -T -e N=50 -e DELAY_MS=$(DELAY_MS) pqc-client run-bench.sh

capture: up    ## write results/handshakes.pcap for Wireshark
	docker compose exec -T pqc-client capture.sh

logs:          ## server access log shows the negotiated group per request
	docker compose logs -f pqc-server

shell:
	docker compose exec pqc-client sh

down:
	docker compose down

clean:         ## also removes generated certs
	docker compose down -v

# ---------------- AWS (deploy/aws, Terraform) ----------------
TF ?= terraform
AWS_DIR := deploy/aws

aws-test:      ## offline Terraform tests (mocked AWS, no credentials needed)
	$(TF) -chdir=$(AWS_DIR) init -input=false -backend=false >/dev/null
	$(TF) -chdir=$(AWS_DIR) test

aws-up:        ## create the VPC, lab server and scanner (asks for confirmation)
	$(TF) -chdir=$(AWS_DIR) init -input=false
	$(TF) -chdir=$(AWS_DIR) apply

aws-status:    ## is the scanner done bootstrapping? (takes ~15 min after aws-up)
	TF=$(TF) $(AWS_DIR)/bench.sh status

aws-smoke:     ## one request per endpoint, scanner -> server across AZs
	TF=$(TF) $(AWS_DIR)/bench.sh smoke

aws-bench:     ## full scenario matrix over the VPC; results synced to results/aws/
	TF=$(TF) $(AWS_DIR)/bench.sh bench

aws-bench-wan: ## same, with DELAY_MS extra per round trip on top of the real network
	TF=$(TF) $(AWS_DIR)/bench.sh bench-wan

aws-down:      ## destroy everything, including the S3 bucket and log group
	$(TF) -chdir=$(AWS_DIR) destroy
