.PHONY: install test eval adk-web adk-run agents-deploy tf-init tf-plan

install:
	python3 -m pip install -r requirements.txt

test:
	pytest -v

eval:
	pytest tests/test_eval_suite.py -v

adk-web:
	adk web .

adk-run:
	adk run sre_agent

agents-deploy:
	agents-cli deploy --no-confirm-project

tf-init:
	cd terraform && terraform init -backend=false

tf-plan:
	cd terraform && terraform plan -var="project_id=$${GOOGLE_CLOUD_PROJECT:-demo-gcp-project}"
