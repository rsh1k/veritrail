.PHONY: install test demo serve docker-build docker-up clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

demo:
	python -m examples.demo

serve:
	uvicorn veritrail.api.server:app --host 0.0.0.0 --port 8080 --reload

docker-build:
	docker build -t veritrail:0.2.2 .

docker-up:
	docker compose up --build

clean:
	rm -rf __pycache__ */__pycache__ .pytest_cache *.egg-info build dist *.html
