.PHONY: fresh

fresh:
	docker-compose down --remove-orphans
	docker-compose up -d --build -V

run:
	go build -o ./bin/api-gateway
	./bin/api-gateway

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f
