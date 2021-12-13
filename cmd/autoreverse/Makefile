NAME = autoreverse

all:
	go build

race:
	go build -race

clean:
	go clean
	rm -f $(NAME)

test tests:
	go test -v ./...
