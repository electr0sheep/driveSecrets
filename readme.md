# driveSecrets

CLI tool to store secrets on Google Drive (cause why not?)

## Getting Started

### Dependencies

1. [Go](https://golang.org/)
2. [Cobra](https://github.com/spf13/cobra)
3. [Google API Go Client](https://github.com/googleapis/google-api-go-client)

### Setup
1. Install Go
```
brew install go
```
2. Install Cobra
```
go get -u github.com/spf13/cobra/cobra
```
3. Install Google API Go Client
```
go get -u google.golang.org/api/drive/v3
go get -u golang.org/x/oauth2/google
```

### Run

```
go run main.go
```

### Build

```
go build main.go
```

## Contributing

Don't bother, this isn't even close to being in a state where contributors are necessary.

## Authors

* [electr0sheep](https://github.com/electr0sheep)

## License

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details

## Acknowledgments

* The 21oz bag of pepperoni providing gamer fuel to me while writing this readme

## To-Do List
1. Make it work without having to do Google Dev API stuff
2. Store a copy of the drive file locally to reduce network usage?
3. Where should the aes key file go? How should it be stored? etc., etc.
4. How to securely handle client secret in api_credentials?
5. Possibly use viper to store aes key, name of file, location of file, cached data, etc.