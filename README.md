
This application is an excercise in generating ECDSA keys and a bit of Docker.


## Running the application

### Using go build

`go build && ./codechallenge rexposadas@gmail.com`

If you have jq installed, you can do the following for a prettier format. 

```
➜ go build && ./codechallenge rexposadas@gmail.com | jq '.'
{
  "message": "rexposadas@gmail.com",
  "signature": "MEQCIEPhR7qSl+WPNgYuHQqd9DG56IN4eXiVVwSQzr3wtxy7AiAQDk0xdaxjVSy+cc1dJxBtpemzDDohdhZ5tu3PWitwWg==",
  "pubkey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcm6UU3W8TGK6IWHb+POnSpFf2VmP\n1Y2vJ52miaNTTuiMi1jlZ+tXDn4XiTQ9+SDcEjOGvBdC/eo8SzECZLuzXQ==\n-----END PUBLIC KEY-----\n"
}
```

### Using Docker

```
docker build . -t codechal
docker run codechal "your@email.com"
```


## Testing the application

### Without Docker

Use the built in test command `go test ./...`

### Using Docker in a CI/CD pipeline

I don't have much experience integrating Docker to CI/CD. One way I would attempt this is to create a `test.sh` file which calls `go test`.  Then, the Docker container will accept an environment flag which, if toggled on, would run `test.sh` inside the Docker container. 

I can see running a similar command to the one below during the deployment process:

`docker run -e test=true codechal`


### Design decisions I needed to make

1.  In the requirements it stated "Subsequent invocations of your application should read from the same files". I assumed that this was a requirement only for the non-dockerize running of the application.  Subsequent calls of this applicationg using the following format:

`go build && ./codechallenge rexposadas@gmail.com`


will use the files created. 

If this was a requirement for running the application in Docker as well, I would have made one or more of the following:
        
        a. Use a [volume](https://docs.docker.com/storage/volumes/) in order to hold the files. 
        b. Create a webservice so that this will be a long running application.  Generating the keys will be an API call in this case. 

2. Some key generation tools default storing the new keys in the user's home directory. I opted to generate them in the same directory the application was ran.  I didn't want to write them in the user's home directory since the testers of this application will probably not want me doing that in their machines. 

3. I wrote most of the key generation code in the `lib` directory. I couldn't think of a better name and didn't bother given the time constraints.


