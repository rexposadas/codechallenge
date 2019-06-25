# Container is based on a preexisting image that contains the Go tools needed
# to compile and install
FROM golang:1.10

# Project URI based on repository URL 
ENV PROJECT_URI=github.com/rexposadas/codechallenge
ENV PROJECT_DIR=${GOPATH}/src/${PROJECT_URI}

# Create project directory
RUN mkdir -p ${PROJECT_DIR}

# Change current working directory to project directory
WORKDIR ${PROJECT_DIR}

# Copy source code to project directory
COPY . ${PROJECT_DIR}

# Compile and install code
RUN go install ${PROJECT_URI}/...

# Configure the container entrypoint so that it runs the compiled program. In
# this case, we utilize the shell to enable variable substitution for the
# GOPATH variable (for more info, refer to Docker's documentation:
# https://docs.docker.com/engine/reference/builder/#shell-form-entrypoint-example) 
ENTRYPOINT ["sh", "-c", "$GOPATH/bin/codechallenge"]