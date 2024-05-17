# password-compromise-check-server
A server that allows you to download a database of compromised passwords from the Have I Been Pwned (HIBP) service and deploy a local compliant HTTP-API to check for passwords in the database.
## How to build
1. Install Bazelisk
2. Install GCC (`sudo apt-get install build-essential`)
3. Run the following command in the root of this project
`
bazel build //:all_modules
`
## Containerization
1. Install Docker
2. Build the container `docker build -t pccserver .`
3. Create a volume for the storage using the command `docker volume create
pccserver-data` command
4. initialize the storage using the command `docker run --rm -v pccserver-
data:/data pccserver import-values` command
5. Start the container using the command `docker run -d -v pccserver-data:/data -p
8080:8080 pccserver run-server`
## Usage
- Use `pccserver` command
- `help` subcommand is available
- You can redefine the storage path by setting the `PCCSERVER_STORAGE` environment variable (by default `~/.config/pccserver` is used)
- Before running the server initialize the storage (`import-values` subcommand)
- Use `run-server` subcommand to run the HIBP-similar service
