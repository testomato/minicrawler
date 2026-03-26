# Define the Docker Compose services block
# https://docs.docker.com/build/bake/reference/

variable "CI_REGISTRY_IMAGE" {
  default = "gitlab.int.wikidi.net:5050/testomato/minicrawler"
}

####################################################################################################
# docker buildx bake --file docker-bake.hcl minicrawler --push --no-cache --progress=plain
####################################################################################################

target "minicrawler" {
  context    = "."
  dockerfile = ".docker/Dockerfile"
  target     = "minicrawler"
  platforms  = ["linux/amd64", "linux/arm64"]
  pull       = true
  tags       = [
    "${CI_REGISTRY_IMAGE}:latest",
    "${CI_REGISTRY_IMAGE}:v5.2.7",
  ]
}

####################################################################################################
# docker buildx bake --file docker-bake.hcl --push --no-cache --progress=plain
####################################################################################################

group "default" {
  targets = ["minicrawler"]
}