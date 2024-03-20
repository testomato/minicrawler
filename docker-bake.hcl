# Define the Docker Compose services block
# https://docs.docker.com/build/bake/reference/

####################################################################################################
# docker buildx bake --file docker-bake.hcl minicrawler --push --no-cache --progress=plain
####################################################################################################

target "minicrawler" {
  context    = "."
  dockerfile = ".docker/Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  pull       = true
  tags       = [
    "dr.brzy.cz/testomato/minicrawler:latest",
    "dr.brzy.cz/testomato/minicrawler:v5.2.6",
  ]
}

####################################################################################################
# docker buildx bake --file docker-bake.hcl --push --no-cache --progress=plain
####################################################################################################

group "default" {
  targets = ["minicrawler"]
}